//! Pure, read-only evaluation for local Administrators group membership.
//!
//! The legacy capability accepts names and paths, then resolves those names at
//! execution time. This bounded native foundation deliberately accepts only
//! canonical SID strings. It neither reads allow-list files nor resolves names,
//! so untrusted path and account-resolution behaviour remains outside this
//! slice.

use crate::{Observation, PolicyFinding};
use baselineops_domain::{FindingStatus, JsonMap, Severity};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Largest allow-list accepted by the native foundation.
pub const MAX_ALLOWED_SIDS: usize = 4_096;

/// Strict, portable parameters for the read-only local-admins guardrail.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, rename_all = "snake_case", deny_unknown_fields)]
pub struct LocalAdminsParameters {
    /// Canonical account SIDs allowed as direct Administrators-group members.
    pub allowed_sids: Vec<String>,
}

impl LocalAdminsParameters {
    /// Validates the bounded canonical SID allow-list.
    ///
    /// # Errors
    ///
    /// Returns an error for too many, duplicate, or non-canonical SID values.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.allowed_sids.len() > MAX_ALLOWED_SIDS {
            return Err("allowed_sids exceeds the bounded 4096-entry limit");
        }
        for sid in &self.allowed_sids {
            if !is_canonical_sid(sid) {
                return Err("allowed_sids must contain canonical SID strings");
            }
        }
        let mut unique = self.allowed_sids.clone();
        unique.sort_unstable();
        unique.dedup();
        if unique.len() != self.allowed_sids.len() {
            return Err("allowed_sids must not contain duplicates");
        }
        Ok(())
    }
}

/// One direct local Administrators-group member acquired from Windows.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct LocalAdministratorMember {
    /// Member SID, or a typed incomplete conversion result.
    pub sid: Observation<String>,
    /// Windows-provided domain-qualified name when available.
    pub account_name: Observation<String>,
    /// Raw `SID_NAME_USE` value from `LOCALGROUP_MEMBERS_INFO_2`.
    pub sid_use: u32,
}

/// Fixed native observation for the built-in local Administrators group.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct LocalAdminsObservation {
    /// Localized display name resolved from the fixed Builtin Administrators SID.
    pub group_name: Observation<String>,
    /// Direct members only; nested group expansion is deliberately absent.
    pub members: Observation<Vec<LocalAdministratorMember>>,
    /// Whether `NetAPI` enumeration completed before its explicit record bound.
    pub enumeration_complete: bool,
}

/// Deterministic result of evaluating direct Administrators-group membership.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct LocalAdminsAudit {
    /// Original native observation, including incomplete evidence.
    pub observation: LocalAdminsObservation,
    /// Allowed SIDs that were not observed as direct members.
    pub missing_allowed_sids: Vec<String>,
    /// Direct member SIDs not on the configured allow-list, excluding RID 500.
    pub unexpected_member_sids: Vec<String>,
    /// Built-in Administrator SIDs (RID 500) retained as protected evidence.
    pub protected_builtin_administrator_sids: Vec<String>,
    /// Drift and incomplete-evidence findings.
    pub findings: Vec<PolicyFinding>,
}

/// Evaluates direct member evidence without Windows I/O or membership mutation.
#[must_use]
pub fn evaluate_local_admins(
    observation: LocalAdminsObservation,
    parameters: &LocalAdminsParameters,
) -> LocalAdminsAudit {
    let mut findings = Vec::new();
    incomplete(
        "LOCALADM-GroupNameIncomplete",
        &observation.group_name,
        &mut findings,
    );
    if !observation.enumeration_complete {
        findings.push(finding(
            "LOCALADM-EnumerationIncomplete",
            FindingStatus::Warning,
            Severity::Medium,
            "Direct local Administrators-group enumeration exceeded its fixed record bound.",
        ));
    }

    let membership = evaluate_members(&observation.members, parameters, &mut findings);
    LocalAdminsAudit {
        observation,
        missing_allowed_sids: membership.missing_allowed,
        unexpected_member_sids: membership.unexpected,
        protected_builtin_administrator_sids: membership.protected_builtin,
        findings,
    }
}

#[derive(Default)]
struct MembershipEvaluation {
    missing_allowed: Vec<String>,
    unexpected: Vec<String>,
    protected_builtin: Vec<String>,
}

fn evaluate_members(
    observation: &Observation<Vec<LocalAdministratorMember>>,
    parameters: &LocalAdminsParameters,
    findings: &mut Vec<PolicyFinding>,
) -> MembershipEvaluation {
    let Observation::Present(members) = observation else {
        incomplete("LOCALADM-MembersIncomplete", observation, findings);
        return MembershipEvaluation::default();
    };
    let mut evidence = collect_member_evidence(members, findings);
    evidence.observed.sort_unstable();
    evidence.observed.dedup();
    evidence.protected_builtin.sort_unstable();
    evidence.protected_builtin.dedup();
    compare_allow_list(evidence, parameters, findings)
}

#[derive(Default)]
struct MemberEvidence {
    observed: Vec<String>,
    protected_builtin: Vec<String>,
}

fn collect_member_evidence(
    members: &[LocalAdministratorMember],
    findings: &mut Vec<PolicyFinding>,
) -> MemberEvidence {
    let mut evidence = MemberEvidence {
        observed: Vec::with_capacity(members.len()),
        protected_builtin: Vec::new(),
    };
    for member in members {
        collect_member_sid(member, &mut evidence, findings);
        incomplete(
            "LOCALADM-MemberNameIncomplete",
            &member.account_name,
            findings,
        );
    }
    evidence
}

fn collect_member_sid(
    member: &LocalAdministratorMember,
    evidence: &mut MemberEvidence,
    findings: &mut Vec<PolicyFinding>,
) {
    let Observation::Present(sid) = &member.sid else {
        incomplete("LOCALADM-MemberSidIncomplete", &member.sid, findings);
        return;
    };
    if is_builtin_administrator_sid(sid) {
        evidence.protected_builtin.push(sid.clone());
    }
    evidence.observed.push(sid.clone());
}

fn compare_allow_list(
    evidence: MemberEvidence,
    parameters: &LocalAdminsParameters,
    findings: &mut Vec<PolicyFinding>,
) -> MembershipEvaluation {
    if parameters.allowed_sids.is_empty() {
        findings.push(finding(
            "LOCALADM-AllowListNotConfigured",
            FindingStatus::Warning,
            Severity::High,
            "No typed SID allow-list was supplied; member drift is intentionally not inferred.",
        ));
        return MembershipEvaluation {
            protected_builtin: evidence.protected_builtin,
            ..MembershipEvaluation::default()
        };
    }
    let mut allowed = parameters.allowed_sids.clone();
    allowed.sort_unstable();
    let missing_allowed = allowed
        .iter()
        .filter(|sid| evidence.observed.binary_search(sid).is_err())
        .cloned()
        .collect::<Vec<_>>();
    let unexpected = evidence
        .observed
        .iter()
        .filter(|sid| !is_builtin_administrator_sid(sid) && allowed.binary_search(sid).is_err())
        .cloned()
        .collect::<Vec<_>>();
    append_drift_findings(&missing_allowed, &unexpected, findings);
    MembershipEvaluation {
        missing_allowed,
        unexpected,
        protected_builtin: evidence.protected_builtin,
    }
}

fn append_drift_findings(
    missing_allowed: &[String],
    unexpected: &[String],
    findings: &mut Vec<PolicyFinding>,
) {
    if !missing_allowed.is_empty() {
        findings.push(finding(
            "LOCALADM-AllowedMemberMissing",
            FindingStatus::Fail,
            Severity::High,
            "Configured allowed SID values are absent from direct Administrators-group membership.",
        ));
    }
    if !unexpected.is_empty() {
        findings.push(finding(
            "LOCALADM-UnexpectedMember",
            FindingStatus::Fail,
            Severity::High,
            "Direct Administrators-group membership includes SID values outside the typed allow-list.",
        ));
    }
}

fn is_canonical_sid(value: &str) -> bool {
    let mut parts = value.split('-');
    if parts.next() != Some("S") || parts.next() != Some("1") {
        return false;
    }
    let mut count = 0_usize;
    for part in parts {
        if part.is_empty() || part.parse::<u32>().is_err() {
            return false;
        }
        count += 1;
    }
    count >= 2 && value.len() <= 184
}

fn is_builtin_administrator_sid(sid: &str) -> bool {
    sid.starts_with("S-1-5-21-") && sid.ends_with("-500")
}

fn incomplete<T>(code: &'static str, value: &Observation<T>, findings: &mut Vec<PolicyFinding>) {
    if matches!(value, Observation::Present(_)) {
        return;
    }
    findings.push(PolicyFinding {
        code,
        status: FindingStatus::Warning,
        severity: Severity::Medium,
        message: format!(
            "Required local Administrators evidence is incomplete: {}.",
            observation_state(value)
        ),
        evidence: JsonMap::from([("observation_status".into(), json!(observation_state(value)))]),
    });
}

fn observation_state<T>(value: &Observation<T>) -> &'static str {
    match value {
        Observation::Present(_) => "present",
        Observation::Missing => "missing",
        Observation::AccessDenied => "access_denied",
        Observation::TimedOut => "timed_out",
        Observation::Truncated => "truncated",
        Observation::Failed { .. } => "failed",
        Observation::NotRun => "not_run",
        Observation::Unparsed => "unparsed",
    }
}

fn finding(
    code: &'static str,
    status: FindingStatus,
    severity: Severity,
    message: &'static str,
) -> PolicyFinding {
    PolicyFinding {
        code,
        status,
        severity,
        message: message.into(),
        evidence: JsonMap::from([("read_only".into(), json!(true))]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(sid: &str) -> LocalAdministratorMember {
        LocalAdministratorMember {
            sid: Observation::Present(sid.into()),
            account_name: Observation::Present("fixture".into()),
            sid_use: 1,
        }
    }

    fn observation(members: Observation<Vec<LocalAdministratorMember>>) -> LocalAdminsObservation {
        LocalAdminsObservation {
            group_name: Observation::Present("Administrators".into()),
            members,
            enumeration_complete: true,
        }
    }

    #[test]
    fn strict_parameters_reject_raw_commands_and_noncanonical_sids() {
        assert!(serde_json::from_value::<LocalAdminsParameters>(json!({"command":"net"})).is_err());
        assert!(
            LocalAdminsParameters {
                allowed_sids: vec!["DOMAIN\\Admin".into()]
            }
            .validate()
            .is_err()
        );
        assert!(
            LocalAdminsParameters {
                allowed_sids: vec!["S-1-5-21-1-2-3-1001".into()]
            }
            .validate()
            .is_ok()
        );
    }

    #[test]
    fn portable_fixture_preserves_drift_and_builtin_protection() {
        let parameters = LocalAdminsParameters {
            allowed_sids: vec!["S-1-5-21-1-2-3-1001".into()],
        };
        let audit = evaluate_local_admins(
            observation(Observation::Present(vec![
                member("S-1-5-21-1-2-3-500"),
                member("S-1-5-21-1-2-3-2002"),
            ])),
            &parameters,
        );
        assert_eq!(audit.missing_allowed_sids, vec!["S-1-5-21-1-2-3-1001"]);
        assert_eq!(audit.unexpected_member_sids, vec!["S-1-5-21-1-2-3-2002"]);
        assert_eq!(
            audit.protected_builtin_administrator_sids,
            vec!["S-1-5-21-1-2-3-500"]
        );
        assert_eq!(audit.findings.len(), 2);
    }

    #[test]
    fn incomplete_membership_is_never_reported_as_compliant() {
        let audit = evaluate_local_admins(
            observation(Observation::AccessDenied),
            &LocalAdminsParameters::default(),
        );
        assert!(audit.missing_allowed_sids.is_empty());
        assert!(audit.unexpected_member_sids.is_empty());
        assert_eq!(audit.findings[0].code, "LOCALADM-MembersIncomplete");
    }
}
