//! Pure, read-only SMB encryption policy for capability 22.
//!
//! This deliberately models only three fixed local Windows settings. Per-share
//! state, remote servers, connection negotiation, legacy script parity, and all
//! mutation remain outside this bounded foundation.

use crate::{Observation, PolicyFinding};
use baselineops_domain::{FindingStatus, JsonMap, Severity};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Fixed SMB encryption controls that this capability may observe.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SmbEncryptionField {
    /// Server-wide SMB encryption requirement.
    ServerEncryptData,
    /// Server behavior for clients that cannot encrypt.
    ServerRejectUnencryptedAccess,
    /// Client requirement for encrypted outbound SMB connections.
    ClientRequireEncryption,
}

/// Strict desired state for the fixed local SMB encryption subset.
///
/// No share name, host name, registry location, command, or remediation scope
/// is accepted as v3 authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "snake_case")]
pub struct SmbEncryptionPolicy {
    /// Require encryption for this computer's SMB server.
    pub server_encrypt_data: bool,
    /// Reject server clients that cannot use encryption.
    pub server_reject_unencrypted_access: bool,
    /// Require encryption for this computer's outbound SMB client connections.
    pub client_require_encryption: bool,
}

impl Default for SmbEncryptionPolicy {
    fn default() -> Self {
        Self {
            server_encrypt_data: true,
            server_reject_unencrypted_access: true,
            client_require_encryption: true,
        }
    }
}

/// Fixed native local evidence for SMB encryption settings.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct SmbEncryptionObservation {
    /// Fixed server-wide encryption setting.
    pub server_encrypt_data: Observation<bool>,
    /// Fixed server rejection setting for unencrypted clients.
    pub server_reject_unencrypted_access: Observation<bool>,
    /// Fixed local SMB client encryption requirement.
    pub client_require_encryption: Observation<bool>,
}

/// One proven difference between fixed evidence and finite desired state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct SmbEncryptionDrift {
    /// The fixed SMB setting that differs.
    pub field: SmbEncryptionField,
    /// The observed Boolean value.
    pub observed: bool,
    /// The finite Boolean value requested by policy.
    pub desired: bool,
}

/// Deterministic read-only SMB encryption assessment.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct SmbEncryptionAudit {
    /// Retained native evidence, including incomplete evidence states.
    pub observation: SmbEncryptionObservation,
    /// The finite desired state used to evaluate the evidence.
    pub policy: SmbEncryptionPolicy,
    /// Drift and incomplete-evidence findings.
    pub findings: Vec<PolicyFinding>,
    /// Reasons why this foundation cannot truthfully produce a plan.
    pub plan_blockers: Vec<&'static str>,
    /// Explicit capability and validation gaps.
    pub exclusions: Vec<&'static str>,
}

/// A non-mutating proposal for a separately approved future worker route.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct SmbEncryptionPlan {
    /// The full audit from which fixed proposed changes were derived.
    pub audit: SmbEncryptionAudit,
    /// Only fixed settings with complete, differing Boolean evidence.
    pub proposed_changes: Vec<SmbEncryptionDrift>,
    /// A future mutation route would require administrator authority.
    pub requires_administrator: bool,
    /// Raw capability Apply remains intentionally unavailable.
    pub apply_available: bool,
}

/// Evaluate fixed SMB encryption evidence without Windows I/O or mutation.
#[must_use]
pub fn evaluate_smb_encryption(
    observation: SmbEncryptionObservation,
    policy: &SmbEncryptionPolicy,
) -> SmbEncryptionAudit {
    let mut findings = Vec::new();
    let mut plan_blockers = Vec::new();
    evaluate(
        SmbEncryptionField::ServerEncryptData,
        "server-wide SMB encryption",
        &observation.server_encrypt_data,
        policy.server_encrypt_data,
        &mut findings,
        &mut plan_blockers,
    );
    evaluate(
        SmbEncryptionField::ServerRejectUnencryptedAccess,
        "SMB server rejection of unencrypted clients",
        &observation.server_reject_unencrypted_access,
        policy.server_reject_unencrypted_access,
        &mut findings,
        &mut plan_blockers,
    );
    evaluate(
        SmbEncryptionField::ClientRequireEncryption,
        "outbound SMB client encryption",
        &observation.client_require_encryption,
        policy.client_require_encryption,
        &mut findings,
        &mut plan_blockers,
    );
    findings.push(read_only_exclusion());
    SmbEncryptionAudit {
        observation,
        policy: policy.clone(),
        findings,
        plan_blockers,
        exclusions: exclusions(),
    }
}

/// Build a non-mutating plan only when all fixed evidence is complete.
///
/// # Errors
///
/// Returns an error if any fixed observation is missing, denied, or unparsed.
/// The result cannot safely infer a proposed change from incomplete evidence.
pub fn build_smb_encryption_plan(
    observation: SmbEncryptionObservation,
    policy: &SmbEncryptionPolicy,
) -> Result<SmbEncryptionPlan, String> {
    let audit = evaluate_smb_encryption(observation, policy);
    if !audit.plan_blockers.is_empty() {
        return Err(
            "SMB encryption plan is unavailable because fixed evidence is incomplete".into(),
        );
    }
    let proposed_changes = [
        (
            SmbEncryptionField::ServerEncryptData,
            &audit.observation.server_encrypt_data,
            policy.server_encrypt_data,
        ),
        (
            SmbEncryptionField::ServerRejectUnencryptedAccess,
            &audit.observation.server_reject_unencrypted_access,
            policy.server_reject_unencrypted_access,
        ),
        (
            SmbEncryptionField::ClientRequireEncryption,
            &audit.observation.client_require_encryption,
            policy.client_require_encryption,
        ),
    ]
    .into_iter()
    .filter_map(|(field, observed, desired)| match observed {
        Observation::Present(actual) if *actual != desired => Some(SmbEncryptionDrift {
            field,
            observed: *actual,
            desired,
        }),
        _ => None,
    })
    .collect();
    Ok(SmbEncryptionPlan {
        audit,
        proposed_changes,
        requires_administrator: true,
        apply_available: false,
    })
}

fn evaluate(
    field: SmbEncryptionField,
    label: &'static str,
    observed: &Observation<bool>,
    desired: bool,
    findings: &mut Vec<PolicyFinding>,
    plan_blockers: &mut Vec<&'static str>,
) {
    match observed {
        Observation::Present(actual) if *actual == desired => {}
        Observation::Present(actual) => findings.push(PolicyFinding {
            code: "SMB-EncryptionDrift",
            status: FindingStatus::Warning,
            severity: Severity::High,
            message: format!("{label} is {actual}, expected {desired}."),
            evidence: JsonMap::from([
                ("field".into(), json!(field)),
                ("observed".into(), json!(actual)),
                ("desired".into(), json!(desired)),
            ]),
        }),
        incomplete => {
            plan_blockers.push("fixed SMB encryption evidence is incomplete");
            findings.push(PolicyFinding {
                code: "SMB-EncryptionEvidenceIncomplete",
                status: FindingStatus::Error,
                severity: Severity::High,
                message: format!("{label} evidence is incomplete: {}.", state(incomplete)),
                evidence: JsonMap::from([
                    ("field".into(), json!(field)),
                    ("observed".into(), json!(incomplete)),
                    ("read_only".into(), json!(true)),
                ]),
            });
        }
    }
}

fn read_only_exclusion() -> PolicyFinding {
    PolicyFinding {
        code: "SMB-ReadOnlyFoundation",
        status: FindingStatus::Warning,
        severity: Severity::Low,
        message: "This is a fixed local read-only SMB configuration assessment; it does not prove SMB negotiation, per-share state, remote reachability, or legacy-script parity.".into(),
        evidence: JsonMap::from([("read_only".into(), json!(true))]),
    }
}

fn exclusions() -> Vec<&'static str> {
    vec![
        "Per-share EncryptData state and share enumeration are excluded.",
        "Remote hosts, SMB sessions, negotiation, and encrypted-transfer effectiveness are not observed.",
        "The legacy PowerShell script and its remediation behavior are not claimed as equivalent.",
        "Windows 11 client and server VM validation is not included.",
        "Apply and every state mutation are intentionally unavailable.",
    ]
}

fn state<T>(value: &Observation<T>) -> &'static str {
    match value {
        Observation::Present(_) => "present",
        Observation::Missing => "missing",
        Observation::AccessDenied => "access denied",
        Observation::TimedOut => "timed out",
        Observation::Truncated => "truncated",
        Observation::Failed { .. } => "failed",
        Observation::NotRun => "not run",
        Observation::Unparsed => "unparsed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete() -> SmbEncryptionObservation {
        SmbEncryptionObservation {
            server_encrypt_data: Observation::Present(true),
            server_reject_unencrypted_access: Observation::Present(true),
            client_require_encryption: Observation::Present(true),
        }
    }

    #[test]
    fn policy_rejects_dynamic_or_remediation_inputs() {
        for value in [
            json!({"share_name":"Finance"}),
            json!({"host":"server.example"}),
            json!({"registry_path":"HKLM\\anything"}),
            json!({"command":"Set-SmbServerConfiguration"}),
        ] {
            assert!(serde_json::from_value::<SmbEncryptionPolicy>(value).is_err());
        }
    }

    #[test]
    fn incomplete_evidence_fails_closed_and_cannot_plan() {
        let mut observation = complete();
        observation.client_require_encryption = Observation::AccessDenied;
        let audit = evaluate_smb_encryption(observation.clone(), &SmbEncryptionPolicy::default());
        assert!(
            audit
                .findings
                .iter()
                .any(|finding| finding.code == "SMB-EncryptionEvidenceIncomplete")
        );
        assert!(!audit.plan_blockers.is_empty());
        assert!(build_smb_encryption_plan(observation, &SmbEncryptionPolicy::default()).is_err());
    }

    #[test]
    fn complete_fixture_only_proposes_proven_fixed_drift() {
        let mut observation = complete();
        observation.server_encrypt_data = Observation::Present(false);
        let plan = build_smb_encryption_plan(observation, &SmbEncryptionPolicy::default())
            .expect("complete evidence permits a read-only plan");
        assert_eq!(plan.proposed_changes.len(), 1);
        assert_eq!(
            plan.proposed_changes[0].field,
            SmbEncryptionField::ServerEncryptData
        );
        assert!(!plan.apply_available);
    }
}
