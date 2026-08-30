//! Pure, read-only evaluation for fixed Windows and legacy LAPS indicators.

use crate::{Observation, PolicyFinding};
use baselineops_domain::{FindingStatus, JsonMap, Severity};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// The largest supported early-rotation offset.
pub const MAX_EARLY_ROTATION_DAYS: u16 = 365;

/// Strict LAPS audit/plan parameters with no command, path, or secret inputs.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, rename_all = "snake_case", deny_unknown_fields)]
pub struct LapsHygieneParameters {
    /// Days to bring the reported policy rotation threshold forward.
    pub early_rotation_days: u16,
    /// Typed request that the read-only executor returns as unsupported.
    pub request_rotation: bool,
}

impl LapsHygieneParameters {
    /// Validates the fixed upper bound on the early-rotation offset.
    ///
    /// # Errors
    ///
    /// Returns an error when the offset exceeds one policy year.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.early_rotation_days > MAX_EARLY_ROTATION_DAYS {
            return Err("early_rotation_days must be 0 through 365");
        }
        Ok(())
    }
}

/// Fixed policy roots in the legacy script's effective precedence order.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LapsPolicySource {
    /// Windows LAPS CSP policy under HKLM.
    WindowsCsp,
    /// Windows LAPS Group Policy under HKLM.
    WindowsGpo,
    /// Windows LAPS local configuration under HKLM.
    WindowsLocal,
    /// Legacy Microsoft LAPS Group Policy under HKLM.
    LegacyGpo,
}

impl LapsPolicySource {
    /// Returns true for Windows LAPS sources and false for legacy `AdmPwd`.
    #[must_use]
    pub const fn is_windows_laps(self) -> bool {
        !matches!(self, Self::LegacyGpo)
    }
}

/// Fixed registry evidence from the selected LAPS policy root.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct LapsPolicyEvidence {
    /// The selected fixed policy root.
    pub source: LapsPolicySource,
    /// Windows LAPS backup target; legacy LAPS leaves it not run.
    pub backup_directory: Observation<u32>,
    /// Effective policy age in days, with legacy hours normalized by acquisition.
    pub password_age_days: Observation<u16>,
    /// Password complexity policy value, without any password material.
    pub password_complexity: Observation<u32>,
}

/// One bounded metadata record from `Microsoft-Windows-LAPS/Operational`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct LapsOperationalEvent {
    /// Numeric Windows Event Log event ID.
    pub event_id: u32,
    /// Event creation timestamp as source XML system-time text.
    pub time_created: String,
    /// Event Log record identifier.
    pub record_id: u64,
}

/// Fixed policy and event evidence for capability 02.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct LapsHygieneObservation {
    /// Selected policy evidence, absence, denial, or incomplete observation.
    pub policy: Observation<LapsPolicyEvidence>,
    /// Bounded LAPS Operational metadata without rendered messages or XML.
    pub operational_events: Observation<Vec<LapsOperationalEvent>>,
    /// Whether the fixed Operational query completed without its bound.
    pub operational_events_complete: bool,
}

/// Rotation reporting that neither claims a password is due nor changes one.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RotationEligibility {
    /// A policy age permits reporting this future threshold only.
    Reportable {
        /// Policy-derived reporting threshold; this is not password-expiry evidence.
        threshold_days: u16,
    },
    /// Incomplete policy evidence prevents a threshold report.
    Unknown,
}

/// Deterministic LAPS audit or plan report.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct LapsHygieneAudit {
    /// Source evidence evaluated without platform I/O.
    pub observation: LapsHygieneObservation,
    /// Non-mutating threshold report derived from complete policy evidence.
    pub rotation_eligibility: RotationEligibility,
    /// Drift and incomplete-evidence findings.
    pub findings: Vec<PolicyFinding>,
}

/// Evaluates fixed LAPS evidence without Windows I/O, accounts, or secrets.
#[must_use]
pub fn evaluate_laps_hygiene(
    observation: LapsHygieneObservation,
    parameters: &LapsHygieneParameters,
) -> LapsHygieneAudit {
    let mut findings = Vec::new();
    let rotation_eligibility = match &observation.policy {
        Observation::Present(policy) => evaluate_policy(policy, parameters, &mut findings),
        Observation::Missing => {
            findings.push(finding(
                "LAPS-PolicyAbsent",
                FindingStatus::Fail,
                Severity::High,
                "No configured Windows LAPS or legacy LAPS policy was observed.",
            ));
            RotationEligibility::Unknown
        }
        value => {
            incomplete("LAPS-PolicyIncomplete", value, &mut findings);
            RotationEligibility::Unknown
        }
    };
    if !observation.operational_events_complete {
        findings.push(finding(
            "LAPS-OperationalEventsIncomplete",
            FindingStatus::Warning,
            Severity::Medium,
            "LAPS Operational event enumeration did not complete within its fixed bound.",
        ));
    }
    if !matches!(observation.operational_events, Observation::Present(_)) {
        incomplete(
            "LAPS-OperationalEventsUnavailable",
            &observation.operational_events,
            &mut findings,
        );
    }
    LapsHygieneAudit {
        observation,
        rotation_eligibility,
        findings,
    }
}

fn evaluate_policy(
    policy: &LapsPolicyEvidence,
    parameters: &LapsHygieneParameters,
    findings: &mut Vec<PolicyFinding>,
) -> RotationEligibility {
    if policy.source.is_windows_laps() {
        match policy.backup_directory {
            Observation::Present(1 | 2) => {}
            Observation::Present(_) | Observation::Missing => findings.push(finding(
                "LAPS-BackupTargetDrift",
                FindingStatus::Fail,
                Severity::High,
                "Windows LAPS backup must target Microsoft Entra ID or Active Directory.",
            )),
            ref value => incomplete("LAPS-BackupTargetIncomplete", value, findings),
        }
    }
    match policy.password_complexity {
        Observation::Present(0) => findings.push(finding(
            "LAPS-PasswordComplexityInvalid",
            FindingStatus::Fail,
            Severity::High,
            "LAPS PasswordComplexity is disabled or invalid.",
        )),
        Observation::Present(_) | Observation::Missing => {}
        ref value => incomplete("LAPS-PasswordComplexityIncomplete", value, findings),
    }
    match policy.password_age_days {
        Observation::Present(age) if age >= parameters.early_rotation_days => {
            RotationEligibility::Reportable {
                threshold_days: age - parameters.early_rotation_days,
            }
        }
        Observation::Present(_) => {
            findings.push(finding(
                "LAPS-RotationOffsetInvalid",
                FindingStatus::Warning,
                Severity::Medium,
                "The early rotation offset exceeds the configured LAPS password age.",
            ));
            RotationEligibility::Reportable { threshold_days: 0 }
        }
        ref value => {
            incomplete("LAPS-PasswordAgeIncomplete", value, findings);
            RotationEligibility::Unknown
        }
    }
}

fn incomplete<T>(code: &'static str, value: &Observation<T>, findings: &mut Vec<PolicyFinding>) {
    let state = observation_state(value);
    findings.push(PolicyFinding {
        code,
        status: FindingStatus::Warning,
        severity: Severity::Medium,
        message: format!("Required LAPS evidence is incomplete: {state}."),
        evidence: JsonMap::from([("observation_status".into(), json!(state))]),
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

    fn evidence() -> LapsPolicyEvidence {
        LapsPolicyEvidence {
            source: LapsPolicySource::WindowsGpo,
            backup_directory: Observation::Present(2),
            password_age_days: Observation::Present(30),
            password_complexity: Observation::Present(4),
        }
    }

    #[test]
    fn strict_parameters_and_threshold_are_bounded() {
        assert!(serde_json::from_value::<LapsHygieneParameters>(json!({"command":"x"})).is_err());
        assert!(
            LapsHygieneParameters {
                early_rotation_days: 366,
                request_rotation: false
            }
            .validate()
            .is_err()
        );
        let audit = evaluate_laps_hygiene(
            LapsHygieneObservation {
                policy: Observation::Present(evidence()),
                operational_events: Observation::Present(vec![]),
                operational_events_complete: true,
            },
            &LapsHygieneParameters {
                early_rotation_days: 5,
                request_rotation: false,
            },
        );
        assert_eq!(
            audit.rotation_eligibility,
            RotationEligibility::Reportable { threshold_days: 25 }
        );
        assert!(audit.findings.is_empty());
    }

    #[test]
    fn absence_denial_and_partial_event_evidence_remain_distinct() {
        let absent = evaluate_laps_hygiene(
            LapsHygieneObservation {
                policy: Observation::Missing,
                operational_events: Observation::AccessDenied,
                operational_events_complete: false,
            },
            &LapsHygieneParameters::default(),
        );
        assert_eq!(absent.findings[0].code, "LAPS-PolicyAbsent");
        assert!(
            absent
                .findings
                .iter()
                .any(|finding| finding.code == "LAPS-OperationalEventsUnavailable")
        );
        assert!(
            absent
                .findings
                .iter()
                .any(|finding| finding.code == "LAPS-OperationalEventsIncomplete")
        );
    }
}
