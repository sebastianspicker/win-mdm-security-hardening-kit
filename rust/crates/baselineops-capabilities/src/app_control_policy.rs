//! Pure policy for a fixed, bounded App Control for Business observation.

use crate::{EventLogObservation, Observation, PolicyFinding};
use baselineops_domain::{FindingStatus, JsonMap, Severity};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// The only Code Integrity event IDs retained by capability 43.
pub const CODE_INTEGRITY_EVENT_IDS: [u32; 3] = [3076, 3077, 3089];
/// Maximum current-log records retained by capability 43.
pub const MAX_APP_CONTROL_EVENTS: u16 = 64;
/// Maximum XML bytes retained for one Code Integrity record.
pub const MAX_APP_CONTROL_EVENT_XML_BYTES: u32 = 64 * 1024;
/// Maximum wait for one fixed Code Integrity Event Log retrieval call.
pub const APP_CONTROL_EVENT_TIMEOUT_MS: u32 = 5_000;

/// Strict capability 43 parameters. The policy path, channel, query, and bounds are fixed.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AppControlPolicy {}

/// Metadata for the fixed legacy single-policy file only.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct AppControlPolicyFile {
    /// Observed size without reading or parsing file content.
    pub bytes: u64,
}

/// Native capability 43 evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct AppControlObservation {
    /// Fixed `%Windows%\\System32\\CodeIntegrity\\SIPolicy.p7b` metadata.
    pub legacy_policy_file: Observation<AppControlPolicyFile>,
    /// Fixed bounded records from the local Code Integrity Operational channel.
    pub code_integrity_events: EventLogObservation,
}

/// Deterministic capability 43 result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct AppControlAudit {
    /// Native input evidence.
    pub observation: AppControlObservation,
    /// Policy-file, event, and completeness findings.
    pub findings: Vec<PolicyFinding>,
}

/// Evaluates fixed App Control evidence without parsing policy content or signatures.
#[must_use]
pub fn evaluate_app_control(
    observation: AppControlObservation,
    _policy: &AppControlPolicy,
) -> AppControlAudit {
    let mut findings = Vec::new();
    match &observation.legacy_policy_file {
        Observation::Present(file) if file.bytes == 0 => findings.push(finding(
            "APPCONTROL-PolicyFileEmpty",
            FindingStatus::Warning,
            Severity::Medium,
            "The fixed Code Integrity policy file is empty.",
        )),
        Observation::Present(_) => findings.push(finding(
            "APPCONTROL-PolicySemanticsExcluded",
            FindingStatus::Warning,
            Severity::Medium,
            "The fixed policy file was observed, but content and signature semantics are excluded.",
        )),
        Observation::Missing => findings.push(finding(
            "APPCONTROL-PolicyFileMissing",
            FindingStatus::Warning,
            Severity::Medium,
            "The fixed legacy Code Integrity policy file is absent; this does not establish effective policy state.",
        )),
        value => incomplete("APPCONTROL-PolicyFileEvidenceIncomplete", value, &mut findings),
    }
    evaluate_events(&observation.code_integrity_events, &mut findings);
    AppControlAudit {
        observation,
        findings,
    }
}

fn evaluate_events(events: &EventLogObservation, findings: &mut Vec<PolicyFinding>) {
    for record in &events.records {
        match record {
            Observation::Present(record) => match record.event_id {
                3077 => findings.push(finding(
                    "APPCONTROL-CodeIntegrityBlocked",
                    FindingStatus::Fail,
                    Severity::High,
                    "The bounded Code Integrity log contains a policy-block event.",
                )),
                3076 => findings.push(finding(
                    "APPCONTROL-CodeIntegrityAuditOnly",
                    FindingStatus::Warning,
                    Severity::Medium,
                    "The bounded Code Integrity log contains an audit-only event.",
                )),
                3089 => findings.push(finding(
                    "APPCONTROL-CodeIntegritySignerInfo",
                    FindingStatus::Info,
                    Severity::Info,
                    "The bounded Code Integrity log contains signer-information evidence.",
                )),
                _ => findings.push(finding(
                    "APPCONTROL-EventIdUnexpected",
                    FindingStatus::Warning,
                    Severity::Medium,
                    "The fixed Code Integrity query returned an unexpected event ID.",
                )),
            },
            value => incomplete("APPCONTROL-EventEvidenceIncomplete", value, findings),
        }
    }
    if !events.enumeration_complete {
        findings.push(finding(
            "APPCONTROL-EventEnumerationIncomplete",
            FindingStatus::Warning,
            Severity::Medium,
            "Code Integrity Event Log enumeration reached a fixed bound or ended incompletely.",
        ));
    }
}

fn incomplete<T>(code: &'static str, _value: &Observation<T>, findings: &mut Vec<PolicyFinding>) {
    findings.push(finding(
        code,
        FindingStatus::Warning,
        Severity::Medium,
        "Required App Control evidence is incomplete.",
    ));
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

    fn observation(event_id: u32) -> AppControlObservation {
        AppControlObservation {
            legacy_policy_file: Observation::Present(AppControlPolicyFile { bytes: 16 }),
            code_integrity_events: EventLogObservation {
                records: vec![Observation::Present(crate::EventLogRecord {
                    provider: "Microsoft-Windows-CodeIntegrity".into(),
                    event_id,
                    level: 3,
                    time_created: "2026-08-10T00:00:00Z".into(),
                    record_id: 1,
                    xml: Observation::Present("<Event/>".into()),
                    message: None,
                })],
                enumeration_complete: true,
            },
        }
    }

    #[test]
    fn strict_parameters_and_block_event_are_fail_closed() {
        assert!(serde_json::from_value::<AppControlPolicy>(json!({"path":"C:\\\\out"})).is_err());
        let audit = evaluate_app_control(observation(3077), &AppControlPolicy {});
        assert!(
            audit
                .findings
                .iter()
                .any(|finding| finding.code == "APPCONTROL-CodeIntegrityBlocked")
        );
        assert!(
            audit
                .findings
                .iter()
                .any(|finding| finding.code == "APPCONTROL-PolicySemanticsExcluded")
        );
    }

    #[test]
    fn incomplete_policy_and_event_evidence_never_passes() {
        let audit = evaluate_app_control(
            AppControlObservation {
                legacy_policy_file: Observation::AccessDenied,
                code_integrity_events: EventLogObservation {
                    records: vec![Observation::Truncated],
                    enumeration_complete: false,
                },
            },
            &AppControlPolicy {},
        );
        assert_eq!(audit.findings.len(), 3);
        assert!(
            audit
                .findings
                .iter()
                .all(|finding| finding.status == FindingStatus::Warning)
        );
    }
}
