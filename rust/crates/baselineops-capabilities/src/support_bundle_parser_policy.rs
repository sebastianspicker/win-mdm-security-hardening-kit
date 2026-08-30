//! Typed, side-effect-free policy for the support-bundle parser.
//!
//! ZIP acquisition and extraction belong to the engine. This module keeps the
//! legacy summary contract bounded and makes missing or unparsed evidence a
//! finding rather than a healthy result.

use crate::PolicyFinding;
use baselineops_domain::{FindingStatus, JsonMap, Severity};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::PathBuf;

/// Maximum UTF-8 bytes accepted for `Summary.json` or `KBStatus.json`.
pub const MAX_JSON_BYTES: u64 = 1024 * 1024;
/// Maximum strings retained from any legacy summary list.
pub const MAX_SUMMARY_ITEMS: usize = 512;
/// Fixed legacy proof names; configuration sidecars are intentionally ignored.
pub const EXPECTED_PROOFS: [&str; 5] = [
    "SysmonState.json",
    "SysmonDriftState.json",
    "SoftwareInventory.json",
    "FirewallAudit.json",
    "HardwareAudit.json",
];

/// Strict operator input for capability 10.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SupportBundleParserParameters {
    /// Local directory containing `SupportBundle-*.zip` files.
    pub support_dir: PathBuf,
}

/// Strict, bounded legacy producer record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SummaryRecord {
    /// Producer name.
    #[serde(rename = "Name")]
    pub name: Option<String>,
    /// Producer success state.
    #[serde(rename = "Ok")]
    pub ok: Option<bool>,
    /// Producer error detail.
    #[serde(rename = "Error")]
    pub error: Option<String>,
    /// Producer note detail.
    #[serde(rename = "Note")]
    pub note: Option<String>,
}

/// Strict subset of `Summary.json` used by the legacy parser.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SupportBundleSummary {
    /// Legacy producer hostname.
    #[serde(rename = "Hostname")]
    pub hostname: Option<String>,
    /// Legacy producer timestamp text.
    #[serde(rename = "Time")]
    pub time: Option<String>,
    /// Optional legacy collection reason.
    #[serde(rename = "Reason")]
    pub reason: Option<String>,
    /// Legacy collecting user text.
    #[serde(rename = "User")]
    pub user: Option<String>,
    /// Best-effort legacy administrative collection marker.
    #[serde(rename = "Admin")]
    pub admin: Option<bool>,
    /// Legacy producer error messages.
    #[serde(rename = "Errors", default)]
    pub errors: Vec<String>,
    /// Legacy producer notes.
    #[serde(rename = "Notes", default)]
    pub notes: Vec<String>,
    /// Legacy producer output markers.
    #[serde(rename = "Outputs", default)]
    pub outputs: Vec<String>,
    /// Per-producer completion records.
    #[serde(rename = "Records", default)]
    pub records: Vec<SummaryRecord>,
}

/// Strict KB evidence retained from `KBStatus.json`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KbStatus {
    /// Installed KB identifiers.
    #[serde(rename = "Installed", default)]
    pub installed: Vec<String>,
    /// Zero-day KB identifiers reported missing.
    #[serde(rename = "MissingZeroDay", default)]
    pub missing_zero_day: Vec<String>,
    /// Critical KB identifiers reported missing.
    #[serde(rename = "MissingCritical", default)]
    pub missing_critical: Vec<String>,
    /// Optional producer summary text.
    #[serde(rename = "Summary")]
    pub summary: Option<String>,
}

/// A non-executable archive member retained as parser evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct BundleArtifact {
    /// Fixed artifact role.
    pub kind: String,
    /// Member path relative to the freshly extracted archive root.
    pub relative_path: String,
    /// Member length when known.
    pub size_bytes: u64,
}

/// Presence state for one fixed legacy proof file.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ProofObservation {
    /// Fixed leaf name from [`EXPECTED_PROOFS`].
    pub file_name: String,
    /// A matching archive member exists.
    pub present_by_file: bool,
    /// A matching legacy output marker exists.
    pub present_by_output: bool,
    /// Relative member path when uniquely located.
    pub relative_path: Option<String>,
}

impl ProofObservation {
    /// Whether either retained legacy evidence source establishes presence.
    #[must_use]
    pub const fn present(&self) -> bool {
        self.present_by_file || self.present_by_output
    }
}

/// Complete bounded observation produced by the engine parser.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct SupportBundleParserObservation {
    /// Canonical selected archive path.
    pub bundle_path: PathBuf,
    /// Selected archive filename.
    pub bundle_name: String,
    /// Archive size before decompression.
    pub archive_bytes: u64,
    /// Parsed root summary, never a sidecar.
    pub summary: SupportBundleSummary,
    /// Fixed proof evidence.
    pub proofs: Vec<ProofObservation>,
    /// Non-executable `.evtx` member evidence below `eventlogs/`.
    pub event_logs: Vec<BundleArtifact>,
    /// Parsed KB evidence, or `None` when it is unavailable or rejected.
    pub kb_status: Option<KbStatus>,
    /// Evidence members retained without opening or executing their content.
    pub artifacts: Vec<BundleArtifact>,
}

/// Deterministic native parser output.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct SupportBundleParserAudit {
    /// Bounded source observation.
    pub observation: SupportBundleParserObservation,
    /// Findings, including every incomplete evidence condition.
    pub findings: Vec<PolicyFinding>,
}

/// Evaluates bundle evidence without filesystem, process, or archive access.
#[must_use]
pub fn evaluate_support_bundle_parser(
    observation: SupportBundleParserObservation,
) -> SupportBundleParserAudit {
    let mut findings = Vec::new();
    for error in observation.summary.errors.iter().take(MAX_SUMMARY_ITEMS) {
        findings.push(finding(
            "SB-ProducerError",
            FindingStatus::Warning,
            Severity::Medium,
            "SupportBundle producer reported an error.",
            JsonMap::from([("error".into(), json!(bounded(error)))]),
        ));
    }
    for record in observation.summary.records.iter().take(MAX_SUMMARY_ITEMS) {
        if record.ok == Some(false) {
            findings.push(finding(
                "SB-ProducerRecordFailed",
                FindingStatus::Warning,
                Severity::Medium,
                "SupportBundle producer record failed.",
                JsonMap::from([
                    ("name".into(), json!(record.name.as_deref().map(bounded))),
                    (
                        "detail".into(),
                        json!(
                            record
                                .error
                                .as_deref()
                                .or(record.note.as_deref())
                                .map(bounded)
                        ),
                    ),
                ]),
            ));
        }
    }
    for proof in &observation.proofs {
        if !proof.present() {
            findings.push(finding(
                "SB-MissingProof",
                FindingStatus::Warning,
                Severity::Medium,
                "Expected support-bundle proof is absent.",
                JsonMap::from([("file_name".into(), json!(proof.file_name))]),
            ));
        }
    }
    if observation.event_logs.is_empty() {
        findings.push(finding(
            "SB-EventEvidenceMissing",
            FindingStatus::Warning,
            Severity::Low,
            "No event-log evidence was found in the validated archive.",
            JsonMap::new(),
        ));
    }
    match &observation.kb_status {
        None => findings.push(finding(
            "SB-KbEvidenceMissing",
            FindingStatus::Warning,
            Severity::Medium,
            "KB status evidence is missing or could not be parsed.",
            JsonMap::new(),
        )),
        Some(kb) => {
            if !kb.missing_zero_day.is_empty() {
                findings.push(finding(
                    "SB-MissingZeroDayKB",
                    FindingStatus::Fail,
                    Severity::High,
                    "KB status reports missing zero-day updates.",
                    JsonMap::from([("count".into(), json!(kb.missing_zero_day.len()))]),
                ));
            }
            if !kb.missing_critical.is_empty() {
                findings.push(finding(
                    "SB-MissingCriticalKB",
                    FindingStatus::Fail,
                    Severity::Medium,
                    "KB status reports missing critical updates.",
                    JsonMap::from([("count".into(), json!(kb.missing_critical.len()))]),
                ));
            }
        }
    }
    SupportBundleParserAudit {
        observation,
        findings,
    }
}

fn finding(
    code: &'static str,
    status: FindingStatus,
    severity: Severity,
    message: &str,
    evidence: JsonMap,
) -> PolicyFinding {
    PolicyFinding {
        code,
        status,
        severity,
        message: message.into(),
        evidence,
    }
}

fn bounded(value: &str) -> String {
    value.chars().take(512).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation() -> SupportBundleParserObservation {
        SupportBundleParserObservation {
            bundle_path: PathBuf::from("C:/bundle.zip"),
            bundle_name: "SupportBundle-test.zip".into(),
            archive_bytes: 4,
            summary: SupportBundleSummary {
                hostname: None,
                time: None,
                reason: None,
                user: None,
                admin: None,
                errors: vec![],
                notes: vec![],
                outputs: vec![],
                records: vec![],
            },
            proofs: EXPECTED_PROOFS
                .into_iter()
                .map(|file_name| ProofObservation {
                    file_name: file_name.into(),
                    present_by_file: true,
                    present_by_output: false,
                    relative_path: Some(file_name.into()),
                })
                .collect(),
            event_logs: vec![BundleArtifact {
                kind: "event_log".into(),
                relative_path: "eventlogs/System.evtx".into(),
                size_bytes: 1,
            }],
            kb_status: Some(KbStatus {
                installed: vec![],
                missing_zero_day: vec![],
                missing_critical: vec![],
                summary: None,
            }),
            artifacts: vec![],
        }
    }

    #[test]
    fn incomplete_evidence_never_becomes_healthy() {
        let mut input = observation();
        input.proofs[0].present_by_file = false;
        input.proofs[0].relative_path = None;
        input.kb_status = None;
        let audit = evaluate_support_bundle_parser(input);
        assert!(
            audit
                .findings
                .iter()
                .any(|finding| finding.code == "SB-MissingProof")
        );
        assert!(
            audit
                .findings
                .iter()
                .any(|finding| finding.code == "SB-KbEvidenceMissing")
        );
    }

    #[test]
    fn unknown_summary_fields_are_rejected() {
        let parsed =
            serde_json::from_value::<SupportBundleSummary>(serde_json::json!({"Extra":true}));
        assert!(parsed.is_err());
    }
}
