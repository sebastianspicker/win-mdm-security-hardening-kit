//! Pure parsing and evaluation for bounded Advanced Audit Policy evidence.

use crate::{Observation, PolicyFinding};
use baselineops_domain::{FindingStatus, JsonMap, Severity};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

/// Maximum retained subcategories from one `auditpol` report.
pub const MAX_AUDIT_SUBCATEGORIES: usize = 128;

/// Desired success/failure flags for one canonical subcategory GUID.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DesiredAuditSubcategory {
    /// Canonical lowercase GUID without braces.
    pub guid: String,
    /// Enable successful-event auditing.
    pub success: bool,
    /// Enable failed-event auditing.
    pub failure: bool,
}

/// Strict capability 33 parameters.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AdvancedAuditPolicy {
    /// Optional finite desired policy. Empty selects the built-in minimum.
    pub desired: Vec<DesiredAuditSubcategory>,
}

/// One parsed `auditpol /r` row.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct AuditSubcategoryObservation {
    /// Localized display name retained only as evidence.
    pub display_name: String,
    /// Canonical lowercase GUID used for comparisons.
    pub guid: String,
    /// Current success flag.
    pub success: bool,
    /// Current failure flag.
    pub failure: bool,
}

/// Native capability 33 evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct AdvancedAuditObservation {
    /// Complete bounded CSV parse or typed failure state.
    pub subcategories: Observation<Vec<AuditSubcategoryObservation>>,
}

/// Deterministic capability 33 audit/plan result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct AdvancedAuditResult {
    /// Native input evidence.
    pub observation: AdvancedAuditObservation,
    /// Effective desired settings, always GUID-bound.
    pub desired: Vec<DesiredAuditSubcategory>,
    /// Completeness and drift findings.
    pub findings: Vec<PolicyFinding>,
}

/// Validate a strict finite desired policy.
///
/// # Errors
///
/// Rejects too many, duplicate, or non-canonical GUID entries.
pub fn validate_advanced_audit_policy(policy: &AdvancedAuditPolicy) -> Result<(), &'static str> {
    if policy.desired.len() > 64 {
        return Err("desired audit policy exceeds 64 entries");
    }
    let mut seen = BTreeSet::new();
    for entry in &policy.desired {
        if !canonical_guid(&entry.guid) {
            return Err("audit subcategory GUID is not canonical lowercase text");
        }
        if !seen.insert(entry.guid.as_str()) {
            return Err("desired audit policy contains a duplicate GUID");
        }
    }
    Ok(())
}

/// Parse the fixed six-column `auditpol /get /category:* /r` report shape.
#[must_use]
pub fn parse_auditpol_csv(text: &str) -> Observation<Vec<AuditSubcategoryObservation>> {
    if text.is_empty() || text.len() > 1024 * 1024 {
        return Observation::Unparsed;
    }
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut reader = csv::ReaderBuilder::new()
        .flexible(false)
        .from_reader(text.as_bytes());
    let Ok(headers) = reader.headers() else {
        return Observation::Unparsed;
    };
    if headers.len() != 6 {
        return Observation::Unparsed;
    }
    let mut rows = Vec::new();
    let mut guids = BTreeSet::new();
    for row in reader.records() {
        let Ok(row) = row else {
            return Observation::Unparsed;
        };
        if row.len() != 6 || rows.len() == MAX_AUDIT_SUBCATEGORIES {
            return Observation::Truncated;
        }
        let Some(guid) = normalize_guid(&row[3]) else {
            return Observation::Unparsed;
        };
        let Some((success, failure)) = parse_setting(&row[4]) else {
            return Observation::Unparsed;
        };
        if row[2].trim().is_empty() || !guids.insert(guid.clone()) {
            return Observation::Unparsed;
        }
        rows.push(AuditSubcategoryObservation {
            display_name: row[2].trim().into(),
            guid,
            success,
            failure,
        });
    }
    if rows.len() < 10 {
        Observation::Unparsed
    } else {
        Observation::Present(rows)
    }
}

/// Evaluate current evidence against caller-supplied or built-in GUID policy.
#[must_use]
pub fn evaluate_advanced_audit(
    observation: AdvancedAuditObservation,
    policy: &AdvancedAuditPolicy,
) -> AdvancedAuditResult {
    let desired = if policy.desired.is_empty() {
        built_in_desired()
    } else {
        policy.desired.clone()
    };
    let mut findings = Vec::new();
    match &observation.subcategories {
        Observation::Present(rows) => evaluate_rows(rows, &desired, &mut findings),
        _ => findings.push(finding(
            "AUD-EvidenceIncomplete",
            FindingStatus::Fail,
            Severity::High,
            "Advanced Audit Policy evidence is incomplete or unparseable.",
        )),
    }
    AdvancedAuditResult {
        observation,
        desired,
        findings,
    }
}

fn evaluate_rows(
    rows: &[AuditSubcategoryObservation],
    desired: &[DesiredAuditSubcategory],
    findings: &mut Vec<PolicyFinding>,
) {
    let current = rows
        .iter()
        .map(|row| (row.guid.as_str(), row))
        .collect::<BTreeMap<_, _>>();
    for wanted in desired {
        let Some(actual) = current.get(wanted.guid.as_str()) else {
            findings.push(PolicyFinding {
                code: "AUD-DesiredNotFound",
                status: FindingStatus::Fail,
                severity: Severity::High,
                message: format!("Audit subcategory {} is absent.", wanted.guid),
                evidence: JsonMap::from([("subcategory_guid".into(), json!(wanted.guid))]),
            });
            continue;
        };
        if actual.success != wanted.success || actual.failure != wanted.failure {
            findings.push(PolicyFinding {
                code: "AUD-Drift",
                status: FindingStatus::Warning,
                severity: Severity::Medium,
                message: format!(
                    "Audit subcategory {} differs from desired flags.",
                    wanted.guid
                ),
                evidence: JsonMap::from([
                    ("subcategory_guid".into(), json!(wanted.guid)),
                    ("current_success".into(), json!(actual.success)),
                    ("current_failure".into(), json!(actual.failure)),
                    ("desired_success".into(), json!(wanted.success)),
                    ("desired_failure".into(), json!(wanted.failure)),
                ]),
            });
        }
    }
}

fn built_in_desired() -> Vec<DesiredAuditSubcategory> {
    [
        ("0cce9215-69ae-11d9-bed3-505054503030", true, true),
        ("0cce921b-69ae-11d9-bed3-505054503030", true, false),
        ("0cce922f-69ae-11d9-bed3-505054503030", true, true),
        ("0cce9240-69ae-11d9-bed3-505054503030", false, true),
        ("0cce9242-69ae-11d9-bed3-505054503030", false, true),
    ]
    .into_iter()
    .map(|(guid, success, failure)| DesiredAuditSubcategory {
        guid: guid.into(),
        success,
        failure,
    })
    .collect()
}

fn parse_setting(value: &str) -> Option<(bool, bool)> {
    match value.trim() {
        "Success and Failure" => Some((true, true)),
        "Success" => Some((true, false)),
        "Failure" => Some((false, true)),
        "No Auditing" => Some((false, false)),
        _ => None,
    }
}

fn normalize_guid(value: &str) -> Option<String> {
    let value = value.trim().trim_start_matches('{').trim_end_matches('}');
    let normalized = value.to_ascii_lowercase();
    canonical_guid(&normalized).then_some(normalized)
}

fn canonical_guid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
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
    use std::fmt::Write as _;

    fn fixture(setting: &str) -> String {
        let mut text =
            "Machine,Target,Subcategory,Subcategory GUID,Inclusion,Exclusion\n".to_owned();
        for index in 0..10 {
            let guid = format!("0cce92{index:02x}-69ae-11d9-bed3-505054503030");
            writeln!(text, "HOST,System,Item {index},{{{guid}}},{setting},")
                .expect("write fixture");
        }
        text
    }

    #[test]
    fn parser_is_bounded_and_fails_closed_on_localized_settings() {
        assert!(matches!(
            parse_auditpol_csv(&fixture("Success")),
            Observation::Present(_)
        ));
        assert_eq!(
            parse_auditpol_csv(&fixture("Erfolg")),
            Observation::Unparsed
        );
    }

    #[test]
    fn desired_input_is_guid_only_and_unique() {
        let invalid: AdvancedAuditPolicy = serde_json::from_value(json!({
            "desired":[{"guid":"Logon","success":true,"failure":true}]
        }))
        .expect("shape");
        assert!(validate_advanced_audit_policy(&invalid).is_err());
        assert!(
            serde_json::from_value::<AdvancedAuditPolicy>(json!({"path":"policy.json"})).is_err()
        );
    }
}
