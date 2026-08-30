//! Pure policy for bounded, read-only installed-software inventory.

use crate::{Observation, PolicyFinding};
use baselineops_domain::{FindingStatus, JsonMap, Severity};
use serde::Serialize;
use serde_json::json;
use std::collections::BTreeSet;

/// Maximum retained uninstall entries across both registry views.
pub const MAX_SOFTWARE_RECORDS: usize = 4_096;

/// The registry view used to observe an uninstall entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SoftwareRegistryView {
    /// Native 64-bit HKLM uninstall view.
    Registry64,
    /// `WOW6432Node` / 32-bit HKLM uninstall view.
    Registry32,
}

/// A safe, read-only uninstall-registry record. Uninstall command strings are never retained.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct SoftwareInventoryRecord {
    /// Registry view from which the key was read.
    pub source_view: SoftwareRegistryView,
    /// Registry subkey name; this is not an executable command.
    pub key_name: String,
    /// Product display name, when the value was present and readable.
    pub display_name: Observation<String>,
    /// Product display version, when supplied.
    pub display_version: Observation<String>,
    /// Product publisher, when supplied.
    pub publisher: Observation<String>,
}

/// Bounded inventory before deterministic de-duplication.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct SoftwareInventoryObservation {
    /// Retained entries from both HKLM uninstall views.
    pub records: Vec<Observation<SoftwareInventoryRecord>>,
    /// Whether both registry-view enumerations completed within their bounds.
    pub enumeration_complete: bool,
}

/// Read-only installed-software audit result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct SoftwareInventoryAudit {
    /// Original native observations, including missing fields and access denials.
    pub observation: SoftwareInventoryObservation,
    /// De-duplicated records retaining their source-view evidence.
    pub records: Vec<SoftwareInventoryRecord>,
    /// Typed incomplete-evidence findings. No finding is a health assertion.
    pub findings: Vec<PolicyFinding>,
}

/// Evaluate bounded uninstall observations without platform I/O.
#[must_use]
pub fn evaluate_software_inventory(
    observation: SoftwareInventoryObservation,
) -> SoftwareInventoryAudit {
    let mut findings = Vec::new();
    let mut seen = BTreeSet::new();
    let mut records = Vec::new();
    for record in observation.records.iter().take(MAX_SOFTWARE_RECORDS) {
        let Observation::Present(record) = record else {
            incomplete(
                &mut findings,
                "INV-SoftwareRecordIncomplete",
                "software record",
                record,
            );
            continue;
        };
        incomplete(
            &mut findings,
            "INV-SoftwareNameIncomplete",
            "software display name",
            &record.display_name,
        );
        incomplete(
            &mut findings,
            "INV-SoftwareVersionIncomplete",
            "software display version",
            &record.display_version,
        );
        incomplete(
            &mut findings,
            "INV-SoftwarePublisherIncomplete",
            "software publisher",
            &record.publisher,
        );
        let identity = identity(record);
        if seen.insert(identity) {
            records.push(record.clone());
        }
    }
    if !observation.enumeration_complete || observation.records.len() > MAX_SOFTWARE_RECORDS {
        findings.push(finding(
            "INV-SoftwareEnumerationIncomplete",
            "Uninstall-registry enumeration did not complete within its bounded record limit.",
        ));
    }
    SoftwareInventoryAudit {
        observation,
        records,
        findings,
    }
}

fn identity(record: &SoftwareInventoryRecord) -> (String, String, String) {
    fn value(field: &Observation<String>, fallback: &str) -> String {
        match field {
            Observation::Present(value) => value.trim().to_ascii_lowercase(),
            _ => fallback.to_ascii_lowercase(),
        }
    }
    (
        value(&record.display_name, &record.key_name),
        value(&record.display_version, ""),
        value(&record.publisher, ""),
    )
}

fn incomplete<T>(
    findings: &mut Vec<PolicyFinding>,
    code: &'static str,
    label: &str,
    value: &Observation<T>,
) {
    if matches!(value, Observation::Present(_)) {
        return;
    }
    findings.push(PolicyFinding {
        code,
        status: FindingStatus::Warning,
        severity: Severity::Medium,
        message: format!("{label} observation is incomplete: {}.", status(value)),
        evidence: JsonMap::from([("observation_status".into(), json!(status(value)))]),
    });
}

fn status<T>(value: &Observation<T>) -> &'static str {
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

fn finding(code: &'static str, message: &str) -> PolicyFinding {
    PolicyFinding {
        code,
        status: FindingStatus::Warning,
        severity: Severity::Medium,
        message: message.into(),
        evidence: JsonMap::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(view: SoftwareRegistryView) -> SoftwareInventoryRecord {
        SoftwareInventoryRecord {
            source_view: view,
            key_name: "Vendor.App".into(),
            display_name: Observation::Present("Vendor App".into()),
            display_version: Observation::Present("1.0".into()),
            publisher: Observation::Present("Vendor".into()),
        }
    }

    #[test]
    fn deduplicates_across_registry_views_without_retaining_commands() {
        let audit = evaluate_software_inventory(SoftwareInventoryObservation {
            records: vec![
                Observation::Present(record(SoftwareRegistryView::Registry64)),
                Observation::Present(record(SoftwareRegistryView::Registry32)),
            ],
            enumeration_complete: true,
        });
        assert_eq!(audit.records.len(), 1);
        assert!(audit.findings.is_empty());
    }

    #[test]
    fn missing_display_name_remains_typed_incomplete_evidence() {
        let mut item = record(SoftwareRegistryView::Registry64);
        item.display_name = Observation::Missing;
        let audit = evaluate_software_inventory(SoftwareInventoryObservation {
            records: vec![Observation::Present(item)],
            enumeration_complete: true,
        });
        assert_eq!(audit.findings[0].code, "INV-SoftwareNameIncomplete");
    }
}
