//! Pure policy for fixed `AppLocker` registry and service indicators.

use crate::{Observation, PolicyFinding, ServiceObservation};
use baselineops_domain::{FindingStatus, JsonMap, Severity};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;

/// Strict capability 51 parameters. Collection names are compile-time fixed.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AppLockerPolicy {}

/// Fixed `AppLocker` rule collection.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AppLockerCollection {
    /// Executable rules.
    Exe,
    /// Windows Installer rules.
    Msi,
    /// Script rules.
    Script,
    /// Dynamic-link library rules.
    Dll,
    /// Packaged application rules.
    Appx,
}

/// Registry evidence for one fixed collection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct AppLockerCollectionObservation {
    /// `EnforcementMode`: 0 not configured, 1 enforced, 2 audit only.
    pub enforcement_mode: Observation<u32>,
    /// Number of immediate rule subkeys, capped by acquisition.
    pub rule_count: Observation<u32>,
}

/// Native capability 51 evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct AppLockerObservation {
    /// Whether the fixed `SrpV2` policy root exists.
    pub configured: Observation<bool>,
    /// Application Identity service state.
    pub application_identity: Observation<ServiceObservation>,
    /// All five fixed rule collections.
    pub collections: BTreeMap<AppLockerCollection, AppLockerCollectionObservation>,
}

/// Deterministic capability 51 result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct AppLockerAudit {
    /// Native input evidence.
    pub observation: AppLockerObservation,
    /// Enforcement, rule, service, and completeness findings.
    pub findings: Vec<PolicyFinding>,
}

/// Evaluate `AppLocker` indicators without platform I/O.
#[must_use]
pub fn evaluate_applocker(
    observation: AppLockerObservation,
    _policy: &AppLockerPolicy,
) -> AppLockerAudit {
    let mut findings = Vec::new();
    match observation.configured {
        Observation::Present(false) | Observation::Missing => findings.push(finding(
            "APPLOCK-NotConfigured",
            FindingStatus::Warning,
            Severity::Medium,
            "No AppLocker policy is configured.",
        )),
        Observation::Present(true) => evaluate_collections(&observation, &mut findings),
        ref other => incomplete("APPLOCK-ConfigurationIncomplete", other, &mut findings),
    }
    AppLockerAudit {
        observation,
        findings,
    }
}

fn evaluate_collections(observation: &AppLockerObservation, findings: &mut Vec<PolicyFinding>) {
    let mut summary = CollectionSummary::default();
    for collection in all_collections() {
        let Some(value) = observation.collections.get(&collection) else {
            findings.push(finding(
                "APPLOCK-CollectionMissing",
                FindingStatus::Warning,
                Severity::Medium,
                "A fixed AppLocker collection observation is missing.",
            ));
            continue;
        };
        summary.add(evaluate_collection(collection, value, findings));
    }
    if summary.enforced == 0 && summary.audit_only > 0 {
        findings.push(finding(
            "APPLOCK-AllAuditOnly",
            FindingStatus::Fail,
            Severity::High,
            "No observed AppLocker collection is enforced.",
        ));
    }
    if summary.total_rules > 0 && !service_running(&observation.application_identity) {
        findings.push(finding(
            "APPLOCK-AppIDSvcStopped",
            FindingStatus::Fail,
            Severity::High,
            "AppLocker rules exist but Application Identity is not running.",
        ));
    }
}

#[derive(Clone, Copy, Default)]
struct CollectionSummary {
    total_rules: u32,
    enforced: u8,
    audit_only: u8,
}

impl CollectionSummary {
    fn add(&mut self, other: Self) {
        self.total_rules = self.total_rules.saturating_add(other.total_rules);
        self.enforced = self.enforced.saturating_add(other.enforced);
        self.audit_only = self.audit_only.saturating_add(other.audit_only);
    }
}

fn evaluate_collection(
    collection: AppLockerCollection,
    value: &AppLockerCollectionObservation,
    findings: &mut Vec<PolicyFinding>,
) -> CollectionSummary {
    let total_rules = match value.rule_count {
        Observation::Present(count) => count,
        ref incomplete_value => {
            incomplete("APPLOCK-RuleCountIncomplete", incomplete_value, findings);
            0
        }
    };
    let (enforced, audit_only) =
        evaluate_enforcement(collection, &value.enforcement_mode, findings);
    CollectionSummary {
        total_rules,
        enforced,
        audit_only,
    }
}

fn evaluate_enforcement(
    collection: AppLockerCollection,
    mode: &Observation<u32>,
    findings: &mut Vec<PolicyFinding>,
) -> (u8, u8) {
    match mode {
        Observation::Present(1) => (1, 0),
        Observation::Present(2) => {
            findings.push(finding(
                "APPLOCK-CollectionAuditOnly",
                FindingStatus::Warning,
                Severity::Medium,
                "An AppLocker collection is audit-only and does not enforce its rules.",
            ));
            (0, 1)
        }
        Observation::Present(0) | Observation::Missing => {
            not_configured(collection, findings);
            (0, 0)
        }
        incomplete_value => {
            incomplete(
                "APPLOCK-EnforcementModeIncomplete",
                incomplete_value,
                findings,
            );
            (0, 0)
        }
    }
}

fn not_configured(collection: AppLockerCollection, findings: &mut Vec<PolicyFinding>) {
    let executable = collection == AppLockerCollection::Exe;
    findings.push(finding(
        if executable {
            "APPLOCK-Exe-NotConfigured"
        } else {
            "APPLOCK-CollectionNotConfigured"
        },
        FindingStatus::Warning,
        if executable {
            Severity::High
        } else {
            Severity::Low
        },
        "An AppLocker collection is not configured.",
    ));
}

fn service_running(value: &Observation<ServiceObservation>) -> bool {
    matches!(
        value,
        Observation::Present(service)
            if service.state == crate::ServiceState::Running
    )
}

const fn all_collections() -> [AppLockerCollection; 5] {
    [
        AppLockerCollection::Exe,
        AppLockerCollection::Msi,
        AppLockerCollection::Script,
        AppLockerCollection::Dll,
        AppLockerCollection::Appx,
    ]
}

fn incomplete<T>(code: &'static str, _value: &Observation<T>, findings: &mut Vec<PolicyFinding>) {
    findings.push(finding(
        code,
        FindingStatus::Warning,
        Severity::Medium,
        "Required AppLocker evidence is incomplete.",
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
    use crate::{ServiceStartMode, ServiceState};

    fn collection(mode: u32, rules: u32) -> AppLockerCollectionObservation {
        AppLockerCollectionObservation {
            enforcement_mode: Observation::Present(mode),
            rule_count: Observation::Present(rules),
        }
    }

    fn observation(mode: u32) -> AppLockerObservation {
        AppLockerObservation {
            configured: Observation::Present(true),
            application_identity: Observation::Present(ServiceObservation {
                name: "AppIDSvc".into(),
                state: ServiceState::Running,
                start_mode: ServiceStartMode::Manual,
            }),
            collections: all_collections()
                .into_iter()
                .map(|name| (name, collection(mode, 1)))
                .collect(),
        }
    }

    #[test]
    fn strict_parameters_and_enforced_fixture_are_bounded() {
        assert!(serde_json::from_value::<AppLockerPolicy>(json!({"collection":"Exe"})).is_err());
        assert!(
            evaluate_applocker(observation(1), &AppLockerPolicy {})
                .findings
                .is_empty()
        );
    }

    #[test]
    fn audit_only_and_stopped_service_are_findings() {
        let mut input = observation(2);
        if let Observation::Present(service) = &mut input.application_identity {
            service.state = ServiceState::Stopped;
        }
        let audit = evaluate_applocker(input, &AppLockerPolicy {});
        assert!(
            audit
                .findings
                .iter()
                .any(|finding| finding.code == "APPLOCK-AllAuditOnly")
        );
        assert!(
            audit
                .findings
                .iter()
                .any(|finding| finding.code == "APPLOCK-AppIDSvcStopped")
        );
    }
}
