//! Pure report model for a bounded client-security baseline subset.

use crate::{Observation, PolicyFinding, PolicyValueSnapshot};
use baselineops_domain::{FindingStatus, JsonMap, Severity};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;

/// Strict capability 42 parameters. External reference files are not accepted.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClientBaselinePolicy {}

/// Fixed registry field reported by the native capability 42 subset.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientBaselineField {
    /// Runtime VBS intent.
    RuntimeEnableVbs,
    /// Runtime required platform-security features.
    RuntimePlatformSecurity,
    /// Runtime LSA configuration flags.
    RuntimeLsaCfgFlags,
    /// Device Guard policy VBS intent.
    PolicyEnableVbs,
    /// Device Guard policy platform-security features.
    PolicyPlatformSecurity,
    /// Device Guard policy LSA configuration flags.
    PolicyLsaCfgFlags,
    /// LSA protected-process policy.
    RunAsPpl,
    /// Script Block Logging policy.
    ScriptBlockLogging,
    /// Script Block Invocation Logging policy.
    ScriptBlockInvocationLogging,
    /// Module Logging policy.
    ModuleLogging,
    /// Transcription policy.
    Transcription,
}

/// Native capability 42 evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ClientBaselineObservation {
    /// Fixed registry intent and policy values.
    pub values: BTreeMap<ClientBaselineField, Observation<PolicyValueSnapshot>>,
    /// Runtime Device Guard evidence, never inferred from registry intent.
    pub device_guard_runtime: Observation<bool>,
    /// Firewall profile evidence, pending a native firewall provider.
    pub firewall_profiles: Observation<bool>,
}

/// Deterministic capability 42 report.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ClientBaselineAudit {
    /// Native input evidence.
    pub observation: ClientBaselineObservation,
    /// Incomplete evidence findings; no built-in desired state is invented.
    pub findings: Vec<PolicyFinding>,
    /// Deliberate exclusions from this bounded subset.
    pub exclusions: Vec<&'static str>,
}

/// Evaluate report completeness without inventing reference-policy matches.
#[must_use]
pub fn evaluate_client_baseline(
    observation: ClientBaselineObservation,
    _policy: &ClientBaselinePolicy,
) -> ClientBaselineAudit {
    let mut findings = Vec::new();
    for (field, value) in &observation.values {
        if !matches!(value, Observation::Present(_)) {
            findings.push(PolicyFinding {
                code: "BASELINE-RegistryEvidenceIncomplete",
                status: FindingStatus::Warning,
                severity: Severity::Medium,
                message: format!("Registry evidence for {field:?} is incomplete."),
                evidence: JsonMap::from([("field".into(), json!(field))]),
            });
        }
    }
    for (code, label, value) in [
        (
            "BASELINE-DeviceGuardRuntimeExcluded",
            "Device Guard runtime",
            &observation.device_guard_runtime,
        ),
        (
            "BASELINE-FirewallProfilesExcluded",
            "firewall profile",
            &observation.firewall_profiles,
        ),
    ] {
        if !matches!(value, Observation::Present(_)) {
            findings.push(PolicyFinding {
                code,
                status: FindingStatus::Warning,
                severity: Severity::Medium,
                message: format!("{label} evidence is not available in this bounded subset."),
                evidence: JsonMap::from([("observation".into(), json!("not_run"))]),
            });
        }
    }
    ClientBaselineAudit {
        observation,
        findings,
        exclusions: vec![
            "operator-supplied reference JSON is not accepted",
            "Device Guard runtime WMI is not implemented",
            "native firewall-profile acquisition is not implemented",
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_parameters_and_missing_sources_are_explicit() {
        assert!(
            serde_json::from_value::<ClientBaselinePolicy>(json!({"reference":"file.json"}))
                .is_err()
        );
        let audit = evaluate_client_baseline(
            ClientBaselineObservation {
                values: BTreeMap::new(),
                device_guard_runtime: Observation::NotRun,
                firewall_profiles: Observation::NotRun,
            },
            &ClientBaselinePolicy {},
        );
        assert_eq!(audit.findings.len(), 2);
        assert_eq!(audit.exclusions.len(), 3);
    }
}
