//! Pure, read-only evaluation for Windows Defender Application Guard readiness.

use crate::{Observation, PolicyFinding};
use baselineops_domain::{FindingStatus, JsonMap, Severity};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Strict parameter object for capability 47. No caller-selected command exists.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct WdagReadinessPolicy {}

/// Strictly parsed English DISM state for a queried optional feature.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OptionalFeatureState {
    /// The feature is installed and enabled.
    Enabled,
    /// The feature is known but disabled.
    Disabled,
    /// The feature is known but its payload has been removed.
    DisabledWithPayloadRemoved,
    /// DISM established that the feature name is absent on this installation.
    Absent,
}

/// Edition grouping relevant to interpreting an unavailable WDAG feature.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsEdition {
    /// A Windows Pro edition reported by `GetProductInfo`.
    Professional,
    /// Another edition code reported by `GetProductInfo`.
    Other(u32),
}

/// Native evidence required to assess WDAG readiness.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct WdagReadinessObservation {
    /// Hyper-V feature state from a fixed DISM query.
    pub hyper_v: Observation<OptionalFeatureState>,
    /// WDAG feature state from a fixed DISM query.
    pub wdag: Observation<OptionalFeatureState>,
    /// Product edition, retained to type a Pro feature absence as unsupported.
    pub edition: Observation<WindowsEdition>,
    /// Firmware virtualization indication from `IsProcessorFeaturePresent`.
    pub virtualization_firmware_enabled: Observation<bool>,
    /// Presence of the fixed `AppHVSI` policy key.
    pub policy_configured: Observation<bool>,
}

/// Deterministic capability 47 output.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct WdagReadinessAudit {
    /// Native input evidence.
    pub observation: WdagReadinessObservation,
    /// Readiness drift, unsupported edition, and incomplete-evidence findings.
    pub findings: Vec<PolicyFinding>,
}

/// Evaluate WDAG readiness without Windows I/O.
#[must_use]
pub fn evaluate_wdag_readiness(
    observation: WdagReadinessObservation,
    _policy: &WdagReadinessPolicy,
) -> WdagReadinessAudit {
    let mut findings = Vec::new();
    evaluate_feature(
        "WDAG-HyperV",
        "Hyper-V",
        &observation.hyper_v,
        &mut findings,
    );
    evaluate_wdag_feature(&observation.wdag, &observation.edition, &mut findings);
    evaluate_bool(
        "WDAG-VirtualizationFirmware",
        "Hardware virtualization is not enabled in firmware.",
        &observation.virtualization_firmware_enabled,
        &mut findings,
    );
    evaluate_bool(
        "WDAG-Policy",
        "The AppHVSI policy key is not configured; confirm intended WDAG isolation policy.",
        &observation.policy_configured,
        &mut findings,
    );
    WdagReadinessAudit {
        observation,
        findings,
    }
}

fn evaluate_feature(
    code: &'static str,
    label: &'static str,
    value: &Observation<OptionalFeatureState>,
    findings: &mut Vec<PolicyFinding>,
) {
    match value {
        Observation::Present(OptionalFeatureState::Enabled) => {}
        Observation::Present(
            OptionalFeatureState::Disabled | OptionalFeatureState::DisabledWithPayloadRemoved,
        ) => {
            findings.push(finding(
                code,
                FindingStatus::Warning,
                Severity::Medium,
                format!("{label} is available but not enabled."),
            ));
        }
        Observation::Present(OptionalFeatureState::Absent) => findings.push(finding(
            code,
            FindingStatus::Warning,
            Severity::Medium,
            format!("{label} is absent; readiness cannot be established."),
        )),
        value => incomplete(code, value, findings),
    }
}

fn evaluate_wdag_feature(
    wdag: &Observation<OptionalFeatureState>,
    edition: &Observation<WindowsEdition>,
    findings: &mut Vec<PolicyFinding>,
) {
    if matches!(wdag, Observation::Present(OptionalFeatureState::Absent))
        && matches!(edition, Observation::Present(WindowsEdition::Professional))
    {
        findings.push(finding(
            "WDAG-FeatureUnsupportedOnPro",
            FindingStatus::Skipped,
            Severity::Low,
            "WDAG is absent on this Pro installation; the capability is typed unsupported, not healthy.",
        ));
        return;
    }
    evaluate_feature(
        "WDAG-Feature",
        "Windows Defender Application Guard",
        wdag,
        findings,
    );
    if matches!(wdag, Observation::Present(OptionalFeatureState::Absent)) {
        match edition {
            Observation::Present(_) => {}
            value => incomplete("WDAG-Edition", value, findings),
        }
    }
}

fn evaluate_bool(
    code: &'static str,
    false_message: &'static str,
    value: &Observation<bool>,
    findings: &mut Vec<PolicyFinding>,
) {
    match value {
        Observation::Present(true) => {}
        Observation::Present(false) => findings.push(finding(
            code,
            FindingStatus::Warning,
            Severity::Medium,
            false_message,
        )),
        value => incomplete(code, value, findings),
    }
}

fn incomplete<T>(code: &'static str, value: &Observation<T>, findings: &mut Vec<PolicyFinding>) {
    findings.push(finding(
        code,
        FindingStatus::Error,
        Severity::Medium,
        format!(
            "Required WDAG readiness evidence is incomplete: {}.",
            observation_state(value)
        ),
    ));
}

fn finding(
    code: &'static str,
    status: FindingStatus,
    severity: Severity,
    message: impl Into<String>,
) -> PolicyFinding {
    PolicyFinding {
        code,
        status,
        severity,
        message: message.into(),
        evidence: JsonMap::from([("read_only".into(), json!(true))]),
    }
}

fn observation_state<T>(value: &Observation<T>) -> &'static str {
    match value {
        Observation::Present(_) => "present",
        Observation::Missing => "missing",
        Observation::AccessDenied => "access denied",
        Observation::TimedOut => "timed out",
        Observation::Truncated => "truncated",
        Observation::Failed { .. } => "failed",
        Observation::NotRun => "not run",
        Observation::Unparsed => "unparsed or localized",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled() -> WdagReadinessObservation {
        WdagReadinessObservation {
            hyper_v: Observation::Present(OptionalFeatureState::Enabled),
            wdag: Observation::Present(OptionalFeatureState::Enabled),
            edition: Observation::Present(WindowsEdition::Other(4)),
            virtualization_firmware_enabled: Observation::Present(true),
            policy_configured: Observation::Present(true),
        }
    }

    #[test]
    fn pro_feature_absence_is_typed_unsupported_not_healthy() {
        let mut observation = enabled();
        observation.wdag = Observation::Present(OptionalFeatureState::Absent);
        observation.edition = Observation::Present(WindowsEdition::Professional);
        let audit = evaluate_wdag_readiness(observation, &WdagReadinessPolicy::default());
        assert!(
            audit
                .findings
                .iter()
                .any(|item| item.code == "WDAG-FeatureUnsupportedOnPro")
        );
    }

    #[test]
    fn unparsed_or_denied_evidence_is_never_healthy() {
        let mut observation = enabled();
        observation.wdag = Observation::Unparsed;
        observation.virtualization_firmware_enabled = Observation::AccessDenied;
        let audit = evaluate_wdag_readiness(observation, &WdagReadinessPolicy::default());
        assert_eq!(audit.findings.len(), 2);
        assert!(
            audit
                .findings
                .iter()
                .all(|item| item.status == FindingStatus::Error)
        );
    }
}
