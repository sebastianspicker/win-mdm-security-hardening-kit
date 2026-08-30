//! Pure policy for fixed Antimalware Scan Interface registry indicators.

use crate::{Observation, PolicyFinding, PolicyValueSnapshot};
use baselineops_domain::{FindingStatus, JsonMap, Severity};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Strict capability 50 parameters. The audit accepts no caller-selected paths.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AmsiPolicy {}

/// Native AMSI evidence collected from fixed registry locations.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct AmsiObservation {
    /// Registered provider CLSID subkeys, capped by acquisition.
    pub providers: Observation<Vec<String>>,
    /// Fixed machine environment bypass marker.
    pub bypass_environment: Observation<PolicyValueSnapshot>,
    /// Fixed PowerShell `DisableAMSI` policy value.
    pub disable_amsi_policy: Observation<PolicyValueSnapshot>,
    /// PowerShell Script Block Logging policy value.
    pub script_block_logging: Observation<PolicyValueSnapshot>,
    /// Machine-wide Windows Script Host enablement.
    pub wsh_machine_enabled: Observation<PolicyValueSnapshot>,
    /// Current-user Windows Script Host enablement.
    pub wsh_user_enabled: Observation<PolicyValueSnapshot>,
}

/// Deterministic capability 50 result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct AmsiAudit {
    /// Native input evidence.
    pub observation: AmsiObservation,
    /// Provider, bypass, logging, and completeness findings.
    pub findings: Vec<PolicyFinding>,
}

const DEFENDER_PROVIDER: &str = "{2781761E-28E0-4109-99FE-B9D127C57AFE}";

/// Evaluate fixed AMSI indicators without platform I/O.
#[must_use]
pub fn evaluate_amsi(observation: AmsiObservation, _policy: &AmsiPolicy) -> AmsiAudit {
    let mut findings = Vec::new();
    evaluate_providers(&observation.providers, &mut findings);
    evaluate_bypass(
        "AMSI-BypassEnvVar",
        "AMSI_BYPASS exists in the machine environment.",
        &observation.bypass_environment,
        &mut findings,
    );
    evaluate_bypass(
        "AMSI-PolicyDisabled",
        "DisableAMSI exists under the fixed PowerShell policy key.",
        &observation.disable_amsi_policy,
        &mut findings,
    );
    evaluate_script_logging(&observation.script_block_logging, &mut findings);
    evaluate_dword(
        "AMSI-WSHDisabledMachine",
        "Windows Script Host is disabled machine-wide.",
        &observation.wsh_machine_enabled,
        Some(0),
        &mut findings,
    );
    evaluate_dword(
        "AMSI-WSHDisabledUser",
        "Windows Script Host is disabled for the current user.",
        &observation.wsh_user_enabled,
        Some(0),
        &mut findings,
    );
    AmsiAudit {
        observation,
        findings,
    }
}

fn evaluate_providers(value: &Observation<Vec<String>>, findings: &mut Vec<PolicyFinding>) {
    match value {
        Observation::Present(providers) => {
            if !providers
                .iter()
                .any(|provider| provider.eq_ignore_ascii_case(DEFENDER_PROVIDER))
            {
                findings.push(finding(
                    "AMSI-DefenderMissing",
                    FindingStatus::Fail,
                    Severity::High,
                    "The Windows Defender AMSI provider is not registered.",
                ));
            }
            for provider in providers {
                if !provider.eq_ignore_ascii_case(DEFENDER_PROVIDER) {
                    findings.push(PolicyFinding {
                        code: "AMSI-UnknownProvider",
                        status: FindingStatus::Warning,
                        severity: Severity::Medium,
                        message: format!(
                            "AMSI provider {provider} is not the fixed Defender provider; verify its publisher."
                        ),
                        evidence: JsonMap::from([("provider_clsid".into(), json!(provider))]),
                    });
                }
            }
        }
        Observation::Missing => findings.push(finding(
            "AMSI-ProvidersKeyMissing",
            FindingStatus::Fail,
            Severity::High,
            "The AMSI Providers registry key is missing.",
        )),
        other => incomplete("AMSI-ProviderQueryIncomplete", other, findings),
    }
}

fn evaluate_bypass(
    code: &'static str,
    message: &'static str,
    value: &Observation<PolicyValueSnapshot>,
    findings: &mut Vec<PolicyFinding>,
) {
    match value {
        Observation::Present(PolicyValueSnapshot::Missing) => {}
        Observation::Present(_) => {
            findings.push(finding(code, FindingStatus::Fail, Severity::High, message));
        }
        other => incomplete("AMSI-BypassEvidenceIncomplete", other, findings),
    }
}

fn evaluate_dword(
    code: &'static str,
    message: &'static str,
    value: &Observation<PolicyValueSnapshot>,
    adverse: Option<u32>,
    findings: &mut Vec<PolicyFinding>,
) {
    match value {
        Observation::Present(PolicyValueSnapshot::Dword(actual)) if Some(*actual) == adverse => {
            findings.push(finding(
                code,
                FindingStatus::Warning,
                Severity::Medium,
                message,
            ));
        }
        Observation::Present(PolicyValueSnapshot::Dword(_) | PolicyValueSnapshot::Missing) => {}
        other => incomplete("AMSI-RegistryEvidenceIncomplete", other, findings),
    }
}

fn evaluate_script_logging(
    value: &Observation<PolicyValueSnapshot>,
    findings: &mut Vec<PolicyFinding>,
) {
    match value {
        Observation::Present(PolicyValueSnapshot::Dword(1)) => {}
        Observation::Present(PolicyValueSnapshot::Dword(_) | PolicyValueSnapshot::Missing) => {
            findings.push(finding(
                "AMSI-PSLoggingOff",
                FindingStatus::Warning,
                Severity::Medium,
                "PowerShell Script Block Logging is not enabled.",
            ));
        }
        other => incomplete("AMSI-RegistryEvidenceIncomplete", other, findings),
    }
}

fn incomplete<T>(code: &'static str, value: &Observation<T>, findings: &mut Vec<PolicyFinding>) {
    findings.push(PolicyFinding {
        code,
        status: FindingStatus::Warning,
        severity: Severity::Medium,
        message: "Required AMSI evidence is incomplete.".into(),
        evidence: JsonMap::from([("observation".into(), json!(observation_state(value)))]),
    });
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

#[cfg(test)]
mod tests {
    use super::*;

    fn complete() -> AmsiObservation {
        AmsiObservation {
            providers: Observation::Present(vec![DEFENDER_PROVIDER.into()]),
            bypass_environment: Observation::Present(PolicyValueSnapshot::Missing),
            disable_amsi_policy: Observation::Present(PolicyValueSnapshot::Missing),
            script_block_logging: Observation::Present(PolicyValueSnapshot::Dword(1)),
            wsh_machine_enabled: Observation::Present(PolicyValueSnapshot::Dword(1)),
            wsh_user_enabled: Observation::Present(PolicyValueSnapshot::Missing),
        }
    }

    #[test]
    fn strict_parameters_and_healthy_fixture_are_bounded() {
        assert!(serde_json::from_value::<AmsiPolicy>(json!({"path":"HKLM"})).is_err());
        assert!(
            evaluate_amsi(complete(), &AmsiPolicy {})
                .findings
                .is_empty()
        );
    }

    #[test]
    fn bypass_and_incomplete_provider_evidence_are_findings() {
        let mut observation = complete();
        observation.providers = Observation::AccessDenied;
        observation.disable_amsi_policy = Observation::Present(PolicyValueSnapshot::Dword(1));
        let audit = evaluate_amsi(observation, &AmsiPolicy {});
        assert!(
            audit
                .findings
                .iter()
                .any(|finding| finding.code == "AMSI-PolicyDisabled")
        );
        assert!(
            audit
                .findings
                .iter()
                .any(|finding| finding.code == "AMSI-ProviderQueryIncomplete")
        );
    }
}
