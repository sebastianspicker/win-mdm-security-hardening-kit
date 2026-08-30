//! Pure policy evaluators for registry-backed read-only capabilities.

use baselineops_domain::{FindingStatus, JsonMap, Severity};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeSet;

/// A deterministic finding before run/action identities and timestamps are attached by the engine.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct PolicyFinding {
    /// Stable capability-defined finding code.
    pub code: &'static str,
    /// Pass, warning, failure, or informational classification.
    pub status: FindingStatus,
    /// Operator-impact severity.
    pub severity: Severity,
    /// Bounded operator-facing explanation.
    pub message: String,
    /// Structured evidence without execution authority.
    pub evidence: JsonMap,
}

/// Normalized registry observation for the DNS-over-HTTPS client audit.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct DohObservation {
    /// `EnableAutoDoh`, or `None` when absent.
    pub enable_auto_doh: Option<u32>,
    /// Configured resolver addresses after `REG_SZ/REG_MULTI_SZ` tokenization.
    pub name_servers: Vec<String>,
    /// Bootstrap addresses after tokenization.
    pub bootstrap_addresses: Vec<String>,
    /// `BlockUntrustedDoh`, or `None` when absent.
    pub block_untrusted_doh: Option<u32>,
    /// Whether reading the resolver value failed rather than returning missing.
    pub server_query_failed: bool,
}

/// Policy result for the DNS-over-HTTPS client audit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct DohAudit {
    /// Stable display label for the observed mode.
    pub mode: String,
    /// Unique configured resolver tokens.
    pub name_servers: Vec<String>,
    /// Resolvers outside the legacy well-known allowlist.
    pub unknown_resolvers: Vec<String>,
    /// Unique bootstrap address tokens.
    pub bootstrap_addresses: Vec<String>,
    /// Deterministic findings.
    pub findings: Vec<PolicyFinding>,
}

/// Evaluate the legacy `DoH` policy without platform I/O.
#[must_use]
pub fn evaluate_doh(observation: &DohObservation) -> DohAudit {
    let name_servers = normalized_tokens(&observation.name_servers);
    let bootstrap_addresses = normalized_tokens(&observation.bootstrap_addresses);
    let mut findings = Vec::new();
    let mode = evaluate_doh_mode(observation.enable_auto_doh, &mut findings);
    evaluate_server_presence(observation, &name_servers, &mut findings);
    let unknown_resolvers = evaluate_resolvers(&name_servers, &mut findings);
    evaluate_fallback(observation, &name_servers, &mut findings);

    DohAudit {
        mode,
        name_servers,
        unknown_resolvers,
        bootstrap_addresses,
        findings,
    }
}

fn evaluate_server_presence(
    observation: &DohObservation,
    name_servers: &[String],
    findings: &mut Vec<PolicyFinding>,
) {
    if observation.server_query_failed {
        findings.push(finding(
            "DOH-ServerQueryFailed",
            FindingStatus::Error,
            Severity::Low,
            "DohNameServers could not be queried.",
            JsonMap::new(),
        ));
    } else if name_servers.is_empty() && observation.enable_auto_doh == Some(1) {
        findings.push(finding(
            "DOH-NoServersConfigured",
            FindingStatus::Fail,
            Severity::High,
            "Explicit DoH mode is enabled without a configured resolver.",
            JsonMap::new(),
        ));
    }
}

fn evaluate_resolvers(name_servers: &[String], findings: &mut Vec<PolicyFinding>) -> Vec<String> {
    let known = known_doh_resolvers();
    let mut unknown_resolvers = Vec::new();
    for server in name_servers {
        let recognized = known.contains(server.as_str());
        if !recognized {
            unknown_resolvers.push(server.clone());
        }
        findings.push(finding(
            if recognized {
                "DOH-KnownResolver"
            } else {
                "DOH-UnknownResolver"
            },
            if recognized {
                FindingStatus::Pass
            } else {
                FindingStatus::Warning
            },
            if recognized {
                Severity::Low
            } else {
                Severity::Medium
            },
            if recognized {
                format!("DoH resolver {server} is in the well-known resolver set.")
            } else {
                format!("DoH resolver {server} is not in the well-known resolver set.")
            },
            JsonMap::from([("resolver".into(), json!(server))]),
        ));
    }
    unknown_resolvers
}

fn evaluate_fallback(
    observation: &DohObservation,
    name_servers: &[String],
    findings: &mut Vec<PolicyFinding>,
) {
    if observation.enable_auto_doh.is_some_and(|mode| mode > 0) && !name_servers.is_empty() {
        let blocked = observation.block_untrusted_doh == Some(1);
        findings.push(finding(
            if blocked {
                "DOH-FallbackBlocked"
            } else {
                "DOH-FallbackAllowed"
            },
            if blocked {
                FindingStatus::Pass
            } else {
                FindingStatus::Warning
            },
            if blocked {
                Severity::Low
            } else {
                Severity::Medium
            },
            if blocked {
                "Plaintext DNS fallback is prohibited when DoH fails."
            } else {
                "Plaintext DNS fallback may be permitted when DoH fails."
            },
            JsonMap::new(),
        ));
    }
}

fn evaluate_doh_mode(value: Option<u32>, findings: &mut Vec<PolicyFinding>) -> String {
    let (mode, code, status, severity, message) = match value {
        None => (
            "NotConfigured".into(),
            "DOH-NotConfigured",
            FindingStatus::Warning,
            Severity::Medium,
            "DoH is not explicitly configured; plaintext DNS may be used.".into(),
        ),
        Some(0) => (
            "Disabled".into(),
            "DOH-Disabled",
            FindingStatus::Fail,
            Severity::High,
            "DoH is explicitly disabled.".into(),
        ),
        Some(1) => (
            "Enabled (Explicit)".into(),
            "DOH-EnabledExplicit",
            FindingStatus::Pass,
            Severity::Low,
            "DoH explicit mode is enabled.".into(),
        ),
        Some(2) => (
            "Enabled (Automatic)".into(),
            "DOH-EnabledAutomatic",
            FindingStatus::Pass,
            Severity::Low,
            "DoH automatic mode is enabled.".into(),
        ),
        Some(other) => (
            format!("Unknown({other})"),
            "DOH-UnknownValue",
            FindingStatus::Warning,
            Severity::Medium,
            format!("EnableAutoDoh has unexpected value {other}."),
        ),
    };
    findings.push(finding(code, status, severity, message, JsonMap::new()));
    mode
}

/// Strict NTLM audit policy supplied after command/profile normalization.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, rename_all = "snake_case", deny_unknown_fields)]
pub struct NtlmPolicy {
    /// Minimum accepted compatibility level, 0 through 5.
    pub minimum_level: u8,
    /// Severity when the level is below the minimum.
    pub severity_too_low: Severity,
    /// Severity when LM is permitted.
    pub severity_lm_allowed: Severity,
    /// Severity when `NTLMv1` client authentication is implied.
    pub severity_ntlm_v1: Severity,
    /// Emit informational findings for compliant levels.
    pub emit_info_findings: bool,
}

impl Default for NtlmPolicy {
    fn default() -> Self {
        Self {
            minimum_level: 3,
            severity_too_low: Severity::High,
            severity_lm_allowed: Severity::High,
            severity_ntlm_v1: Severity::Medium,
            emit_info_findings: true,
        }
    }
}

/// Policy result for the NTLM client audit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct NtlmAudit {
    /// Raw configured level, or `None` when policy is absent.
    pub level: Option<u32>,
    /// Stable legacy-compatible display text.
    pub description: String,
    /// Deterministic findings.
    pub findings: Vec<PolicyFinding>,
}

/// Evaluate `LmCompatibilityLevel` without platform I/O.
///
/// # Errors
///
/// Rejects a minimum outside the Windows-defined range 0 through 5.
pub fn evaluate_ntlm(level: Option<u32>, policy: &NtlmPolicy) -> Result<NtlmAudit, &'static str> {
    if policy.minimum_level > 5 {
        return Err("minimum_level must be between 0 and 5");
    }
    let description = ntlm_level_description(level);
    let mut findings = Vec::new();
    match level {
        None => findings.push(finding(
            "NTLM-LmCompatibilityNotDefined",
            FindingStatus::Info,
            Severity::Info,
            "LmCompatibilityLevel is not defined; validate effective policy through GPO/RSOP.",
            JsonMap::new(),
        )),
        Some(value) => evaluate_configured_ntlm(value, policy, &description, &mut findings),
    }
    Ok(NtlmAudit {
        level,
        description,
        findings,
    })
}

fn evaluate_configured_ntlm(
    value: u32,
    policy: &NtlmPolicy,
    description: &str,
    findings: &mut Vec<PolicyFinding>,
) {
    let evidence = || {
        JsonMap::from([
            ("level".into(), json!(value)),
            ("minimum_level".into(), json!(policy.minimum_level)),
        ])
    };
    if value < u32::from(policy.minimum_level) {
        findings.push(finding(
            "NTLM-LmCompatibilityTooLow",
            FindingStatus::Fail,
            policy.severity_too_low,
            format!(
                "LmCompatibilityLevel={value} ({description}) is below MinimumLevel={}.",
                policy.minimum_level
            ),
            evidence(),
        ));
    }
    match value {
        0 | 1 => findings.push(finding(
            "NTLM-LMAllowed",
            FindingStatus::Fail,
            policy.severity_lm_allowed,
            format!("LmCompatibilityLevel={value} ({description}) allows LM/NTLM."),
            evidence(),
        )),
        2 => findings.push(finding(
            "NTLM-NTLMv1ClientAuth",
            FindingStatus::Fail,
            policy.severity_ntlm_v1,
            "LmCompatibilityLevel=2 implies NTLMv1 client authentication.",
            evidence(),
        )),
        3 | 4 if policy.emit_info_findings => findings.push(finding(
            "NTLM-NTLMv2ClientOnly",
            FindingStatus::Info,
            Severity::Info,
            format!("LmCompatibilityLevel={value} ({description}) uses NTLMv2 for clients."),
            evidence(),
        )),
        5 if policy.emit_info_findings => findings.push(finding(
            "NTLM-Strictest",
            FindingStatus::Info,
            Severity::Info,
            "LmCompatibilityLevel=5 refuses LM and NTLM.",
            evidence(),
        )),
        _ => {}
    }
}

fn ntlm_level_description(level: Option<u32>) -> String {
    match level {
        None => "Not defined (registry value missing)".into(),
        Some(0) => "Send LM & NTLM responses".into(),
        Some(1) => "Send LM & NTLM - use NTLMv2 session security if negotiated".into(),
        Some(2) => "Send NTLM responses only".into(),
        Some(3) => "Send NTLMv2 responses only".into(),
        Some(4) => "Send NTLMv2 responses only. Refuse LM".into(),
        Some(5) => "Send NTLMv2 responses only. Refuse LM & NTLM".into(),
        Some(other) => format!("Unknown({other})"),
    }
}

fn normalized_tokens(values: &[String]) -> Vec<String> {
    values
        .iter()
        .flat_map(|value| value.split_whitespace())
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn known_doh_resolvers() -> BTreeSet<&'static str> {
    [
        "1.1.1.1",
        "1.0.0.1",
        "2606:4700:4700::1111",
        "2606:4700:4700::1001",
        "8.8.8.8",
        "8.8.4.4",
        "2001:4860:4860::8888",
        "2001:4860:4860::8844",
        "9.9.9.9",
        "149.112.112.112",
        "2620:fe::fe",
        "2620:fe::9",
        "208.67.222.222",
        "208.67.220.220",
    ]
    .into_iter()
    .collect()
}

fn finding(
    code: &'static str,
    status: FindingStatus,
    severity: Severity,
    message: impl Into<String>,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doh_explicit_mode_requires_servers() {
        let audit = evaluate_doh(&DohObservation {
            enable_auto_doh: Some(1),
            ..DohObservation::default()
        });
        assert!(audit.findings.iter().any(|finding| {
            finding.code == "DOH-NoServersConfigured" && finding.severity == Severity::High
        }));
    }

    #[test]
    fn doh_normalizes_and_classifies_resolvers_and_fallback() {
        let audit = evaluate_doh(&DohObservation {
            enable_auto_doh: Some(2),
            name_servers: vec!["1.1.1.1 192.0.2.53".into(), "1.1.1.1".into()],
            block_untrusted_doh: Some(0),
            ..DohObservation::default()
        });
        assert_eq!(audit.name_servers, ["1.1.1.1", "192.0.2.53"]);
        assert_eq!(audit.unknown_resolvers, ["192.0.2.53"]);
        assert!(
            audit
                .findings
                .iter()
                .any(|finding| finding.code == "DOH-FallbackAllowed")
        );
    }

    #[test]
    fn ntlm_missing_is_informational() {
        let audit = evaluate_ntlm(None, &NtlmPolicy::default()).expect("valid policy");
        assert_eq!(audit.findings.len(), 1);
        assert_eq!(audit.findings[0].status, FindingStatus::Info);
    }

    #[test]
    fn ntlm_levels_match_legacy_policy_edges() {
        let policy = NtlmPolicy::default();
        let weak = evaluate_ntlm(Some(1), &policy).expect("valid policy");
        assert_eq!(
            weak.findings
                .iter()
                .map(|finding| finding.code)
                .collect::<Vec<_>>(),
            ["NTLM-LmCompatibilityTooLow", "NTLM-LMAllowed"]
        );
        let strict = evaluate_ntlm(Some(5), &policy).expect("valid policy");
        assert_eq!(strict.findings[0].code, "NTLM-Strictest");
    }

    #[test]
    fn ntlm_rejects_invalid_minimum() {
        let policy = NtlmPolicy {
            minimum_level: 6,
            ..NtlmPolicy::default()
        };
        assert!(evaluate_ntlm(Some(5), &policy).is_err());
    }
}
