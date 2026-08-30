use baselineops_capabilities::{
    CapabilityDescriptor, CapabilityExecutor, CapabilityOutcome, CapabilityRequest, Operation,
};
use baselineops_windows::{DefenderHealthObservation, IdentityObservation, PlatformError};
use serde::{Deserialize, Serialize};

const DEFAULT_SIGNATURE_AGE_DAYS: u32 = 3;
const DEFAULT_QUICK_SCAN_AGE_DAYS: u32 = 14;
const DEFAULT_FULL_SCAN_AGE_DAYS: u32 = 30;
const MAX_AGE_DAYS: u32 = 3650;

/// Native Windows executor for the two Wave 1 read-only vertical slices.
///
/// Registry maturity remains `in_development` until authoritative Windows VM evidence is retained.
pub struct WaveOneWindowsExecutor;

impl CapabilityExecutor for WaveOneWindowsExecutor {
    fn execute(
        &self,
        descriptor: &'static CapabilityDescriptor,
        request: CapabilityRequest<'_>,
    ) -> CapabilityOutcome {
        if request.operation != Operation::Audit {
            return failed(descriptor, "Wave 1 executor is read-only");
        }
        let result = match descriptor.id {
            "v3.identity.join" => execute_identity(request),
            "v3.defender.health" => execute_defender(request),
            _ => Err(PlatformError::TrustFailure(
                "capability is not implemented by the Wave 1 executor".into(),
            )),
        };
        match result {
            Ok(result) => CapabilityOutcome::Completed { result },
            Err(error) => failed(descriptor, &error.to_string()),
        }
    }
}

fn execute_identity(request: CapabilityRequest<'_>) -> Result<serde_json::Value, PlatformError> {
    let parameters: IdentityParameters = parse_parameters(request.parameters, "identity")?;
    let observation = baselineops_windows::audit_identity()?;
    to_json(evaluate_identity(&observation, parameters.effective()?))
}

fn execute_defender(request: CapabilityRequest<'_>) -> Result<serde_json::Value, PlatformError> {
    let parameters: DefenderParameters = parse_parameters(request.parameters, "Defender")?;
    let observation = baselineops_windows::audit_defender_health()?;
    to_json(evaluate_defender(&observation, parameters.effective()?))
}

fn parse_parameters<T>(value: &serde_json::Value, capability: &str) -> Result<T, PlatformError>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_value(value.clone()).map_err(|error| {
        PlatformError::TrustFailure(format!("invalid {capability} audit parameters: {error}"))
    })
}

fn failed(descriptor: &'static CapabilityDescriptor, message: &str) -> CapabilityOutcome {
    CapabilityOutcome::Failed {
        capability_id: descriptor.id.into(),
        message: message.into(),
    }
}

fn to_json(value: impl Serialize) -> Result<serde_json::Value, PlatformError> {
    serde_json::to_value(value).map_err(|error| {
        PlatformError::TrustFailure(format!("observation serialization failed: {error}"))
    })
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityParameters {
    #[serde(default)]
    expected_domain: Option<String>,
    #[serde(default)]
    config: Option<IdentityConfig>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityConfig {
    #[serde(default)]
    expected_domain: Option<String>,
}

impl IdentityParameters {
    fn effective(self) -> Result<EffectiveIdentityConfig, PlatformError> {
        let configured = self.config.and_then(|config| config.expected_domain);
        let expected_domain = self.expected_domain.or(configured);
        if expected_domain
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(PlatformError::TrustFailure(
                "expected_domain must not be blank".into(),
            ));
        }
        Ok(EffectiveIdentityConfig { expected_domain })
    }
}

#[derive(Clone, Debug, Serialize)]
struct EffectiveIdentityConfig {
    expected_domain: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct DefenderParameters {
    #[serde(default, rename = "warn_signature_age_days")]
    signature: Option<u32>,
    #[serde(default, rename = "warn_quick_scan_age_days")]
    quick_scan: Option<u32>,
    #[serde(default, rename = "warn_full_scan_age_days")]
    full_scan: Option<u32>,
    #[serde(default)]
    config: Option<DefenderConfig>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct DefenderConfig {
    #[serde(default, rename = "warn_signature_age_days")]
    signature: Option<u32>,
    #[serde(default, rename = "warn_quick_scan_age_days")]
    quick_scan: Option<u32>,
    #[serde(default, rename = "warn_full_scan_age_days")]
    full_scan: Option<u32>,
}

impl DefenderParameters {
    fn effective(self) -> Result<EffectiveDefenderConfig, PlatformError> {
        let config = self.config.unwrap_or_default();
        let effective = EffectiveDefenderConfig {
            signature: self
                .signature
                .or(config.signature)
                .unwrap_or(DEFAULT_SIGNATURE_AGE_DAYS),
            quick_scan: self
                .quick_scan
                .or(config.quick_scan)
                .unwrap_or(DEFAULT_QUICK_SCAN_AGE_DAYS),
            full_scan: self
                .full_scan
                .or(config.full_scan)
                .unwrap_or(DEFAULT_FULL_SCAN_AGE_DAYS),
        };
        for value in [
            effective.signature,
            effective.quick_scan,
            effective.full_scan,
        ] {
            if value > MAX_AGE_DAYS {
                return Err(PlatformError::TrustFailure(format!(
                    "Defender age thresholds must be between 0 and {MAX_AGE_DAYS} days"
                )));
            }
        }
        Ok(effective)
    }
}

#[derive(Clone, Debug, Serialize)]
struct EffectiveDefenderConfig {
    #[serde(rename = "warn_signature_age_days")]
    signature: u32,
    #[serde(rename = "warn_quick_scan_age_days")]
    quick_scan: u32,
    #[serde(rename = "warn_full_scan_age_days")]
    full_scan: u32,
}

#[derive(Clone, Debug, Serialize)]
struct Finding {
    code: &'static str,
    severity: &'static str,
    message: String,
}

#[derive(Clone, Debug, Serialize)]
struct IdentityAudit {
    observation: IdentityObservation,
    effective_config: EffectiveIdentityConfig,
    findings: Vec<Finding>,
    healthy: bool,
}

fn evaluate_identity(
    observation: &IdentityObservation,
    effective_config: EffectiveIdentityConfig,
) -> IdentityAudit {
    let mut findings = Vec::new();
    if let Some(expected_domain) = &effective_config.expected_domain {
        if !observation.domain_joined {
            finding(
                &mut findings,
                "JOIN-NotDomainJoined",
                "high",
                "System is not domain-joined.",
            );
        } else if observation.join_name.trim().is_empty() {
            finding(
                &mut findings,
                "JOIN-DomainEmpty",
                "medium",
                "Domain membership is reported but the domain name is empty.",
            );
        } else if !observation.join_name.eq_ignore_ascii_case(expected_domain) {
            finding(
                &mut findings,
                "JOIN-DomainMismatch",
                "high",
                &format!(
                    "Domain '{}' differs from expected domain '{}'.",
                    observation.join_name, expected_domain
                ),
            );
        }
    }
    IdentityAudit {
        observation: observation.clone(),
        effective_config,
        healthy: findings.is_empty(),
        findings,
    }
}

#[derive(Clone, Debug, Serialize)]
struct DefenderAudit {
    observation: DefenderHealthObservation,
    effective_config: EffectiveDefenderConfig,
    findings: Vec<Finding>,
    healthy: bool,
}

fn evaluate_defender(
    observation: &DefenderHealthObservation,
    effective_config: EffectiveDefenderConfig,
) -> DefenderAudit {
    let mut findings = Vec::new();
    if let Some(error) = &observation.provider_error {
        finding(
            &mut findings,
            "DEF-ProviderAccessError",
            "high",
            &format!("Defender provider evidence is unavailable: {error}"),
        );
    }
    if !observation.service_running {
        finding(
            &mut findings,
            "DEF-AMServiceDisabled",
            "high",
            "Defender AM service is not running.",
        );
    }
    evaluate_bool(
        &mut findings,
        observation.antivirus_enabled,
        "DEF-AntivirusDisabled",
        "AntivirusEnabled",
    );
    evaluate_bool(
        &mut findings,
        observation.antispyware_enabled,
        "DEF-AntispywareDisabled",
        "AntispywareEnabled",
    );
    evaluate_bool(
        &mut findings,
        observation.behavior_monitor_enabled,
        "DEF-BehaviorMonitorDisabled",
        "BehaviorMonitorEnabled",
    );
    evaluate_bool(
        &mut findings,
        observation.real_time_protection_enabled,
        "DEF-RTP-Disabled",
        "RealTimeProtectionEnabled",
    );
    match observation.signatures_out_of_date {
        Some(true) => finding(
            &mut findings,
            "DEF-SignaturesOutOfDate",
            "medium",
            "Defender signatures are out of date.",
        ),
        Some(false) => {}
        None => missing(&mut findings, "signatures_out_of_date"),
    }
    evaluate_age(
        &mut findings,
        observation.antivirus_signature_age_days,
        effective_config.signature,
        "DEF-SignatureAgeHigh",
        "AntivirusSignatureAge",
        false,
    );
    evaluate_age(
        &mut findings,
        observation.quick_scan_age_days,
        effective_config.quick_scan,
        "DEF-QuickScanOld",
        "QuickScanAge",
        false,
    );
    evaluate_age(
        &mut findings,
        observation.full_scan_age_days,
        effective_config.full_scan,
        "DEF-FullScanOld",
        "FullScanAge",
        true,
    );
    if observation.tamper_protected == Some(false) {
        finding(
            &mut findings,
            "DEF-TamperProtectionOff",
            "medium",
            "Tamper protection is off.",
        );
    }
    if observation.reboot_required == Some(true) {
        finding(
            &mut findings,
            "DEF-RebootRequired",
            "medium",
            "Defender reports a pending reboot.",
        );
    }
    DefenderAudit {
        observation: observation.clone(),
        effective_config,
        healthy: findings.is_empty(),
        findings,
    }
}

fn evaluate_bool(
    findings: &mut Vec<Finding>,
    value: Option<bool>,
    code: &'static str,
    field: &str,
) {
    match value {
        Some(true) => {}
        Some(false) => finding(findings, code, "high", &format!("{field}=False.")),
        None => missing(findings, field),
    }
}

fn evaluate_age(
    findings: &mut Vec<Finding>,
    value: Option<u32>,
    threshold: u32,
    code: &'static str,
    field: &str,
    never_is_finding: bool,
) {
    match value {
        Some(u32::MAX) if never_is_finding => finding(
            findings,
            "DEF-FullScanNever",
            "info",
            "FullScanAge indicates never run.",
        ),
        Some(u32::MAX) => finding(
            findings,
            code,
            "low",
            &format!("{field} indicates never run."),
        ),
        Some(age) if age >= threshold => finding(
            findings,
            code,
            "low",
            &format!("{field}={age} days (threshold {threshold})."),
        ),
        Some(_) => {}
        None => missing(findings, field),
    }
}

fn missing(findings: &mut Vec<Finding>, field: &str) {
    finding(
        findings,
        "DEF-EvidenceMissing",
        "high",
        &format!("Defender provider did not return {field}."),
    );
}

fn finding(findings: &mut Vec<Finding>, code: &'static str, severity: &'static str, message: &str) {
    findings.push(Finding {
        code,
        severity,
        message: message.into(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use baselineops_capabilities::lookup;
    use baselineops_windows::DomainRole;

    fn defender_fixture() -> DefenderHealthObservation {
        DefenderHealthObservation {
            provider: "fixture".into(),
            provider_error: None,
            service_running: true,
            service_state: 4,
            process_id: 1,
            win32_exit_code: 0,
            antivirus_enabled: Some(true),
            antispyware_enabled: Some(true),
            behavior_monitor_enabled: Some(true),
            real_time_protection_enabled: Some(true),
            signatures_out_of_date: Some(false),
            antivirus_signature_age_days: Some(1),
            quick_scan_age_days: Some(1),
            full_scan_age_days: Some(1),
            tamper_protected: Some(true),
            reboot_required: Some(false),
        }
    }

    #[test]
    fn defender_fixture_is_healthy_only_with_complete_evidence() {
        let audit = evaluate_defender(
            &defender_fixture(),
            DefenderParameters::default().effective().expect("defaults"),
        );
        assert!(audit.healthy);
        let mut incomplete = defender_fixture();
        incomplete.real_time_protection_enabled = None;
        let audit = evaluate_defender(
            &incomplete,
            DefenderParameters::default().effective().expect("defaults"),
        );
        assert!(!audit.healthy);
        assert!(
            audit
                .findings
                .iter()
                .any(|finding| finding.code == "DEF-EvidenceMissing")
        );
    }

    #[test]
    fn request_parameters_override_nested_config() {
        let parameters: DefenderParameters = parse_parameters(
            &serde_json::json!({
                "warn_signature_age_days": 4,
                "config": { "warn_signature_age_days": 8, "warn_quick_scan_age_days": 9 }
            }),
            "Defender",
        )
        .expect("typed parameters");
        let effective = parameters.effective().expect("effective parameters");
        assert_eq!(effective.signature, 4);
        assert_eq!(effective.quick_scan, 9);
        let serialized = serde_json::to_value(&effective).expect("serialized parameters");
        assert_eq!(serialized["warn_signature_age_days"], 4);
        assert_eq!(serialized["warn_quick_scan_age_days"], 9);
    }

    #[test]
    fn executor_rejects_unknown_parameters_before_platform_access() {
        let descriptor = lookup("v3.identity.join").expect("descriptor");
        let outcome = WaveOneWindowsExecutor.execute(
            descriptor,
            CapabilityRequest {
                operation: Operation::Audit,
                parameters: &serde_json::json!({ "raw_command": "forbidden" }),
            },
        );
        assert!(matches!(outcome, CapabilityOutcome::Failed { .. }));
    }

    #[test]
    fn expected_domain_is_evaluated_case_insensitively() {
        let observation = IdentityObservation {
            hostname: "HOST".into(),
            join_name: "Example.Test".into(),
            domain_joined: true,
            workgroup_joined: false,
            domain_role: DomainRole::MemberWorkstation,
            os_name: "Windows".into(),
            os_version: "10.0".into(),
            os_build: "26100".into(),
            windows_product: "Windows 10.0".into(),
            windows_edition: "sku-00000000".into(),
            architecture: "x86_64".into(),
            time_zone: "UTC".into(),
        };
        let audit = evaluate_identity(
            &observation,
            EffectiveIdentityConfig {
                expected_domain: Some("example.test".into()),
            },
        );
        assert!(audit.healthy);
    }
}
