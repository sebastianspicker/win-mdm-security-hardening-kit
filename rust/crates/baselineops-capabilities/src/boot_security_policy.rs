//! Shared pure policy owner for the overlapping LSASS, Credential Guard, VBS, and HVCI capabilities.

use crate::{Observation, PolicyFinding, PolicyValueSnapshot};
use baselineops_domain::{FindingStatus, JsonMap, Severity};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;

/// Fixed boot-security registry field.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BootSecurityField {
    /// Added LSA protection.
    RunAsPpl,
    /// Firmware-persisted Added LSA protection intent.
    RunAsPplBoot,
    /// Credential Guard configuration.
    LsaCfgFlags,
    /// VBS enablement.
    EnableVbs,
    /// Required VBS platform-security features.
    PlatformSecurity,
    /// HVCI enablement.
    HvciEnabled,
    /// Microsoft vulnerable-driver blocklist enablement.
    VulnerableDriverBlocklist,
}

/// Native shared boot-security evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct BootSecurityObservation {
    /// Fixed registry values, preserving missing state.
    pub values: BTreeMap<BootSecurityField, Observation<PolicyValueSnapshot>>,
    /// Device Guard runtime evidence; never inferred from registry intent.
    pub device_guard_runtime: Observation<bool>,
}

/// Strict capability 13 parameters. Its v3 alpha baseline is fixed.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct LsassHardeningPolicy {}

/// Strict capability 39 parameters.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct CredentialGuardPolicy {
    /// Required platform features: Secure Boot (1) or Secure Boot plus DMA (3).
    pub platform_security: u32,
    /// Credential Guard mode: disabled (0), UEFI lock (1), or without lock (2).
    pub lsa_cfg_flags: u32,
}

impl Default for CredentialGuardPolicy {
    fn default() -> Self {
        Self {
            platform_security: 1,
            lsa_cfg_flags: 1,
        }
    }
}

/// Strict capability 40 parameters.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct LsaProtectionPolicy {
    /// Desired `RunAsPPL` value: disabled (0), UEFI lock (1), or without lock (2).
    pub target_run_as_ppl: u32,
    /// Include `RunAsPPLBoot` in drift evaluation.
    pub manage_run_as_ppl_boot: bool,
}

impl Default for LsaProtectionPolicy {
    fn default() -> Self {
        Self {
            target_run_as_ppl: 1,
            manage_run_as_ppl_boot: false,
        }
    }
}

/// Shared deterministic audit/plan result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct BootSecurityResult {
    /// Native input evidence.
    pub observation: BootSecurityObservation,
    /// Capability-specific fixed desired registry values.
    pub desired: BTreeMap<BootSecurityField, u32>,
    /// Drift and incomplete-runtime findings.
    pub findings: Vec<PolicyFinding>,
    /// All changes require a reboot before runtime assertions are valid.
    pub reboot_required_if_changed: bool,
}

/// Validate capability 39's bounded values.
///
/// # Errors
///
/// Rejects platform-security and Credential Guard modes outside the finite v3 policy.
pub fn validate_credential_guard(policy: &CredentialGuardPolicy) -> Result<(), &'static str> {
    if !matches!(policy.platform_security, 1 | 3) || policy.lsa_cfg_flags > 2 {
        return Err("Credential Guard values are outside the finite v3 policy");
    }
    Ok(())
}

/// Validate capability 40's bounded values.
///
/// # Errors
///
/// Rejects `RunAsPPL` modes outside the documented zero-to-two range.
pub fn validate_lsa_protection(policy: &LsaProtectionPolicy) -> Result<(), &'static str> {
    if policy.target_run_as_ppl > 2 {
        return Err("RunAsPPL must be 0, 1, or 2");
    }
    Ok(())
}

/// Evaluate capability 13's fixed minimum baseline.
#[must_use]
pub fn evaluate_lsass_hardening(
    observation: BootSecurityObservation,
    _policy: &LsassHardeningPolicy,
) -> BootSecurityResult {
    evaluate(
        observation,
        BTreeMap::from([
            (BootSecurityField::RunAsPpl, 1),
            (BootSecurityField::RunAsPplBoot, 1),
            (BootSecurityField::LsaCfgFlags, 2),
            (BootSecurityField::EnableVbs, 1),
            (BootSecurityField::PlatformSecurity, 1),
            (BootSecurityField::HvciEnabled, 1),
            (BootSecurityField::VulnerableDriverBlocklist, 1),
        ]),
    )
}

/// Evaluate capability 39's finite desired state.
#[must_use]
pub fn evaluate_credential_guard(
    observation: BootSecurityObservation,
    policy: &CredentialGuardPolicy,
) -> BootSecurityResult {
    evaluate(
        observation,
        BTreeMap::from([
            (BootSecurityField::EnableVbs, 1),
            (
                BootSecurityField::PlatformSecurity,
                policy.platform_security,
            ),
            (BootSecurityField::LsaCfgFlags, policy.lsa_cfg_flags),
        ]),
    )
}

/// Evaluate capability 40's finite desired state.
#[must_use]
pub fn evaluate_lsa_protection(
    observation: BootSecurityObservation,
    policy: &LsaProtectionPolicy,
) -> BootSecurityResult {
    let mut desired = BTreeMap::from([(BootSecurityField::RunAsPpl, policy.target_run_as_ppl)]);
    if policy.manage_run_as_ppl_boot {
        desired.insert(BootSecurityField::RunAsPplBoot, policy.target_run_as_ppl);
    }
    evaluate(observation, desired)
}

fn evaluate(
    observation: BootSecurityObservation,
    desired: BTreeMap<BootSecurityField, u32>,
) -> BootSecurityResult {
    let mut findings = Vec::new();
    for (field, wanted) in &desired {
        match observation.values.get(field) {
            Some(Observation::Present(PolicyValueSnapshot::Dword(actual))) if actual == wanted => {}
            Some(Observation::Present(PolicyValueSnapshot::Dword(actual))) => {
                findings.push(PolicyFinding {
                    code: "BOOTSEC-Drift",
                    status: FindingStatus::Fail,
                    severity: Severity::High,
                    message: format!("{field:?} is {actual}, expected {wanted}."),
                    evidence: JsonMap::from([
                        ("field".into(), json!(field)),
                        ("actual".into(), json!(actual)),
                        ("desired".into(), json!(wanted)),
                    ]),
                });
            }
            _ => findings.push(PolicyFinding {
                code: "BOOTSEC-EvidenceIncomplete",
                status: FindingStatus::Warning,
                severity: Severity::High,
                message: format!("Registry evidence for {field:?} is incomplete."),
                evidence: JsonMap::from([("field".into(), json!(field))]),
            }),
        }
    }
    if !matches!(observation.device_guard_runtime, Observation::Present(_)) {
        findings.push(PolicyFinding {
            code: "BOOTSEC-RuntimeEvidenceIncomplete",
            status: FindingStatus::Warning,
            severity: Severity::High,
            message: "Device Guard runtime evidence is unavailable; registry intent is not runtime state.".into(),
            evidence: JsonMap::from([("runtime_inferred".into(), json!(false))]),
        });
    }
    BootSecurityResult {
        observation,
        desired,
        findings,
        reboot_required_if_changed: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policies_are_strict_and_incomplete_runtime_never_passes() {
        assert!(serde_json::from_value::<LsassHardeningPolicy>(json!({"path":"x"})).is_err());
        assert!(
            validate_credential_guard(&CredentialGuardPolicy {
                platform_security: 2,
                lsa_cfg_flags: 1,
            })
            .is_err()
        );
        let result = evaluate_lsa_protection(
            BootSecurityObservation {
                values: BTreeMap::new(),
                device_guard_runtime: Observation::NotRun,
            },
            &LsaProtectionPolicy::default(),
        );
        assert_eq!(result.findings.len(), 2);
    }
}
