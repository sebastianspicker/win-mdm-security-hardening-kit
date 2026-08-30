//! Fixed Security Options drift policy for capability 38.
//!
//! The legacy script accepts arbitrary registry paths, value names, and value
//! types through `DesiredJson`. v3 deliberately replaces that authority with a
//! small, fixed HKLM DWORD set. This module performs no Windows I/O or writes.

use crate::PolicyFinding;
use baselineops_domain::{FindingStatus, JsonMap, Severity};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;

/// A fixed registry field within the v3 Security Options subset.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityOptionsField {
    /// UAC master switch.
    EnableLua,
    /// LAN Manager authentication compatibility level.
    LmCompatibilityLevel,
    /// Whether Windows stores LAN Manager password hashes.
    NoLmHash,
    /// Anonymous SAM and share enumeration restriction level.
    RestrictAnonymous,
    /// Whether anonymous users may enumerate SAM accounts and shares.
    RestrictAnonymousSam,
    /// Whether network logons with blank passwords are limited to the console.
    LimitBlankPasswordUse,
}

/// Typed result of reading one fixed HKLM DWORD field.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", content = "value", rename_all = "snake_case")]
pub enum SecurityOptionEvidence {
    /// A DWORD value was read successfully.
    Present(u32),
    /// The fixed registry value or its parent key is absent.
    Missing,
    /// Windows denied the required read access.
    AccessDenied,
    /// A value had the wrong type or Windows returned another read error.
    Error,
}

/// Fixed HKLM evidence for capability 38.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct SecurityOptionsObservation {
    /// Each allowlisted field's independently typed evidence.
    pub values: BTreeMap<SecurityOptionsField, SecurityOptionEvidence>,
}

/// A finite DWORD on/off desired value.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Enabled {
    /// Write the DWORD value zero in a future verified worker path.
    Disabled,
    /// Write the DWORD value one in a future verified worker path.
    #[default]
    Enabled,
}

impl Enabled {
    const fn dword(self) -> u32 {
        match self {
            Self::Disabled => 0,
            Self::Enabled => 1,
        }
    }
}

/// Finite LAN Manager authentication compatibility policy values.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LmCompatibilityLevel {
    /// Send LM and NTLM responses.
    SendLmAndNtlm,
    /// Use `NTLMv2` session security when negotiated.
    SendLmAndNtlmWithNtlmV2SessionSecurity,
    /// Send NTLM responses only.
    SendNtlmOnly,
    /// Send `NTLMv2` responses only.
    #[default]
    SendNtlmV2Only,
    /// Send `NTLMv2` and refuse LM.
    SendNtlmV2RefuseLm,
    /// Send `NTLMv2` and refuse LM and NTLM.
    SendNtlmV2RefuseLmAndNtlm,
}

impl LmCompatibilityLevel {
    const fn dword(self) -> u32 {
        match self {
            Self::SendLmAndNtlm => 0,
            Self::SendLmAndNtlmWithNtlmV2SessionSecurity => 1,
            Self::SendNtlmOnly => 2,
            Self::SendNtlmV2Only => 3,
            Self::SendNtlmV2RefuseLm => 4,
            Self::SendNtlmV2RefuseLmAndNtlm => 5,
        }
    }
}

/// Finite anonymous-enumeration restriction values.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnonymousRestriction {
    /// Do not add a registry restriction.
    None,
    /// Do not permit anonymous SAM account enumeration.
    #[default]
    NoAnonymousSam,
    /// Do not permit anonymous SAM account or share enumeration.
    NoAnonymousSamOrShares,
}

impl AnonymousRestriction {
    const fn dword(self) -> u32 {
        match self {
            Self::None => 0,
            Self::NoAnonymousSam => 1,
            Self::NoAnonymousSamOrShares => 2,
        }
    }
}

/// Strict desired state for the finite v3 Security Options subset.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, rename_all = "snake_case", deny_unknown_fields)]
pub struct SecurityOptionsPolicy {
    /// Desired UAC master-switch state.
    pub enable_lua: Enabled,
    /// Desired LAN Manager authentication compatibility level.
    pub lm_compatibility_level: LmCompatibilityLevel,
    /// Desired LM-hash storage state.
    pub no_lm_hash: Enabled,
    /// Desired anonymous-enumeration restriction level.
    pub restrict_anonymous: AnonymousRestriction,
    /// Desired anonymous SAM restriction state.
    pub restrict_anonymous_sam: Enabled,
    /// Desired blank-password network-logon restriction state.
    pub limit_blank_password_use: Enabled,
}

impl Default for SecurityOptionsPolicy {
    fn default() -> Self {
        Self {
            enable_lua: Enabled::Enabled,
            lm_compatibility_level: LmCompatibilityLevel::SendNtlmV2Only,
            no_lm_hash: Enabled::Enabled,
            restrict_anonymous: AnonymousRestriction::NoAnonymousSam,
            restrict_anonymous_sam: Enabled::Enabled,
            limit_blank_password_use: Enabled::Enabled,
        }
    }
}

/// One fixed field whose observed DWORD differs from the typed desired value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct SecurityOptionsDrift {
    /// Fixed field with drift.
    pub field: SecurityOptionsField,
    /// Typed evidence retained for a future approved worker plan.
    pub observed: SecurityOptionEvidence,
    /// Fixed DWORD derived from the enum-only policy.
    pub desired: u32,
}

/// Deterministic audit result without mutation authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct SecurityOptionsAudit {
    /// Native fixed-field evidence.
    pub observation: SecurityOptionsObservation,
    /// Resolved finite desired DWORD values.
    pub desired: BTreeMap<SecurityOptionsField, u32>,
    /// Drift and incomplete-evidence findings.
    pub findings: Vec<PolicyFinding>,
    /// An `EnableLUA` change requires reboot or logoff before UAC state is relied on.
    pub reboot_or_logoff_required_if_enable_lua_changed: bool,
}

/// Read-only proposed changes for a separately approved future worker route.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct SecurityOptionsPlan {
    /// Full audit evidence and policy assessment.
    pub audit: SecurityOptionsAudit,
    /// Fixed differences only; this executor never applies them.
    pub proposed_changes: Vec<SecurityOptionsDrift>,
    /// A future worker route would need administrator authority.
    pub requires_administrator: bool,
    /// Raw capability Apply is intentionally unavailable.
    pub apply_available: bool,
    /// Legacy generic desired JSON is intentionally excluded from v3.
    pub exclusions: Vec<&'static str>,
}

/// Evaluate fixed evidence against an enum-only desired state.
#[must_use]
pub fn evaluate_security_options(
    observation: SecurityOptionsObservation,
    policy: &SecurityOptionsPolicy,
) -> SecurityOptionsAudit {
    let desired = desired_values(policy);
    let mut findings = Vec::new();
    let mut enable_lua_changed = false;
    for (field, wanted) in &desired {
        let evidence = observation
            .values
            .get(field)
            .cloned()
            .unwrap_or(SecurityOptionEvidence::Missing);
        let (code, status, severity, message) = match &evidence {
            SecurityOptionEvidence::Present(actual) if actual == wanted => (
                "SECOPT-Compliant",
                FindingStatus::Pass,
                Severity::Low,
                format!("{field:?} matches its fixed desired value {wanted}."),
            ),
            SecurityOptionEvidence::Present(actual) => {
                if *field == SecurityOptionsField::EnableLua {
                    enable_lua_changed = true;
                }
                (
                    "SECOPT-Drift",
                    FindingStatus::Fail,
                    Severity::High,
                    format!("{field:?} is {actual}, expected {wanted}."),
                )
            }
            SecurityOptionEvidence::Missing => (
                "SECOPT-Missing",
                FindingStatus::Warning,
                Severity::Medium,
                format!("{field:?} is not configured or its fixed key is absent."),
            ),
            SecurityOptionEvidence::AccessDenied => (
                "SECOPT-AccessDenied",
                FindingStatus::Error,
                Severity::High,
                format!("Windows denied read access to {field:?}."),
            ),
            SecurityOptionEvidence::Error => (
                "SECOPT-ObservationError",
                FindingStatus::Error,
                Severity::High,
                format!("{field:?} could not be read as its required DWORD type."),
            ),
        };
        findings.push(PolicyFinding {
            code,
            status,
            severity,
            message,
            evidence: JsonMap::from([
                ("field".into(), json!(field)),
                ("observed".into(), json!(evidence)),
                ("desired".into(), json!(wanted)),
            ]),
        });
    }
    SecurityOptionsAudit {
        observation,
        desired,
        findings,
        reboot_or_logoff_required_if_enable_lua_changed: enable_lua_changed,
    }
}

/// Build a non-mutating plan from finite desired state and fixed evidence.
#[must_use]
pub fn build_security_options_plan(
    observation: SecurityOptionsObservation,
    policy: &SecurityOptionsPolicy,
) -> SecurityOptionsPlan {
    let audit = evaluate_security_options(observation, policy);
    let proposed_changes = audit
        .desired
        .iter()
        .filter_map(|(field, desired)| {
            let observed = audit
                .observation
                .values
                .get(field)
                .cloned()
                .unwrap_or(SecurityOptionEvidence::Missing);
            (observed != SecurityOptionEvidence::Present(*desired)).then_some(
                SecurityOptionsDrift {
                    field: *field,
                    observed,
                    desired: *desired,
                },
            )
        })
        .collect();
    SecurityOptionsPlan {
        audit,
        proposed_changes,
        requires_administrator: true,
        apply_available: false,
        exclusions: vec![
            "legacy DesiredJson paths, value names, and registry types are not v3 authority",
            "raw registry writes and arbitrary remediation are unavailable",
        ],
    }
}

fn desired_values(policy: &SecurityOptionsPolicy) -> BTreeMap<SecurityOptionsField, u32> {
    BTreeMap::from([
        (SecurityOptionsField::EnableLua, policy.enable_lua.dword()),
        (
            SecurityOptionsField::LmCompatibilityLevel,
            policy.lm_compatibility_level.dword(),
        ),
        (SecurityOptionsField::NoLmHash, policy.no_lm_hash.dword()),
        (
            SecurityOptionsField::RestrictAnonymous,
            policy.restrict_anonymous.dword(),
        ),
        (
            SecurityOptionsField::RestrictAnonymousSam,
            policy.restrict_anonymous_sam.dword(),
        ),
        (
            SecurityOptionsField::LimitBlankPasswordUse,
            policy.limit_blank_password_use.dword(),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_rejects_legacy_arbitrary_registry_authority() {
        for input in [
            serde_json::json!({"path":"HKLM\\anything"}),
            serde_json::json!({"desired_json":{"arbitrary":{"Type":"DWord","Value":1}}}),
            serde_json::json!({"enable_lua": 1}),
        ] {
            assert!(serde_json::from_value::<SecurityOptionsPolicy>(input).is_err());
        }
    }

    #[test]
    fn plan_preserves_typed_incomplete_evidence_without_apply_authority() {
        let observation = SecurityOptionsObservation {
            values: BTreeMap::from([
                (
                    SecurityOptionsField::EnableLua,
                    SecurityOptionEvidence::Present(0),
                ),
                (
                    SecurityOptionsField::LmCompatibilityLevel,
                    SecurityOptionEvidence::AccessDenied,
                ),
                (
                    SecurityOptionsField::NoLmHash,
                    SecurityOptionEvidence::Error,
                ),
            ]),
        };
        let plan = build_security_options_plan(observation, &SecurityOptionsPolicy::default());
        assert!(plan.audit.reboot_or_logoff_required_if_enable_lua_changed);
        assert!(!plan.apply_available);
        assert_eq!(plan.proposed_changes.len(), 6);
        assert!(
            plan.audit
                .findings
                .iter()
                .any(|finding| finding.code == "SECOPT-AccessDenied")
        );
        assert!(
            plan.audit
                .findings
                .iter()
                .any(|finding| finding.code == "SECOPT-ObservationError")
        );
    }
}
