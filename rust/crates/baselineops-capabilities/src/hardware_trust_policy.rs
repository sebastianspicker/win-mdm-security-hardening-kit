//! Pure, read-only policy evaluation for TPM, `BitLocker`, and Secure Boot.
//!
//! Native acquisition belongs to `baselineops-windows`. Every incomplete
//! observation becomes an explicit finding: absence of provider data never
//! manufactures a healthy hardware-security posture.

use crate::{Observation, PolicyFinding};
use baselineops_domain::{FindingStatus, Severity};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Strict, read-only policy for legacy capability 15.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, rename_all = "snake_case", deny_unknown_fields)]
pub struct HardwareTpmPolicy {
    /// Lowest TPM major version accepted by the policy.
    pub minimum_tpm_major: u8,
    /// Require an enabled Secure Boot state on UEFI firmware.
    pub require_secure_boot: bool,
    /// Require active protection on the operating-system volume.
    pub require_os_volume_protection: bool,
}

impl Default for HardwareTpmPolicy {
    fn default() -> Self {
        Self {
            minimum_tpm_major: 2,
            require_secure_boot: true,
            require_os_volume_protection: true,
        }
    }
}

/// Strict, read-only policy for legacy capability 23.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, rename_all = "snake_case", deny_unknown_fields)]
pub struct BitLockerPolicy {}

/// Strict, read-only policy for legacy capability 46.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, rename_all = "snake_case", deny_unknown_fields)]
pub struct SecureBootPolicy {}

/// Native TPM device identity that does not expose secret or ownership data.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TpmDeviceObservation {
    /// TPM specification major version reported by TBS.
    pub major_version: u8,
}

/// Firmware classification from `GetFirmwareType`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FirmwareType {
    /// UEFI firmware, where Secure Boot is applicable.
    Uefi,
    /// Legacy BIOS firmware, where Secure Boot is not applicable.
    LegacyBios,
    /// A valid API result not represented by the supported classifications.
    Other(u32),
}

/// Secure Boot evidence from native firmware and state-registry observations.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct SecureBootObservation {
    /// Firmware type reported by the operating system.
    pub firmware: Observation<FirmwareType>,
    /// `UEFISecureBootEnabled` value from the fixed system state key.
    pub uefi_secure_boot_enabled: Observation<u32>,
    /// `PlatformSecureBootEnabled` value from the fixed system state key.
    pub platform_secure_boot_enabled: Observation<u32>,
}

/// Read-only `BitLocker` evidence for the operating-system volume.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct BitLockerObservation {
    /// Native WMI `GetProtectionStatus` result normalized to protected/not protected.
    pub os_volume_protected: Observation<bool>,
}

/// Combined native evidence for legacy capability 15.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct HardwareTpmObservation {
    /// TBS TPM device information.
    pub tpm: Observation<TpmDeviceObservation>,
    /// Secure Boot evidence.
    pub secure_boot: SecureBootObservation,
    /// Operating-system volume protection evidence.
    pub bitlocker: BitLockerObservation,
}

/// Deterministic result of the hardware TPM posture audit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct HardwareTpmAudit {
    /// Native input evidence.
    pub observation: HardwareTpmObservation,
    /// Drift and incomplete-evidence findings.
    pub findings: Vec<PolicyFinding>,
}

/// Deterministic result of the `BitLocker` audit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct BitLockerAudit {
    /// Native input evidence.
    pub observation: BitLockerObservation,
    /// Drift and incomplete-evidence findings.
    pub findings: Vec<PolicyFinding>,
}

/// Deterministic result of the Secure Boot audit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct SecureBootAudit {
    /// Native input evidence.
    pub observation: SecureBootObservation,
    /// Drift and incomplete-evidence findings.
    pub findings: Vec<PolicyFinding>,
}

/// Evaluate legacy capability 15 without Windows I/O.
#[must_use]
pub fn evaluate_hardware_tpm(
    observation: HardwareTpmObservation,
    policy: &HardwareTpmPolicy,
) -> HardwareTpmAudit {
    let mut findings = evaluate_tpm(&observation.tpm, policy.minimum_tpm_major);
    findings.extend(evaluate_secure_boot_findings(
        &observation.secure_boot,
        policy.require_secure_boot,
    ));
    findings.extend(evaluate_bitlocker_findings(
        &observation.bitlocker,
        policy.require_os_volume_protection,
    ));
    HardwareTpmAudit {
        observation,
        findings,
    }
}

/// Evaluate legacy capability 23 without Windows I/O.
#[must_use]
pub fn evaluate_bitlocker(
    observation: BitLockerObservation,
    _policy: &BitLockerPolicy,
) -> BitLockerAudit {
    let findings = evaluate_bitlocker_findings(&observation, true);
    BitLockerAudit {
        observation,
        findings,
    }
}

/// Evaluate legacy capability 46 without Windows I/O.
#[must_use]
pub fn evaluate_secure_boot(
    observation: SecureBootObservation,
    _policy: &SecureBootPolicy,
) -> SecureBootAudit {
    let findings = evaluate_secure_boot_findings(&observation, true);
    SecureBootAudit {
        observation,
        findings,
    }
}

fn evaluate_tpm(tpm: &Observation<TpmDeviceObservation>, minimum_major: u8) -> Vec<PolicyFinding> {
    match tpm {
        Observation::Present(device) if device.major_version >= minimum_major => Vec::new(),
        Observation::Present(device) => vec![finding(
            "HW-TPMVersionTooOld",
            FindingStatus::Fail,
            Severity::High,
            format!(
                "TPM {} does not meet the required major version {minimum_major}.",
                device.major_version
            ),
        )],
        value => vec![incomplete("HW-TPMIncomplete", value, Severity::High)],
    }
}

fn evaluate_bitlocker_findings(
    observation: &BitLockerObservation,
    required: bool,
) -> Vec<PolicyFinding> {
    if !required {
        return Vec::new();
    }
    match &observation.os_volume_protected {
        Observation::Present(true) => Vec::new(),
        Observation::Present(false) => vec![finding(
            "BLKR-OsVolumeNotProtected",
            FindingStatus::Fail,
            Severity::High,
            "The operating-system volume is not protected by BitLocker.",
        )],
        value => vec![incomplete(
            "BLKR-ProtectionIncomplete",
            value,
            Severity::High,
        )],
    }
}

fn evaluate_secure_boot_findings(
    observation: &SecureBootObservation,
    required: bool,
) -> Vec<PolicyFinding> {
    let mut findings = Vec::new();
    let is_uefi = match &observation.firmware {
        Observation::Present(FirmwareType::Uefi) => true,
        Observation::Present(FirmwareType::LegacyBios) => {
            findings.push(finding(
                "SB-LegacyBIOS",
                FindingStatus::Warning,
                Severity::Low,
                "Legacy BIOS firmware makes Secure Boot not applicable.",
            ));
            false
        }
        Observation::Present(FirmwareType::Other(value)) => {
            findings.push(finding(
                "SB-FirmwareUnsupported",
                FindingStatus::Warning,
                Severity::Medium,
                format!("Firmware type {value} is not supported for Secure Boot evaluation."),
            ));
            false
        }
        value => {
            findings.push(incomplete("SB-FirmwareIncomplete", value, Severity::High));
            false
        }
    };
    if is_uefi && required {
        evaluate_enabled(
            &mut findings,
            "SB-Disabled",
            "Secure Boot is disabled on this UEFI system.",
            &observation.uefi_secure_boot_enabled,
            "SB-SecureBootStateIncomplete",
            Severity::High,
        );
        evaluate_enabled(
            &mut findings,
            "SB-PlatformNotEnabled",
            "Platform Secure Boot is not enabled.",
            &observation.platform_secure_boot_enabled,
            "SB-PlatformStateIncomplete",
            Severity::Medium,
        );
    }
    findings
}

fn evaluate_enabled(
    findings: &mut Vec<PolicyFinding>,
    failed_code: &'static str,
    failed_message: &str,
    value: &Observation<u32>,
    incomplete_code: &'static str,
    severity: Severity,
) {
    match value {
        Observation::Present(1) => {}
        Observation::Present(_) => findings.push(finding(
            failed_code,
            FindingStatus::Fail,
            severity,
            failed_message,
        )),
        other => findings.push(incomplete(incomplete_code, other, severity)),
    }
}

fn incomplete<T>(
    code: &'static str,
    observation: &Observation<T>,
    severity: Severity,
) -> PolicyFinding {
    finding(
        code,
        FindingStatus::Warning,
        severity,
        format!(
            "Required hardware-security evidence is incomplete: {}.",
            observation_status(observation)
        ),
    )
}

fn observation_status<T>(observation: &Observation<T>) -> &'static str {
    match observation {
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
        evidence: BTreeMap::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secure_boot(enabled: Observation<u32>) -> SecureBootObservation {
        SecureBootObservation {
            firmware: Observation::Present(FirmwareType::Uefi),
            uefi_secure_boot_enabled: enabled.clone(),
            platform_secure_boot_enabled: enabled,
        }
    }

    #[test]
    fn incomplete_observations_never_produce_a_clean_hardware_audit() {
        let audit = evaluate_hardware_tpm(
            HardwareTpmObservation {
                tpm: Observation::Missing,
                secure_boot: secure_boot(Observation::AccessDenied),
                bitlocker: BitLockerObservation {
                    os_volume_protected: Observation::NotRun,
                },
            },
            &HardwareTpmPolicy::default(),
        );
        assert_eq!(audit.findings.len(), 4);
        assert!(
            audit
                .findings
                .iter()
                .all(|item| item.status != FindingStatus::Pass)
        );
    }

    #[test]
    fn legacy_bios_is_not_misreported_as_secure_boot_healthy() {
        let audit = evaluate_secure_boot(
            SecureBootObservation {
                firmware: Observation::Present(FirmwareType::LegacyBios),
                uefi_secure_boot_enabled: Observation::Missing,
                platform_secure_boot_enabled: Observation::Missing,
            },
            &SecureBootPolicy {},
        );
        assert_eq!(audit.findings[0].code, "SB-LegacyBIOS");
        assert_eq!(audit.findings[0].status, FindingStatus::Warning);
    }

    #[test]
    fn strict_policies_reject_unknown_fields() {
        assert!(
            serde_json::from_value::<HardwareTpmPolicy>(serde_json::json!({"shell": "cmd"}))
                .is_err()
        );
        assert!(
            serde_json::from_value::<BitLockerPolicy>(serde_json::json!({"mount_point": "Z:"}))
                .is_err()
        );
        assert!(
            serde_json::from_value::<SecureBootPolicy>(serde_json::json!({"apply": true})).is_err()
        );
    }
}
