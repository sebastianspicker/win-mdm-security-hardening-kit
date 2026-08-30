//! Pure evaluation and strict parser for driver-signing integrity evidence.

use crate::{Observation, PolicyFinding};
use baselineops_domain::{FindingStatus, JsonMap, Severity};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Strict capability 49 parameters. No BCD identifier or command is caller-selected.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct DriverIntegrityPolicy {}

/// Parsed fixed BCD integrity flags.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct BootIntegrityFlags {
    /// Test-signing mode, or `None` when the complete output omitted the element.
    pub test_signing: Option<bool>,
    /// Integrity-check bypass, or `None` when the complete output omitted the element.
    pub no_integrity_checks: Option<bool>,
}

/// Native capability 49 evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct DriverIntegrityObservation {
    /// Exact `bcdedit /enum {current}` result.
    pub boot_flags: Observation<BootIntegrityFlags>,
    /// Fixed HVCI `Enabled` registry value.
    pub hvci_enabled: Observation<u32>,
    /// Runtime Device Guard evidence, deliberately not inferred from registry intent.
    pub device_guard_runtime: Observation<bool>,
}

/// Deterministic capability 49 result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct DriverIntegrityAudit {
    /// Native input evidence.
    pub observation: DriverIntegrityObservation,
    /// BCD, HVCI, and completeness findings.
    pub findings: Vec<PolicyFinding>,
}

/// Parse bounded English `bcdedit /enum {current}` output.
#[must_use]
pub fn parse_bcd_integrity(output: &str) -> Observation<BootIntegrityFlags> {
    if output.is_empty() || output.len() > 256 * 1024 {
        return Observation::Unparsed;
    }
    let mut test_signing = None;
    let mut no_integrity_checks = None;
    for line in output.lines() {
        let mut fields = line.split_whitespace();
        let Some(name) = fields.next() else { continue };
        let Some(value) = fields.next() else { continue };
        if fields.next().is_some() {
            continue;
        }
        let parsed = match value.to_ascii_lowercase().as_str() {
            "yes" => Some(true),
            "no" => Some(false),
            _ => None,
        };
        match name.to_ascii_lowercase().as_str() {
            "testsigning" => test_signing = parsed,
            "nointegritychecks" => no_integrity_checks = parsed,
            _ => {}
        }
    }
    if test_signing.is_none() && no_integrity_checks.is_none() {
        Observation::Unparsed
    } else {
        Observation::Present(BootIntegrityFlags {
            test_signing,
            no_integrity_checks,
        })
    }
}

/// Evaluate driver-signing evidence without platform I/O.
#[must_use]
pub fn evaluate_driver_integrity(
    observation: DriverIntegrityObservation,
    _policy: &DriverIntegrityPolicy,
) -> DriverIntegrityAudit {
    let mut findings = Vec::new();
    evaluate_boot_flags(&observation.boot_flags, &mut findings);
    match observation.hvci_enabled {
        Observation::Present(1) => {}
        Observation::Present(value) => findings.push(PolicyFinding {
            code: "DRIVER-HvciDisabled",
            status: FindingStatus::Fail,
            severity: Severity::High,
            message: format!("HVCI Enabled has non-enforcing value {value}."),
            evidence: JsonMap::from([("enabled".into(), json!(value))]),
        }),
        ref value => incomplete("DRIVER-HvciEvidenceIncomplete", value, &mut findings),
    }
    match observation.device_guard_runtime {
        Observation::Present(true) => {}
        Observation::Present(false) => findings.push(finding(
            "DRIVER-HvciNotRunning",
            FindingStatus::Warning,
            Severity::High,
            "Device Guard runtime evidence reports HVCI is not running.",
        )),
        ref value => incomplete("DRIVER-DeviceGuardRuntimeIncomplete", value, &mut findings),
    }
    DriverIntegrityAudit {
        observation,
        findings,
    }
}

fn evaluate_boot_flags(value: &Observation<BootIntegrityFlags>, findings: &mut Vec<PolicyFinding>) {
    match value {
        Observation::Present(flags) => {
            flag(
                flags.test_signing,
                "DRIVER-TestSigningEnabled",
                "DRIVER-TestSigningIncomplete",
                "BCD TESTSIGNING is enabled.",
                findings,
            );
            flag(
                flags.no_integrity_checks,
                "DRIVER-NoIntegrityChecksEnabled",
                "DRIVER-NoIntegrityChecksIncomplete",
                "BCD NOINTEGRITYCHECKS is enabled.",
                findings,
            );
        }
        other => incomplete("DRIVER-BcdEvidenceIncomplete", other, findings),
    }
}

fn flag(
    value: Option<bool>,
    enabled_code: &'static str,
    incomplete_code: &'static str,
    message: &'static str,
    findings: &mut Vec<PolicyFinding>,
) {
    match value {
        Some(true) => findings.push(finding(
            enabled_code,
            FindingStatus::Fail,
            Severity::Critical,
            message,
        )),
        Some(false) => {}
        None => findings.push(finding(
            incomplete_code,
            FindingStatus::Warning,
            Severity::Medium,
            "The complete BCD output omitted the fixed integrity element.",
        )),
    }
}

fn incomplete<T>(code: &'static str, _value: &Observation<T>, findings: &mut Vec<PolicyFinding>) {
    findings.push(finding(
        code,
        FindingStatus::Warning,
        Severity::Medium,
        "Required driver-integrity evidence is incomplete.",
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

    #[test]
    fn strict_parameters_and_bcd_fixture_are_bounded() {
        assert!(
            serde_json::from_value::<DriverIntegrityPolicy>(json!({"identifier":"{default}"}))
                .is_err()
        );
        assert_eq!(
            parse_bcd_integrity("testsigning No\r\nnointegritychecks Yes\r\n"),
            Observation::Present(BootIntegrityFlags {
                test_signing: Some(false),
                no_integrity_checks: Some(true),
            })
        );
        assert_eq!(
            parse_bcd_integrity("localized output"),
            Observation::Unparsed
        );
    }

    #[test]
    fn enabled_bypass_and_missing_runtime_are_never_healthy() {
        let audit = evaluate_driver_integrity(
            DriverIntegrityObservation {
                boot_flags: parse_bcd_integrity("testsigning No\r\nnointegritychecks Yes\r\n"),
                hvci_enabled: Observation::Present(0),
                device_guard_runtime: Observation::NotRun,
            },
            &DriverIntegrityPolicy {},
        );
        assert!(
            audit
                .findings
                .iter()
                .any(|finding| finding.code == "DRIVER-NoIntegrityChecksEnabled")
        );
        assert!(
            audit
                .findings
                .iter()
                .any(|finding| finding.code == "DRIVER-DeviceGuardRuntimeIncomplete")
        );
    }
}
