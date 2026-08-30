//! Pure, read-only evaluation for fixed machine certificate health evidence.
//!
//! This capability deliberately observes neither certificate bodies nor private
//! key material. Native acquisition supplies only a bounded fingerprint, expiry
//! timestamp, and private-key association flag for `LocalMachine/My`.

use crate::{Observation, PolicyFinding};
use baselineops_domain::{FindingStatus, JsonMap, Severity};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// The largest supported certificate-expiry warning window.
pub const MAX_EXPIRY_WARNING_DAYS: u16 = 3_650;

/// Strict, bounded read-only parameters for certificate-health capability 24.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, rename_all = "snake_case", deny_unknown_fields)]
pub struct CertHealthParameters {
    /// Report certificates that expire inside this many whole days.
    pub expiry_warning_days: u16,
    /// Evaluate only certificates associated with a private key, without reading it.
    pub require_private_key: bool,
}

impl Default for CertHealthParameters {
    fn default() -> Self {
        Self {
            expiry_warning_days: 30,
            require_private_key: true,
        }
    }
}

impl CertHealthParameters {
    /// Validates the finite expiry-warning window.
    ///
    /// # Errors
    ///
    /// Returns an error when the requested warning window is zero or exceeds ten
    /// years. No path, command, enrollment, or mutation inputs are accepted.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !(1..=MAX_EXPIRY_WARNING_DAYS).contains(&self.expiry_warning_days) {
            return Err("expiry_warning_days must be 1 through 3650");
        }
        Ok(())
    }
}

/// One bounded, non-secret metadata record from the fixed machine `My` store.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct MachineCertificateMetadata {
    /// SHA-1 certificate fingerprint in lowercase hexadecimal; no certificate body.
    pub sha1_thumbprint: String,
    /// Certificate expiration as whole Unix seconds.
    pub not_after_unix_seconds: i64,
    /// Whether Crypt32 reports an associated private-key provider; key material is never read.
    pub has_private_key: bool,
}

/// Fixed registry policy evidence from `HKLM\\SOFTWARE\\Policies\\Microsoft\\Cryptography\\AutoEnrollment`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct AutoEnrollmentPolicy {
    /// The validated `AEPolicy` bitmask (only bits 0 through 2 are accepted).
    pub flags: u8,
}

impl AutoEnrollmentPolicy {
    /// Whether the policy enables automatic enrollment.
    #[must_use]
    pub const fn auto_enrollment_enabled(self) -> bool {
        self.flags & 0b100 != 0
    }
}

/// Fixed native evidence for capability 24.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct CertHealthObservation {
    /// Read-only `AutoEnrollment` group-policy evidence.
    pub auto_enrollment_policy: Observation<AutoEnrollmentPolicy>,
    /// Complete bounded machine-store metadata or an explicit incomplete state.
    pub machine_certificates: Observation<Vec<MachineCertificateMetadata>>,
}

/// Deterministic report for the read-only certificate-health capability.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct CertHealthAudit {
    /// Fixed source evidence evaluated without platform I/O.
    pub observation: CertHealthObservation,
    /// Explicit evaluation time so expiry evaluation and fixtures remain pure.
    pub evaluated_at_unix_seconds: i64,
    /// Certificate and policy drift or incomplete-evidence findings.
    pub findings: Vec<PolicyFinding>,
}

/// Evaluates fixed certificate-health evidence without Windows I/O or mutation.
#[must_use]
pub fn evaluate_cert_health(
    observation: CertHealthObservation,
    parameters: &CertHealthParameters,
    evaluated_at_unix_seconds: i64,
) -> CertHealthAudit {
    let mut findings = Vec::new();
    evaluate_auto_enrollment_policy(&observation.auto_enrollment_policy, &mut findings);
    evaluate_machine_certificates(
        &observation.machine_certificates,
        parameters,
        evaluated_at_unix_seconds,
        &mut findings,
    );
    CertHealthAudit {
        observation,
        evaluated_at_unix_seconds,
        findings,
    }
}

fn evaluate_auto_enrollment_policy(
    policy: &Observation<AutoEnrollmentPolicy>,
    findings: &mut Vec<PolicyFinding>,
) {
    match policy {
        Observation::Present(policy) if policy.auto_enrollment_enabled() => {}
        Observation::Present(_) => findings.push(finding(
            "CERT-AutoEnrollmentDisabled",
            FindingStatus::Fail,
            Severity::High,
            "The fixed AutoEnrollment group policy does not enable automatic enrollment.",
        )),
        value => incomplete("CERT-AutoEnrollmentPolicyIncomplete", value, findings),
    }
}

fn evaluate_machine_certificates(
    certificates: &Observation<Vec<MachineCertificateMetadata>>,
    parameters: &CertHealthParameters,
    now: i64,
    findings: &mut Vec<PolicyFinding>,
) {
    let Observation::Present(certificates) = certificates else {
        incomplete("CERT-MachineStoreIncomplete", certificates, findings);
        return;
    };
    let relevant = certificates
        .iter()
        .filter(|certificate| !parameters.require_private_key || certificate.has_private_key)
        .collect::<Vec<_>>();
    if relevant.is_empty() {
        findings.push(finding(
            "CERT-NoEligibleMachineCertificates",
            FindingStatus::Warning,
            Severity::Medium,
            "No machine certificate matched the fixed read-only eligibility policy.",
        ));
        return;
    }
    let warning_window_seconds = i64::from(parameters.expiry_warning_days) * 86_400;
    for certificate in relevant {
        let remaining_seconds = certificate.not_after_unix_seconds.saturating_sub(now);
        if remaining_seconds < 0 {
            findings.push(certificate_finding(
                "CERT-Expired",
                FindingStatus::Fail,
                Severity::High,
                certificate,
                remaining_seconds,
            ));
        } else if remaining_seconds <= warning_window_seconds {
            let severity = expiry_severity(remaining_seconds);
            findings.push(certificate_finding(
                "CERT-Expiring",
                FindingStatus::Warning,
                severity,
                certificate,
                remaining_seconds,
            ));
        }
    }
}

fn expiry_severity(remaining_seconds: i64) -> Severity {
    if remaining_seconds <= 7 * 86_400 {
        Severity::High
    } else if remaining_seconds <= 14 * 86_400 {
        Severity::Medium
    } else {
        Severity::Low
    }
}

fn certificate_finding(
    code: &'static str,
    status: FindingStatus,
    severity: Severity,
    certificate: &MachineCertificateMetadata,
    remaining_seconds: i64,
) -> PolicyFinding {
    PolicyFinding {
        code,
        status,
        severity,
        message: format!(
            "Machine certificate {} expires in {} whole days.",
            certificate.sha1_thumbprint,
            remaining_seconds.div_euclid(86_400),
        ),
        evidence: JsonMap::from([
            ("sha1_thumbprint".into(), json!(certificate.sha1_thumbprint)),
            (
                "not_after_unix_seconds".into(),
                json!(certificate.not_after_unix_seconds),
            ),
            ("remaining_seconds".into(), json!(remaining_seconds)),
            ("read_only".into(), json!(true)),
        ]),
    }
}

fn incomplete<T>(code: &'static str, value: &Observation<T>, findings: &mut Vec<PolicyFinding>) {
    let state = observation_state(value);
    findings.push(PolicyFinding {
        code,
        status: FindingStatus::Warning,
        severity: Severity::Medium,
        message: format!("Required certificate-health evidence is incomplete: {state}."),
        evidence: JsonMap::from([
            ("observation_status".into(), json!(state)),
            ("read_only".into(), json!(true)),
        ]),
    });
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

    fn certificate(
        not_after_unix_seconds: i64,
        has_private_key: bool,
    ) -> MachineCertificateMetadata {
        MachineCertificateMetadata {
            sha1_thumbprint: "0123456789abcdef0123456789abcdef01234567".into(),
            not_after_unix_seconds,
            has_private_key,
        }
    }

    fn observation(
        certificates: Observation<Vec<MachineCertificateMetadata>>,
    ) -> CertHealthObservation {
        CertHealthObservation {
            auto_enrollment_policy: Observation::Present(AutoEnrollmentPolicy { flags: 0b111 }),
            machine_certificates: certificates,
        }
    }

    #[test]
    fn strict_parameters_and_expiry_fixture_are_bounded() {
        assert!(
            serde_json::from_value::<CertHealthParameters>(json!({ "command": "certutil" }))
                .is_err()
        );
        assert!(
            CertHealthParameters {
                expiry_warning_days: 0,
                require_private_key: true
            }
            .validate()
            .is_err()
        );
        let audit = evaluate_cert_health(
            observation(Observation::Present(vec![certificate(
                1_000_000 + 7 * 86_400,
                true,
            )])),
            &CertHealthParameters {
                expiry_warning_days: 30,
                require_private_key: true,
            },
            1_000_000,
        );
        assert_eq!(audit.findings[0].code, "CERT-Expiring");
        assert_eq!(audit.findings[0].severity, Severity::High);
    }

    #[test]
    fn disabled_policy_and_incomplete_store_fail_closed() {
        let audit = evaluate_cert_health(
            CertHealthObservation {
                auto_enrollment_policy: Observation::Present(AutoEnrollmentPolicy { flags: 0 }),
                machine_certificates: Observation::AccessDenied,
            },
            &CertHealthParameters::default(),
            1_000_000,
        );
        assert_eq!(audit.findings[0].code, "CERT-AutoEnrollmentDisabled");
        assert_eq!(audit.findings[1].code, "CERT-MachineStoreIncomplete");
    }

    #[test]
    fn expired_certificates_are_not_hidden_by_warning_threshold() {
        let audit = evaluate_cert_health(
            observation(Observation::Present(vec![certificate(999_999, true)])),
            &CertHealthParameters::default(),
            1_000_000,
        );
        assert_eq!(audit.findings[0].code, "CERT-Expired");
        assert_eq!(audit.findings[0].status, FindingStatus::Fail);
    }
}
