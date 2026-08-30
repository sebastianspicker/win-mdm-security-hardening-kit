//! Pure, bounded policy evaluation for the Sysmon configuration and drift audits.
//!
//! This foundation intentionally does not parse configuration XML, invoke the
//! Sysmon executable, or infer an effective configuration from service state.
//! A configuration digest is useful only when a future native source can prove
//! it; absent or incomplete evidence remains visible to the operator.

use crate::{EventLogObservation, Observation, PolicyFinding, ServiceStartMode, ServiceState};
use baselineops_domain::{FindingStatus, JsonMap, Severity};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::json;

/// Maximum fixed Sysmon Operational events retained by the native boundary.
pub const MAX_SYSMON_EVENTS: u16 = 32;
/// Maximum XML bytes retained for one fixed Sysmon Operational event.
pub const MAX_SYSMON_EVENT_XML_BYTES: u32 = 16 * 1024;
/// Maximum wait for one Sysmon Operational Event Log read.
pub const SYSMON_EVENT_TIMEOUT_MS: u32 = 5_000;

/// Strict read-only parameters shared by capabilities 16 and 17.
///
/// No configuration path, XML body, URL, command, service name, or executable
/// argument is accepted. The optional digest is a comparison target only; it
/// never names or loads a configuration file.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SysmonPolicy {
    /// Optional exact lowercase SHA-256 digest for a proven runtime-config indicator.
    #[serde(deserialize_with = "deserialize_expected_digest")]
    pub expected_config_sha256: Option<String>,
    /// Retain fixed local Operational-channel indicators when available.
    pub include_operational_events: bool,
}

impl Default for SysmonPolicy {
    fn default() -> Self {
        Self {
            expected_config_sha256: None,
            include_operational_events: true,
        }
    }
}

/// Fixed SCM identities that may represent a local Sysmon installation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SysmonServiceIdentity {
    /// The 64-bit Sysmon service identity.
    Sysmon64,
    /// The 32-bit-compatible Sysmon service identity.
    Sysmon,
}

/// Signature evidence collected only for an already bounded Sysmon image.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SysmonSignatureEvidence {
    /// The image passed the fixed Microsoft subject-only observation check.
    MicrosoftSubjectVerified,
    /// Signature validation did not prove the fixed Microsoft subject.
    Untrusted,
}

/// Bounded metadata retained for a safely resolved fixed-service image.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct SysmonBinaryEvidence {
    /// Image length in bytes; configuration content is never retained.
    pub bytes: u64,
    /// SHA-256 over the retained regular image file.
    pub sha256: String,
    /// Fixed-subject Authenticode observation, not execution authority.
    pub signature: SysmonSignatureEvidence,
}

/// Outcome of resolving an SCM-provided fixed Sysmon image path.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SysmonImageEvidence {
    /// Path validation and bounded image evidence completed.
    Verified(SysmonBinaryEvidence),
    /// SCM supplied an image path that violated the fixed read-only policy.
    Untrusted,
}

/// One fixed service observation, with no service-config command line retained.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct SysmonServiceObservation {
    /// Compile-time service identity queried through SCM.
    pub identity: SysmonServiceIdentity,
    /// Current SCM state.
    pub state: ServiceState,
    /// Current SCM start mode.
    pub start_mode: ServiceStartMode,
    /// Safely resolved image metadata and trust evidence.
    pub binary: Observation<SysmonImageEvidence>,
}

/// Native read-only Sysmon evidence before policy evaluation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct SysmonObservation {
    /// Exactly the `Sysmon64` and `Sysmon` SCM observations, in that order.
    pub services: Vec<Observation<SysmonServiceObservation>>,
    /// A future stable runtime-config digest source; currently never inferred.
    pub config_hash_indicator: Observation<String>,
    /// Bounded fixed Sysmon Operational-channel records, or `NotRun` by policy.
    pub operational_events: Observation<EventLogObservation>,
}

/// Deterministic read-only result for capabilities 16 and 17.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct SysmonAudit {
    /// Native input evidence, including missing, denied, and incomplete states.
    pub observation: SysmonObservation,
    /// Service, image, config-indicator, event, and completeness findings.
    pub findings: Vec<PolicyFinding>,
}

/// A truthful no-mutation plan for callers that request `Plan`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct SysmonReadOnlyPlan {
    /// Audit evidence used to prepare this non-mutating plan.
    pub audit: SysmonAudit,
    /// Always true: no service, file, event-channel, or configuration mutation exists here.
    pub no_mutation: bool,
    /// Static operator-facing limitation of this foundation.
    pub next_step: String,
}

/// Evaluate Sysmon configuration and drift indicators without platform I/O.
#[must_use]
pub fn evaluate_sysmon(observation: SysmonObservation, policy: &SysmonPolicy) -> SysmonAudit {
    let mut findings = Vec::new();
    evaluate_services(&observation.services, &mut findings);
    evaluate_config_hash(
        &observation.config_hash_indicator,
        policy.expected_config_sha256.as_deref(),
        &mut findings,
    );
    if policy.include_operational_events {
        evaluate_events(&observation.operational_events, &mut findings);
    }
    SysmonAudit {
        observation,
        findings,
    }
}

/// Produce a review-only plan; no apply action is proposed.
#[must_use]
pub fn build_sysmon_read_only_plan(audit: SysmonAudit) -> SysmonReadOnlyPlan {
    SysmonReadOnlyPlan {
        audit,
        no_mutation: true,
        next_step:
            "Review bounded evidence; configuration retrieval and all Sysmon changes are excluded."
                .into(),
    }
}

fn deserialize_expected_digest<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    if let Some(value) = &value
        && (value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    {
        return Err(serde::de::Error::custom(
            "expected_config_sha256 must be exactly 64 lowercase hexadecimal characters",
        ));
    }
    Ok(value)
}

fn evaluate_services(
    services: &[Observation<SysmonServiceObservation>],
    findings: &mut Vec<PolicyFinding>,
) {
    if services.len() != 2 {
        findings.push(finding(
            "SYSMON-ServiceSetIncomplete",
            FindingStatus::Warning,
            Severity::High,
            "The fixed Sysmon service observation set was incomplete.",
        ));
    }
    let mut present = false;
    for service in services.iter().take(2) {
        match service {
            Observation::Present(service) => {
                present = true;
                evaluate_present_service(service, findings);
            }
            Observation::Missing => {}
            value => incomplete("SYSMON-ServiceEvidenceIncomplete", value, findings),
        }
    }
    if !present
        && services
            .iter()
            .all(|value| matches!(value, Observation::Missing))
    {
        findings.push(finding(
            "SYSMON-NotInstalled",
            FindingStatus::Warning,
            Severity::Medium,
            "Neither fixed Sysmon service identity is installed.",
        ));
    }
}

fn evaluate_present_service(service: &SysmonServiceObservation, findings: &mut Vec<PolicyFinding>) {
    if service.state != ServiceState::Running {
        findings.push(finding(
            "SYSMON-ServiceNotRunning",
            FindingStatus::Warning,
            Severity::Medium,
            "A fixed Sysmon service exists but is not running.",
        ));
    }
    match &service.binary {
        Observation::Present(SysmonImageEvidence::Verified(binary)) => {
            if binary.signature == SysmonSignatureEvidence::Untrusted {
                findings.push(finding(
                    "SYSMON-ImageSignatureUntrusted",
                    FindingStatus::Fail,
                    Severity::High,
                    "The fixed Sysmon service image did not prove the expected Microsoft signature subject.",
                ));
            }
        }
        Observation::Present(SysmonImageEvidence::Untrusted) => findings.push(finding(
            "SYSMON-ImagePathUntrusted",
            FindingStatus::Fail,
            Severity::High,
            "The fixed Sysmon service image path violated the read-only trust boundary.",
        )),
        value => incomplete("SYSMON-ImageEvidenceIncomplete", value, findings),
    }
}

fn evaluate_config_hash(
    indicator: &Observation<String>,
    expected: Option<&str>,
    findings: &mut Vec<PolicyFinding>,
) {
    match (indicator, expected) {
        (Observation::Present(actual), Some(expected)) if actual == expected => {}
        (Observation::Present(_), Some(_)) => findings.push(finding(
            "SYSMON-ConfigDigestMismatch",
            FindingStatus::Fail,
            Severity::High,
            "The proven runtime configuration digest differs from the requested exact digest.",
        )),
        (Observation::Present(_), None) => findings.push(finding(
            "SYSMON-ConfigDigestUnpinned",
            FindingStatus::Info,
            Severity::Info,
            "A runtime configuration digest was observed without a requested comparison digest.",
        )),
        (value, _) => incomplete("SYSMON-ConfigHashIndicatorIncomplete", value, findings),
    }
}

fn evaluate_events(events: &Observation<EventLogObservation>, findings: &mut Vec<PolicyFinding>) {
    let Observation::Present(events) = events else {
        incomplete("SYSMON-OperationalEvidenceIncomplete", events, findings);
        return;
    };
    for event in &events.records {
        match event {
            Observation::Present(event) if event.event_id == 255 => findings.push(finding(
                "SYSMON-OperationalError",
                FindingStatus::Fail,
                Severity::High,
                "The bounded Sysmon Operational log contains an internal-error indicator.",
            )),
            Observation::Present(event) if event.event_id == 16 => findings.push(finding(
                "SYSMON-ConfigurationChanged",
                FindingStatus::Info,
                Severity::Info,
                "The bounded Sysmon Operational log contains a configuration-change indicator.",
            )),
            Observation::Present(_) => {}
            value => incomplete("SYSMON-OperationalRecordIncomplete", value, findings),
        }
    }
    if !events.enumeration_complete {
        findings.push(finding(
            "SYSMON-OperationalEnumerationIncomplete",
            FindingStatus::Warning,
            Severity::Medium,
            "Sysmon Operational Event Log enumeration reached a fixed bound or ended incompletely.",
        ));
    }
}

fn incomplete<T>(code: &'static str, value: &Observation<T>, findings: &mut Vec<PolicyFinding>) {
    findings.push(PolicyFinding {
        code,
        status: FindingStatus::Warning,
        severity: Severity::Medium,
        message: "Required Sysmon evidence is incomplete.".into(),
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
    use crate::EventLogRecord;

    fn service() -> Observation<SysmonServiceObservation> {
        Observation::Present(SysmonServiceObservation {
            identity: SysmonServiceIdentity::Sysmon64,
            state: ServiceState::Running,
            start_mode: ServiceStartMode::Automatic,
            binary: Observation::Present(SysmonImageEvidence::Verified(SysmonBinaryEvidence {
                bytes: 64,
                sha256: "ab".repeat(32),
                signature: SysmonSignatureEvidence::MicrosoftSubjectVerified,
            })),
        })
    }

    fn observation() -> SysmonObservation {
        SysmonObservation {
            services: vec![service(), Observation::Missing],
            config_hash_indicator: Observation::Present("cd".repeat(32)),
            operational_events: Observation::Present(EventLogObservation {
                records: vec![Observation::Present(EventLogRecord {
                    provider: "Microsoft-Windows-Sysmon".into(),
                    event_id: 4,
                    level: 4,
                    time_created: "2026-08-10T00:00:00Z".into(),
                    record_id: 1,
                    xml: Observation::Present("<Event/>".into()),
                    message: None,
                })],
                enumeration_complete: true,
            }),
        }
    }

    #[test]
    fn strict_parameters_reject_paths_commands_and_noncanonical_digest() {
        for value in [
            json!({"path": "C:\\config.xml"}),
            json!({"url": "https://example.invalid/config.xml"}),
            json!({"service": "other"}),
            json!({"command": "sysmon -c config.xml"}),
            json!({"expected_config_sha256": "AB".repeat(32)}),
        ] {
            assert!(serde_json::from_value::<SysmonPolicy>(value).is_err());
        }
    }

    #[test]
    fn matching_digest_fixture_has_no_drift_or_incomplete_findings() {
        let audit = evaluate_sysmon(
            observation(),
            &SysmonPolicy {
                expected_config_sha256: Some("cd".repeat(32)),
                include_operational_events: true,
            },
        );
        assert!(audit.findings.is_empty());
    }

    #[test]
    fn untrusted_and_incomplete_evidence_fail_closed() {
        let mut input = observation();
        input.config_hash_indicator = Observation::NotRun;
        input.operational_events = Observation::Present(EventLogObservation {
            records: vec![Observation::AccessDenied],
            enumeration_complete: false,
        });
        if let Observation::Present(service) = &mut input.services[0] {
            service.binary =
                Observation::Present(SysmonImageEvidence::Verified(SysmonBinaryEvidence {
                    bytes: 1,
                    sha256: "00".repeat(32),
                    signature: SysmonSignatureEvidence::Untrusted,
                }));
        }
        let audit = evaluate_sysmon(input, &SysmonPolicy::default());
        assert!(
            audit
                .findings
                .iter()
                .any(|finding| finding.code == "SYSMON-ImageSignatureUntrusted")
        );
        assert!(
            audit
                .findings
                .iter()
                .any(|finding| finding.code == "SYSMON-ConfigHashIndicatorIncomplete")
        );
        assert!(
            audit
                .findings
                .iter()
                .any(|finding| finding.code == "SYSMON-OperationalRecordIncomplete")
        );
    }

    #[test]
    fn service_evaluation_preserves_finding_order_and_ignores_a_third_observation() {
        let Observation::Present(mut stopped_untrusted) = service() else {
            unreachable!("service fixture must be present");
        };
        stopped_untrusted.state = ServiceState::Stopped;
        stopped_untrusted.binary =
            Observation::Present(SysmonImageEvidence::Verified(SysmonBinaryEvidence {
                bytes: 1,
                sha256: "00".repeat(32),
                signature: SysmonSignatureEvidence::Untrusted,
            }));
        let mut findings = Vec::new();

        evaluate_services(
            &[
                Observation::Present(stopped_untrusted),
                Observation::AccessDenied,
                Observation::TimedOut,
            ],
            &mut findings,
        );

        assert_eq!(
            findings,
            vec![
                PolicyFinding {
                    code: "SYSMON-ServiceSetIncomplete",
                    status: FindingStatus::Warning,
                    severity: Severity::High,
                    message: "The fixed Sysmon service observation set was incomplete.".into(),
                    evidence: JsonMap::from([("read_only".into(), json!(true))]),
                },
                PolicyFinding {
                    code: "SYSMON-ServiceNotRunning",
                    status: FindingStatus::Warning,
                    severity: Severity::Medium,
                    message: "A fixed Sysmon service exists but is not running.".into(),
                    evidence: JsonMap::from([("read_only".into(), json!(true))]),
                },
                PolicyFinding {
                    code: "SYSMON-ImageSignatureUntrusted",
                    status: FindingStatus::Fail,
                    severity: Severity::High,
                    message: "The fixed Sysmon service image did not prove the expected Microsoft signature subject.".into(),
                    evidence: JsonMap::from([("read_only".into(), json!(true))]),
                },
                PolicyFinding {
                    code: "SYSMON-ServiceEvidenceIncomplete",
                    status: FindingStatus::Warning,
                    severity: Severity::Medium,
                    message: "Required Sysmon evidence is incomplete.".into(),
                    evidence: JsonMap::from([(
                        "observation".into(),
                        json!("access_denied"),
                    )]),
                },
            ]
        );
    }

    #[test]
    fn not_installed_requires_every_observation_in_the_whole_slice_to_be_missing() {
        let mut all_missing_findings = Vec::new();
        evaluate_services(
            &[
                Observation::Missing,
                Observation::Missing,
                Observation::Missing,
            ],
            &mut all_missing_findings,
        );
        assert_eq!(
            all_missing_findings,
            vec![
                PolicyFinding {
                    code: "SYSMON-ServiceSetIncomplete",
                    status: FindingStatus::Warning,
                    severity: Severity::High,
                    message: "The fixed Sysmon service observation set was incomplete.".into(),
                    evidence: JsonMap::from([("read_only".into(), json!(true))]),
                },
                PolicyFinding {
                    code: "SYSMON-NotInstalled",
                    status: FindingStatus::Warning,
                    severity: Severity::Medium,
                    message: "Neither fixed Sysmon service identity is installed.".into(),
                    evidence: JsonMap::from([("read_only".into(), json!(true))]),
                },
            ]
        );

        let mut third_observation_findings = Vec::new();
        evaluate_services(
            &[
                Observation::Missing,
                Observation::Missing,
                Observation::AccessDenied,
            ],
            &mut third_observation_findings,
        );
        assert_eq!(
            third_observation_findings,
            vec![PolicyFinding {
                code: "SYSMON-ServiceSetIncomplete",
                status: FindingStatus::Warning,
                severity: Severity::High,
                message: "The fixed Sysmon service observation set was incomplete.".into(),
                evidence: JsonMap::from([("read_only".into(), json!(true))]),
            }]
        );
    }
}
