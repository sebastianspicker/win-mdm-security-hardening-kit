//! Pure, read-only policy evaluation for Windows Time and WEF readiness.
//!
//! Acquisition belongs to the Windows crate. These evaluators intentionally
//! treat missing, denied, timed-out, truncated, and unparsed observations as
//! incomplete evidence rather than manufacturing a healthy result.

use crate::PolicyFinding;
use baselineops_domain::{FindingStatus, JsonMap, Severity};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Bounded, source-independent service observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ServiceObservation {
    /// Fixed service name requested by the capability.
    pub name: String,
    /// Current SCM state when it could be read.
    pub state: ServiceState,
    /// Configured SCM start mode when it could be read.
    pub start_mode: ServiceStartMode,
}

/// Current Service Control Manager state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceState {
    /// The service is running.
    Running,
    /// The service exists but is not running.
    Stopped,
    /// A valid SCM state that is neither running nor stopped.
    Other(u32),
}

/// Service Control Manager start mode.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceStartMode {
    /// Automatic service start.
    Automatic,
    /// Automatic delayed service start.
    AutomaticDelayed,
    /// Demand/manual service start.
    Manual,
    /// Disabled service start.
    Disabled,
    /// An unexpected SCM start type.
    Other(u32),
}

/// Observation completeness shared by native registry and command reads.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", content = "value", rename_all = "snake_case")]
pub enum Observation<T> {
    /// A complete, typed observation.
    Present(T),
    /// The service, key, executable, or value is absent.
    Missing,
    /// The OS denied the minimum read access.
    AccessDenied,
    /// The native observation timed out before completion.
    TimedOut,
    /// Output exceeded the configured retention limit.
    Truncated,
    /// The command ran but returned a non-zero status.
    Failed {
        /// Native process exit code.
        exit_code: i32,
    },
    /// The observation was deliberately skipped by a read-only policy.
    NotRun,
    /// The output was complete but did not match supported localized labels.
    Unparsed,
}

/// Strict policy for capability 34. No mutation flags are accepted.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, rename_all = "snake_case", deny_unknown_fields)]
pub struct TimeSyncPolicy {
    /// Warning boundary for absolute root dispersion in milliseconds.
    pub root_dispersion_warn_ms: u32,
    /// Warning boundary for absolute phase offset in milliseconds.
    pub phase_offset_warn_ms: u32,
    /// Permit bounded `w32tm` observations when the service is stopped.
    pub always_run_w32tm_even_if_service_stopped: bool,
}

impl Default for TimeSyncPolicy {
    fn default() -> Self {
        Self {
            root_dispersion_warn_ms: 5_000,
            phase_offset_warn_ms: 1_000,
            always_run_w32tm_even_if_service_stopped: false,
        }
    }
}

/// Parsed and normalized `W32Time` state before policy evaluation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TimeSyncObservation {
    /// `w32time` service state.
    pub service: Observation<ServiceObservation>,
    /// `Type` from the `W32Time` Parameters key.
    pub time_type: Observation<String>,
    /// `NtpServer` from the `W32Time` Parameters key.
    pub ntp_server: Observation<String>,
    /// `Enabled` from the `NtpClient` provider key.
    pub ntp_client_enabled: Observation<u32>,
    /// Source parsed from `w32tm /query /source`.
    pub source: Observation<String>,
    /// Root dispersion parsed from `w32tm /query /status /verbose`.
    pub root_dispersion_ms: Observation<u32>,
    /// Phase offset parsed from `w32tm /query /status /verbose`.
    pub phase_offset_ms: Observation<i32>,
}

/// Deterministic result of the `TimeSync` read-only policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TimeSyncAudit {
    /// All native observations, including incomplete evidence.
    pub observation: TimeSyncObservation,
    /// Deterministic findings; no finding implies no inferred health claim.
    pub findings: Vec<PolicyFinding>,
}

/// Strict policy for capability 45. `wecutil` is optional and indicator-only.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, rename_all = "snake_case", deny_unknown_fields)]
pub struct WefReadinessPolicy {
    /// Run the exact bounded token sequence `qc /q` through `wecutil.exe`.
    pub include_wecutil_check: bool,
}

/// Parsed WEF client observations before evaluation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct WefReadinessObservation {
    /// `WinRM` service state and configured start mode.
    pub winrm: Observation<ServiceObservation>,
    /// String values under the fixed `SubscriptionManager` policy key.
    pub subscription_managers: Observation<Vec<String>>,
    /// Optional bounded `wecutil qc /q` indicator.
    pub wecutil_qc: Observation<WecutilQc>,
}

/// Non-authoritative summary of complete `wecutil qc /q` output.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct WecutilQc {
    /// Whether non-whitespace output was observed.
    pub has_output: bool,
    /// Whether a supported localized error marker was observed.
    pub explicit_failure_marker: bool,
}

/// Deterministic result of the WEF client readiness policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct WefReadinessAudit {
    /// All native observations, including incomplete evidence.
    pub observation: WefReadinessObservation,
    /// Deterministic findings; collector-side `wecutil` never proves readiness.
    pub findings: Vec<PolicyFinding>,
}

/// Evaluate capability 34 without Windows I/O.
#[must_use]
pub fn evaluate_time_sync(
    observation: TimeSyncObservation,
    policy: &TimeSyncPolicy,
) -> TimeSyncAudit {
    let mut findings = Vec::new();
    match &observation.service {
        Observation::Present(service) if service.state == ServiceState::Running => {}
        Observation::Present(service) => finding(
            &mut findings,
            "TIME-ServiceNotRunning",
            FindingStatus::Fail,
            Severity::High,
            format!("{} service is not running.", service.name),
        ),
        other => incomplete(
            &mut findings,
            "TIME-ServiceIncomplete",
            other,
            Severity::High,
        ),
    }
    match &observation.time_type {
        Observation::Present(value) if value.eq_ignore_ascii_case("NoSync") => finding(
            &mut findings,
            "TIME-TypeNoSync",
            FindingStatus::Fail,
            Severity::High,
            "Registry Type=NoSync: time service will not synchronize.",
        ),
        Observation::Present(_) => {}
        other => incomplete(
            &mut findings,
            "TIME-TypeIncomplete",
            other,
            Severity::Medium,
        ),
    }
    if matches!(&observation.time_type, Observation::Present(value) if value.eq_ignore_ascii_case("NTP"))
        && matches!(&observation.ntp_server, Observation::Present(value) if value.trim().is_empty())
    {
        finding(
            &mut findings,
            "TIME-NtpServerMissing",
            FindingStatus::Fail,
            Severity::High,
            "Registry Type=NTP has no NtpServer.",
        );
    } else if !matches!(observation.ntp_server, Observation::Present(_)) {
        incomplete(
            &mut findings,
            "TIME-NtpServerIncomplete",
            &observation.ntp_server,
            Severity::Medium,
        );
    }
    match &observation.ntp_client_enabled {
        Observation::Present(1) => {}
        Observation::Present(value) => finding(
            &mut findings,
            "TIME-NtpClientDisabled",
            FindingStatus::Fail,
            Severity::High,
            format!("NtpClient Enabled={value}; the client is not enabled."),
        ),
        other => incomplete(
            &mut findings,
            "TIME-NtpClientIncomplete",
            other,
            Severity::Medium,
        ),
    }
    evaluate_source(&mut findings, &observation.source);
    evaluate_root_dispersion(
        &mut findings,
        &observation.root_dispersion_ms,
        policy.root_dispersion_warn_ms,
    );
    match &observation.phase_offset_ms {
        Observation::Present(value) if value.unsigned_abs() > policy.phase_offset_warn_ms => {
            finding(
                &mut findings,
                "TIME-PhaseOffsetHigh",
                FindingStatus::Warning,
                Severity::Medium,
                format!(
                    "Phase offset {value} ms exceeds the {} ms warning threshold.",
                    policy.phase_offset_warn_ms
                ),
            );
        }
        Observation::Present(_) => {}
        other => incomplete(
            &mut findings,
            "TIME-PhaseOffsetIncomplete",
            other,
            Severity::Medium,
        ),
    }
    TimeSyncAudit {
        observation,
        findings,
    }
}

/// Evaluate capability 45 without Windows I/O.
#[must_use]
pub fn evaluate_wef_readiness(observation: WefReadinessObservation) -> WefReadinessAudit {
    let mut findings = Vec::new();
    match &observation.winrm {
        Observation::Present(service) if service.state != ServiceState::Running => finding(
            &mut findings,
            "WEF-WinRMNotRunning",
            FindingStatus::Fail,
            Severity::High,
            "WinRM service is not running; WEF sources require WinRM/WSMan.",
        ),
        Observation::Present(service) if service.start_mode == ServiceStartMode::Disabled => {
            finding(
                &mut findings,
                "WEF-WinRMDisabled",
                FindingStatus::Fail,
                Severity::High,
                "WinRM start mode is Disabled; client is not WEF-ready.",
            );
        }
        Observation::Present(_) => {}
        other => incomplete(&mut findings, "WEF-WinRMIncomplete", other, Severity::High),
    }
    match &observation.subscription_managers {
        Observation::Present(values) if values.is_empty() => finding(
            &mut findings,
            "WEF-SubscriptionManagerMissing",
            FindingStatus::Warning,
            Severity::Medium,
            "No SubscriptionManager policy value was observed; client binding is not evidenced.",
        ),
        Observation::Present(_) => {}
        other => incomplete(
            &mut findings,
            "WEF-SubscriptionManagerIncomplete",
            other,
            Severity::Medium,
        ),
    }
    match &observation.wecutil_qc {
        Observation::Present(result) if result.explicit_failure_marker => finding(
            &mut findings,
            "WEF-WecutilQcReportedFailure",
            FindingStatus::Warning,
            Severity::Low,
            "wecutil qc /q output contains a localized failure marker; it is not a client-health oracle.",
        ),
        Observation::Present(_) | Observation::NotRun => {}
        other => incomplete(
            &mut findings,
            "WEF-WecutilQcIncomplete",
            other,
            Severity::Low,
        ),
    }
    WefReadinessAudit {
        observation,
        findings,
    }
}

fn evaluate_source(findings: &mut Vec<PolicyFinding>, observation: &Observation<String>) {
    if !matches!(observation, Observation::Present(_)) {
        incomplete(
            findings,
            "TIME-SourceIncomplete",
            observation,
            Severity::Medium,
        );
    }
}

fn evaluate_root_dispersion(
    findings: &mut Vec<PolicyFinding>,
    observation: &Observation<u32>,
    warning: u32,
) {
    match observation {
        Observation::Present(value) if *value > warning => finding(
            findings,
            "TIME-RootDispersionHigh",
            FindingStatus::Warning,
            Severity::Medium,
            format!("Root dispersion {value} ms exceeds the {warning} ms warning threshold."),
        ),
        Observation::Present(_) => {}
        other => incomplete(
            findings,
            "TIME-RootDispersionIncomplete",
            other,
            Severity::Medium,
        ),
    }
}

fn incomplete<T>(
    findings: &mut Vec<PolicyFinding>,
    code: &'static str,
    observation: &Observation<T>,
    severity: Severity,
) {
    let suffix = match observation {
        Observation::Missing => "Missing",
        Observation::AccessDenied => "AccessDenied",
        Observation::TimedOut => "TimedOut",
        Observation::Truncated => "Truncated",
        Observation::Failed { .. } => "Failed",
        Observation::NotRun => "NotRun",
        Observation::Unparsed => "Unparsed",
        Observation::Present(_) => return,
    };
    finding(
        findings,
        code,
        FindingStatus::Warning,
        severity,
        format!("{code} observation is {suffix}; health is not inferred."),
    );
}

fn finding(
    findings: &mut Vec<PolicyFinding>,
    code: &'static str,
    status: FindingStatus,
    severity: Severity,
    message: impl Into<String>,
) {
    findings.push(PolicyFinding {
        code,
        status,
        severity,
        message: message.into(),
        evidence: JsonMap::from([("code".into(), json!(code))]),
    });
}

/// Parse a localized `w32tm /query /source` fixture without assigning health.
#[must_use]
pub fn parse_w32tm_source(text: &str) -> Observation<String> {
    parse_label(text, &["source", "quelle"]).map_or(Observation::Unparsed, Observation::Present)
}

/// Parse bounded localized `w32tm /query /status /verbose` measurements.
#[must_use]
pub fn parse_w32tm_status(text: &str) -> (Observation<u32>, Observation<i32>) {
    let root = parse_seconds_ms(text, &["root dispersion", "stammdispersion"])
        .map_or(Observation::Unparsed, Observation::Present);
    let phase = parse_signed_seconds_ms(text, &["phase offset", "phasenoffset"])
        .map_or(Observation::Unparsed, Observation::Present);
    (root, phase)
}

/// Parse the indicator-only `wecutil qc /q` output without claiming readiness.
#[must_use]
pub fn parse_wecutil_qc(text: &str) -> WecutilQc {
    let lower = text.to_ascii_lowercase();
    WecutilQc {
        has_output: !text.trim().is_empty(),
        explicit_failure_marker: ["error", "failed", "fehler", "fehlgeschlagen"]
            .iter()
            .any(|marker| lower.contains(marker)),
    }
}

fn parse_label(text: &str, labels: &[&str]) -> Option<String> {
    text.lines().find_map(|line| {
        let (label, value) = line.split_once(':')?;
        labels
            .iter()
            .any(|expected| label.trim().eq_ignore_ascii_case(expected))
            .then(|| value.trim())
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    })
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn parse_seconds_ms(text: &str, labels: &[&str]) -> Option<u32> {
    parse_label(text, labels)?
        .trim_end_matches(['s', 'S'])
        .trim()
        .parse::<f64>()
        .ok()
        .filter(|value| value.is_finite() && *value >= 0.0 && *value <= 86_400.0)
        .map(|value| (value * 1_000.0).round() as u32)
}

#[allow(clippy::cast_possible_truncation)]
fn parse_signed_seconds_ms(text: &str, labels: &[&str]) -> Option<i32> {
    parse_label(text, labels)?
        .trim_end_matches(['s', 'S'])
        .trim()
        .parse::<f64>()
        .ok()
        .filter(|value| value.is_finite() && value.abs() <= 86_400.0)
        .map(|value| (value * 1_000.0).round() as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn running(name: &str) -> Observation<ServiceObservation> {
        Observation::Present(ServiceObservation {
            name: name.into(),
            state: ServiceState::Running,
            start_mode: ServiceStartMode::Automatic,
        })
    }

    #[test]
    fn localized_w32tm_fixtures_parse_but_unknown_output_is_incomplete() {
        assert_eq!(
            parse_w32tm_source("Quelle: time.example.test\r\n"),
            Observation::Present("time.example.test".into())
        );
        assert_eq!(
            parse_w32tm_status("Stammdispersion: 5.5s\nPhasenoffset: -0.125s\n"),
            (Observation::Present(5_500), Observation::Present(-125))
        );
        assert_eq!(
            parse_w32tm_source("irrelevant output"),
            Observation::Unparsed
        );
    }

    #[test]
    fn time_evaluator_does_not_treat_incomplete_evidence_as_healthy() {
        let audit = evaluate_time_sync(
            TimeSyncObservation {
                service: running("w32time"),
                time_type: Observation::Present("NTP".into()),
                ntp_server: Observation::Present("pool.ntp.org,0x9".into()),
                ntp_client_enabled: Observation::Present(1),
                source: Observation::Unparsed,
                root_dispersion_ms: Observation::Truncated,
                phase_offset_ms: Observation::TimedOut,
            },
            &TimeSyncPolicy::default(),
        );
        assert!(
            audit
                .findings
                .iter()
                .all(|finding| finding.status != FindingStatus::Pass)
        );
        assert!(
            audit
                .findings
                .iter()
                .any(|finding| finding.code == "TIME-RootDispersionIncomplete")
        );
    }

    #[test]
    fn wef_service_and_policy_failures_remain_distinct() {
        let audit = evaluate_wef_readiness(WefReadinessObservation {
            winrm: Observation::Present(ServiceObservation {
                name: "WinRM".into(),
                state: ServiceState::Stopped,
                start_mode: ServiceStartMode::Disabled,
            }),
            subscription_managers: Observation::AccessDenied,
            wecutil_qc: Observation::Present(parse_wecutil_qc("Fehler: access denied")),
        });
        assert!(
            audit
                .findings
                .iter()
                .any(|finding| finding.code == "WEF-WinRMNotRunning")
        );
        assert!(
            audit
                .findings
                .iter()
                .any(|finding| finding.code == "WEF-SubscriptionManagerIncomplete")
        );
        assert!(
            audit
                .findings
                .iter()
                .any(|finding| finding.code == "WEF-WecutilQcReportedFailure")
        );
    }

    #[test]
    fn strict_parameters_reject_mutation_and_unknown_switches() {
        assert!(
            serde_json::from_value::<TimeSyncPolicy>(
                serde_json::json!({ "auto_start_service": true })
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<WefReadinessPolicy>(
                serde_json::json!({ "raw_command": "qc /q" })
            )
            .is_err()
        );
    }
}
