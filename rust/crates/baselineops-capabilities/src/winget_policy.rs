//! Typed, read-only `WinGet` evidence shared by capabilities 08 and 25.
//!
//! This is deliberately a narrow foundation, not parity with either legacy
//! script. It accepts no source, package, configuration file, executable,
//! argument, repair, reset, install, or apply input. Native acquisition may
//! report the fixed App Paths registration only; source and configuration
//! evidence remain explicitly incomplete until stable package APIs can be
//! integrated without invoking an untrusted App Execution Alias.

use crate::{Observation, PolicyFinding};
use baselineops_domain::{FindingStatus, JsonMap, Severity};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Canonical capability-08 identifier.
pub const WINGET_SELF_HEAL_ID: &str = "v3.winget.self-heal";
/// Canonical capability-25 identifier.
pub const WINGET_CONFIGURATION_ID: &str = "v3.winget.configuration";
/// Fixed Microsoft App Installer package family identity.
pub const APP_INSTALLER_PACKAGE_FAMILY: &str = "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe";
/// Fixed HKLM App Paths leaf used only as installation-location evidence.
pub const WINGET_APP_PATHS_KEY: &str =
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\winget.exe";
/// Maximum UTF-8 bytes retained from the fixed App Paths default value.
pub const MAX_WINGET_APP_PATH_BYTES: usize = 1024;

/// Strict empty input accepted by both bounded `WinGet` foundations.
///
/// The legacy scripts accept private sources, files, raw arguments, package
/// agreements, remediation settings, and configuration content. None of those
/// are part of this native read-only slice.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WingetParameters {}

/// Parsed App Installer version, independent of localized display text.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct WingetVersion {
    /// Major version component.
    pub major: u16,
    /// Minor version component.
    pub minor: u16,
    /// Patch version component.
    pub patch: u16,
}

/// Fixed App Installer location evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WingetExecutableEvidence {
    /// A bounded absolute App Paths value. It is not an execution authority.
    Located {
        /// Canonical App Installer package family expected by this foundation.
        package_family: String,
        /// Bounded absolute path recorded as evidence only.
        path: String,
        /// Version is intentionally unavailable without a verified package API.
        version: Observation<WingetVersion>,
    },
    /// The fixed App Paths value was present but cannot be used as evidence.
    UntrustedPath {
        /// Bounded raw location retained for diagnosis, never execution.
        path: String,
    },
}

/// Non-secret source evidence retained by a future package API adapter.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct WingetSourceEvidence {
    /// Count from a bounded, API-supplied source inventory.
    pub source_count: u16,
}

/// Non-secret configuration evidence retained by a future package API adapter.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct WingetConfigurationEvidence {
    /// Whether the package API exposed a configuration capability indicator.
    pub available: bool,
}

/// Shared bounded observation acquired once for both canonical `WinGet` IDs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct WingetObservation {
    /// Fixed HKLM App Paths evidence for `winget.exe`.
    pub executable: Observation<WingetExecutableEvidence>,
    /// Source inventory evidence. This foundation does not invoke `winget source`.
    pub sources: Observation<WingetSourceEvidence>,
    /// Configuration capability evidence. No caller-selected config is opened.
    pub configuration: Observation<WingetConfigurationEvidence>,
}

/// Deterministic read-only result for either bounded `WinGet` capability.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct WingetAudit {
    /// Canonical capability evaluated from the shared acquisition.
    pub capability_id: String,
    /// Untouched native evidence, including incomplete observations.
    pub observation: WingetObservation,
    /// Findings that prevent this limited evidence from being mistaken for health.
    pub findings: Vec<PolicyFinding>,
}

/// The only truthful plan exposed by the current `WinGet` foundation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct WingetReadOnlyPlan {
    /// The audit retained for a future separately authorized design.
    pub audit: WingetAudit,
    /// Always zero: no native mutation action exists in this slice.
    pub mutation_count: u8,
}

/// Parse a fixed three-component version without depending on localized labels.
///
/// A leading `v` is accepted because App Installer commonly emits it. Suffixes,
/// four-component versions, whitespace, signed values, and non-ASCII digits are
/// rejected rather than silently normalized.
pub fn parse_winget_version(value: &str) -> Option<WingetVersion> {
    let value = value.strip_prefix('v').unwrap_or(value);
    let mut parts = value.split('.');
    let major = parse_component(parts.next()?)?;
    let minor = parse_component(parts.next()?)?;
    let patch = parse_component(parts.next()?)?;
    parts.next().is_none().then_some(WingetVersion {
        major,
        minor,
        patch,
    })
}

fn parse_component(value: &str) -> Option<u16> {
    (!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| value.parse().ok())
        .flatten()
}

/// Evaluate capability 08 using shared acquisition without Windows I/O.
#[must_use]
pub fn evaluate_winget_self_heal(observation: WingetObservation) -> WingetAudit {
    evaluate(WINGET_SELF_HEAL_ID, observation, false)
}

/// Evaluate capability 25 using shared acquisition without Windows I/O.
#[must_use]
pub fn evaluate_winget_configuration(observation: WingetObservation) -> WingetAudit {
    evaluate(WINGET_CONFIGURATION_ID, observation, true)
}

/// Build a truthful zero-mutation plan for either canonical capability.
#[must_use]
pub fn build_winget_read_only_plan(audit: WingetAudit) -> WingetReadOnlyPlan {
    WingetReadOnlyPlan {
        audit,
        mutation_count: 0,
    }
}

fn evaluate(
    capability_id: &'static str,
    observation: WingetObservation,
    configuration_required: bool,
) -> WingetAudit {
    let mut findings = Vec::new();
    executable_findings(&observation.executable, &mut findings);
    source_findings(&observation.sources, &mut findings);
    if configuration_required {
        configuration_findings(&observation.configuration, &mut findings);
    }
    WingetAudit {
        capability_id: capability_id.into(),
        observation,
        findings,
    }
}

fn source_findings(
    evidence: &Observation<WingetSourceEvidence>,
    findings: &mut Vec<PolicyFinding>,
) {
    match evidence {
        Observation::Present(WingetSourceEvidence { source_count: 0 }) => finding(
            findings,
            "WINGET-SourceInventoryEmpty",
            FindingStatus::Warning,
            Severity::Medium,
            "The bounded WinGet source inventory is empty.",
            "empty",
        ),
        Observation::Present(_) => {}
        other => incomplete(other, "WINGET-SourceEvidenceIncomplete", findings),
    }
}

fn configuration_findings(
    evidence: &Observation<WingetConfigurationEvidence>,
    findings: &mut Vec<PolicyFinding>,
) {
    match evidence {
        Observation::Present(WingetConfigurationEvidence { available: false }) => finding(
            findings,
            "WINGET-ConfigurationUnavailable",
            FindingStatus::Warning,
            Severity::Medium,
            "The package API reported no WinGet configuration capability.",
            "unavailable",
        ),
        Observation::Present(_) => {}
        other => incomplete(other, "WINGET-ConfigurationEvidenceIncomplete", findings),
    }
}

fn executable_findings(
    evidence: &Observation<WingetExecutableEvidence>,
    findings: &mut Vec<PolicyFinding>,
) {
    match evidence {
        Observation::Present(WingetExecutableEvidence::Located { version, .. }) => {
            incomplete(version, "WINGET-VersionEvidenceIncomplete", findings);
        }
        Observation::Present(WingetExecutableEvidence::UntrustedPath { .. }) => finding(
            findings,
            "WINGET-AppPathUntrusted",
            FindingStatus::Warning,
            Severity::High,
            "The fixed WinGet App Paths value is not a safe absolute evidence path.",
            "untrusted",
        ),
        other => incomplete(other, "WINGET-AppInstallerEvidenceIncomplete", findings),
    }
}

fn incomplete<T>(
    observation: &Observation<T>,
    code: &'static str,
    findings: &mut Vec<PolicyFinding>,
) {
    if !matches!(observation, Observation::Present(_)) {
        finding(
            findings,
            code,
            FindingStatus::Warning,
            Severity::Medium,
            "Required read-only WinGet evidence is incomplete.",
            observation_state(observation),
        );
    }
}

fn finding(
    findings: &mut Vec<PolicyFinding>,
    code: &'static str,
    status: FindingStatus,
    severity: Severity,
    message: &str,
    state: &'static str,
) {
    findings.push(PolicyFinding {
        code,
        status,
        severity,
        message: message.into(),
        evidence: JsonMap::from([
            ("read_only".into(), json!(true)),
            ("state".into(), json!(state)),
        ]),
    });
}

fn observation_state<T>(observation: &Observation<T>) -> &'static str {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn complete_location(version: Observation<WingetVersion>) -> WingetObservation {
        WingetObservation {
            executable: Observation::Present(WingetExecutableEvidence::Located {
                package_family: APP_INSTALLER_PACKAGE_FAMILY.into(),
                path: r"C:\Program Files\WindowsApps\winget.exe".into(),
                version,
            }),
            sources: Observation::Present(WingetSourceEvidence { source_count: 1 }),
            configuration: Observation::Present(WingetConfigurationEvidence { available: true }),
        }
    }

    #[test]
    fn localized_version_fixture_is_strict_and_locale_independent() {
        assert_eq!(
            parse_winget_version("v1.6.3482"),
            Some(WingetVersion {
                major: 1,
                minor: 6,
                patch: 3482,
            })
        );
        for value in [
            "version 1.6.3482",
            "1,6,3482",
            "1.6",
            "1.6.3482.0",
            " 1.6.3482",
        ] {
            assert_eq!(parse_winget_version(value), None);
        }
    }

    #[test]
    fn source_and_configuration_fixtures_are_retained_without_side_effects() {
        let audit =
            evaluate_winget_configuration(complete_location(Observation::Present(WingetVersion {
                major: 1,
                minor: 6,
                patch: 0,
            })));
        assert!(audit.findings.is_empty());
        assert_eq!(build_winget_read_only_plan(audit).mutation_count, 0);
    }

    #[test]
    fn empty_sources_or_unavailable_configuration_are_not_healthy() {
        let mut observation = complete_location(Observation::Present(WingetVersion {
            major: 1,
            minor: 6,
            patch: 0,
        }));
        observation.sources = Observation::Present(WingetSourceEvidence { source_count: 0 });
        observation.configuration =
            Observation::Present(WingetConfigurationEvidence { available: false });
        let audit = evaluate_winget_configuration(observation);
        assert_eq!(audit.findings.len(), 2);
    }

    #[test]
    fn missing_denied_untrusted_truncated_and_unparsed_evidence_never_looks_healthy() {
        for executable in [
            Observation::Missing,
            Observation::AccessDenied,
            Observation::Truncated,
            Observation::Unparsed,
            Observation::Present(WingetExecutableEvidence::UntrustedPath {
                path: "winget.exe".into(),
            }),
        ] {
            let audit = evaluate_winget_self_heal(WingetObservation {
                executable,
                sources: Observation::NotRun,
                configuration: Observation::NotRun,
            });
            assert!(!audit.findings.is_empty());
            assert!(
                audit
                    .findings
                    .iter()
                    .all(|finding| finding.status != FindingStatus::Pass)
            );
        }
    }

    #[test]
    fn unknown_parameters_are_rejected() {
        assert!(
            serde_json::from_value::<WingetParameters>(serde_json::json!({
                "config_path": "untrusted.yaml"
            }))
            .is_err()
        );
    }
}
