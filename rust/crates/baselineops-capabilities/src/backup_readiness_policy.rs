//! Pure, read-only policy evaluation for backup-readiness indicators.

use crate::{Observation, PolicyFinding};
use baselineops_domain::{FindingStatus, JsonMap, Severity};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Strict bounded parameters for legacy capability 36.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, rename_all = "snake_case", deny_unknown_fields)]
pub struct BackupReadinessPolicy {
    /// Minimum free bytes required on the operating-system volume.
    pub minimum_os_free_bytes: u64,
}
impl Default for BackupReadinessPolicy {
    fn default() -> Self {
        Self {
            minimum_os_free_bytes: 10 * 1024 * 1024 * 1024,
        }
    }
}
impl BackupReadinessPolicy {
    /// Validate the bounded free-space threshold.
    ///
    /// # Errors
    ///
    /// Returns an error unless the threshold is in the supported 1 GiB through
    /// 1 TiB range.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !(1024 * 1024 * 1024..=1024_u64 * 1024 * 1024 * 1024)
            .contains(&self.minimum_os_free_bytes)
        {
            return Err("minimum_os_free_bytes must be 1 GiB through 1 TiB");
        }
        Ok(())
    }
}

/// Fixed OS-volume free-space evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct OsVolumeSpace {
    /// Drive-rooted operating-system volume path.
    pub volume: String,
    /// Free bytes reported by `GetDiskFreeSpaceExW`.
    pub free_bytes: u64,
    /// Total bytes reported by `GetDiskFreeSpaceExW`.
    pub total_bytes: u64,
}
/// One strictly parsed VSS writer state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct VssWriter {
    /// Bounded VSS writer display name.
    pub name: String,
    /// Whether the exact supported writer state is `Stable`.
    pub stable: bool,
    /// Whether the exact supported last-error string is `No error`.
    pub no_error: bool,
}
/// Native evidence before backup-readiness evaluation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct BackupReadinessObservation {
    /// Operating-system volume free-space observation.
    pub os_volume: Observation<OsVolumeSpace>,
    /// Strictly parsed fixed `vssadmin list writers` observation.
    pub vss_writers: Observation<Vec<VssWriter>>,
    /// Presence of the fixed HKLM File History key.
    pub file_history_present: Observation<bool>,
}
/// Deterministic result for capability 36.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct BackupReadinessAudit {
    /// Native input evidence.
    pub observation: BackupReadinessObservation,
    /// Deterministic drift and incomplete-evidence findings.
    pub findings: Vec<PolicyFinding>,
}

/// Evaluate capability 36 without Windows I/O.
#[must_use]
pub fn evaluate_backup_readiness(
    observation: BackupReadinessObservation,
    policy: &BackupReadinessPolicy,
) -> BackupReadinessAudit {
    let mut findings = Vec::new();
    evaluate_os_volume(&observation.os_volume, policy, &mut findings);
    evaluate_vss_writers(&observation.vss_writers, &mut findings);
    evaluate_file_history(&observation.file_history_present, &mut findings);
    BackupReadinessAudit {
        observation,
        findings,
    }
}

fn evaluate_os_volume(
    observation: &Observation<OsVolumeSpace>,
    policy: &BackupReadinessPolicy,
    findings: &mut Vec<PolicyFinding>,
) {
    match observation {
        Observation::Present(space) if space.free_bytes >= policy.minimum_os_free_bytes => {}
        Observation::Present(space) => findings.push(finding(
            "BKP-OsDiskLowFree",
            FindingStatus::Fail,
            Severity::High,
            format!(
                "OS volume {} has {} free bytes, below {}.",
                space.volume, space.free_bytes, policy.minimum_os_free_bytes
            ),
        )),
        value => incomplete("BKP-OsDiskIncomplete", observation_state(value), findings),
    }
}

fn evaluate_vss_writers(
    observation: &Observation<Vec<VssWriter>>,
    findings: &mut Vec<PolicyFinding>,
) {
    match observation {
        Observation::Present(writers) if writers.is_empty() => incomplete(
            "BKP-VssWritersEmpty",
            "no VSS writers were parsed",
            findings,
        ),
        Observation::Present(writers) => evaluate_unhealthy_vss_writers(writers, findings),
        value => incomplete(
            "BKP-VssWritersIncomplete",
            observation_state(value),
            findings,
        ),
    }
}

fn evaluate_unhealthy_vss_writers(writers: &[VssWriter], findings: &mut Vec<PolicyFinding>) {
    for writer in writers
        .iter()
        .filter(|writer| !writer.stable || !writer.no_error)
    {
        findings.push(finding(
            "BKP-VssWriterFailed",
            FindingStatus::Fail,
            Severity::High,
            format!(
                "VSS writer {} is not stable or reports an error.",
                writer.name
            ),
        ));
    }
}

fn evaluate_file_history(observation: &Observation<bool>, findings: &mut Vec<PolicyFinding>) {
    match observation {
        Observation::Present(true) => {}
        Observation::Present(false) => findings.push(finding(
            "BKP-NoNativeBackupIndicator",
            FindingStatus::Warning,
            Severity::Low,
            "File History is not configured; confirm another backup product and restore test."
                .into(),
        )),
        value => incomplete(
            "BKP-FileHistoryIncomplete",
            observation_state(value),
            findings,
        ),
    }
}

/// Parse only the fixed English `vssadmin list writers` grammar.
/// Localized, partial, or unexpected output remains `Unparsed`.
#[must_use]
pub fn parse_vss_writers(output: &str) -> Observation<Vec<VssWriter>> {
    if output.is_empty() || output.len() > 256 * 1024 {
        return Observation::Unparsed;
    }
    let mut writers = Vec::new();
    for block in output.split("Writer name: '").skip(1) {
        let Some(writer) = parse_writer_block(block) else {
            return Observation::Unparsed;
        };
        writers.push(writer);
    }
    if writers.is_empty() {
        Observation::Unparsed
    } else {
        Observation::Present(writers)
    }
}

fn parse_writer_block(block: &str) -> Option<VssWriter> {
    let (name, body) = block.split_once('\'')?;
    let state = body
        .lines()
        .find_map(|line| line.trim().strip_prefix("State: ["))?;
    let (_, state) = state.split_once("] ")?;
    let error = body
        .lines()
        .find_map(|line| line.trim().strip_prefix("Last error: "))?;
    if name.is_empty() || name.len() > 256 || state.is_empty() || error.is_empty() {
        return None;
    }
    Some(VssWriter {
        name: name.into(),
        stable: state == "Stable",
        no_error: error == "No error",
    })
}

fn incomplete(code: &'static str, state: &str, findings: &mut Vec<PolicyFinding>) {
    findings.push(finding(
        code,
        FindingStatus::Warning,
        Severity::Medium,
        format!("Required backup-readiness evidence is incomplete: {state}."),
    ));
}
fn finding(
    code: &'static str,
    status: FindingStatus,
    severity: Severity,
    message: String,
) -> PolicyFinding {
    PolicyFinding {
        code,
        status,
        severity,
        message,
        evidence: JsonMap::from([("read_only".into(), json!(true))]),
    }
}
fn observation_state<T>(value: &Observation<T>) -> &'static str {
    match value {
        Observation::Present(_) => "present",
        Observation::Missing => "missing",
        Observation::AccessDenied => "access denied",
        Observation::TimedOut => "timed out",
        Observation::Truncated => "truncated",
        Observation::Failed { .. } => "failed",
        Observation::NotRun => "not run",
        Observation::Unparsed => "unparsed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn localized_vss_text_fails_closed() {
        assert!(matches!(
            parse_vss_writers("Writer Name: x"),
            Observation::Unparsed
        ));
    }
    #[test]
    fn mixed_vss_writers_preserve_failed_writer_and_audit_finding_order() {
        let audit = evaluate_backup_readiness(
            BackupReadinessObservation {
                os_volume: Observation::Present(OsVolumeSpace {
                    volume: "C:\\".into(),
                    free_bytes: BackupReadinessPolicy::default().minimum_os_free_bytes,
                    total_bytes: 100 * 1024 * 1024 * 1024,
                }),
                vss_writers: Observation::Present(vec![
                    VssWriter {
                        name: "System Writer".into(),
                        stable: true,
                        no_error: true,
                    },
                    VssWriter {
                        name: "SqlServerWriter".into(),
                        stable: false,
                        no_error: true,
                    },
                    VssWriter {
                        name: "Registry Writer".into(),
                        stable: true,
                        no_error: false,
                    },
                ]),
                file_history_present: Observation::Present(false),
            },
            &BackupReadinessPolicy::default(),
        );

        assert_eq!(
            audit.findings,
            vec![
                PolicyFinding {
                    code: "BKP-VssWriterFailed",
                    status: FindingStatus::Fail,
                    severity: Severity::High,
                    message: "VSS writer SqlServerWriter is not stable or reports an error."
                        .into(),
                    evidence: JsonMap::from([("read_only".into(), json!(true))]),
                },
                PolicyFinding {
                    code: "BKP-VssWriterFailed",
                    status: FindingStatus::Fail,
                    severity: Severity::High,
                    message: "VSS writer Registry Writer is not stable or reports an error."
                        .into(),
                    evidence: JsonMap::from([("read_only".into(), json!(true))]),
                },
                PolicyFinding {
                    code: "BKP-NoNativeBackupIndicator",
                    status: FindingStatus::Warning,
                    severity: Severity::Low,
                    message: "File History is not configured; confirm another backup product and restore test."
                        .into(),
                    evidence: JsonMap::from([("read_only".into(), json!(true))]),
                },
            ]
        );
    }

    #[test]
    fn empty_vss_writers_emit_the_exact_incomplete_finding() {
        let mut findings = Vec::new();
        evaluate_vss_writers(&Observation::Present(vec![]), &mut findings);

        assert_eq!(
            findings,
            vec![PolicyFinding {
                code: "BKP-VssWritersEmpty",
                status: FindingStatus::Warning,
                severity: Severity::Medium,
                message:
                    "Required backup-readiness evidence is incomplete: no VSS writers were parsed."
                        .into(),
                evidence: JsonMap::from([("read_only".into(), json!(true))]),
            }]
        );
    }

    #[test]
    fn incomplete_evidence_emits_findings_in_observation_order() {
        let audit = evaluate_backup_readiness(
            BackupReadinessObservation {
                os_volume: Observation::AccessDenied,
                vss_writers: Observation::AccessDenied,
                file_history_present: Observation::AccessDenied,
            },
            &BackupReadinessPolicy::default(),
        );
        assert_eq!(
            audit.findings,
            vec![
                PolicyFinding {
                    code: "BKP-OsDiskIncomplete",
                    status: FindingStatus::Warning,
                    severity: Severity::Medium,
                    message: "Required backup-readiness evidence is incomplete: access denied."
                        .into(),
                    evidence: JsonMap::from([("read_only".into(), json!(true))]),
                },
                PolicyFinding {
                    code: "BKP-VssWritersIncomplete",
                    status: FindingStatus::Warning,
                    severity: Severity::Medium,
                    message: "Required backup-readiness evidence is incomplete: access denied."
                        .into(),
                    evidence: JsonMap::from([("read_only".into(), json!(true))]),
                },
                PolicyFinding {
                    code: "BKP-FileHistoryIncomplete",
                    status: FindingStatus::Warning,
                    severity: Severity::Medium,
                    message: "Required backup-readiness evidence is incomplete: access denied."
                        .into(),
                    evidence: JsonMap::from([("read_only".into(), json!(true))]),
                },
            ]
        );
    }
}
