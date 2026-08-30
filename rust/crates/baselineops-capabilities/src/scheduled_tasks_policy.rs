//! Pure, bounded policy evaluation for the read-only Scheduled Tasks subset.
//!
//! This capability observes only four exact legacy critical paths. It never
//! accepts task paths, filters, XML, commands, credentials, or remediation
//! settings from profiles. The legacy Defender and `StorageSense` wildcard
//! categories are intentionally excluded: expanding a wildcard would require
//! general task enumeration and is outside this native foundation.

use crate::{Observation, PolicyFinding};
use baselineops_domain::{FindingStatus, JsonMap, Severity};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;

/// Strict empty parameter object for capability 07.
///
/// The native foundation has a compile-time task allowlist. Any supplied
/// setting, including a path, command, export destination, or mutation flag,
/// is rejected by serde before Windows APIs are called.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduledTasksParameters {}

/// One exact legacy critical task accepted by the native foundation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduledTask {
    /// `\\Microsoft\\Windows\\WindowsUpdate\\Scheduled Start`.
    WindowsUpdateScheduledStart,
    /// `\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Scan`.
    UpdateOrchestratorScheduleScan,
    /// `\\Microsoft\\Windows\\DiskCleanup\\SilentCleanup`.
    DiskCleanupSilentCleanup,
    /// `\\Microsoft\\Windows\\Servicing\\StartComponentCleanup`.
    ServicingStartComponentCleanup,
}

impl ScheduledTask {
    /// Return the exact COM task path for this allowlisted task.
    #[must_use]
    pub const fn path(self) -> &'static str {
        match self {
            Self::WindowsUpdateScheduledStart => {
                r"\Microsoft\Windows\WindowsUpdate\Scheduled Start"
            }
            Self::UpdateOrchestratorScheduleScan => {
                r"\Microsoft\Windows\UpdateOrchestrator\Schedule Scan"
            }
            Self::DiskCleanupSilentCleanup => r"\Microsoft\Windows\DiskCleanup\SilentCleanup",
            Self::ServicingStartComponentCleanup => {
                r"\Microsoft\Windows\Servicing\StartComponentCleanup"
            }
        }
    }
}

/// Fixed task set observed by this native subset.
pub const FIXED_SCHEDULED_TASKS: [ScheduledTask; 4] = [
    ScheduledTask::WindowsUpdateScheduledStart,
    ScheduledTask::UpdateOrchestratorScheduleScan,
    ScheduledTask::DiskCleanupSilentCleanup,
    ScheduledTask::ServicingStartComponentCleanup,
];

/// Scheduler runtime state exposed by Task Scheduler COM.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduledTaskState {
    /// The scheduler reports no reliable current state.
    Unknown,
    /// The task is disabled.
    Disabled,
    /// The task is queued.
    Queued,
    /// The task is ready.
    Ready,
    /// The task is currently running.
    Running,
}

/// Non-secret metadata read from one exact task.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ScheduledTaskSnapshot {
    /// The task's enabled property, without changing it.
    pub enabled: Observation<bool>,
    /// The task's scheduler state, without exporting its definition.
    pub state: Observation<ScheduledTaskState>,
}

/// Native evidence for each fixed task.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ScheduledTasksObservation {
    /// Observations keyed only by compile-time task identities.
    pub tasks: BTreeMap<ScheduledTask, Observation<ScheduledTaskSnapshot>>,
}

/// Deterministic audit result for capability 07.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ScheduledTasksAudit {
    /// Preserved read-only native evidence.
    pub observation: ScheduledTasksObservation,
    /// Drift and incomplete-evidence findings.
    pub findings: Vec<PolicyFinding>,
}

/// Truthful non-mutating plan for capability 07.
///
/// A plan only records the audit that informed it. It contains no actions,
/// does not enable or disable tasks, and cannot be applied through this raw
/// capability executor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ScheduledTasksReadOnlyPlan {
    /// The read-only audit used to make the plan.
    pub audit: ScheduledTasksAudit,
    /// Always zero because this foundation has no mutation actions.
    pub mutation_count: u8,
}

/// Evaluate fixed task evidence without Windows I/O.
#[must_use]
pub fn evaluate_scheduled_tasks(observation: ScheduledTasksObservation) -> ScheduledTasksAudit {
    let mut findings = Vec::new();
    for task in FIXED_SCHEDULED_TASKS {
        match observation.tasks.get(&task) {
            Some(Observation::Present(snapshot)) => {
                evaluate_snapshot(task, snapshot, &mut findings);
            }
            Some(Observation::Missing) | None => missing(task, &mut findings),
            Some(value) => incomplete(
                task,
                "TASK-ObservationIncomplete",
                observation_state(value),
                &mut findings,
            ),
        }
    }
    ScheduledTasksAudit {
        observation,
        findings,
    }
}

/// Construct the only truthful plan: retained observation and zero mutations.
#[must_use]
pub fn build_scheduled_tasks_read_only_plan(
    observation: ScheduledTasksObservation,
) -> ScheduledTasksReadOnlyPlan {
    ScheduledTasksReadOnlyPlan {
        audit: evaluate_scheduled_tasks(observation),
        mutation_count: 0,
    }
}

fn evaluate_snapshot(
    task: ScheduledTask,
    snapshot: &ScheduledTaskSnapshot,
    findings: &mut Vec<PolicyFinding>,
) {
    match &snapshot.enabled {
        Observation::Present(true) => {}
        Observation::Present(false) => findings.push(finding(
            task,
            "TASK-Disabled",
            FindingStatus::Fail,
            Severity::High,
            "The exact legacy critical task is disabled.",
        )),
        value => incomplete(
            task,
            "TASK-EnabledIncomplete",
            observation_state(value),
            findings,
        ),
    }
    match &snapshot.state {
        Observation::Present(ScheduledTaskState::Unknown) => findings.push(finding(
            task,
            "TASK-StateUnknown",
            FindingStatus::Warning,
            Severity::Medium,
            "Task Scheduler returned an unknown runtime state.",
        )),
        Observation::Present(_) => {}
        value => incomplete(
            task,
            "TASK-StateIncomplete",
            observation_state(value),
            findings,
        ),
    }
}

fn missing(task: ScheduledTask, findings: &mut Vec<PolicyFinding>) {
    findings.push(finding(
        task,
        "TASK-Missing",
        FindingStatus::Fail,
        Severity::High,
        "The exact legacy critical task is missing.",
    ));
}

fn incomplete(
    task: ScheduledTask,
    code: &'static str,
    state: &str,
    findings: &mut Vec<PolicyFinding>,
) {
    findings.push(finding(
        task,
        code,
        FindingStatus::Warning,
        Severity::Medium,
        format!("Required scheduled-task evidence is incomplete: {state}."),
    ));
}

fn finding(
    task: ScheduledTask,
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
        evidence: JsonMap::from([
            ("read_only".into(), json!(true)),
            ("task_path".into(), json!(task.path())),
        ]),
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

    fn healthy_observation() -> ScheduledTasksObservation {
        ScheduledTasksObservation {
            tasks: FIXED_SCHEDULED_TASKS
                .into_iter()
                .map(|task| {
                    (
                        task,
                        Observation::Present(ScheduledTaskSnapshot {
                            enabled: Observation::Present(true),
                            state: Observation::Present(ScheduledTaskState::Ready),
                        }),
                    )
                })
                .collect(),
        }
    }

    #[test]
    fn exact_legacy_disabled_task_fixture_fails() {
        let mut observation = healthy_observation();
        observation.tasks.insert(
            ScheduledTask::WindowsUpdateScheduledStart,
            Observation::Present(ScheduledTaskSnapshot {
                enabled: Observation::Present(false),
                state: Observation::Present(ScheduledTaskState::Disabled),
            }),
        );
        let audit = evaluate_scheduled_tasks(observation);
        assert_eq!(audit.findings[0].code, "TASK-Disabled");
        assert_eq!(audit.findings[0].status, FindingStatus::Fail);
    }

    #[test]
    fn missing_access_denied_unparsed_and_truncated_are_not_healthy() {
        let mut observation = healthy_observation();
        let [missing, denied, unparsed, truncated] = FIXED_SCHEDULED_TASKS;
        observation.tasks.insert(missing, Observation::Missing);
        observation.tasks.insert(denied, Observation::AccessDenied);
        observation.tasks.insert(unparsed, Observation::Unparsed);
        observation.tasks.insert(truncated, Observation::Truncated);
        let audit = evaluate_scheduled_tasks(observation);
        assert_eq!(audit.findings.len(), 4);
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
                .any(|finding| finding.code == "TASK-Missing")
        );
    }

    #[test]
    fn plan_retains_audit_and_never_contains_mutations() {
        let plan = build_scheduled_tasks_read_only_plan(healthy_observation());
        assert!(plan.audit.findings.is_empty());
        assert_eq!(plan.mutation_count, 0);
    }

    #[test]
    fn parameters_reject_task_selection_and_commands() {
        assert!(serde_json::from_value::<ScheduledTasksParameters>(serde_json::json!({})).is_ok());
        assert!(
            serde_json::from_value::<ScheduledTasksParameters>(
                serde_json::json!({ "task_path": "\\\\arbitrary" })
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<ScheduledTasksParameters>(
                serde_json::json!({ "command": "schtasks.exe" })
            )
            .is_err()
        );
    }
}
