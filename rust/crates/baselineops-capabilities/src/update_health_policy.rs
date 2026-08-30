//! Pure policy records for the narrow, read-only Update Health foundation.
//!
//! This is deliberately not parity with the legacy proof script.  It accepts
//! no catalog, path, package, KB, service, task, feed, command, or repair
//! setting.  The only evidence identities are compiled into this module.

use crate::{Observation, PolicyFinding, ServiceObservation};
use baselineops_domain::{FindingStatus, JsonMap, Severity};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;

/// The maximum number of Windows Update Agent history records retained.
pub const MAX_UPDATE_HISTORY_RECORDS: usize = 16;
/// The maximum UTF-8 bytes retained for one Windows Update Agent title.
pub const MAX_UPDATE_TITLE_BYTES: usize = 256;

/// Strict empty input for capability 06.
///
/// The collector never acts on caller-selected service names, task paths,
/// package locations, KB numbers, feeds, files, commands, or mutation flags.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateHealthParameters {}

/// Fixed Service Control Manager identities in this bounded foundation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateHealthService {
    /// Microsoft Update Health Service.
    UpdateHealth,
    /// Update Orchestrator Service.
    UpdateOrchestrator,
    /// Windows Update Medic Service.
    WindowsUpdateMedic,
    /// Windows Update service.
    WindowsUpdate,
    /// Delivery Optimization service.
    DeliveryOptimization,
    /// Background Intelligent Transfer Service.
    Bits,
    /// Cryptographic Services.
    CryptographicServices,
}

impl UpdateHealthService {
    /// Return the fixed SCM service name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::UpdateHealth => "uhssvc",
            Self::UpdateOrchestrator => "UsoSvc",
            Self::WindowsUpdateMedic => "WaaSMedicSvc",
            Self::WindowsUpdate => "wuauserv",
            Self::DeliveryOptimization => "DoSvc",
            Self::Bits => "BITS",
            Self::CryptographicServices => "cryptsvc",
        }
    }
}

/// Every SCM service observed by this capability, in a stable order.
pub const FIXED_UPDATE_HEALTH_SERVICES: [UpdateHealthService; 7] = [
    UpdateHealthService::UpdateHealth,
    UpdateHealthService::UpdateOrchestrator,
    UpdateHealthService::WindowsUpdateMedic,
    UpdateHealthService::WindowsUpdate,
    UpdateHealthService::DeliveryOptimization,
    UpdateHealthService::Bits,
    UpdateHealthService::CryptographicServices,
];

/// Exact Task Scheduler identities relevant to Windows Update scheduling.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateHealthTask {
    /// `\\Microsoft\\Windows\\WindowsUpdate\\Scheduled Start`.
    WindowsUpdateScheduledStart,
    /// `\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Scan`.
    UpdateOrchestratorScheduleScan,
}

impl UpdateHealthTask {
    /// Return the fixed Task Scheduler path.
    #[must_use]
    pub const fn path(self) -> &'static str {
        match self {
            Self::WindowsUpdateScheduledStart => {
                r"\Microsoft\Windows\WindowsUpdate\Scheduled Start"
            }
            Self::UpdateOrchestratorScheduleScan => {
                r"\Microsoft\Windows\UpdateOrchestrator\Schedule Scan"
            }
        }
    }
}

/// Every fixed task observed by this capability, in a stable order.
pub const FIXED_UPDATE_HEALTH_TASKS: [UpdateHealthTask; 2] = [
    UpdateHealthTask::WindowsUpdateScheduledStart,
    UpdateHealthTask::UpdateOrchestratorScheduleScan,
];

/// Task Scheduler runtime state retained without task-definition export.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateHealthTaskState {
    /// Task Scheduler supplied no recognized state.
    Unknown,
    /// The task is disabled.
    Disabled,
    /// The task is queued.
    Queued,
    /// The task is ready.
    Ready,
    /// The task is running.
    Running,
}

/// Non-secret, read-only metadata for one exact task.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct UpdateHealthTaskSnapshot {
    /// The scheduler's enabled flag.
    pub enabled: Observation<bool>,
    /// The current scheduler state.
    pub state: Observation<UpdateHealthTaskState>,
}

/// One bounded Windows Update Agent history record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct UpdateHistoryRecord {
    /// Bounded WUA title, not a package path or external feed item.
    pub title: String,
    /// WUA operation-result value, retained without interpretation.
    pub result_code: i32,
    /// WUA HRESULT, retained without remediation behavior.
    pub hresult: i32,
}

/// Bounded metadata acquired exclusively from Windows Update Agent COM.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct UpdateAgentMetadata {
    /// WUA's total history count, when available.
    pub total_history_count: u32,
    /// The newest fixed-size prefix of WUA history.
    pub recent_history: Vec<UpdateHistoryRecord>,
}

/// Read-only evidence collected for the capability-06 subset.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct UpdateHealthObservation {
    /// Fixed SCM service evidence only.
    pub services: BTreeMap<UpdateHealthService, Observation<ServiceObservation>>,
    /// Exact Task Scheduler evidence only.
    pub tasks: BTreeMap<UpdateHealthTask, Observation<UpdateHealthTaskSnapshot>>,
    /// Bounded update and SSU-adjacent metadata from WUA only.
    pub update_agent: Observation<UpdateAgentMetadata>,
}

/// Deterministic, non-mutating audit result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct UpdateHealthAudit {
    /// The untouched native evidence.
    pub observation: UpdateHealthObservation,
    /// Incomplete-evidence findings only; no service/task health is inferred.
    pub findings: Vec<PolicyFinding>,
}

/// The only truthful plan currently available for capability 06.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct UpdateHealthReadOnlyPlan {
    /// Audit evidence retained for a future, separately authorized design.
    pub audit: UpdateHealthAudit,
    /// Always zero: this native foundation has no mutation actions.
    pub mutation_count: u8,
}

/// Evaluate fixed evidence without Windows I/O.
///
/// A present stopped/disabled service or task is evidence, not an instruction
/// to start, stop, enable, disable, repair, reset, or reboot it.  Only absent
/// or incomplete evidence generates a finding, so callers cannot mistake this
/// bounded collector for a full update-health assertion.
#[must_use]
pub fn evaluate_update_health(observation: UpdateHealthObservation) -> UpdateHealthAudit {
    let mut findings = Vec::new();

    evaluate_service_findings(&observation.services, &mut findings);
    evaluate_task_findings(&observation.tasks, &mut findings);
    evaluate_update_agent_finding(&observation.update_agent, &mut findings);

    UpdateHealthAudit {
        observation,
        findings,
    }
}

fn evaluate_service_findings(
    services: &BTreeMap<UpdateHealthService, Observation<ServiceObservation>>,
    findings: &mut Vec<PolicyFinding>,
) {
    for service in FIXED_UPDATE_HEALTH_SERVICES {
        match services.get(&service) {
            Some(Observation::Present(_)) => {}
            Some(value) => incomplete(
                findings,
                "UPDATE-ServiceEvidenceIncomplete",
                "service",
                service.name(),
                observation_state(value),
            ),
            None => missing(findings, "service", service.name()),
        }
    }
}

fn evaluate_task_findings(
    tasks: &BTreeMap<UpdateHealthTask, Observation<UpdateHealthTaskSnapshot>>,
    findings: &mut Vec<PolicyFinding>,
) {
    for task in FIXED_UPDATE_HEALTH_TASKS {
        match tasks.get(&task) {
            Some(Observation::Present(snapshot)) => {
                evaluate_task_snapshot_findings(task, snapshot, findings);
            }
            Some(value) => incomplete(
                findings,
                "UPDATE-TaskEvidenceIncomplete",
                "task",
                task.path(),
                observation_state(value),
            ),
            None => missing(findings, "task", task.path()),
        }
    }
}

fn evaluate_task_snapshot_findings(
    task: UpdateHealthTask,
    snapshot: &UpdateHealthTaskSnapshot,
    findings: &mut Vec<PolicyFinding>,
) {
    if !matches!(snapshot.enabled, Observation::Present(_)) {
        incomplete(
            findings,
            "UPDATE-TaskEnabledEvidenceIncomplete",
            "task",
            task.path(),
            observation_state(&snapshot.enabled),
        );
    }
    if !matches!(snapshot.state, Observation::Present(_)) {
        incomplete(
            findings,
            "UPDATE-TaskStateEvidenceIncomplete",
            "task",
            task.path(),
            observation_state(&snapshot.state),
        );
    }
}

fn evaluate_update_agent_finding(
    update_agent: &Observation<UpdateAgentMetadata>,
    findings: &mut Vec<PolicyFinding>,
) {
    if !matches!(update_agent, Observation::Present(_)) {
        incomplete(
            findings,
            "UPDATE-AgentEvidenceIncomplete",
            "update_agent",
            "Windows Update Agent COM",
            observation_state(update_agent),
        );
    }
}

/// Construct the zero-mutation plan from fixed evidence.
#[must_use]
pub fn build_update_health_read_only_plan(
    observation: UpdateHealthObservation,
) -> UpdateHealthReadOnlyPlan {
    UpdateHealthReadOnlyPlan {
        audit: evaluate_update_health(observation),
        mutation_count: 0,
    }
}

fn missing(findings: &mut Vec<PolicyFinding>, kind: &'static str, identity: &'static str) {
    incomplete(
        findings,
        "UPDATE-FixedEvidenceMissing",
        kind,
        identity,
        "missing",
    );
}

fn incomplete(
    findings: &mut Vec<PolicyFinding>,
    code: &'static str,
    kind: &'static str,
    identity: &'static str,
    state: &'static str,
) {
    findings.push(PolicyFinding {
        code,
        status: FindingStatus::Warning,
        severity: Severity::Medium,
        message: format!("Required fixed {kind} evidence is {state}: {identity}."),
        evidence: JsonMap::from([
            ("read_only".into(), json!(true)),
            ("identity_kind".into(), json!(kind)),
            ("identity".into(), json!(identity)),
            ("observation_state".into(), json!(state)),
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

#[cfg(test)]
#[path = "update_health_policy_tests.rs"]
mod tests;
