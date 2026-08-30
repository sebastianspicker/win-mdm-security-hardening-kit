use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{ActionId, CapabilityId, FindingId, PlanId, ProfileId, ResultId, RunId};

use super::{ArtifactV3, HostIdentityV3, JsonMap, Operation, SchemaVersion};

/// Per-action terminal status.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionStatus {
    /// The action completed without non-compliant findings.
    Succeeded,
    /// The action completed and recorded non-compliant findings.
    Findings,
    /// A declared precondition was not met.
    Blocked,
    /// The action was skipped because a dependency did not complete.
    Skipped,
    /// The action failed while executing.
    Failed,
}

/// Terminal status for one execution unit.
pub type ExecutionStatus = ActionStatus;

/// The outcome of one planned action.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ActionResultV3 {
    /// Action identity from the plan.
    pub action_id: ActionId,
    /// Capability that produced this outcome.
    pub capability: CapabilityId,
    /// Terminal action status.
    pub status: ActionStatus,
    /// Start time.
    pub started_at: DateTime<Utc>,
    /// Completion time.
    pub completed_at: DateTime<Utc>,
    /// Capability-defined bounded outcome metadata.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: JsonMap,
}

/// Severity for an individual finding.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Informational evidence.
    Info,
    /// Low-priority condition.
    Low,
    /// Material condition needing normal remediation.
    Medium,
    /// Security-relevant condition needing prompt attention.
    High,
    /// Emergency security or availability condition.
    Critical,
}

/// Classification of what a finding means.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    /// Expected state was observed.
    Pass,
    /// Expected state was not observed.
    Fail,
    /// The state is usable but requires attention.
    Warning,
    /// Evidence with no pass/fail assertion.
    Info,
    /// The check did not run.
    Skipped,
    /// The check could not establish state.
    Error,
}

/// One capability finding with bounded structured evidence.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingV3 {
    /// Finding identity.
    #[serde(rename = "finding_id")]
    pub id: FindingId,
    /// Capability emitting the finding.
    pub capability: CapabilityId,
    /// Action that emitted the finding, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_id: Option<ActionId>,
    /// Stable, capability-defined code used for automation.
    pub code: String,
    /// Result classification.
    pub status: FindingStatus,
    /// Operator-impact severity.
    pub severity: Severity,
    /// Human-readable description.
    pub message: String,
    /// Time the condition was observed.
    pub observed_at: DateTime<Utc>,
    /// Bounded, typed evidence.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub evidence: JsonMap,
}

/// Overall terminal status of a plan execution.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultStatus {
    /// Execution completed with no drift or warnings.
    Completed,
    /// Execution failed to produce a trustworthy completed result.
    ExecutionFailed,
    /// Execution completed but observed warning-level drift.
    Warnings,
    /// The requested capability or operation is not supported.
    Unsupported,
    /// Input, trust, freshness, or plan verification was rejected.
    Rejected,
    /// The operator cancelled before completion.
    Cancelled,
}

/// Stable process exit mapping for v3 command-line boundaries.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[repr(u8)]
pub enum ExitCode {
    /// Completed without drift.
    Completed = 0,
    /// Worker or capability execution failure.
    ExecutionFailure = 1,
    /// Completed with warnings or drift.
    Warnings = 2,
    /// Requested capability or operation is unsupported.
    Unsupported = 3,
    /// Input, trust, freshness, or plan verification was rejected.
    Rejected = 4,
    /// The operator cancelled execution.
    Cancelled = 5,
}

impl ExitCode {
    /// Returns the platform process exit value.
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
    }

    /// Maps a result status to its stable process exit code.
    #[must_use]
    pub const fn for_status(status: ResultStatus) -> Self {
        match status {
            ResultStatus::Completed => Self::Completed,
            ResultStatus::ExecutionFailed => Self::ExecutionFailure,
            ResultStatus::Warnings => Self::Warnings,
            ResultStatus::Unsupported => Self::Unsupported,
            ResultStatus::Rejected => Self::Rejected,
            ResultStatus::Cancelled => Self::Cancelled,
        }
    }
}

/// Strict final execution result emitted by the worker and consumed by reports.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ResultV3 {
    /// Version marker for strict decoding.
    pub schema_version: SchemaVersion,
    /// Result identity.
    #[serde(rename = "result_id")]
    pub id: ResultId,
    /// Worker execution identity reserved in the plan.
    pub run_id: RunId,
    /// Executed plan identity.
    pub plan_id: PlanId,
    /// Source profile identity.
    pub profile_id: ProfileId,
    /// Capability scope for a single-capability result; absent for aggregate profiles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<CapabilityId>,
    /// Operation requested for this execution.
    pub operation: Operation,
    /// Host on which the result was produced.
    pub host: HostIdentityV3,
    /// Overall status.
    pub status: ResultStatus,
    /// Start time for the plan execution.
    pub started_at: DateTime<Utc>,
    /// Completion time for the plan execution.
    pub completed_at: DateTime<Utc>,
    /// Individual action outcomes.
    pub actions: Vec<ActionResultV3>,
    /// Findings retained in deterministic action emission order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<FindingV3>,
    /// Human-readable aggregate outcome summary.
    pub summary: String,
    /// Retained artifacts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<ArtifactV3>,
    /// Result metadata with no execution semantics.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: JsonMap,
}

/// Short name for the versioned host identity contract.
pub type HostIdentity = HostIdentityV3;

impl ResultV3 {
    /// Returns the stable CLI exit code for this terminal result.
    #[must_use]
    pub const fn exit_code(&self) -> ExitCode {
        ExitCode::for_status(self.status)
    }
}
