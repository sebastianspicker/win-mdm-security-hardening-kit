use baselineops_domain::{
    ActionId, ActionResultV3, ActionStatus, ArtifactV3, FindingV3, JsonMap, Operation,
    PlannedActionV3,
};
use chrono::{DateTime, Utc};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::VerifiedPlan;

/// Cooperative cancellation observed only at safe action boundaries.
#[derive(Clone, Debug, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    /// Request cancellation after the currently running action completes.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    /// Return whether cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Execution policy supplied by the CLI command, never by an untrusted profile.
#[derive(Clone, Copy, Debug)]
pub struct ExecutionPolicy {
    /// Operation being performed.
    pub operation: Operation,
    /// Continue after failures for audit and plan only.
    pub continue_on_error: bool,
}

impl ExecutionPolicy {
    fn should_stop_after_failure(self, action: &PlannedActionV3) -> bool {
        self.operation == Operation::Apply || !(self.continue_on_error || action.continue_on_error)
    }
}

/// Capability-provided action outcome before the engine adds timing and dependency state.
#[derive(Clone, Debug)]
pub struct ActionExecution {
    /// Terminal status.
    pub status: ActionStatus,
    /// Findings emitted by the capability.
    pub findings: Vec<FindingV3>,
    /// Artifacts emitted by the capability.
    pub artifacts: Vec<ArtifactV3>,
    /// Bounded execution metadata.
    pub metadata: JsonMap,
}

/// Narrow execution port implemented by capability dispatch.
pub trait ActionRunner {
    /// Execute one already-authorized action.
    ///
    /// # Errors
    ///
    /// Returns an error when the capability cannot produce a trustworthy structured outcome.
    fn run(
        &self,
        action: &PlannedActionV3,
        cancellation: &CancellationToken,
    ) -> Result<ActionExecution, SchedulerError>;
}

/// Deterministic scheduler output.
#[derive(Clone, Debug)]
pub struct ExecutionSummary {
    /// Ordered action results including dependency skips.
    pub actions: Vec<ActionResultV3>,
    /// Findings in action execution order.
    pub findings: Vec<FindingV3>,
    /// Artifacts in action execution order.
    pub artifacts: Vec<ArtifactV3>,
    /// Whether the operator requested cancellation.
    pub cancelled: bool,
}

/// Scheduler failures that prevent a trustworthy continuation.
#[derive(Debug, thiserror::Error)]
pub enum SchedulerError {
    /// The graph is invalid or cyclic.
    #[error("invalid action graph: {0}")]
    InvalidGraph(String),
    /// A capability failed before producing a structured terminal outcome.
    #[error("capability execution failed: {0}")]
    Capability(String),
}

/// Execute sequentially in deterministic topological order.
///
/// ```compile_fail
/// use baselineops_domain::PlanV3;
/// use baselineops_engine::{ActionRunner, execute_verified_plan};
///
/// fn raw_plan_cannot_apply(plan: &PlanV3, runner: &dyn ActionRunner) {
///     execute_verified_plan(plan, false, runner, unimplemented!(), unimplemented!());
/// }
/// ```
///
/// # Errors
///
/// Returns an error when the dependency graph is invalid or a capability fails
/// before producing a structured terminal outcome.
pub fn execute_verified_plan(
    verified_plan: &VerifiedPlan,
    continue_on_error: bool,
    runner: &dyn ActionRunner,
    cancellation: &CancellationToken,
    clock: impl Fn() -> DateTime<Utc>,
) -> Result<ExecutionSummary, SchedulerError> {
    let plan = verified_plan.plan();
    execute_actions(
        &plan.actions,
        ExecutionPolicy {
            operation: plan.intent.into(),
            continue_on_error,
        },
        runner,
        cancellation,
        clock,
    )
}

/// Schedules trusted planned actions inside the engine.
///
/// The function is crate-visible so raw deserialized plan actions can never
/// enter the public mutation path. External callers must use
/// [`execute_verified_plan`].
pub(crate) fn execute_actions(
    actions: &[PlannedActionV3],
    policy: ExecutionPolicy,
    runner: &dyn ActionRunner,
    cancellation: &CancellationToken,
    clock: impl Fn() -> DateTime<Utc>,
) -> Result<ExecutionSummary, SchedulerError> {
    let order = topological_order(actions)?;
    let by_id = actions
        .iter()
        .map(|action| (action.id, action))
        .collect::<BTreeMap<_, _>>();
    let mut state = ExecutionState::new(actions.len());

    for action_id in order {
        let action = by_id[&action_id];
        let started_at = clock();
        let (status, metadata) = state.next_outcome(action, policy, runner, cancellation);
        let completed_at = clock();
        state.record(action, status, metadata, started_at, completed_at);
    }

    Ok(state.finish())
}

struct ExecutionState {
    statuses: BTreeMap<ActionId, ActionStatus>,
    results: Vec<ActionResultV3>,
    findings: Vec<FindingV3>,
    artifacts: Vec<ArtifactV3>,
    stopped: bool,
    cancelled: bool,
}

impl ExecutionState {
    fn new(action_count: usize) -> Self {
        Self {
            statuses: BTreeMap::new(),
            results: Vec::with_capacity(action_count),
            findings: Vec::new(),
            artifacts: Vec::new(),
            stopped: false,
            cancelled: false,
        }
    }

    fn next_outcome(
        &mut self,
        action: &PlannedActionV3,
        policy: ExecutionPolicy,
        runner: &dyn ActionRunner,
        cancellation: &CancellationToken,
    ) -> (ActionStatus, JsonMap) {
        if cancellation.is_cancelled() {
            self.cancelled = true;
            self.stopped = true;
            return (ActionStatus::Skipped, JsonMap::new());
        }
        if self.stopped || self.dependency_failed(action) {
            return (ActionStatus::Skipped, JsonMap::new());
        }
        match runner.run(action, cancellation) {
            Ok(execution) => self.accept_execution(action, policy, execution),
            Err(error) => self.accept_error(action, policy, &error),
        }
    }

    fn dependency_failed(&self, action: &PlannedActionV3) -> bool {
        action.depends_on.iter().any(|dependency| {
            matches!(
                self.statuses.get(dependency),
                Some(ActionStatus::Failed | ActionStatus::Blocked | ActionStatus::Skipped)
            )
        })
    }

    fn accept_execution(
        &mut self,
        action: &PlannedActionV3,
        policy: ExecutionPolicy,
        execution: ActionExecution,
    ) -> (ActionStatus, JsonMap) {
        self.findings.extend(execution.findings);
        self.artifacts.extend(execution.artifacts);
        if matches!(
            execution.status,
            ActionStatus::Failed | ActionStatus::Blocked
        ) && policy.should_stop_after_failure(action)
        {
            self.stopped = true;
        }
        (execution.status, execution.metadata)
    }

    fn accept_error(
        &mut self,
        action: &PlannedActionV3,
        policy: ExecutionPolicy,
        error: &SchedulerError,
    ) -> (ActionStatus, JsonMap) {
        if policy.should_stop_after_failure(action) {
            self.stopped = true;
        }
        let metadata = JsonMap::from([(
            "engineError".into(),
            serde_json::Value::String(error.to_string()),
        )]);
        (ActionStatus::Failed, metadata)
    }

    fn record(
        &mut self,
        action: &PlannedActionV3,
        status: ActionStatus,
        metadata: JsonMap,
        started_at: DateTime<Utc>,
        completed_at: DateTime<Utc>,
    ) {
        self.statuses.insert(action.id, status);
        self.results.push(ActionResultV3 {
            action_id: action.id,
            capability: action.capability.clone(),
            status,
            started_at,
            completed_at,
            metadata,
        });
    }

    fn finish(self) -> ExecutionSummary {
        ExecutionSummary {
            actions: self.results,
            findings: self.findings,
            artifacts: self.artifacts,
            cancelled: self.cancelled,
        }
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use baselineops_domain::{ActionId, CapabilityId, RebootRequirement, Reversibility, RiskLevel};
    use std::sync::Mutex;

    fn action(depends_on: Vec<ActionId>, continue_on_error: bool) -> PlannedActionV3 {
        PlannedActionV3 {
            id: ActionId::new(),
            source_step: ActionId::new(),
            capability: CapabilityId::new("v3.test.capability").expect("capability"),
            operation: Operation::Audit,
            parameters: BTreeMap::new(),
            depends_on,
            continue_on_error,
            facts_digest: baselineops_domain::Sha256Digest::of_bytes(b"facts"),
            preconditions: vec![],
            risk: RiskLevel::Low,
            reversibility: Reversibility::NotApplicable,
            reboot: RebootRequirement::NotRequired,
            privileges: vec![],
            metadata: BTreeMap::new(),
        }
    }

    struct SequenceRunner {
        statuses: Mutex<Vec<ActionStatus>>,
    }

    impl ActionRunner for SequenceRunner {
        fn run(
            &self,
            _action: &PlannedActionV3,
            _cancellation: &CancellationToken,
        ) -> Result<ActionExecution, SchedulerError> {
            Ok(ActionExecution {
                status: self.statuses.lock().expect("lock").remove(0),
                findings: vec![],
                artifacts: vec![],
                metadata: BTreeMap::new(),
            })
        }
    }

    #[test]
    fn apply_is_fail_fast_even_when_continuation_is_requested() {
        let first = action(vec![], true);
        let second = action(vec![], true);
        let runner = SequenceRunner {
            statuses: Mutex::new(vec![ActionStatus::Failed, ActionStatus::Succeeded]),
        };
        let summary = execute_actions(
            &[first, second],
            ExecutionPolicy {
                operation: Operation::Apply,
                continue_on_error: true,
            },
            &runner,
            &CancellationToken::default(),
            Utc::now,
        )
        .expect("execution");
        assert_eq!(summary.actions[0].status, ActionStatus::Failed);
        assert_eq!(summary.actions[1].status, ActionStatus::Skipped);
    }

    #[test]
    fn failed_dependency_is_always_skipped() {
        let first = action(vec![], true);
        let second = action(vec![first.id], true);
        let runner = SequenceRunner {
            statuses: Mutex::new(vec![ActionStatus::Failed]),
        };
        let summary = execute_actions(
            &[first, second],
            ExecutionPolicy {
                operation: Operation::Audit,
                continue_on_error: true,
            },
            &runner,
            &CancellationToken::default(),
            Utc::now,
        )
        .expect("execution");
        assert_eq!(summary.actions[1].status, ActionStatus::Skipped);
    }

    #[test]
    fn cancellation_is_observed_before_dispatch_and_skips_remaining_actions() {
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        let runner = SequenceRunner {
            statuses: Mutex::new(vec![]),
        };
        let summary = execute_actions(
            &[action(vec![], false)],
            ExecutionPolicy {
                operation: Operation::Audit,
                continue_on_error: false,
            },
            &runner,
            &cancellation,
            Utc::now,
        )
        .expect("execution");
        assert!(summary.cancelled);
        assert_eq!(summary.actions[0].status, ActionStatus::Skipped);
    }
}

fn topological_order(actions: &[PlannedActionV3]) -> Result<Vec<ActionId>, SchedulerError> {
    if actions.is_empty() {
        return Err(SchedulerError::InvalidGraph(
            "no actions were supplied".into(),
        ));
    }
    let by_id = actions
        .iter()
        .map(|action| (action.id, action))
        .collect::<BTreeMap<_, _>>();
    if by_id.len() != actions.len() {
        return Err(SchedulerError::InvalidGraph("duplicate action IDs".into()));
    }
    let mut complete = BTreeSet::new();
    let mut order = Vec::with_capacity(actions.len());
    while order.len() < actions.len() {
        let next = actions.iter().find(|action| {
            !complete.contains(&action.id)
                && action
                    .depends_on
                    .iter()
                    .all(|dependency| complete.contains(dependency))
        });
        let Some(next) = next else {
            return Err(SchedulerError::InvalidGraph(
                "dependencies are missing or cyclic".into(),
            ));
        };
        if next
            .depends_on
            .iter()
            .any(|dependency| !by_id.contains_key(dependency))
        {
            return Err(SchedulerError::InvalidGraph(
                "an action depends on an unknown action".into(),
            ));
        }
        complete.insert(next.id);
        order.push(next.id);
    }
    Ok(order)
}
