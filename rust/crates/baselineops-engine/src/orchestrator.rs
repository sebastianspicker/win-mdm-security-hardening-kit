use baselineops_domain::{
    ActionResultV3, ActionStatus, ObservedStateV3, PlanV3, ProfileV3, RebootRequirement,
};
use chrono::{DateTime, Utc};

use crate::{CancellationToken, ExecutionSummary, VerifiedPlan, WorkerPlan};

/// Read-only observation seam. It never accepts execution authority.
pub trait AuditService {
    /// Capture the trusted observations required to build a plan.
    ///
    /// # Errors
    ///
    /// Returns an error when trustworthy read-only observations cannot be produced.
    fn audit(&self, profile: &ProfileV3) -> Result<ObservedStateV3, OrchestratorError>;
}

/// Plan-construction seam. Its output remains a worker-only typestate.
pub trait PlanService {
    /// Build a worker-authoritative proposal from a validated profile and observations.
    ///
    /// # Errors
    ///
    /// Returns an error when validated inputs cannot be converted into a worker plan.
    fn plan(
        &self,
        profile: &ProfileV3,
        observed_state: ObservedStateV3,
        now: DateTime<Utc>,
    ) -> Result<WorkerPlan, OrchestratorError>;
}

/// Apply seam. It can receive only a plan already approved and live-verified.
pub trait ApplyService {
    /// Execute the approved plan at safe cancellation boundaries.
    ///
    /// # Errors
    ///
    /// Returns an error when an execution summary cannot be trusted.
    fn apply(
        &self,
        plan: &VerifiedPlan,
        cancellation: &CancellationToken,
    ) -> Result<ExecutionSummary, OrchestratorError>;
}

/// Composition root that keeps audit, plan, and mutation providers distinct.
pub struct EngineOrchestrator<'a> {
    audit: &'a dyn AuditService,
    planner: &'a dyn PlanService,
    apply: &'a dyn ApplyService,
}

impl<'a> EngineOrchestrator<'a> {
    /// Compose independently supplied audit, plan, and apply services.
    #[must_use]
    pub const fn new(
        audit: &'a dyn AuditService,
        planner: &'a dyn PlanService,
        apply: &'a dyn ApplyService,
    ) -> Self {
        Self {
            audit,
            planner,
            apply,
        }
    }

    /// Run read-only audit and pass observations only to the planning seam.
    ///
    /// # Errors
    ///
    /// Returns an error from the audit or planning service.
    pub fn audit_and_plan(
        &self,
        profile: &ProfileV3,
        now: DateTime<Utc>,
    ) -> Result<WorkerPlan, OrchestratorError> {
        let observed_state = self.audit.audit(profile)?;
        self.planner.plan(profile, observed_state, now)
    }

    /// Apply an approved plan and summarize cancellation and reboot consequences.
    ///
    /// # Errors
    ///
    /// Returns an error from the apply service.
    pub fn apply(
        &self,
        plan: &VerifiedPlan,
        cancellation: &CancellationToken,
    ) -> Result<ApplyOutcome, OrchestratorError> {
        let execution = self.apply.apply(plan, cancellation)?;
        let disposition =
            aggregate_disposition(plan.plan(), &execution.actions, execution.cancelled);
        Ok(ApplyOutcome {
            execution,
            disposition,
        })
    }
}

/// Conservative aggregate of cancellation and reboot state for an apply attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionDisposition {
    /// True when cancellation was observed before every action completed.
    pub cancelled: bool,
    /// Highest reboot consequence among actions that may have executed.
    pub reboot: RebootRequirement,
}

/// Apply output retaining raw scheduler data and the operator-facing disposition.
#[derive(Clone, Debug)]
pub struct ApplyOutcome {
    /// Deterministic scheduler output.
    pub execution: ExecutionSummary,
    /// Cancellation and reboot aggregation.
    pub disposition: ExecutionDisposition,
}

/// Aggregate reboot consequences without treating skipped or blocked actions as executed.
#[must_use]
pub fn aggregate_disposition(
    plan: &PlanV3,
    actions: &[ActionResultV3],
    cancelled: bool,
) -> ExecutionDisposition {
    let reboot = aggregate_reboot(actions.iter().filter_map(|result| {
        plan.actions
            .iter()
            .find(|action| action.id == result.action_id)
            .map(|action| (result.status, action.reboot))
    }));
    ExecutionDisposition { cancelled, reboot }
}

fn aggregate_reboot(
    actions: impl Iterator<Item = (ActionStatus, RebootRequirement)>,
) -> RebootRequirement {
    actions
        .filter(|(status, _)| !matches!(status, ActionStatus::Skipped | ActionStatus::Blocked))
        .map(|(_, reboot)| reboot)
        .max_by_key(|reboot| reboot_rank(*reboot))
        .unwrap_or(RebootRequirement::NotRequired)
}

const fn reboot_rank(reboot: RebootRequirement) -> u8 {
    match reboot {
        RebootRequirement::NotRequired => 0,
        RebootRequirement::Recommended => 1,
        RebootRequirement::Required => 2,
    }
}

/// Service-boundary failures. The public seams normalize their implementation errors here.
#[derive(Debug, thiserror::Error)]
pub enum OrchestratorError {
    /// An audit service could not produce trustworthy observations.
    #[error("audit service failed: {0}")]
    Audit(String),
    /// A planner could not produce a trusted worker proposal.
    #[error("plan service failed: {0}")]
    Plan(String),
    /// An apply service could not produce a trustworthy execution summary.
    #[error("apply service failed: {0}")]
    Apply(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skipped_actions_do_not_raise_reboot_requirement() {
        let reboot = aggregate_reboot(
            [
                (ActionStatus::Skipped, RebootRequirement::Required),
                (ActionStatus::Succeeded, RebootRequirement::Recommended),
            ]
            .into_iter(),
        );
        assert_eq!(reboot, RebootRequirement::Recommended);
    }
}
