use baselineops_domain::{DomainError, PlanV3, PlanValidationContext, Sha256Digest};
use baselineops_windows::TrustedInstallation;

use crate::planner::WorkerPlan;

/// A worker-computed plan waiting for approval of its exact digest.
#[derive(Debug)]
pub(crate) struct PlanApprovalSession {
    plan: PlanV3,
    digest: Sha256Digest,
}

impl PlanApprovalSession {
    /// Capture a plan that was computed inside the trusted worker.
    ///
    pub(crate) fn from_worker_plan(worker_plan: WorkerPlan) -> Self {
        let (plan, digest) = worker_plan.into_parts();
        Self { plan, digest }
    }

    /// Digest presented to the operator for approval.
    pub(crate) const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    /// Read-only proposal rendered by the standard-user client.
    pub(crate) const fn proposal(&self) -> &PlanV3 {
        &self.plan
    }

    /// Approve only an exact digest after all live bindings are independently revalidated.
    ///
    /// # Errors
    ///
    /// Returns an error when the approved digest differs or any live host, package,
    /// input, observation, source, tool, or expiry binding fails validation.
    pub(crate) fn approve(
        self,
        approved_digest: Sha256Digest,
        live: &PlanValidationContext,
        authority: &TrustedInstallation,
    ) -> Result<VerifiedPlan, ApprovalError> {
        self.approve_at_root(approved_digest, live, authority.root())
    }

    pub(crate) fn approve_at_root(
        self,
        approved_digest: Sha256Digest,
        live: &PlanValidationContext,
        trusted_root: &std::path::Path,
    ) -> Result<VerifiedPlan, ApprovalError> {
        if approved_digest != self.digest {
            return Err(ApprovalError::DigestMismatch);
        }
        let plan = self.plan.verify_for_execution(live)?;
        Ok(VerifiedPlan {
            plan,
            digest: self.digest,
            trusted_root: trusted_root.to_path_buf(),
        })
    }
}

/// Plan typestate accepted by the mutation executor.
///
/// It cannot be deserialized or constructed by a GUI/CLI-provided plan file.
#[derive(Debug)]
pub struct VerifiedPlan {
    plan: baselineops_domain::VerifiedPlan,
    digest: Sha256Digest,
    trusted_root: std::path::PathBuf,
}

impl VerifiedPlan {
    /// Worker-authoritative action proposal.
    pub fn plan(&self) -> &PlanV3 {
        self.plan.as_plan()
    }

    /// Approved canonical plan digest.
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    /// Protected product root that issued this execution authority.
    pub fn trusted_root(&self) -> &std::path::Path {
        &self.trusted_root
    }
}

/// Approval failures are invalid input/trust failures and must map to exit 4.
#[derive(Debug, thiserror::Error)]
pub enum ApprovalError {
    /// The client approved different bytes than the current proposal.
    #[error("approved plan digest does not match the worker proposal")]
    DigestMismatch,
    /// A host, tool, source, input, expiry, or observation binding changed.
    #[error(transparent)]
    Domain(#[from] DomainError),
}
