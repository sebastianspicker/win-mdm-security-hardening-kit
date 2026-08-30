//! Strict, versioned contracts shared by `BaselineOps` v3 components.
//!
//! The crate deliberately keeps execution-specific implementation details out
//! of its types.  Profiles describe requested work, plans bind that work to a
//! particular host and observation, and results describe what actually ran.

#![forbid(unsafe_code)]

mod canonical;
mod error;
mod ids;
mod load;
mod model;
mod validate;

#[cfg(test)]
mod tests;

pub use canonical::{
    Sha256Digest, canonical_json_bytes, canonical_json_digest, canonical_json_value,
};
pub use error::{DomainError, DomainResult};
pub use ids::{ActionId, ArtifactId, CapabilityId, FindingId, PlanId, ProfileId, ResultId, RunId};
pub use load::{JsonLoadLimits, load_json, load_json_file, load_plan_json, load_profile_json};
pub use model::{
    ActionKind, ActionResultV3, ActionStatus, ArtifactKind, ArtifactV3, CapabilityStatus,
    ExecutionIntent, ExecutionStatus, ExitCode, FindingStatus, FindingV3, HostIdentity,
    HostIdentityV3, ImplementationStatus, InputIdentityV3, JsonMap, ObservedStateV3,
    ObservedValueV3, Operation, OsFamily, PlanV3, PlannedActionV3, PreconditionKind,
    PreconditionV3, Privilege, ProfileDefaultsV3, ProfileStepV3, ProfileV3, RebootRequirement,
    ResultStatus, ResultV3, Reversibility, RiskLevel, SchemaVersion, Severity, SourceIdentityV3,
    SourceKind, ToolIdentityV3,
};
pub use validate::{PlanValidationContext, ProfileValidation, TopologicalOrder, VerifiedPlan};

/// Maximum number of entries accepted in a typed parameter or metadata map.
pub const MAX_TYPED_MAP_ENTRIES: usize = 256;
