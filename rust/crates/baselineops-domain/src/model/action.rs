use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{ActionId, ArtifactId, CapabilityId, ProfileId, Sha256Digest};

use super::{
    JsonMap, Operation, OsFamily, Privilege, RebootRequirement, Reversibility, RiskLevel,
    SchemaVersion,
};

/// A typed prerequisite evaluated by the planner or worker.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PreconditionV3 {
    /// The worker must have (or deliberately not have) elevation.
    Elevation {
        /// Expected elevation state.
        required: bool,
    },
    /// The worker token must contain a named privilege.
    Privilege {
        /// Required privilege.
        privilege: Privilege,
    },
    /// A capability must be registered in the runtime.
    CapabilityAvailable {
        /// Capability expected to be available.
        capability: CapabilityId,
    },
    /// The plan is bound to the captured host fingerprint.
    HostFingerprint {
        /// Canonical digest of host identity fields.
        fingerprint: Sha256Digest,
    },
    /// The action depends on a specific observed-state capture.
    ObservedStateDigest {
        /// Canonical digest of the state capture.
        digest: Sha256Digest,
    },
    /// The action requires a particular operating-system family and optional minimum version.
    OperatingSystem {
        /// Required OS family.
        family: OsFamily,
        /// Capability-defined minimum version, compared by the capability.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        minimum_version: Option<String>,
    },
}

/// Discriminant for a [`PreconditionV3`].
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreconditionKind {
    /// Elevation-state prerequisite.
    Elevation,
    /// Token privilege prerequisite.
    Privilege,
    /// Capability-registry prerequisite.
    CapabilityAvailable,
    /// Host fingerprint prerequisite.
    HostFingerprint,
    /// Observed state prerequisite.
    ObservedStateDigest,
    /// Operating-system prerequisite.
    OperatingSystem,
}

impl PreconditionV3 {
    /// Returns the stable kind of this prerequisite.
    #[must_use]
    pub const fn kind(&self) -> PreconditionKind {
        match self {
            Self::Elevation { .. } => PreconditionKind::Elevation,
            Self::Privilege { .. } => PreconditionKind::Privilege,
            Self::CapabilityAvailable { .. } => PreconditionKind::CapabilityAvailable,
            Self::HostFingerprint { .. } => PreconditionKind::HostFingerprint,
            Self::ObservedStateDigest { .. } => PreconditionKind::ObservedStateDigest,
            Self::OperatingSystem { .. } => PreconditionKind::OperatingSystem,
        }
    }
}

/// A deterministic artifact request or produced artifact classification.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    /// A text or structured execution log.
    Log,
    /// A report intended for an operator.
    Report,
    /// Captured evidence such as a bounded export.
    Evidence,
    /// State retained to enable rollback.
    RollbackState,
    /// A capability-specific output file.
    Output,
}

/// A requested or retained artifact with integrity information.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ArtifactV3 {
    /// Artifact identifier.
    pub id: ArtifactId,
    /// Artifact category.
    pub kind: ArtifactKind,
    /// MIME type of the retained content.
    pub media_type: String,
    /// Worker-controlled, non-secret locator relative to its artifact root.
    pub locator: String,
    /// Canonical SHA-256 digest of the retained bytes.
    pub digest: Sha256Digest,
    /// Number of retained bytes.
    pub size_bytes: u64,
    /// Time at which the artifact became available.
    pub created_at: DateTime<Utc>,
    /// Capability-defined, bounded metadata.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: JsonMap,
}

/// One dependency-aware unit of operator-requested work.
///
/// A profile step intentionally cannot select an operation or declare its own
/// safety properties. The trusted planner obtains those values from its
/// capability registry when it derives a [`PlannedActionV3`].
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ProfileStepV3 {
    /// Step identity, unique within its profile.
    pub step_id: ActionId,
    /// Registered capability implementing this work.
    pub capability_id: CapabilityId,
    /// Capability-defined typed parameters.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub parameters: JsonMap,
    /// Step identities that must complete successfully first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<ActionId>,
    /// Continue after a failed step for audit and plan only. Apply always fails fast.
    #[serde(default)]
    pub continue_on_error: bool,
}

/// One worker-derived action with capability-owned execution authority.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PlannedActionV3 {
    /// Action identity, unique within a plan.
    #[serde(rename = "action_id")]
    pub id: ActionId,
    /// Profile step from which the trusted worker derived this action.
    #[serde(rename = "source_step_id")]
    pub source_step: ActionId,
    /// Registered capability selected by the profile step.
    #[serde(rename = "capability_id")]
    pub capability: CapabilityId,
    /// Operation supplied by the trusted execution boundary.
    pub operation: Operation,
    /// Operator-provided capability parameters, validated by the planner.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub parameters: JsonMap,
    /// Derived action identities that must complete successfully first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<ActionId>,
    /// Continue after a failed action for audit and plan only. Apply always fails fast.
    #[serde(default)]
    pub continue_on_error: bool,
    /// Stable digest of the facts used by the capability to derive this action.
    pub facts_digest: Sha256Digest,
    /// Conditions that must remain true at apply time.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preconditions: Vec<PreconditionV3>,
    /// Declared endpoint risk.
    pub risk: RiskLevel,
    /// Declared rollback behavior.
    pub reversibility: Reversibility,
    /// Declared reboot consequence.
    pub reboot: RebootRequirement,
    /// Required worker privileges.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub privileges: Vec<Privilege>,
    /// Capability-defined safety metadata.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: JsonMap,
}

/// Profile-wide execution defaults that never authorize mutation or output paths.
#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ProfileDefaultsV3 {
    /// Continue after a failed step for audit and plan operations.
    #[serde(default)]
    pub continue_on_error: bool,
}

/// A strict, portable profile used as planner input.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ProfileV3 {
    /// Version marker for strict decoding.
    pub schema_version: SchemaVersion,
    /// Profile identity.
    #[serde(rename = "profile_id")]
    pub id: ProfileId,
    /// Operator-facing name.
    pub name: String,
    /// Profile revision chosen by the profile author.
    pub version: String,
    /// Optional operator-facing explanation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Time this profile revision was created.
    pub created_at: DateTime<Utc>,
    /// Optional profile expiry; an expired profile cannot produce a plan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Profile-wide continuation defaults. Mode and output remain command-owned.
    #[serde(default)]
    pub defaults: ProfileDefaultsV3,
    /// Dependency-aware requested steps.
    pub steps: Vec<ProfileStepV3>,
    /// Profile-author metadata with no execution semantics.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: JsonMap,
}
