use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{PlanId, ProfileId, RunId, Sha256Digest};

use super::{
    ExecutionIntent, HostIdentityV3, InputIdentityV3, JsonMap, ObservedStateV3, PlannedActionV3,
    SchemaVersion, SourceIdentityV3, ToolIdentityV3,
};

/// A short-lived execution authority derived from a validated profile.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PlanV3 {
    /// Version marker for strict decoding.
    pub schema_version: SchemaVersion,
    /// Plan identity.
    #[serde(rename = "plan_id")]
    pub id: PlanId,
    /// Reserved worker run identity that a result must retain.
    pub run_id: RunId,
    /// Command-bound intent authorized by this plan.
    pub intent: ExecutionIntent,
    /// Profile this plan was derived from.
    pub profile_id: ProfileId,
    /// Canonical digest of the validated profile.
    pub profile_digest: Sha256Digest,
    /// Endpoint for which the plan is valid.
    pub host: HostIdentityV3,
    /// Tool that authored the plan.
    pub tool: ToolIdentityV3,
    /// Digest of the verified `BaselineOps` package used to produce the plan.
    pub package_digest: Sha256Digest,
    /// Trusted source identity for the input.
    pub source: SourceIdentityV3,
    /// Digest identity for all plan-affecting input.
    pub input: InputIdentityV3,
    /// State snapshot used to make the plan.
    pub observed_state: ObservedStateV3,
    /// Time the plan was issued.
    pub issued_at: DateTime<Utc>,
    /// Time after which the worker must reject the plan.
    pub expires_at: DateTime<Utc>,
    /// Ordered-by-dependency action set. Wire order does not have execution semantics.
    pub actions: Vec<PlannedActionV3>,
    /// Planner metadata with no execution semantics.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: JsonMap,
}
