use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{CapabilityId, Sha256Digest};

use super::{JsonMap, OsFamily};

/// Identity information that binds a plan to the intended endpoint.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct HostIdentityV3 {
    /// Stable worker-defined endpoint identifier, not an authentication secret.
    pub host_id: String,
    /// Operating-system boot identifier; prevents a plan crossing a reboot boundary.
    pub boot_id: String,
    /// Worker session identifier; prevents replay through another local session.
    pub session_id: String,
    /// Current computer name for operator display.
    pub hostname: String,
    /// Operating-system family.
    pub os_family: OsFamily,
    /// Operating-system version returned by the worker.
    pub os_version: String,
    /// CPU architecture label.
    pub architecture: String,
    /// Canonical digest binding these identity fields.
    pub fingerprint: Sha256Digest,
}

/// Build identity of the component that created or validates a plan.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ToolIdentityV3 {
    /// Tool name, normally `baselineops`.
    pub name: String,
    /// Tool version.
    pub version: String,
    /// Optional build or package digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_digest: Option<Sha256Digest>,
}

/// The origin category of profile or configuration input.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// A local, operator-supplied file.
    LocalFile,
    /// A profile embedded in the signed distribution.
    Bundled,
    /// A source retrieved through an explicitly trusted remote workflow.
    Remote,
    /// Input constructed by a caller through the public API.
    Api,
}

/// Source provenance that remains stable enough to validate at apply time.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct SourceIdentityV3 {
    /// Origin category.
    pub kind: SourceKind,
    /// Operator-readable origin label or normalized URI.
    pub locator: String,
    /// Digest of the source content as received.
    pub digest: Sha256Digest,
}

/// Digest identity of a profile and capability input bundle.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct InputIdentityV3 {
    /// Canonical digest of all input bytes that affect the plan.
    pub digest: Sha256Digest,
    /// Number of input bytes used to calculate the digest.
    pub size_bytes: u64,
}

/// A capability-provided value captured before planning.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ObservedValueV3 {
    /// Time the capability observed this value.
    pub observed_at: DateTime<Utc>,
    /// Capability-defined bounded facts.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub facts: JsonMap,
}

/// Point-in-time state supplied to the planner by registered capabilities.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ObservedStateV3 {
    /// Capture time for the whole observation bundle.
    pub captured_at: DateTime<Utc>,
    /// Canonical digest of the exact observation bundle.
    pub digest: Sha256Digest,
    /// Capability-keyed observations.
    pub values: BTreeMap<CapabilityId, ObservedValueV3>,
}
