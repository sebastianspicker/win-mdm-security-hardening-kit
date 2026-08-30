use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A bounded dictionary used for capability-defined parameters and evidence.
pub type JsonMap = BTreeMap<String, Value>;

/// Wire version for every v3 document.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub enum SchemaVersion {
    /// `BaselineOps` v3.0 contract.
    #[serde(rename = "3.0")]
    #[default]
    V3,
}

/// Whether an action is observation-only or can alter the endpoint.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    /// Gather state without applying a desired configuration.
    Audit,
    /// Produce a host-bound, expiring plan without changing endpoint state.
    Plan,
    /// Apply an already validated plan.
    Apply,
}

/// Requested high-level capability operation.
///
/// `ActionKind` is retained as an alias so older internal call sites can use a
/// descriptive name while new capability descriptors use `Operation`.
pub type ActionKind = Operation;

/// Intent selected at the unprivileged command boundary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionIntent {
    /// Inspect current endpoint state.
    Audit,
    /// Produce a short-lived host-bound plan.
    Plan,
    /// Execute a previously verified plan.
    Apply,
}

impl From<ExecutionIntent> for Operation {
    fn from(value: ExecutionIntent) -> Self {
        match value {
            ExecutionIntent::Audit => Self::Audit,
            ExecutionIntent::Plan => Self::Plan,
            ExecutionIntent::Apply => Self::Apply,
        }
    }
}

/// Risk classification supplied by a capability author.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    /// No endpoint mutation and little sensitivity.
    None,
    /// Local read-only inspection or low-impact operation.
    Low,
    /// A guarded change with a local scope.
    Moderate,
    /// A change that can materially alter endpoint availability or security.
    High,
    /// A change that needs explicit, out-of-band operator confirmation.
    Critical,
}

/// Ability to return from an action to its previous state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reversibility {
    /// The action has no persistent side effects.
    NotApplicable,
    /// A rollback action is complete and deterministic.
    Reversible,
    /// A rollback is possible only while retained artifacts or system state remain available.
    ConditionallyReversible,
    /// The action cannot be rolled back by `BaselineOps`.
    Irreversible,
}

/// Reboot consequence advertised before an action is applied.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebootRequirement {
    /// No reboot is expected.
    NotRequired,
    /// A reboot can be deferred but may be needed for complete effect.
    Recommended,
    /// A reboot is required for the requested outcome.
    Required,
}

/// An execution privilege recognized by the v3 worker boundary.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Privilege {
    /// No elevated token is required.
    User,
    /// A local administrator token is required.
    Administrator,
    /// The local system account is required.
    LocalSystem,
    /// Windows backup/restore privileges are required.
    BackupOperator,
    /// Windows security-log and security-policy privileges are required.
    SecurityOperator,
}

/// Runtime availability reported by the capability registry.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityStatus {
    /// The capability is available for the requested operation.
    Available,
    /// The capability is known but unavailable on this host.
    Unavailable,
    /// The capability is not supported by this build or platform.
    Unsupported,
}

/// Delivery state of a capability implementation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImplementationStatus {
    /// Implementation is complete and supported.
    Implemented,
    /// The capability is deliberately not yet implemented.
    Planned,
    /// Support was retired and must not be selected for a plan.
    Deprecated,
}

/// The Windows or cross-platform operating-system family that a capability supports.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OsFamily {
    /// Microsoft Windows.
    Windows,
    /// Linux.
    Linux,
    /// macOS.
    Macos,
    /// An explicitly unsupported or unrecognized platform.
    Other,
}
