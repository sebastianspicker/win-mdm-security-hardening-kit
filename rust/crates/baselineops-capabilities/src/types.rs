use serde::{Deserialize, Serialize};

/// A stable v3 operation requested for a capability.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Operation {
    /// Inspect state without intending to change it.
    Audit,
    /// Produce a proposed change plan.
    Plan,
    /// Apply a state-changing action.
    Apply,
}

/// Operations that a descriptor may expose.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Operations {
    /// Whether the capability can audit.
    pub audit: bool,
    /// Whether the capability can plan a supported change.
    pub plan: bool,
    /// Whether the capability can apply a supported change.
    pub apply: bool,
}

impl Operations {
    /// Returns whether `operation` is advertised by this descriptor.
    #[must_use]
    pub const fn supports(self, operation: Operation) -> bool {
        match operation {
            Operation::Audit => self.audit,
            Operation::Plan => self.plan,
            Operation::Apply => self.apply,
        }
    }
}

/// The least privilege needed for meaningful capability execution.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Privilege {
    /// Audits can run unelevated; mutation is unavailable.
    StandardUser,
    /// Audits can run unelevated; applying the change normally needs elevation.
    ElevatedForApply,
    /// The legacy script requires an Administrator token.
    AdministratorRequired,
}

/// A qualitative impact classification, retained for planning and approvals.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Risk {
    /// Read-only or narrowly scoped impact.
    Low,
    /// Change can affect an endpoint feature or policy.
    Medium,
    /// Change can affect endpoint protection or connectivity.
    High,
    /// Change can isolate the endpoint or weaken a core control if misapplied.
    Critical,
}

/// Whether a completed apply action can be safely reversed by the same capability.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reversibility {
    /// The capability has no apply operation.
    NotApplicable,
    /// The same capability can restore its prior state.
    Reversible,
    /// Recovery needs a separate operator procedure.
    ManualRecovery,
    /// No supported recovery is known.
    NotReversible,
}

/// Reboot expectation advertised by a capability.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reboot {
    /// Restart is not expected.
    No,
    /// Restart may be required for the changed state to take effect.
    Possible,
    /// Restart is required for the changed state to take effect.
    Required,
}

/// Honest maturity state of the Rust implementation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImplementationMaturity {
    /// Only a legacy PowerShell implementation is evidenced.
    LegacyOnly,
    /// A typed executor seam exists, but no native implementation evidence exists yet.
    InDevelopment,
    /// A native implementation has been independently verified.
    Implemented,
}

/// Curated legacy runner memberships.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Batch {
    /// Legacy audit batch.
    Audit,
    /// Legacy remediation batch.
    Remediation,
    /// Legacy evidence collection batch.
    Collection,
    /// Legacy utility batch.
    Utility,
    /// Legacy monitoring batch.
    Monitoring,
    /// Every numbered legacy leaf script.
    All,
}

/// Immutable metadata for one legacy numbered capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct CapabilityDescriptor {
    /// Legacy leaf script number (1 through 52).
    pub legacy_number: u8,
    /// Canonical, lowercase, stable v3 identifier.
    pub id: &'static str,
    /// Operator-facing display name.
    pub display_name: &'static str,
    /// Legacy PowerShell script basename.
    pub legacy_script: &'static str,
    /// Concise behavior description, derived from the legacy script catalog.
    pub description: &'static str,
    /// Incremental migration wave; not an implementation-complete claim.
    pub wave: u8,
    /// Advertised v3 operations, based on proven legacy mutation behavior.
    pub operations: Operations,
    /// Required execution authority.
    pub privilege: Privilege,
    /// Planning risk classification.
    pub risk: Risk,
    /// Recovery expectation for an apply operation.
    pub reversibility: Reversibility,
    /// Whether an apply may require a restart.
    pub reboot: Reboot,
    /// Required Windows features, cmdlets, APIs, or native tools.
    pub requirements: &'static [&'static str],
    /// Native Rust implementation status.
    pub maturity: ImplementationMaturity,
    /// Legacy runner batches containing this script.
    pub batches: &'static [Batch],
}

/// Describes the host state used to prevent false-positive execution.
#[derive(Clone, Copy, Debug)]
pub struct ExecutionEnvironment<'a> {
    /// Whether the current host is Windows.
    pub is_windows: bool,
    /// Features/tools known available to the executor.
    pub available_requirements: &'a [&'a str],
}

impl ExecutionEnvironment<'_> {
    /// Creates a non-Windows environment with no Windows capabilities available.
    #[must_use]
    pub const fn non_windows() -> Self {
        Self {
            is_windows: false,
            available_requirements: &[],
        }
    }

    /// Returns whether a named capability requirement is available.
    #[must_use]
    pub fn has_requirement(self, requirement: &str) -> bool {
        self.available_requirements.contains(&requirement)
    }
}

/// A requested operation together with opaque executor parameters.
#[derive(Clone, Copy, Debug)]
pub struct CapabilityRequest<'a> {
    /// Requested operation.
    pub operation: Operation,
    /// JSON parameters interpreted only by a registered executor.
    pub parameters: &'a serde_json::Value,
}

/// Structured reason native execution did not run.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Unsupported {
    /// The host is not Windows.
    NonWindowsHost,
    /// A Windows feature, cmdlet, API, or native tool was not available.
    MissingRequirement {
        /// Missing feature, cmdlet, API, or native tool name.
        requirement: String,
    },
    /// The operation is not exposed by this descriptor.
    OperationUnavailable {
        /// Requested v3 operation that the descriptor does not expose.
        operation: Operation,
    },
    /// No executor has been registered for this capability yet.
    ExecutorUnavailable {
        /// Stable capability ID whose engine/platform handler is absent.
        capability_id: String,
    },
}

/// Typed dispatch result. `Completed` requires an executor to produce it.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CapabilityOutcome {
    /// The executor completed and returned structured result data.
    Completed {
        /// Structured output supplied by the registered executor.
        result: serde_json::Value,
    },
    /// Dispatch deliberately did not run and gives a machine-readable reason.
    Unsupported {
        /// Machine-readable reason dispatch did not execute.
        reason: Unsupported,
    },
    /// The executor ran but could not produce a trustworthy observation or mutation result.
    Failed {
        /// Stable capability ID.
        capability_id: String,
        /// Bounded diagnostic message.
        message: String,
    },
}

/// A native or bridge executor supplied by the engine/platform layer.
pub trait CapabilityExecutor: Send + Sync {
    /// Executes a capability only after the registry's platform checks pass.
    fn execute(
        &self,
        descriptor: &'static CapabilityDescriptor,
        request: CapabilityRequest<'_>,
    ) -> CapabilityOutcome;
}

/// Dispatch contract appropriate for engine integration.
pub trait Capability {
    /// Static metadata for the capability.
    fn descriptor(&self) -> &'static CapabilityDescriptor;

    /// Performs safe preflight and forwards execution to the supplied hook.
    fn execute(
        &self,
        environment: ExecutionEnvironment<'_>,
        request: CapabilityRequest<'_>,
        executor: Option<&dyn CapabilityExecutor>,
    ) -> CapabilityOutcome;
}
