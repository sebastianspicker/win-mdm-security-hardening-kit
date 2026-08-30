use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;

use crate::{
    ActionId, ActionResultV3, ArtifactV3, DomainError, DomainResult, ExecutionIntent, FindingV3,
    HostIdentityV3, InputIdentityV3, JsonMap, MAX_TYPED_MAP_ENTRIES, ObservedStateV3, PlanV3,
    PlannedActionV3, ProfileStepV3, ProfileV3, ResultV3, Sha256Digest, SourceIdentityV3,
    ToolIdentityV3, canonical_json_digest,
};

mod graph;

use graph::validate_dependency_graph;

/// Deterministic action ordering that honors every declared dependency.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TopologicalOrder(Vec<ActionId>);

impl TopologicalOrder {
    /// Returns action IDs in dependency-safe order.
    #[must_use]
    pub fn as_slice(&self) -> &[ActionId] {
        &self.0
    }

    /// Consumes the order into its action IDs.
    #[must_use]
    pub fn into_inner(self) -> Vec<ActionId> {
        self.0
    }
}

/// Semantic validation output for a profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileValidation {
    /// Deterministic dependency-safe action order.
    pub topological_order: TopologicalOrder,
}

/// Runtime values against which a plan must be validated before execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanValidationContext {
    /// Current trusted UTC time.
    pub now: DateTime<Utc>,
    /// Intent requested through the command or worker boundary.
    pub intent: ExecutionIntent,
    /// Current host identity.
    pub host: HostIdentityV3,
    /// Current worker/tool identity.
    pub tool: ToolIdentityV3,
    /// Recomputed digest of the verified `BaselineOps` package.
    pub package_digest: Sha256Digest,
    /// Source identity as re-verified by the caller.
    pub source: SourceIdentityV3,
    /// Recomputed identity of all plan-affecting input.
    pub input: InputIdentityV3,
    /// Recomputed observed-state digest.
    pub observed_state_digest: Sha256Digest,
}

/// A plan that passed live binding validation and is safe to hand to an apply worker.
///
/// This type deliberately has no `Deserialize` implementation. Untrusted JSON
/// always enters as [`PlanV3`] and must be checked with a live
/// [`PlanValidationContext`] before it can become execution authority.
#[derive(Clone, Debug)]
pub struct VerifiedPlan(PlanV3);

impl VerifiedPlan {
    /// Borrows the verified plan for worker execution.
    #[must_use]
    pub fn as_plan(&self) -> &PlanV3 {
        &self.0
    }

    /// Consumes the approval wrapper when a caller must persist the trusted plan.
    #[must_use]
    pub fn into_inner(self) -> PlanV3 {
        self.0
    }
}

impl ProfileV3 {
    /// Validates the profile's bounded fields, action graph, and expiry range.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid field bounds, metadata, expiry, dependencies, or cycles.
    pub fn validate(&self) -> DomainResult<ProfileValidation> {
        validate_nonempty("profile name", &self.name, 256)?;
        validate_nonempty("profile version", &self.version, 128)?;
        validate_optional_text("profile description", self.description.as_deref(), 4096)?;
        if let Some(expires_at) = self.expires_at
            && expires_at <= self.created_at
        {
            return validation("profile expiry must be after its creation time");
        }
        validate_json_map("profile metadata", &self.metadata)?;
        Ok(ProfileValidation {
            topological_order: validate_profile_steps(&self.steps)?,
        })
    }

    /// Returns a deterministic dependency-safe action order after validation.
    ///
    /// # Errors
    ///
    /// Returns an error when profile validation fails.
    pub fn topological_order(&self) -> DomainResult<TopologicalOrder> {
        Ok(self.validate()?.topological_order)
    }
}

impl HostIdentityV3 {
    /// Computes the host fingerprint from all identity fields except the fingerprint itself.
    ///
    /// # Errors
    ///
    /// Returns an error if canonical serialization fails.
    pub fn calculated_fingerprint(&self) -> DomainResult<Sha256Digest> {
        canonical_json_digest(&HostFingerprintPayload {
            host_id: &self.host_id,
            boot_id: &self.boot_id,
            session_id: &self.session_id,
            hostname: &self.hostname,
            os_family: self.os_family,
            os_version: &self.os_version,
            architecture: &self.architecture,
        })
    }

    /// Ensures identity fields are bounded and the supplied fingerprint is exact.
    ///
    /// # Errors
    ///
    /// Returns an error if an identity field is invalid or the fingerprint does not match.
    pub fn validate(&self) -> DomainResult<()> {
        validate_nonempty("host ID", &self.host_id, 256)?;
        validate_nonempty("boot ID", &self.boot_id, 256)?;
        validate_nonempty("session ID", &self.session_id, 256)?;
        validate_nonempty("hostname", &self.hostname, 255)?;
        validate_nonempty("OS version", &self.os_version, 128)?;
        validate_nonempty("architecture", &self.architecture, 64)?;
        if self.calculated_fingerprint()? != self.fingerprint {
            return validation("host fingerprint does not match the host identity fields");
        }
        Ok(())
    }
}

impl ObservedStateV3 {
    /// Computes the observed facts digest, excluding capture timestamps and its digest field.
    ///
    /// # Errors
    ///
    /// Returns an error if canonical serialization fails.
    pub fn calculated_digest(&self) -> DomainResult<Sha256Digest> {
        let facts = self
            .values
            .iter()
            .map(|(capability, value)| (capability, &value.facts))
            .collect::<BTreeMap<_, _>>();
        canonical_json_digest(&facts)
    }

    /// Validates state values and their canonical binding digest.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid facts, missing observations, or a digest mismatch.
    pub fn validate(&self) -> DomainResult<()> {
        if self.values.is_empty() {
            return validation("observed state must contain at least one capability value");
        }
        for (capability, value) in &self.values {
            validate_nonempty("observed-state capability ID", capability.as_str(), 128)?;
            validate_json_map("observed-state facts", &value.facts)?;
        }
        if self.calculated_digest()? != self.digest {
            return validation("observed-state digest does not match its captured values");
        }
        Ok(())
    }
}

impl PlanV3 {
    /// Checks consistency that is independent of current host and tool state.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid expiry, identity, source, state, metadata, or action graph data.
    pub fn validate_structure(&self) -> DomainResult<TopologicalOrder> {
        if self.expires_at <= self.issued_at {
            return validation("plan expiry must be after its issue time");
        }
        self.host.validate()?;
        validate_tool(&self.tool)?;
        validate_source(&self.source)?;
        if self.input.size_bytes == 0 {
            return validation("plan input size must be non-zero");
        }
        self.observed_state.validate()?;
        validate_json_map("plan metadata", &self.metadata)?;
        let order = validate_planned_actions(&self.actions)?;
        if self
            .actions
            .iter()
            .any(|action| action.facts_digest != self.observed_state.digest)
        {
            return validation("planned action facts do not match the plan observation binding");
        }
        Ok(order)
    }

    /// Rejects a plan that has expired at `now`.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid plan or when the plan is expired.
    pub fn validate_at(&self, now: DateTime<Utc>) -> DomainResult<TopologicalOrder> {
        let order = self.validate_structure()?;
        if now >= self.expires_at {
            return validation("plan has expired");
        }
        Ok(order)
    }

    /// Validates every live binding required before an apply worker executes the plan.
    ///
    /// # Errors
    ///
    /// Returns an error when the plan is stale or any intent, host, package, tool, source, input, or state binding differs.
    pub fn validate_against(
        &self,
        context: &PlanValidationContext,
    ) -> DomainResult<TopologicalOrder> {
        let order = self.validate_at(context.now)?;
        if self.intent != context.intent {
            return validation("plan intent does not match the requested execution intent");
        }
        context.host.validate()?;
        if self.host != context.host {
            return validation("plan host identity does not match the current host");
        }
        if self.tool != context.tool {
            return validation("plan tool identity does not match the current worker");
        }
        if self.package_digest != context.package_digest {
            return validation("plan package digest does not match the verified package");
        }
        if self.source != context.source {
            return validation("plan source identity does not match the re-verified source");
        }
        if self.input != context.input {
            return validation("plan input identity does not match the re-verified input");
        }
        if self.observed_state.digest != context.observed_state_digest {
            return validation("plan observed state does not match the current state binding");
        }
        Ok(order)
    }

    /// Consumes this plan and returns execution authority only after all live
    /// bindings, freshness checks, and canonical digests have been verified.
    ///
    /// # Errors
    ///
    /// Returns an error when live plan validation fails.
    pub fn verify_for_execution(
        self,
        context: &PlanValidationContext,
    ) -> DomainResult<VerifiedPlan> {
        self.validate_against(context)?;
        Ok(VerifiedPlan(self))
    }
}

impl ResultV3 {
    /// Validates result timestamps, references, findings, and bounded evidence.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid timestamps, identity, summary, metadata, references, or evidence.
    pub fn validate(&self) -> DomainResult<()> {
        if self.completed_at < self.started_at {
            return validation("result completion time must not precede its start time");
        }
        self.host.validate()?;
        validate_nonempty("result summary", &self.summary, 4096)?;
        validate_json_map("result metadata", &self.metadata)?;
        let mut action_ids = BTreeSet::new();
        for action in &self.actions {
            validate_action_result(action)?;
            if !action_ids.insert(action.action_id) {
                return validation("result contains duplicate action result IDs");
            }
        }
        let mut finding_ids = BTreeSet::new();
        for finding in &self.findings {
            finding.validate()?;
            if !finding_ids.insert(finding.id) {
                return validation("result contains duplicate finding IDs");
            }
        }
        validate_artifacts(&self.artifacts)
    }
}

impl FindingV3 {
    /// Validates a finding's stable automation fields and evidence bounds.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid code, message, or evidence.
    pub fn validate(&self) -> DomainResult<()> {
        validate_nonempty("finding code", &self.code, 128)?;
        validate_nonempty("finding message", &self.message, 4096)?;
        validate_json_map("finding evidence", &self.evidence)
    }
}

fn validate_profile_steps(steps: &[ProfileStepV3]) -> DomainResult<TopologicalOrder> {
    validate_dependency_graph(
        steps,
        |step| step.step_id,
        |step| &step.depends_on,
        validate_profile_step,
    )
}

fn validate_planned_actions(actions: &[PlannedActionV3]) -> DomainResult<TopologicalOrder> {
    validate_dependency_graph(
        actions,
        |action| action.id,
        |action| &action.depends_on,
        validate_planned_action,
    )
}

fn validate_profile_step(step: &ProfileStepV3) -> DomainResult<()> {
    validate_nonempty(
        "profile step capability ID",
        step.capability_id.as_str(),
        128,
    )?;
    validate_json_map("profile step parameters", &step.parameters)
}

fn validate_planned_action(action: &PlannedActionV3) -> DomainResult<()> {
    validate_nonempty(
        "planned action capability ID",
        action.capability.as_str(),
        128,
    )?;
    validate_json_map("planned action parameters", &action.parameters)?;
    validate_json_map("planned action metadata", &action.metadata)?;
    for condition in &action.preconditions {
        if let crate::PreconditionV3::OperatingSystem {
            minimum_version: Some(version),
            ..
        } = condition
        {
            validate_nonempty("minimum OS version", version, 128)?;
        }
    }
    Ok(())
}

fn validate_action_result(action: &ActionResultV3) -> DomainResult<()> {
    if action.completed_at < action.started_at {
        return validation("action completion time must not precede its start time");
    }
    validate_nonempty(
        "action-result capability ID",
        action.capability.as_str(),
        128,
    )?;
    validate_json_map("action-result metadata", &action.metadata)
}

fn validate_artifacts(artifacts: &[ArtifactV3]) -> DomainResult<()> {
    let mut ids = BTreeSet::new();
    for artifact in artifacts {
        if !ids.insert(artifact.id) {
            return validation("artifact IDs must be unique within their collection");
        }
        validate_nonempty("artifact media type", &artifact.media_type, 255)?;
        validate_relative_locator(&artifact.locator)?;
        validate_json_map("artifact metadata", &artifact.metadata)?;
    }
    Ok(())
}

fn validate_tool(tool: &ToolIdentityV3) -> DomainResult<()> {
    validate_nonempty("tool name", &tool.name, 128)?;
    validate_nonempty("tool version", &tool.version, 128)
}

fn validate_source(source: &SourceIdentityV3) -> DomainResult<()> {
    validate_nonempty("source locator", &source.locator, 2048)
}

fn validate_relative_locator(locator: &str) -> DomainResult<()> {
    validate_nonempty("artifact locator", locator, 2048)?;
    if locator.starts_with(['/', '\\']) || locator.split(['/', '\\']).any(|segment| segment == "..")
    {
        return validation(
            "artifact locator must be relative and may not contain parent traversal",
        );
    }
    Ok(())
}

fn validate_json_map(name: &str, map: &JsonMap) -> DomainResult<()> {
    if map.len() > MAX_TYPED_MAP_ENTRIES {
        return validation(&format!(
            "{name} has more than {MAX_TYPED_MAP_ENTRIES} entries"
        ));
    }
    for (key, value) in map {
        validate_nonempty(name, key, 256)?;
        validate_value(value, 0, &mut 0)?;
    }
    Ok(())
}

fn validate_value(value: &Value, depth: usize, nodes: &mut usize) -> DomainResult<()> {
    const MAX_DEPTH: usize = 16;
    const MAX_NODES: usize = 4096;
    const MAX_STRING_BYTES: usize = 64 * 1024;
    *nodes += 1;
    if *nodes > MAX_NODES {
        return validation("typed JSON value exceeds the 4096 node limit");
    }
    if depth > MAX_DEPTH {
        return validation("typed JSON value exceeds the 16-level nesting limit");
    }
    match value {
        Value::String(value) if value.len() > MAX_STRING_BYTES => {
            validation("typed JSON string exceeds the 64 KiB limit")
        }
        Value::Array(values) => {
            if values.len() > MAX_TYPED_MAP_ENTRIES {
                return validation("typed JSON array exceeds the 256 entry limit");
            }
            for item in values {
                validate_value(item, depth + 1, nodes)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            if values.len() > MAX_TYPED_MAP_ENTRIES {
                return validation("typed JSON object exceeds the 256 entry limit");
            }
            for (key, item) in values {
                validate_nonempty("typed JSON property name", key, 256)?;
                validate_value(item, depth + 1, nodes)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn validate_optional_text(name: &str, value: Option<&str>, max_bytes: usize) -> DomainResult<()> {
    if let Some(value) = value {
        validate_nonempty(name, value, max_bytes)?;
    }
    Ok(())
}

fn validate_nonempty(name: &str, value: &str, max_bytes: usize) -> DomainResult<()> {
    if value.trim().is_empty() {
        return validation(&format!("{name} must not be empty"));
    }
    if value.len() > max_bytes {
        return validation(&format!("{name} exceeds the {max_bytes} byte limit"));
    }
    Ok(())
}

fn validation<T>(message: &str) -> DomainResult<T> {
    Err(DomainError::Validation(message.to_owned()))
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct HostFingerprintPayload<'a> {
    host_id: &'a str,
    boot_id: &'a str,
    session_id: &'a str,
    hostname: &'a str,
    os_family: crate::OsFamily,
    os_version: &'a str,
    architecture: &'a str,
}
