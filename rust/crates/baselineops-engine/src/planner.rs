use baselineops_domain::{
    ActionId, DomainError, ExecutionIntent, HostIdentityV3, InputIdentityV3, ObservedStateV3,
    PlanId, PlanV3, PlannedActionV3, ProfileStepV3, ProfileV3, RunId, Sha256Digest,
    SourceIdentityV3, ToolIdentityV3, canonical_json_digest,
};
use chrono::{DateTime, Duration, Utc};
use std::collections::BTreeMap;

/// Worker-derived values needed to bind a plan to one host and input closure.
#[derive(Clone, Debug)]
pub struct PlanBuildContext {
    /// Intent authorized by the command boundary.
    pub intent: ExecutionIntent,
    /// Trusted current host identity.
    pub host: HostIdentityV3,
    /// Exact worker/package version.
    pub tool: ToolIdentityV3,
    /// Digest of the verified package closure.
    pub package_digest: Sha256Digest,
    /// Re-read operator-writable profile source, bound by exact digest.
    pub source: SourceIdentityV3,
    /// Digest and size of all plan-affecting input.
    pub input: InputIdentityV3,
    /// Capability observations used to derive actions.
    pub observed_state: ObservedStateV3,
    /// Maximum plan lifetime.
    pub lifetime: Duration,
}

/// A plan produced by the trusted planner and eligible for approval.
///
/// This typestate deliberately has no deserializer and can only be minted by
/// [`build_plan`]. It prevents a raw plan document from entering the approval
/// path as though it had been produced by the trusted registry.
#[derive(Debug)]
pub struct WorkerPlan {
    plan: PlanV3,
    digest: Sha256Digest,
}

impl WorkerPlan {
    /// Returns the worker-derived proposal for read-only operator review.
    #[must_use]
    pub const fn proposal(&self) -> &PlanV3 {
        &self.plan
    }

    /// Returns the canonical proposal digest presented for approval.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    pub(crate) fn into_parts(self) -> (PlanV3, Sha256Digest) {
        (self.plan, self.digest)
    }
}

/// Trusted capability-registry port that derives executable actions from profile requests.
///
/// Implementations belong to the worker-side capability registry. Profile JSON
/// is deliberately not a valid implementation of this port: the registry owns
/// operation, safety metadata, and the facts binding for every planned action.
pub trait TrustedActionDeriver {
    /// Derive one action from a validated profile step and trusted observations.
    ///
    /// # Errors
    ///
    /// Returns an error when the registered capability cannot derive a safe action.
    fn derive(
        &self,
        step: &ProfileStepV3,
        intent: ExecutionIntent,
        observed_state: &ObservedStateV3,
    ) -> Result<PlannedActionV3, String>;
}

/// Errors produced while constructing an authoritative plan.
#[derive(Debug, thiserror::Error)]
pub enum PlanningError {
    /// Domain validation rejected the profile, host, or observed state.
    #[error(transparent)]
    Domain(#[from] DomainError),
    /// The requested lifetime is empty or unreasonably long.
    #[error("plan lifetime must be between one second and 24 hours")]
    InvalidLifetime,
    /// A timestamp overflowed.
    #[error("plan expiry overflowed the supported timestamp range")]
    ExpiryOverflow,
    /// The selected profile is no longer usable.
    #[error("profile has expired")]
    ExpiredProfile,
    /// A registry-derived action did not retain the requested step identity.
    #[error("derived action does not match its source profile step")]
    SourceStepMismatch,
    /// A registry-derived action does not use the command-bound operation.
    #[error("derived action operation does not match the requested execution intent")]
    IntentMismatch,
    /// A registry-derived action has not bound the trusted observed facts.
    #[error("derived action facts digest does not match the observed facts")]
    FactsMismatch,
    /// A trusted capability registry could not derive an executable action.
    #[error("capability action derivation failed: {0}")]
    Derivation(String),
    /// A reviewed plan envelope differs from fresh worker authority.
    #[error("reviewed plan envelope does not match fresh worker authority")]
    ReviewedEnvelopeMismatch,
}

/// Build the worker-authoritative proposal in deterministic dependency order.
///
/// # Errors
///
/// Returns an error when the profile, host, or observed state is invalid; when
/// the lifetime is outside one second through 24 hours; or when canonical plan
/// construction fails.
///
pub fn build_plan(
    profile: &ProfileV3,
    context: PlanBuildContext,
    deriver: &dyn TrustedActionDeriver,
    now: DateTime<Utc>,
) -> Result<WorkerPlan, PlanningError> {
    let validation = profile.validate()?;
    context.host.validate()?;
    context.observed_state.validate()?;
    if profile
        .expires_at
        .is_some_and(|expires_at| now >= expires_at)
    {
        return Err(PlanningError::ExpiredProfile);
    }
    if context.lifetime < Duration::seconds(1) || context.lifetime > Duration::hours(24) {
        return Err(PlanningError::InvalidLifetime);
    }
    let expires_at = now
        .checked_add_signed(context.lifetime)
        .ok_or(PlanningError::ExpiryOverflow)?;
    let actions = derive_actions(
        profile,
        validation.topological_order.as_slice(),
        &context,
        deriver,
    )?;
    let plan = PlanV3 {
        schema_version: profile.schema_version,
        id: PlanId::new(),
        run_id: RunId::new(),
        intent: context.intent,
        profile_id: profile.id,
        profile_digest: canonical_json_digest(profile)?,
        host: context.host,
        tool: context.tool,
        package_digest: context.package_digest,
        source: context.source,
        input: context.input,
        observed_state: context.observed_state,
        issued_at: now,
        expires_at,
        actions,
        metadata: BTreeMap::default(),
    };
    plan.validate_structure()?;
    let digest = canonical_json_digest(&plan)?;
    Ok(WorkerPlan { plan, digest })
}

fn derive_actions(
    profile: &ProfileV3,
    order: &[ActionId],
    context: &PlanBuildContext,
    deriver: &dyn TrustedActionDeriver,
) -> Result<Vec<PlannedActionV3>, PlanningError> {
    let mut actions = Vec::with_capacity(profile.steps.len());
    for step_id in order {
        let step = profile
            .steps
            .iter()
            .find(|candidate| candidate.step_id == *step_id)
            .ok_or(PlanningError::SourceStepMismatch)?;
        let action = deriver
            .derive(step, context.intent, &context.observed_state)
            .map_err(PlanningError::Derivation)?;
        validate_derived_action(&action, step, context)?;
        actions.push(action);
    }
    Ok(actions)
}

fn validate_derived_action(
    action: &PlannedActionV3,
    step: &ProfileStepV3,
    context: &PlanBuildContext,
) -> Result<(), PlanningError> {
    if action.source_step != step.step_id || action.capability != step.capability_id {
        return Err(PlanningError::SourceStepMismatch);
    }
    if action.operation != context.intent.into() {
        return Err(PlanningError::IntentMismatch);
    }
    if action.facts_digest != context.observed_state.digest {
        return Err(PlanningError::FactsMismatch);
    }
    Ok(())
}

/// Rebuild a worker plan using a reviewed envelope without extending authority.
///
/// # Errors
///
/// Returns an error when the reviewed envelope is stale, would extend expiry,
/// or differs from fresh worker-derived bindings or actions.
pub(crate) fn rebuild_reviewed_apply_plan(
    reviewed: &PlanV3,
    profile: &ProfileV3,
    context: PlanBuildContext,
    deriver: &dyn TrustedActionDeriver,
    now: DateTime<Utc>,
) -> Result<WorkerPlan, PlanningError> {
    if reviewed.intent != ExecutionIntent::Apply {
        return Err(PlanningError::ReviewedEnvelopeMismatch);
    }
    reviewed.validate_at(now)?;
    let fresh = build_plan(profile, context, deriver, now)?.into_parts().0;
    validate_reviewed_authority(reviewed, &fresh)?;
    let plan = PlanV3 {
        schema_version: fresh.schema_version,
        id: reviewed.id,
        run_id: reviewed.run_id,
        intent: fresh.intent,
        profile_id: fresh.profile_id,
        profile_digest: fresh.profile_digest,
        host: fresh.host,
        tool: fresh.tool,
        package_digest: fresh.package_digest,
        source: fresh.source,
        input: fresh.input,
        observed_state: reviewed.observed_state.clone(),
        issued_at: reviewed.issued_at,
        expires_at: reviewed.expires_at,
        actions: fresh.actions,
        metadata: reviewed.metadata.clone(),
    };
    plan.validate_structure()?;
    Ok(WorkerPlan {
        digest: canonical_json_digest(&plan)?,
        plan,
    })
}

fn validate_reviewed_authority(reviewed: &PlanV3, fresh: &PlanV3) -> Result<(), PlanningError> {
    if reviewed.expires_at > fresh.expires_at {
        return Err(PlanningError::ReviewedEnvelopeMismatch);
    }
    if reviewed.profile_id != fresh.profile_id {
        return Err(PlanningError::ReviewedEnvelopeMismatch);
    }
    if reviewed.profile_digest != fresh.profile_digest {
        return Err(PlanningError::ReviewedEnvelopeMismatch);
    }
    if reviewed.host != fresh.host {
        return Err(PlanningError::ReviewedEnvelopeMismatch);
    }
    if reviewed.tool != fresh.tool {
        return Err(PlanningError::ReviewedEnvelopeMismatch);
    }
    if reviewed.package_digest != fresh.package_digest {
        return Err(PlanningError::ReviewedEnvelopeMismatch);
    }
    if reviewed.source != fresh.source {
        return Err(PlanningError::ReviewedEnvelopeMismatch);
    }
    if reviewed.input != fresh.input {
        return Err(PlanningError::ReviewedEnvelopeMismatch);
    }
    if reviewed.observed_state.digest != fresh.observed_state.digest {
        return Err(PlanningError::ReviewedEnvelopeMismatch);
    }
    if reviewed.actions != fresh.actions {
        return Err(PlanningError::ReviewedEnvelopeMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use baselineops_domain::{
        ActionId, CapabilityId, JsonMap, Operation, OsFamily, PlannedActionV3, PreconditionV3,
        Privilege, ProfileDefaultsV3, ProfileId, ProfileStepV3, RebootRequirement, Reversibility,
        RiskLevel, SchemaVersion, SourceKind,
    };

    fn capability() -> CapabilityId {
        CapabilityId::new("v3.test.capability").expect("capability")
    }

    fn profile(expires_at: Option<DateTime<Utc>>) -> ProfileV3 {
        ProfileV3 {
            schema_version: SchemaVersion::V3,
            id: ProfileId::new(),
            name: "test profile".into(),
            version: "1.0.0".into(),
            description: None,
            created_at: Utc::now() - Duration::minutes(1),
            expires_at,
            defaults: ProfileDefaultsV3::default(),
            steps: vec![ProfileStepV3 {
                step_id: ActionId::new(),
                capability_id: capability(),
                parameters: JsonMap::default(),
                depends_on: Vec::new(),
                continue_on_error: false,
            }],
            metadata: JsonMap::default(),
        }
    }

    fn observed_state() -> ObservedStateV3 {
        let mut values = BTreeMap::new();
        values.insert(
            capability(),
            baselineops_domain::ObservedValueV3 {
                observed_at: Utc::now(),
                facts: BTreeMap::from([("enabled".into(), serde_json::json!(true))]),
            },
        );
        let mut observed_state = ObservedStateV3 {
            captured_at: Utc::now(),
            digest: Sha256Digest::of_bytes(b"placeholder"),
            values,
        };
        observed_state.digest = observed_state.calculated_digest().expect("facts digest");
        observed_state
    }

    fn context(observed_state: ObservedStateV3) -> PlanBuildContext {
        let package_digest = Sha256Digest::of_bytes(b"package");
        let mut host = HostIdentityV3 {
            host_id: "host".into(),
            boot_id: "boot".into(),
            session_id: "session".into(),
            hostname: "endpoint".into(),
            os_family: OsFamily::Windows,
            os_version: "10.0".into(),
            architecture: "x86_64".into(),
            fingerprint: Sha256Digest::of_bytes(b"placeholder"),
        };
        host.fingerprint = host.calculated_fingerprint().expect("fingerprint");
        PlanBuildContext {
            intent: ExecutionIntent::Apply,
            host,
            tool: ToolIdentityV3 {
                name: "baselineops".into(),
                version: "3.0.0".into(),
                build_digest: Some(package_digest),
            },
            package_digest,
            source: SourceIdentityV3 {
                kind: SourceKind::LocalFile,
                locator: "profile.json".into(),
                digest: Sha256Digest::of_bytes(b"profile"),
            },
            input: InputIdentityV3 {
                digest: Sha256Digest::of_bytes(b"input"),
                size_bytes: 5,
            },
            observed_state,
            lifetime: Duration::minutes(5),
        }
    }

    struct TestRegistry {
        operation: Operation,
    }

    impl TrustedActionDeriver for TestRegistry {
        fn derive(
            &self,
            step: &ProfileStepV3,
            _intent: ExecutionIntent,
            observed_state: &ObservedStateV3,
        ) -> Result<PlannedActionV3, String> {
            Ok(PlannedActionV3 {
                id: step.step_id,
                source_step: step.step_id,
                capability: step.capability_id.clone(),
                operation: self.operation,
                parameters: step.parameters.clone(),
                depends_on: step.depends_on.clone(),
                continue_on_error: step.continue_on_error,
                facts_digest: observed_state.digest,
                preconditions: vec![PreconditionV3::Elevation { required: true }],
                risk: RiskLevel::High,
                reversibility: Reversibility::ConditionallyReversible,
                reboot: RebootRequirement::Recommended,
                privileges: vec![Privilege::Administrator],
                metadata: BTreeMap::from([("registry".into(), serde_json::json!(true))]),
            })
        }
    }

    #[test]
    fn trusted_registry_derives_worker_owned_safety_metadata() {
        let state = observed_state();
        let profile = profile(None);
        let plan = build_plan(
            &profile,
            context(state.clone()),
            &TestRegistry {
                operation: Operation::Apply,
            },
            Utc::now(),
        )
        .expect("plan");
        let action = &plan.proposal().actions[0];
        assert_eq!(action.source_step, profile.steps[0].step_id);
        assert_eq!(action.operation, Operation::Apply);
        assert_eq!(action.risk, RiskLevel::High);
        assert_eq!(action.facts_digest, state.digest);
        assert_eq!(action.privileges, vec![Privilege::Administrator]);
    }

    #[test]
    fn planner_rejects_expired_profiles_and_mismatched_intent() {
        let now = Utc::now();
        let expired = profile(Some(now - Duration::seconds(1)));
        let error = build_plan(
            &expired,
            context(observed_state()),
            &TestRegistry {
                operation: Operation::Apply,
            },
            now,
        )
        .expect_err("expired profile");
        assert!(matches!(error, PlanningError::ExpiredProfile));

        let error = build_plan(
            &profile(None),
            context(observed_state()),
            &TestRegistry {
                operation: Operation::Audit,
            },
            Utc::now(),
        )
        .expect_err("registry action must match command intent");
        assert!(matches!(error, PlanningError::IntentMismatch));
    }

    #[test]
    fn reviewed_apply_envelope_keeps_digest_without_extending_expiry() {
        let now = Utc::now();
        let profile = profile(None);
        let plan_context = context(observed_state());
        let reviewed = build_plan(
            &profile,
            plan_context.clone(),
            &TestRegistry {
                operation: Operation::Apply,
            },
            now,
        )
        .expect("reviewed")
        .proposal()
        .clone();
        let rebuilt = rebuild_reviewed_apply_plan(
            &reviewed,
            &profile,
            plan_context,
            &TestRegistry {
                operation: Operation::Apply,
            },
            now + Duration::seconds(1),
        )
        .expect("rebuilt");
        assert_eq!(
            rebuilt.digest(),
            canonical_json_digest(&reviewed).expect("digest")
        );
        assert_eq!(rebuilt.proposal().expires_at, reviewed.expires_at);

        let mut extended = reviewed;
        extended.expires_at += Duration::hours(1);
        assert!(matches!(
            rebuild_reviewed_apply_plan(
                &extended,
                &profile,
                context(observed_state()),
                &TestRegistry {
                    operation: Operation::Apply,
                },
                now + Duration::seconds(1),
            ),
            Err(PlanningError::ReviewedEnvelopeMismatch)
        ));
    }
}
