//! Worker-side recomputation gate for apply authority.

use baselineops_capabilities::{
    Capability, CapabilityDescriptor, CapabilityExecutor, CapabilityOutcome, CapabilityRequest,
    ExecutionEnvironment, Operation as CapabilityOperation, adapter_for, lookup,
};
use baselineops_domain::{
    ObservedStateV3, ObservedValueV3, ProfileStepV3, ProfileV3, Sha256Digest,
};
use chrono::{DateTime, Utc};
use std::collections::BTreeMap;

use crate::{
    ApprovalError, PlanBuildContext, PlanningError, RegistryActionDeriver, VerifiedPlan,
    approval::PlanApprovalSession, planner::rebuild_reviewed_apply_plan,
};
use baselineops_domain::{PlanV3, PlanValidationContext};
use baselineops_windows::TrustedInstallation;

/// Fixed-registry production authority retained by the elevated worker.
pub struct WorkerApplyAuthority {
    session: PlanApprovalSession,
}

/// Opaque proof that the production worker approved its retained proposal.
///
/// This token intentionally exposes no plan or scheduler access. The engine will
/// consume it internally once a fixed native mutation dispatcher is available.
pub struct ApprovedWorkerApply {
    #[allow(dead_code)]
    verified: VerifiedPlan,
}

impl WorkerApplyAuthority {
    /// Exact worker proposal for operator review.
    #[must_use]
    pub const fn proposal(&self) -> &PlanV3 {
        self.session.proposal()
    }
    /// Exact canonical digest requiring operator approval.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.session.digest()
    }
    /// Mint authority only after worker-collected live bindings are revalidated.
    ///
    /// # Errors
    ///
    /// Returns an error when the digest or live bindings fail worker approval.
    pub fn approve(
        self,
        digest: Sha256Digest,
        live: &PlanValidationContext,
        installation: &TrustedInstallation,
    ) -> Result<ApprovedWorkerApply, ApprovalError> {
        self.session
            .approve(digest, live, installation)
            .map(|verified| ApprovedWorkerApply { verified })
    }
}

/// Build retained apply authority using the fixed compile-time registry and worker clock.
///
/// This accepts no caller-supplied action derivation or approval session.
///
/// # Errors
///
/// Returns an error when the reviewed apply plan cannot be rebuilt and validated.
pub fn prepare_worker_apply(
    reviewed: &PlanV3,
    profile: &ProfileV3,
    context: PlanBuildContext,
) -> Result<WorkerApplyAuthority, PlanningError> {
    Ok(WorkerApplyAuthority {
        session: PlanApprovalSession::from_worker_plan(rebuild_reviewed_apply_plan(
            reviewed,
            profile,
            context,
            &RegistryActionDeriver,
            Utc::now(),
        )?),
    })
}

/// Worker observation port used by the authority gate before every apply.
pub trait TrustedObservationSource {
    /// Read current capability facts for a validated profile step.
    ///
    /// # Errors
    ///
    /// Returns an error when the native capability facts cannot be observed.
    fn observe(&self, step: &ProfileStepV3) -> Result<serde_json::Value, String>;
}

/// Re-observe every profile capability and bind the exact fresh facts digest.
///
/// # Errors
///
/// Returns an error if any capability cannot supply trustworthy native facts.
pub fn reobserve_profile(
    profile: &ProfileV3,
    observer: &dyn TrustedObservationSource,
    now: DateTime<Utc>,
) -> Result<ObservedStateV3, String> {
    profile.validate().map_err(|error| error.to_string())?;
    let mut values = BTreeMap::new();
    for step in &profile.steps {
        values.insert(
            step.capability_id.clone(),
            ObservedValueV3 {
                observed_at: now,
                facts: BTreeMap::from([("native_result".into(), observer.observe(step)?)]),
            },
        );
    }
    let mut observed_state = ObservedStateV3 {
        captured_at: now,
        digest: Sha256Digest::of_bytes([]),
        values,
    };
    observed_state.digest = observed_state
        .calculated_digest()
        .map_err(|error| error.to_string())?;
    Ok(observed_state)
}

/// Native, read-only observation implementation compiled into the protected worker.
pub struct NativeObservationSource;

impl TrustedObservationSource for NativeObservationSource {
    fn observe(&self, step: &ProfileStepV3) -> Result<serde_json::Value, String> {
        let descriptor = lookup(step.capability_id.as_str())
            .ok_or_else(|| format!("unknown capability {}", step.capability_id))?;
        let parameters =
            serde_json::to_value(&step.parameters).map_err(|error| error.to_string())?;
        match native_audit(descriptor, &parameters) {
            CapabilityOutcome::Completed { result } => Ok(result),
            CapabilityOutcome::Unsupported { reason } => {
                Err(format!("native observation unavailable: {reason:?}"))
            }
            CapabilityOutcome::Failed { message, .. } => {
                Err(format!("native observation failed: {message}"))
            }
        }
    }
}

fn native_audit(
    descriptor: &'static CapabilityDescriptor,
    parameters: &serde_json::Value,
) -> CapabilityOutcome {
    let environment = ExecutionEnvironment {
        is_windows: cfg!(windows),
        available_requirements: descriptor.requirements,
    };
    let request = CapabilityRequest {
        operation: CapabilityOperation::Audit,
        parameters,
    };
    let executor: &dyn CapabilityExecutor = match descriptor.id {
        "v3.defender.health" | "v3.identity.join" => &crate::WaveOneWindowsExecutor,
        "v3.office-browser.hardening" => &crate::WaveOfficeBrowserWindowsExecutor,
        "v3.windows-update.policy" => &crate::WaveWindowsUpdateWindowsExecutor,
        "v3.laps.hygiene" => &crate::WaveLapsHygieneWindowsExecutor,
        "v3.local-admins.guardrail" => &crate::WaveLocalAdminsWindowsExecutor,
        "v3.ntlm.client" | "v3.doh.audit" => &crate::WaveTwoWindowsExecutor,
        "v3.time-sync.health" | "v3.wef.client-readiness" => &crate::WaveWefTimeWindowsExecutor,
        "v3.network.configuration" | "v3.service-process.inventory" => {
            &crate::WaveNetworkServicesWindowsExecutor
        }
        "v3.firewall.logging" => &crate::WaveFirewallLoggingWindowsExecutor,
        "v3.advanced-audit-policy" => &crate::WaveAdvancedAuditWindowsExecutor,
        "v3.security-options.drift" => &crate::WaveSecurityOptionsWindowsExecutor,
        "v3.lsass.vbs-hardening" | "v3.credential-guard.vbs" | "v3.lsa.protection" => {
            &crate::WaveBootSecurityWindowsExecutor
        }
        "v3.support-bundle.parse" => &crate::SupportBundleParserExecutor,
        "v3.software.inventory" | "v3.patch.missing" | "v3.eventlog.fast-triage" => {
            &crate::WaveInventoryWindowsExecutor
        }
        "v3.hardware.tpm-posture" | "v3.bitlocker.operations" | "v3.secure-boot.uefi" => {
            &crate::WaveHardwareTrustWindowsExecutor
        }
        "v3.storage.reliability" | "v3.backup.readiness" => {
            &crate::WaveStorageBackupWindowsExecutor
        }
        "v3.remote-surface.audit" | "v3.wdag.readiness" => &crate::WaveRemoteWdagWindowsExecutor,
        "v3.app-control.audit" => &crate::AppControlWindowsExecutor,
        "v3.defender.ransomware-network-protection" => {
            &crate::WaveDefenderRansomwareWindowsExecutor
        }
        "v3.client-security-baseline"
        | "v3.driver-signing.integrity"
        | "v3.exploit-protection.audit"
        | "v3.amsi.audit"
        | "v3.applocker.audit" => &crate::WaveApplicationControlWindowsExecutor,
        _ => {
            return CapabilityOutcome::Unsupported {
                reason: baselineops_capabilities::Unsupported::ExecutorUnavailable {
                    capability_id: descriptor.id.into(),
                },
            };
        }
    };
    adapter_for(descriptor.id)
        .expect("compile-time catalog IDs are valid")
        .execute(environment, request, Some(executor))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        PlanBuildContext, TrustedActionDeriver, approval::PlanApprovalSession, build_plan,
    };
    use baselineops_domain::{
        ActionId, CapabilityId, ExecutionIntent, HostIdentityV3, InputIdentityV3, JsonMap,
        ObservedStateV3, ObservedValueV3, OsFamily, PlanValidationContext, PlannedActionV3,
        ProfileDefaultsV3, ProfileId, ProfileStepV3, RebootRequirement, Reversibility, RiskLevel,
        SchemaVersion, SourceIdentityV3, SourceKind, ToolIdentityV3,
    };
    use chrono::Duration;
    use std::collections::BTreeMap;

    fn capability() -> CapabilityId {
        CapabilityId::new("v3.test.authority").expect("capability")
    }

    fn fixture() -> (
        ProfileV3,
        PlanBuildContext,
        DeterministicDeriver,
        DateTime<Utc>,
    ) {
        let now = Utc::now();
        let capability = capability();
        let profile = ProfileV3 {
            schema_version: SchemaVersion::V3,
            id: ProfileId::new(),
            name: "authority test".into(),
            version: "1".into(),
            description: None,
            created_at: now - Duration::minutes(1),
            expires_at: None,
            defaults: ProfileDefaultsV3::default(),
            steps: vec![ProfileStepV3 {
                step_id: ActionId::new(),
                capability_id: capability.clone(),
                parameters: JsonMap::new(),
                depends_on: Vec::new(),
                continue_on_error: false,
            }],
            metadata: JsonMap::new(),
        };
        let package_digest = Sha256Digest::of_bytes(b"package");
        let mut host = HostIdentityV3 {
            host_id: "host".into(),
            boot_id: "boot".into(),
            session_id: "session".into(),
            hostname: "endpoint".into(),
            os_family: OsFamily::Windows,
            os_version: "11".into(),
            architecture: "x86_64".into(),
            fingerprint: Sha256Digest::of_bytes([]),
        };
        host.fingerprint = host.calculated_fingerprint().expect("fingerprint");
        let mut observed = ObservedStateV3 {
            captured_at: now,
            digest: Sha256Digest::of_bytes([]),
            values: BTreeMap::from([(
                capability,
                ObservedValueV3 {
                    observed_at: now,
                    facts: BTreeMap::from([("fresh".into(), serde_json::json!(true))]),
                },
            )]),
        };
        observed.digest = observed.calculated_digest().expect("observation");
        let context = PlanBuildContext {
            intent: ExecutionIntent::Apply,
            host,
            tool: ToolIdentityV3 {
                name: "baselineops".into(),
                version: "3".into(),
                build_digest: Some(package_digest),
            },
            package_digest,
            source: SourceIdentityV3 {
                kind: SourceKind::LocalFile,
                locator: "C:\\profiles\\test.json".into(),
                digest: Sha256Digest::of_bytes(b"profile"),
            },
            input: InputIdentityV3 {
                digest: Sha256Digest::of_bytes(b"profile"),
                size_bytes: 7,
            },
            observed_state: observed,
            lifetime: Duration::minutes(5),
        };
        (profile, context, DeterministicDeriver, now)
    }

    struct DeterministicDeriver;
    impl TrustedActionDeriver for DeterministicDeriver {
        fn derive(
            &self,
            step: &ProfileStepV3,
            intent: ExecutionIntent,
            observed: &ObservedStateV3,
        ) -> Result<PlannedActionV3, String> {
            Ok(PlannedActionV3 {
                id: step.step_id,
                source_step: step.step_id,
                capability: step.capability_id.clone(),
                operation: intent.into(),
                parameters: step.parameters.clone(),
                depends_on: step.depends_on.clone(),
                continue_on_error: step.continue_on_error,
                facts_digest: observed.digest,
                preconditions: vec![],
                risk: RiskLevel::High,
                reversibility: Reversibility::Reversible,
                reboot: RebootRequirement::NotRequired,
                privileges: vec![],
                metadata: BTreeMap::new(),
            })
        }
    }

    fn live_context(context: &PlanBuildContext, now: DateTime<Utc>) -> PlanValidationContext {
        PlanValidationContext {
            now,
            intent: context.intent,
            host: context.host.clone(),
            tool: context.tool.clone(),
            package_digest: context.package_digest,
            source: context.source.clone(),
            input: context.input.clone(),
            observed_state_digest: context.observed_state.digest,
        }
    }

    #[test]
    fn retained_worker_proposal_uses_its_exact_canonical_digest() {
        let (profile, context, deriver, now) = fixture();
        let plan = build_plan(&profile, context.clone(), &deriver, now).expect("worker plan");
        let digest = plan.digest();
        assert_eq!(
            digest,
            baselineops_domain::canonical_json_digest(plan.proposal()).expect("digest")
        );
        let session = PlanApprovalSession::from_worker_plan(plan);
        let verified = session
            .approve_at_root(
                digest,
                &live_context(&context, now),
                std::path::Path::new("C:\\trusted"),
            )
            .expect("verified");
        assert_eq!(verified.digest(), digest);
        assert_eq!(verified.plan().intent, ExecutionIntent::Apply);
    }

    #[test]
    fn wrong_digest_and_live_binding_changes_are_rejected() {
        let (profile, context, deriver, now) = fixture();
        let seed = build_plan(&profile, context.clone(), &deriver, now).expect("worker plan");
        let digest = seed.digest();
        let contexts = [
            ("host", {
                let mut live = live_context(&context, now);
                live.host.boot_id = "rebooted".into();
                live
            }),
            ("package", {
                let mut live = live_context(&context, now);
                live.package_digest = Sha256Digest::of_bytes(b"other");
                live
            }),
            ("input", {
                let mut live = live_context(&context, now);
                live.input.size_bytes += 1;
                live
            }),
            ("source", {
                let mut live = live_context(&context, now);
                live.source.locator = "C:\\other.json".into();
                live
            }),
            ("facts", {
                let mut live = live_context(&context, now);
                live.observed_state_digest = Sha256Digest::of_bytes(b"edited");
                live
            }),
            (
                "expired",
                live_context(&context, now + Duration::minutes(6)),
            ),
        ];
        for (name, live) in contexts {
            let session = PlanApprovalSession::from_worker_plan(
                build_plan(&profile, context.clone(), &deriver, now).expect("worker plan"),
            );
            assert!(
                session
                    .approve_at_root(digest, &live, std::path::Path::new("C:\\trusted"))
                    .is_err(),
                "{name}"
            );
        }
        let session = PlanApprovalSession::from_worker_plan(seed);
        assert!(
            session
                .approve_at_root(
                    Sha256Digest::of_bytes(b"self-approved"),
                    &live_context(&context, now),
                    std::path::Path::new("C:\\trusted")
                )
                .is_err()
        );
    }

    struct FixedObserver;
    impl TrustedObservationSource for FixedObserver {
        fn observe(&self, _step: &ProfileStepV3) -> Result<serde_json::Value, String> {
            Ok(serde_json::json!({"fresh": true}))
        }
    }

    #[test]
    fn injected_observer_controls_the_fresh_facts_binding() {
        let (profile, _context, _deriver, now) = fixture();
        let observed = reobserve_profile(&profile, &FixedObserver, now).expect("observed");
        assert_eq!(observed.values.len(), 1);
        assert_ne!(observed.digest, Sha256Digest::of_bytes([]));
    }
}
