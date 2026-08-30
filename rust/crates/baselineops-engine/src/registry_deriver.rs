//! Capability-registry action derivation with exhaustive domain mappings.

use crate::TrustedActionDeriver;
use baselineops_capabilities::{
    ImplementationMaturity, Operation as RegistryOperation, Privilege as RegistryPrivilege,
    Reboot as RegistryReboot, Reversibility as RegistryReversibility, Risk as RegistryRisk, lookup,
};
use baselineops_domain::{
    ExecutionIntent, ObservedStateV3, PlannedActionV3, PreconditionV3, Privilege, ProfileStepV3,
    RebootRequirement, Reversibility, RiskLevel,
};
use std::collections::BTreeMap;

/// Trusted derivation backed only by the compile-time capability registry.
pub struct RegistryActionDeriver;

impl TrustedActionDeriver for RegistryActionDeriver {
    fn derive(
        &self,
        step: &ProfileStepV3,
        intent: ExecutionIntent,
        observed_state: &ObservedStateV3,
    ) -> Result<PlannedActionV3, String> {
        let descriptor = lookup(step.capability_id.as_str())
            .ok_or_else(|| format!("unknown capability {}", step.capability_id))?;
        let operation = registry_operation(intent);
        if !descriptor.operations.supports(operation) {
            return Err(format!(
                "capability {} does not support {operation:?}",
                descriptor.id
            ));
        }
        if descriptor.maturity != ImplementationMaturity::Implemented {
            return Err(format!(
                "capability {} is not independently evidenced as implemented",
                descriptor.id
            ));
        }
        if !observed_state.values.contains_key(&step.capability_id) {
            return Err(format!(
                "trusted observation is absent for capability {}",
                descriptor.id
            ));
        }
        let privilege = domain_privilege(descriptor.privilege, intent);
        let mut preconditions = vec![
            PreconditionV3::CapabilityAvailable {
                capability: step.capability_id.clone(),
            },
            PreconditionV3::ObservedStateDigest {
                digest: observed_state.digest,
            },
        ];
        if privilege == Privilege::Administrator {
            preconditions.push(PreconditionV3::Elevation { required: true });
        }
        Ok(PlannedActionV3 {
            // Reusing the validated source-step ID makes independent derivation deterministic.
            id: step.step_id,
            source_step: step.step_id,
            capability: step.capability_id.clone(),
            operation: intent.into(),
            parameters: step.parameters.clone(),
            depends_on: step.depends_on.clone(),
            continue_on_error: step.continue_on_error,
            facts_digest: observed_state.digest,
            preconditions,
            risk: domain_risk(descriptor.risk),
            reversibility: domain_reversibility(descriptor.reversibility),
            reboot: domain_reboot(descriptor.reboot),
            privileges: vec![privilege],
            metadata: BTreeMap::default(),
        })
    }
}

const fn registry_operation(intent: ExecutionIntent) -> RegistryOperation {
    match intent {
        ExecutionIntent::Audit => RegistryOperation::Audit,
        ExecutionIntent::Plan => RegistryOperation::Plan,
        ExecutionIntent::Apply => RegistryOperation::Apply,
    }
}

const fn domain_privilege(value: RegistryPrivilege, intent: ExecutionIntent) -> Privilege {
    match value {
        RegistryPrivilege::ElevatedForApply if matches!(intent, ExecutionIntent::Apply) => {
            Privilege::Administrator
        }
        RegistryPrivilege::StandardUser | RegistryPrivilege::ElevatedForApply => Privilege::User,
        RegistryPrivilege::AdministratorRequired => Privilege::Administrator,
    }
}

const fn domain_risk(value: RegistryRisk) -> RiskLevel {
    match value {
        RegistryRisk::Low => RiskLevel::Low,
        RegistryRisk::Medium => RiskLevel::Moderate,
        RegistryRisk::High => RiskLevel::High,
        RegistryRisk::Critical => RiskLevel::Critical,
    }
}

const fn domain_reversibility(value: RegistryReversibility) -> Reversibility {
    match value {
        RegistryReversibility::NotApplicable => Reversibility::NotApplicable,
        RegistryReversibility::Reversible => Reversibility::Reversible,
        RegistryReversibility::ManualRecovery | RegistryReversibility::NotReversible => {
            Reversibility::Irreversible
        }
    }
}

const fn domain_reboot(value: RegistryReboot) -> RebootRequirement {
    match value {
        RegistryReboot::No => RebootRequirement::NotRequired,
        RegistryReboot::Possible => RebootRequirement::Recommended,
        RegistryReboot::Required => RebootRequirement::Required,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use baselineops_domain::{ActionId, CapabilityId, JsonMap, Sha256Digest};

    #[test]
    fn all_registry_vocabularies_have_explicit_domain_mappings() {
        assert_eq!(domain_risk(RegistryRisk::Medium), RiskLevel::Moderate);
        assert_eq!(
            domain_reversibility(RegistryReversibility::ManualRecovery),
            Reversibility::Irreversible
        );
        assert_eq!(
            domain_reboot(RegistryReboot::Possible),
            RebootRequirement::Recommended
        );
        assert_eq!(
            domain_privilege(RegistryPrivilege::ElevatedForApply, ExecutionIntent::Apply),
            Privilege::Administrator
        );
    }

    #[test]
    fn incomplete_capability_cannot_mint_a_worker_action() {
        let capability = CapabilityId::new("v3.doh.audit").expect("capability");
        let step = ProfileStepV3 {
            step_id: ActionId::new(),
            capability_id: capability.clone(),
            parameters: JsonMap::new(),
            depends_on: Vec::new(),
            continue_on_error: false,
        };
        let mut state = ObservedStateV3 {
            captured_at: chrono::Utc::now(),
            digest: Sha256Digest::of_bytes(b"placeholder"),
            values: BTreeMap::default(),
        };
        state.values.insert(
            capability,
            baselineops_domain::ObservedValueV3 {
                observed_at: chrono::Utc::now(),
                facts: JsonMap::new(),
            },
        );
        state.digest = state.calculated_digest().expect("facts digest");
        let result = RegistryActionDeriver.derive(&step, ExecutionIntent::Audit, &state);
        assert!(result.is_err());
    }
}
