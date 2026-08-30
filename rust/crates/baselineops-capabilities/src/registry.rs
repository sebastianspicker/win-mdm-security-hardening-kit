use crate::{
    Batch, CAPABILITIES, Capability, CapabilityDescriptor, CapabilityExecutor, CapabilityOutcome,
    CapabilityRequest, ExecutionEnvironment, Unsupported,
};

/// A lightweight adapter over an immutable registry descriptor.
#[derive(Clone, Copy, Debug)]
pub struct RegistryCapability {
    descriptor: &'static CapabilityDescriptor,
}

impl Capability for RegistryCapability {
    fn descriptor(&self) -> &'static CapabilityDescriptor {
        self.descriptor
    }

    fn execute(
        &self,
        environment: ExecutionEnvironment<'_>,
        request: CapabilityRequest<'_>,
        executor: Option<&dyn CapabilityExecutor>,
    ) -> CapabilityOutcome {
        if !self.descriptor.operations.supports(request.operation) {
            return CapabilityOutcome::Unsupported {
                reason: Unsupported::OperationUnavailable {
                    operation: request.operation,
                },
            };
        }
        if !environment.is_windows {
            return CapabilityOutcome::Unsupported {
                reason: Unsupported::NonWindowsHost,
            };
        }
        if let Some(requirement) = self
            .descriptor
            .requirements
            .iter()
            .find(|requirement| !environment.has_requirement(requirement))
        {
            return CapabilityOutcome::Unsupported {
                reason: Unsupported::MissingRequirement {
                    requirement: (*requirement).to_owned(),
                },
            };
        }
        match executor {
            Some(executor) => executor.execute(self.descriptor, request),
            None => CapabilityOutcome::Unsupported {
                reason: Unsupported::ExecutorUnavailable {
                    capability_id: self.descriptor.id.to_owned(),
                },
            },
        }
    }
}

/// Returns all legacy leaf descriptors in legacy-number order.
#[must_use]
pub const fn list() -> &'static [CapabilityDescriptor] {
    CAPABILITIES
}

/// Looks up a descriptor by its stable v3 ID.
#[must_use]
pub fn lookup(id: &str) -> Option<&'static CapabilityDescriptor> {
    CAPABILITIES.iter().find(|descriptor| descriptor.id == id)
}

/// Looks up a descriptor by its legacy script number.
#[must_use]
pub fn lookup_legacy(number: u8) -> Option<&'static CapabilityDescriptor> {
    CAPABILITIES
        .iter()
        .find(|descriptor| descriptor.legacy_number == number)
}

/// Returns all descriptors in a curated legacy runner batch.
#[must_use]
pub fn select_batch(batch: Batch) -> Vec<&'static CapabilityDescriptor> {
    if batch == Batch::All {
        return CAPABILITIES.iter().collect();
    }
    CAPABILITIES
        .iter()
        .filter(|descriptor| descriptor.batches.contains(&batch))
        .collect()
}

/// Builds a typed adapter for a stable capability ID.
#[must_use]
pub fn adapter_for(id: &str) -> Option<RegistryCapability> {
    lookup(id).map(|descriptor| RegistryCapability { descriptor })
}
