//! Native read-only executor for the bounded App Control for Business audit.

use baselineops_capabilities::{
    AppControlPolicy, CapabilityDescriptor, CapabilityExecutor, CapabilityOutcome,
    CapabilityRequest, Operation, evaluate_app_control,
};
use baselineops_windows::{PlatformError, audit_app_control};

/// Native Windows executor for capability 43.
///
/// The descriptor remains `in_development`: EFI and multi-policy enumeration,
/// policy content, signature, and effective-policy semantics are intentionally excluded.
pub struct AppControlWindowsExecutor;

impl CapabilityExecutor for AppControlWindowsExecutor {
    fn execute(
        &self,
        descriptor: &'static CapabilityDescriptor,
        request: CapabilityRequest<'_>,
    ) -> CapabilityOutcome {
        if descriptor.id != "v3.app-control.audit" {
            return failed(
                descriptor,
                "capability is not implemented by the App Control executor",
            );
        }
        if request.operation != Operation::Audit {
            return failed(descriptor, "App Control executor is read-only");
        }
        let result = parse_policy(request.parameters)
            .and_then(|policy| audit_app_control().map(|observation| (policy, observation)))
            .and_then(|(policy, observation)| {
                serialize(evaluate_app_control(observation, &policy))
            });
        match result {
            Ok(result) => CapabilityOutcome::Completed { result },
            Err(error) => failed(descriptor, &error.to_string()),
        }
    }
}

fn parse_policy(value: &serde_json::Value) -> Result<AppControlPolicy, PlatformError> {
    serde_json::from_value(value.clone()).map_err(|error| {
        PlatformError::TrustFailure(format!("invalid App Control audit parameters: {error}"))
    })
}

fn serialize<T: serde::Serialize>(value: T) -> Result<serde_json::Value, PlatformError> {
    serde_json::to_value(value).map_err(|error| PlatformError::TrustFailure(error.to_string()))
}

fn failed(descriptor: &'static CapabilityDescriptor, message: &str) -> CapabilityOutcome {
    CapabilityOutcome::Failed {
        capability_id: descriptor.id.into(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use baselineops_capabilities::lookup;

    #[test]
    fn unknown_parameters_and_mutation_are_rejected_before_windows_access() {
        let descriptor = lookup("v3.app-control.audit").expect("App Control descriptor");
        for request in [
            CapabilityRequest {
                operation: Operation::Audit,
                parameters: &serde_json::json!({"policy_path":"C:\\outside"}),
            },
            CapabilityRequest {
                operation: Operation::Apply,
                parameters: &serde_json::json!({}),
            },
        ] {
            assert!(matches!(
                AppControlWindowsExecutor.execute(descriptor, request),
                CapabilityOutcome::Failed { .. }
            ));
        }
    }
}
