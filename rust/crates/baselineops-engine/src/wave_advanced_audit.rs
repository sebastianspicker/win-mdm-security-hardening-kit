//! Read-only native Audit/Plan executor for capability 33.

use baselineops_capabilities::{
    AdvancedAuditPolicy, CapabilityDescriptor, CapabilityExecutor, CapabilityOutcome,
    CapabilityRequest, Operation, evaluate_advanced_audit, validate_advanced_audit_policy,
};
use baselineops_windows::{PlatformError, audit_advanced_policy};

/// Native executor for the bounded Advanced Audit Policy foundation.
pub struct WaveAdvancedAuditWindowsExecutor;

impl CapabilityExecutor for WaveAdvancedAuditWindowsExecutor {
    fn execute(
        &self,
        descriptor: &'static CapabilityDescriptor,
        request: CapabilityRequest<'_>,
    ) -> CapabilityOutcome {
        if descriptor.id != "v3.advanced-audit-policy" {
            return failed(descriptor, "capability is not implemented by this executor");
        }
        if !matches!(request.operation, Operation::Audit | Operation::Plan) {
            return failed(
                descriptor,
                "Advanced Audit Policy mutation is not available",
            );
        }
        let result = parameters(request.parameters)
            .and_then(|policy| audit_advanced_policy().map(|observation| (policy, observation)))
            .and_then(|(policy, observation)| {
                serde_json::to_value(evaluate_advanced_audit(observation, &policy))
                    .map_err(|error| PlatformError::TrustFailure(error.to_string()))
            });
        result.map_or_else(
            |error| failed(descriptor, &error.to_string()),
            |result| CapabilityOutcome::Completed { result },
        )
    }
}

fn parameters(value: &serde_json::Value) -> Result<AdvancedAuditPolicy, PlatformError> {
    let policy: AdvancedAuditPolicy = serde_json::from_value(value.clone()).map_err(|error| {
        PlatformError::TrustFailure(format!("invalid Advanced Audit Policy parameters: {error}"))
    })?;
    validate_advanced_audit_policy(&policy)
        .map_err(|error| PlatformError::TrustFailure(error.into()))?;
    Ok(policy)
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
    fn raw_paths_names_and_apply_reject_before_platform_access() {
        let descriptor = lookup("v3.advanced-audit-policy").expect("descriptor");
        for request in [
            CapabilityRequest {
                operation: Operation::Audit,
                parameters: &serde_json::json!({"path":"desired.json"}),
            },
            CapabilityRequest {
                operation: Operation::Plan,
                parameters: &serde_json::json!({"desired":[{
                    "guid":"Logon","success":true,"failure":true
                }]}),
            },
            CapabilityRequest {
                operation: Operation::Apply,
                parameters: &serde_json::json!({}),
            },
        ] {
            assert!(matches!(
                WaveAdvancedAuditWindowsExecutor.execute(descriptor, request),
                CapabilityOutcome::Failed { .. }
            ));
        }
    }
}
