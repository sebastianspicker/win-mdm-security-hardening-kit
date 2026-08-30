//! Read-only executor boundary for the bounded capability-06 foundation.

use baselineops_capabilities::{
    CapabilityDescriptor, CapabilityExecutor, CapabilityOutcome, CapabilityRequest, Operation,
    Unsupported, UpdateHealthParameters, build_update_health_read_only_plan,
    evaluate_update_health,
};
use baselineops_windows::{PlatformError, audit_update_health};

/// Native executor for the bounded Update Health and SSU evidence subset.
///
/// It never runs a shell, accepts arbitrary identities, writes evidence,
/// modifies services/tasks, repairs Windows Update, resets components, or
/// restarts the machine. Apply is explicitly typed unsupported.
pub struct WaveUpdateHealthWindowsExecutor;

impl CapabilityExecutor for WaveUpdateHealthWindowsExecutor {
    fn execute(
        &self,
        descriptor: &'static CapabilityDescriptor,
        request: CapabilityRequest<'_>,
    ) -> CapabilityOutcome {
        if descriptor.id != "v3.update-health.ssu" {
            return failed(
                descriptor,
                "capability is not implemented by the update-health executor",
            );
        }
        if request.operation == Operation::Apply {
            return CapabilityOutcome::Unsupported {
                reason: Unsupported::OperationUnavailable {
                    operation: Operation::Apply,
                },
            };
        }
        let result = match request.operation {
            Operation::Audit => audit(request),
            Operation::Plan => plan(request),
            Operation::Apply => unreachable!("Apply returned Unsupported above"),
        };
        result.map_or_else(
            |error| failed(descriptor, &error.to_string()),
            |result| CapabilityOutcome::Completed { result },
        )
    }
}

fn audit(request: CapabilityRequest<'_>) -> Result<serde_json::Value, PlatformError> {
    parse_parameters(request.parameters)?;
    serialize(evaluate_update_health(audit_update_health()?))
}

fn plan(request: CapabilityRequest<'_>) -> Result<serde_json::Value, PlatformError> {
    parse_parameters(request.parameters)?;
    serialize(build_update_health_read_only_plan(audit_update_health()?))
}

fn parse_parameters(value: &serde_json::Value) -> Result<(), PlatformError> {
    serde_json::from_value::<UpdateHealthParameters>(value.clone())
        .map(|_| ())
        .map_err(|error| {
            PlatformError::TrustFailure(format!("invalid update-health parameters: {error}"))
        })
}

fn serialize(value: impl serde::Serialize) -> Result<serde_json::Value, PlatformError> {
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
    fn raw_apply_is_typed_unsupported_before_windows_access() {
        let descriptor = lookup("v3.update-health.ssu").expect("update health descriptor");
        let outcome = WaveUpdateHealthWindowsExecutor.execute(
            descriptor,
            CapabilityRequest {
                operation: Operation::Apply,
                parameters: &serde_json::json!({}),
            },
        );
        assert!(matches!(
            outcome,
            CapabilityOutcome::Unsupported {
                reason: Unsupported::OperationUnavailable {
                    operation: Operation::Apply
                }
            }
        ));
    }

    #[test]
    fn unsafe_legacy_inputs_are_rejected_before_windows_access() {
        for parameters in [
            serde_json::json!({ "service": "wuauserv" }),
            serde_json::json!({ "task_folder": "\\\\Microsoft\\\\UpdateHealthService" }),
            serde_json::json!({ "dism": true }),
            serde_json::json!({ "repair": true }),
            serde_json::json!({ "restart": true }),
        ] {
            assert!(parse_parameters(&parameters).is_err());
        }
    }
}
