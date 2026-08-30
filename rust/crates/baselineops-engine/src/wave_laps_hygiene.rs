//! Read-only audit and plan execution for Windows LAPS hygiene.

use baselineops_capabilities::{
    CapabilityDescriptor, CapabilityExecutor, CapabilityOutcome, CapabilityRequest,
    LapsHygieneParameters, Operation, Unsupported, evaluate_laps_hygiene,
};
use baselineops_windows::{PlatformError, audit_laps_hygiene};

/// Read-only LAPS hygiene executor; password rotation remains unsupported.
pub struct WaveLapsHygieneWindowsExecutor;

impl CapabilityExecutor for WaveLapsHygieneWindowsExecutor {
    fn execute(
        &self,
        descriptor: &'static CapabilityDescriptor,
        request: CapabilityRequest<'_>,
    ) -> CapabilityOutcome {
        if descriptor.id != "v3.laps.hygiene" {
            return failed(
                descriptor,
                "capability is not implemented by the LAPS hygiene executor",
            );
        }
        if request.operation == Operation::Apply {
            return unsupported();
        }
        if !matches!(request.operation, Operation::Audit | Operation::Plan) {
            return unsupported();
        }
        let parameters =
            match serde_json::from_value::<LapsHygieneParameters>(request.parameters.clone()) {
                Ok(value) => value,
                Err(error) => {
                    return failed(
                        descriptor,
                        &format!("invalid LAPS hygiene parameters: {error}"),
                    );
                }
            };
        if let Err(error) = parameters.validate() {
            return failed(descriptor, error);
        }
        if parameters.request_rotation {
            return unsupported();
        }
        match audit_laps_hygiene()
            .map(|observation| evaluate_laps_hygiene(observation, &parameters))
            .and_then(serialize)
        {
            Ok(result) => CapabilityOutcome::Completed { result },
            Err(error) => failed(descriptor, &error.to_string()),
        }
    }
}

fn unsupported() -> CapabilityOutcome {
    CapabilityOutcome::Unsupported {
        reason: Unsupported::OperationUnavailable {
            operation: Operation::Apply,
        },
    }
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
    fn raw_apply_and_typed_rotation_request_are_unsupported_before_windows_access() {
        let descriptor = lookup("v3.laps.hygiene").expect("LAPS descriptor");
        for request in [
            CapabilityRequest {
                operation: Operation::Apply,
                parameters: &serde_json::json!({}),
            },
            CapabilityRequest {
                operation: Operation::Plan,
                parameters: &serde_json::json!({ "request_rotation": true }),
            },
        ] {
            assert!(matches!(
                WaveLapsHygieneWindowsExecutor.execute(descriptor, request),
                CapabilityOutcome::Unsupported {
                    reason: Unsupported::OperationUnavailable {
                        operation: Operation::Apply
                    }
                }
            ));
        }
    }

    #[test]
    fn raw_commands_and_out_of_range_parameters_are_rejected_before_windows_access() {
        let descriptor = lookup("v3.laps.hygiene").expect("LAPS descriptor");
        for parameters in [
            serde_json::json!({ "command": "Reset-LapsPassword" }),
            serde_json::json!({ "early_rotation_days": 366 }),
        ] {
            assert!(matches!(
                WaveLapsHygieneWindowsExecutor.execute(
                    descriptor,
                    CapabilityRequest {
                        operation: Operation::Audit,
                        parameters: &parameters,
                    }
                ),
                CapabilityOutcome::Failed { .. }
            ));
        }
    }
}
