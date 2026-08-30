//! Audit and planning executor for bounded Security Options capability 38.

use baselineops_capabilities::{
    CapabilityDescriptor, CapabilityExecutor, CapabilityOutcome, CapabilityRequest, Operation,
    SecurityOptionsPolicy, Unsupported, build_security_options_plan, evaluate_security_options,
};
use baselineops_windows::{PlatformError, observe_security_options};

/// Native executor seam for capability 38's fixed, read-only policy subset.
///
/// The descriptor must remain `in_development`: raw capability Apply is
/// rejected, and no worker mutation route exists in this slice.
pub struct WaveSecurityOptionsWindowsExecutor;

impl CapabilityExecutor for WaveSecurityOptionsWindowsExecutor {
    fn execute(
        &self,
        descriptor: &'static CapabilityDescriptor,
        request: CapabilityRequest<'_>,
    ) -> CapabilityOutcome {
        if descriptor.id == "v3.security-options.drift" && request.operation == Operation::Apply {
            return CapabilityOutcome::Unsupported {
                reason: Unsupported::OperationUnavailable {
                    operation: Operation::Apply,
                },
            };
        }
        let result = match (descriptor.id, request.operation) {
            ("v3.security-options.drift", Operation::Audit) => audit(request),
            ("v3.security-options.drift", Operation::Plan) => plan(request),
            _ => Err(PlatformError::TrustFailure(
                "capability is not implemented by the Security Options executor".into(),
            )),
        };
        result.map_or_else(
            |error| CapabilityOutcome::Failed {
                capability_id: descriptor.id.into(),
                message: error.to_string(),
            },
            |result| CapabilityOutcome::Completed { result },
        )
    }
}

fn parameters(value: &serde_json::Value) -> Result<SecurityOptionsPolicy, PlatformError> {
    serde_json::from_value(value.clone()).map_err(|error| {
        PlatformError::TrustFailure(format!("invalid Security Options parameters: {error}"))
    })
}

fn audit(request: CapabilityRequest<'_>) -> Result<serde_json::Value, PlatformError> {
    let policy = parameters(request.parameters)?;
    json(evaluate_security_options(
        observe_security_options()?,
        &policy,
    ))
}

fn plan(request: CapabilityRequest<'_>) -> Result<serde_json::Value, PlatformError> {
    let policy = parameters(request.parameters)?;
    json(build_security_options_plan(
        observe_security_options()?,
        &policy,
    ))
}

fn json(value: impl serde::Serialize) -> Result<serde_json::Value, PlatformError> {
    serde_json::to_value(value).map_err(|error| PlatformError::TrustFailure(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use baselineops_capabilities::lookup;

    #[test]
    fn legacy_arbitrary_parameters_reject_before_windows_access() {
        let descriptor = lookup("v3.security-options.drift").expect("descriptor");
        for (operation, parameters) in [
            (
                Operation::Audit,
                serde_json::json!({"path":"HKLM\\anything"}),
            ),
            (
                Operation::Plan,
                serde_json::json!({"desired_json":{"Type":"DWord","Value":1}}),
            ),
        ] {
            assert!(matches!(
                WaveSecurityOptionsWindowsExecutor.execute(
                    descriptor,
                    CapabilityRequest {
                        operation,
                        parameters: &parameters,
                    }
                ),
                CapabilityOutcome::Failed { .. }
            ));
        }
    }

    #[test]
    fn raw_apply_is_typed_unsupported_before_windows_access() {
        let descriptor = lookup("v3.security-options.drift").expect("descriptor");
        assert!(matches!(
            WaveSecurityOptionsWindowsExecutor.execute(
                descriptor,
                CapabilityRequest {
                    operation: Operation::Apply,
                    parameters: &serde_json::json!({}),
                }
            ),
            CapabilityOutcome::Unsupported {
                reason: Unsupported::OperationUnavailable {
                    operation: Operation::Apply
                }
            }
        ));
    }
}
