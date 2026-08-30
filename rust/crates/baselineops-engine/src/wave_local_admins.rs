//! Read-only Audit/Plan executor for the local Administrators guardrail.

use baselineops_capabilities::{
    CapabilityDescriptor, CapabilityExecutor, CapabilityOutcome, CapabilityRequest,
    LocalAdminsParameters, Operation, Unsupported, evaluate_local_admins,
};
use baselineops_windows::{PlatformError, audit_local_admins};

/// Native read-only executor for capability `v3.local-admins.guardrail`.
///
/// Apply remains deliberately unavailable: this executor has no membership-add
/// or membership-remove implementation and reports raw Apply requests as a
/// typed unsupported operation before accessing Windows.
pub struct WaveLocalAdminsWindowsExecutor;

impl CapabilityExecutor for WaveLocalAdminsWindowsExecutor {
    fn execute(
        &self,
        descriptor: &'static CapabilityDescriptor,
        request: CapabilityRequest<'_>,
    ) -> CapabilityOutcome {
        if descriptor.id != "v3.local-admins.guardrail" {
            return failed(
                descriptor,
                "capability is not implemented by the local Administrators executor",
            );
        }
        if request.operation == Operation::Apply {
            return unsupported_apply();
        }
        if !matches!(request.operation, Operation::Audit | Operation::Plan) {
            return unsupported_apply();
        }
        let parameters = match parameters(request.parameters) {
            Ok(value) => value,
            Err(error) => return failed(descriptor, &error.to_string()),
        };
        audit_local_admins()
            .map(|observation| evaluate_local_admins(observation, &parameters))
            .and_then(serialize)
            .map_or_else(
                |error| failed(descriptor, &error.to_string()),
                |result| CapabilityOutcome::Completed { result },
            )
    }
}

fn parameters(value: &serde_json::Value) -> Result<LocalAdminsParameters, PlatformError> {
    let parameters: LocalAdminsParameters =
        serde_json::from_value(value.clone()).map_err(|error| {
            PlatformError::TrustFailure(format!("invalid local Administrators parameters: {error}"))
        })?;
    parameters
        .validate()
        .map_err(|error| PlatformError::TrustFailure(error.into()))?;
    Ok(parameters)
}

fn serialize(value: impl serde::Serialize) -> Result<serde_json::Value, PlatformError> {
    serde_json::to_value(value).map_err(|error| PlatformError::TrustFailure(error.to_string()))
}

fn unsupported_apply() -> CapabilityOutcome {
    CapabilityOutcome::Unsupported {
        reason: Unsupported::OperationUnavailable {
            operation: Operation::Apply,
        },
    }
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
        let descriptor =
            lookup("v3.local-admins.guardrail").expect("local administrators descriptor");
        let outcome = WaveLocalAdminsWindowsExecutor.execute(
            descriptor,
            CapabilityRequest {
                operation: Operation::Apply,
                parameters: &serde_json::json!({ "allowed_sids": ["S-1-5-21-1-2-3-1001"] }),
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
    fn unknown_paths_commands_and_account_names_reject_before_windows_access() {
        for value in [
            serde_json::json!({ "allow_list_path": "allow.json" }),
            serde_json::json!({ "command": "net localgroup" }),
            serde_json::json!({ "allowed_sids": ["CONTOSO\\Admins"] }),
        ] {
            assert!(matches!(
                parameters(&value),
                Err(PlatformError::TrustFailure(_))
            ));
        }
    }

    #[test]
    fn plan_accepts_only_typed_sid_parameters() {
        let parameters = parameters(&serde_json::json!({
            "allowed_sids": ["S-1-5-21-1-2-3-1001"]
        }))
        .expect("typed SID parameters");
        assert_eq!(parameters.allowed_sids.len(), 1);
    }
}
