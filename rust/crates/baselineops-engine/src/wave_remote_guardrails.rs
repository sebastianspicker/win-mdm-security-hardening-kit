//! Read-only native executor for capability 14's fixed remote guardrails.
//!
//! Audit reads fixed local evidence. Plan may only produce a non-mutating
//! proposal from complete fixed evidence. Raw Apply is typed unsupported.

use baselineops_capabilities::{
    CapabilityDescriptor, CapabilityExecutor, CapabilityOutcome, CapabilityRequest, Operation,
    RemoteGuardrailsPolicy, Unsupported, build_remote_guardrails_plan, evaluate_remote_guardrails,
};
use baselineops_windows::{PlatformError, audit_remote_guardrails};

/// Native capability 14 executor for fixed local RDP and Remote Assistance state.
///
/// It neither connects to remote hosts nor controls RDP, Remote Assistance,
/// services, firewall rules, groups, users, or registry values.
pub struct WaveRemoteGuardrailsWindowsExecutor;

impl CapabilityExecutor for WaveRemoteGuardrailsWindowsExecutor {
    fn execute(
        &self,
        descriptor: &'static CapabilityDescriptor,
        request: CapabilityRequest<'_>,
    ) -> CapabilityOutcome {
        if descriptor.id == "v3.remote-access.guardrails" && request.operation == Operation::Apply {
            return CapabilityOutcome::Unsupported {
                reason: Unsupported::OperationUnavailable {
                    operation: Operation::Apply,
                },
            };
        }
        let result = match (descriptor.id, request.operation) {
            ("v3.remote-access.guardrails", Operation::Audit) => audit(request),
            ("v3.remote-access.guardrails", Operation::Plan) => plan(request),
            _ => Err(PlatformError::TrustFailure(
                "capability is not implemented by the remote guardrails executor".into(),
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

fn policy(value: &serde_json::Value) -> Result<RemoteGuardrailsPolicy, PlatformError> {
    serde_json::from_value(value.clone()).map_err(|error| {
        PlatformError::TrustFailure(format!("invalid remote guardrails parameters: {error}"))
    })
}

fn audit(request: CapabilityRequest<'_>) -> Result<serde_json::Value, PlatformError> {
    let policy = policy(request.parameters)?;
    json(evaluate_remote_guardrails(
        audit_remote_guardrails()?,
        &policy,
    ))
}

fn plan(request: CapabilityRequest<'_>) -> Result<serde_json::Value, PlatformError> {
    let policy = policy(request.parameters)?;
    json(
        build_remote_guardrails_plan(audit_remote_guardrails()?, &policy)
            .map_err(PlatformError::TrustFailure)?,
    )
}

fn json(value: impl serde::Serialize) -> Result<serde_json::Value, PlatformError> {
    serde_json::to_value(value).map_err(|error| {
        PlatformError::TrustFailure(format!("remote guardrails serialization failed: {error}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use baselineops_capabilities::lookup;

    #[test]
    fn dynamic_parameters_reject_before_windows_access() {
        let descriptor = lookup("v3.remote-access.guardrails").expect("descriptor");
        for parameters in [
            serde_json::json!({"remote_host":"host.example"}),
            serde_json::json!({"rdp_port":3389}),
            serde_json::json!({"firewall_rule":"Remote Desktop"}),
            serde_json::json!({"allowed_groups":["DOMAIN\\RDP-Admins"]}),
            serde_json::json!({"command":"netsh"}),
        ] {
            assert!(matches!(
                WaveRemoteGuardrailsWindowsExecutor.execute(
                    descriptor,
                    CapabilityRequest {
                        operation: Operation::Audit,
                        parameters: &parameters,
                    },
                ),
                CapabilityOutcome::Failed { .. }
            ));
        }
    }

    #[test]
    fn raw_apply_is_typed_unsupported_before_windows_access() {
        let descriptor = lookup("v3.remote-access.guardrails").expect("descriptor");
        assert!(matches!(
            WaveRemoteGuardrailsWindowsExecutor.execute(
                descriptor,
                CapabilityRequest {
                    operation: Operation::Apply,
                    parameters: &serde_json::json!({}),
                },
            ),
            CapabilityOutcome::Unsupported {
                reason: Unsupported::OperationUnavailable {
                    operation: Operation::Apply
                }
            }
        ));
    }
}
