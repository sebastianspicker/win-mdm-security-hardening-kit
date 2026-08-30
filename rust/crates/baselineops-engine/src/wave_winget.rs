//! Read-only execution seam shared by `WinGet` capabilities 08 and 25.
//!
//! Both canonical IDs consume the same fixed native acquisition. Raw Apply is
//! typed Unsupported; Audit and Plan accept only an empty strict object. This
//! module never forwards caller-selected files, sources, packages, arguments,
//! aliases, or configuration content to Windows or a native process.

use baselineops_capabilities::{
    CapabilityDescriptor, CapabilityExecutor, CapabilityOutcome, CapabilityRequest, Operation,
    Unsupported, WINGET_CONFIGURATION_ID, WINGET_SELF_HEAL_ID, WingetParameters,
    build_winget_read_only_plan, evaluate_winget_configuration, evaluate_winget_self_heal,
};
use baselineops_windows::{PlatformError, audit_winget};

/// Native executor for the bounded shared `WinGet` audit foundation.
pub struct WaveWingetWindowsExecutor;

impl CapabilityExecutor for WaveWingetWindowsExecutor {
    fn execute(
        &self,
        descriptor: &'static CapabilityDescriptor,
        request: CapabilityRequest<'_>,
    ) -> CapabilityOutcome {
        if !matches!(descriptor.id, WINGET_SELF_HEAL_ID | WINGET_CONFIGURATION_ID) {
            return failed(
                descriptor,
                "capability is not implemented by the WinGet executor",
            );
        }
        if request.operation == Operation::Apply {
            return CapabilityOutcome::Unsupported {
                reason: Unsupported::OperationUnavailable {
                    operation: Operation::Apply,
                },
            };
        }
        let result = parameters(request.parameters)
            .and_then(|()| audit_winget())
            .and_then(|observation| {
                serialize_result(descriptor.id, request.operation, observation)
            });
        result.map_or_else(
            |error| failed(descriptor, &error.to_string()),
            |result| CapabilityOutcome::Completed { result },
        )
    }
}

fn parameters(value: &serde_json::Value) -> Result<(), PlatformError> {
    serde_json::from_value::<WingetParameters>(value.clone())
        .map(|_| ())
        .map_err(|error| PlatformError::TrustFailure(format!("invalid WinGet parameters: {error}")))
}

fn serialize_result(
    capability_id: &str,
    operation: Operation,
    observation: baselineops_capabilities::WingetObservation,
) -> Result<serde_json::Value, PlatformError> {
    let audit = match capability_id {
        WINGET_SELF_HEAL_ID => evaluate_winget_self_heal(observation),
        WINGET_CONFIGURATION_ID => evaluate_winget_configuration(observation),
        _ => {
            return Err(PlatformError::TrustFailure(
                "unsupported canonical WinGet capability identifier".into(),
            ));
        }
    };
    let value = match operation {
        Operation::Audit => serde_json::to_value(audit),
        Operation::Plan => serde_json::to_value(build_winget_read_only_plan(audit)),
        Operation::Apply => unreachable!("Apply is typed Unsupported before serialization"),
    };
    value.map_err(|error| PlatformError::TrustFailure(error.to_string()))
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
    fn raw_apply_is_typed_unsupported_before_windows_access_for_both_ids() {
        for id in [WINGET_SELF_HEAL_ID, WINGET_CONFIGURATION_ID] {
            let descriptor = lookup(id).expect("WinGet descriptor");
            let outcome = WaveWingetWindowsExecutor.execute(
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
    }

    #[test]
    fn executor_rejects_files_sources_packages_and_arguments_before_windows_access() {
        let descriptor = lookup(WINGET_CONFIGURATION_ID).expect("WinGet configuration descriptor");
        for parameters in [
            serde_json::json!({"config_path":"untrusted.yaml"}),
            serde_json::json!({"source":"private"}),
            serde_json::json!({"package":"Contoso.Tool"}),
            serde_json::json!({"arguments":["source", "update"]}),
            serde_json::json!({"repair":true}),
        ] {
            let outcome = WaveWingetWindowsExecutor.execute(
                descriptor,
                CapabilityRequest {
                    operation: Operation::Audit,
                    parameters: &parameters,
                },
            );
            assert!(matches!(outcome, CapabilityOutcome::Failed { .. }));
        }
    }
}
