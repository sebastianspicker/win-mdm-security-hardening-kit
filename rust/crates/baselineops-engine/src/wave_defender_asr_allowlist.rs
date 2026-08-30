//! Read-only Audit/Plan executor for Defender ASR allowlist metadata.

use baselineops_capabilities::{
    CapabilityDescriptor, CapabilityExecutor, CapabilityOutcome, CapabilityRequest,
    DefenderAsrAllowlistPolicy, Operation, Unsupported, build_defender_asr_allowlist_plan,
    evaluate_defender_asr_allowlist,
};
use baselineops_windows::{PlatformError, audit_defender_asr_allowlist};

/// Native executor seam for capability 01's bounded ASR metadata foundation.
///
/// Audit and Plan are read-only. Plan deliberately reports zero proposed mutations;
/// raw Apply is typed unsupported before parameter parsing or Windows access.
pub struct WaveDefenderAsrAllowlistWindowsExecutor;

impl CapabilityExecutor for WaveDefenderAsrAllowlistWindowsExecutor {
    fn execute(
        &self,
        descriptor: &'static CapabilityDescriptor,
        request: CapabilityRequest<'_>,
    ) -> CapabilityOutcome {
        if descriptor.id == "v3.defender.asr-allowlist" && request.operation == Operation::Apply {
            return CapabilityOutcome::Unsupported {
                reason: Unsupported::OperationUnavailable {
                    operation: Operation::Apply,
                },
            };
        }
        let result = match (descriptor.id, request.operation) {
            ("v3.defender.asr-allowlist", Operation::Audit) => audit(request),
            ("v3.defender.asr-allowlist", Operation::Plan) => plan(request),
            _ => Err(PlatformError::TrustFailure(
                "capability is not implemented by the Defender ASR allowlist executor".into(),
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

fn audit(request: CapabilityRequest<'_>) -> Result<serde_json::Value, PlatformError> {
    let policy = parameters(request.parameters)?;
    serialize(evaluate_defender_asr_allowlist(
        audit_defender_asr_allowlist()?,
        &policy,
    ))
}

fn plan(request: CapabilityRequest<'_>) -> Result<serde_json::Value, PlatformError> {
    let policy = parameters(request.parameters)?;
    serialize(build_defender_asr_allowlist_plan(
        audit_defender_asr_allowlist()?,
        &policy,
    ))
}

fn parameters(value: &serde_json::Value) -> Result<DefenderAsrAllowlistPolicy, PlatformError> {
    serde_json::from_value(value.clone()).map_err(|error| {
        PlatformError::TrustFailure(format!(
            "invalid Defender ASR allowlist parameters: {error}"
        ))
    })
}

fn serialize(value: impl serde::Serialize) -> Result<serde_json::Value, PlatformError> {
    serde_json::to_value(value).map_err(|error| PlatformError::TrustFailure(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use baselineops_capabilities::lookup;

    #[test]
    fn raw_apply_is_typed_unsupported_before_windows_access() {
        let descriptor = lookup("v3.defender.asr-allowlist").expect("descriptor");
        assert!(matches!(
            WaveDefenderAsrAllowlistWindowsExecutor.execute(
                descriptor,
                CapabilityRequest {
                    operation: Operation::Apply,
                    parameters: &serde_json::json!({"command":"Set-MpPreference"}),
                },
            ),
            CapabilityOutcome::Unsupported {
                reason: Unsupported::OperationUnavailable {
                    operation: Operation::Apply
                }
            }
        ));
    }

    #[test]
    fn unknown_parameters_reject_before_windows_access() {
        let descriptor = lookup("v3.defender.asr-allowlist").expect("descriptor");
        for parameters in [
            serde_json::json!({"path":"C:\\\\temp"}),
            serde_json::json!({"rule_id":"unbounded"}),
            serde_json::json!({"exclusion":"example.exe"}),
        ] {
            assert!(matches!(
                WaveDefenderAsrAllowlistWindowsExecutor.execute(
                    descriptor,
                    CapabilityRequest {
                        operation: Operation::Plan,
                        parameters: &parameters,
                    },
                ),
                CapabilityOutcome::Failed { .. }
            ));
        }
    }
}
