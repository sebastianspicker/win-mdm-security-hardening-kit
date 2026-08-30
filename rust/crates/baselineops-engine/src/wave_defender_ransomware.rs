//! Read-only Audit/Plan executor for Defender ransomware and Network Protection.

use baselineops_capabilities::{
    CapabilityDescriptor, CapabilityExecutor, CapabilityOutcome, CapabilityRequest,
    DefenderRansomwarePolicy, Operation, Unsupported, build_defender_ransomware_plan,
    evaluate_defender_ransomware,
};
use baselineops_windows::{PlatformError, audit_defender_ransomware};

/// Native executor seam for capability 44's bounded observation foundation.
///
/// It deliberately exposes no remediation: provider behavior, legacy oracle
/// comparison, and client/Server Windows VM validation remain open evidence lanes.
pub struct WaveDefenderRansomwareWindowsExecutor;

impl CapabilityExecutor for WaveDefenderRansomwareWindowsExecutor {
    fn execute(
        &self,
        descriptor: &'static CapabilityDescriptor,
        request: CapabilityRequest<'_>,
    ) -> CapabilityOutcome {
        if descriptor.id == "v3.defender.ransomware-network-protection"
            && request.operation == Operation::Apply
        {
            return CapabilityOutcome::Unsupported {
                reason: Unsupported::OperationUnavailable {
                    operation: Operation::Apply,
                },
            };
        }
        let result = match (descriptor.id, request.operation) {
            ("v3.defender.ransomware-network-protection", Operation::Audit) => audit(request),
            ("v3.defender.ransomware-network-protection", Operation::Plan) => plan(request),
            _ => Err(PlatformError::TrustFailure(
                "capability is not implemented by the Defender ransomware executor".into(),
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
    serialize(evaluate_defender_ransomware(
        audit_defender_ransomware()?,
        &policy,
    ))
}

fn plan(request: CapabilityRequest<'_>) -> Result<serde_json::Value, PlatformError> {
    let policy = parameters(request.parameters)?;
    serialize(build_defender_ransomware_plan(
        audit_defender_ransomware()?,
        &policy,
    ))
}

fn parameters(value: &serde_json::Value) -> Result<DefenderRansomwarePolicy, PlatformError> {
    serde_json::from_value(value.clone()).map_err(|error| {
        PlatformError::TrustFailure(format!("invalid Defender ransomware parameters: {error}"))
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
        let descriptor = lookup("v3.defender.ransomware-network-protection").expect("descriptor");
        assert!(matches!(
            WaveDefenderRansomwareWindowsExecutor.execute(
                descriptor,
                CapabilityRequest {
                    operation: Operation::Apply,
                    parameters: &serde_json::json!({})
                }
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
        let descriptor = lookup("v3.defender.ransomware-network-protection").expect("descriptor");
        let parameters = serde_json::json!({"command":"Set-MpPreference"});
        assert!(matches!(
            WaveDefenderRansomwareWindowsExecutor.execute(
                descriptor,
                CapabilityRequest {
                    operation: Operation::Plan,
                    parameters: &parameters
                }
            ),
            CapabilityOutcome::Failed { .. }
        ));
    }
}
