//! Audit and planning boundary for bounded capability 05 policy state.

use baselineops_capabilities::{
    CapabilityDescriptor, CapabilityExecutor, CapabilityOutcome, CapabilityRequest, Operation,
    WindowsUpdateParameters, build_windows_update_plan, resolve_windows_update_desired_state,
};
use baselineops_windows::{PlatformError, observe_windows_update_policy};

/// Native executor seam for capability 05.
///
/// Public mutation remains unavailable until verified-plan application has
/// independent oracle and Windows VM evidence.
pub struct WaveWindowsUpdateWindowsExecutor;

impl CapabilityExecutor for WaveWindowsUpdateWindowsExecutor {
    fn execute(
        &self,
        descriptor: &'static CapabilityDescriptor,
        request: CapabilityRequest<'_>,
    ) -> CapabilityOutcome {
        let result = match (descriptor.id, request.operation) {
            ("v3.windows-update.policy", Operation::Audit) => audit(request),
            ("v3.windows-update.policy", Operation::Plan) => plan(request),
            ("v3.windows-update.policy", Operation::Apply) => Err(PlatformError::TrustFailure(
                "Windows Update Apply requires a verified-plan executor and is not reachable through raw capability requests".into(),
            )),
            _ => Err(PlatformError::TrustFailure(
                "capability is not implemented by the Windows Update executor".into(),
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

fn parameters(value: &serde_json::Value) -> Result<WindowsUpdateParameters, PlatformError> {
    serde_json::from_value(value.clone()).map_err(|error| {
        PlatformError::TrustFailure(format!("invalid Windows Update parameters: {error}"))
    })
}

fn audit(request: CapabilityRequest<'_>) -> Result<serde_json::Value, PlatformError> {
    let _ = parameters(request.parameters)?;
    json(observe_windows_update_policy()?)
}

fn plan(request: CapabilityRequest<'_>) -> Result<serde_json::Value, PlatformError> {
    let desired = resolve_windows_update_desired_state(&parameters(request.parameters)?)
        .map_err(PlatformError::TrustFailure)?;
    json(build_windows_update_plan(
        observe_windows_update_policy()?,
        desired,
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
    fn rejects_unknown_input_and_raw_apply_before_windows_access() {
        let descriptor = lookup("v3.windows-update.policy").expect("descriptor");
        for (operation, parameters) in [
            (Operation::Audit, serde_json::json!({"command":"reg.exe"})),
            (Operation::Apply, serde_json::json!({})),
        ] {
            assert!(matches!(
                WaveWindowsUpdateWindowsExecutor.execute(
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
}
