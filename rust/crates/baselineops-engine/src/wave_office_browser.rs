//! Audit and planning boundary for bounded capability 04 policy state.

use baselineops_capabilities::{
    CapabilityDescriptor, CapabilityExecutor, CapabilityOutcome, CapabilityRequest,
    OfficeBrowserParameters, Operation, build_office_browser_plan,
    resolve_office_browser_desired_state,
};
use baselineops_windows::{PlatformError, observe_office_browser_policy};

/// Native executor seam for capability 04.
///
/// Raw capability Apply is deliberately rejected. The descriptor remains in
/// development until VM/oracle evidence validates every mapping and a verified
/// worker-plan application route exists.
pub struct WaveOfficeBrowserWindowsExecutor;

impl CapabilityExecutor for WaveOfficeBrowserWindowsExecutor {
    fn execute(
        &self,
        descriptor: &'static CapabilityDescriptor,
        request: CapabilityRequest<'_>,
    ) -> CapabilityOutcome {
        let result = match (descriptor.id, request.operation) {
            ("v3.office-browser.hardening", Operation::Audit) => audit(request),
            ("v3.office-browser.hardening", Operation::Plan) => plan(request),
            ("v3.office-browser.hardening", Operation::Apply) => Err(PlatformError::TrustFailure(
                "Office/browser Apply requires a verified-plan executor and is not reachable through raw capability requests".into(),
            )),
            _ => Err(PlatformError::TrustFailure(
                "capability is not implemented by the Office/browser executor".into(),
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

fn parameters(value: &serde_json::Value) -> Result<OfficeBrowserParameters, PlatformError> {
    serde_json::from_value(value.clone()).map_err(|error| {
        PlatformError::TrustFailure(format!("invalid Office/browser parameters: {error}"))
    })
}
fn audit(request: CapabilityRequest<'_>) -> Result<serde_json::Value, PlatformError> {
    let _ = parameters(request.parameters)?;
    json(observe_office_browser_policy()?)
}

fn plan(request: CapabilityRequest<'_>) -> Result<serde_json::Value, PlatformError> {
    let desired = resolve_office_browser_desired_state(&parameters(request.parameters)?)
        .map_err(PlatformError::TrustFailure)?;
    json(build_office_browser_plan(
        observe_office_browser_policy()?,
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
        let descriptor = lookup("v3.office-browser.hardening").expect("descriptor");
        for (operation, parameters) in [
            (Operation::Audit, serde_json::json!({"raw_path":"HKLM"})),
            (Operation::Apply, serde_json::json!({})),
        ] {
            assert!(matches!(
                WaveOfficeBrowserWindowsExecutor.execute(
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
