//! Native read-only executor for the `W32Time` and WEF readiness capability wave.

use baselineops_capabilities::{
    CapabilityDescriptor, CapabilityExecutor, CapabilityOutcome, CapabilityRequest, Operation,
    TimeSyncPolicy, WefReadinessPolicy, evaluate_time_sync, evaluate_wef_readiness,
};
use baselineops_windows::{PlatformError, audit_time_sync, audit_wef_readiness};

/// Native Windows executor for capabilities 34 and 45.
///
/// The descriptors deliberately remain `in_development` until their bounded
/// observations have Windows-oracle and VM evidence against legacy behavior.
pub struct WaveWefTimeWindowsExecutor;

impl CapabilityExecutor for WaveWefTimeWindowsExecutor {
    fn execute(
        &self,
        descriptor: &'static CapabilityDescriptor,
        request: CapabilityRequest<'_>,
    ) -> CapabilityOutcome {
        if request.operation != Operation::Audit {
            return failed(descriptor, "WEF/time executor is read-only");
        }
        let result = match descriptor.id {
            "v3.time-sync.health" => execute_time(request),
            "v3.wef.client-readiness" => execute_wef(request),
            _ => Err(PlatformError::TrustFailure(
                "capability is not implemented by the WEF/time executor".into(),
            )),
        };
        match result {
            Ok(result) => CapabilityOutcome::Completed { result },
            Err(error) => failed(descriptor, &error.to_string()),
        }
    }
}

fn execute_time(request: CapabilityRequest<'_>) -> Result<serde_json::Value, PlatformError> {
    let policy: TimeSyncPolicy =
        serde_json::from_value(request.parameters.clone()).map_err(|error| {
            PlatformError::TrustFailure(format!("invalid time-sync audit parameters: {error}"))
        })?;
    let observation = audit_time_sync(policy.always_run_w32tm_even_if_service_stopped)?;
    serde_json::to_value(evaluate_time_sync(observation, &policy))
        .map_err(|error| PlatformError::TrustFailure(error.to_string()))
}

fn execute_wef(request: CapabilityRequest<'_>) -> Result<serde_json::Value, PlatformError> {
    let policy: WefReadinessPolicy =
        serde_json::from_value(request.parameters.clone()).map_err(|error| {
            PlatformError::TrustFailure(format!("invalid WEF readiness audit parameters: {error}"))
        })?;
    let observation = audit_wef_readiness(policy.include_wecutil_check)?;
    serde_json::to_value(evaluate_wef_readiness(observation))
        .map_err(|error| PlatformError::TrustFailure(error.to_string()))
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
    fn mutation_and_legacy_autostart_are_rejected_before_windows_access() {
        let descriptor = lookup("v3.time-sync.health").expect("time descriptor");
        let mutation = WaveWefTimeWindowsExecutor.execute(
            descriptor,
            CapabilityRequest {
                operation: Operation::Apply,
                parameters: &serde_json::json!({}),
            },
        );
        assert!(matches!(mutation, CapabilityOutcome::Failed { .. }));
        let autostart = WaveWefTimeWindowsExecutor.execute(
            descriptor,
            CapabilityRequest {
                operation: Operation::Audit,
                parameters: &serde_json::json!({ "auto_start_service": true }),
            },
        );
        assert!(matches!(autostart, CapabilityOutcome::Failed { .. }));
    }

    #[test]
    fn wef_rejects_raw_command_parameters_before_windows_access() {
        let descriptor = lookup("v3.wef.client-readiness").expect("WEF descriptor");
        let outcome = WaveWefTimeWindowsExecutor.execute(
            descriptor,
            CapabilityRequest {
                operation: Operation::Audit,
                parameters: &serde_json::json!({ "raw_command": "qc /q" }),
            },
        );
        assert!(matches!(outcome, CapabilityOutcome::Failed { .. }));
    }
}
