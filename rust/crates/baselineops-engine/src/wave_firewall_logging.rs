//! Read-only native audit and drift-only plan executor for capability 32.

use baselineops_capabilities::{
    CapabilityDescriptor, CapabilityExecutor, CapabilityOutcome, CapabilityRequest,
    FirewallLoggingParameters, Operation, build_firewall_logging_plan,
    resolve_firewall_logging_desired_state,
};
use baselineops_windows::{PlatformError, observe_firewall};

/// Native capability 32 executor; mutation and rule scope remain excluded.
pub struct WaveFirewallLoggingWindowsExecutor;

impl CapabilityExecutor for WaveFirewallLoggingWindowsExecutor {
    fn execute(
        &self,
        descriptor: &'static CapabilityDescriptor,
        request: CapabilityRequest<'_>,
    ) -> CapabilityOutcome {
        let result = match (descriptor.id, request.operation) {
            ("v3.firewall.logging", Operation::Audit) => audit(request),
            ("v3.firewall.logging", Operation::Plan) => plan(request),
            ("v3.firewall.logging", Operation::Apply) => Err(PlatformError::TrustFailure(
                "firewall logging Apply requires a verified-plan executor and is not reachable through raw capability requests".into(),
            )),
            _ => Err(PlatformError::TrustFailure(
                "capability is not implemented by the firewall logging executor".into(),
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

fn parse_parameters(value: &serde_json::Value) -> Result<FirewallLoggingParameters, PlatformError> {
    serde_json::from_value(value.clone()).map_err(|error| {
        PlatformError::TrustFailure(format!("invalid firewall logging parameters: {error}"))
    })
}

fn audit(request: CapabilityRequest<'_>) -> Result<serde_json::Value, PlatformError> {
    let _ = parse_parameters(request.parameters)?;
    json(observe_firewall()?)
}

fn plan(request: CapabilityRequest<'_>) -> Result<serde_json::Value, PlatformError> {
    let desired = resolve_firewall_logging_desired_state(&parse_parameters(request.parameters)?)
        .map_err(PlatformError::TrustFailure)?;
    json(
        build_firewall_logging_plan(observe_firewall()?, desired)
            .map_err(PlatformError::TrustFailure)?,
    )
}

fn json(value: impl serde::Serialize) -> Result<serde_json::Value, PlatformError> {
    serde_json::to_value(value).map_err(|error| {
        PlatformError::TrustFailure(format!("firewall logging serialization failed: {error}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use baselineops_capabilities::lookup;

    #[test]
    fn raw_apply_and_unknown_parameters_are_rejected_before_windows_access() {
        let descriptor = lookup("v3.firewall.logging").expect("descriptor");
        for (operation, parameters) in [
            (
                Operation::Audit,
                serde_json::json!({"raw_command": "forbidden"}),
            ),
            (Operation::Apply, serde_json::json!({})),
        ] {
            assert!(matches!(
                WaveFirewallLoggingWindowsExecutor.execute(
                    descriptor,
                    CapabilityRequest {
                        operation,
                        parameters: &parameters,
                    },
                ),
                CapabilityOutcome::Failed { .. }
            ));
        }
    }
}
