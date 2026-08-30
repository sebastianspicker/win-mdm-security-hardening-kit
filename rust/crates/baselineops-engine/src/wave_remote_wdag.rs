//! Native read-only executor for remote-surface and WDAG readiness capabilities.

use baselineops_capabilities::{
    CapabilityDescriptor, CapabilityExecutor, CapabilityOutcome, CapabilityRequest, Operation,
    RemoteSurfacePolicy, WdagReadinessPolicy, evaluate_remote_surface, evaluate_wdag_readiness,
};
use baselineops_windows::{PlatformError, audit_remote_surface, audit_wdag_readiness};

/// Native Windows executor for capabilities 37 and 47.
///
/// Both descriptors remain `in_development` until the legacy script oracle,
/// representative Windows VM/edition evidence, and native-tool trust binding
/// have independent retained proof.
pub struct WaveRemoteWdagWindowsExecutor;

impl CapabilityExecutor for WaveRemoteWdagWindowsExecutor {
    fn execute(
        &self,
        descriptor: &'static CapabilityDescriptor,
        request: CapabilityRequest<'_>,
    ) -> CapabilityOutcome {
        if request.operation != Operation::Audit {
            return failed(descriptor, "remote/WDAG executor is read-only");
        }
        let result = match descriptor.id {
            "v3.remote-surface.audit" => execute_remote_surface(request),
            "v3.wdag.readiness" => execute_wdag(request),
            _ => Err(PlatformError::TrustFailure(
                "capability is not implemented by the remote/WDAG executor".into(),
            )),
        };
        result.map_or_else(
            |error| failed(descriptor, &error.to_string()),
            |result| CapabilityOutcome::Completed { result },
        )
    }
}

fn execute_remote_surface(
    request: CapabilityRequest<'_>,
) -> Result<serde_json::Value, PlatformError> {
    let policy: RemoteSurfacePolicy = parse(request.parameters, "remote-surface")?;
    serialize(evaluate_remote_surface(audit_remote_surface()?, &policy))
}

fn execute_wdag(request: CapabilityRequest<'_>) -> Result<serde_json::Value, PlatformError> {
    let policy: WdagReadinessPolicy = parse(request.parameters, "WDAG readiness")?;
    serialize(evaluate_wdag_readiness(audit_wdag_readiness()?, &policy))
}

fn parse<T>(value: &serde_json::Value, label: &str) -> Result<T, PlatformError>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_value(value.clone()).map_err(|error| {
        PlatformError::TrustFailure(format!("invalid {label} parameters: {error}"))
    })
}

fn serialize<T: serde::Serialize>(value: T) -> Result<serde_json::Value, PlatformError> {
    serde_json::to_value(value).map_err(|error| PlatformError::TrustFailure(error.to_string()))
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
    fn mutation_and_unknown_parameters_are_rejected_before_windows_access() {
        let remote = lookup("v3.remote-surface.audit").expect("remote descriptor");
        let mutation = WaveRemoteWdagWindowsExecutor.execute(
            remote,
            CapabilityRequest {
                operation: Operation::Apply,
                parameters: &serde_json::json!({}),
            },
        );
        assert!(matches!(mutation, CapabilityOutcome::Failed { .. }));
        let wdag = lookup("v3.wdag.readiness").expect("WDAG descriptor");
        let unknown = WaveRemoteWdagWindowsExecutor.execute(
            wdag,
            CapabilityRequest {
                operation: Operation::Audit,
                parameters: &serde_json::json!({ "command": "dism" }),
            },
        );
        assert!(matches!(unknown, CapabilityOutcome::Failed { .. }));
    }
}
