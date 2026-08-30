//! Typed observation, planning, and guarded mutation for capability 31.

use baselineops_capabilities::{
    CapabilityDescriptor, CapabilityExecutor, CapabilityOutcome, CapabilityRequest, Operation,
    PowerShellLoggingParameters, build_powershell_logging_plan,
    resolve_powershell_logging_desired_state,
};
use baselineops_windows::{PlatformError, observe_powershell_logging};

/// Native Windows executor for the PowerShell logging policy capability.
///
/// This remains `in_development` until Windows VM and legacy-oracle evidence
/// verifies observation and mutation semantics.
pub struct WavePowerShellLoggingWindowsExecutor;

impl CapabilityExecutor for WavePowerShellLoggingWindowsExecutor {
    fn execute(
        &self,
        descriptor: &'static CapabilityDescriptor,
        request: CapabilityRequest<'_>,
    ) -> CapabilityOutcome {
        let result = match descriptor.id {
            "v3.powershell.logging" => execute(request),
            _ => Err(PlatformError::TrustFailure(
                "capability is not implemented by the PowerShell logging executor".into(),
            )),
        };
        match result {
            Ok(result) => CapabilityOutcome::Completed { result },
            Err(error) => CapabilityOutcome::Failed {
                capability_id: descriptor.id.into(),
                message: error.to_string(),
            },
        }
    }
}

fn execute(request: CapabilityRequest<'_>) -> Result<serde_json::Value, PlatformError> {
    let parameters: PowerShellLoggingParameters =
        serde_json::from_value(request.parameters.clone()).map_err(|error| {
            PlatformError::TrustFailure(format!("invalid PowerShell logging parameters: {error}"))
        })?;
    match request.operation {
        Operation::Audit => to_json(observe_powershell_logging(parameters.include_hkcu)?),
        Operation::Plan => {
            let desired = resolve_powershell_logging_desired_state(&parameters)
                .map_err(PlatformError::TrustFailure)?;
            let observation = observe_powershell_logging(parameters.include_hkcu)?;
            let plan = build_powershell_logging_plan(observation, desired)
                .map_err(PlatformError::TrustFailure)?;
            to_json(plan)
        }
        Operation::Apply => {
            let _ = parameters;
            Err(PlatformError::TrustFailure(
                "PowerShell logging Apply requires a verified-plan executor and is not reachable through raw capability requests".into(),
            ))
        }
    }
}

fn to_json(value: impl serde::Serialize) -> Result<serde_json::Value, PlatformError> {
    serde_json::to_value(value).map_err(|error| {
        PlatformError::TrustFailure(format!("PowerShell logging serialization failed: {error}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use baselineops_capabilities::lookup;

    #[test]
    fn unknown_and_raw_parameters_are_rejected_before_windows_access() {
        let descriptor = lookup("v3.powershell.logging").expect("PowerShell logging descriptor");
        for parameters in [
            serde_json::json!({ "raw_path": "HKLM:\\anything" }),
            serde_json::json!({ "raw_command": "Set-ItemProperty" }),
            serde_json::json!({ "config": { "unexpected": true } }),
        ] {
            let outcome = WavePowerShellLoggingWindowsExecutor.execute(
                descriptor,
                CapabilityRequest {
                    operation: Operation::Audit,
                    parameters: &parameters,
                },
            );
            assert!(matches!(outcome, CapabilityOutcome::Failed { .. }));
        }
    }

    #[test]
    fn raw_apply_is_rejected_without_reaching_registry_mutation() {
        let descriptor = lookup("v3.powershell.logging").expect("PowerShell logging descriptor");
        let outcome = WavePowerShellLoggingWindowsExecutor.execute(
            descriptor,
            CapabilityRequest {
                operation: Operation::Apply,
                parameters: &serde_json::json!({}),
            },
        );
        assert!(matches!(outcome, CapabilityOutcome::Failed { .. }));
    }
}
