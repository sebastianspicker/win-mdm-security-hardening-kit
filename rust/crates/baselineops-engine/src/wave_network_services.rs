//! Native read-only executor for network and service/process inventory.

use baselineops_capabilities::{
    CapabilityDescriptor, CapabilityExecutor, CapabilityOutcome, CapabilityRequest,
    EmptyAuditParameters, Operation, evaluate_network_inventory,
    evaluate_service_process_inventory,
};
use baselineops_windows::{
    PlatformError, audit_network_inventory, audit_service_process_inventory,
};

/// Native Windows executor for capabilities 29 and 30.
///
/// Both descriptors remain `in_development` until legacy-oracle comparison and
/// Windows VM evidence are retained. This executor accepts only `{}` and never
/// accepts a command, path, filter, export, or mutation parameter.
pub struct WaveNetworkServicesWindowsExecutor;

impl CapabilityExecutor for WaveNetworkServicesWindowsExecutor {
    fn execute(
        &self,
        descriptor: &'static CapabilityDescriptor,
        request: CapabilityRequest<'_>,
    ) -> CapabilityOutcome {
        if request.operation != Operation::Audit {
            return failed(descriptor, "network/services executor is read-only");
        }
        let result = match descriptor.id {
            "v3.network.configuration" => execute_network(request),
            "v3.service-process.inventory" => execute_services(request),
            _ => Err(PlatformError::TrustFailure(
                "capability is not implemented by the network/services executor".into(),
            )),
        };
        match result {
            Ok(result) => CapabilityOutcome::Completed { result },
            Err(error) => failed(descriptor, &error.to_string()),
        }
    }
}

fn execute_network(request: CapabilityRequest<'_>) -> Result<serde_json::Value, PlatformError> {
    parse_empty(request.parameters, "network")?;
    serde_json::to_value(evaluate_network_inventory(audit_network_inventory()?))
        .map_err(|error| PlatformError::TrustFailure(error.to_string()))
}

fn execute_services(request: CapabilityRequest<'_>) -> Result<serde_json::Value, PlatformError> {
    parse_empty(request.parameters, "service/process")?;
    serde_json::to_value(evaluate_service_process_inventory(
        audit_service_process_inventory()?,
    ))
    .map_err(|error| PlatformError::TrustFailure(error.to_string()))
}

fn parse_empty(value: &serde_json::Value, label: &str) -> Result<(), PlatformError> {
    serde_json::from_value::<EmptyAuditParameters>(value.clone())
        .map(|_| ())
        .map_err(|error| {
            PlatformError::TrustFailure(format!("invalid {label} audit parameters: {error}"))
        })
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
    fn parameterized_or_mutating_requests_are_rejected_before_windows_access() {
        let descriptor = lookup("v3.network.configuration").expect("network descriptor");
        let mutation = WaveNetworkServicesWindowsExecutor.execute(
            descriptor,
            CapabilityRequest {
                operation: Operation::Apply,
                parameters: &serde_json::json!({}),
            },
        );
        assert!(matches!(mutation, CapabilityOutcome::Failed { .. }));
        let raw_command = WaveNetworkServicesWindowsExecutor.execute(
            descriptor,
            CapabilityRequest {
                operation: Operation::Audit,
                parameters: &serde_json::json!({ "raw_command": "ipconfig" }),
            },
        );
        assert!(matches!(raw_command, CapabilityOutcome::Failed { .. }));
    }

    #[test]
    fn only_an_object_empty_parameters_fixture_is_accepted() {
        assert!(parse_empty(&serde_json::json!({}), "fixture").is_ok());
        assert!(parse_empty(&serde_json::Value::Null, "fixture").is_err());
        assert!(parse_empty(&serde_json::json!({ "path": "C:\\\\temp" }), "fixture").is_err());
    }
}
