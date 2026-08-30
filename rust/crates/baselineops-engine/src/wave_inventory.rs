//! Native read-only executor for software, patch, and Event Log inventory.

use baselineops_capabilities::{
    CapabilityDescriptor, CapabilityExecutor, CapabilityOutcome, CapabilityRequest,
    EmptyAuditParameters, EventLogQueryParameters, MissingPatchObservation, Operation, PatchFeed,
    evaluate_event_triage, evaluate_missing_patches, evaluate_software_inventory,
    validate_event_query, validate_patch_feed,
};
use baselineops_windows::{
    PlatformError, audit_event_log, audit_installed_kbs, audit_software_inventory,
};

/// Native Windows executor for capabilities 19, 20, and 26.
///
/// This executor remains `in_development` pending Windows inventory,
/// update-history, Event Log, and legacy-oracle evidence. It accepts no shell,
/// native tool, path, URL, export, or mutation parameter.
pub struct WaveInventoryWindowsExecutor;

impl CapabilityExecutor for WaveInventoryWindowsExecutor {
    fn execute(
        &self,
        descriptor: &'static CapabilityDescriptor,
        request: CapabilityRequest<'_>,
    ) -> CapabilityOutcome {
        if request.operation != Operation::Audit {
            return failed(descriptor, "inventory executor is read-only");
        }
        let result = match descriptor.id {
            "v3.software.inventory" => execute_software(request),
            "v3.patch.missing" => execute_patches(request),
            "v3.eventlog.fast-triage" => execute_eventlog(request),
            _ => Err(PlatformError::TrustFailure(
                "capability is not implemented by the inventory executor".into(),
            )),
        };
        match result {
            Ok(result) => CapabilityOutcome::Completed { result },
            Err(error) => failed(descriptor, &error.to_string()),
        }
    }
}

fn execute_software(request: CapabilityRequest<'_>) -> Result<serde_json::Value, PlatformError> {
    parse_empty(request.parameters, "software inventory")?;
    serialize(evaluate_software_inventory(audit_software_inventory()?))
}

fn execute_patches(request: CapabilityRequest<'_>) -> Result<serde_json::Value, PlatformError> {
    if request
        .parameters
        .as_object()
        .is_some_and(serde_json::Map::is_empty)
    {
        return serialize(evaluate_missing_patches(MissingPatchObservation {
            feed: baselineops_capabilities::Observation::Missing,
            installed_kbs: audit_installed_kbs()?,
        }));
    }
    let feed =
        serde_json::from_value::<PatchFeed>(request.parameters.clone()).map_err(|error| {
            PlatformError::TrustFailure(format!("invalid missing-patch feed: {error}"))
        })?;
    let feed = validate_patch_feed(feed).map_err(PlatformError::TrustFailure)?;
    serialize(evaluate_missing_patches(MissingPatchObservation {
        feed: baselineops_capabilities::Observation::Present(feed),
        installed_kbs: audit_installed_kbs()?,
    }))
}

fn execute_eventlog(request: CapabilityRequest<'_>) -> Result<serde_json::Value, PlatformError> {
    let parameters = if request
        .parameters
        .as_object()
        .is_some_and(serde_json::Map::is_empty)
    {
        EventLogQueryParameters {
            channel: "System".into(),
            xpath: "*".into(),
            max_records: 100,
            timeout_ms: 5_000,
            max_xml_bytes: 64 * 1024,
            max_message_bytes: 0,
        }
    } else {
        serde_json::from_value::<EventLogQueryParameters>(request.parameters.clone()).map_err(
            |error| PlatformError::TrustFailure(format!("invalid Event Log query: {error}")),
        )?
    };
    validate_event_query(&parameters).map_err(PlatformError::TrustFailure)?;
    serialize(evaluate_event_triage(audit_event_log(&parameters)?))
}

fn parse_empty(value: &serde_json::Value, label: &str) -> Result<(), PlatformError> {
    serde_json::from_value::<EmptyAuditParameters>(value.clone())
        .map(|_| ())
        .map_err(|error| {
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
    fn dangerous_or_malformed_parameters_are_rejected_before_windows_access() {
        let software = lookup("v3.software.inventory").expect("software descriptor");
        let outcome = WaveInventoryWindowsExecutor.execute(
            software,
            CapabilityRequest {
                operation: Operation::Audit,
                parameters: &serde_json::json!({ "command": "winget" }),
            },
        );
        assert!(matches!(outcome, CapabilityOutcome::Failed { .. }));
        let patch = lookup("v3.patch.missing").expect("patch descriptor");
        let outcome = WaveInventoryWindowsExecutor.execute(
            patch,
            CapabilityRequest {
                operation: Operation::Audit,
                parameters: &serde_json::json!({ "url": "https://example.invalid/feed.json" }),
            },
        );
        assert!(matches!(outcome, CapabilityOutcome::Failed { .. }));
        let events = lookup("v3.eventlog.fast-triage").expect("events descriptor");
        let outcome = WaveInventoryWindowsExecutor.execute(events, CapabilityRequest { operation: Operation::Audit, parameters: &serde_json::json!({ "channel": "Application", "xpath": "*", "max_records": 1, "timeout_ms": 1, "max_xml_bytes": 1, "max_message_bytes": 0, "export_path": "C:\\out.evtx" }) });
        assert!(matches!(outcome, CapabilityOutcome::Failed { .. }));
    }
}
