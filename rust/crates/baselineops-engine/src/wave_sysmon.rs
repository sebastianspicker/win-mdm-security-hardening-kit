//! Read-only native executor seam for Sysmon capabilities 16 and 17.
//!
//! This wave exposes bounded Audit and review-only Plan results. It never
//! invokes Sysmon, reads configuration XML, controls a service, changes an
//! event channel, or performs installer/updater/quarantine work.

use baselineops_capabilities::{
    CapabilityDescriptor, CapabilityExecutor, CapabilityOutcome, CapabilityRequest, Operation,
    SysmonPolicy, Unsupported, build_sysmon_read_only_plan, evaluate_sysmon,
};
use baselineops_windows::{PlatformError, audit_sysmon};

/// Native executor for the shared read-only foundation behind capabilities 16 and 17.
pub struct WaveSysmonWindowsExecutor;

impl CapabilityExecutor for WaveSysmonWindowsExecutor {
    fn execute(
        &self,
        descriptor: &'static CapabilityDescriptor,
        request: CapabilityRequest<'_>,
    ) -> CapabilityOutcome {
        if !matches!(descriptor.id, "v3.sysmon.config" | "v3.sysmon.rule-drift") {
            return failed(
                descriptor,
                "capability is not implemented by the Sysmon executor",
            );
        }
        match request.operation {
            Operation::Apply => CapabilityOutcome::Unsupported {
                reason: Unsupported::OperationUnavailable {
                    operation: Operation::Apply,
                },
            },
            Operation::Audit => execute_audit(request.parameters)
                .map_or_else(|error| failed(descriptor, &error.to_string()), completed),
            Operation::Plan => execute_plan(request.parameters)
                .map_or_else(|error| failed(descriptor, &error.to_string()), completed),
        }
    }
}

fn execute_audit(parameters: &serde_json::Value) -> Result<serde_json::Value, PlatformError> {
    let policy = parse_policy(parameters)?;
    serialize(evaluate_sysmon(
        audit_sysmon(policy.include_operational_events)?,
        &policy,
    ))
}

fn execute_plan(parameters: &serde_json::Value) -> Result<serde_json::Value, PlatformError> {
    let policy = parse_policy(parameters)?;
    let audit = evaluate_sysmon(audit_sysmon(policy.include_operational_events)?, &policy);
    serialize(build_sysmon_read_only_plan(audit))
}

fn parse_policy(parameters: &serde_json::Value) -> Result<SysmonPolicy, PlatformError> {
    serde_json::from_value(parameters.clone()).map_err(|error| {
        PlatformError::TrustFailure(format!("invalid Sysmon audit parameters: {error}"))
    })
}

fn serialize(value: impl serde::Serialize) -> Result<serde_json::Value, PlatformError> {
    serde_json::to_value(value).map_err(|error| {
        PlatformError::TrustFailure(format!("Sysmon serialization failed: {error}"))
    })
}

fn completed(result: serde_json::Value) -> CapabilityOutcome {
    CapabilityOutcome::Completed { result }
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
    fn raw_paths_urls_commands_names_and_apply_are_rejected_before_windows_access() {
        for id in ["v3.sysmon.config", "v3.sysmon.rule-drift"] {
            let descriptor = lookup(id).expect("Sysmon descriptor");
            for parameters in [
                serde_json::json!({"path": "C:\\config.xml"}),
                serde_json::json!({"url": "https://example.invalid/sysmon.xml"}),
                serde_json::json!({"command": "sysmon64.exe -c config.xml"}),
                serde_json::json!({"service_name": "other"}),
                serde_json::json!({"config_xml": "<Sysmon/>"}),
            ] {
                assert!(matches!(
                    WaveSysmonWindowsExecutor.execute(
                        descriptor,
                        CapabilityRequest {
                            operation: Operation::Audit,
                            parameters: &parameters,
                        },
                    ),
                    CapabilityOutcome::Failed { .. }
                ));
            }
            assert!(matches!(
                WaveSysmonWindowsExecutor.execute(
                    descriptor,
                    CapabilityRequest {
                        operation: Operation::Apply,
                        parameters: &serde_json::json!({}),
                    },
                ),
                CapabilityOutcome::Unsupported {
                    reason: Unsupported::OperationUnavailable {
                        operation: Operation::Apply
                    }
                }
            ));
        }
    }
}
