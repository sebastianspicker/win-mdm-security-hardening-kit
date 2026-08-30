//! Read-only audit and zero-mutation planning boundary for capability 07.

use baselineops_capabilities::{
    CapabilityDescriptor, CapabilityExecutor, CapabilityOutcome, CapabilityRequest, Operation,
    ScheduledTasksParameters, Unsupported, build_scheduled_tasks_read_only_plan,
    evaluate_scheduled_tasks,
};
use baselineops_windows::{PlatformError, audit_scheduled_tasks};

/// Native executor for the bounded Scheduled Tasks hygiene foundation.
///
/// It observes four exact legacy task paths through Task Scheduler COM. It
/// never accepts arbitrary task selection, uses no PowerShell or shell, and
/// never enables, disables, quarantines, exports, or otherwise changes tasks.
pub struct WaveScheduledTasksWindowsExecutor;

impl CapabilityExecutor for WaveScheduledTasksWindowsExecutor {
    fn execute(
        &self,
        descriptor: &'static CapabilityDescriptor,
        request: CapabilityRequest<'_>,
    ) -> CapabilityOutcome {
        if descriptor.id != "v3.scheduled-tasks.hygiene" {
            return failed(
                descriptor,
                "capability is not implemented by the scheduled-tasks executor",
            );
        }
        if request.operation == Operation::Apply {
            return CapabilityOutcome::Unsupported {
                reason: Unsupported::OperationUnavailable {
                    operation: Operation::Apply,
                },
            };
        }
        let result = match request.operation {
            Operation::Audit => audit(request),
            Operation::Plan => plan(request),
            Operation::Apply => unreachable!("Apply returned Unsupported above"),
        };
        result.map_or_else(
            |error| failed(descriptor, &error.to_string()),
            |result| CapabilityOutcome::Completed { result },
        )
    }
}

fn audit(request: CapabilityRequest<'_>) -> Result<serde_json::Value, PlatformError> {
    parse_parameters(request.parameters)?;
    serialize(evaluate_scheduled_tasks(audit_scheduled_tasks()?))
}

fn plan(request: CapabilityRequest<'_>) -> Result<serde_json::Value, PlatformError> {
    parse_parameters(request.parameters)?;
    serialize(build_scheduled_tasks_read_only_plan(
        audit_scheduled_tasks()?
    ))
}

fn parse_parameters(value: &serde_json::Value) -> Result<(), PlatformError> {
    serde_json::from_value::<ScheduledTasksParameters>(value.clone())
        .map(|_| ())
        .map_err(|error| {
            PlatformError::TrustFailure(format!("invalid scheduled-tasks parameters: {error}"))
        })
}

fn serialize(value: impl serde::Serialize) -> Result<serde_json::Value, PlatformError> {
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
    fn raw_apply_is_typed_unsupported_before_windows_access() {
        let descriptor = lookup("v3.scheduled-tasks.hygiene").expect("scheduled tasks descriptor");
        let outcome = WaveScheduledTasksWindowsExecutor.execute(
            descriptor,
            CapabilityRequest {
                operation: Operation::Apply,
                parameters: &serde_json::json!({}),
            },
        );
        assert!(matches!(
            outcome,
            CapabilityOutcome::Unsupported {
                reason: Unsupported::OperationUnavailable {
                    operation: Operation::Apply
                }
            }
        ));
    }

    #[test]
    fn task_selection_and_commands_are_rejected_before_windows_access() {
        for parameters in [
            serde_json::json!({ "task_path": "\\\\untrusted" }),
            serde_json::json!({ "command": "schtasks.exe" }),
            serde_json::json!({ "export_xml": true }),
            serde_json::json!({ "disable": true }),
        ] {
            assert!(parse_parameters(&parameters).is_err());
        }
    }
}
