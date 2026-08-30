//! Read-only execution seam for certificate autoenrollment health capability 24.

use baselineops_capabilities::{
    CapabilityDescriptor, CapabilityExecutor, CapabilityOutcome, CapabilityRequest,
    CertHealthParameters, Operation, Unsupported, evaluate_cert_health,
};
use baselineops_windows::{PlatformError, audit_cert_health};
use std::time::{SystemTime, UNIX_EPOCH};

/// Read-only executor for fixed certificate policy and machine-store evidence.
///
/// It never starts enrollment, invokes a shell, deletes certificates, writes a
/// store, or exposes certificate/private-key bodies.
pub struct WaveCertHealthWindowsExecutor;

impl CapabilityExecutor for WaveCertHealthWindowsExecutor {
    fn execute(
        &self,
        descriptor: &'static CapabilityDescriptor,
        request: CapabilityRequest<'_>,
    ) -> CapabilityOutcome {
        if descriptor.id != "v3.cert.autoenrollment-health" {
            return failed(
                descriptor,
                "capability is not implemented by the certificate-health executor",
            );
        }
        if request.operation == Operation::Apply {
            return unsupported(Operation::Apply);
        }
        if request.operation != Operation::Audit {
            return unsupported(request.operation);
        }
        let parameters =
            match serde_json::from_value::<CertHealthParameters>(request.parameters.clone()) {
                Ok(value) => value,
                Err(error) => {
                    return failed(
                        descriptor,
                        &format!("invalid certificate-health parameters: {error}"),
                    );
                }
            };
        if let Err(error) = parameters.validate() {
            return failed(descriptor, error);
        }
        match current_unix_seconds()
            .and_then(|now| {
                audit_cert_health()
                    .map(|observation| evaluate_cert_health(observation, &parameters, now))
            })
            .and_then(serialize)
        {
            Ok(result) => CapabilityOutcome::Completed { result },
            Err(error) => failed(descriptor, &error.to_string()),
        }
    }
}

fn current_unix_seconds() -> Result<i64, PlatformError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PlatformError::TrustFailure("system clock predates the Unix epoch".into()))?
        .as_secs();
    i64::try_from(seconds).map_err(|_| {
        PlatformError::TrustFailure("system time exceeds supported timestamp range".into())
    })
}

fn unsupported(operation: Operation) -> CapabilityOutcome {
    CapabilityOutcome::Unsupported {
        reason: Unsupported::OperationUnavailable { operation },
    }
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
    fn apply_and_unknown_parameters_are_rejected_before_windows_access() {
        let descriptor = lookup("v3.cert.autoenrollment-health").expect("certificate descriptor");
        let apply = WaveCertHealthWindowsExecutor.execute(
            descriptor,
            CapabilityRequest {
                operation: Operation::Apply,
                parameters: &serde_json::json!({}),
            },
        );
        assert!(matches!(
            apply,
            CapabilityOutcome::Unsupported {
                reason: Unsupported::OperationUnavailable {
                    operation: Operation::Apply
                }
            }
        ));
        let unknown = WaveCertHealthWindowsExecutor.execute(
            descriptor,
            CapabilityRequest {
                operation: Operation::Audit,
                parameters: &serde_json::json!({ "command": "forbidden" }),
            },
        );
        assert!(matches!(unknown, CapabilityOutcome::Failed { .. }));
    }

    #[test]
    fn plan_is_truthfully_unsupported_by_the_audit_only_executor() {
        let descriptor = lookup("v3.cert.autoenrollment-health").expect("certificate descriptor");
        let plan = WaveCertHealthWindowsExecutor.execute(
            descriptor,
            CapabilityRequest {
                operation: Operation::Plan,
                parameters: &serde_json::json!({}),
            },
        );
        assert!(matches!(
            plan,
            CapabilityOutcome::Unsupported {
                reason: Unsupported::OperationUnavailable {
                    operation: Operation::Plan
                }
            }
        ));
    }
}
