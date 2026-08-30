//! Read-only Audit/Plan executor for bounded SMB encryption capability 22.

use baselineops_capabilities::{
    CapabilityDescriptor, CapabilityExecutor, CapabilityOutcome, CapabilityRequest, Operation,
    SmbEncryptionPolicy, Unsupported, build_smb_encryption_plan, evaluate_smb_encryption,
};
use baselineops_windows::{PlatformError, audit_smb_encryption};

/// Native executor seam for the fixed local SMB encryption observation subset.
///
/// It does not enumerate shares, contact remote hosts, execute commands, or
/// apply configuration. Raw capability Apply remains typed unsupported.
pub struct WaveSmbEncryptionWindowsExecutor;

impl CapabilityExecutor for WaveSmbEncryptionWindowsExecutor {
    fn execute(
        &self,
        descriptor: &'static CapabilityDescriptor,
        request: CapabilityRequest<'_>,
    ) -> CapabilityOutcome {
        if descriptor.id == "v3.smb.encryption" && request.operation == Operation::Apply {
            return CapabilityOutcome::Unsupported {
                reason: Unsupported::OperationUnavailable {
                    operation: Operation::Apply,
                },
            };
        }
        let result = match (descriptor.id, request.operation) {
            ("v3.smb.encryption", Operation::Audit) => audit(request),
            ("v3.smb.encryption", Operation::Plan) => plan(request),
            _ => Err(PlatformError::TrustFailure(
                "capability is not implemented by the SMB encryption executor".into(),
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

fn parameters(value: &serde_json::Value) -> Result<SmbEncryptionPolicy, PlatformError> {
    serde_json::from_value(value.clone()).map_err(|error| {
        PlatformError::TrustFailure(format!("invalid SMB encryption parameters: {error}"))
    })
}

fn audit(request: CapabilityRequest<'_>) -> Result<serde_json::Value, PlatformError> {
    let policy = parameters(request.parameters)?;
    serialize(evaluate_smb_encryption(audit_smb_encryption()?, &policy))
}

fn plan(request: CapabilityRequest<'_>) -> Result<serde_json::Value, PlatformError> {
    let policy = parameters(request.parameters)?;
    serialize(
        build_smb_encryption_plan(audit_smb_encryption()?, &policy)
            .map_err(PlatformError::TrustFailure)?,
    )
}

fn serialize(value: impl serde::Serialize) -> Result<serde_json::Value, PlatformError> {
    serde_json::to_value(value).map_err(|error| {
        PlatformError::TrustFailure(format!("SMB encryption serialization failed: {error}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use baselineops_capabilities::lookup;

    #[test]
    fn raw_apply_is_typed_unsupported_before_windows_access() {
        let descriptor = lookup("v3.smb.encryption").expect("descriptor");
        assert!(matches!(
            WaveSmbEncryptionWindowsExecutor.execute(
                descriptor,
                CapabilityRequest {
                    operation: Operation::Apply,
                    parameters: &serde_json::json!({"share_name":"Finance"}),
                },
            ),
            CapabilityOutcome::Unsupported {
                reason: Unsupported::OperationUnavailable {
                    operation: Operation::Apply
                }
            }
        ));
    }

    #[test]
    fn dynamic_legacy_inputs_reject_before_windows_access() {
        let descriptor = lookup("v3.smb.encryption").expect("descriptor");
        for parameters in [
            serde_json::json!({"share_name":"Finance"}),
            serde_json::json!({"host":"server.example"}),
            serde_json::json!({"registry_path":"HKLM\\anything"}),
            serde_json::json!({"command":"Set-SmbServerConfiguration"}),
        ] {
            assert!(matches!(
                WaveSmbEncryptionWindowsExecutor.execute(
                    descriptor,
                    CapabilityRequest {
                        operation: Operation::Audit,
                        parameters: &parameters,
                    },
                ),
                CapabilityOutcome::Failed { .. }
            ));
        }
    }
}
