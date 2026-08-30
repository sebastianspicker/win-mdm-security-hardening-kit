//! Native read-only executor for storage reliability and backup readiness.

use baselineops_capabilities::{
    BackupReadinessPolicy, CapabilityDescriptor, CapabilityExecutor, CapabilityOutcome,
    CapabilityRequest, Operation, StorageReliabilityPolicy, evaluate_backup_readiness,
    evaluate_storage_reliability,
};
use baselineops_windows::{PlatformError, audit_backup_readiness, audit_storage_reliability};

/// Native Windows executor for capabilities 35 and 36.
///
/// Both descriptors remain `in_development` until retained comparison against
/// the legacy scripts and Windows VM evidence cover real Storage providers,
/// VSS writer states, and File History configurations.
pub struct WaveStorageBackupWindowsExecutor;

impl CapabilityExecutor for WaveStorageBackupWindowsExecutor {
    fn execute(
        &self,
        descriptor: &'static CapabilityDescriptor,
        request: CapabilityRequest<'_>,
    ) -> CapabilityOutcome {
        if request.operation != Operation::Audit {
            return failed(descriptor, "storage/backup executor is read-only");
        }
        let result = match descriptor.id {
            "v3.storage.reliability" => execute_storage(request),
            "v3.backup.readiness" => execute_backup(request),
            _ => Err(PlatformError::TrustFailure(
                "capability is not implemented by the storage/backup executor".into(),
            )),
        };
        result.map_or_else(
            |error| failed(descriptor, &error.to_string()),
            |result| CapabilityOutcome::Completed { result },
        )
    }
}

fn execute_storage(request: CapabilityRequest<'_>) -> Result<serde_json::Value, PlatformError> {
    let policy: StorageReliabilityPolicy = parse(request.parameters, "storage-reliability")?;
    policy
        .validate()
        .map_err(|error| PlatformError::TrustFailure(error.into()))?;
    serialize(evaluate_storage_reliability(
        audit_storage_reliability()?,
        &policy,
    ))
}

fn execute_backup(request: CapabilityRequest<'_>) -> Result<serde_json::Value, PlatformError> {
    let policy: BackupReadinessPolicy = parse(request.parameters, "backup-readiness")?;
    policy
        .validate()
        .map_err(|error| PlatformError::TrustFailure(error.into()))?;
    serialize(evaluate_backup_readiness(
        audit_backup_readiness()?,
        &policy,
    ))
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
        let storage = lookup("v3.storage.reliability").expect("storage descriptor");
        let mutation = WaveStorageBackupWindowsExecutor.execute(
            storage,
            CapabilityRequest {
                operation: Operation::Apply,
                parameters: &serde_json::json!({}),
            },
        );
        assert!(matches!(mutation, CapabilityOutcome::Failed { .. }));
        let backup = lookup("v3.backup.readiness").expect("backup descriptor");
        let unknown = WaveStorageBackupWindowsExecutor.execute(
            backup,
            CapabilityRequest {
                operation: Operation::Audit,
                parameters: &serde_json::json!({ "command": "vssadmin" }),
            },
        );
        assert!(matches!(unknown, CapabilityOutcome::Failed { .. }));
    }
}
