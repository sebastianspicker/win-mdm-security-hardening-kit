//! Native read-only executor for TPM, `BitLocker`, and Secure Boot capability wave.

use baselineops_capabilities::{
    BitLockerPolicy, CapabilityDescriptor, CapabilityExecutor, CapabilityOutcome,
    CapabilityRequest, HardwareTpmPolicy, Operation, SecureBootPolicy, evaluate_bitlocker,
    evaluate_hardware_tpm, evaluate_secure_boot,
};
use baselineops_windows::{
    PlatformError, audit_bitlocker_os_volume, audit_hardware_tpm, audit_secure_boot,
};

/// Native Windows executor for capabilities 15, 23, and 46.
///
/// The descriptors remain `in_development` until native observations are
/// compared with legacy PowerShell on representative physical and virtual
/// hardware, including TPM and UEFI/Secure Boot permutations.
pub struct WaveHardwareTrustWindowsExecutor;

impl CapabilityExecutor for WaveHardwareTrustWindowsExecutor {
    fn execute(
        &self,
        descriptor: &'static CapabilityDescriptor,
        request: CapabilityRequest<'_>,
    ) -> CapabilityOutcome {
        if request.operation != Operation::Audit {
            return failed(descriptor, "hardware-trust executor is read-only");
        }
        let result = match descriptor.id {
            "v3.hardware.tpm-posture" => execute_hardware_tpm(request),
            "v3.bitlocker.operations" => execute_bitlocker(request),
            "v3.secure-boot.uefi" => execute_secure_boot(request),
            _ => Err(PlatformError::TrustFailure(
                "capability is not implemented by the hardware-trust executor".into(),
            )),
        };
        match result {
            Ok(result) => CapabilityOutcome::Completed { result },
            Err(error) => failed(descriptor, &error.to_string()),
        }
    }
}

fn execute_hardware_tpm(
    request: CapabilityRequest<'_>,
) -> Result<serde_json::Value, PlatformError> {
    let policy: HardwareTpmPolicy = parse(request.parameters, "hardware TPM audit")?;
    serialize(evaluate_hardware_tpm(audit_hardware_tpm()?, &policy))
}

fn execute_bitlocker(request: CapabilityRequest<'_>) -> Result<serde_json::Value, PlatformError> {
    let policy: BitLockerPolicy = parse(request.parameters, "BitLocker audit")?;
    serialize(evaluate_bitlocker(audit_bitlocker_os_volume()?, &policy))
}

fn execute_secure_boot(request: CapabilityRequest<'_>) -> Result<serde_json::Value, PlatformError> {
    let policy: SecureBootPolicy = parse(request.parameters, "Secure Boot audit")?;
    serialize(evaluate_secure_boot(audit_secure_boot()?, &policy))
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
    fn mutations_and_unknown_parameters_are_rejected_before_windows_access() {
        let hardware = lookup("v3.hardware.tpm-posture").expect("hardware descriptor");
        let outcome = WaveHardwareTrustWindowsExecutor.execute(
            hardware,
            CapabilityRequest {
                operation: Operation::Apply,
                parameters: &serde_json::json!({}),
            },
        );
        assert!(matches!(outcome, CapabilityOutcome::Failed { .. }));
        let secure_boot = lookup("v3.secure-boot.uefi").expect("Secure Boot descriptor");
        let outcome = WaveHardwareTrustWindowsExecutor.execute(
            secure_boot,
            CapabilityRequest {
                operation: Operation::Audit,
                parameters: &serde_json::json!({ "command": "powershell" }),
            },
        );
        assert!(matches!(outcome, CapabilityOutcome::Failed { .. }));
    }
}
