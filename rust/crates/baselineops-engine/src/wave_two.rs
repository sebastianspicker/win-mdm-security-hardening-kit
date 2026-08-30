//! Read-only registry-backed native capability execution.

use baselineops_capabilities::{
    CapabilityDescriptor, CapabilityExecutor, CapabilityOutcome, CapabilityRequest, DohObservation,
    NtlmPolicy, Operation, evaluate_doh, evaluate_ntlm,
};
use baselineops_windows::{
    PlatformError,
    registry::{RegistryLocation, RegistryRead, RegistryValue, RegistryValueName, read_hklm_value},
};

/// Native Windows executor for the first registry-backed read-only capabilities.
///
/// Registry maturity remains `in_development` until authoritative Windows VM
/// evidence is retained and compared with the legacy semantic oracle.
pub struct WaveTwoWindowsExecutor;

impl CapabilityExecutor for WaveTwoWindowsExecutor {
    fn execute(
        &self,
        descriptor: &'static CapabilityDescriptor,
        request: CapabilityRequest<'_>,
    ) -> CapabilityOutcome {
        if request.operation != Operation::Audit {
            return failed(descriptor, "Wave 2 registry executor is read-only");
        }
        let result = match descriptor.id {
            "v3.doh.audit" => execute_doh(request),
            "v3.ntlm.client" => execute_ntlm(request),
            _ => Err(PlatformError::TrustFailure(
                "capability is not implemented by the Wave 2 registry executor".into(),
            )),
        };
        match result {
            Ok(result) => CapabilityOutcome::Completed { result },
            Err(error) => failed(descriptor, &error.to_string()),
        }
    }
}

fn execute_doh(request: CapabilityRequest<'_>) -> Result<serde_json::Value, PlatformError> {
    if request
        .parameters
        .as_object()
        .is_none_or(|parameters| !parameters.is_empty())
    {
        return Err(PlatformError::TrustFailure(
            "DoH audit parameters must be an empty object".into(),
        ));
    }
    let observation = DohObservation {
        enable_auto_doh: read_optional_dword(
            RegistryLocation::DnsCacheParameters,
            RegistryValueName::EnableAutoDoh,
        )?,
        name_servers: read_optional_strings(
            RegistryLocation::DnsCacheParameters,
            RegistryValueName::DohNameServers,
        )?,
        bootstrap_addresses: read_optional_strings(
            RegistryLocation::DnsCacheParameters,
            RegistryValueName::ServerAddresses,
        )?,
        block_untrusted_doh: read_optional_dword(
            RegistryLocation::DnsCacheParameters,
            RegistryValueName::BlockUntrustedDoh,
        )?,
        server_query_failed: false,
    };
    serde_json::to_value(evaluate_doh(&observation))
        .map_err(|error| PlatformError::TrustFailure(error.to_string()))
}

fn execute_ntlm(request: CapabilityRequest<'_>) -> Result<serde_json::Value, PlatformError> {
    let policy: NtlmPolicy = serde_json::from_value(request.parameters.clone())
        .map_err(|error| PlatformError::TrustFailure(format!("invalid NTLM policy: {error}")))?;
    let level = read_optional_dword(
        RegistryLocation::LocalSecurityAuthority,
        RegistryValueName::LmCompatibilityLevel,
    )?;
    let audit = evaluate_ntlm(level, &policy)
        .map_err(|error| PlatformError::TrustFailure(format!("invalid NTLM policy: {error}")))?;
    serde_json::to_value(audit).map_err(|error| PlatformError::TrustFailure(error.to_string()))
}

fn read_optional_dword(
    location: RegistryLocation,
    name: RegistryValueName,
) -> Result<Option<u32>, PlatformError> {
    match read_hklm_value(location, name)? {
        RegistryRead::Missing => Ok(None),
        RegistryRead::Present(RegistryValue::Dword(value)) => Ok(Some(value)),
        RegistryRead::Present(_) => Err(PlatformError::TrustFailure(
            "registry value has an unexpected type".into(),
        )),
    }
}

fn read_optional_strings(
    location: RegistryLocation,
    name: RegistryValueName,
) -> Result<Vec<String>, PlatformError> {
    match read_hklm_value(location, name)? {
        RegistryRead::Missing => Ok(Vec::new()),
        RegistryRead::Present(RegistryValue::String(value)) => Ok(vec![value]),
        RegistryRead::Present(RegistryValue::MultiString(values)) => Ok(values),
        RegistryRead::Present(_) => Err(PlatformError::TrustFailure(
            "registry value has an unexpected type".into(),
        )),
    }
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
    fn executor_rejects_mutation_before_platform_access() {
        let descriptor = lookup("v3.doh.audit").expect("descriptor");
        let outcome = WaveTwoWindowsExecutor.execute(
            descriptor,
            CapabilityRequest {
                operation: Operation::Apply,
                parameters: &serde_json::json!({}),
            },
        );
        assert!(matches!(outcome, CapabilityOutcome::Failed { .. }));
    }

    #[test]
    fn doh_rejects_unknown_parameters_before_platform_access() {
        let descriptor = lookup("v3.doh.audit").expect("descriptor");
        let outcome = WaveTwoWindowsExecutor.execute(
            descriptor,
            CapabilityRequest {
                operation: Operation::Audit,
                parameters: &serde_json::json!({ "raw_command": "forbidden" }),
            },
        );
        assert!(matches!(outcome, CapabilityOutcome::Failed { .. }));
    }
}
