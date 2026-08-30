//! Fixed registry acquisition for the bounded capability 42 subset.

use crate::PlatformError;
#[cfg(windows)]
use crate::policy_registry;
use baselineops_capabilities::ClientBaselineObservation;
#[cfg(windows)]
use baselineops_capabilities::{ClientBaselineField, Observation, PolicyValueSnapshot};
#[cfg(windows)]
use std::collections::BTreeMap;

#[cfg(windows)]
const DEVICE_GUARD_RUNTIME: &str = r"SYSTEM\CurrentControlSet\Control\DeviceGuard";
#[cfg(windows)]
const LSA_RUNTIME: &str = r"SYSTEM\CurrentControlSet\Control\Lsa";
#[cfg(windows)]
const DEVICE_GUARD_POLICY: &str = r"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard";
#[cfg(windows)]
const SCRIPT_BLOCK: &str = r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging";
#[cfg(windows)]
const MODULE_LOGGING: &str = r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging";
#[cfg(windows)]
const TRANSCRIPTION: &str = r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription";

/// Observe the fixed Device Guard, LSA, and PowerShell policy subset.
///
/// # Errors
///
/// Returns [`PlatformError::UnsupportedPlatform`] outside Windows.
pub fn audit_client_baseline() -> Result<ClientBaselineObservation, PlatformError> {
    #[cfg(not(windows))]
    {
        Err(PlatformError::UnsupportedPlatform)
    }
    #[cfg(windows)]
    {
        let mut values = BTreeMap::new();
        for (field, path, name) in FIELDS {
            values.insert(field, observed(policy_registry::read_dword(path, name)));
        }
        Ok(ClientBaselineObservation {
            values,
            device_guard_runtime: Observation::NotRun,
            firewall_profiles: Observation::NotRun,
        })
    }
}

#[cfg(windows)]
const FIELDS: [(ClientBaselineField, &str, &str); 11] = [
    (
        ClientBaselineField::RuntimeEnableVbs,
        DEVICE_GUARD_RUNTIME,
        "EnableVirtualizationBasedSecurity",
    ),
    (
        ClientBaselineField::RuntimePlatformSecurity,
        DEVICE_GUARD_RUNTIME,
        "RequirePlatformSecurityFeatures",
    ),
    (
        ClientBaselineField::RuntimeLsaCfgFlags,
        LSA_RUNTIME,
        "LsaCfgFlags",
    ),
    (
        ClientBaselineField::PolicyEnableVbs,
        DEVICE_GUARD_POLICY,
        "EnableVirtualizationBasedSecurity",
    ),
    (
        ClientBaselineField::PolicyPlatformSecurity,
        DEVICE_GUARD_POLICY,
        "RequirePlatformSecurityFeatures",
    ),
    (
        ClientBaselineField::PolicyLsaCfgFlags,
        DEVICE_GUARD_POLICY,
        "LsaCfgFlags",
    ),
    (ClientBaselineField::RunAsPpl, LSA_RUNTIME, "RunAsPPL"),
    (
        ClientBaselineField::ScriptBlockLogging,
        SCRIPT_BLOCK,
        "EnableScriptBlockLogging",
    ),
    (
        ClientBaselineField::ScriptBlockInvocationLogging,
        SCRIPT_BLOCK,
        "EnableScriptBlockInvocationLogging",
    ),
    (
        ClientBaselineField::ModuleLogging,
        MODULE_LOGGING,
        "EnableModuleLogging",
    ),
    (
        ClientBaselineField::Transcription,
        TRANSCRIPTION,
        "EnableTranscripting",
    ),
];

#[cfg(windows)]
fn observed(
    result: Result<PolicyValueSnapshot, PlatformError>,
) -> Observation<PolicyValueSnapshot> {
    match result {
        Ok(value) => Observation::Present(value),
        Err(PlatformError::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            Observation::AccessDenied
        }
        Err(_) => Observation::Unparsed,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn non_windows_acquisition_is_explicitly_unsupported() {
        #[cfg(not(windows))]
        assert!(matches!(
            super::audit_client_baseline(),
            Err(super::PlatformError::UnsupportedPlatform)
        ));
    }
}
