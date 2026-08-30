//! Fixed read-only AMSI registry acquisition for capability 50.

use crate::{PlatformError, policy_registry};
use baselineops_capabilities::{AmsiObservation, Observation, PolicyValueSnapshot};

const PROVIDERS: &str = r"SOFTWARE\Microsoft\AMSI\Providers";
const MACHINE_ENVIRONMENT: &str = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment";
const POWERSHELL_POLICY: &str = r"SOFTWARE\Policies\Microsoft\Windows\PowerShell";
const SCRIPT_BLOCK_LOGGING: &str =
    r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging";
const WSH_MACHINE: &str = r"SOFTWARE\Microsoft\Windows Script Host\Settings";
const WSH_USER: &str = r"SOFTWARE\Microsoft\Windows Script Host\Settings";

/// Observe fixed AMSI provider, bypass, logging, and script-host indicators.
///
/// # Errors
///
/// Returns an error outside Windows or when a fixed registry value has an
/// unexpected type that cannot be represented as trustworthy evidence.
pub fn audit_amsi() -> Result<AmsiObservation, PlatformError> {
    Ok(AmsiObservation {
        providers: policy_registry::subkeys_hklm(PROVIDERS, 64)?,
        bypass_environment: observed(policy_registry::read_string(
            MACHINE_ENVIRONMENT,
            "AMSI_BYPASS",
        )),
        disable_amsi_policy: observed(policy_registry::read_dword(
            POWERSHELL_POLICY,
            "DisableAMSI",
        )),
        script_block_logging: observed(policy_registry::read_dword(
            SCRIPT_BLOCK_LOGGING,
            "EnableScriptBlockLogging",
        )),
        wsh_machine_enabled: observed(policy_registry::read_dword(WSH_MACHINE, "Enabled")),
        wsh_user_enabled: observed(policy_registry::read_hkcu_dword(WSH_USER, "Enabled")),
    })
}

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
            super::audit_amsi(),
            Err(super::PlatformError::UnsupportedPlatform)
        ));
    }
}
