//! Fixed, read-only SMB encryption acquisition for capability 22.
//!
//! This adapter reads three compile-time HKLM DWORD locations through the
//! bounded private registry reader. It exposes neither registry addressing nor
//! mutation, and it never invokes PowerShell, `cmd`, or a shell.

use crate::PlatformError;
#[cfg(windows)]
use crate::policy_registry;
use baselineops_capabilities::SmbEncryptionObservation;
#[cfg(windows)]
use baselineops_capabilities::{Observation, PolicyValueSnapshot};

/// Observe the fixed local SMB server and client encryption configuration.
///
/// # Errors
///
/// Returns [`PlatformError::UnsupportedPlatform`] outside Windows. On Windows,
/// absent, denied, and malformed values are retained as typed field evidence.
pub fn audit_smb_encryption() -> Result<SmbEncryptionObservation, PlatformError> {
    #[cfg(not(windows))]
    {
        Err(PlatformError::UnsupportedPlatform)
    }
    #[cfg(windows)]
    {
        Ok(SmbEncryptionObservation {
            server_encrypt_data: observed(policy_registry::read_dword(
                SERVER_PARAMETERS,
                "EncryptData",
            )),
            server_reject_unencrypted_access: observed(policy_registry::read_dword(
                SERVER_PARAMETERS,
                "RejectUnencryptedAccess",
            )),
            client_require_encryption: observed(policy_registry::read_dword(
                CLIENT_PARAMETERS,
                "RequireEncryption",
            )),
        })
    }
}

#[cfg(windows)]
const SERVER_PARAMETERS: &str = r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters";
#[cfg(windows)]
const CLIENT_PARAMETERS: &str = r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters";

#[cfg(windows)]
fn observed(result: Result<PolicyValueSnapshot, PlatformError>) -> Observation<bool> {
    match result {
        Ok(PolicyValueSnapshot::Dword(0)) => Observation::Present(false),
        Ok(PolicyValueSnapshot::Dword(1)) => Observation::Present(true),
        Ok(PolicyValueSnapshot::Missing) => Observation::Missing,
        Err(PlatformError::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            Observation::AccessDenied
        }
        Ok(PolicyValueSnapshot::Dword(_) | PolicyValueSnapshot::String(_)) | Err(_) => {
            Observation::Unparsed
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn non_windows_observation_is_explicitly_unsupported() {
        #[cfg(not(windows))]
        assert!(matches!(
            super::audit_smb_encryption(),
            Err(super::PlatformError::UnsupportedPlatform)
        ));
    }
}
