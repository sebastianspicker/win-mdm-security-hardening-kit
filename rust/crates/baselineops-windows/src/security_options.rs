//! Fixed HKLM registry acquisition for Security Options capability 38.
//!
//! Paths and value names are compile-time constants. This adapter exposes no
//! raw registry API and no mutation operation.

use crate::PlatformError;
#[cfg(windows)]
use crate::policy_registry;
use baselineops_capabilities::SecurityOptionsObservation;
#[cfg(windows)]
use baselineops_capabilities::{PolicyValueSnapshot, SecurityOptionEvidence, SecurityOptionsField};
#[cfg(windows)]
use std::collections::BTreeMap;

/// Observe the finite v3 Security Options DWORD subset from HKLM only.
///
/// # Errors
///
/// Returns [`PlatformError::UnsupportedPlatform`] outside Windows. Individual
/// Windows registry failures remain typed evidence so one blocked field does
/// not erase trustworthy observations from the remaining fixed fields.
pub fn observe_security_options() -> Result<SecurityOptionsObservation, PlatformError> {
    #[cfg(not(windows))]
    {
        Err(PlatformError::UnsupportedPlatform)
    }
    #[cfg(windows)]
    {
        let values = FIELDS
            .into_iter()
            .map(|(field, path, name)| (field, observed(policy_registry::read_dword(path, name))))
            .collect::<BTreeMap<_, _>>();
        Ok(SecurityOptionsObservation { values })
    }
}

#[cfg(windows)]
fn observed(result: Result<PolicyValueSnapshot, PlatformError>) -> SecurityOptionEvidence {
    match result {
        Ok(PolicyValueSnapshot::Dword(value)) => SecurityOptionEvidence::Present(value),
        Ok(PolicyValueSnapshot::Missing) => SecurityOptionEvidence::Missing,
        Err(PlatformError::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            SecurityOptionEvidence::AccessDenied
        }
        Ok(PolicyValueSnapshot::String(_)) | Err(_) => SecurityOptionEvidence::Error,
    }
}

#[cfg(windows)]
const LSA: &str = r"SYSTEM\CurrentControlSet\Control\Lsa";
#[cfg(windows)]
const SYSTEM_POLICIES: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
#[cfg(windows)]
const FIELDS: [(SecurityOptionsField, &str, &str); 6] = [
    (
        SecurityOptionsField::EnableLua,
        SYSTEM_POLICIES,
        "EnableLUA",
    ),
    (
        SecurityOptionsField::LmCompatibilityLevel,
        LSA,
        "LmCompatibilityLevel",
    ),
    (SecurityOptionsField::NoLmHash, LSA, "NoLMHash"),
    (
        SecurityOptionsField::RestrictAnonymous,
        LSA,
        "RestrictAnonymous",
    ),
    (
        SecurityOptionsField::RestrictAnonymousSam,
        LSA,
        "RestrictAnonymousSAM",
    ),
    (
        SecurityOptionsField::LimitBlankPasswordUse,
        LSA,
        "LimitBlankPasswordUse",
    ),
];

#[cfg(test)]
mod tests {
    #[test]
    fn non_windows_observation_is_explicitly_unsupported() {
        #[cfg(not(windows))]
        assert!(matches!(
            super::observe_security_options(),
            Err(super::PlatformError::UnsupportedPlatform)
        ));
    }
}
