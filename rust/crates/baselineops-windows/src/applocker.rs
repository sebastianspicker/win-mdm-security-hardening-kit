//! Fixed read-only `AppLocker` registry and service acquisition for capability 51.

use crate::{KnownService, PlatformError, observe_service, policy_registry};
use baselineops_capabilities::{
    AppLockerCollection, AppLockerCollectionObservation, AppLockerObservation, Observation,
    PolicyValueSnapshot,
};
use std::collections::BTreeMap;

const ROOT: &str = r"SOFTWARE\Policies\Microsoft\Windows\SrpV2";
const COLLECTIONS: [(AppLockerCollection, &str); 5] = [
    (
        AppLockerCollection::Exe,
        r"SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe",
    ),
    (
        AppLockerCollection::Msi,
        r"SOFTWARE\Policies\Microsoft\Windows\SrpV2\Msi",
    ),
    (
        AppLockerCollection::Script,
        r"SOFTWARE\Policies\Microsoft\Windows\SrpV2\Script",
    ),
    (
        AppLockerCollection::Dll,
        r"SOFTWARE\Policies\Microsoft\Windows\SrpV2\Dll",
    ),
    (
        AppLockerCollection::Appx,
        r"SOFTWARE\Policies\Microsoft\Windows\SrpV2\Appx",
    ),
];

/// Observe the five fixed `AppLocker` collections and Application Identity service.
///
/// # Errors
///
/// Returns an error outside Windows or when a fixed registry access cannot be
/// represented as a typed incomplete observation.
pub fn audit_applocker() -> Result<AppLockerObservation, PlatformError> {
    let root = policy_registry::subkeys_hklm(ROOT, 64)?;
    let configured = match root {
        Observation::Present(_) => Observation::Present(true),
        Observation::Missing => Observation::Present(false),
        Observation::AccessDenied => Observation::AccessDenied,
        Observation::Truncated => Observation::Truncated,
        Observation::TimedOut
        | Observation::Failed { .. }
        | Observation::NotRun
        | Observation::Unparsed => Observation::Unparsed,
    };
    let mut collections = BTreeMap::new();
    for (collection, path) in COLLECTIONS {
        collections.insert(
            collection,
            AppLockerCollectionObservation {
                enforcement_mode: dword(policy_registry::read_dword(path, "EnforcementMode")),
                rule_count: rule_count(policy_registry::subkeys_hklm(path, 4096)),
            },
        );
    }
    Ok(AppLockerObservation {
        configured,
        application_identity: observe_service(KnownService::ApplicationIdentity)?,
        collections,
    })
}

fn dword(result: Result<PolicyValueSnapshot, PlatformError>) -> Observation<u32> {
    match result {
        Ok(PolicyValueSnapshot::Dword(value)) => Observation::Present(value),
        Ok(PolicyValueSnapshot::Missing) => Observation::Missing,
        Err(PlatformError::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            Observation::AccessDenied
        }
        Ok(PolicyValueSnapshot::String(_)) | Err(_) => Observation::Unparsed,
    }
}

fn rule_count(result: Result<Observation<Vec<String>>, PlatformError>) -> Observation<u32> {
    match result {
        Ok(Observation::Present(values)) => {
            u32::try_from(values.len()).map_or(Observation::Truncated, Observation::Present)
        }
        Ok(Observation::Missing) => Observation::Present(0),
        Ok(Observation::AccessDenied) => Observation::AccessDenied,
        Ok(Observation::Truncated) => Observation::Truncated,
        Ok(_) | Err(_) => Observation::Unparsed,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn non_windows_acquisition_is_explicitly_unsupported() {
        #[cfg(not(windows))]
        assert!(matches!(
            super::audit_applocker(),
            Err(super::PlatformError::UnsupportedPlatform)
        ));
    }
}
