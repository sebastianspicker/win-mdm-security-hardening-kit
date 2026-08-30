//! Fixed registry acquisition shared by capabilities 13, 39, and 40.

use crate::PlatformError;
use baselineops_capabilities::BootSecurityObservation;

/// Observe fixed LSASS, Device Guard, HVCI, and blocklist registry values.
///
/// # Errors
///
/// Returns an error outside Windows. Fixed value failures are represented as
/// typed incomplete observations.
pub fn audit_boot_security() -> Result<BootSecurityObservation, PlatformError> {
    #[cfg(not(windows))]
    {
        Err(PlatformError::UnsupportedPlatform)
    }
    #[cfg(windows)]
    {
        Ok(platform::audit())
    }
}

#[cfg(windows)]
mod platform {
    use super::{BootSecurityObservation, PlatformError};
    use crate::policy_registry;
    use baselineops_capabilities::{BootSecurityField, Observation, PolicyValueSnapshot};
    use std::collections::BTreeMap;

    const LSA: &str = r"SYSTEM\CurrentControlSet\Control\Lsa";
    const DEVICE_GUARD: &str = r"SYSTEM\CurrentControlSet\Control\DeviceGuard";
    const HVCI: &str =
        r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity";
    const CI_CONFIG: &str = r"SYSTEM\CurrentControlSet\Control\CI\Config";

    pub(super) fn audit() -> BootSecurityObservation {
        let fields = [
            (BootSecurityField::RunAsPpl, LSA, "RunAsPPL"),
            (BootSecurityField::RunAsPplBoot, LSA, "RunAsPPLBoot"),
            (BootSecurityField::LsaCfgFlags, LSA, "LsaCfgFlags"),
            (
                BootSecurityField::EnableVbs,
                DEVICE_GUARD,
                "EnableVirtualizationBasedSecurity",
            ),
            (
                BootSecurityField::PlatformSecurity,
                DEVICE_GUARD,
                "RequirePlatformSecurityFeatures",
            ),
            (BootSecurityField::HvciEnabled, HVCI, "Enabled"),
            (
                BootSecurityField::VulnerableDriverBlocklist,
                CI_CONFIG,
                "VulnerableDriverBlocklistEnable",
            ),
        ];
        let values = fields
            .into_iter()
            .map(|(field, path, name)| (field, observed(policy_registry::read_dword(path, name))))
            .collect::<BTreeMap<_, _>>();
        BootSecurityObservation {
            values,
            device_guard_runtime: Observation::NotRun,
        }
    }

    fn observed(
        result: Result<PolicyValueSnapshot, PlatformError>,
    ) -> Observation<PolicyValueSnapshot> {
        match result {
            Ok(value) => Observation::Present(value),
            Err(PlatformError::Io(error))
                if error.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                Observation::AccessDenied
            }
            Err(_) => Observation::Unparsed,
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn non_windows_acquisition_is_explicitly_unsupported() {
        #[cfg(not(windows))]
        assert!(matches!(
            super::audit_boot_security(),
            Err(super::PlatformError::UnsupportedPlatform)
        ));
    }
}
