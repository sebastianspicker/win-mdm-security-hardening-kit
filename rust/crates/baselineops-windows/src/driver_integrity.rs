//! Fixed driver-signing and HVCI acquisition for capability 49.

use crate::PlatformError;
use baselineops_capabilities::DriverIntegrityObservation;

/// Observe exact current-loader BCD flags and fixed HVCI registry intent.
///
/// Runtime Device Guard evidence remains `NotRun`; registry intent is never
/// promoted into a runtime-health claim.
///
/// # Errors
///
/// Returns [`PlatformError::UnsupportedPlatform`] outside Windows.
pub fn audit_driver_integrity() -> Result<DriverIntegrityObservation, PlatformError> {
    #[cfg(windows)]
    {
        Ok(platform::audit())
    }
    #[cfg(not(windows))]
    {
        Err(PlatformError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
mod platform {
    use crate::{
        NativeArgumentRule, NativeEncoding, NativeExecutableTrust, NativeProcessPolicy,
        NativeProcessSpec, PlatformError, decode_native_output, policy_registry, run_native,
    };
    use baselineops_capabilities::{
        DriverIntegrityObservation, Observation, PolicyValueSnapshot, parse_bcd_integrity,
    };
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::time::Duration;

    const HVCI: &str =
        r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity";
    const TIMEOUT: Duration = Duration::from_secs(30);
    const OUTPUT_LIMIT: usize = 256 * 1024;

    pub(super) fn audit() -> DriverIntegrityObservation {
        DriverIntegrityObservation {
            boot_flags: boot_flags(),
            hvci_enabled: dword(policy_registry::read_dword(HVCI, "Enabled")),
            device_guard_runtime: Observation::NotRun,
        }
    }

    fn boot_flags() -> Observation<baselineops_capabilities::BootIntegrityFlags> {
        let Ok(executable) = crate::trust::windows_system32_file("bcdedit.exe") else {
            return Observation::Unparsed;
        };
        let working_directory = executable
            .parent()
            .expect("an API-resolved System32 executable has a parent")
            .to_path_buf();
        let policy = NativeProcessPolicy {
            executable,
            executable_trust: NativeExecutableTrust::WindowsSystemPublisher,
            working_directory,
            argument_patterns: vec![vec![
                NativeArgumentRule::Exact("/enum".into()),
                NativeArgumentRule::Exact("{current}".into()),
            ]],
            environment: BTreeMap::<OsString, OsString>::new(),
            max_timeout: TIMEOUT,
            max_output_limit: OUTPUT_LIMIT,
        };
        match run_native(
            &policy,
            &NativeProcessSpec {
                args: vec!["/enum".into(), "{current}".into()],
                timeout: TIMEOUT,
                output_limit: OUTPUT_LIMIT,
            },
        ) {
            Ok(result) if result.exit_code == 0 => {
                decode_native_output(&result.stdout, NativeEncoding::Utf16Le)
                    .map_or(Observation::Unparsed, |text| parse_bcd_integrity(&text))
            }
            Ok(result) => Observation::Failed {
                exit_code: result.exit_code,
            },
            Err(PlatformError::ProcessTimeout { .. }) => Observation::TimedOut,
            Err(PlatformError::OutputTooLarge { .. }) => Observation::Truncated,
            Err(PlatformError::Io(error))
                if error.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                Observation::AccessDenied
            }
            Err(PlatformError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                Observation::Missing
            }
            Err(_) => Observation::Unparsed,
        }
    }

    fn dword(result: Result<PolicyValueSnapshot, PlatformError>) -> Observation<u32> {
        match result {
            Ok(PolicyValueSnapshot::Dword(value)) => Observation::Present(value),
            Ok(PolicyValueSnapshot::Missing) => Observation::Missing,
            Err(PlatformError::Io(error))
                if error.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                Observation::AccessDenied
            }
            Ok(PolicyValueSnapshot::String(_)) | Err(_) => Observation::Unparsed,
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn non_windows_acquisition_is_explicitly_unsupported() {
        #[cfg(not(windows))]
        assert!(matches!(
            super::audit_driver_integrity(),
            Err(super::PlatformError::UnsupportedPlatform)
        ));
    }
}
