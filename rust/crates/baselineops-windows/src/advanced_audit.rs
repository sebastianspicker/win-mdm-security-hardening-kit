//! Protected, bounded `auditpol` acquisition for capability 33.

use crate::PlatformError;
use baselineops_capabilities::AdvancedAuditObservation;

/// Observe all Advanced Audit Policy subcategories through a fixed report command.
///
/// # Errors
///
/// Returns an error outside Windows or when the protected System32 executable
/// cannot be resolved. Process and parser failures become typed observations.
pub fn audit_advanced_policy() -> Result<AdvancedAuditObservation, PlatformError> {
    #[cfg(not(windows))]
    {
        Err(PlatformError::UnsupportedPlatform)
    }
    #[cfg(windows)]
    {
        platform::audit()
    }
}

#[cfg(windows)]
mod platform {
    use super::{AdvancedAuditObservation, PlatformError};
    use crate::{
        NativeArgumentRule, NativeEncoding, NativeExecutableTrust, NativeProcessPolicy,
        NativeProcessSpec, decode_native_output, run_native,
    };
    use baselineops_capabilities::{AuditSubcategoryObservation, Observation, parse_auditpol_csv};
    use std::{collections::BTreeMap, ffi::OsString, time::Duration};

    const TIMEOUT: Duration = Duration::from_secs(30);
    const OUTPUT_LIMIT: usize = 1024 * 1024;

    pub(super) fn audit() -> Result<AdvancedAuditObservation, PlatformError> {
        let executable = crate::trust::windows_system32_file("auditpol.exe")?;
        let working_directory = executable
            .parent()
            .expect("an API-resolved System32 executable has a parent")
            .to_path_buf();
        let args = ["/get", "/category:*", "/r"];
        let policy = NativeProcessPolicy {
            executable,
            executable_trust: NativeExecutableTrust::WindowsSystemPublisher,
            working_directory,
            argument_patterns: vec![
                args.iter()
                    .map(|arg| NativeArgumentRule::Exact((*arg).into()))
                    .collect(),
            ],
            environment: BTreeMap::<OsString, OsString>::new(),
            max_timeout: TIMEOUT,
            max_output_limit: OUTPUT_LIMIT,
        };
        let spec = NativeProcessSpec {
            args: args.iter().map(|arg| (*arg).into()).collect(),
            timeout: TIMEOUT,
            output_limit: OUTPUT_LIMIT,
        };
        let subcategories = match run_native(&policy, &spec) {
            Ok(result) if result.exit_code == 0 => decode_report(&result.stdout),
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
            Err(_) => Observation::Unparsed,
        };
        Ok(AdvancedAuditObservation { subcategories })
    }

    fn decode_report(bytes: &[u8]) -> Observation<Vec<AuditSubcategoryObservation>> {
        let encoding = if bytes.starts_with(&[0xff, 0xfe])
            || bytes.chunks_exact(2).take(32).any(|pair| pair[1] == 0)
        {
            NativeEncoding::Utf16Le
        } else {
            NativeEncoding::Utf8
        };
        decode_native_output(bytes, encoding)
            .map_or(Observation::Unparsed, |text| parse_auditpol_csv(&text))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn non_windows_acquisition_is_explicitly_unsupported() {
        #[cfg(not(windows))]
        assert!(matches!(
            super::audit_advanced_policy(),
            Err(super::PlatformError::UnsupportedPlatform)
        ));
    }
}
