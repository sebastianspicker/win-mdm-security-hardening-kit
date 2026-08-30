//! Read-only Windows Event Forwarding client acquisition for capability 45.

use crate::{
    KnownService, NativeArgumentRule, NativeEncoding, NativeExecutableTrust, NativeProcessPolicy,
    NativeProcessSpec, PlatformError, decode_native_output, observe_service, run_native,
};
use baselineops_capabilities::{Observation, WefReadinessObservation, parse_wecutil_qc};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(30);
const OUTPUT_LIMIT: usize = 256 * 1024;

/// Acquire fixed WEF client indicators without configuring forwarding.
///
/// The optional `wecutil qc /q` invocation is token-allowlisted and is kept
/// indicator-only because it is principally collector-side output.
///
/// # Errors
///
/// Returns an error for unsupported hosts or registry failures that cannot be
/// represented as missing or access-denied observations.
pub fn audit_wef_readiness(
    include_wecutil_check: bool,
) -> Result<WefReadinessObservation, PlatformError> {
    Ok(WefReadinessObservation {
        winrm: observe_service(KnownService::WinRm)?,
        subscription_managers: platform::subscription_managers()?,
        wecutil_qc: if include_wecutil_check {
            wecutil().map_or_else(command_error, |text| {
                Observation::Present(parse_wecutil_qc(&text))
            })
        } else {
            Observation::NotRun
        },
    })
}

fn wecutil() -> Result<String, PlatformError> {
    let executable = crate::trust::windows_system32_file("wecutil.exe")?;
    let working_directory = executable
        .parent()
        .expect("an API-resolved System32 executable has a parent")
        .to_path_buf();
    let policy = NativeProcessPolicy {
        executable,
        executable_trust: NativeExecutableTrust::WindowsSystemPublisher,
        working_directory,
        argument_patterns: vec![vec![
            NativeArgumentRule::Exact("qc".into()),
            NativeArgumentRule::Exact("/q".into()),
        ]],
        environment: BTreeMap::<OsString, OsString>::new(),
        max_timeout: TIMEOUT,
        max_output_limit: OUTPUT_LIMIT,
    };
    let result = run_native(
        &policy,
        &NativeProcessSpec {
            args: vec!["qc".into(), "/q".into()],
            timeout: TIMEOUT,
            output_limit: OUTPUT_LIMIT,
        },
    )?;
    if result.exit_code != 0 {
        return Err(PlatformError::TrustFailure(format!(
            "wecutil qc /q exited with {}",
            result.exit_code
        )));
    }
    decode_native_output(&result.stdout, NativeEncoding::Utf8)
}

fn command_error(error: PlatformError) -> Observation<baselineops_capabilities::WecutilQc> {
    match error {
        PlatformError::ProcessTimeout { .. } => Observation::TimedOut,
        PlatformError::OutputTooLarge { .. } => Observation::Truncated,
        PlatformError::Io(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Observation::Missing
        }
        PlatformError::Io(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            Observation::AccessDenied
        }
        PlatformError::TrustFailure(message)
            if message.starts_with("wecutil qc /q exited with ") =>
        {
            let exit_code = message
                .rsplit_once(' ')
                .and_then(|(_, code)| code.parse().ok())
                .unwrap_or(-1);
            Observation::Failed { exit_code }
        }
        _ => Observation::Unparsed,
    }
}

#[cfg(not(windows))]
mod platform {
    use super::{Observation, PlatformError};

    pub(super) fn subscription_managers() -> Result<Observation<Vec<String>>, PlatformError> {
        Err(PlatformError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
mod platform {
    #![allow(unsafe_code, unsafe_op_in_unsafe_fn)]

    use super::{Observation, PlatformError};
    use windows::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, WIN32_ERROR,
    };
    use windows::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_MULTI_SZ, REG_SZ, REG_VALUE_TYPE, RegCloseKey,
        RegEnumValueW, RegOpenKeyExW,
    };
    use windows::core::{PCWSTR, PWSTR};

    const PATH: &str =
        r"SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager";
    const MAX_VALUES: u32 = 128;
    const MAX_VALUE_BYTES: u32 = 64 * 1024;

    pub(super) fn subscription_managers() -> Result<Observation<Vec<String>>, PlatformError> {
        match unsafe { subscription_managers_inner() } {
            Err(PlatformError::Io(error))
                if error.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                Ok(Observation::AccessDenied)
            }
            other => other,
        }
    }

    unsafe fn subscription_managers_inner() -> Result<Observation<Vec<String>>, PlatformError> {
        unsafe {
            let path = wide(PATH);
            let mut raw = HKEY::default();
            let status = RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(path.as_ptr()),
                None,
                KEY_READ,
                &raw mut raw,
            );
            if status == ERROR_FILE_NOT_FOUND {
                return Ok(Observation::Missing);
            }
            if status == ERROR_ACCESS_DENIED {
                return Ok(Observation::AccessDenied);
            }
            check(status)?;
            let key = OwnedKey(raw);
            let mut values = Vec::new();
            for index in 0..MAX_VALUES {
                match read_value(&key, index)? {
                    Some(value) => values.extend(value),
                    None => break,
                }
            }
            Ok(Observation::Present(values))
        }
    }

    unsafe fn read_value(key: &OwnedKey, index: u32) -> Result<Option<Vec<String>>, PlatformError> {
        let mut name = vec![0_u16; 16_384];
        let mut name_len = u32::try_from(name.len() - 1).expect("name capacity fits u32");
        let mut kind = 0_u32;
        let mut data_len = MAX_VALUE_BYTES;
        let mut data = vec![0_u8; usize::try_from(data_len).unwrap_or(0)];
        let status = RegEnumValueW(
            key.0,
            index,
            Some(PWSTR(name.as_mut_ptr())),
            &raw mut name_len,
            None,
            Some(&raw mut kind),
            Some(data.as_mut_ptr()),
            Some(&raw mut data_len),
        );
        if status == ERROR_NO_MORE_ITEMS {
            return Ok(None);
        }
        if status == ERROR_ACCESS_DENIED {
            return Err(PlatformError::Io(std::io::Error::from(
                std::io::ErrorKind::PermissionDenied,
            )));
        }
        check(status)?;
        data.truncate(usize::try_from(data_len).unwrap_or(0));
        let kind = REG_VALUE_TYPE(kind);
        if kind != REG_SZ && kind != REG_MULTI_SZ || !data.len().is_multiple_of(2) {
            return Ok(Some(Vec::new()));
        }
        let units = data
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        let values = units
            .split(|unit| *unit == 0)
            .filter(|item| !item.is_empty())
            .map(String::from_utf16)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| PlatformError::TrustFailure(error.to_string()))?;
        Ok(Some(values))
    }

    fn check(status: WIN32_ERROR) -> Result<(), PlatformError> {
        if status == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(PlatformError::Io(std::io::Error::from_raw_os_error(
                i32::try_from(status.0).unwrap_or(i32::MAX),
            )))
        }
    }
    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }
    struct OwnedKey(HKEY);
    impl Drop for OwnedKey {
        fn drop(&mut self) {
            unsafe {
                let _ = RegCloseKey(self.0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wecutil_timeout_and_truncation_remain_explicit() {
        assert!(matches!(
            command_error(PlatformError::ProcessTimeout { seconds: 1 }),
            Observation::TimedOut
        ));
        assert!(matches!(
            command_error(PlatformError::OutputTooLarge {
                stream: "stdout",
                limit: 1
            }),
            Observation::Truncated
        ));
    }
}
