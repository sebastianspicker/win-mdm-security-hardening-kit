//! Read-only Windows Time acquisition for capability 34.

use crate::{
    NativeArgumentRule, NativeEncoding, NativeExecutableTrust, NativeProcessPolicy,
    NativeProcessSpec, PlatformError, decode_native_output, observe_service, run_native,
};
use baselineops_capabilities::{
    Observation, TimeSyncObservation, parse_w32tm_source, parse_w32tm_status,
};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(30);
const OUTPUT_LIMIT: usize = 256 * 1024;

/// Acquire the bounded, read-only observations used by capability 34.
///
/// `always_run_w32tm_even_if_service_stopped` only controls observation. It
/// never starts `w32time`; the legacy `AutoStartService` switch has no native
/// equivalent and is rejected by the engine parameter type.
///
/// # Errors
///
/// Returns an error for unsupported hosts, invalid bounded registry values, or
/// operating-system failures that cannot be represented as incomplete data.
pub fn audit_time_sync(
    always_run_w32tm_even_if_service_stopped: bool,
) -> Result<TimeSyncObservation, PlatformError> {
    let service = observe_service(crate::KnownService::WindowsTime)?;
    let registry = platform::registry()?;
    let should_run = always_run_w32tm_even_if_service_stopped
        || !matches!(service, Observation::Present(ref service) if service.state != baselineops_capabilities::ServiceState::Running);
    let (source, root_dispersion_ms, phase_offset_ms) = if should_run {
        let source = command(&["/query", "/source"]);
        let status = command(&["/query", "/status", "/verbose"]);
        (
            parse_command(source, parse_w32tm_source),
            parse_command(status.clone(), |text| parse_w32tm_status(text).0),
            parse_command(status, |text| parse_w32tm_status(text).1),
        )
    } else {
        (
            Observation::NotRun,
            Observation::NotRun,
            Observation::NotRun,
        )
    };
    Ok(TimeSyncObservation {
        service,
        time_type: registry.time_type,
        ntp_server: registry.ntp_server,
        ntp_client_enabled: registry.ntp_client_enabled,
        source,
        root_dispersion_ms,
        phase_offset_ms,
    })
}

#[derive(Debug)]
struct RegistryObservation {
    time_type: Observation<String>,
    ntp_server: Observation<String>,
    ntp_client_enabled: Observation<u32>,
}

fn command(args: &[&str]) -> Observation<String> {
    let executable = match crate::trust::windows_system32_file("w32tm.exe") {
        Ok(executable) => executable,
        Err(error) => return command_error(error),
    };
    let working_directory = executable
        .parent()
        .expect("an API-resolved System32 executable has a parent")
        .to_path_buf();
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
    match run_native(&policy, &spec) {
        Ok(result) if result.exit_code == 0 => {
            decode_native_output(&result.stdout, NativeEncoding::Utf8)
                .map_or(Observation::Unparsed, Observation::Present)
        }
        Ok(result) => Observation::Failed {
            exit_code: result.exit_code,
        },
        Err(error) => command_error(error),
    }
}

fn parse_command<T>(
    value: Observation<String>,
    parser: impl FnOnce(&str) -> Observation<T>,
) -> Observation<T> {
    match value {
        Observation::Present(text) => parser(&text),
        Observation::Missing => Observation::Missing,
        Observation::AccessDenied => Observation::AccessDenied,
        Observation::TimedOut => Observation::TimedOut,
        Observation::Truncated => Observation::Truncated,
        Observation::Failed { exit_code } => Observation::Failed { exit_code },
        Observation::NotRun => Observation::NotRun,
        Observation::Unparsed => Observation::Unparsed,
    }
}

fn command_error(error: PlatformError) -> Observation<String> {
    match error {
        PlatformError::ProcessTimeout { .. } => Observation::TimedOut,
        PlatformError::OutputTooLarge { .. } => Observation::Truncated,
        PlatformError::Io(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Observation::Missing
        }
        PlatformError::Io(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            Observation::AccessDenied
        }
        _ => Observation::Unparsed,
    }
}

#[cfg(not(windows))]
mod platform {
    use super::{PlatformError, RegistryObservation};

    pub(super) fn registry() -> Result<RegistryObservation, PlatformError> {
        Err(PlatformError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
mod platform {
    #![allow(unsafe_code, unsafe_op_in_unsafe_fn)]

    use super::{Observation, PlatformError, RegistryObservation};
    use windows::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_SUCCESS, WIN32_ERROR,
    };
    use windows::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_DWORD, REG_SZ, REG_VALUE_TYPE, RegCloseKey,
        RegOpenKeyExW, RegQueryValueExW,
    };
    use windows::core::PCWSTR;

    const MAX_BYTES: u32 = 64 * 1024;

    pub(super) fn registry() -> Result<RegistryObservation, PlatformError> {
        Ok(RegistryObservation {
            time_type: typed(read_string(
                r"SYSTEM\CurrentControlSet\Services\W32Time\Parameters",
                "Type",
            ))?,
            ntp_server: typed(read_string(
                r"SYSTEM\CurrentControlSet\Services\W32Time\Parameters",
                "NtpServer",
            ))?,
            ntp_client_enabled: typed(read_dword(
                r"SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient",
                "Enabled",
            ))?,
        })
    }

    fn typed<T>(
        result: Result<Observation<T>, PlatformError>,
    ) -> Result<Observation<T>, PlatformError> {
        match result {
            Err(PlatformError::Io(error))
                if error.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                Ok(Observation::AccessDenied)
            }
            other => other,
        }
    }

    unsafe fn open(path: &str) -> Result<Option<OwnedKey>, PlatformError> {
        let path = wide(path);
        let mut raw = HKEY::default();
        let status = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(path.as_ptr()),
            None,
            KEY_READ,
            &raw mut raw,
        );
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if status == ERROR_ACCESS_DENIED {
            return Err(PlatformError::Io(std::io::Error::from(
                std::io::ErrorKind::PermissionDenied,
            )));
        }
        check(status)?;
        Ok(Some(OwnedKey(raw)))
    }

    fn read_string(path: &str, name: &str) -> Result<Observation<String>, PlatformError> {
        unsafe {
            let Some(key) = open(path)? else {
                return Ok(Observation::Missing);
            };
            let name = wide(name);
            let Some((kind, bytes)) = value(&key, &name)? else {
                return Ok(Observation::Missing);
            };
            if kind != REG_SZ || !bytes.len().is_multiple_of(2) {
                return Ok(Observation::Unparsed);
            }
            let units = bytes
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect::<Vec<_>>();
            let end = units
                .iter()
                .position(|unit| *unit == 0)
                .unwrap_or(units.len());
            String::from_utf16(&units[..end])
                .map(Observation::Present)
                .map_err(|error| PlatformError::TrustFailure(error.to_string()))
        }
    }

    fn read_dword(path: &str, name: &str) -> Result<Observation<u32>, PlatformError> {
        unsafe {
            let Some(key) = open(path)? else {
                return Ok(Observation::Missing);
            };
            let name = wide(name);
            let Some((kind, bytes)) = value(&key, &name)? else {
                return Ok(Observation::Missing);
            };
            if kind != REG_DWORD || bytes.len() != 4 {
                return Ok(Observation::Unparsed);
            }
            Ok(Observation::Present(u32::from_le_bytes(
                bytes.try_into().expect("DWORD length checked"),
            )))
        }
    }

    unsafe fn value(
        key: &OwnedKey,
        name: &[u16],
    ) -> Result<Option<(REG_VALUE_TYPE, Vec<u8>)>, PlatformError> {
        let mut kind = REG_VALUE_TYPE::default();
        let mut size = 0_u32;
        let status = RegQueryValueExW(
            key.0,
            PCWSTR(name.as_ptr()),
            None,
            Some(&raw mut kind),
            None,
            Some(&raw mut size),
        );
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if status == ERROR_ACCESS_DENIED {
            return Err(PlatformError::Io(std::io::Error::from(
                std::io::ErrorKind::PermissionDenied,
            )));
        }
        check(status)?;
        if size > MAX_BYTES {
            return Err(PlatformError::TrustFailure(
                "time registry value exceeds the 64 KiB observation limit".into(),
            ));
        }
        let mut bytes = vec![0_u8; usize::try_from(size).unwrap_or(0)];
        let status = RegQueryValueExW(
            key.0,
            PCWSTR(name.as_ptr()),
            None,
            Some(&raw mut kind),
            Some(bytes.as_mut_ptr()),
            Some(&raw mut size),
        );
        if status == ERROR_ACCESS_DENIED {
            return Err(PlatformError::Io(std::io::Error::from(
                std::io::ErrorKind::PermissionDenied,
            )));
        }
        check(status)?;
        bytes.truncate(usize::try_from(size).unwrap_or(0));
        Ok(Some((kind, bytes)))
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
    fn process_failures_remain_explicit_observations() {
        assert_eq!(
            command_error(PlatformError::ProcessTimeout { seconds: 1 }),
            Observation::TimedOut
        );
        assert_eq!(
            command_error(PlatformError::OutputTooLarge {
                stream: "stdout",
                limit: 1
            }),
            Observation::Truncated
        );
    }
}
