//! Fixed read-only acquisition for backup readiness capability 36.

use crate::PlatformError;
#[cfg(windows)]
use crate::{
    NativeArgumentRule, NativeEncoding, NativeExecutableTrust, NativeProcessPolicy,
    NativeProcessSpec, decode_native_output, run_native,
};
use baselineops_capabilities::BackupReadinessObservation;
#[cfg(windows)]
use baselineops_capabilities::{Observation, OsVolumeSpace, VssWriter, parse_vss_writers};
#[cfg(windows)]
use std::collections::BTreeMap;
#[cfg(windows)]
use std::ffi::OsString;
#[cfg(windows)]
use std::time::Duration;

#[cfg(windows)]
const TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(windows)]
const OUTPUT_LIMIT: usize = 256 * 1024;

/// Observe fixed backup-readiness indicators without starting services or jobs.
///
/// # Errors
///
/// Returns [`PlatformError::UnsupportedPlatform`] outside Windows.
pub fn audit_backup_readiness() -> Result<BackupReadinessObservation, PlatformError> {
    #[cfg(windows)]
    {
        Ok(BackupReadinessObservation {
            os_volume: platform::os_volume(),
            vss_writers: vss_writers(),
            file_history_present: platform::file_history(),
        })
    }
    #[cfg(not(windows))]
    {
        Err(PlatformError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
fn vss_writers() -> Observation<Vec<VssWriter>> {
    let Ok(executable) = crate::trust::windows_system32_file("vssadmin.exe") else {
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
            NativeArgumentRule::Exact("list".into()),
            NativeArgumentRule::Exact("writers".into()),
        ]],
        environment: BTreeMap::<OsString, OsString>::new(),
        max_timeout: TIMEOUT,
        max_output_limit: OUTPUT_LIMIT,
    };
    match run_native(
        &policy,
        &NativeProcessSpec {
            args: vec!["list".into(), "writers".into()],
            timeout: TIMEOUT,
            output_limit: OUTPUT_LIMIT,
        },
    ) {
        Ok(result) if result.exit_code == 0 => {
            decode_native_output(&result.stdout, NativeEncoding::Utf8)
                .map_or(Observation::Unparsed, |text| parse_vss_writers(&text))
        }
        Ok(result) => Observation::Failed {
            exit_code: result.exit_code,
        },
        Err(PlatformError::ProcessTimeout { .. }) => Observation::TimedOut,
        Err(PlatformError::OutputTooLarge { .. }) => Observation::Truncated,
        Err(PlatformError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            Observation::Missing
        }
        Err(PlatformError::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            Observation::AccessDenied
        }
        Err(_) => Observation::Unparsed,
    }
}

#[cfg(windows)]
mod platform {
    #![allow(unsafe_code, unsafe_op_in_unsafe_fn)]
    use super::{Observation, OsVolumeSpace, PlatformError};
    use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
    use windows::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    use windows::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_READ, RegCloseKey, RegOpenKeyExW,
    };
    use windows::Win32::System::SystemInformation::GetWindowsDirectoryW;
    use windows::core::PCWSTR;
    const FILE_HISTORY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\FileHistory";
    pub(super) fn os_volume() -> Observation<OsVolumeSpace> {
        let Ok(volume) = windows_volume() else {
            return Observation::Unparsed;
        };
        let wide = wide(&volume);
        let mut free = 0_u64;
        let mut total = 0_u64;
        if unsafe {
            GetDiskFreeSpaceExW(
                PCWSTR(wide.as_ptr()),
                Some(&raw mut free),
                Some(&raw mut total),
                None,
            )
        }
        .is_err()
        {
            return Observation::Unparsed;
        }
        Observation::Present(OsVolumeSpace {
            volume,
            free_bytes: free,
            total_bytes: total,
        })
    }
    pub(super) fn file_history() -> Observation<bool> {
        let path = wide(FILE_HISTORY);
        let mut key = HKEY::default();
        let status = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(path.as_ptr()),
                None,
                KEY_READ,
                &raw mut key,
            )
        };
        if status == ERROR_FILE_NOT_FOUND {
            return Observation::Present(false);
        }
        if status == ERROR_ACCESS_DENIED {
            return Observation::AccessDenied;
        }
        if status != ERROR_SUCCESS {
            return Observation::Unparsed;
        }
        unsafe {
            let _ = RegCloseKey(key);
        }
        Observation::Present(true)
    }
    fn windows_volume() -> Result<String, PlatformError> {
        let mut path = vec![0_u16; 32_768];
        let length = unsafe { GetWindowsDirectoryW(Some(&mut path)) };
        if !(3..u32::try_from(path.len()).expect("path length fits u32")).contains(&length) {
            return Err(PlatformError::TrustFailure(
                "Windows directory has no drive volume".into(),
            ));
        }
        let value =
            String::from_utf16(&path[..usize::try_from(length).expect("length fits usize")])
                .map_err(|error| PlatformError::TrustFailure(error.to_string()))?;
        let bytes = value.as_bytes();
        if bytes.len() < 2 || bytes[1] != b':' || !bytes[0].is_ascii_alphabetic() {
            return Err(PlatformError::TrustFailure(
                "Windows directory is not drive-rooted".into(),
            ));
        }
        Ok(format!("{}:\\", char::from(bytes[0]).to_ascii_uppercase()))
    }
    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(Some(0)).collect()
    }
}
