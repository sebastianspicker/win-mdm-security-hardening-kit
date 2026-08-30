//! Fixed, shell-free `WinGet` acquisition shared by capabilities 08 and 25.
//!
//! The adapter reads one fixed HKLM App Paths registration as installation
//! evidence. It never executes `winget`, uses no App Execution Alias or PATH,
//! and never reads a source, package, configuration file, profile, or argument
//! supplied by a caller. The existing trust boundary has no protected App
//! Installer executable verifier, so command execution is intentionally absent.

use crate::PlatformError;
use baselineops_capabilities::WingetObservation;

/// Acquire one shared bounded `WinGet` observation without changing Windows state.
///
/// # Errors
///
/// Returns [`PlatformError::UnsupportedPlatform`] outside Windows or a native
/// registry error that cannot be represented as a bounded observation. Missing,
/// access-denied, truncated, unparsed, and untrusted App Paths evidence is
/// retained in the result. Sources and configuration remain `NotRun` because
/// collecting them would require an unverified `WinGet` executable or package API.
pub fn audit_winget() -> Result<WingetObservation, PlatformError> {
    #[cfg(windows)]
    {
        platform::audit()
    }
    #[cfg(not(windows))]
    {
        Err(PlatformError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
mod platform {
    #![allow(unsafe_code, unsafe_op_in_unsafe_fn)]

    use super::{PlatformError, WingetObservation};
    use baselineops_capabilities::{
        APP_INSTALLER_PACKAGE_FAMILY, MAX_WINGET_APP_PATH_BYTES, Observation, WINGET_APP_PATHS_KEY,
        WingetExecutableEvidence,
    };
    use windows::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_PATH_NOT_FOUND,
        ERROR_SUCCESS, WIN32_ERROR,
    };
    use windows::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_SZ, REG_VALUE_TYPE, RegCloseKey, RegOpenKeyExW,
        RegQueryValueExW,
    };
    use windows::core::PCWSTR;

    pub(super) fn audit() -> Result<WingetObservation, PlatformError> {
        Ok(WingetObservation {
            executable: unsafe { app_paths_evidence()? },
            sources: Observation::NotRun,
            configuration: Observation::NotRun,
        })
    }

    unsafe fn app_paths_evidence() -> Result<Observation<WingetExecutableEvidence>, PlatformError> {
        let path = wide(WINGET_APP_PATHS_KEY);
        let mut raw_key = HKEY::default();
        let status = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(path.as_ptr()),
            None,
            KEY_READ,
            &raw mut raw_key,
        );
        if missing(status) {
            return Ok(Observation::Missing);
        }
        if status == ERROR_ACCESS_DENIED {
            return Ok(Observation::AccessDenied);
        }
        status_ok(status)?;
        let key = Key(raw_key);
        let mut value_type = REG_VALUE_TYPE::default();
        let mut size = 0_u32;
        let status = RegQueryValueExW(
            key.0,
            PCWSTR::null(),
            None,
            Some(&raw mut value_type),
            None,
            Some(&raw mut size),
        );
        if missing(status) {
            return Ok(Observation::Missing);
        }
        if status == ERROR_ACCESS_DENIED {
            return Ok(Observation::AccessDenied);
        }
        if status == ERROR_MORE_DATA
            || usize::try_from(size).unwrap_or(usize::MAX) > MAX_WINGET_APP_PATH_BYTES
        {
            return Ok(Observation::Truncated);
        }
        status_ok(status)?;
        if value_type != REG_SZ || size == 0 || !size.is_multiple_of(2) {
            return Ok(Observation::Unparsed);
        }
        let mut bytes = vec![
            0_u8;
            usize::try_from(size).map_err(|_| {
                PlatformError::TrustFailure("WinGet App Paths value length overflow".into())
            })?
        ];
        let status = RegQueryValueExW(
            key.0,
            PCWSTR::null(),
            None,
            Some(&raw mut value_type),
            Some(bytes.as_mut_ptr()),
            Some(&raw mut size),
        );
        if status == ERROR_ACCESS_DENIED {
            return Ok(Observation::AccessDenied);
        }
        if status == ERROR_MORE_DATA
            || usize::try_from(size).unwrap_or(usize::MAX) > MAX_WINGET_APP_PATH_BYTES
        {
            return Ok(Observation::Truncated);
        }
        status_ok(status)?;
        if value_type != REG_SZ || !size.is_multiple_of(2) {
            return Ok(Observation::Unparsed);
        }
        bytes.truncate(usize::try_from(size).map_err(|_| {
            PlatformError::TrustFailure("WinGet App Paths value length overflow".into())
        })?);
        let units = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .take_while(|unit| *unit != 0)
            .collect::<Vec<_>>();
        let path = match String::from_utf16(&units) {
            Ok(path) if path.len() <= MAX_WINGET_APP_PATH_BYTES => path,
            Ok(_) => return Ok(Observation::Truncated),
            Err(_) => return Ok(Observation::Unparsed),
        };
        if !absolute_windows_path(&path) {
            return Ok(Observation::Present(
                WingetExecutableEvidence::UntrustedPath { path },
            ));
        }
        Ok(Observation::Present(WingetExecutableEvidence::Located {
            package_family: APP_INSTALLER_PACKAGE_FAMILY.into(),
            path,
            version: Observation::NotRun,
        }))
    }

    fn absolute_windows_path(path: &str) -> bool {
        let bytes = path.as_bytes();
        bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && matches!(bytes[2], b'\\' | b'/')
            && !path.contains('\0')
    }

    fn missing(status: WIN32_ERROR) -> bool {
        status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND
    }

    fn status_ok(status: WIN32_ERROR) -> Result<(), PlatformError> {
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

    struct Key(HKEY);

    impl Drop for Key {
        fn drop(&mut self) {
            unsafe {
                let _ = RegCloseKey(self.0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn non_windows_acquisition_is_explicitly_unsupported() {
        #[cfg(not(windows))]
        assert!(matches!(
            super::audit_winget(),
            Err(super::PlatformError::UnsupportedPlatform)
        ));
    }
}
