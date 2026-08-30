//! Private bounded registry reader shared by the Office and `WUfB` adapters.
//!
//! Paths and value names enter only as compile-time constants in sibling
//! adapters. This module has no public raw-registry API and no mutation API.

use crate::PlatformError;
use baselineops_capabilities::{Observation, PolicyValueSnapshot};

pub(crate) fn read_dword(
    path: &'static str,
    name: &'static str,
) -> Result<PolicyValueSnapshot, PlatformError> {
    platform::read(path, name, true)
}
pub(crate) fn read_string(
    path: &'static str,
    name: &'static str,
) -> Result<PolicyValueSnapshot, PlatformError> {
    platform::read(path, name, false)
}
pub(crate) fn read_hkcu_dword(
    path: &'static str,
    name: &'static str,
) -> Result<PolicyValueSnapshot, PlatformError> {
    platform::read_hkcu(path, name, true)
}

pub(crate) fn subkeys_hklm(
    path: &'static str,
    max_subkeys: u32,
) -> Result<Observation<Vec<String>>, PlatformError> {
    if max_subkeys == 0 || max_subkeys > 4096 {
        return Err(PlatformError::TrustFailure(
            "registry subkey bound is outside the internal policy".into(),
        ));
    }
    platform::subkeys_hklm(path, max_subkeys)
}

#[cfg(not(windows))]
mod platform {
    use super::{Observation, PlatformError, PolicyValueSnapshot};
    pub(super) fn read(
        _: &'static str,
        _: &'static str,
        _: bool,
    ) -> Result<PolicyValueSnapshot, PlatformError> {
        Err(PlatformError::UnsupportedPlatform)
    }
    pub(super) fn read_hkcu(
        _: &'static str,
        _: &'static str,
        _: bool,
    ) -> Result<PolicyValueSnapshot, PlatformError> {
        Err(PlatformError::UnsupportedPlatform)
    }
    pub(super) fn subkeys_hklm(
        _: &'static str,
        _: u32,
    ) -> Result<Observation<Vec<String>>, PlatformError> {
        Err(PlatformError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
mod platform {
    #![allow(unsafe_code, unsafe_op_in_unsafe_fn)]
    use super::{Observation, PlatformError, PolicyValueSnapshot};
    use windows::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS,
        ERROR_SUCCESS, WIN32_ERROR,
    };
    use windows::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, REG_DWORD, REG_SZ, REG_VALUE_TYPE,
        RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW,
    };
    use windows::core::{PCWSTR, PWSTR};
    const MAX_BYTES: u32 = 512;
    pub(super) fn read(
        path: &'static str,
        name: &'static str,
        dword: bool,
    ) -> Result<PolicyValueSnapshot, PlatformError> {
        read_from(HKEY_LOCAL_MACHINE, path, name, dword)
    }
    pub(super) fn read_hkcu(
        path: &'static str,
        name: &'static str,
        dword: bool,
    ) -> Result<PolicyValueSnapshot, PlatformError> {
        read_from(HKEY_CURRENT_USER, path, name, dword)
    }
    pub(super) fn subkeys_hklm(
        path: &'static str,
        max_subkeys: u32,
    ) -> Result<Observation<Vec<String>>, PlatformError> {
        unsafe {
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
                return Ok(Observation::Missing);
            }
            if status == ERROR_ACCESS_DENIED {
                return Ok(Observation::AccessDenied);
            }
            status_ok(status)?;
            enumerate_subkeys(&Key(raw), max_subkeys)
        }
    }

    unsafe fn enumerate_subkeys(
        key: &Key,
        max_subkeys: u32,
    ) -> Result<Observation<Vec<String>>, PlatformError> {
        let mut values = Vec::new();
        for index in 0..=max_subkeys {
            let mut name = vec![0_u16; 512];
            let mut length = u32::try_from(name.len()).expect("bounded key name buffer");
            let status = unsafe {
                RegEnumKeyExW(
                    key.0,
                    index,
                    Some(PWSTR(name.as_mut_ptr())),
                    &raw mut length,
                    None,
                    None,
                    None,
                    None,
                )
            };
            if status == ERROR_NO_MORE_ITEMS {
                return Ok(Observation::Present(values));
            }
            if status == ERROR_MORE_DATA || index == max_subkeys {
                return Ok(Observation::Truncated);
            }
            if status == ERROR_ACCESS_DENIED {
                return Ok(Observation::AccessDenied);
            }
            status_ok(status)?;
            name.truncate(usize::try_from(length).map_err(|_| {
                PlatformError::TrustFailure("registry subkey length overflow".into())
            })?);
            values.push(String::from_utf16(&name).map_err(|_| {
                PlatformError::TrustFailure("registry subkey is not valid UTF-16".into())
            })?);
        }
        Ok(Observation::Truncated)
    }
    fn read_from(
        root: HKEY,
        path: &'static str,
        name: &'static str,
        dword: bool,
    ) -> Result<PolicyValueSnapshot, PlatformError> {
        unsafe {
            let path = wide(path);
            let mut key = HKEY::default();
            let status = RegOpenKeyExW(root, PCWSTR(path.as_ptr()), None, KEY_READ, &raw mut key);
            if status == ERROR_FILE_NOT_FOUND {
                return Ok(PolicyValueSnapshot::Missing);
            }
            status_ok(status)?;
            let key = Key(key);
            let name = wide(name);
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
                return Ok(PolicyValueSnapshot::Missing);
            }
            status_ok(status)?;
            if size > MAX_BYTES {
                return Err(PlatformError::TrustFailure(
                    "policy registry value exceeds the bounded reader limit".into(),
                ));
            }
            let mut bytes = vec![
                0_u8;
                usize::try_from(size).map_err(|_| PlatformError::TrustFailure(
                    "registry length overflow".into()
                ))?
            ];
            status_ok(RegQueryValueExW(
                key.0,
                PCWSTR(name.as_ptr()),
                None,
                Some(&raw mut kind),
                Some(bytes.as_mut_ptr()),
                Some(&raw mut size),
            ))?;
            bytes.truncate(
                usize::try_from(size)
                    .map_err(|_| PlatformError::TrustFailure("registry length overflow".into()))?,
            );
            if dword {
                if kind != REG_DWORD || bytes.len() != 4 {
                    return Err(PlatformError::TrustFailure(
                        "policy registry value has an unexpected type".into(),
                    ));
                }
                return Ok(PolicyValueSnapshot::Dword(u32::from_le_bytes(
                    bytes.try_into().expect("four bytes"),
                )));
            }
            if kind != REG_SZ || !bytes.len().is_multiple_of(2) {
                return Err(PlatformError::TrustFailure(
                    "policy registry value has an unexpected type".into(),
                ));
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
                .map(PolicyValueSnapshot::String)
                .map_err(|error| PlatformError::TrustFailure(error.to_string()))
        }
    }
    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
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
    struct Key(HKEY);
    impl Drop for Key {
        fn drop(&mut self) {
            unsafe {
                let _ = RegCloseKey(self.0);
            }
        }
    }
}
