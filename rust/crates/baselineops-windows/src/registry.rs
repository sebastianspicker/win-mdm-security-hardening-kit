//! Read-only, compile-time allowlisted registry access for native capabilities.

use crate::PlatformError;
use serde::Serialize;
/// Registry locations required by the first native read-only capability wave.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryLocation {
    /// DNS Client parameters used by the `DoH` audit.
    DnsCacheParameters,
    /// LSA parameters used by the NTLM client audit.
    LocalSecurityAuthority,
    /// Machine or user policy for transcript logging.
    PowerShellTranscription,
    /// Machine or user policy for script-block logging.
    PowerShellScriptBlockLogging,
    /// Machine or user policy for module logging.
    PowerShellModuleLogging,
    /// Machine or user policy for the bounded numbered module-name set.
    PowerShellModuleNames,
}
/// Value names available through the allowlisted reader.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryValueName {
    /// DNS client `DoH` mode.
    EnableAutoDoh,
    /// Configured `DoH` resolvers.
    DohNameServers,
    /// `DoH` bootstrap addresses.
    ServerAddresses,
    /// Plaintext fallback policy.
    BlockUntrustedDoh,
    /// NTLM/LM compatibility level.
    LmCompatibilityLevel,
    /// Windows policy spelling for transcription enablement.
    EnableTranscripting,
    /// Transcript directory policy.
    OutputDirectory,
    /// Transcription invocation header policy.
    EnableInvocationHeader,
    /// Script-block logging policy.
    EnableScriptBlockLogging,
    /// Script-block invocation logging policy.
    EnableScriptBlockInvocationLogging,
    /// Module logging policy.
    EnableModuleLogging,
    /// Bounded numbered module-name value (1 through 64).
    ModuleName(u16),
}
/// A normalized, bounded registry value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum RegistryValue {
    /// 32-bit integer value.
    Dword(u32),
    /// One UTF-16 string.
    String(String),
    /// A UTF-16 multi-string with empty terminators removed.
    MultiString(Vec<String>),
}

/// Result of a registry observation. Absence is distinct from access failure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", content = "value", rename_all = "snake_case")]
pub enum RegistryRead {
    /// The key or value is not configured.
    Missing,
    /// The value was present and decoded.
    Present(RegistryValue),
}

/// Read one compile-time allowlisted HKLM registry value without mutation.
/// # Errors
/// Returns an error for a non-allowlisted pair, an unsupported platform, native registry failures, or malformed, unsupported, or oversized values.
pub fn read_hklm_value(
    location: RegistryLocation,
    name: RegistryValueName,
) -> Result<RegistryRead, PlatformError> {
    if !allowed_pair(location, name) {
        return Err(PlatformError::TrustFailure(
            "registry location/value pair is not capability-allowlisted".into(),
        ));
    }
    platform::read_hklm_value(location, name)
}

/// Read one allowlisted HKCU PowerShell policy value without mutation.
/// # Errors
/// Returns an error for a non-PowerShell-policy pair, an unsupported platform, native registry failures, or malformed, unsupported, or oversized values.
pub fn read_hkcu_value(
    location: RegistryLocation,
    name: RegistryValueName,
) -> Result<RegistryRead, PlatformError> {
    if !allowed_powershell_pair(location, name) {
        return Err(PlatformError::TrustFailure(
            "HKCU registry location/value pair is not PowerShell-policy allowlisted".into(),
        ));
    }
    platform::read_hkcu_value(location, name)
}

/// Set one typed HKLM value and require an exact read-back.
/// # Errors
/// Returns an error for a non-allowlisted pair or type, an unsupported platform, native write or read-back failure, or a mismatched read-back.
pub fn set_hklm_value(
    location: RegistryLocation,
    name: RegistryValueName,
    value: impl Into<RegistryValue>,
) -> Result<(), PlatformError> {
    let value = value.into();
    if !allowed_pair(location, name) || !value_matches(name, &value) {
        return Err(PlatformError::TrustFailure(
            "registry mutation is outside the typed capability allowlist".into(),
        ));
    }
    platform::set_hklm_value(location, name, &value)
}
/// Delete one typed HKLM PowerShell policy value; absence is successful.
/// # Errors
/// Returns an error for a non-PowerShell-policy pair, an unsupported platform, native registry failures, or a value that remains after deletion.
pub fn delete_hklm_value(
    location: RegistryLocation,
    name: RegistryValueName,
) -> Result<(), PlatformError> {
    if !allowed_powershell_pair(location, name) {
        return Err(PlatformError::TrustFailure(
            "registry deletion is outside the typed PowerShell-policy allowlist".into(),
        ));
    }
    platform::delete_hklm_value(location, name)
}

/// Enumerate every bounded numbered HKLM `ModuleNames` value completely.
/// # Errors
/// Returns an error on an unsupported platform, native registry failure, malformed numbering, unsupported value type, or invalid UTF-16.
pub fn list_hklm_module_names() -> Result<crate::powershell_logging::ModuleNamesRead, PlatformError>
{
    platform::list_hklm_module_names()
}

const fn allowed_pair(location: RegistryLocation, name: RegistryValueName) -> bool {
    matches!(
        (location, name),
        (
            RegistryLocation::DnsCacheParameters,
            RegistryValueName::EnableAutoDoh
                | RegistryValueName::DohNameServers
                | RegistryValueName::ServerAddresses
                | RegistryValueName::BlockUntrustedDoh
        ) | (
            RegistryLocation::LocalSecurityAuthority,
            RegistryValueName::LmCompatibilityLevel
        ) | (
            RegistryLocation::PowerShellTranscription,
            RegistryValueName::EnableTranscripting
                | RegistryValueName::OutputDirectory
                | RegistryValueName::EnableInvocationHeader
        ) | (
            RegistryLocation::PowerShellScriptBlockLogging,
            RegistryValueName::EnableScriptBlockLogging
                | RegistryValueName::EnableScriptBlockInvocationLogging
        ) | (
            RegistryLocation::PowerShellModuleLogging,
            RegistryValueName::EnableModuleLogging
        ) | (
            RegistryLocation::PowerShellModuleNames,
            RegistryValueName::ModuleName(1..=64)
        )
    )
}

const fn allowed_powershell_pair(location: RegistryLocation, name: RegistryValueName) -> bool {
    matches!(
        (location, name),
        (
            RegistryLocation::PowerShellTranscription
                | RegistryLocation::PowerShellScriptBlockLogging
                | RegistryLocation::PowerShellModuleLogging,
            _
        ) | (
            RegistryLocation::PowerShellModuleNames,
            RegistryValueName::ModuleName(1..=64)
        )
    ) && allowed_pair(location, name)
}

const fn value_matches(name: RegistryValueName, value: &RegistryValue) -> bool {
    matches!(
        (name, value),
        (
            RegistryValueName::EnableAutoDoh
                | RegistryValueName::BlockUntrustedDoh
                | RegistryValueName::LmCompatibilityLevel
                | RegistryValueName::EnableTranscripting
                | RegistryValueName::EnableInvocationHeader
                | RegistryValueName::EnableScriptBlockLogging
                | RegistryValueName::EnableScriptBlockInvocationLogging
                | RegistryValueName::EnableModuleLogging,
            RegistryValue::Dword(_)
        ) | (
            RegistryValueName::DohNameServers
                | RegistryValueName::ServerAddresses
                | RegistryValueName::OutputDirectory
                | RegistryValueName::ModuleName(_),
            RegistryValue::String(_)
        )
    )
}

#[cfg(not(windows))]
mod platform {
    use super::{PlatformError, RegistryLocation, RegistryRead, RegistryValue, RegistryValueName};

    #[rustfmt::skip] pub(super) fn read_hklm_value(_location: RegistryLocation, _name: RegistryValueName) -> Result<RegistryRead, PlatformError> { Err(PlatformError::UnsupportedPlatform) }
    #[rustfmt::skip] pub(super) fn read_hkcu_value(_location: RegistryLocation, _name: RegistryValueName) -> Result<RegistryRead, PlatformError> { Err(PlatformError::UnsupportedPlatform) }
    #[rustfmt::skip] pub(super) fn set_hklm_value(_location: RegistryLocation, _name: RegistryValueName, _value: &RegistryValue) -> Result<(), PlatformError> { Err(PlatformError::UnsupportedPlatform) }
    #[rustfmt::skip] pub(super) fn delete_hklm_value(_location: RegistryLocation, _name: RegistryValueName) -> Result<(), PlatformError> { Err(PlatformError::UnsupportedPlatform) }
    #[rustfmt::skip] pub(super) fn list_hklm_module_names() -> Result<crate::powershell_logging::ModuleNamesRead, PlatformError> { Err(PlatformError::UnsupportedPlatform) }
}

#[cfg(windows)]
mod platform {
    #![allow(unsafe_code, unsafe_op_in_unsafe_fn)]

    use super::{PlatformError, RegistryLocation, RegistryRead, RegistryValue, RegistryValueName};
    use windows::Win32::Foundation::{
        ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, WIN32_ERROR,
    };
    use windows::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_DWORD, REG_MULTI_SZ,
        REG_OPTION_NON_VOLATILE, REG_SZ, REG_VALUE_TYPE, RegCloseKey, RegCreateKeyExW,
        RegDeleteValueW, RegEnumValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
    };
    use windows::core::PCWSTR;

    const MAX_REGISTRY_BYTES: u32 = 64 * 1024;

    pub(super) fn read_hklm_value(
        location: RegistryLocation,
        name: RegistryValueName,
    ) -> Result<RegistryRead, PlatformError> {
        read_value(HKEY_LOCAL_MACHINE, location, name)
    }

    pub(super) fn read_hkcu_value(
        location: RegistryLocation,
        name: RegistryValueName,
    ) -> Result<RegistryRead, PlatformError> {
        read_value(HKEY_CURRENT_USER, location, name)
    }

    pub(super) fn set_hklm_value(
        location: RegistryLocation,
        name: RegistryValueName,
        value: &RegistryValue,
    ) -> Result<(), PlatformError> {
        unsafe {
            let key = create_hklm_key(location)?;
            let name_wide = wide(value_name(name));
            let (kind, bytes) = encode_value(value)?;
            check_status(RegSetValueExW(
                key.0,
                PCWSTR(name_wide.as_ptr()),
                None,
                kind,
                Some(&bytes),
            ))?;
            match query_value(&key, name)? {
                RegistryRead::Present(actual) if actual == *value => Ok(()),
                RegistryRead::Present(_) | RegistryRead::Missing => {
                    Err(PlatformError::TrustFailure(
                        "registry read-after-write did not match the requested value".into(),
                    ))
                }
            }
        }
    }

    pub(super) fn delete_hklm_value(
        location: RegistryLocation,
        name: RegistryValueName,
    ) -> Result<(), PlatformError> {
        unsafe {
            let key = create_hklm_key(location)?;
            let name_wide = wide(value_name(name));
            let status = RegDeleteValueW(key.0, PCWSTR(name_wide.as_ptr()));
            if status != ERROR_FILE_NOT_FOUND {
                check_status(status)?;
            }
            match query_value(&key, name)? {
                RegistryRead::Missing => Ok(()),
                RegistryRead::Present(_) => Err(PlatformError::TrustFailure(
                    "registry value remained after delete read-back".into(),
                )),
            }
        }
    }

    pub(super) fn list_hklm_module_names()
    -> Result<crate::powershell_logging::ModuleNamesRead, PlatformError> {
        unsafe {
            let path = wide(location_path(RegistryLocation::PowerShellModuleNames));
            let mut raw_key = HKEY::default();
            let status = RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(path.as_ptr()),
                None,
                KEY_READ,
                &raw mut raw_key,
            );
            if status == ERROR_FILE_NOT_FOUND {
                return Ok(crate::powershell_logging::ModuleNamesRead::missing());
            }
            check_status(status)?;
            let key = OwnedKey(raw_key);
            let mut values = std::collections::BTreeMap::new();
            for index in 0..=u32::from(crate::powershell_logging::MAX_MODULE_NAMES) {
                let mut name = vec![0_u16; 4];
                let mut name_len = u32::try_from(name.len()).map_err(|_| {
                    PlatformError::TrustFailure("module name length overflow".into())
                })?;
                let mut value_type = 0_u32;
                let mut size = 0_u32;
                let status = RegEnumValueW(
                    key.0,
                    index,
                    Some(windows::core::PWSTR(name.as_mut_ptr())),
                    &raw mut name_len,
                    None,
                    Some(&raw mut value_type),
                    None,
                    Some(&raw mut size),
                );
                if status == ERROR_NO_MORE_ITEMS {
                    break;
                }
                check_status(status)?;
                let numeric = String::from_utf16(
                    &name[..usize::try_from(name_len).map_err(|_| {
                        PlatformError::TrustFailure("module name length overflow".into())
                    })?],
                )
                .map_err(|error| PlatformError::TrustFailure(error.to_string()))?
                .parse::<u16>()
                .ok()
                .filter(|value| (1..=crate::powershell_logging::MAX_MODULE_NAMES).contains(value))
                .ok_or_else(|| {
                    PlatformError::TrustFailure(
                        "ModuleNames has a non-numbered or out-of-range value".into(),
                    )
                })?;
                let read = query_value(&key, RegistryValueName::ModuleName(numeric))?;
                let RegistryRead::Present(RegistryValue::String(value)) = read else {
                    return Err(PlatformError::TrustFailure(
                        "ModuleNames value has an unexpected type".into(),
                    ));
                };
                values.insert(numeric, value);
            }
            Ok(crate::powershell_logging::ModuleNamesRead {
                values,
                complete: true,
            })
        }
    }

    fn read_value(
        root: HKEY,
        location: RegistryLocation,
        name: RegistryValueName,
    ) -> Result<RegistryRead, PlatformError> {
        unsafe {
            let path = wide(location_path(location));
            let mut raw_key = HKEY::default();
            let status = RegOpenKeyExW(
                root,
                PCWSTR(path.as_ptr()),
                None,
                KEY_READ,
                &raw mut raw_key,
            );
            if status == ERROR_FILE_NOT_FOUND {
                return Ok(RegistryRead::Missing);
            }
            check_status(status)?;
            query_value(&OwnedKey(raw_key), name)
        }
    }

    unsafe fn create_hklm_key(location: RegistryLocation) -> Result<OwnedKey, PlatformError> {
        let path = wide(location_path(location));
        let mut raw_key = HKEY::default();
        check_status(RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(path.as_ptr()),
            None,
            None,
            REG_OPTION_NON_VOLATILE,
            KEY_READ | KEY_WRITE,
            None,
            &raw mut raw_key,
            None,
        ))?;
        Ok(OwnedKey(raw_key))
    }

    unsafe fn query_value(
        key: &OwnedKey,
        name: RegistryValueName,
    ) -> Result<RegistryRead, PlatformError> {
        let name = wide(value_name(name));
        let mut value_type = REG_VALUE_TYPE::default();
        let mut size = 0_u32;
        let status = RegQueryValueExW(
            key.0,
            PCWSTR(name.as_ptr()),
            None,
            Some(&raw mut value_type),
            None,
            Some(&raw mut size),
        );
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(RegistryRead::Missing);
        }
        check_status(status)?;
        if size > MAX_REGISTRY_BYTES {
            return Err(PlatformError::TrustFailure(
                "registry value exceeds the 64 KiB observation limit".into(),
            ));
        }
        let mut bytes = vec![0_u8; usize::try_from(size).unwrap_or(usize::MAX)];
        check_status(RegQueryValueExW(
            key.0,
            PCWSTR(name.as_ptr()),
            None,
            Some(&raw mut value_type),
            Some(bytes.as_mut_ptr()),
            Some(&raw mut size),
        ))?;
        bytes.truncate(usize::try_from(size).unwrap_or(0));
        decode_value(value_type, &bytes).map(RegistryRead::Present)
    }

    fn decode_value(
        value_type: REG_VALUE_TYPE,
        bytes: &[u8],
    ) -> Result<RegistryValue, PlatformError> {
        if value_type == REG_DWORD && bytes.len() == 4 {
            return Ok(RegistryValue::Dword(u32::from_le_bytes(
                bytes.try_into().expect("DWORD length checked"),
            )));
        }
        if value_type != REG_SZ && value_type != REG_MULTI_SZ {
            return Err(PlatformError::TrustFailure(format!(
                "registry value has unsupported type {}",
                value_type.0
            )));
        }
        if !bytes.len().is_multiple_of(2) {
            return Err(PlatformError::TrustFailure(
                "registry string has an odd UTF-16 byte length".into(),
            ));
        }
        let units = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        if value_type == REG_SZ {
            let end = units
                .iter()
                .position(|unit| *unit == 0)
                .unwrap_or(units.len());
            return String::from_utf16(&units[..end])
                .map(RegistryValue::String)
                .map_err(|error| PlatformError::TrustFailure(error.to_string()));
        }
        let values = units
            .split(|unit| *unit == 0)
            .filter(|value| !value.is_empty())
            .map(String::from_utf16)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| PlatformError::TrustFailure(error.to_string()))?;
        Ok(RegistryValue::MultiString(values))
    }

    fn encode_value(value: &RegistryValue) -> Result<(REG_VALUE_TYPE, Vec<u8>), PlatformError> {
        match value {
            RegistryValue::Dword(value) => Ok((REG_DWORD, value.to_le_bytes().to_vec())),
            RegistryValue::String(value) => encode_string(value).map(|bytes| (REG_SZ, bytes)),
            RegistryValue::MultiString(_) => Err(PlatformError::TrustFailure(
                "multi-string registry mutation is not permitted".into(),
            )),
        }
    }

    fn encode_string(value: &str) -> Result<Vec<u8>, PlatformError> {
        let units = value
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let bytes = units
            .iter()
            .flat_map(|unit| unit.to_le_bytes())
            .collect::<Vec<_>>();
        if bytes.len() > usize::try_from(MAX_REGISTRY_BYTES).unwrap_or(usize::MAX) {
            return Err(PlatformError::TrustFailure(
                "registry value exceeds the 64 KiB mutation limit".into(),
            ));
        }
        Ok(bytes)
    }

    fn check_status(status: WIN32_ERROR) -> Result<(), PlatformError> {
        if status == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(PlatformError::Io(std::io::Error::from_raw_os_error(
                i32::try_from(status.0).unwrap_or(i32::MAX),
            )))
        }
    }

    const fn location_path(location: RegistryLocation) -> &'static str {
        match location {
            RegistryLocation::DnsCacheParameters => {
                r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
            }
            RegistryLocation::LocalSecurityAuthority => r"SYSTEM\CurrentControlSet\Control\Lsa",
            RegistryLocation::PowerShellTranscription => {
                r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
            }
            RegistryLocation::PowerShellScriptBlockLogging => {
                r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
            }
            RegistryLocation::PowerShellModuleLogging => {
                r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
            }
            RegistryLocation::PowerShellModuleNames => {
                r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames"
            }
        }
    }

    fn value_name(name: RegistryValueName) -> &'static str {
        match name {
            RegistryValueName::EnableAutoDoh => "EnableAutoDoh",
            RegistryValueName::DohNameServers => "DohNameServers",
            RegistryValueName::ServerAddresses => "ServerAddresses",
            RegistryValueName::BlockUntrustedDoh => "BlockUntrustedDoh",
            RegistryValueName::LmCompatibilityLevel => "LmCompatibilityLevel",
            RegistryValueName::EnableTranscripting => "EnableTranscripting",
            RegistryValueName::OutputDirectory => "OutputDirectory",
            RegistryValueName::EnableInvocationHeader => "EnableInvocationHeader",
            RegistryValueName::EnableScriptBlockLogging => "EnableScriptBlockLogging",
            RegistryValueName::EnableScriptBlockInvocationLogging => {
                "EnableScriptBlockInvocationLogging"
            }
            RegistryValueName::EnableModuleLogging => "EnableModuleLogging",
            RegistryValueName::ModuleName(value) => module_name(value),
        }
    }

    fn module_name(value: u16) -> &'static str {
        const NAMES: [&str; 64] = [
            "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16",
            "17", "18", "19", "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "30",
            "31", "32", "33", "34", "35", "36", "37", "38", "39", "40", "41", "42", "43", "44",
            "45", "46", "47", "48", "49", "50", "51", "52", "53", "54", "55", "56", "57", "58",
            "59", "60", "61", "62", "63", "64",
        ];
        NAMES[usize::from(value - 1)]
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
    fn unrelated_location_and_value_are_rejected_before_platform_access() {
        let result = read_hklm_value(
            RegistryLocation::LocalSecurityAuthority,
            RegistryValueName::EnableAutoDoh,
        );
        assert!(matches!(result, Err(PlatformError::TrustFailure(_))));
    }
}
