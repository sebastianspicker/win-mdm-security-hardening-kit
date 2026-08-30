//! Native, read-only TPM, `BitLocker`, and Secure Boot observations.
//!
//! The collector uses fixed TBS, firmware, registry, and local-WMI calls. It
//! accepts no commands, paths, WQL, or mutation inputs from a caller.

use crate::PlatformError;
use baselineops_capabilities::{
    BitLockerObservation, HardwareTpmObservation, SecureBootObservation,
};

/// Observe the legacy capability 15 hardware-trust inputs without mutation.
///
/// # Errors
///
/// Returns [`PlatformError::UnsupportedPlatform`] outside Windows. Individual
/// provider failures remain typed incomplete observations whenever possible.
pub fn audit_hardware_tpm() -> Result<HardwareTpmObservation, PlatformError> {
    platform::audit_hardware_tpm()
}

/// Observe operating-system `BitLocker` protection without mutation.
///
/// # Errors
///
/// Returns [`PlatformError::UnsupportedPlatform`] outside Windows. A missing,
/// denied, malformed, or unavailable WMI result remains typed evidence.
pub fn audit_bitlocker_os_volume() -> Result<BitLockerObservation, PlatformError> {
    platform::audit_bitlocker_os_volume()
}

/// Observe firmware and Secure Boot state without mutation.
///
/// # Errors
///
/// Returns [`PlatformError::UnsupportedPlatform`] outside Windows. Registry
/// failures remain typed incomplete observations.
pub fn audit_secure_boot() -> Result<SecureBootObservation, PlatformError> {
    platform::audit_secure_boot()
}

#[cfg(not(windows))]
mod platform {
    use super::{
        BitLockerObservation, HardwareTpmObservation, PlatformError, SecureBootObservation,
    };

    pub(super) fn audit_hardware_tpm() -> Result<HardwareTpmObservation, PlatformError> {
        Err(PlatformError::UnsupportedPlatform)
    }

    pub(super) fn audit_bitlocker_os_volume() -> Result<BitLockerObservation, PlatformError> {
        Err(PlatformError::UnsupportedPlatform)
    }

    pub(super) fn audit_secure_boot() -> Result<SecureBootObservation, PlatformError> {
        Err(PlatformError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
mod platform {
    #![allow(unsafe_code, unsafe_op_in_unsafe_fn)]

    use super::{
        BitLockerObservation, HardwareTpmObservation, PlatformError, SecureBootObservation,
    };
    use baselineops_capabilities::{FirmwareType, Observation, TpmDeviceObservation};
    use std::mem::size_of;
    use windows::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_SUCCESS, RPC_E_TOO_LATE,
    };
    use windows::Win32::System::Com::{
        CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
        CoInitializeSecurity, CoSetProxyBlanket, CoUninitialize, EOAC_NONE, RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
    };
    use windows::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_DWORD, REG_VALUE_TYPE, RegCloseKey, RegOpenKeyExW,
        RegQueryValueExW,
    };
    use windows::Win32::System::SystemInformation::{
        FIRMWARE_TYPE, FirmwareTypeBios, FirmwareTypeUefi, GetFirmwareType,
    };
    use windows::Win32::System::TpmBaseServices::{
        TBS_SUCCESS, TPM_DEVICE_INFO, TPM_VERSION_12, TPM_VERSION_20, Tbsi_GetDeviceInfo,
    };
    use windows::Win32::System::Variant::{VARIANT, VARIANT_0_0, VT_BSTR, VT_UI4, VariantClear};
    use windows::Win32::System::Wmi::{
        IEnumWbemClassObject, IWbemClassObject, IWbemLocator, WBEM_FLAG_FORWARD_ONLY,
        WBEM_FLAG_RETURN_IMMEDIATELY, WBEM_INFINITE, WbemLocator,
    };
    use windows::core::{BSTR, PCWSTR};

    const SECURE_BOOT_STATE: &str = r"SYSTEM\CurrentControlSet\Control\SecureBoot\State";
    const UEFI_SECURE_BOOT_ENABLED: &str = "UEFISecureBootEnabled";
    const PLATFORM_SECURE_BOOT_ENABLED: &str = "PlatformSecureBootEnabled";
    const VOLUME_ENCRYPTION_NAMESPACE: &str = r"ROOT\CIMV2\Security\MicrosoftVolumeEncryption";
    const BITLOCKER_QUERY: &str = "SELECT DriveLetter, __PATH FROM Win32_EncryptableVolume";
    const RPC_C_AUTHN_WINNT: u32 = 10;
    const RPC_C_AUTHZ_NONE: u32 = 0;

    pub(super) fn audit_hardware_tpm() -> Result<HardwareTpmObservation, PlatformError> {
        Ok(HardwareTpmObservation {
            tpm: tpm(),
            secure_boot: audit_secure_boot()?,
            bitlocker: audit_bitlocker_os_volume()?,
        })
    }

    #[allow(clippy::unnecessary_wraps)] // Public contract distinguishes unsupported platforms.
    pub(super) fn audit_secure_boot() -> Result<SecureBootObservation, PlatformError> {
        Ok(SecureBootObservation {
            firmware: firmware_type(),
            uefi_secure_boot_enabled: secure_boot_value(UEFI_SECURE_BOOT_ENABLED),
            platform_secure_boot_enabled: secure_boot_value(PLATFORM_SECURE_BOOT_ENABLED),
        })
    }

    #[allow(clippy::unnecessary_wraps)] // Public contract distinguishes unsupported platforms.
    pub(super) fn audit_bitlocker_os_volume() -> Result<BitLockerObservation, PlatformError> {
        Ok(BitLockerObservation {
            os_volume_protected: bitlocker_protection(),
        })
    }

    fn tpm() -> Observation<TpmDeviceObservation> {
        let mut info = TPM_DEVICE_INFO::default();
        let status = unsafe {
            Tbsi_GetDeviceInfo(
                u32::try_from(size_of::<TPM_DEVICE_INFO>()).expect("TPM info size fits u32"),
                (&raw mut info).cast(),
            )
        };
        if status != TBS_SUCCESS {
            return Observation::Failed {
                exit_code: i32::try_from(status).unwrap_or(-1),
            };
        }
        let major_version = match info.tpmVersion {
            TPM_VERSION_12 => 1,
            TPM_VERSION_20 => 2,
            _ => return Observation::Unparsed,
        };
        Observation::Present(TpmDeviceObservation { major_version })
    }

    fn firmware_type() -> Observation<FirmwareType> {
        let mut firmware = FIRMWARE_TYPE::default();
        if unsafe { GetFirmwareType(&raw mut firmware) }.is_err() {
            return Observation::Unparsed;
        }
        match firmware {
            value if value == FirmwareTypeUefi => Observation::Present(FirmwareType::Uefi),
            value if value == FirmwareTypeBios => Observation::Present(FirmwareType::LegacyBios),
            value => Observation::Present(FirmwareType::Other(u32::try_from(value.0).unwrap_or(0))),
        }
    }

    fn secure_boot_value(name: &str) -> Observation<u32> {
        unsafe {
            let path = wide(SECURE_BOOT_STATE);
            let mut key = HKEY::default();
            let status = RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(path.as_ptr()),
                None,
                KEY_READ,
                &raw mut key,
            );
            if status == ERROR_FILE_NOT_FOUND {
                return Observation::Missing;
            }
            if status == ERROR_ACCESS_DENIED {
                return Observation::AccessDenied;
            }
            if status != ERROR_SUCCESS {
                return Observation::Unparsed;
            }
            let key = OwnedKey(key);
            let name = wide(name);
            let mut kind = REG_VALUE_TYPE::default();
            let mut bytes = u32::try_from(size_of::<u32>()).expect("DWORD length fits u32");
            let mut value = 0_u32;
            let status = RegQueryValueExW(
                key.0,
                PCWSTR(name.as_ptr()),
                None,
                Some(&raw mut kind),
                Some((&raw mut value).cast()),
                Some(&raw mut bytes),
            );
            if status == ERROR_FILE_NOT_FOUND {
                return Observation::Missing;
            }
            if status == ERROR_ACCESS_DENIED {
                return Observation::AccessDenied;
            }
            if status != ERROR_SUCCESS
                || kind != REG_DWORD
                || bytes != u32::try_from(size_of::<u32>()).expect("DWORD size fits u32")
            {
                return Observation::Unparsed;
            }
            Observation::Present(value)
        }
    }

    fn bitlocker_protection() -> Observation<bool> {
        match bitlocker_protection_inner() {
            Ok(value) => value,
            Err(error) if error.contains("access denied") => Observation::AccessDenied,
            Err(error) if error.contains("no operating-system volume") => Observation::Missing,
            Err(_) => Observation::Unparsed,
        }
    }

    fn bitlocker_protection_inner() -> Result<Observation<bool>, String> {
        let _apartment = ComApartment::initialize()?;
        unsafe {
            if let Err(error) = CoInitializeSecurity(
                None,
                -1,
                None,
                None,
                RPC_C_AUTHN_LEVEL_CALL,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                None,
                EOAC_NONE,
                None,
            ) && error.code() != RPC_E_TOO_LATE
            {
                return Err(format!("WMI security initialization failed: {error}"));
            }
            let locator: IWbemLocator = CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER)
                .map_err(|error| format!("WMI locator failed: {error}"))?;
            let empty = BSTR::new();
            let services = locator
                .ConnectServer(
                    &BSTR::from(VOLUME_ENCRYPTION_NAMESPACE),
                    &empty,
                    &empty,
                    &empty,
                    0,
                    &empty,
                    None,
                )
                .map_err(|error| format!("WMI provider access denied or failed: {error}"))?;
            CoSetProxyBlanket(
                &services,
                RPC_C_AUTHN_WINNT,
                RPC_C_AUTHZ_NONE,
                PCWSTR::null(),
                RPC_C_AUTHN_LEVEL_CALL,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                None,
                EOAC_NONE,
            )
            .map_err(|error| format!("WMI proxy access denied or failed: {error}"))?;
            let volumes: IEnumWbemClassObject = services
                .ExecQuery(
                    &BSTR::from("WQL"),
                    &BSTR::from(BITLOCKER_QUERY),
                    WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                    None,
                )
                .map_err(|error| format!("BitLocker WMI query failed: {error}"))?;
            let system_drive = system_drive()?;
            loop {
                let mut values = [None];
                let mut returned = 0_u32;
                volumes
                    .Next(WBEM_INFINITE, &mut values, &raw mut returned)
                    .ok()
                    .map_err(|error| format!("BitLocker WMI enumeration failed: {error}"))?;
                if returned == 0 {
                    break;
                }
                let volume = values[0].take().ok_or("WMI returned an empty volume")?;
                if string_property(&volume, "DriveLetter")? != system_drive {
                    continue;
                }
                let path = string_property(&volume, "__PATH")?;
                return protection_status(&services, &path);
            }
        }
        Err("no operating-system volume was returned by BitLocker WMI".into())
    }

    unsafe fn protection_status(
        services: &windows::Win32::System::Wmi::IWbemServices,
        path: &str,
    ) -> Result<Observation<bool>, String> {
        let mut output = None;
        services
            .ExecMethod(
                &BSTR::from(path),
                &BSTR::from("GetProtectionStatus"),
                WBEM_FLAG_RETURN_IMMEDIATELY,
                None,
                None,
                Some(&raw mut output),
                None,
            )
            .map_err(|error| format!("GetProtectionStatus failed: {error}"))?;
        let output = output.ok_or("GetProtectionStatus returned no output")?;
        match u32_property(&output, "ProtectionStatus")? {
            1 => Ok(Observation::Present(true)),
            0 | 2 => Ok(Observation::Present(false)),
            _ => Ok(Observation::Unparsed),
        }
    }

    unsafe fn string_property(object: &IWbemClassObject, name: &str) -> Result<String, String> {
        let mut value = VARIANT::default();
        let name = wide(name);
        object
            .Get(PCWSTR(name.as_ptr()), 0, &raw mut value, None, None)
            .map_err(|error| format!("WMI property {name:?} failed: {error}"))?;
        let body = variant_body(&value);
        if body.vt != VT_BSTR {
            let _ = VariantClear(&raw mut value);
            return Err("WMI string property had an unexpected type".into());
        }
        let raw = (&raw const body.Anonymous.bstrVal).cast::<BSTR>();
        let result = (*raw).to_string();
        let _ = VariantClear(&raw mut value);
        Ok(result)
    }

    unsafe fn u32_property(object: &IWbemClassObject, name: &str) -> Result<u32, String> {
        let mut value = VARIANT::default();
        let name = wide(name);
        object
            .Get(PCWSTR(name.as_ptr()), 0, &raw mut value, None, None)
            .map_err(|error| format!("WMI property {name:?} failed: {error}"))?;
        let body = variant_body(&value);
        if body.vt != VT_UI4 {
            let _ = VariantClear(&raw mut value);
            return Err("WMI integer property had an unexpected type".into());
        }
        let result = body.Anonymous.ulVal;
        let _ = VariantClear(&raw mut value);
        Ok(result)
    }

    unsafe fn variant_body(value: &VARIANT) -> VARIANT_0_0 {
        std::ptr::read_unaligned(std::ptr::from_ref(&value.Anonymous).cast::<VARIANT_0_0>())
    }

    fn system_drive() -> Result<String, String> {
        use windows::Win32::System::SystemInformation::GetWindowsDirectoryW;

        let mut path = vec![0_u16; 32_768];
        let length = unsafe { GetWindowsDirectoryW(Some(&mut path)) };
        if !(3..u32::try_from(path.len()).expect("path length fits u32")).contains(&length) {
            return Err("Windows directory had an invalid length".into());
        }
        let value = String::from_utf16(&path[..usize::try_from(length).unwrap_or(0)])
            .map_err(|_| "Windows directory was not UTF-16".to_owned())?;
        let bytes = value.as_bytes();
        if bytes.len() < 2 || bytes[1] != b':' || !bytes[0].is_ascii_alphabetic() {
            return Err("Windows directory did not begin with a drive letter".into());
        }
        Ok(value[..2].to_ascii_uppercase())
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(Some(0)).collect()
    }

    struct OwnedKey(HKEY);

    impl Drop for OwnedKey {
        fn drop(&mut self) {
            unsafe {
                let _ = RegCloseKey(self.0);
            }
        }
    }

    struct ComApartment {
        uninitialize: bool,
    }

    impl ComApartment {
        fn initialize() -> Result<Self, String> {
            let result = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
            if result.is_ok() {
                Ok(Self { uninitialize: true })
            } else {
                Err(format!("WMI COM initialization failed: {result}"))
            }
        }
    }

    impl Drop for ComApartment {
        fn drop(&mut self) {
            if self.uninitialize {
                unsafe {
                    CoUninitialize();
                }
            }
        }
    }
}
