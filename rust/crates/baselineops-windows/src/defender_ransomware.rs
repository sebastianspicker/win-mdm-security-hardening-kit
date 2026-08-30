//! Fixed, read-only Defender WMI acquisition for capability 44.
//!
//! The collector accepts no WQL, namespace, path, command, or mutation input.
//! It intentionally does not invoke PowerShell, `cmd`, shell tools, or Defender
//! remediation APIs. Provider gaps remain typed incomplete evidence.

use crate::PlatformError;
use baselineops_capabilities::DefenderRansomwareObservation;

/// Observe the fixed Defender ransomware and Network Protection properties.
///
/// # Errors
///
/// Returns [`PlatformError::UnsupportedPlatform`] outside Windows. On Windows,
/// provider failures are represented in each fixed field so evaluation fails
/// closed rather than treating unavailable preference data as compliant.
pub fn audit_defender_ransomware() -> Result<DefenderRansomwareObservation, PlatformError> {
    platform::audit_defender_ransomware()
}

#[cfg(not(windows))]
mod platform {
    use super::{DefenderRansomwareObservation, PlatformError};

    #[allow(clippy::unnecessary_wraps)] // Public contract distinguishes unsupported platforms.
    pub(super) fn audit_defender_ransomware() -> Result<DefenderRansomwareObservation, PlatformError>
    {
        Err(PlatformError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
mod platform {
    #![allow(unsafe_code, unsafe_op_in_unsafe_fn)]

    use super::{DefenderRansomwareObservation, PlatformError};
    use baselineops_capabilities::{
        ControlledFolderAccessState, NetworkProtectionState, Observation,
    };
    use windows::Win32::Foundation::{E_ACCESSDENIED, RPC_E_TOO_LATE};
    use windows::Win32::System::Com::{
        CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
        CoInitializeSecurity, CoSetProxyBlanket, CoUninitialize, EOAC_NONE, RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
    };
    use windows::Win32::System::SystemInformation::{GetVersionExW, OSVERSIONINFOEXW};
    use windows::Win32::System::Variant::{
        VARIANT, VARIANT_0_0, VT_BOOL, VT_I2, VT_I4, VT_UI2, VT_UI4, VariantClear,
    };
    use windows::Win32::System::Wmi::{
        IEnumWbemClassObject, IWbemClassObject, IWbemLocator, WBEM_E_NOT_FOUND,
        WBEM_FLAG_FORWARD_ONLY, WBEM_FLAG_RETURN_IMMEDIATELY, WBEM_INFINITE, WbemLocator,
    };
    use windows::core::{BSTR, PCWSTR};

    const DEFENDER_NAMESPACE: &str = r"ROOT\Microsoft\Windows\Defender";
    const PREFERENCE_QUERY: &str = "SELECT EnableControlledFolderAccess, EnableNetworkProtection, AllowNetworkProtectionOnWinServer, AllowNetworkProtectionDownLevel, AllowDatagramProcessingOnWinServer FROM MSFT_MpPreference";
    const RPC_C_AUTHN_WINNT: u32 = 10;
    const RPC_C_AUTHZ_NONE: u32 = 0;

    #[allow(clippy::unnecessary_wraps)] // Public contract distinguishes unsupported platforms.
    pub(super) fn audit_defender_ransomware() -> Result<DefenderRansomwareObservation, PlatformError>
    {
        let provider = provider_evidence();
        Ok(match provider {
            Ok(provider) => DefenderRansomwareObservation {
                controlled_folder_access: provider.controlled_folder_access,
                network_protection: provider.network_protection,
                is_server: product_type(),
                allow_network_protection_on_win_server: provider
                    .allow_network_protection_on_win_server,
                allow_network_protection_down_level: provider.allow_network_protection_down_level,
                allow_datagram_processing_on_win_server: provider
                    .allow_datagram_processing_on_win_server,
            },
            Err(error) => DefenderRansomwareObservation {
                controlled_folder_access: incomplete(&error),
                network_protection: incomplete(&error),
                is_server: product_type(),
                allow_network_protection_on_win_server: incomplete(&error),
                allow_network_protection_down_level: incomplete(&error),
                allow_datagram_processing_on_win_server: incomplete(&error),
            },
        })
    }

    struct ProviderEvidence {
        controlled_folder_access: Observation<ControlledFolderAccessState>,
        network_protection: Observation<NetworkProtectionState>,
        allow_network_protection_on_win_server: Observation<bool>,
        allow_network_protection_down_level: Observation<bool>,
        allow_datagram_processing_on_win_server: Observation<bool>,
    }

    fn provider_evidence() -> Result<ProviderEvidence, Observation<()>> {
        unsafe {
            CoInitializeEx(None, COINIT_MULTITHREADED)
                .ok()
                .map_err(|error| classify(&error))?;
            let result = provider_evidence_initialized();
            CoUninitialize();
            result
        }
    }

    unsafe fn provider_evidence_initialized() -> Result<ProviderEvidence, Observation<()>> {
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
        ) && error.code().0 != RPC_E_TOO_LATE.0
        {
            return Err(classify(&error));
        }
        let locator: IWbemLocator = CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER)
            .map_err(|error| classify(&error))?;
        let empty = BSTR::new();
        let services = locator
            .ConnectServer(
                &BSTR::from(DEFENDER_NAMESPACE),
                &empty,
                &empty,
                &empty,
                0,
                &empty,
                None,
            )
            .map_err(|error| classify(&error))?;
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
        .map_err(|error| classify(&error))?;
        let enumerator: IEnumWbemClassObject = services
            .ExecQuery(
                &BSTR::from("WQL"),
                &BSTR::from(PREFERENCE_QUERY),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                None,
            )
            .map_err(|error| classify(&error))?;
        let mut values = [None];
        let mut returned = 0_u32;
        enumerator
            .Next(WBEM_INFINITE, &mut values, &raw mut returned)
            .ok()
            .map_err(|error| classify(&error))?;
        if returned != 1 {
            return Err(Observation::Missing);
        }
        let object = values[0].take().ok_or(Observation::Unparsed)?;
        let mut additional_values = [None];
        let mut additional_returned = 0_u32;
        enumerator
            .Next(
                WBEM_INFINITE,
                &mut additional_values,
                &raw mut additional_returned,
            )
            .ok()
            .map_err(|error| classify(&error))?;
        if additional_returned != 0 {
            return Err(Observation::Unparsed);
        }
        Ok(ProviderEvidence {
            controlled_folder_access: enum_property(
                &object,
                "EnableControlledFolderAccess",
                ControlledFolderAccessState::from_wmi,
            ),
            network_protection: enum_property(
                &object,
                "EnableNetworkProtection",
                NetworkProtectionState::from_wmi,
            ),
            allow_network_protection_on_win_server: bool_property(
                &object,
                "AllowNetworkProtectionOnWinServer",
            ),
            allow_network_protection_down_level: bool_property(
                &object,
                "AllowNetworkProtectionDownLevel",
            ),
            allow_datagram_processing_on_win_server: bool_property(
                &object,
                "AllowDatagramProcessingOnWinServer",
            ),
        })
    }

    fn product_type() -> Observation<bool> {
        unsafe {
            let mut info = OSVERSIONINFOEXW {
                dwOSVersionInfoSize: u32::try_from(std::mem::size_of::<OSVERSIONINFOEXW>())
                    .expect("OS version structure fits u32"),
                ..Default::default()
            };
            if GetVersionExW((&raw mut info).cast()).is_err() || info.dwPlatformId != 2 {
                return Observation::Unparsed;
            }
            Observation::Present(info.wProductType != 1)
        }
    }

    unsafe fn enum_property<T>(
        object: &IWbemClassObject,
        name: &str,
        convert: impl FnOnce(u32) -> Option<T>,
    ) -> Observation<T> {
        match integer_property(object, name) {
            Ok(Some(value)) => convert(value).map_or(Observation::Unparsed, Observation::Present),
            Ok(None) => Observation::Missing,
            Err(value) => incomplete(&value),
        }
    }

    unsafe fn bool_property(object: &IWbemClassObject, name: &str) -> Observation<bool> {
        let mut value = VARIANT::default();
        let name = wide(name);
        if let Err(error) = object.Get(PCWSTR(name.as_ptr()), 0, &raw mut value, None, None) {
            return if error.code().0 == WBEM_E_NOT_FOUND.0 {
                Observation::Missing
            } else {
                incomplete(&classify(&error))
            };
        }
        let body = variant_body(&value);
        let result = if body.vt == VT_BOOL {
            Observation::Present(body.Anonymous.boolVal.0 != 0)
        } else {
            Observation::Unparsed
        };
        let _ = VariantClear(&raw mut value);
        result
    }

    unsafe fn integer_property(
        object: &IWbemClassObject,
        name: &str,
    ) -> Result<Option<u32>, Observation<()>> {
        let mut value = VARIANT::default();
        let name = wide(name);
        if let Err(error) = object.Get(PCWSTR(name.as_ptr()), 0, &raw mut value, None, None) {
            return if error.code().0 == WBEM_E_NOT_FOUND.0 {
                Ok(None)
            } else {
                Err(classify(&error))
            };
        }
        let body = variant_body(&value);
        let result = if body.vt == VT_UI4 {
            Some(body.Anonymous.ulVal)
        } else if body.vt == VT_I4 {
            u32::try_from(body.Anonymous.lVal).ok()
        } else if body.vt == VT_UI2 {
            Some(u32::from(body.Anonymous.uiVal))
        } else if body.vt == VT_I2 {
            u32::try_from(i32::from(body.Anonymous.iVal)).ok()
        } else {
            None
        };
        let _ = VariantClear(&raw mut value);
        Ok(result)
    }

    unsafe fn variant_body(value: &VARIANT) -> VARIANT_0_0 {
        std::ptr::read_unaligned(std::ptr::from_ref(&value.Anonymous).cast::<VARIANT_0_0>())
    }

    fn classify(error: &windows::core::Error) -> Observation<()> {
        if error.code().0 == E_ACCESSDENIED.0 {
            Observation::AccessDenied
        } else {
            Observation::Unparsed
        }
    }

    fn incomplete<T>(value: &Observation<()>) -> Observation<T> {
        match value {
            Observation::Missing => Observation::Missing,
            Observation::AccessDenied => Observation::AccessDenied,
            Observation::TimedOut => Observation::TimedOut,
            Observation::Truncated => Observation::Truncated,
            Observation::Failed { exit_code } => Observation::Failed {
                exit_code: *exit_code,
            },
            Observation::NotRun => Observation::NotRun,
            Observation::Present(()) | Observation::Unparsed => Observation::Unparsed,
        }
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }
}
