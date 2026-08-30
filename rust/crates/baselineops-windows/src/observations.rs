use crate::PlatformError;
use serde::Serialize;

/// Role reported for the local computer by the `NetAPI` server service.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainRole {
    /// A workgroup or unjoined workstation.
    StandaloneWorkstation,
    /// A domain-joined workstation.
    MemberWorkstation,
    /// A workgroup or unjoined server.
    StandaloneServer,
    /// A domain-joined member server.
    MemberServer,
    /// A backup domain controller.
    BackupDomainController,
    /// A primary domain controller.
    PrimaryDomainController,
}

/// Native identity observation used by capability 28.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct IdentityObservation {
    /// Physical DNS host name.
    pub hostname: String,
    /// Domain or workgroup reported by `NetAPI`.
    pub join_name: String,
    /// Whether Windows reports domain membership.
    pub domain_joined: bool,
    /// Whether Windows reports workgroup membership.
    pub workgroup_joined: bool,
    /// Computer role reported by the local server service.
    pub domain_role: DomainRole,
    /// Operating-system family name.
    pub os_name: String,
    /// Operating-system major/minor version.
    pub os_version: String,
    /// Operating-system build number.
    pub os_build: String,
    /// Windows product name derived from the verified native version.
    pub windows_product: String,
    /// Windows edition SKU derived by the host identity collector.
    pub windows_edition: String,
    /// Native processor architecture.
    pub architecture: String,
    /// Dynamic Windows time-zone key name.
    pub time_zone: String,
}

/// Native Defender observation used by capability 27.
///
/// The optional fields are deliberately distinct from `false`: absent provider
/// evidence is not a healthy result.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct DefenderHealthObservation {
    /// Provider used for the detailed Defender state.
    pub provider: String,
    /// Explicit provider-access failure, if detailed evidence was unavailable.
    pub provider_error: Option<String>,
    /// Whether the `WinDefend` service is running.
    pub service_running: bool,
    /// Raw Service Control Manager state value.
    pub service_state: u32,
    /// Defender service process ID when running.
    pub process_id: u32,
    /// Win32 service exit code.
    pub win32_exit_code: u32,
    /// Antivirus protection state from the Defender provider.
    pub antivirus_enabled: Option<bool>,
    /// Antispyware protection state from the Defender provider.
    pub antispyware_enabled: Option<bool>,
    /// Behavior-monitor state from the Defender provider.
    pub behavior_monitor_enabled: Option<bool>,
    /// Real-time protection state from the Defender provider.
    pub real_time_protection_enabled: Option<bool>,
    /// Whether Defender reports stale signatures.
    pub signatures_out_of_date: Option<bool>,
    /// Antivirus signature age in days.
    pub antivirus_signature_age_days: Option<u32>,
    /// Quick scan age in days; `u32::MAX` means never run.
    pub quick_scan_age_days: Option<u32>,
    /// Full scan age in days; `u32::MAX` means never run.
    pub full_scan_age_days: Option<u32>,
    /// Tamper protection state when the provider exposes it.
    pub tamper_protected: Option<bool>,
    /// Reboot requirement when the provider exposes it.
    pub reboot_required: Option<bool>,
}

/// Observe host and join identity without changing endpoint state.
///
/// # Errors
///
/// Returns an error when the platform is unsupported or a required Windows API
/// observation fails.
pub fn audit_identity() -> Result<IdentityObservation, PlatformError> {
    platform::audit_identity()
}

/// Observe Defender without changing endpoint state.
///
/// The Service Control Manager evidence is always collected where possible.
/// Detailed Defender evidence remains absent until the WMI provider is linked;
/// callers must evaluate absent evidence as non-healthy.
///
/// # Errors
///
/// Returns an error when the platform is unsupported or Service Control Manager
/// access or observation fails.
pub fn audit_defender_health() -> Result<DefenderHealthObservation, PlatformError> {
    platform::audit_defender_health()
}

#[cfg(not(windows))]
mod platform {
    use super::{DefenderHealthObservation, IdentityObservation, PlatformError};

    pub fn audit_identity() -> Result<IdentityObservation, PlatformError> {
        Err(PlatformError::UnsupportedPlatform)
    }

    pub fn audit_defender_health() -> Result<DefenderHealthObservation, PlatformError> {
        Err(PlatformError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
mod platform {
    #![allow(unsafe_code, unsafe_op_in_unsafe_fn)]

    use super::{DefenderHealthObservation, DomainRole, IdentityObservation, PlatformError};
    use std::mem::{MaybeUninit, size_of};
    use windows::Win32::NetworkManagement::NetManagement::{
        NERR_Success, NETSETUP_JOIN_STATUS, NetApiBufferFree, NetGetJoinInformation,
        NetServerGetInfo, NetSetupDomainName, NetSetupWorkgroupName, SERVER_INFO_101,
        SV_TYPE_DOMAIN_BAKCTRL, SV_TYPE_DOMAIN_CTRL, SV_TYPE_SERVER,
    };
    use windows::Win32::System::Com::{
        CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
        CoInitializeSecurity, CoSetProxyBlanket, CoUninitialize, EOAC_NONE, RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
    };
    use windows::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_MANAGER_CONNECT,
        SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_STATUS_PROCESS,
    };
    use windows::Win32::System::Variant::{
        VARIANT, VARIANT_0_0, VT_BOOL, VT_I2, VT_I4, VT_UI2, VT_UI4, VariantClear,
    };
    use windows::Win32::System::Wmi::{
        IEnumWbemClassObject, IWbemClassObject, IWbemLocator, WBEM_E_NOT_FOUND,
        WBEM_FLAG_FORWARD_ONLY, WBEM_FLAG_RETURN_IMMEDIATELY, WBEM_INFINITE, WbemLocator,
    };
    use windows::core::{BSTR, PCWSTR, PWSTR, w};

    const TIME_ZONE_KEY_MAX: usize = 128;
    const RPC_E_TOO_LATE: i32 = -2_147_417_577;
    const RPC_C_AUTHN_WINNT: u32 = 10;
    const RPC_C_AUTHZ_NONE: u32 = 0;

    #[repr(C)]
    struct SystemTime {
        year: u16,
        month: u16,
        day_of_week: u16,
        day: u16,
        hour: u16,
        minute: u16,
        second: u16,
        milliseconds: u16,
    }

    #[repr(C)]
    struct DynamicTimeZoneInformation {
        bias: i32,
        standard_name: [u16; 32],
        standard_date: SystemTime,
        standard_bias: i32,
        daylight_name: [u16; 32],
        daylight_date: SystemTime,
        daylight_bias: i32,
        time_zone_key_name: [u16; TIME_ZONE_KEY_MAX],
        dynamic_daylight_time_disabled: u8,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetDynamicTimeZoneInformation(information: *mut DynamicTimeZoneInformation) -> u32;
    }

    pub fn audit_identity() -> Result<IdentityObservation, PlatformError> {
        unsafe {
            let host = crate::collect_host_identity()?;
            let mut join_name = PWSTR::null();
            let mut status = NETSETUP_JOIN_STATUS::default();
            let result = NetGetJoinInformation(PCWSTR::null(), &raw mut join_name, &raw mut status);
            if result != NERR_Success {
                return Err(os_error(result));
            }
            let join_result = join_name
                .to_string()
                .map_err(|error| PlatformError::TrustFailure(error.to_string()));
            let _ = NetApiBufferFree(Some(join_name.0.cast()));
            let join_name = join_result?;
            let domain_joined = status == NetSetupDomainName;
            let (os_name, os_version, os_build, windows_edition) =
                parse_os_version(&host.os_version)?;
            Ok(IdentityObservation {
                hostname: host.hostname,
                join_name,
                domain_joined,
                workgroup_joined: status == NetSetupWorkgroupName,
                domain_role: domain_role(domain_joined)?,
                windows_product: format!("{os_name} {os_version}"),
                os_name,
                os_version,
                os_build,
                windows_edition,
                architecture: host.architecture,
                time_zone: time_zone_key()?,
            })
        }
    }

    pub fn audit_defender_health() -> Result<DefenderHealthObservation, PlatformError> {
        unsafe {
            let manager = OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
                .map_err(|error| PlatformError::TrustFailure(error.to_string()))?;
            let service_result = OpenServiceW(manager, w!("WinDefend"), SERVICE_QUERY_STATUS);
            let service = match service_result {
                Ok(service) => service,
                Err(error) => {
                    let _ = CloseServiceHandle(manager);
                    return Err(PlatformError::TrustFailure(error.to_string()));
                }
            };
            let mut status = MaybeUninit::<SERVICE_STATUS_PROCESS>::zeroed();
            let buffer = std::slice::from_raw_parts_mut(
                status.as_mut_ptr().cast::<u8>(),
                size_of::<SERVICE_STATUS_PROCESS>(),
            );
            let mut required = 0_u32;
            let query = QueryServiceStatusEx(
                service,
                SC_STATUS_PROCESS_INFO,
                Some(buffer),
                &raw mut required,
            );
            let _ = CloseServiceHandle(service);
            let _ = CloseServiceHandle(manager);
            query.map_err(|error| PlatformError::TrustFailure(error.to_string()))?;
            let status = status.assume_init();
            let evidence = defender_wmi().map_err(|error| error.to_string());
            Ok(DefenderHealthObservation {
                provider: "wmi_msft_mpcomputerstatus".into(),
                provider_error: evidence.as_ref().err().cloned(),
                service_running: status.dwCurrentState == SERVICE_RUNNING,
                service_state: status.dwCurrentState.0,
                process_id: status.dwProcessId,
                win32_exit_code: status.dwWin32ExitCode,
                antivirus_enabled: evidence
                    .as_ref()
                    .ok()
                    .and_then(|item| item.antivirus_enabled),
                antispyware_enabled: evidence
                    .as_ref()
                    .ok()
                    .and_then(|item| item.antispyware_enabled),
                behavior_monitor_enabled: evidence
                    .as_ref()
                    .ok()
                    .and_then(|item| item.behavior_monitor_enabled),
                real_time_protection_enabled: evidence
                    .as_ref()
                    .ok()
                    .and_then(|item| item.real_time_protection_enabled),
                signatures_out_of_date: evidence
                    .as_ref()
                    .ok()
                    .and_then(|item| item.signatures_out_of_date),
                antivirus_signature_age_days: evidence
                    .as_ref()
                    .ok()
                    .and_then(|item| item.antivirus_signature_age_days),
                quick_scan_age_days: evidence
                    .as_ref()
                    .ok()
                    .and_then(|item| item.quick_scan_age_days),
                full_scan_age_days: evidence
                    .as_ref()
                    .ok()
                    .and_then(|item| item.full_scan_age_days),
                tamper_protected: evidence
                    .as_ref()
                    .ok()
                    .and_then(|item| item.tamper_protected),
                reboot_required: evidence.as_ref().ok().and_then(|item| item.reboot_required),
            })
        }
    }

    #[derive(Clone, Debug)]
    struct DefenderProviderEvidence {
        antivirus_enabled: Option<bool>,
        antispyware_enabled: Option<bool>,
        behavior_monitor_enabled: Option<bool>,
        real_time_protection_enabled: Option<bool>,
        signatures_out_of_date: Option<bool>,
        antivirus_signature_age_days: Option<u32>,
        quick_scan_age_days: Option<u32>,
        full_scan_age_days: Option<u32>,
        tamper_protected: Option<bool>,
        reboot_required: Option<bool>,
    }

    fn defender_wmi() -> Result<DefenderProviderEvidence, PlatformError> {
        unsafe {
            CoInitializeEx(None, COINIT_MULTITHREADED)
                .ok()
                .map_err(|error| {
                    PlatformError::TrustFailure(format!(
                        "Defender WMI COM initialization failed: {error}"
                    ))
                })?;
            let result = defender_wmi_initialized();
            CoUninitialize();
            result
        }
    }

    unsafe fn defender_wmi_initialized() -> Result<DefenderProviderEvidence, PlatformError> {
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
        ) && error.code().0 != RPC_E_TOO_LATE
        {
            return Err(PlatformError::TrustFailure(format!(
                "Defender WMI security initialization failed: {error}"
            )));
        }
        let locator: IWbemLocator = CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER)
            .map_err(|error| {
                PlatformError::TrustFailure(format!("Defender WMI locator failed: {error}"))
            })?;
        let empty = BSTR::new();
        let services = locator
            .ConnectServer(
                &BSTR::from("ROOT\\Microsoft\\Windows\\Defender"),
                &empty,
                &empty,
                &empty,
                0,
                &empty,
                None,
            )
            .map_err(|error| {
                PlatformError::TrustFailure(format!("Defender WMI provider access failed: {error}"))
            })?;
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
        .map_err(|error| {
            PlatformError::TrustFailure(format!("Defender WMI proxy setup failed: {error}"))
        })?;
        let query = BSTR::from("SELECT * FROM MSFT_MpComputerStatus");
        let enumerator: IEnumWbemClassObject = services
            .ExecQuery(
                &BSTR::from("WQL"),
                &query,
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                None,
            )
            .map_err(|error| {
                PlatformError::TrustFailure(format!("Defender WMI query failed: {error}"))
            })?;
        let mut objects = [None];
        let mut returned = 0_u32;
        enumerator
            .Next(WBEM_INFINITE, &mut objects, &raw mut returned)
            .ok()
            .map_err(|error| {
                PlatformError::TrustFailure(format!("Defender WMI read failed: {error}"))
            })?;
        if returned != 1 {
            return Err(PlatformError::TrustFailure(
                "Defender WMI provider returned no health instance".into(),
            ));
        }
        let object = objects[0].take().ok_or_else(|| {
            PlatformError::TrustFailure("Defender WMI provider returned an empty instance".into())
        })?;
        Ok(DefenderProviderEvidence {
            antivirus_enabled: bool_property(&object, w!("AntivirusEnabled"))?,
            antispyware_enabled: bool_property(&object, w!("AntispywareEnabled"))?,
            behavior_monitor_enabled: bool_property(&object, w!("BehaviorMonitorEnabled"))?,
            real_time_protection_enabled: bool_property(&object, w!("RealTimeProtectionEnabled"))?,
            signatures_out_of_date: bool_property(&object, w!("DefenderSignaturesOutOfDate"))?,
            antivirus_signature_age_days: age_property(&object, w!("AntivirusSignatureAge"))?,
            quick_scan_age_days: age_property(&object, w!("QuickScanAge"))?,
            full_scan_age_days: age_property(&object, w!("FullScanAge"))?,
            tamper_protected: bool_property(&object, w!("IsTamperProtected"))?,
            reboot_required: bool_property(&object, w!("RebootRequired"))?,
        })
    }

    unsafe fn bool_property(
        object: &IWbemClassObject,
        name: PCWSTR,
    ) -> Result<Option<bool>, PlatformError> {
        let mut value = VARIANT::default();
        if let Err(error) = object.Get(name, 0, &raw mut value, None, None) {
            if error.code().0 == WBEM_E_NOT_FOUND.0 {
                return Ok(None);
            }
            return Err(PlatformError::TrustFailure(format!(
                "Defender WMI property read failed: {error}"
            )));
        }
        let body = variant_body(&value);
        let result = if body.vt == VT_BOOL {
            Some(body.Anonymous.boolVal.0 != 0)
        } else {
            None
        };
        let _ = VariantClear(&raw mut value);
        Ok(result)
    }

    unsafe fn age_property(
        object: &IWbemClassObject,
        name: PCWSTR,
    ) -> Result<Option<u32>, PlatformError> {
        let mut value = VARIANT::default();
        if let Err(error) = object.Get(name, 0, &raw mut value, None, None) {
            if error.code().0 == WBEM_E_NOT_FOUND.0 {
                return Ok(None);
            }
            return Err(PlatformError::TrustFailure(format!(
                "Defender WMI property read failed: {error}"
            )));
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
        const _: () = assert!(std::mem::size_of::<VARIANT>() >= std::mem::size_of::<VARIANT_0_0>());
        std::ptr::read_unaligned(std::ptr::from_ref(&value.Anonymous).cast::<VARIANT_0_0>())
    }

    unsafe fn domain_role(domain_joined: bool) -> Result<DomainRole, PlatformError> {
        let mut buffer = std::ptr::null_mut();
        let result = NetServerGetInfo(PCWSTR::null(), 101, &raw mut buffer);
        if result != NERR_Success || buffer.is_null() {
            return Err(os_error(result));
        }
        // `NetServerGetInfo` level 101 promises a complete `SERVER_INFO_101` buffer.
        let source = std::slice::from_raw_parts(buffer, size_of::<SERVER_INFO_101>());
        let mut storage = MaybeUninit::<SERVER_INFO_101>::uninit();
        std::ptr::copy_nonoverlapping(
            source.as_ptr(),
            storage.as_mut_ptr().cast::<u8>(),
            source.len(),
        );
        let info = storage.assume_init();
        let server_type = info.sv101_type.0;
        let _ = NetApiBufferFree(Some(buffer.cast_const().cast()));
        if server_type & SV_TYPE_DOMAIN_CTRL.0 != 0 {
            Ok(DomainRole::PrimaryDomainController)
        } else if server_type & SV_TYPE_DOMAIN_BAKCTRL.0 != 0 {
            Ok(DomainRole::BackupDomainController)
        } else if server_type & SV_TYPE_SERVER.0 != 0 {
            Ok(if domain_joined {
                DomainRole::MemberServer
            } else {
                DomainRole::StandaloneServer
            })
        } else {
            Ok(if domain_joined {
                DomainRole::MemberWorkstation
            } else {
                DomainRole::StandaloneWorkstation
            })
        }
    }

    unsafe fn time_zone_key() -> Result<String, PlatformError> {
        let mut information = MaybeUninit::<DynamicTimeZoneInformation>::zeroed();
        let _ = GetDynamicTimeZoneInformation(information.as_mut_ptr());
        let information = information.assume_init();
        let length = information
            .time_zone_key_name
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(TIME_ZONE_KEY_MAX);
        if length == 0 {
            return Err(PlatformError::TrustFailure(
                "Windows returned an empty time-zone key".into(),
            ));
        }
        String::from_utf16(&information.time_zone_key_name[..length])
            .map_err(|error| PlatformError::TrustFailure(error.to_string()))
    }

    fn parse_os_version(value: &str) -> Result<(String, String, String, String), PlatformError> {
        let Some(version) = value.strip_prefix("Windows ") else {
            return Err(PlatformError::TrustFailure(
                "unexpected host OS identity".into(),
            ));
        };
        let Some((version_build, edition)) = version.split_once(" edition ") else {
            return Err(PlatformError::TrustFailure(
                "unexpected host OS edition".into(),
            ));
        };
        let mut parts = version_build.split('.');
        let (Some(major), Some(minor), Some(build), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(PlatformError::TrustFailure(
                "unexpected host OS version".into(),
            ));
        };
        Ok((
            "Windows".into(),
            format!("{major}.{minor}"),
            build.into(),
            edition.into(),
        ))
    }

    fn os_error(code: u32) -> PlatformError {
        PlatformError::Io(std::io::Error::from_raw_os_error(
            i32::try_from(code).unwrap_or(i32::MAX),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::DomainRole;

    #[test]
    fn domain_role_has_stable_json_values() {
        assert_eq!(
            serde_json::to_string(&DomainRole::MemberWorkstation).expect("serialize role"),
            "\"member_workstation\""
        );
    }
}
