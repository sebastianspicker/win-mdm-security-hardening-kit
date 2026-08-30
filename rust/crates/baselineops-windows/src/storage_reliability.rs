//! Fixed Windows Storage WMI observation for capability 35.

use crate::PlatformError;
use baselineops_capabilities::StorageReliabilityObservation;
#[cfg(windows)]
use baselineops_capabilities::{Observation, PhysicalDiskObservation, ReliabilityCounters};

/// Observe physical-disk health and reliability counters without mutation.
///
/// Provider failures become incomplete evidence, so the policy layer cannot
/// infer a healthy disk from an unavailable controller or Storage namespace.
///
/// # Errors
///
/// Returns [`PlatformError::UnsupportedPlatform`] outside Windows.
pub fn audit_storage_reliability() -> Result<StorageReliabilityObservation, PlatformError> {
    #[cfg(windows)]
    {
        Ok(platform::audit())
    }
    #[cfg(not(windows))]
    {
        Err(PlatformError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
mod platform {
    #![allow(unsafe_code, unsafe_op_in_unsafe_fn)]

    use super::{Observation, PhysicalDiskObservation, ReliabilityCounters};
    use baselineops_capabilities::StorageReliabilityObservation;
    use std::collections::BTreeMap;
    use windows::Win32::Foundation::RPC_E_TOO_LATE;
    use windows::Win32::System::Com::{
        CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
        CoInitializeSecurity, CoSetProxyBlanket, CoUninitialize, EOAC_NONE, RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
    };
    use windows::Win32::System::Variant::{
        VARIANT, VARIANT_0_0, VT_BSTR, VT_UI2, VT_UI4, VT_UI8, VariantClear,
    };
    use windows::Win32::System::Wmi::{
        IEnumWbemClassObject, IWbemClassObject, IWbemLocator, IWbemServices,
        WBEM_FLAG_FORWARD_ONLY, WBEM_FLAG_RETURN_IMMEDIATELY, WBEM_INFINITE, WbemLocator,
    };
    use windows::core::{BSTR, PCWSTR};

    const NAMESPACE: &str = r"ROOT\Microsoft\Windows\Storage";
    const DISKS: &str = "SELECT DeviceId, HealthStatus, OperationalStatus FROM MSFT_PhysicalDisk";
    const COUNTERS: &str = "SELECT DeviceId, Temperature, Wear, ReadErrorsTotal, WriteErrorsTotal, UncorrectableErrors FROM MSFT_StorageReliabilityCounter";
    const RPC_C_AUTHN_WINNT: u32 = 10;
    const RPC_C_AUTHZ_NONE: u32 = 0;

    pub(super) fn audit() -> StorageReliabilityObservation {
        let result = unsafe { observe() };
        result.unwrap_or(StorageReliabilityObservation {
            physical_disks: Observation::Unparsed,
        })
    }

    unsafe fn observe() -> Result<StorageReliabilityObservation, String> {
        let _apartment = ComApartment::initialize()?;
        initialize_security()?;
        let services = services()?;
        let counters = query(&services, COUNTERS)?
            .into_iter()
            .filter_map(|object| counter(&object).ok())
            .collect::<BTreeMap<_, _>>();
        let mut disks = Vec::new();
        for object in query(&services, DISKS)? {
            let id = string_property(&object, "DeviceId")?;
            disks.push(PhysicalDiskObservation {
                health_healthy: health(&object),
                operational_ok: operational(&object),
                reliability: counters
                    .get(&id)
                    .cloned()
                    .map_or(Observation::Missing, Observation::Present),
                id,
            });
        }
        Ok(StorageReliabilityObservation {
            physical_disks: Observation::Present(disks),
        })
    }

    unsafe fn initialize_security() -> Result<(), String> {
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
        Ok(())
    }

    unsafe fn services() -> Result<IWbemServices, String> {
        let locator: IWbemLocator = CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER)
            .map_err(|error| format!("WMI locator failed: {error}"))?;
        let empty = BSTR::new();
        let services = locator
            .ConnectServer(
                &BSTR::from(NAMESPACE),
                &empty,
                &empty,
                &empty,
                0,
                &empty,
                None,
            )
            .map_err(|error| format!("Storage WMI provider failed: {error}"))?;
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
        .map_err(|error| format!("Storage WMI proxy failed: {error}"))?;
        Ok(services)
    }

    unsafe fn query(services: &IWbemServices, text: &str) -> Result<Vec<IWbemClassObject>, String> {
        let enumeration: IEnumWbemClassObject = services
            .ExecQuery(
                &BSTR::from("WQL"),
                &BSTR::from(text),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                None,
            )
            .map_err(|error| format!("Storage WMI query failed: {error}"))?;
        let mut values = Vec::new();
        loop {
            let mut object: [Option<IWbemClassObject>; 1] = [None];
            let mut returned = 0_u32;
            enumeration
                .Next(WBEM_INFINITE, &mut object, &raw mut returned)
                .ok()
                .map_err(|error| format!("Storage WMI enumeration failed: {error}"))?;
            if returned == 0 {
                break;
            }
            values.push(
                object[0]
                    .take()
                    .ok_or("Storage WMI returned an empty object")?,
            );
        }
        Ok(values)
    }

    unsafe fn counter(object: &IWbemClassObject) -> Result<(String, ReliabilityCounters), String> {
        Ok((
            string_property(object, "DeviceId")?,
            ReliabilityCounters {
                temperature_c: u64_property(object, "Temperature")
                    .and_then(|value| {
                        u16::try_from(value).map_err(|_| "Temperature exceeded u16".into())
                    })
                    .map_or(Observation::Unparsed, Observation::Present),
                wear_percent_remaining: u64_property(object, "Wear")
                    .and_then(|value| u8::try_from(value).map_err(|_| "Wear exceeded u8".into()))
                    .map_or(Observation::Unparsed, Observation::Present),
                uncorrectable_errors: u64_property(object, "UncorrectableErrors")
                    .map_or(Observation::Unparsed, Observation::Present),
                read_errors: u64_property(object, "ReadErrorsTotal")
                    .map_or(Observation::Unparsed, Observation::Present),
                write_errors: u64_property(object, "WriteErrorsTotal")
                    .map_or(Observation::Unparsed, Observation::Present),
            },
        ))
    }

    unsafe fn health(object: &IWbemClassObject) -> Observation<bool> {
        u64_property(object, "HealthStatus")
            .map(|value| value == 0 || value == 1)
            .map_or(Observation::Unparsed, Observation::Present)
    }
    unsafe fn operational(object: &IWbemClassObject) -> Observation<bool> {
        u64_property(object, "OperationalStatus")
            .map(|value| value == 2)
            .map_or(Observation::Unparsed, Observation::Present)
    }

    unsafe fn string_property(object: &IWbemClassObject, name: &str) -> Result<String, String> {
        let mut value = VARIANT::default();
        let wide = wide(name);
        object
            .Get(PCWSTR(wide.as_ptr()), 0, &raw mut value, None, None)
            .map_err(|error| format!("WMI {name} failed: {error}"))?;
        let body = variant_body(&value);
        if body.vt != VT_BSTR {
            let _ = VariantClear(&raw mut value);
            return Err(format!("WMI {name} was not a string"));
        }
        let result = (*(&raw const body.Anonymous.bstrVal).cast::<BSTR>()).to_string();
        let _ = VariantClear(&raw mut value);
        Ok(result)
    }

    unsafe fn u64_property(object: &IWbemClassObject, name: &str) -> Result<u64, String> {
        let mut value = VARIANT::default();
        let wide = wide(name);
        object
            .Get(PCWSTR(wide.as_ptr()), 0, &raw mut value, None, None)
            .map_err(|error| format!("WMI {name} failed: {error}"))?;
        let body = variant_body(&value);
        let result = match body.vt {
            VT_UI2 => Ok(u64::from(body.Anonymous.uiVal)),
            VT_UI4 => Ok(u64::from(body.Anonymous.ulVal)),
            VT_UI8 => Ok(body.Anonymous.ullVal),
            _ => Err(format!("WMI {name} was not an unsigned integer")),
        };
        let _ = VariantClear(&raw mut value);
        result
    }
    unsafe fn variant_body(value: &VARIANT) -> VARIANT_0_0 {
        std::ptr::read_unaligned(std::ptr::from_ref(&value.Anonymous).cast::<VARIANT_0_0>())
    }
    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(Some(0)).collect()
    }
    struct ComApartment;
    impl ComApartment {
        fn initialize() -> Result<Self, String> {
            let status = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
            if status.is_ok() {
                Ok(Self)
            } else {
                Err(format!("WMI COM initialization failed: {status}"))
            }
        }
    }
    impl Drop for ComApartment {
        fn drop(&mut self) {
            unsafe {
                CoUninitialize();
            }
        }
    }
}
