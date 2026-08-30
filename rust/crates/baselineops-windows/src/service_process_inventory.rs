//! Shell-free, bounded SCM and `ToolHelp` inventory for capability 30.

use crate::PlatformError;
use baselineops_capabilities::ServiceProcessInventoryObservation;

/// Collect a read-only process and service inventory without invoking a shell.
///
/// # Errors
///
/// Returns [`PlatformError::UnsupportedPlatform`] outside Windows. Enumeration
/// failures that cannot be represented per record return a typed platform error.
pub fn audit_service_process_inventory() -> Result<ServiceProcessInventoryObservation, PlatformError>
{
    platform::audit_service_process_inventory()
}

#[cfg(not(windows))]
mod platform {
    use super::{PlatformError, ServiceProcessInventoryObservation};

    pub(super) fn audit_service_process_inventory()
    -> Result<ServiceProcessInventoryObservation, PlatformError> {
        Err(PlatformError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
mod platform {
    #![allow(unsafe_code, unsafe_op_in_unsafe_fn)]

    use super::{PlatformError, ServiceProcessInventoryObservation};
    use baselineops_capabilities::{Observation, ProcessInventoryRecord, ServiceInventoryRecord};
    use std::mem::size_of;
    use windows::Win32::Foundation::{
        CloseHandle, ERROR_ACCESS_DENIED, ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA, FILETIME,
    };
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
    use windows::Win32::System::Services::{
        CloseServiceHandle, ENUM_SERVICE_STATUS_PROCESSW, EnumServicesStatusExW, OpenSCManagerW,
        OpenServiceW, QUERY_SERVICE_CONFIGW, QueryServiceConfigW, SC_ENUM_PROCESS_INFO,
        SC_MANAGER_ENUMERATE_SERVICE, SERVICE_QUERY_CONFIG, SERVICE_STATE_ALL, SERVICE_WIN32,
    };
    use windows::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
        QueryFullProcessImageNameW,
    };
    use windows::core::PCWSTR;

    const MAX_RECORDS: usize = 4_096;
    const MAX_SERVICE_BUFFER: usize = 4 * 1024 * 1024;
    const MAX_SERVICE_CONFIG: u32 = 64 * 1024;
    const MAX_IMAGE_CHARS: usize = 32_768;

    pub(super) fn audit_service_process_inventory()
    -> Result<ServiceProcessInventoryObservation, PlatformError> {
        unsafe {
            let (processes, process_enumeration_complete) = processes()?;
            let (services, service_enumeration_complete) = services()?;
            Ok(ServiceProcessInventoryObservation {
                processes,
                services,
                process_enumeration_complete,
                service_enumeration_complete,
            })
        }
    }

    unsafe fn processes() -> Result<(Vec<ProcessInventoryRecord>, bool), PlatformError> {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            .map_err(|error| PlatformError::TrustFailure(error.to_string()))?;
        let mut entry = PROCESSENTRY32W {
            dwSize: u32::try_from(size_of::<PROCESSENTRY32W>()).expect("PROCESSENTRY32W fits u32"),
            ..Default::default()
        };
        let first = Process32FirstW(snapshot, &raw mut entry);
        if let Err(error) = first {
            let _ = CloseHandle(snapshot);
            return Err(PlatformError::TrustFailure(error.to_string()));
        }
        let mut records = Vec::new();
        let mut complete = true;
        loop {
            if records.len() == MAX_RECORDS {
                complete = false;
                break;
            }
            records.push(process_record(&entry));
            entry = PROCESSENTRY32W {
                dwSize: u32::try_from(size_of::<PROCESSENTRY32W>())
                    .expect("PROCESSENTRY32W fits u32"),
                ..Default::default()
            };
            if Process32NextW(snapshot, &raw mut entry).is_err() {
                break;
            }
        }
        let _ = CloseHandle(snapshot);
        Ok((records, complete))
    }

    unsafe fn process_record(entry: &PROCESSENTRY32W) -> ProcessInventoryRecord {
        let process_id = entry.th32ProcessID;
        let name = nul_terminated(&entry.szExeFile);
        let handle = match OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            false,
            process_id,
        ) {
            Ok(handle) => handle,
            Err(error) if win32_code(&error) == ERROR_ACCESS_DENIED.0 => {
                return ProcessInventoryRecord {
                    process_id,
                    name,
                    cpu_time_100ns: Observation::AccessDenied,
                    working_set_bytes: Observation::AccessDenied,
                    image_path: Observation::AccessDenied,
                };
            }
            Err(_) => {
                return ProcessInventoryRecord {
                    process_id,
                    name,
                    cpu_time_100ns: Observation::Unparsed,
                    working_set_bytes: Observation::Unparsed,
                    image_path: Observation::Unparsed,
                };
            }
        };
        let record = ProcessInventoryRecord {
            process_id,
            name,
            cpu_time_100ns: process_time(handle),
            working_set_bytes: memory(handle),
            image_path: image_path(handle),
        };
        let _ = CloseHandle(handle);
        record
    }

    unsafe fn process_time(handle: windows::Win32::Foundation::HANDLE) -> Observation<u64> {
        let mut created = FILETIME::default();
        let mut exited = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        match GetProcessTimes(
            handle,
            &raw mut created,
            &raw mut exited,
            &raw mut kernel,
            &raw mut user,
        ) {
            Ok(()) => Observation::Present(filetime(kernel).saturating_add(filetime(user))),
            Err(error) if win32_code(&error) == ERROR_ACCESS_DENIED.0 => Observation::AccessDenied,
            Err(_) => Observation::Unparsed,
        }
    }

    unsafe fn memory(handle: windows::Win32::Foundation::HANDLE) -> Observation<u64> {
        let mut counters = PROCESS_MEMORY_COUNTERS {
            cb: u32::try_from(size_of::<PROCESS_MEMORY_COUNTERS>())
                .expect("memory counters fit u32"),
            ..Default::default()
        };
        match GetProcessMemoryInfo(handle, &raw mut counters, counters.cb) {
            Ok(()) => Observation::Present(counters.WorkingSetSize as u64),
            Err(error) if win32_code(&error) == ERROR_ACCESS_DENIED.0 => Observation::AccessDenied,
            Err(_) => Observation::Unparsed,
        }
    }

    unsafe fn image_path(handle: windows::Win32::Foundation::HANDLE) -> Observation<String> {
        let mut buffer = vec![0_u16; MAX_IMAGE_CHARS];
        let mut length = u32::try_from(buffer.len()).expect("image path buffer fits u32");
        match QueryFullProcessImageNameW(
            handle,
            windows::Win32::System::Threading::PROCESS_NAME_FORMAT::default(),
            windows::core::PWSTR(buffer.as_mut_ptr()),
            &raw mut length,
        ) {
            Ok(()) => Observation::Present(String::from_utf16_lossy(&buffer[..length as usize])),
            Err(error) if win32_code(&error) == ERROR_ACCESS_DENIED.0 => Observation::AccessDenied,
            Err(_) => Observation::Unparsed,
        }
    }

    unsafe fn services() -> Result<(Vec<Observation<ServiceInventoryRecord>>, bool), PlatformError>
    {
        let manager = OpenSCManagerW(None, None, SC_MANAGER_ENUMERATE_SERVICE)
            .map_err(|error| PlatformError::TrustFailure(error.to_string()))?;
        let mut needed = 0_u32;
        let mut returned = 0_u32;
        let probe = EnumServicesStatusExW(
            manager,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            None,
            &raw mut needed,
            &raw mut returned,
            None,
            PCWSTR::null(),
        );
        if !matches!(probe, Err(ref error) if win32_code(error) == ERROR_MORE_DATA.0)
            || needed == 0
            || needed as usize > MAX_SERVICE_BUFFER
        {
            let _ = CloseServiceHandle(manager);
            return Err(PlatformError::TrustFailure(
                "SCM returned an invalid service enumeration size".into(),
            ));
        }
        let allocation = usize::try_from(needed).map_err(|_| {
            PlatformError::TrustFailure(
                "SCM returned an unrepresentable service buffer size".into(),
            )
        })?;
        let word_count = allocation.div_ceil(size_of::<usize>());
        let mut buffer = vec![0_usize; word_count];
        let bytes = std::slice::from_raw_parts_mut(buffer.as_mut_ptr().cast::<u8>(), allocation);
        returned = 0;
        let result = EnumServicesStatusExW(
            manager,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            Some(bytes),
            &raw mut needed,
            &raw mut returned,
            None,
            PCWSTR::null(),
        );
        if let Err(error) = result {
            let _ = CloseServiceHandle(manager);
            return Err(PlatformError::TrustFailure(error.to_string()));
        }
        let rows = service_rows(bytes, returned).ok_or_else(|| {
            PlatformError::TrustFailure("SCM returned malformed service records".into())
        })?;
        let complete = rows.len() <= MAX_RECORDS;
        let records = rows
            .iter()
            .take(MAX_RECORDS)
            .map(|row| service_record(manager, row))
            .collect();
        let _ = CloseServiceHandle(manager);
        Ok((records, complete))
    }

    unsafe fn service_record(
        manager: windows::Win32::System::Services::SC_HANDLE,
        row: &ENUM_SERVICE_STATUS_PROCESSW,
    ) -> Observation<ServiceInventoryRecord> {
        let name = wide_ptr(row.lpServiceName.0);
        let display_name = wide_ptr(row.lpDisplayName.0);
        let service = match OpenServiceW(manager, PCWSTR(row.lpServiceName.0), SERVICE_QUERY_CONFIG)
        {
            Ok(service) => service,
            Err(error) if win32_code(&error) == ERROR_ACCESS_DENIED.0 => {
                return Observation::AccessDenied;
            }
            Err(_) => return Observation::Unparsed,
        };
        let configuration = service_configuration(service);
        let _ = CloseServiceHandle(service);
        match configuration {
            Observation::Present((start_mode, image_path, start_name)) => {
                Observation::Present(ServiceInventoryRecord {
                    name,
                    display_name,
                    state: row.ServiceStatusProcess.dwCurrentState.0,
                    process_id: row.ServiceStatusProcess.dwProcessId,
                    start_mode,
                    image_path,
                    start_name,
                })
            }
            Observation::AccessDenied => Observation::AccessDenied,
            _ => Observation::Unparsed,
        }
    }

    fn service_rows(buffer: &[u8], count: u32) -> Option<&[ENUM_SERVICE_STATUS_PROCESSW]> {
        let count = usize::try_from(count).ok()?;
        let bytes = count.checked_mul(size_of::<ENUM_SERVICE_STATUS_PROCESSW>())?;
        if bytes > buffer.len()
            || !buffer
                .as_ptr()
                .addr()
                .is_multiple_of(std::mem::align_of::<ENUM_SERVICE_STATUS_PROCESSW>())
        {
            return None;
        }
        // SAFETY: the checked record byte count fits the caller-owned buffer and
        // the alignment predicate above holds for the typed slice.
        #[allow(clippy::cast_ptr_alignment)]
        Some(unsafe {
            std::slice::from_raw_parts(
                buffer.as_ptr().cast::<ENUM_SERVICE_STATUS_PROCESSW>(),
                count,
            )
        })
    }

    unsafe fn service_configuration(
        service: windows::Win32::System::Services::SC_HANDLE,
    ) -> Observation<(Observation<u32>, Observation<String>, Observation<String>)> {
        let mut needed = 0_u32;
        let probe = QueryServiceConfigW(service, None, 0, &raw mut needed);
        if !matches!(probe, Err(ref error) if win32_code(error) == ERROR_INSUFFICIENT_BUFFER.0)
            || needed == 0
            || needed > MAX_SERVICE_CONFIG
        {
            return Observation::Unparsed;
        }
        let words = (needed as usize).div_ceil(size_of::<usize>());
        let mut storage = vec![0_usize; words];
        let config = storage.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
        match QueryServiceConfigW(service, Some(config), needed, &raw mut needed) {
            Ok(()) => Observation::Present((
                Observation::Present((*config).dwStartType.0),
                string_observation((*config).lpBinaryPathName.0),
                string_observation((*config).lpServiceStartName.0),
            )),
            Err(error) if win32_code(&error) == ERROR_ACCESS_DENIED.0 => Observation::AccessDenied,
            Err(_) => Observation::Unparsed,
        }
    }

    unsafe fn string_observation(value: *mut u16) -> Observation<String> {
        if value.is_null() {
            Observation::Missing
        } else {
            Observation::Present(wide_ptr(value))
        }
    }

    fn filetime(value: FILETIME) -> u64 {
        (u64::from(value.dwHighDateTime) << 32) | u64::from(value.dwLowDateTime)
    }

    fn win32_code(error: &windows::core::Error) -> u32 {
        u32::from_ne_bytes(error.code().0.to_ne_bytes()) & 0xffff
    }

    unsafe fn wide_ptr(value: *mut u16) -> String {
        if value.is_null() {
            return String::new();
        }
        let mut length = 0_usize;
        while length < MAX_IMAGE_CHARS && *value.add(length) != 0 {
            length += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(value, length))
    }

    fn nul_terminated(value: &[u16]) -> String {
        let length = value
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(value.len());
        String::from_utf16_lossy(&value[..length])
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn non_windows_service_process_observation_is_explicitly_unsupported() {
        #[cfg(not(windows))]
        assert!(matches!(
            super::audit_service_process_inventory(),
            Err(super::PlatformError::UnsupportedPlatform)
        ));
    }
}
