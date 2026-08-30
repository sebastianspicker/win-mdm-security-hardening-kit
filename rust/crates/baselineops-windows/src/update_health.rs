//! Shell-free, fixed-identity evidence collection for capability 06.
//!
//! This adapter does not inspect packages or the servicing registry, invoke
//! DISM/PowerShell/cmd, enumerate task folders, export task XML, or perform
//! any repair, reset, restart, or task/service mutation.

use crate::PlatformError;
use baselineops_capabilities::UpdateHealthObservation;

/// Read the finite capability-06 evidence set without changing Windows state.
///
/// # Errors
///
/// Returns [`PlatformError::UnsupportedPlatform`] off Windows.  Individual
/// missing, denied, or unparsed service/task/WUA records are retained as
/// observations; initialization failures at a trust boundary fail closed.
pub fn audit_update_health() -> Result<UpdateHealthObservation, PlatformError> {
    #[cfg(windows)]
    {
        platform::audit_update_health()
    }
    #[cfg(not(windows))]
    {
        Err(PlatformError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
mod platform {
    #![allow(unsafe_code, unsafe_op_in_unsafe_fn)]

    use super::{PlatformError, UpdateHealthObservation};
    use baselineops_capabilities::{
        FIXED_UPDATE_HEALTH_SERVICES, FIXED_UPDATE_HEALTH_TASKS, MAX_UPDATE_HISTORY_RECORDS,
        MAX_UPDATE_TITLE_BYTES, Observation, ServiceObservation, ServiceStartMode, ServiceState,
        UpdateAgentMetadata, UpdateHealthService, UpdateHealthTask, UpdateHealthTaskSnapshot,
        UpdateHealthTaskState, UpdateHistoryRecord,
    };
    use std::collections::BTreeMap;
    use std::mem::{MaybeUninit, size_of};
    use windows::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND,
        ERROR_SERVICE_DOES_NOT_EXIST,
    };
    use windows::Win32::System::Com::{
        CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
        CoUninitialize,
    };
    use windows::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QUERY_SERVICE_CONFIGW,
        QueryServiceConfigW, QueryServiceStatusEx, SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO,
        SERVICE_AUTO_START, SERVICE_DEMAND_START, SERVICE_DISABLED, SERVICE_QUERY_CONFIG,
        SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_STATUS_PROCESS,
    };
    use windows::Win32::System::TaskScheduler::{
        IRegisteredTask, ITaskFolder, ITaskService, TASK_STATE_DISABLED, TASK_STATE_QUEUED,
        TASK_STATE_READY, TASK_STATE_RUNNING, TaskScheduler,
    };
    use windows::Win32::System::UpdateAgent::{IUpdateSession, UpdateSession};
    use windows::Win32::System::Variant::VARIANT;
    use windows::core::{BSTR, Error, PCWSTR, w};

    pub(super) fn audit_update_health() -> Result<UpdateHealthObservation, PlatformError> {
        let apartment = ComApartment::initialize()?;
        let result = unsafe { observe() };
        drop(apartment);
        result
    }

    unsafe fn observe() -> Result<UpdateHealthObservation, PlatformError> {
        Ok(UpdateHealthObservation {
            services: observe_services()?,
            tasks: observe_tasks()?,
            update_agent: observe_update_agent(),
        })
    }

    unsafe fn observe_services()
    -> Result<BTreeMap<UpdateHealthService, Observation<ServiceObservation>>, PlatformError> {
        let manager = OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
            .map_err(|error| platform_error(&error))?;
        let values = FIXED_UPDATE_HEALTH_SERVICES
            .into_iter()
            .map(|service| (service, observe_service(manager, service)))
            .collect();
        let _ = CloseServiceHandle(manager);
        Ok(values)
    }

    unsafe fn observe_service(
        manager: windows::Win32::System::Services::SC_HANDLE,
        requested: UpdateHealthService,
    ) -> Observation<ServiceObservation> {
        let handle = match OpenServiceW(
            manager,
            service_name(requested),
            SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG,
        ) {
            Ok(handle) => handle,
            Err(error) => return observation_error(&error),
        };
        let result =
            service_snapshot(handle, requested).unwrap_or_else(|error| observation_error(&error));
        let _ = CloseServiceHandle(handle);
        result
    }

    unsafe fn service_snapshot(
        service: windows::Win32::System::Services::SC_HANDLE,
        requested: UpdateHealthService,
    ) -> Result<Observation<ServiceObservation>, Error> {
        let mut status = MaybeUninit::<SERVICE_STATUS_PROCESS>::zeroed();
        let buffer = std::slice::from_raw_parts_mut(
            status.as_mut_ptr().cast::<u8>(),
            size_of::<SERVICE_STATUS_PROCESS>(),
        );
        let mut required = 0_u32;
        QueryServiceStatusEx(
            service,
            SC_STATUS_PROCESS_INFO,
            Some(buffer),
            &raw mut required,
        )?;
        let mut required = 0_u32;
        let _ = QueryServiceConfigW(service, None, 0, &raw mut required);
        if required == 0 || required > 64 * 1024 {
            return Ok(Observation::Unparsed);
        }
        let words = usize::try_from(required)
            .unwrap_or(0)
            .div_ceil(size_of::<usize>());
        let mut storage = vec![0_usize; words];
        let config = storage.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
        QueryServiceConfigW(service, Some(config), required, &raw mut required)?;
        let status = status.assume_init();
        Ok(Observation::Present(ServiceObservation {
            name: requested.name().into(),
            state: if status.dwCurrentState == SERVICE_RUNNING {
                ServiceState::Running
            } else if status.dwCurrentState.0 == 1 {
                ServiceState::Stopped
            } else {
                ServiceState::Other(status.dwCurrentState.0)
            },
            start_mode: service_start_mode((&*config).dwStartType.0),
        }))
    }

    unsafe fn observe_tasks()
    -> Result<BTreeMap<UpdateHealthTask, Observation<UpdateHealthTaskSnapshot>>, PlatformError>
    {
        let scheduler: ITaskService = CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER)
            .map_err(|error| platform_error(&error))?;
        let empty = VARIANT::default();
        scheduler
            .Connect(&empty, &empty, &empty, &empty)
            .map_err(|error| platform_error(&error))?;
        let root = scheduler
            .GetFolder(&BSTR::from("\\"))
            .map_err(|error| platform_error(&error))?;
        Ok(FIXED_UPDATE_HEALTH_TASKS
            .into_iter()
            .map(|task| (task, observe_task(&root, task)))
            .collect())
    }

    unsafe fn observe_task(
        root: &ITaskFolder,
        task: UpdateHealthTask,
    ) -> Observation<UpdateHealthTaskSnapshot> {
        match root.GetTask(&BSTR::from(task.path())) {
            Ok(task) => Observation::Present(task_snapshot(&task)),
            Err(error) => observation_error(&error),
        }
    }

    unsafe fn task_snapshot(task: &IRegisteredTask) -> UpdateHealthTaskSnapshot {
        UpdateHealthTaskSnapshot {
            enabled: task.Enabled().map_or_else(
                |error| observation_error(&error),
                |value| Observation::Present(value.as_bool()),
            ),
            state: task
                .State()
                .map_or_else(|error| observation_error(&error), task_state),
        }
    }

    unsafe fn observe_update_agent() -> Observation<UpdateAgentMetadata> {
        let session: IUpdateSession =
            match CoCreateInstance(&UpdateSession, None, CLSCTX_INPROC_SERVER) {
                Ok(session) => session,
                Err(error) => return observation_error(&error),
            };
        let searcher = match session.CreateUpdateSearcher() {
            Ok(searcher) => searcher,
            Err(error) => return observation_error(&error),
        };
        let total = match searcher.GetTotalHistoryCount() {
            Ok(total) if total >= 0 => usize::try_from(total).unwrap_or(usize::MAX),
            Ok(_) => return Observation::Unparsed,
            Err(error) => return observation_error(&error),
        };
        let count = total.min(MAX_UPDATE_HISTORY_RECORDS);
        let history = match searcher.QueryHistory(0, i32::try_from(count).unwrap_or(0)) {
            Ok(history) => history,
            Err(error) => return observation_error(&error),
        };
        let mut records = Vec::with_capacity(count);
        for index in 0..count {
            let entry = match history.get_Item(i32::try_from(index).unwrap_or(0)) {
                Ok(entry) => entry,
                Err(error) => return observation_error(&error),
            };
            let title = match entry.Title() {
                Ok(title) => bounded_title(&title.to_string()),
                Err(error) => return observation_error(&error),
            };
            let result_code = match entry.ResultCode() {
                Ok(value) => value.0,
                Err(error) => return observation_error(&error),
            };
            let hresult = match entry.HResult() {
                Ok(value) => value,
                Err(error) => return observation_error(&error),
            };
            records.push(UpdateHistoryRecord {
                title,
                result_code,
                hresult,
            });
        }
        Observation::Present(UpdateAgentMetadata {
            total_history_count: u32::try_from(total).unwrap_or(u32::MAX),
            recent_history: records,
        })
    }

    fn bounded_title(value: &str) -> String {
        if value.len() <= MAX_UPDATE_TITLE_BYTES {
            return value.into();
        }
        let mut end = MAX_UPDATE_TITLE_BYTES;
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        value[..end].into()
    }

    fn task_state(
        value: windows::Win32::System::TaskScheduler::TASK_STATE,
    ) -> Observation<UpdateHealthTaskState> {
        Observation::Present(if value == TASK_STATE_DISABLED {
            UpdateHealthTaskState::Disabled
        } else if value == TASK_STATE_QUEUED {
            UpdateHealthTaskState::Queued
        } else if value == TASK_STATE_READY {
            UpdateHealthTaskState::Ready
        } else if value == TASK_STATE_RUNNING {
            UpdateHealthTaskState::Running
        } else {
            UpdateHealthTaskState::Unknown
        })
    }

    fn service_start_mode(value: u32) -> ServiceStartMode {
        if value == SERVICE_AUTO_START.0 {
            ServiceStartMode::Automatic
        } else if value == SERVICE_DEMAND_START.0 {
            ServiceStartMode::Manual
        } else if value == SERVICE_DISABLED.0 {
            ServiceStartMode::Disabled
        } else {
            ServiceStartMode::Other(value)
        }
    }

    fn service_name(service: UpdateHealthService) -> PCWSTR {
        match service {
            UpdateHealthService::UpdateHealth => w!("uhssvc"),
            UpdateHealthService::UpdateOrchestrator => w!("UsoSvc"),
            UpdateHealthService::WindowsUpdateMedic => w!("WaaSMedicSvc"),
            UpdateHealthService::WindowsUpdate => w!("wuauserv"),
            UpdateHealthService::DeliveryOptimization => w!("DoSvc"),
            UpdateHealthService::Bits => w!("BITS"),
            UpdateHealthService::CryptographicServices => w!("cryptsvc"),
        }
    }

    fn observation_error<T>(error: &Error) -> Observation<T> {
        match win32_code(error) {
            value
                if value == ERROR_SERVICE_DOES_NOT_EXIST.0
                    || value == ERROR_FILE_NOT_FOUND.0
                    || value == ERROR_PATH_NOT_FOUND.0 =>
            {
                Observation::Missing
            }
            value if value == ERROR_ACCESS_DENIED.0 => Observation::AccessDenied,
            _ => Observation::Unparsed,
        }
    }

    fn platform_error(error: &Error) -> PlatformError {
        PlatformError::TrustFailure(format!("fixed Update Health observation failed: {error}"))
    }

    fn win32_code(error: &Error) -> u32 {
        u32::from_ne_bytes(error.code().0.to_ne_bytes()) & 0xffff
    }

    struct ComApartment;

    impl ComApartment {
        fn initialize() -> Result<Self, PlatformError> {
            unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) }
                .ok()
                .map(|()| Self)
                .map_err(|error| platform_error(&error))
        }
    }

    impl Drop for ComApartment {
        fn drop(&mut self) {
            unsafe { CoUninitialize() };
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn non_windows_update_health_observation_is_explicitly_unsupported() {
        #[cfg(not(windows))]
        assert!(matches!(
            super::audit_update_health(),
            Err(super::PlatformError::UnsupportedPlatform)
        ));
    }
}
