//! Typed, read-only Service Control Manager observations for fixed service names.

use crate::PlatformError;
use baselineops_capabilities::{Observation, ServiceObservation};

/// Fixed service identities available to native read-only capability waves.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KnownService {
    /// Windows Time service used by capability 34.
    WindowsTime,
    /// Windows Remote Management service used by capability 45.
    WinRm,
    /// OpenSSH server service used by capability 37.
    OpenSshServer,
    /// Remote Desktop Services used by capability 37.
    RemoteDesktop,
    /// SMB server service used by capability 37.
    SmbServer,
    /// Application Identity service used by capability 51.
    ApplicationIdentity,
}

/// Read one fixed SCM service without changing its status or configuration.
///
/// Missing and access-denied services are typed observations. Other platform
/// failures remain errors because their meaning cannot be safely normalized.
///
/// # Errors
///
/// Returns an error for unsupported hosts or SCM failures other than missing
/// service and access denied.
pub fn observe_service(
    service: KnownService,
) -> Result<Observation<ServiceObservation>, PlatformError> {
    platform::observe_service(service)
}

#[cfg(not(windows))]
mod platform {
    use super::{KnownService, Observation, PlatformError, ServiceObservation};

    pub(super) fn observe_service(
        _service: KnownService,
    ) -> Result<Observation<ServiceObservation>, PlatformError> {
        Err(PlatformError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
mod platform {
    #![allow(unsafe_code, unsafe_op_in_unsafe_fn)]

    use super::{KnownService, Observation, PlatformError, ServiceObservation};
    use baselineops_capabilities::{ServiceStartMode, ServiceState};
    use std::mem::{MaybeUninit, size_of};
    use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_SERVICE_DOES_NOT_EXIST};
    use windows::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QUERY_SERVICE_CONFIGW,
        QueryServiceConfigW, QueryServiceStatusEx, SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO,
        SERVICE_AUTO_START, SERVICE_DEMAND_START, SERVICE_DISABLED, SERVICE_QUERY_CONFIG,
        SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_STATUS_PROCESS,
    };
    use windows::core::{PCWSTR, w};

    const fn name(service: KnownService) -> &'static str {
        match service {
            KnownService::WindowsTime => "w32time",
            KnownService::WinRm => "WinRM",
            KnownService::OpenSshServer => "sshd",
            KnownService::RemoteDesktop => "TermService",
            KnownService::SmbServer => "LanmanServer",
            KnownService::ApplicationIdentity => "AppIDSvc",
        }
    }

    pub(super) fn observe_service(
        requested: KnownService,
    ) -> Result<Observation<ServiceObservation>, PlatformError> {
        unsafe {
            let manager = match OpenSCManagerW(None, None, SC_MANAGER_CONNECT) {
                Ok(handle) => handle,
                Err(error) => return map_open_error(&error),
            };
            let service = match OpenServiceW(
                manager,
                wide_name(requested),
                SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG,
            ) {
                Ok(handle) => handle,
                Err(error) => {
                    let _ = CloseServiceHandle(manager);
                    return map_open_error(&error);
                }
            };
            let result = observe_open_service(service, requested);
            let _ = CloseServiceHandle(service);
            let _ = CloseServiceHandle(manager);
            result
        }
    }

    unsafe fn observe_open_service(
        service: windows::Win32::System::Services::SC_HANDLE,
        requested: KnownService,
    ) -> Result<Observation<ServiceObservation>, PlatformError> {
        let mut status = MaybeUninit::<SERVICE_STATUS_PROCESS>::zeroed();
        let buffer = std::slice::from_raw_parts_mut(
            status.as_mut_ptr().cast::<u8>(),
            size_of::<SERVICE_STATUS_PROCESS>(),
        );
        let mut required = 0_u32;
        if let Err(error) = QueryServiceStatusEx(
            service,
            SC_STATUS_PROCESS_INFO,
            Some(buffer),
            &raw mut required,
        ) {
            return map_open_error(&error);
        }
        let mut required = 0_u32;
        let _ = QueryServiceConfigW(service, None, 0, &raw mut required);
        if required == 0 || required > 64 * 1024 {
            return Err(PlatformError::TrustFailure(
                "SCM returned an invalid service config size".into(),
            ));
        }
        let word_count = usize::try_from(required)
            .unwrap_or(0)
            .div_ceil(size_of::<usize>());
        let mut storage = vec![0_usize; word_count];
        let config = storage.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
        if let Err(error) = QueryServiceConfigW(service, Some(config), required, &raw mut required)
        {
            return map_open_error(&error);
        }
        let status = status.assume_init();
        let config = &*config;
        Ok(Observation::Present(ServiceObservation {
            name: name(requested).into(),
            state: if status.dwCurrentState == SERVICE_RUNNING {
                ServiceState::Running
            } else if status.dwCurrentState.0 == 1 {
                ServiceState::Stopped
            } else {
                ServiceState::Other(status.dwCurrentState.0)
            },
            start_mode: start_mode(config.dwStartType.0),
        }))
    }

    fn map_open_error(
        error: &windows::core::Error,
    ) -> Result<Observation<ServiceObservation>, PlatformError> {
        match win32_code(error) {
            value if value == ERROR_SERVICE_DOES_NOT_EXIST.0 => Ok(Observation::Missing),
            value if value == ERROR_ACCESS_DENIED.0 => Ok(Observation::AccessDenied),
            _ => Err(PlatformError::TrustFailure(error.to_string())),
        }
    }

    fn start_mode(value: u32) -> ServiceStartMode {
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

    fn wide_name(service: KnownService) -> PCWSTR {
        match service {
            KnownService::WindowsTime => w!("w32time"),
            KnownService::WinRm => w!("WinRM"),
            KnownService::OpenSshServer => w!("sshd"),
            KnownService::RemoteDesktop => w!("TermService"),
            KnownService::SmbServer => w!("LanmanServer"),
            KnownService::ApplicationIdentity => w!("AppIDSvc"),
        }
    }

    fn win32_code(error: &windows::core::Error) -> u32 {
        u32::from_ne_bytes(error.code().0.to_ne_bytes()) & 0xffff
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn non_windows_service_observation_is_explicitly_unsupported() {
        #[cfg(not(windows))]
        assert!(matches!(
            super::observe_service(super::KnownService::WinRm),
            Err(super::PlatformError::UnsupportedPlatform)
        ));
    }
}
