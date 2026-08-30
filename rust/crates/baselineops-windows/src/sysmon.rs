//! Fixed, shell-free Sysmon acquisition for capabilities 16 and 17.
//!
//! The adapter queries only `Sysmon64` and `Sysmon` through SCM and a fixed
//! local Operational Event Log selector. It never starts, stops, installs,
//! updates, uninstalls, quarantines, or invokes Sysmon; configuration XML and
//! service command-line arguments are neither retained nor interpreted.

use crate::PlatformError;
#[cfg(windows)]
use crate::audit_event_log;
#[cfg(windows)]
use baselineops_capabilities::Observation;
use baselineops_capabilities::SysmonObservation;
#[cfg(any(windows, test))]
use baselineops_capabilities::{
    EventLogQueryParameters, MAX_SYSMON_EVENT_XML_BYTES, MAX_SYSMON_EVENTS, SYSMON_EVENT_TIMEOUT_MS,
};

#[cfg(any(windows, test))]
const SYSMON_CHANNEL: &str = "Microsoft-Windows-Sysmon/Operational";
#[cfg(any(windows, test))]
const SYSMON_XPATH: &str = "*[System[Provider[@Name='Microsoft-Windows-Sysmon'] and (EventID=4 or EventID=16 or EventID=255)]]";
#[cfg(windows)]
const MAX_SYSMON_IMAGE_BYTES: u64 = 256 * 1024 * 1024;
#[cfg(windows)]
const MICROSOFT_SUBJECT: &str =
    "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US";

/// Collect bounded native Sysmon evidence without changing endpoint state.
///
/// # Errors
///
/// Returns [`PlatformError::UnsupportedPlatform`] outside Windows. Missing,
/// denied, malformed, oversized, untrusted, and truncated evidence is retained
/// in [`baselineops_capabilities::Observation`] values whenever it can be
/// represented safely.
pub fn audit_sysmon(include_operational_events: bool) -> Result<SysmonObservation, PlatformError> {
    #[cfg(windows)]
    {
        Ok(SysmonObservation {
            services: platform::observe_services()?,
            // The legacy `-c` runtime dump is a process invocation, so there is
            // no stable native config-hash source in this read-only foundation.
            config_hash_indicator: Observation::NotRun,
            operational_events: if include_operational_events {
                Observation::Present(audit_event_log(&fixed_event_query())?)
            } else {
                Observation::NotRun
            },
        })
    }
    #[cfg(not(windows))]
    {
        let _ = include_operational_events;
        Err(PlatformError::UnsupportedPlatform)
    }
}

#[cfg(any(windows, test))]
fn fixed_event_query() -> EventLogQueryParameters {
    EventLogQueryParameters {
        channel: SYSMON_CHANNEL.into(),
        xpath: SYSMON_XPATH.into(),
        max_records: MAX_SYSMON_EVENTS,
        timeout_ms: SYSMON_EVENT_TIMEOUT_MS,
        max_xml_bytes: MAX_SYSMON_EVENT_XML_BYTES,
        max_message_bytes: 0,
    }
}

#[cfg(windows)]
mod platform {
    #![allow(unsafe_code, unsafe_op_in_unsafe_fn)]

    use super::{MAX_SYSMON_IMAGE_BYTES, MICROSOFT_SUBJECT};
    use crate::{PathPolicy, PlatformError, verify_authenticode_subject};
    use baselineops_capabilities::{
        Observation, ServiceStartMode, ServiceState, SysmonBinaryEvidence, SysmonImageEvidence,
        SysmonServiceIdentity, SysmonServiceObservation, SysmonSignatureEvidence,
    };
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, File},
        io::{self, Read},
        mem::{MaybeUninit, size_of},
        path::{Component, Path, PathBuf},
    };
    use windows::{
        Win32::{
            Foundation::{ERROR_ACCESS_DENIED, ERROR_SERVICE_DOES_NOT_EXIST},
            System::Services::{
                CloseServiceHandle, OpenSCManagerW, OpenServiceW, QUERY_SERVICE_CONFIGW,
                QueryServiceConfigW, QueryServiceStatusEx, SC_MANAGER_CONNECT,
                SC_STATUS_PROCESS_INFO, SERVICE_AUTO_START, SERVICE_DEMAND_START, SERVICE_DISABLED,
                SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_RUNNING,
                SERVICE_STATUS_PROCESS,
            },
        },
        core::{PCWSTR, w},
    };

    pub(super) fn observe_services()
    -> Result<Vec<Observation<SysmonServiceObservation>>, PlatformError> {
        unsafe {
            let manager = match OpenSCManagerW(None, None, SC_MANAGER_CONNECT) {
                Ok(manager) => manager,
                Err(error) => return shared_manager_error(&error),
            };
            let mut services = Vec::with_capacity(2);
            for identity in [
                SysmonServiceIdentity::Sysmon64,
                SysmonServiceIdentity::Sysmon,
            ] {
                services.push(observe_service(manager, identity)?);
            }
            let _ = CloseServiceHandle(manager);
            Ok(services)
        }
    }

    unsafe fn observe_service(
        manager: windows::Win32::System::Services::SC_HANDLE,
        identity: SysmonServiceIdentity,
    ) -> Result<Observation<SysmonServiceObservation>, PlatformError> {
        let service = match OpenServiceW(
            manager,
            wide_name(identity),
            SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG,
        ) {
            Ok(service) => service,
            Err(error) => return map_open_error(&error),
        };
        let result = observe_open_service(service, identity);
        let _ = CloseServiceHandle(service);
        result
    }

    unsafe fn observe_open_service(
        service: windows::Win32::System::Services::SC_HANDLE,
        identity: SysmonServiceIdentity,
    ) -> Result<Observation<SysmonServiceObservation>, PlatformError> {
        let mut status = MaybeUninit::<SERVICE_STATUS_PROCESS>::zeroed();
        let status_buffer = std::slice::from_raw_parts_mut(
            status.as_mut_ptr().cast::<u8>(),
            size_of::<SERVICE_STATUS_PROCESS>(),
        );
        let mut returned = 0_u32;
        if let Err(error) = QueryServiceStatusEx(
            service,
            SC_STATUS_PROCESS_INFO,
            Some(status_buffer),
            &raw mut returned,
        ) {
            return map_open_error(&error);
        }
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
        if let Err(error) = QueryServiceConfigW(service, Some(config), required, &raw mut required)
        {
            return map_open_error(&error);
        }
        let status = status.assume_init();
        let config = &*config;
        let binary = config
            .lpBinaryPathName
            .to_string()
            .ok()
            .map_or(Observation::Unparsed, |value| {
                binary_evidence(&value, identity)
            });
        Ok(Observation::Present(SysmonServiceObservation {
            identity,
            state: if status.dwCurrentState == SERVICE_RUNNING {
                ServiceState::Running
            } else if status.dwCurrentState.0 == 1 {
                ServiceState::Stopped
            } else {
                ServiceState::Other(status.dwCurrentState.0)
            },
            start_mode: start_mode(config.dwStartType.0),
            binary,
        }))
    }

    fn binary_evidence(
        command_line: &str,
        identity: SysmonServiceIdentity,
    ) -> Observation<SysmonImageEvidence> {
        let Ok(path) = fixed_image_path(command_line, identity) else {
            return Observation::Unparsed;
        };
        let Some(parent) = path.parent() else {
            return Observation::Unparsed;
        };
        let path = match PathPolicy::new(parent).and_then(|policy| policy.existing_file(&path)) {
            Ok(path) => path,
            Err(PlatformError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                return Observation::Missing;
            }
            Err(PlatformError::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied => {
                return Observation::AccessDenied;
            }
            Err(_) => return Observation::Present(SysmonImageEvidence::Untrusted),
        };
        match bounded_binary_evidence(&path) {
            Ok(value) => Observation::Present(SysmonImageEvidence::Verified(value)),
            Err(PlatformError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                Observation::Missing
            }
            Err(PlatformError::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied => {
                Observation::AccessDenied
            }
            Err(PlatformError::InputTooLarge { .. }) => Observation::Truncated,
            Err(_) => Observation::Unparsed,
        }
    }

    fn bounded_binary_evidence(path: &Path) -> Result<SysmonBinaryEvidence, PlatformError> {
        let metadata = fs::metadata(path)?;
        if !metadata.is_file() {
            return Err(PlatformError::TrustFailure(
                "Sysmon image is not a regular file".into(),
            ));
        }
        if metadata.len() > MAX_SYSMON_IMAGE_BYTES {
            return Err(PlatformError::InputTooLarge {
                path: path.to_path_buf(),
                limit: MAX_SYSMON_IMAGE_BYTES,
            });
        }
        let sha256 = digest_file(path)?;
        let signature = if verify_authenticode_subject(path, MICROSOFT_SUBJECT).is_ok() {
            SysmonSignatureEvidence::MicrosoftSubjectVerified
        } else {
            SysmonSignatureEvidence::Untrusted
        };
        Ok(SysmonBinaryEvidence {
            bytes: metadata.len(),
            sha256,
            signature,
        })
    }

    fn digest_file(path: &Path) -> Result<String, PlatformError> {
        let mut file = File::open(path)?;
        let mut digest = Sha256::new();
        let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            digest.update(&buffer[..count]);
        }
        Ok(hex::encode(digest.finalize()))
    }

    fn fixed_image_path(
        command_line: &str,
        identity: SysmonServiceIdentity,
    ) -> Result<PathBuf, PlatformError> {
        let command_line = command_line.trim();
        let executable = if let Some(rest) = command_line.strip_prefix('"') {
            rest.split_once('"')
                .map(|(value, _)| value)
                .ok_or_else(|| {
                    PlatformError::TrustFailure("unterminated Sysmon image quote".into())
                })?
        } else {
            command_line
                .split_ascii_whitespace()
                .next()
                .ok_or_else(|| {
                    PlatformError::TrustFailure("Sysmon service has no image path".into())
                })?
        };
        let path = PathBuf::from(executable);
        let expected = match identity {
            SysmonServiceIdentity::Sysmon64 => "sysmon64.exe",
            SysmonServiceIdentity::Sysmon => "sysmon.exe",
        };
        let valid_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case(expected));
        if executable.contains('\0')
            || !path.is_absolute()
            || executable.starts_with(r"\\")
            || !valid_name
            || path.components().any(|part| part == Component::ParentDir)
        {
            return Err(PlatformError::TrustFailure(
                "Sysmon service image path violated the fixed read-only policy".into(),
            ));
        }
        Ok(path)
    }

    fn shared_manager_error(
        error: &windows::core::Error,
    ) -> Result<Vec<Observation<SysmonServiceObservation>>, PlatformError> {
        if win32_code(error) == ERROR_ACCESS_DENIED.0 {
            Ok(vec![Observation::AccessDenied, Observation::AccessDenied])
        } else {
            Err(PlatformError::TrustFailure(error.to_string()))
        }
    }

    fn map_open_error(
        error: &windows::core::Error,
    ) -> Result<Observation<SysmonServiceObservation>, PlatformError> {
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

    fn wide_name(identity: SysmonServiceIdentity) -> PCWSTR {
        match identity {
            SysmonServiceIdentity::Sysmon64 => w!("Sysmon64"),
            SysmonServiceIdentity::Sysmon => w!("Sysmon"),
        }
    }

    fn win32_code(error: &windows::core::Error) -> u32 {
        u32::from_ne_bytes(error.code().0.to_ne_bytes()) & 0xffff
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_event_query_has_no_caller_controlled_channel_or_bounds() {
        let query = fixed_event_query();
        assert_eq!(query.channel, SYSMON_CHANNEL);
        assert_eq!(query.max_records, MAX_SYSMON_EVENTS);
        assert_eq!(query.max_xml_bytes, MAX_SYSMON_EVENT_XML_BYTES);
    }

    #[test]
    fn non_windows_acquisition_is_explicitly_unsupported() {
        #[cfg(not(windows))]
        assert!(matches!(
            audit_sysmon(true),
            Err(PlatformError::UnsupportedPlatform)
        ));
    }
}
