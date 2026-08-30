//! Fixed read-only App Control for Business acquisition for capability 43.

use crate::PlatformError;
use baselineops_capabilities::AppControlObservation;

#[cfg(any(windows, test))]
use baselineops_capabilities::{
    APP_CONTROL_EVENT_TIMEOUT_MS, EventLogQueryParameters, MAX_APP_CONTROL_EVENT_XML_BYTES,
    MAX_APP_CONTROL_EVENTS,
};

#[cfg(any(windows, test))]
const CODE_INTEGRITY_CHANNEL: &str = "Microsoft-Windows-CodeIntegrity/Operational";
#[cfg(any(windows, test))]
const CODE_INTEGRITY_XPATH: &str = "*[System[(EventID=3076 or EventID=3077 or EventID=3089)]]";

/// Observe a fixed legacy policy-file indicator and bounded local Code Integrity events.
///
/// This does not scan EFI, enumerate multi-policy directories, read policy content, or
/// validate policy signatures. Those omitted semantics must not be inferred from this result.
///
/// # Errors
///
/// Returns [`PlatformError::UnsupportedPlatform`] outside Windows.
pub fn audit_app_control() -> Result<AppControlObservation, PlatformError> {
    #[cfg(windows)]
    {
        Ok(AppControlObservation {
            legacy_policy_file: platform::legacy_policy_file(),
            code_integrity_events: crate::audit_event_log(&fixed_event_query())?,
        })
    }
    #[cfg(not(windows))]
    {
        Err(PlatformError::UnsupportedPlatform)
    }
}

#[cfg(any(windows, test))]
fn fixed_event_query() -> EventLogQueryParameters {
    EventLogQueryParameters {
        channel: CODE_INTEGRITY_CHANNEL.into(),
        xpath: CODE_INTEGRITY_XPATH.into(),
        max_records: MAX_APP_CONTROL_EVENTS,
        timeout_ms: APP_CONTROL_EVENT_TIMEOUT_MS,
        max_xml_bytes: MAX_APP_CONTROL_EVENT_XML_BYTES,
        max_message_bytes: 0,
    }
}

#[cfg(windows)]
mod platform {
    #![allow(unsafe_code, unsafe_op_in_unsafe_fn)]

    use super::PlatformError;
    use crate::PathPolicy;
    use baselineops_capabilities::{AppControlPolicyFile, Observation};
    use std::{fs, io, path::PathBuf};
    use windows::Win32::System::SystemInformation::GetWindowsDirectoryW;

    const PATH_PARTS: [&str; 3] = ["System32", "CodeIntegrity", "SIPolicy.p7b"];

    pub(super) fn legacy_policy_file() -> Observation<AppControlPolicyFile> {
        let Ok(windows) = windows_directory() else {
            return Observation::Unparsed;
        };
        let path = PATH_PARTS
            .iter()
            .fold(windows.clone(), |path, part| path.join(part));
        let path = match PathPolicy::new(&windows).and_then(|policy| policy.existing_file(&path)) {
            Ok(path) => path,
            Err(PlatformError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                return Observation::Missing;
            }
            Err(PlatformError::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied => {
                return Observation::AccessDenied;
            }
            Err(_) => return Observation::Unparsed,
        };
        match fs::metadata(path) {
            Ok(metadata) if metadata.is_file() => Observation::Present(AppControlPolicyFile {
                bytes: metadata.len(),
            }),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Observation::Missing,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                Observation::AccessDenied
            }
            Ok(_) | Err(_) => Observation::Unparsed,
        }
    }

    fn windows_directory() -> Result<PathBuf, PlatformError> {
        let mut path = vec![0_u16; 32_768];
        let length = unsafe { GetWindowsDirectoryW(Some(&mut path)) };
        let length = usize::try_from(length).map_err(|_| {
            PlatformError::TrustFailure("Windows directory length does not fit this process".into())
        })?;
        if length == 0 || length >= path.len() {
            return Err(PlatformError::TrustFailure(
                "Windows did not return a bounded Windows directory".into(),
            ));
        }
        Ok(PathBuf::from(String::from_utf16(&path[..length]).map_err(
            |_| PlatformError::TrustFailure("Windows directory is not valid UTF-16".into()),
        )?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_query_has_no_caller_controlled_path_or_channel() {
        let parameters = fixed_event_query();
        assert_eq!(parameters.channel, CODE_INTEGRITY_CHANNEL);
        assert_eq!(parameters.max_records, MAX_APP_CONTROL_EVENTS);
        assert_eq!(parameters.max_message_bytes, 0);
    }

    #[test]
    fn non_windows_acquisition_is_explicitly_unsupported() {
        #[cfg(not(windows))]
        assert!(matches!(
            audit_app_control(),
            Err(PlatformError::UnsupportedPlatform)
        ));
    }
}
