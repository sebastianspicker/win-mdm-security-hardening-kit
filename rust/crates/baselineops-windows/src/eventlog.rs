//! Shell-free bounded Event Log acquisition through `EvtQuery` APIs.

use crate::PlatformError;
use baselineops_capabilities::{
    EventLogObservation, EventLogQueryParameters, validate_event_query,
};

/// Query local Windows Event Log channels without export, command execution, or remote sessions.
///
/// # Errors
///
/// Returns [`PlatformError::UnsupportedPlatform`] outside Windows. Access denials,
/// bounds, and render failures are preserved as typed incomplete observations.
pub fn audit_event_log(
    parameters: &EventLogQueryParameters,
) -> Result<EventLogObservation, PlatformError> {
    validate_event_query(parameters).map_err(PlatformError::TrustFailure)?;
    #[cfg(windows)]
    {
        Ok(platform::audit_event_log(parameters))
    }
    #[cfg(not(windows))]
    platform::audit_event_log(parameters)
}

#[cfg(not(windows))]
mod platform {
    use super::{EventLogObservation, EventLogQueryParameters, PlatformError};
    pub(super) fn audit_event_log(
        _: &EventLogQueryParameters,
    ) -> Result<EventLogObservation, PlatformError> {
        Err(PlatformError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
mod platform {
    #![allow(unsafe_code, unsafe_op_in_unsafe_fn)]
    use super::{EventLogObservation, EventLogQueryParameters};
    use baselineops_capabilities::{EventLogRecord, Observation};
    use windows::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_ITEMS,
    };
    use windows::Win32::System::EventLog::{
        EVT_HANDLE, EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryReverseDirection,
        EvtRender, EvtRenderEventXml,
    };
    use windows::core::PCWSTR;

    pub(super) fn audit_event_log(parameters: &EventLogQueryParameters) -> EventLogObservation {
        unsafe {
            let channel = wide(&parameters.channel);
            let xpath = wide(&parameters.xpath);
            let query = match EvtQuery(
                None,
                PCWSTR(channel.as_ptr()),
                PCWSTR(xpath.as_ptr()),
                EvtQueryChannelPath.0 | EvtQueryReverseDirection.0,
            ) {
                Ok(query) => query,
                Err(error) if code(&error) == ERROR_ACCESS_DENIED.0 => {
                    return EventLogObservation {
                        records: vec![Observation::AccessDenied],
                        enumeration_complete: true,
                    };
                }
                Err(error) => {
                    return EventLogObservation {
                        records: vec![Observation::Failed {
                            exit_code: error.code().0,
                        }],
                        enumeration_complete: true,
                    };
                }
            };
            let query = OwnedEventHandle(query);
            let mut records = Vec::new();
            let mut complete = true;
            for _ in 0..parameters.max_records {
                // `EvtNext` exposes the ABI's raw handle array; immediately wrap the result.
                let mut raw_handle = [EVT_HANDLE::default().0];
                let mut returned = 0_u32;
                match EvtNext(
                    query.0,
                    &mut raw_handle,
                    parameters.timeout_ms,
                    0,
                    &raw mut returned,
                ) {
                    Ok(()) if returned == 1 => {
                        let event = OwnedEventHandle(EVT_HANDLE(raw_handle[0]));
                        records.push(render(event.0, parameters.max_xml_bytes));
                    }
                    Ok(()) => break,
                    Err(error) if code(&error) == ERROR_NO_MORE_ITEMS.0 => break,
                    Err(error) if code(&error) == ERROR_ACCESS_DENIED.0 => {
                        records.push(Observation::AccessDenied);
                        complete = false;
                        break;
                    }
                    Err(_) => {
                        records.push(Observation::TimedOut);
                        complete = false;
                        break;
                    }
                }
            }
            if records.len() == parameters.max_records as usize {
                complete = false;
            }
            EventLogObservation {
                records,
                enumeration_complete: complete,
            }
        }
    }

    unsafe fn render(handle: EVT_HANDLE, max_bytes: u32) -> Observation<EventLogRecord> {
        let mut required = 0_u32;
        let mut property_count = 0_u32;
        match EvtRender(
            None,
            handle,
            EvtRenderEventXml.0,
            0,
            None,
            &raw mut required,
            &raw mut property_count,
        ) {
            Err(error) if code(&error) == ERROR_INSUFFICIENT_BUFFER.0 => {}
            Err(error) if code(&error) == ERROR_ACCESS_DENIED.0 => {
                return Observation::AccessDenied;
            }
            Err(_) | Ok(()) => return Observation::Unparsed,
        }
        if required == 0 || required > max_bytes || !required.is_multiple_of(2) {
            return Observation::Truncated;
        }
        let mut buffer = vec![0_u16; usize::try_from(required / 2).unwrap_or(0)];
        let capacity = required;
        let status = EvtRender(
            None,
            handle,
            EvtRenderEventXml.0,
            capacity,
            Some(buffer.as_mut_ptr().cast()),
            &raw mut required,
            &raw mut property_count,
        );
        match status {
            Ok(()) => {}
            Err(error) if code(&error) == ERROR_ACCESS_DENIED.0 => {
                return Observation::AccessDenied;
            }
            Err(error) if code(&error) == ERROR_INSUFFICIENT_BUFFER.0 => {
                return Observation::Truncated;
            }
            Err(_) => return Observation::Unparsed,
        }
        if required == 0 || required > capacity || !required.is_multiple_of(2) {
            return Observation::Truncated;
        }
        let length = usize::try_from(required / 2).unwrap_or(0);
        let Ok(text) = String::from_utf16(&buffer[..length]) else {
            return Observation::Unparsed;
        };
        let text = text.trim_end_matches('\0').to_owned();
        let Some(record) = parse_xml(text) else {
            return Observation::Unparsed;
        };
        Observation::Present(record)
    }

    fn parse_xml(xml: String) -> Option<EventLogRecord> {
        Some(EventLogRecord {
            provider: attribute(&xml, "Provider", "Name")?,
            event_id: tag(&xml, "EventID")?.parse().ok()?,
            level: tag(&xml, "Level")?.parse().ok()?,
            time_created: attribute(&xml, "TimeCreated", "SystemTime")?,
            record_id: tag(&xml, "EventRecordID")?.parse().ok()?,
            xml: Observation::Present(xml),
            message: None,
        })
    }
    fn tag<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
        let start = xml.find(&format!("<{name}>"))? + name.len() + 2;
        let end = xml[start..].find(&format!("</{name}>"))? + start;
        Some(&xml[start..end])
    }
    fn attribute(xml: &str, tag_name: &str, attribute_name: &str) -> Option<String> {
        let start = xml.find(&format!("<{tag_name}"))?;
        let rest = &xml[start..xml[start..].find('>')? + start];
        let marker = format!("{attribute_name}=\"");
        let value = rest.find(&marker)? + marker.len();
        Some(rest[value..].split('"').next()?.to_owned())
    }
    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }
    fn code(error: &windows::core::Error) -> u32 {
        u32::from_ne_bytes(error.code().0.to_ne_bytes()) & 0xffff
    }
    struct OwnedEventHandle(EVT_HANDLE);
    impl Drop for OwnedEventHandle {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                unsafe {
                    let _ = EvtClose(self.0);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn non_windows_event_log_is_explicitly_unsupported() {
        #[cfg(not(windows))]
        assert!(matches!(
            super::audit_event_log(&baselineops_capabilities::EventLogQueryParameters {
                channel: "Application".into(),
                xpath: "*".into(),
                max_records: 1,
                timeout_ms: 1,
                max_xml_bytes: 1,
                max_message_bytes: 0
            }),
            Err(super::PlatformError::UnsupportedPlatform)
        ));
    }
}
