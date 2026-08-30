//! Pure bounded policy for Windows Event Log triage.

use crate::{Observation, PolicyFinding};
use baselineops_domain::{FindingStatus, JsonMap, Severity};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Hard maximum retained Event Log records.
pub const MAX_EVENT_RECORDS: u16 = 512;
/// Largest permitted `XPath` query in UTF-8 bytes.
pub const MAX_EVENT_QUERY_BYTES: usize = 4_096;
/// Hard upper bound for per-record XML retention.
pub const MAX_EVENT_XML_BYTES: u32 = 256 * 1024;
/// Hard upper bound for optional localized-message retention.
pub const MAX_EVENT_MESSAGE_BYTES: u32 = 16 * 1024;
/// Hard upper bound for one `EvtNext` wait.
pub const MAX_EVENT_TIMEOUT_MS: u32 = 30_000;

/// Strict, read-only Event Log query parameters.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EventLogQueryParameters {
    /// Local channel name, never a file path or remote endpoint.
    pub channel: String,
    /// `XPath` selector passed only to `EvtQuery`.
    pub xpath: String,
    /// Maximum events retained.
    pub max_records: u16,
    /// Maximum wait for one native retrieval call.
    pub timeout_ms: u32,
    /// Maximum retained UTF-8 XML bytes per event.
    pub max_xml_bytes: u32,
    /// Maximum retained bytes for an optional localized message.
    pub max_message_bytes: u32,
}

/// A retained event. `message` is optional and intentionally localization-opaque.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct EventLogRecord {
    /// Event provider name from rendered XML.
    pub provider: String,
    /// Numeric Event ID from rendered XML.
    pub event_id: u32,
    /// Numeric event level from rendered XML.
    pub level: u8,
    /// `SystemTime` from rendered XML, retained as source text.
    pub time_created: String,
    /// Event-log record ID.
    pub record_id: u64,
    /// Bounded rendered XML.
    pub xml: Observation<String>,
    /// Optional localized message; absent means no message was resolved.
    pub message: Option<Observation<String>>,
}

/// Event Log evidence before evaluation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct EventLogObservation {
    /// Retained records or typed query/read errors.
    pub records: Vec<Observation<EventLogRecord>>,
    /// False when the record or time bound stopped enumeration.
    pub enumeration_complete: bool,
}

/// Read-only Event Log triage result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct EventLogTriageAudit {
    /// Original bounded record observations.
    pub observation: EventLogObservation,
    /// Typed incomplete-evidence findings; no localized message is interpreted.
    pub findings: Vec<PolicyFinding>,
}

/// Checks bounds before the Windows boundary is reached.
///
/// # Errors
///
/// Returns an explanation when a local channel, `XPath`, or resource bound is invalid.
pub fn validate_event_query(parameters: &EventLogQueryParameters) -> Result<(), String> {
    validate_channel(&parameters.channel)?;
    validate_xpath(&parameters.xpath)?;
    validate_nonzero_bound(
        "max_records",
        u64::from(parameters.max_records),
        u64::from(MAX_EVENT_RECORDS),
    )?;
    validate_nonzero_bound(
        "timeout_ms",
        u64::from(parameters.timeout_ms),
        u64::from(MAX_EVENT_TIMEOUT_MS),
    )?;
    validate_nonzero_bound(
        "max_xml_bytes",
        u64::from(parameters.max_xml_bytes),
        u64::from(MAX_EVENT_XML_BYTES),
    )?;
    validate_optional_bound(
        "max_message_bytes",
        u64::from(parameters.max_message_bytes),
        u64::from(MAX_EVENT_MESSAGE_BYTES),
    )
}

/// Evaluates incomplete Event Log evidence without interpreting localized messages.
#[must_use]
pub fn evaluate_event_triage(observation: EventLogObservation) -> EventLogTriageAudit {
    let mut findings = Vec::new();
    for item in &observation.records {
        evaluate_record(item, &mut findings);
    }
    if !observation.enumeration_complete {
        findings.push(PolicyFinding {
            code: "EVT-EnumerationIncomplete",
            status: FindingStatus::Warning,
            severity: Severity::Medium,
            message: "Event Log enumeration ended at its record or time bound.".into(),
            evidence: JsonMap::new(),
        });
    }
    EventLogTriageAudit {
        observation,
        findings,
    }
}

fn validate_channel(channel: &str) -> Result<(), String> {
    let bounded = !channel.is_empty() && channel.len() <= 256;
    let local = !channel.contains(['\\', ':', '\0']) && !channel.starts_with('/');
    let segments_are_safe = channel
        .split('/')
        .all(|segment| !segment.is_empty() && !matches!(segment, "." | ".."));
    if bounded && local && segments_are_safe {
        Ok(())
    } else {
        Err("channel must be a bounded local channel name".into())
    }
}

fn validate_xpath(xpath: &str) -> Result<(), String> {
    if !xpath.is_empty() && xpath.len() <= MAX_EVENT_QUERY_BYTES && !xpath.contains('\0') {
        Ok(())
    } else {
        Err("xpath must be non-empty and bounded".into())
    }
}

fn validate_nonzero_bound(name: &str, value: u64, maximum: u64) -> Result<(), String> {
    if (1..=maximum).contains(&value) {
        Ok(())
    } else {
        Err(format!("{name} must be 1 through {maximum}"))
    }
}

fn validate_optional_bound(name: &str, value: u64, maximum: u64) -> Result<(), String> {
    if value <= maximum {
        Ok(())
    } else {
        Err(format!("{name} must be 0 through {maximum}"))
    }
}

fn evaluate_record(observation: &Observation<EventLogRecord>, findings: &mut Vec<PolicyFinding>) {
    let Observation::Present(record) = observation else {
        incomplete(
            findings,
            "EVT-RecordIncomplete",
            "event record",
            observation,
        );
        return;
    };
    incomplete(findings, "EVT-XmlIncomplete", "event XML", &record.xml);
    if let Some(message) = &record.message {
        incomplete(findings, "EVT-MessageIncomplete", "event message", message);
    }
}

fn incomplete<T>(
    findings: &mut Vec<PolicyFinding>,
    code: &'static str,
    label: &str,
    value: &Observation<T>,
) {
    if matches!(value, Observation::Present(_)) {
        return;
    }
    let status = match value {
        Observation::Present(_) => "present",
        Observation::Missing => "missing",
        Observation::AccessDenied => "access_denied",
        Observation::TimedOut => "timed_out",
        Observation::Truncated => "truncated",
        Observation::Failed { .. } => "failed",
        Observation::NotRun => "not_run",
        Observation::Unparsed => "unparsed",
    };
    findings.push(PolicyFinding {
        code,
        status: FindingStatus::Warning,
        severity: Severity::Medium,
        message: format!("{label} observation is incomplete: {status}."),
        evidence: JsonMap::from([("observation_status".into(), json!(status))]),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_path_and_unbounded_query_parameters() {
        let parameters = EventLogQueryParameters {
            channel: "Application".into(),
            xpath: "*".into(),
            max_records: 1,
            timeout_ms: 1,
            max_xml_bytes: 1,
            max_message_bytes: 0,
        };
        assert!(validate_event_query(&parameters).is_ok());
        assert!(
            validate_event_query(&EventLogQueryParameters {
                channel: "C:\\events.evtx".into(),
                ..parameters
            })
            .is_err()
        );
    }
    #[test]
    fn access_denial_and_truncation_are_typed_incomplete() {
        let audit = evaluate_event_triage(EventLogObservation {
            records: vec![Observation::AccessDenied],
            enumeration_complete: false,
        });
        assert_eq!(audit.findings[0].code, "EVT-RecordIncomplete");
        assert_eq!(audit.findings[1].code, "EVT-EnumerationIncomplete");
    }
}
