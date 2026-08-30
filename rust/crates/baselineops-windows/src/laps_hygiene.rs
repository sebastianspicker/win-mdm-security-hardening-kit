//! Fixed read-only Windows LAPS registry and Operational-event acquisition.

use crate::PlatformError;
#[cfg(windows)]
use crate::{audit_event_log, policy_registry};
use baselineops_capabilities::LapsHygieneObservation;
#[cfg(windows)]
use baselineops_capabilities::{EventLogObservation, EventLogQueryParameters};
#[cfg(windows)]
use baselineops_capabilities::{
    LapsOperationalEvent, LapsPolicyEvidence, LapsPolicySource, Observation, PolicyValueSnapshot,
};

#[cfg(windows)]
const CSP: &str = r"SOFTWARE\Microsoft\Policies\LAPS";
#[cfg(windows)]
const GPO: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS";
#[cfg(windows)]
const LOCAL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config";
#[cfg(windows)]
const LEGACY: &str = r"SOFTWARE\Policies\Microsoft Services\AdmPwd";

/// Acquires fixed LAPS configuration and Operational metadata without mutation.
///
/// # Errors
///
/// Returns [`PlatformError::UnsupportedPlatform`] outside Windows; absence,
/// denial, and incomplete observations remain typed in the returned evidence.
pub fn audit_laps_hygiene() -> Result<LapsHygieneObservation, PlatformError> {
    #[cfg(windows)]
    {
        let (operational_events, operational_events_complete) = operational_events();
        Ok(LapsHygieneObservation {
            policy: select_policy(),
            operational_events,
            operational_events_complete,
        })
    }
    #[cfg(not(windows))]
    {
        Err(PlatformError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
fn select_policy() -> Observation<LapsPolicyEvidence> {
    let mut incomplete = None;
    for (source, path, legacy) in [
        (LapsPolicySource::WindowsCsp, CSP, false),
        (LapsPolicySource::WindowsGpo, GPO, false),
        (LapsPolicySource::WindowsLocal, LOCAL, false),
        (LapsPolicySource::LegacyGpo, LEGACY, true),
    ] {
        let evidence = read_policy(source, path, legacy);
        if has_present_value(&evidence) {
            return Observation::Present(evidence);
        }
        if let Some(state) = incomplete_policy_state(&evidence) {
            incomplete.get_or_insert(state);
        }
    }
    incomplete.unwrap_or(Observation::Missing)
}

#[cfg(windows)]
fn read_policy(source: LapsPolicySource, path: &'static str, legacy: bool) -> LapsPolicyEvidence {
    let password_age_days = if legacy {
        legacy_password_age(policy_registry::read_dword(path, "PasswordAge"))
    } else {
        password_age(policy_registry::read_dword(path, "PasswordAgeDays"))
    };
    LapsPolicyEvidence {
        source,
        backup_directory: if legacy {
            Observation::NotRun
        } else {
            dword(policy_registry::read_dword(path, "BackupDirectory"))
        },
        password_age_days,
        password_complexity: dword(policy_registry::read_dword(path, "PasswordComplexity")),
    }
}

#[cfg(windows)]
fn has_present_value(evidence: &LapsPolicyEvidence) -> bool {
    matches!(
        (
            &evidence.backup_directory,
            &evidence.password_age_days,
            &evidence.password_complexity,
        ),
        (Observation::Present(_), _, _)
            | (_, Observation::Present(_), _)
            | (_, _, Observation::Present(_))
    )
}

#[cfg(windows)]
fn incomplete_policy_state(
    evidence: &LapsPolicyEvidence,
) -> Option<Observation<LapsPolicyEvidence>> {
    [
        state(&evidence.backup_directory),
        state(&evidence.password_age_days),
        state(&evidence.password_complexity),
    ]
    .into_iter()
    .flatten()
    .next()
}

#[cfg(windows)]
fn state<T>(value: &Observation<T>) -> Option<Observation<LapsPolicyEvidence>> {
    match value {
        Observation::AccessDenied => Some(Observation::AccessDenied),
        Observation::TimedOut => Some(Observation::TimedOut),
        Observation::Truncated => Some(Observation::Truncated),
        Observation::Failed { exit_code } => Some(Observation::Failed {
            exit_code: *exit_code,
        }),
        Observation::NotRun | Observation::Present(_) | Observation::Missing => None,
        Observation::Unparsed => Some(Observation::Unparsed),
    }
}

#[cfg(windows)]
fn dword(result: Result<PolicyValueSnapshot, PlatformError>) -> Observation<u32> {
    match result {
        Ok(PolicyValueSnapshot::Dword(value)) => Observation::Present(value),
        Ok(PolicyValueSnapshot::Missing) => Observation::Missing,
        Ok(PolicyValueSnapshot::String(_)) | Err(PlatformError::TrustFailure(_)) => {
            Observation::Unparsed
        }
        Err(PlatformError::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            Observation::AccessDenied
        }
        Err(_) => Observation::Unparsed,
    }
}

#[cfg(windows)]
fn password_age(result: Result<PolicyValueSnapshot, PlatformError>) -> Observation<u16> {
    match dword(result) {
        Observation::Present(value @ 1..=365) => {
            u16::try_from(value).map_or(Observation::Unparsed, Observation::Present)
        }
        Observation::Present(_) | Observation::Unparsed => Observation::Unparsed,
        Observation::Missing => Observation::Missing,
        Observation::AccessDenied => Observation::AccessDenied,
        Observation::TimedOut => Observation::TimedOut,
        Observation::Truncated => Observation::Truncated,
        Observation::Failed { exit_code } => Observation::Failed { exit_code },
        Observation::NotRun => Observation::NotRun,
    }
}

#[cfg(windows)]
fn legacy_password_age(result: Result<PolicyValueSnapshot, PlatformError>) -> Observation<u16> {
    match dword(result) {
        Observation::Present(hours @ 1..=8_760) => {
            u16::try_from(hours.div_ceil(24)).map_or(Observation::Unparsed, Observation::Present)
        }
        Observation::Present(_) | Observation::Unparsed => Observation::Unparsed,
        Observation::Missing => Observation::Missing,
        Observation::AccessDenied => Observation::AccessDenied,
        Observation::TimedOut => Observation::TimedOut,
        Observation::Truncated => Observation::Truncated,
        Observation::Failed { exit_code } => Observation::Failed { exit_code },
        Observation::NotRun => Observation::NotRun,
    }
}

#[cfg(windows)]
fn operational_events() -> (Observation<Vec<LapsOperationalEvent>>, bool) {
    map_events(fixed_operational_event_query())
}

#[cfg(windows)]
fn fixed_operational_event_query() -> Result<EventLogObservation, PlatformError> {
    audit_event_log(&EventLogQueryParameters {
        channel: "Microsoft-Windows-LAPS/Operational".into(),
        xpath: "*".into(),
        max_records: 32,
        timeout_ms: 3_000,
        max_xml_bytes: 16 * 1024,
        max_message_bytes: 0,
    })
}

#[cfg(windows)]
fn map_events(
    result: Result<EventLogObservation, PlatformError>,
) -> (Observation<Vec<LapsOperationalEvent>>, bool) {
    let observation = match result {
        Ok(value) => value,
        Err(PlatformError::UnsupportedPlatform) => return (Observation::NotRun, false),
        Err(_) => return (Observation::Unparsed, false),
    };
    if !observation.enumeration_complete {
        return (Observation::Truncated, false);
    }
    let mut events = Vec::with_capacity(observation.records.len());
    for value in observation.records {
        match value {
            Observation::Present(record) => events.push(LapsOperationalEvent {
                event_id: record.event_id,
                time_created: record.time_created,
                record_id: record.record_id,
            }),
            Observation::Missing => return (Observation::Missing, true),
            Observation::AccessDenied => return (Observation::AccessDenied, true),
            Observation::TimedOut => return (Observation::TimedOut, true),
            Observation::Truncated => return (Observation::Truncated, true),
            Observation::Failed { exit_code } => return (Observation::Failed { exit_code }, true),
            Observation::NotRun => return (Observation::NotRun, true),
            Observation::Unparsed => return (Observation::Unparsed, true),
        }
    }
    (Observation::Present(events), true)
}

#[cfg(test)]
mod tests {
    #[test]
    fn non_windows_acquisition_is_explicitly_unsupported() {
        #[cfg(not(windows))]
        assert!(matches!(
            super::audit_laps_hygiene(),
            Err(super::PlatformError::UnsupportedPlatform)
        ));
    }
}
