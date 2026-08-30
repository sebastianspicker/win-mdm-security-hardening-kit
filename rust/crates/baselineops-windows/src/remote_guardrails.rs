//! Fixed read-only acquisition for capability 14 remote-access guardrails.
//!
//! The adapter reads only compile-time RDP and Remote Assistance registry
//! values and reuses the existing local RDP surface acquisition. It exposes no
//! raw registry interface, remote connection, service control, firewall API,
//! shell, or mutation capability.

use crate::PlatformError;
use baselineops_capabilities::RemoteGuardrailsObservation;

/// Observe fixed local RDP and Remote Assistance guardrail evidence.
///
/// Local listener and service indicators are retained solely as local evidence;
/// they do not prove a firewall path or reachability from any remote host.
///
/// # Errors
///
/// Returns [`PlatformError::UnsupportedPlatform`] outside Windows. On Windows,
/// missing, access-denied, and unparsed registry values are preserved as typed
/// evidence so callers fail closed.
pub fn audit_remote_guardrails() -> Result<RemoteGuardrailsObservation, PlatformError> {
    #[cfg(windows)]
    {
        platform::audit()
    }
    #[cfg(not(windows))]
    {
        Err(PlatformError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
mod platform {
    use crate::{PlatformError, audit_remote_surface, policy_registry};
    use baselineops_capabilities::{Observation, PolicyValueSnapshot, RemoteGuardrailsObservation};

    const RDP_TCP: &str = r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp";
    const LSA: &str = r"SYSTEM\CurrentControlSet\Control\Lsa";
    const TERMINAL_SERVICES_POLICY: &str =
        r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";

    pub(super) fn audit() -> Result<RemoteGuardrailsObservation, PlatformError> {
        Ok(RemoteGuardrailsObservation {
            remote_surface: audit_remote_surface()?,
            network_level_authentication: dword(RDP_TCP, "UserAuthentication", |value| value <= 1),
            security_layer: dword(RDP_TCP, "SecurityLayer", |value| value <= 2),
            minimum_encryption: dword(RDP_TCP, "MinEncryptionLevel", |value| {
                (2..=4).contains(&value)
            }),
            disable_restricted_admin: dword(LSA, "DisableRestrictedAdmin", |value| value <= 1),
            disable_password_saving: dword(
                TERMINAL_SERVICES_POLICY,
                "DisablePasswordSaving",
                |value| value <= 1,
            ),
            allow_solicited_remote_assistance: dword(
                TERMINAL_SERVICES_POLICY,
                "fAllowToGetHelp",
                |value| value <= 1,
            ),
            allow_unsolicited_remote_assistance: dword(
                TERMINAL_SERVICES_POLICY,
                "fAllowUnsolicited",
                |value| value <= 1,
            ),
            remote_assistance_ticket_lifetime: dword(
                TERMINAL_SERVICES_POLICY,
                "MaxTicketExpiry",
                |value| matches!(value, 60 | 120),
            ),
        })
    }

    fn dword(
        path: &'static str,
        name: &'static str,
        valid: impl FnOnce(u32) -> bool,
    ) -> Observation<u32> {
        match policy_registry::read_dword(path, name) {
            Ok(PolicyValueSnapshot::Dword(value)) if valid(value) => Observation::Present(value),
            Ok(PolicyValueSnapshot::Dword(_) | PolicyValueSnapshot::String(_)) => {
                Observation::Unparsed
            }
            Ok(PolicyValueSnapshot::Missing) => Observation::Missing,
            Err(PlatformError::Io(error))
                if error.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                Observation::AccessDenied
            }
            Err(_) => Observation::Unparsed,
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn non_windows_observation_is_explicitly_unsupported() {
        #[cfg(not(windows))]
        assert!(matches!(
            super::audit_remote_guardrails(),
            Err(super::PlatformError::UnsupportedPlatform)
        ));
    }
}
