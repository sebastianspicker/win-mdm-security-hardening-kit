//! Fixed-profile Windows Firewall observation through documented native APIs.

use crate::PlatformError;
use baselineops_capabilities::FirewallObservation;

/// Observe fixed profile and logging state without mutation.
///
/// # Errors
///
/// Returns an explicit unsupported-platform error outside Windows.
pub fn observe_firewall() -> Result<FirewallObservation, PlatformError> {
    #[cfg(windows)]
    {
        Ok(platform::observe())
    }
    #[cfg(not(windows))]
    {
        Err(PlatformError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
mod platform {
    #![allow(unsafe_code, unsafe_op_in_unsafe_fn)]

    use super::FirewallObservation;
    use crate::policy_registry;
    use baselineops_capabilities::{
        FirewallEvidence, FirewallPolicyModifyState, FirewallProfile, FirewallProfileObservation,
        PolicyValueSnapshot,
    };
    use std::collections::BTreeMap;
    use windows::Win32::NetworkManagement::WindowsFirewall::{
        INetFwPolicy2, NET_FW_MODIFY_STATE_GP_OVERRIDE, NET_FW_MODIFY_STATE_INBOUND_BLOCKED,
        NET_FW_MODIFY_STATE_OK, NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE,
        NET_FW_PROFILE2_PUBLIC, NetFwPolicy2,
    };
    use windows::Win32::System::Com::{
        CLSCTX_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize,
    };

    const LOG_DOMAIN: &str = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging";
    const LOG_PRIVATE: &str = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile\Logging";
    const LOG_PUBLIC: &str = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging";

    pub(super) fn observe() -> FirewallObservation {
        let logging = fixed_profiles()
            .into_iter()
            .map(|(profile, _, path)| (profile, logging_observation(path)))
            .collect::<BTreeMap<_, _>>();
        let policy = (|| {
            let apartment = ComApartment::initialize()?;
            let policy = unsafe {
                CoCreateInstance::<_, INetFwPolicy2>(&NetFwPolicy2, None, CLSCTX_SERVER)
                    .map_err(|error| error.to_string())
            };
            let policy = policy?;
            let observation = complete_from_policy(&policy, &logging);
            // COM interfaces must be released while their apartment remains initialized.
            drop(policy);
            drop(apartment);
            Ok::<_, String>(observation)
        })();
        match policy {
            Ok(observation) => observation,
            Err(_) => FirewallObservation {
                profiles: fixed_profiles()
                    .into_iter()
                    .map(|(profile, _, _)| (profile, unavailable_profile(&logging, profile)))
                    .collect(),
                local_policy_modify_state: FirewallPolicyModifyState::Unknown,
            },
        }
    }

    fn complete_from_policy(
        policy: &INetFwPolicy2,
        logging: &BTreeMap<FirewallProfile, LoggingObservation>,
    ) -> FirewallObservation {
        let profiles = fixed_profiles()
            .into_iter()
            .map(|(profile, _, _)| {
                let logs = logging.get(&profile).expect("fixed profile logging entry");
                (
                    profile,
                    FirewallProfileObservation {
                        log_dropped_packets: logs.dropped.clone(),
                        log_successful_connections: logs.allowed.clone(),
                        log_file_path: logs.file_path.clone(),
                        log_max_size_kilobytes: logs.max_size_kilobytes.clone(),
                    },
                )
            })
            .collect();
        FirewallObservation {
            profiles,
            local_policy_modify_state: unsafe { policy.LocalPolicyModifyState() }
                .map_or(FirewallPolicyModifyState::Unknown, modify_state),
        }
    }

    fn unavailable_profile(
        logging: &BTreeMap<FirewallProfile, LoggingObservation>,
        profile: FirewallProfile,
    ) -> FirewallProfileObservation {
        let logs = logging.get(&profile).expect("fixed profile logging entry");
        FirewallProfileObservation {
            log_dropped_packets: logs.dropped.clone(),
            log_successful_connections: logs.allowed.clone(),
            log_file_path: logs.file_path.clone(),
            log_max_size_kilobytes: logs.max_size_kilobytes.clone(),
        }
    }

    fn logging_observation(path: &'static str) -> LoggingObservation {
        LoggingObservation {
            dropped: bool_registry(policy_registry::read_dword(path, "LogDroppedPackets")),
            allowed: bool_registry(policy_registry::read_dword(
                path,
                "LogSuccessfulConnections",
            )),
            file_path: string_registry(policy_registry::read_string(path, "LogFilePath")),
            max_size_kilobytes: size_registry(policy_registry::read_dword(path, "LogFileSize")),
        }
    }

    fn bool_registry(
        value: Result<PolicyValueSnapshot, crate::PlatformError>,
    ) -> FirewallEvidence<bool> {
        match value {
            Ok(PolicyValueSnapshot::Dword(0)) => FirewallEvidence::Present(false),
            Ok(PolicyValueSnapshot::Dword(1)) => FirewallEvidence::Present(true),
            Ok(PolicyValueSnapshot::Missing) => FirewallEvidence::Missing,
            Ok(_) => FirewallEvidence::Unparsed,
            Err(crate::PlatformError::Io(error))
                if error.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                FirewallEvidence::AccessDenied
            }
            Err(_) => FirewallEvidence::Unavailable,
        }
    }

    fn string_registry(
        value: Result<PolicyValueSnapshot, crate::PlatformError>,
    ) -> FirewallEvidence<String> {
        match value {
            Ok(PolicyValueSnapshot::String(value))
                if !value.trim().is_empty() && !value.contains('\0') =>
            {
                FirewallEvidence::Present(value)
            }
            Ok(PolicyValueSnapshot::Missing) => FirewallEvidence::Missing,
            Ok(_) => FirewallEvidence::Unparsed,
            Err(crate::PlatformError::Io(error))
                if error.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                FirewallEvidence::AccessDenied
            }
            Err(_) => FirewallEvidence::Unavailable,
        }
    }

    fn size_registry(
        value: Result<PolicyValueSnapshot, crate::PlatformError>,
    ) -> FirewallEvidence<u16> {
        match value {
            Ok(PolicyValueSnapshot::Dword(value)) => u16::try_from(value)
                .ok()
                .filter(|value| (1..=32_767).contains(value))
                .map_or(FirewallEvidence::Unparsed, FirewallEvidence::Present),
            Ok(PolicyValueSnapshot::Missing) => FirewallEvidence::Missing,
            Ok(_) => FirewallEvidence::Unparsed,
            Err(crate::PlatformError::Io(error))
                if error.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                FirewallEvidence::AccessDenied
            }
            Err(_) => FirewallEvidence::Unavailable,
        }
    }

    fn modify_state(
        value: windows::Win32::NetworkManagement::WindowsFirewall::NET_FW_MODIFY_STATE,
    ) -> FirewallPolicyModifyState {
        if value == NET_FW_MODIFY_STATE_OK {
            FirewallPolicyModifyState::LocalPolicyWritable
        } else if value == NET_FW_MODIFY_STATE_GP_OVERRIDE {
            FirewallPolicyModifyState::GroupPolicyOverride
        } else if value == NET_FW_MODIFY_STATE_INBOUND_BLOCKED {
            FirewallPolicyModifyState::InboundBlocked
        } else {
            FirewallPolicyModifyState::Unknown
        }
    }

    type LoggingObservation = FirewallLogFields;

    #[derive(Clone)]
    struct FirewallLogFields {
        dropped: FirewallEvidence<bool>,
        allowed: FirewallEvidence<bool>,
        file_path: FirewallEvidence<String>,
        max_size_kilobytes: FirewallEvidence<u16>,
    }

    fn fixed_profiles() -> [(
        FirewallProfile,
        windows::Win32::NetworkManagement::WindowsFirewall::NET_FW_PROFILE_TYPE2,
        &'static str,
    ); 3] {
        [
            (FirewallProfile::Domain, NET_FW_PROFILE2_DOMAIN, LOG_DOMAIN),
            (
                FirewallProfile::Private,
                NET_FW_PROFILE2_PRIVATE,
                LOG_PRIVATE,
            ),
            (FirewallProfile::Public, NET_FW_PROFILE2_PUBLIC, LOG_PUBLIC),
        ]
    }

    struct ComApartment;

    impl ComApartment {
        fn initialize() -> Result<Self, String> {
            unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }
                .map(|| Self)
                .map_err(|error| format!("Windows Firewall COM initialization failed: {error}"))
        }
    }

    impl Drop for ComApartment {
        fn drop(&mut self) {
            unsafe { CoUninitialize() };
        }
    }
}
