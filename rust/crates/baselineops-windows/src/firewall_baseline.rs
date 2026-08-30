//! Read-only Windows Firewall profile observation for capability 18.
//!
//! The adapter uses `INetFwPolicy2` only. It does not enumerate rules, select
//! policy stores, access logging registry values, start services, or mutate
//! firewall state.

use crate::PlatformError;
use baselineops_capabilities::FirewallBaselineObservation;

/// Observe the three fixed Windows Firewall profiles without mutation.
///
/// # Errors
///
/// Returns [`PlatformError::UnsupportedPlatform`] outside Windows. On Windows,
/// individual COM failures are preserved as incomplete typed evidence so
/// callers fail closed rather than treating unavailable values as compliant.
pub fn observe_firewall_baseline() -> Result<FirewallBaselineObservation, PlatformError> {
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

    use baselineops_capabilities::{
        FirewallBaselineObservation, FirewallBaselineProfileObservation,
        FirewallBaselineProfileObservations, FirewallDefaultAction, FirewallEvidence,
        FirewallPolicyModifyState,
    };
    use windows::Win32::NetworkManagement::WindowsFirewall::{
        INetFwPolicy2, NET_FW_ACTION_ALLOW, NET_FW_ACTION_BLOCK, NET_FW_MODIFY_STATE_GP_OVERRIDE,
        NET_FW_MODIFY_STATE_INBOUND_BLOCKED, NET_FW_MODIFY_STATE_OK, NET_FW_PROFILE_TYPE2,
        NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC, NetFwPolicy2,
    };
    use windows::Win32::System::Com::{
        CLSCTX_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize,
    };

    pub(super) fn observe() -> FirewallBaselineObservation {
        let Ok(_apartment) = ComApartment::initialize() else {
            return unavailable_observation();
        };
        let policy =
            unsafe { CoCreateInstance::<_, INetFwPolicy2>(&NetFwPolicy2, None, CLSCTX_SERVER) };
        match policy {
            Ok(policy) => FirewallBaselineObservation {
                profiles: FirewallBaselineProfileObservations {
                    domain: profile(&policy, NET_FW_PROFILE2_DOMAIN),
                    private: profile(&policy, NET_FW_PROFILE2_PRIVATE),
                    public: profile(&policy, NET_FW_PROFILE2_PUBLIC),
                },
                local_policy_modify_state: unsafe { policy.LocalPolicyModifyState() }
                    .map_or(FirewallPolicyModifyState::Unknown, modify_state),
            },
            Err(_) => unavailable_observation(),
        }
    }

    fn profile(
        policy: &INetFwPolicy2,
        profile: NET_FW_PROFILE_TYPE2,
    ) -> FirewallBaselineProfileObservation {
        FirewallBaselineProfileObservation {
            enabled: unsafe { policy.get_FirewallEnabled(profile) }
                .map_or(FirewallEvidence::Unavailable, |value| {
                    FirewallEvidence::Present(value.as_bool())
                }),
            default_inbound_action: unsafe { policy.get_DefaultInboundAction(profile) }
                .map_or(FirewallEvidence::Unavailable, action),
            default_outbound_action: unsafe { policy.get_DefaultOutboundAction(profile) }
                .map_or(FirewallEvidence::Unavailable, action),
            notify_on_listen: unsafe { policy.get_NotificationsDisabled(profile) }
                .map_or(FirewallEvidence::Unavailable, |value| {
                    FirewallEvidence::Present(!value.as_bool())
                }),
        }
    }

    fn action(
        value: windows::Win32::NetworkManagement::WindowsFirewall::NET_FW_ACTION,
    ) -> FirewallEvidence<FirewallDefaultAction> {
        if value == NET_FW_ACTION_BLOCK {
            FirewallEvidence::Present(FirewallDefaultAction::Block)
        } else if value == NET_FW_ACTION_ALLOW {
            FirewallEvidence::Present(FirewallDefaultAction::Allow)
        } else {
            FirewallEvidence::Unparsed
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

    fn unavailable_profile() -> FirewallBaselineProfileObservation {
        FirewallBaselineProfileObservation {
            enabled: FirewallEvidence::Unavailable,
            default_inbound_action: FirewallEvidence::Unavailable,
            default_outbound_action: FirewallEvidence::Unavailable,
            notify_on_listen: FirewallEvidence::Unavailable,
        }
    }

    fn unavailable_observation() -> FirewallBaselineObservation {
        FirewallBaselineObservation {
            profiles: FirewallBaselineProfileObservations {
                domain: unavailable_profile(),
                private: unavailable_profile(),
                public: unavailable_profile(),
            },
            local_policy_modify_state: FirewallPolicyModifyState::Unknown,
        }
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

#[cfg(test)]
mod tests {
    #[test]
    fn non_windows_observation_is_explicitly_unsupported() {
        #[cfg(not(windows))]
        assert!(matches!(
            super::observe_firewall_baseline(),
            Err(super::PlatformError::UnsupportedPlatform)
        ));
    }
}
