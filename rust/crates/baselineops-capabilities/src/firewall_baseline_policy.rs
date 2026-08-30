//! Fixed-profile Windows Firewall baseline policy for capability 18.
//!
//! This is intentionally narrower than the legacy script. It models only the
//! three built-in profiles and the four profile controls exposed by the Windows
//! Firewall policy API. Logging, rules, policy-store selection, and mutation
//! remain outside this foundation.

use crate::{FirewallEvidence, FirewallPolicyModifyState, FirewallProfile};
use serde::{Deserialize, Serialize};

/// Fixed default action accepted for a Windows Firewall profile.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallDefaultAction {
    /// Block traffic not matched by an allow rule.
    #[default]
    Block,
    /// Allow traffic not matched by a block rule.
    Allow,
}

/// Finite desired state for one built-in Windows Firewall profile.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "snake_case")]
pub struct FirewallBaselineProfileDesiredState {
    /// Whether the profile is enabled.
    pub enabled: bool,
    /// Default inbound disposition.
    pub default_inbound_action: FirewallDefaultAction,
    /// Default outbound disposition.
    pub default_outbound_action: FirewallDefaultAction,
    /// Whether Windows should show inbound-listening notifications.
    pub notify_on_listen: bool,
}

impl Default for FirewallBaselineProfileDesiredState {
    fn default() -> Self {
        Self {
            enabled: true,
            default_inbound_action: FirewallDefaultAction::Block,
            default_outbound_action: FirewallDefaultAction::Allow,
            notify_on_listen: false,
        }
    }
}

/// Strict finite desired state for Domain, Private, and Public profiles.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "snake_case")]
pub struct FirewallBaselineProfiles {
    /// Desired state for the Domain profile.
    pub domain: FirewallBaselineProfileDesiredState,
    /// Desired state for the Private profile.
    pub private: FirewallBaselineProfileDesiredState,
    /// Desired state for the Public profile.
    pub public: FirewallBaselineProfileDesiredState,
}

/// Strict capability parameters with no catalog paths, rules, or store names.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "snake_case")]
pub struct FirewallBaselineParameters {
    /// The complete fixed-profile desired state.
    pub profiles: FirewallBaselineProfiles,
}

/// Typed read evidence for the supported controls of one fixed profile.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct FirewallBaselineProfileObservation {
    /// Profile enablement from the effective Windows Firewall policy.
    pub enabled: FirewallEvidence<bool>,
    /// Effective default inbound action.
    pub default_inbound_action: FirewallEvidence<FirewallDefaultAction>,
    /// Effective default outbound action.
    pub default_outbound_action: FirewallEvidence<FirewallDefaultAction>,
    /// Effective inbound-listening notification setting.
    pub notify_on_listen: FirewallEvidence<bool>,
}

impl FirewallBaselineProfileObservation {
    /// Returns whether every fixed profile field has typed, present evidence.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.enabled.is_present()
            && self.default_inbound_action.is_present()
            && self.default_outbound_action.is_present()
            && self.notify_on_listen.is_present()
    }
}

/// Fixed observations for the only three profiles this capability accepts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct FirewallBaselineProfileObservations {
    /// Domain-profile evidence.
    pub domain: FirewallBaselineProfileObservation,
    /// Private-profile evidence.
    pub private: FirewallBaselineProfileObservation,
    /// Public-profile evidence.
    pub public: FirewallBaselineProfileObservation,
}

impl FirewallBaselineProfileObservations {
    /// Return the observation for one of the three fixed profiles.
    #[must_use]
    pub const fn get(&self, profile: FirewallProfile) -> &FirewallBaselineProfileObservation {
        match profile {
            FirewallProfile::Domain => &self.domain,
            FirewallProfile::Private => &self.private,
            FirewallProfile::Public => &self.public,
        }
    }
}

/// Read-only effective firewall evidence from the documented Windows API.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct FirewallBaselineObservation {
    /// Evidence for the three fixed profiles.
    pub profiles: FirewallBaselineProfileObservations,
    /// Whether Windows permits local policy modification.
    pub local_policy_modify_state: FirewallPolicyModifyState,
}

impl FirewallBaselineObservation {
    /// Returns whether all profile evidence is complete and local policy is writable.
    #[must_use]
    pub fn is_complete_and_locally_writable(&self) -> bool {
        self.local_policy_modify_state == FirewallPolicyModifyState::LocalPolicyWritable
            && fixed_profiles()
                .iter()
                .all(|profile| self.profiles.get(*profile).is_complete())
    }
}

/// One fixed profile field that differs from the requested state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallBaselineField {
    /// Profile enablement.
    Enabled,
    /// Default inbound action.
    DefaultInboundAction,
    /// Default outbound action.
    DefaultOutboundAction,
    /// Inbound-listening notification setting.
    NotifyOnListen,
}

/// Fixed, typed differences for one Windows Firewall profile.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct FirewallBaselineDrift {
    /// One of Domain, Private, or Public.
    pub profile: FirewallProfile,
    /// Only supported fixed fields that differ.
    pub fields: Vec<FirewallBaselineField>,
}

/// Read-only assessment retained even when a plan cannot be represented safely.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct FirewallBaselineAudit {
    /// Native effective policy evidence.
    pub observation: FirewallBaselineObservation,
    /// Parsed finite desired state.
    pub desired: FirewallBaselineProfiles,
    /// Differences proven by complete, typed evidence.
    pub drift: Vec<FirewallBaselineDrift>,
    /// Reasons that prevent a safe future plan.
    pub plan_blockers: Vec<&'static str>,
}

/// Non-mutating proposal for a separately approved future worker route.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct FirewallBaselinePlan {
    /// The exact audit from which this proposal was derived.
    pub audit: FirewallBaselineAudit,
    /// Fixed differences only; no action execution is attached.
    pub proposed_changes: Vec<FirewallBaselineDrift>,
    /// A future verified worker would require administrator authority.
    pub requires_administrator: bool,
    /// Raw capability Apply is intentionally unavailable.
    pub apply_available: bool,
    /// Out-of-scope authority and unverified parity gaps.
    pub exclusions: Vec<&'static str>,
}

/// Evaluate fixed-profile Windows Firewall evidence without performing I/O.
#[must_use]
pub fn evaluate_firewall_baseline(
    observation: FirewallBaselineObservation,
    parameters: &FirewallBaselineParameters,
) -> FirewallBaselineAudit {
    let desired = parameters.profiles.clone();
    let drift = fixed_profiles()
        .iter()
        .filter_map(|profile| {
            let fields = drift_fields(
                observation.profiles.get(*profile),
                desired_for(&desired, *profile),
            );
            (!fields.is_empty()).then_some(FirewallBaselineDrift {
                profile: *profile,
                fields,
            })
        })
        .collect();
    let mut plan_blockers = Vec::new();
    if observation.local_policy_modify_state != FirewallPolicyModifyState::LocalPolicyWritable {
        plan_blockers.push("Windows Firewall local policy is not writable or is policy-overridden");
    }
    if fixed_profiles()
        .iter()
        .any(|profile| !observation.profiles.get(*profile).is_complete())
    {
        plan_blockers.push("Windows Firewall profile evidence is incomplete");
    }
    FirewallBaselineAudit {
        observation,
        desired,
        drift,
        plan_blockers,
    }
}

/// Build a truthful non-mutating proposal only from complete local-policy evidence.
///
/// # Errors
///
/// Returns an error when Windows policy is overridden or the required evidence
/// is incomplete, because this foundation cannot identify a safe policy store.
pub fn build_firewall_baseline_plan(
    observation: FirewallBaselineObservation,
    parameters: &FirewallBaselineParameters,
) -> Result<FirewallBaselinePlan, String> {
    let audit = evaluate_firewall_baseline(observation, parameters);
    if !audit.plan_blockers.is_empty() {
        return Err(format!(
            "firewall baseline plan is unavailable: {}",
            audit.plan_blockers.join("; ")
        ));
    }
    Ok(FirewallBaselinePlan {
        proposed_changes: audit.drift.clone(),
        audit,
        requires_administrator: true,
        apply_available: false,
        exclusions: vec![
            "firewall logging is delegated to v3.firewall.logging",
            "firewall rule enumeration, creation, modification, and disablement",
            "dynamic or non-default Windows Firewall policy-store selection",
            "all mutation, rollback, and Windows Firewall service changes",
            "legacy-script semantic-oracle and Windows VM parity validation",
        ],
    })
}

/// Return the only Windows Firewall profiles accepted by this capability.
#[must_use]
pub const fn fixed_profiles() -> [FirewallProfile; 3] {
    [
        FirewallProfile::Domain,
        FirewallProfile::Private,
        FirewallProfile::Public,
    ]
}

fn desired_for(
    profiles: &FirewallBaselineProfiles,
    profile: FirewallProfile,
) -> &FirewallBaselineProfileDesiredState {
    match profile {
        FirewallProfile::Domain => &profiles.domain,
        FirewallProfile::Private => &profiles.private,
        FirewallProfile::Public => &profiles.public,
    }
}

fn drift_fields(
    observed: &FirewallBaselineProfileObservation,
    desired: &FirewallBaselineProfileDesiredState,
) -> Vec<FirewallBaselineField> {
    let mut fields = Vec::new();
    if !matches!(observed.enabled, FirewallEvidence::Present(value) if value == desired.enabled) {
        fields.push(FirewallBaselineField::Enabled);
    }
    if !matches!(observed.default_inbound_action, FirewallEvidence::Present(value) if value == desired.default_inbound_action)
    {
        fields.push(FirewallBaselineField::DefaultInboundAction);
    }
    if !matches!(observed.default_outbound_action, FirewallEvidence::Present(value) if value == desired.default_outbound_action)
    {
        fields.push(FirewallBaselineField::DefaultOutboundAction);
    }
    if !matches!(observed.notify_on_listen, FirewallEvidence::Present(value) if value == desired.notify_on_listen)
    {
        fields.push(FirewallBaselineField::NotifyOnListen);
    }
    fields
}

#[cfg(test)]
mod tests {
    use super::*;

    fn present_profile() -> FirewallBaselineProfileObservation {
        FirewallBaselineProfileObservation {
            enabled: FirewallEvidence::Present(true),
            default_inbound_action: FirewallEvidence::Present(FirewallDefaultAction::Block),
            default_outbound_action: FirewallEvidence::Present(FirewallDefaultAction::Allow),
            notify_on_listen: FirewallEvidence::Present(false),
        }
    }

    fn complete_observation() -> FirewallBaselineObservation {
        FirewallBaselineObservation {
            profiles: FirewallBaselineProfileObservations {
                domain: present_profile(),
                private: present_profile(),
                public: present_profile(),
            },
            local_policy_modify_state: FirewallPolicyModifyState::LocalPolicyWritable,
        }
    }

    #[test]
    fn parameters_are_finite_and_reject_legacy_dynamic_authority() {
        for value in [
            serde_json::json!({"catalog_path":"untrusted.json"}),
            serde_json::json!({"profiles":{"domain":{"rule_name":"anything"}}}),
            serde_json::json!({"local_policy_store":"PersistentStore"}),
        ] {
            assert!(serde_json::from_value::<FirewallBaselineParameters>(value).is_err());
        }
    }

    #[test]
    fn complete_local_evidence_can_produce_a_non_mutating_plan() {
        let plan = build_firewall_baseline_plan(
            complete_observation(),
            &FirewallBaselineParameters::default(),
        )
        .expect("complete fixed evidence");
        assert!(plan.proposed_changes.is_empty());
        assert!(!plan.apply_available);
    }

    #[test]
    fn incomplete_or_overridden_evidence_cannot_produce_a_plan() {
        let mut observation = complete_observation();
        observation.profiles.public.enabled = FirewallEvidence::AccessDenied;
        assert!(
            build_firewall_baseline_plan(observation, &FirewallBaselineParameters::default())
                .is_err()
        );
    }
}
