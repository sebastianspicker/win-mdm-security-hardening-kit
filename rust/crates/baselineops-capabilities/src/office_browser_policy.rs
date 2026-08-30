//! Typed Office and Edge policy desired state, drift, and rollback records.
//!
//! The legacy Firefox `policies.json` route accepts an arbitrary distribution
//! directory. It is deliberately excluded until a fixed protected installation
//! root and atomic-write contract are independently evidenced. Likewise,
//! legacy Edge startup URL enumeration is excluded because it is an unbounded
//! mutable set. This module has no Windows I/O or raw registry strings.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Typed snapshot of one fixed registry policy value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", content = "value", rename_all = "snake_case")]
pub enum PolicyValueSnapshot {
    /// The value does not exist.
    Missing,
    /// A 32-bit integer value.
    Dword(u32),
    /// A bounded string value.
    String(String),
}

/// Fixed Office and Edge policy fields supported by the native foundation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OfficeBrowserField {
    /// Word VBA warning mode.
    WordVbaWarnings,
    /// Excel VBA warning mode.
    ExcelVbaWarnings,
    /// `PowerPoint` VBA warning mode.
    PowerPointVbaWarnings,
    /// Word macros-from-internet blocking.
    WordBlockMacrosFromInternet,
    /// Excel macros-from-internet blocking.
    ExcelBlockMacrosFromInternet,
    /// `PowerPoint` macros-from-internet blocking.
    PowerPointBlockMacrosFromInternet,
    /// Word programmatic VBA object-model access.
    WordAccessVbom,
    /// Excel programmatic VBA object-model access.
    ExcelAccessVbom,
    /// `PowerPoint` programmatic VBA object-model access.
    PowerPointAccessVbom,
    /// Word Protected View for internet files.
    WordProtectedViewInternet,
    /// Excel Protected View for internet files.
    ExcelProtectedViewInternet,
    /// `PowerPoint` Protected View for internet files.
    PowerPointProtectedViewInternet,
    /// Word Protected View for unsafe locations.
    WordProtectedViewUnsafeLocations,
    /// Excel Protected View for unsafe locations.
    ExcelProtectedViewUnsafeLocations,
    /// `PowerPoint` Protected View for unsafe locations.
    PowerPointProtectedViewUnsafeLocations,
    /// Word Protected View for Outlook attachments.
    WordProtectedViewOutlook,
    /// Excel Protected View for Outlook attachments.
    ExcelProtectedViewOutlook,
    /// `PowerPoint` Protected View for Outlook attachments.
    PowerPointProtectedViewOutlook,
    /// Word trusted-location disablement.
    WordDisableTrustedLocations,
    /// Excel trusted-location disablement.
    ExcelDisableTrustedLocations,
    /// `PowerPoint` trusted-location disablement.
    PowerPointDisableTrustedLocations,
    /// Edge `SmartScreen` enablement.
    EdgeSmartScreen,
    /// Edge potentially unwanted application protection.
    EdgePua,
    /// Edge password-manager availability.
    EdgePasswordManager,
    /// Edge address autofill availability.
    EdgeAutofillAddress,
    /// Edge credit-card autofill availability.
    EdgeAutofillCreditCard,
    /// Edge synchronization disablement.
    EdgeSyncDisabled,
    /// Edge minimum TLS version.
    EdgeSslVersionMin,
    /// Edge tracking-prevention level.
    EdgeTrackingPrevention,
}

/// Observed fixed Office and Edge policy values.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct OfficeBrowserObservation {
    /// Values keyed by finite field identity.
    pub values: BTreeMap<OfficeBrowserField, PolicyValueSnapshot>,
}

/// Strict request parameters with explicit values overriding catalog defaults.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, rename_all = "snake_case", deny_unknown_fields)]
pub struct OfficeBrowserParameters {
    /// Optional bounded configuration-catalog defaults.
    pub config: Option<OfficeBrowserConfig>,
    /// Explicit Office desired state.
    pub office: Option<OfficeConfig>,
    /// Explicit Edge desired state.
    pub edge: Option<EdgeConfig>,
}

/// Optional bounded Office and Edge catalog defaults.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, rename_all = "snake_case", deny_unknown_fields)]
pub struct OfficeBrowserConfig {
    /// Optional Office defaults.
    pub office: Option<OfficeConfig>,
    /// Optional Edge defaults.
    pub edge: Option<EdgeConfig>,
}

/// Bounded Office 16 desired state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct OfficeConfig {
    /// Fixed Office major version; only 16 is accepted.
    #[serde(default = "default_office_version")]
    pub version_major: u16,
    /// VBA macro warning mode.
    #[serde(default)]
    pub macros_mode: MacrosMode,
    /// Whether macros from the internet are blocked.
    #[serde(default = "default_true")]
    pub block_macros_from_internet: bool,
    /// Whether trusted locations are disabled.
    #[serde(default = "default_true")]
    pub disable_trusted_locations: bool,
    /// Protected View desired state.
    #[serde(default)]
    pub protected_view: ProtectedViewConfig,
    /// Whether programmatic VBA object-model access is permitted.
    #[serde(default)]
    pub access_vbom: bool,
}

impl Default for OfficeConfig {
    fn default() -> Self {
        Self {
            version_major: 16,
            macros_mode: MacrosMode::SignedOnly,
            block_macros_from_internet: true,
            disable_trusted_locations: true,
            protected_view: ProtectedViewConfig::default(),
            access_vbom: false,
        }
    }
}

/// Finite Office VBA macro warning modes.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MacrosMode {
    /// Allow only digitally signed macros.
    #[default]
    SignedOnly,
    /// Disable all macros.
    DisableAll,
}

/// Protected View desired state shared by supported Office applications.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, rename_all = "snake_case", deny_unknown_fields)]
pub struct ProtectedViewConfig {
    /// Open internet-originated files in Protected View.
    pub internet: bool,
    /// Open files from unsafe locations in Protected View.
    pub unsafe_locations: bool,
    /// Open Outlook attachments in Protected View.
    pub outlook: bool,
}
impl Default for ProtectedViewConfig {
    fn default() -> Self {
        Self {
            internet: true,
            unsafe_locations: true,
            outlook: true,
        }
    }
}

/// Bounded mandatory Edge policy desired state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, rename_all = "snake_case", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct EdgeConfig {
    /// Whether `SmartScreen` is enabled.
    pub smart_screen: bool,
    /// Whether potentially unwanted application protection is enabled.
    pub pua: bool,
    /// Whether the password manager is available.
    pub password_manager: bool,
    /// Whether address autofill is available.
    pub autofill_address: bool,
    /// Whether credit-card autofill is available.
    pub autofill_credit_card: bool,
    /// Whether Edge synchronization is disabled.
    pub sync_disabled: bool,
    /// Minimum accepted TLS version.
    pub ssl_version_min: TlsMinimum,
    /// Tracking-prevention level.
    pub tracking_prevention: TrackingPrevention,
}
impl Default for EdgeConfig {
    fn default() -> Self {
        Self {
            smart_screen: true,
            pua: true,
            password_manager: false,
            autofill_address: false,
            autofill_credit_card: false,
            sync_disabled: true,
            ssl_version_min: TlsMinimum::Tls12,
            tracking_prevention: TrackingPrevention::Balanced,
        }
    }
}

/// Finite minimum TLS versions supported by the Edge policy.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsMinimum {
    /// TLS 1.2.
    #[default]
    Tls12,
    /// TLS 1.3.
    Tls13,
}
/// Finite Edge tracking-prevention levels.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrackingPrevention {
    /// Basic tracking prevention.
    Basic,
    /// Balanced tracking prevention.
    #[default]
    Balanced,
    /// Strict tracking prevention.
    Strict,
}

/// Fully resolved Office and Edge desired state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct OfficeBrowserDesiredState {
    /// Validated Office 16 desired state.
    pub office: OfficeConfig,
    /// Validated mandatory Edge desired state.
    pub edge: EdgeConfig,
}

/// One fixed Office or Edge policy difference.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct OfficeBrowserMutation {
    /// Fixed policy field.
    pub field: OfficeBrowserField,
    /// Desired typed registry value.
    pub desired: PolicyValueSnapshot,
}

/// Non-mutating Office and Edge proposal with rollback evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct OfficeBrowserPlan {
    /// Observation used to derive the proposal.
    pub observation: OfficeBrowserObservation,
    /// Validated desired state.
    pub desired: OfficeBrowserDesiredState,
    /// Finite proposed differences.
    pub mutations: Vec<OfficeBrowserMutation>,
    /// Exact pre-state retained for a future authorized rollback path.
    pub rollback: OfficeBrowserObservation,
    /// Whether future mutation would require Administrator authority.
    pub requires_administrator: bool,
    /// Whether the fixed policy values require a reboot.
    pub reboot_required: bool,
    /// Declared exclusions that prevent a parity claim.
    pub exclusions: Vec<&'static str>,
}

/// Resolves strict Office and Edge desired state with explicit-over-config precedence.
///
/// # Errors
///
/// Returns an error when the supplied Office version is outside the fixed
/// Office 16 allowlist.
pub fn resolve_desired_state(
    parameters: &OfficeBrowserParameters,
) -> Result<OfficeBrowserDesiredState, String> {
    let configured = parameters.config.as_ref();
    let office = parameters
        .office
        .clone()
        .or_else(|| configured.and_then(|value| value.office.clone()))
        .unwrap_or_default();
    if office.version_major != 16 {
        return Err("only Office version_major=16 is allowlisted".into());
    }
    let edge = parameters
        .edge
        .clone()
        .or_else(|| configured.and_then(|value| value.edge.clone()))
        .unwrap_or_default();
    Ok(OfficeBrowserDesiredState { office, edge })
}

/// Builds finite proposed differences from fixed observed policy values.
#[must_use]
pub fn build_plan(
    observation: OfficeBrowserObservation,
    desired: OfficeBrowserDesiredState,
) -> OfficeBrowserPlan {
    let expected = expected_values(&desired);
    let mutations = expected
        .into_iter()
        .filter_map(|(field, desired)| {
            (observation.values.get(&field) != Some(&desired))
                .then_some(OfficeBrowserMutation { field, desired })
        })
        .collect();
    OfficeBrowserPlan {
        rollback: observation.clone(),
        observation,
        desired,
        mutations,
        requires_administrator: true,
        reboot_required: false,
        exclusions: vec![
            "Firefox policies.json is unsupported: arbitrary distribution paths are not accepted",
            "Edge RestoreOnStartupURLs is unsupported: legacy numbered values are an unbounded mutable set",
        ],
    }
}

fn expected_values(
    desired: &OfficeBrowserDesiredState,
) -> BTreeMap<OfficeBrowserField, PolicyValueSnapshot> {
    let mut expected = BTreeMap::new();
    insert_office_values(&mut expected, &desired.office);
    insert_edge_values(&mut expected, &desired.edge);
    expected
}

fn insert_office_values(
    expected: &mut BTreeMap<OfficeBrowserField, PolicyValueSnapshot>,
    office: &OfficeConfig,
) {
    let vba = match office.macros_mode {
        MacrosMode::SignedOnly => 3,
        MacrosMode::DisableAll => 4,
    };
    for (vba_field, macro_field, vbom_field, internet, unsafe_locations, outlook, trusted) in
        office_fields()
    {
        expected.insert(vba_field, PolicyValueSnapshot::Dword(vba));
        expected.insert(
            macro_field,
            PolicyValueSnapshot::Dword(u32::from(office.block_macros_from_internet)),
        );
        expected.insert(
            vbom_field,
            PolicyValueSnapshot::Dword(u32::from(office.access_vbom)),
        );
        expected.insert(
            internet,
            PolicyValueSnapshot::Dword(u32::from(!office.protected_view.internet)),
        );
        expected.insert(
            unsafe_locations,
            PolicyValueSnapshot::Dword(u32::from(!office.protected_view.unsafe_locations)),
        );
        expected.insert(
            outlook,
            PolicyValueSnapshot::Dword(u32::from(!office.protected_view.outlook)),
        );
        expected.insert(
            trusted,
            PolicyValueSnapshot::Dword(u32::from(office.disable_trusted_locations)),
        );
    }
}

fn insert_edge_values(
    expected: &mut BTreeMap<OfficeBrowserField, PolicyValueSnapshot>,
    edge: &EdgeConfig,
) {
    for (field, value) in [
        (
            OfficeBrowserField::EdgeSmartScreen,
            PolicyValueSnapshot::Dword(u32::from(edge.smart_screen)),
        ),
        (
            OfficeBrowserField::EdgePua,
            PolicyValueSnapshot::Dword(u32::from(edge.pua)),
        ),
        (
            OfficeBrowserField::EdgePasswordManager,
            PolicyValueSnapshot::Dword(u32::from(edge.password_manager)),
        ),
        (
            OfficeBrowserField::EdgeAutofillAddress,
            PolicyValueSnapshot::Dword(u32::from(edge.autofill_address)),
        ),
        (
            OfficeBrowserField::EdgeAutofillCreditCard,
            PolicyValueSnapshot::Dword(u32::from(edge.autofill_credit_card)),
        ),
        (
            OfficeBrowserField::EdgeSyncDisabled,
            PolicyValueSnapshot::Dword(u32::from(edge.sync_disabled)),
        ),
        (
            OfficeBrowserField::EdgeSslVersionMin,
            PolicyValueSnapshot::String(
                match edge.ssl_version_min {
                    TlsMinimum::Tls12 => "tls1.2",
                    TlsMinimum::Tls13 => "tls1.3",
                }
                .into(),
            ),
        ),
        (
            OfficeBrowserField::EdgeTrackingPrevention,
            PolicyValueSnapshot::Dword(match edge.tracking_prevention {
                TrackingPrevention::Basic => 1,
                TrackingPrevention::Balanced => 2,
                TrackingPrevention::Strict => 3,
            }),
        ),
    ] {
        expected.insert(field, value);
    }
}

const fn default_office_version() -> u16 {
    16
}
const fn default_true() -> bool {
    true
}
const fn office_fields() -> [(
    OfficeBrowserField,
    OfficeBrowserField,
    OfficeBrowserField,
    OfficeBrowserField,
    OfficeBrowserField,
    OfficeBrowserField,
    OfficeBrowserField,
); 3] {
    [
        (
            OfficeBrowserField::WordVbaWarnings,
            OfficeBrowserField::WordBlockMacrosFromInternet,
            OfficeBrowserField::WordAccessVbom,
            OfficeBrowserField::WordProtectedViewInternet,
            OfficeBrowserField::WordProtectedViewUnsafeLocations,
            OfficeBrowserField::WordProtectedViewOutlook,
            OfficeBrowserField::WordDisableTrustedLocations,
        ),
        (
            OfficeBrowserField::ExcelVbaWarnings,
            OfficeBrowserField::ExcelBlockMacrosFromInternet,
            OfficeBrowserField::ExcelAccessVbom,
            OfficeBrowserField::ExcelProtectedViewInternet,
            OfficeBrowserField::ExcelProtectedViewUnsafeLocations,
            OfficeBrowserField::ExcelProtectedViewOutlook,
            OfficeBrowserField::ExcelDisableTrustedLocations,
        ),
        (
            OfficeBrowserField::PowerPointVbaWarnings,
            OfficeBrowserField::PowerPointBlockMacrosFromInternet,
            OfficeBrowserField::PowerPointAccessVbom,
            OfficeBrowserField::PowerPointProtectedViewInternet,
            OfficeBrowserField::PowerPointProtectedViewUnsafeLocations,
            OfficeBrowserField::PowerPointProtectedViewOutlook,
            OfficeBrowserField::PowerPointDisableTrustedLocations,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unknown_fields_and_non_allowlisted_version_are_rejected() {
        assert!(
            serde_json::from_value::<OfficeBrowserParameters>(
                serde_json::json!({"raw_path":"HKLM"})
            )
            .is_err()
        );
        assert!(
            resolve_desired_state(&OfficeBrowserParameters {
                office: Some(OfficeConfig {
                    version_major: 15,
                    ..OfficeConfig::default()
                }),
                ..OfficeBrowserParameters::default()
            })
            .is_err()
        );
    }
    #[test]
    fn missing_values_plan_then_second_plan_is_idempotent() {
        let desired = resolve_desired_state(&OfficeBrowserParameters::default()).expect("desired");
        let initial = build_plan(
            OfficeBrowserObservation {
                values: BTreeMap::new(),
            },
            desired.clone(),
        );
        assert!(!initial.mutations.is_empty());
        let values = initial
            .mutations
            .iter()
            .map(|change| (change.field, change.desired.clone()))
            .collect();
        assert!(
            build_plan(OfficeBrowserObservation { values }, desired)
                .mutations
                .is_empty()
        );
    }
    #[test]
    fn rollback_preserves_missing() {
        let plan = build_plan(
            OfficeBrowserObservation {
                values: BTreeMap::new(),
            },
            resolve_desired_state(&OfficeBrowserParameters::default()).expect("desired"),
        );
        assert!(plan.rollback.values.is_empty());
        assert_eq!(plan.mutations.len(), 29);
    }
}
