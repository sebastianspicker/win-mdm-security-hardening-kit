//! Typed Windows Update for Business desired state, drift, and rollback records.
//!
//! All mutation targets are finite field identifiers. The profile can select
//! only this desired state; it cannot supply registry paths, types, commands,
//! action safety metadata, or reboot classifications.
use crate::office_browser_policy::PolicyValueSnapshot;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Maximum UTF-8 size of one bounded policy string.
pub const MAX_POLICY_STRING_BYTES: usize = 128;

/// Fixed Windows Update registry fields understood by the native foundation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsUpdateField {
    /// Whether Windows Server Update Services is selected.
    UseWsus,
    /// Windows Server Update Services content endpoint.
    WsusServer,
    /// Windows Server Update Services status endpoint.
    WsusStatusServer,
    /// Whether Microsoft Update service participation is allowed.
    AllowMicrosoftUpdate,
    /// Whether feature-update deferral is enabled.
    DeferFeatureUpdates,
    /// Feature-update deferral in days.
    DeferFeatureDays,
    /// Whether quality-update deferral is enabled.
    DeferQualityUpdates,
    /// Quality-update deferral in days.
    DeferQualityDays,
    /// Whether target-release policy is enabled.
    TargetReleaseVersion,
    /// Target Windows product family.
    ProductVersion,
    /// Target Windows feature release.
    TargetReleaseVersionInfo,
    /// Delivery Optimization download mode.
    DeliveryOptimizationMode,
}

/// Fixed observed Windows Update policy values.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct WindowsUpdateObservation {
    /// Values keyed by finite policy-field identity.
    pub values: BTreeMap<WindowsUpdateField, PolicyValueSnapshot>,
}

/// Strict profile parameters with explicit desired-over-config precedence.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, rename_all = "snake_case", deny_unknown_fields)]
pub struct WindowsUpdateParameters {
    /// Optional configuration-catalog defaults.
    pub config: Option<WindowsUpdateConfig>,
    /// Optional explicit desired state, which takes precedence over `config`.
    pub desired: Option<WindowsUpdateConfig>,
}

/// Bounded Windows Update for Business desired state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, rename_all = "snake_case", deny_unknown_fields)]
pub struct WindowsUpdateConfig {
    /// Selected update-source family.
    pub update_source: UpdateSource,
    /// Whether Microsoft Update service participation is allowed.
    pub allow_microsoft_update: bool,
    /// Feature and quality update deferrals.
    pub deferrals: Deferrals,
    /// Target-release policy.
    pub target_release: TargetRelease,
    /// Delivery Optimization policy.
    pub delivery_optimization: DeliveryOptimization,
}
impl Default for WindowsUpdateConfig {
    fn default() -> Self {
        Self {
            update_source: UpdateSource::Wufb,
            allow_microsoft_update: true,
            deferrals: Deferrals::default(),
            target_release: TargetRelease::default(),
            delivery_optimization: DeliveryOptimization::default(),
        }
    }
}
/// Finite update-source selection.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateSource {
    /// Windows Update for Business.
    #[default]
    Wufb,
    /// Windows Server Update Services; currently rejected by validation.
    Wsus,
}
/// Bounded feature and quality update deferrals.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, rename_all = "snake_case", deny_unknown_fields)]
pub struct Deferrals {
    /// Feature-update deferral in days.
    pub feature_days: u16,
    /// Quality-update deferral in days.
    pub quality_days: u8,
}
impl Default for Deferrals {
    fn default() -> Self {
        Self {
            feature_days: 30,
            quality_days: 7,
        }
    }
}
/// Desired Windows product and feature release.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, rename_all = "snake_case", deny_unknown_fields)]
pub struct TargetRelease {
    /// Whether target-release policy is enabled.
    pub enabled: bool,
    /// Bounded Windows product family.
    pub product_version: String,
    /// Bounded feature-release identifier.
    pub release: String,
}
impl Default for TargetRelease {
    fn default() -> Self {
        Self {
            enabled: false,
            product_version: "Windows 11".into(),
            release: "24H2".into(),
        }
    }
}
/// Delivery Optimization desired state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, rename_all = "snake_case", deny_unknown_fields)]
pub struct DeliveryOptimization {
    /// Finite Delivery Optimization download mode.
    pub download_mode: DownloadMode,
}
impl Default for DeliveryOptimization {
    fn default() -> Self {
        Self {
            download_mode: DownloadMode::HttpOnly,
        }
    }
}
/// Finite Delivery Optimization download modes.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DownloadMode {
    /// HTTP only, with no peer-to-peer delivery.
    #[default]
    HttpOnly,
    /// Local-network peers.
    Lan,
    /// Configured peer group.
    Group,
    /// Internet peers.
    Internet,
    /// Simple download mode.
    Simple,
}

/// One finite Windows Update policy difference.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct WindowsUpdateMutation {
    /// Fixed policy field.
    pub field: WindowsUpdateField,
    /// Desired typed registry value.
    pub desired: PolicyValueSnapshot,
}
/// Read-only Windows Update plan with rollback evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct WindowsUpdatePlan {
    /// Observed fixed policy values.
    pub observation: WindowsUpdateObservation,
    /// Validated desired state.
    pub desired: WindowsUpdateConfig,
    /// Finite proposed differences; no mutation is performed here.
    pub mutations: Vec<WindowsUpdateMutation>,
    /// Exact pre-state retained for a future authorized rollback path.
    pub rollback: WindowsUpdateObservation,
    /// Whether applying these differences would require Administrator authority.
    pub requires_administrator: bool,
    /// Whether policy activation can require a reboot.
    pub reboot_possible: bool,
}

/// # Errors
///
/// Returns an error when values exceed legacy bounds or select an unsupported
/// update source.
pub fn resolve_desired_state(
    parameters: &WindowsUpdateParameters,
) -> Result<WindowsUpdateConfig, String> {
    let desired = parameters
        .desired
        .clone()
        .or_else(|| parameters.config.clone())
        .unwrap_or_default();
    validate_deferrals(&desired.deferrals)?;
    validate_update_source(desired.update_source)?;
    validate_target_release(&desired.target_release)?;
    Ok(desired)
}

fn validate_deferrals(deferrals: &Deferrals) -> Result<(), String> {
    if deferrals.feature_days > 365 || deferrals.quality_days > 35 {
        return Err("Windows Update deferrals exceed the legacy allowlisted ranges".into());
    }
    Ok(())
}

fn validate_update_source(source: UpdateSource) -> Result<(), String> {
    if source != UpdateSource::Wufb {
        return Err(
            "WSUS is excluded until bounded server identities and service evidence are implemented"
                .into(),
        );
    }
    Ok(())
}

fn validate_target_release(target: &TargetRelease) -> Result<(), String> {
    if !valid_policy_string(&target.product_version) || !valid_policy_string(&target.release) {
        return Err("target release strings must be bounded non-empty strings without NUL".into());
    }
    Ok(())
}

fn valid_policy_string(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_POLICY_STRING_BYTES && !value.contains('\0')
}

/// Builds finite proposed differences from fixed observed policy values.
#[must_use]
pub fn build_plan(
    observation: WindowsUpdateObservation,
    desired: WindowsUpdateConfig,
) -> WindowsUpdatePlan {
    let expected = expected_values(&desired);
    let mutations = expected
        .into_iter()
        .filter_map(|(field, desired)| {
            (observation.values.get(&field) != Some(&desired))
                .then_some(WindowsUpdateMutation { field, desired })
        })
        .collect();
    WindowsUpdatePlan {
        rollback: observation.clone(),
        observation,
        desired,
        mutations,
        requires_administrator: true,
        reboot_possible: true,
    }
}

fn expected_values(
    desired: &WindowsUpdateConfig,
) -> BTreeMap<WindowsUpdateField, PolicyValueSnapshot> {
    let mut expected = BTreeMap::new();
    let use_wsus = matches!(desired.update_source, UpdateSource::Wsus);
    expected.insert(
        WindowsUpdateField::UseWsus,
        PolicyValueSnapshot::Dword(u32::from(use_wsus)),
    );
    expected.insert(
        WindowsUpdateField::AllowMicrosoftUpdate,
        PolicyValueSnapshot::Dword(u32::from(desired.allow_microsoft_update)),
    );
    expected.insert(
        WindowsUpdateField::DeferFeatureUpdates,
        PolicyValueSnapshot::Dword(1),
    );
    expected.insert(
        WindowsUpdateField::DeferFeatureDays,
        PolicyValueSnapshot::Dword(u32::from(desired.deferrals.feature_days)),
    );
    expected.insert(
        WindowsUpdateField::DeferQualityUpdates,
        PolicyValueSnapshot::Dword(1),
    );
    expected.insert(
        WindowsUpdateField::DeferQualityDays,
        PolicyValueSnapshot::Dword(u32::from(desired.deferrals.quality_days)),
    );
    expected.insert(
        WindowsUpdateField::TargetReleaseVersion,
        PolicyValueSnapshot::Dword(u32::from(desired.target_release.enabled)),
    );
    insert_target_release(&mut expected, &desired.target_release);
    expected.insert(
        WindowsUpdateField::DeliveryOptimizationMode,
        PolicyValueSnapshot::Dword(download_mode_value(
            desired.delivery_optimization.download_mode,
        )),
    );
    if !use_wsus {
        expected.insert(WindowsUpdateField::WsusServer, PolicyValueSnapshot::Missing);
        expected.insert(
            WindowsUpdateField::WsusStatusServer,
            PolicyValueSnapshot::Missing,
        );
    }
    expected
}

fn insert_target_release(
    expected: &mut BTreeMap<WindowsUpdateField, PolicyValueSnapshot>,
    target: &TargetRelease,
) {
    let product = target.enabled.then(|| target.product_version.clone());
    let release = target.enabled.then(|| target.release.clone());
    expected.insert(
        WindowsUpdateField::ProductVersion,
        product.map_or(PolicyValueSnapshot::Missing, PolicyValueSnapshot::String),
    );
    expected.insert(
        WindowsUpdateField::TargetReleaseVersionInfo,
        release.map_or(PolicyValueSnapshot::Missing, PolicyValueSnapshot::String),
    );
}

const fn download_mode_value(mode: DownloadMode) -> u32 {
    match mode {
        DownloadMode::HttpOnly => 0,
        DownloadMode::Lan => 1,
        DownloadMode::Group => 2,
        DownloadMode::Internet => 3,
        DownloadMode::Simple => 99,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unknown_and_raw_parameters_are_rejected() {
        assert!(
            serde_json::from_value::<WindowsUpdateParameters>(
                serde_json::json!({"command":"reg.exe"})
            )
            .is_err()
        );
        assert!(
            resolve_desired_state(&WindowsUpdateParameters {
                desired: Some(WindowsUpdateConfig {
                    deferrals: Deferrals {
                        feature_days: 366,
                        quality_days: 7
                    },
                    ..WindowsUpdateConfig::default()
                }),
                ..WindowsUpdateParameters::default()
            })
            .is_err()
        );
    }
    #[test]
    fn missing_and_present_values_have_reversible_deterministic_plans() {
        let desired = resolve_desired_state(&WindowsUpdateParameters::default()).expect("desired");
        let first = build_plan(
            WindowsUpdateObservation {
                values: BTreeMap::new(),
            },
            desired.clone(),
        );
        assert!(
            first
                .mutations
                .iter()
                .any(|mutation| mutation.desired == PolicyValueSnapshot::Missing)
        );
        assert!(first.rollback.values.is_empty());
        let values = first
            .mutations
            .iter()
            .map(|change| (change.field, change.desired.clone()))
            .collect();
        assert!(
            build_plan(WindowsUpdateObservation { values }, desired)
                .mutations
                .is_empty()
        );
    }
}
