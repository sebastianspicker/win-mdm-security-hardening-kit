//! Bounded HKLM observation adapter for the native capability 05 subset.

use crate::{PlatformError, policy_registry};
use baselineops_capabilities::{WindowsUpdateField, WindowsUpdateObservation};
use std::collections::BTreeMap;

/// Observes every v3 allowlisted `WUfB` registry value. Legacy active-hours
/// metadata is intentionally excluded because the script never mutates it.
///
/// # Errors
///
/// Returns an error for an unavailable platform, denied registry access, or a
/// present value whose Windows registry type does not match its allowlisted
/// policy field.
pub fn observe_windows_update_policy() -> Result<WindowsUpdateObservation, PlatformError> {
    let mut values = BTreeMap::new();
    for (field, path, name, dword) in FIELDS {
        values.insert(
            field,
            if dword {
                policy_registry::read_dword(path, name)?
            } else {
                policy_registry::read_string(path, name)?
            },
        );
    }
    Ok(WindowsUpdateObservation { values })
}
const WU: &str = r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate";
const AU: &str = r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU";
const DO: &str = r"SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization";
const FIELDS: [(WindowsUpdateField, &str, &str, bool); 12] = [
    (WindowsUpdateField::UseWsus, AU, "UseWUServer", true),
    (WindowsUpdateField::WsusServer, WU, "WUServer", false),
    (
        WindowsUpdateField::WsusStatusServer,
        WU,
        "WUStatusServer",
        false,
    ),
    (
        WindowsUpdateField::AllowMicrosoftUpdate,
        AU,
        "AllowMUUpdateService",
        true,
    ),
    (
        WindowsUpdateField::DeferFeatureUpdates,
        WU,
        "DeferFeatureUpdates",
        true,
    ),
    (
        WindowsUpdateField::DeferFeatureDays,
        WU,
        "DeferFeatureUpdatesPeriodInDays",
        true,
    ),
    (
        WindowsUpdateField::DeferQualityUpdates,
        WU,
        "DeferQualityUpdates",
        true,
    ),
    (
        WindowsUpdateField::DeferQualityDays,
        WU,
        "DeferQualityUpdatesPeriodInDays",
        true,
    ),
    (
        WindowsUpdateField::TargetReleaseVersion,
        WU,
        "TargetReleaseVersion",
        true,
    ),
    (
        WindowsUpdateField::ProductVersion,
        WU,
        "ProductVersion",
        false,
    ),
    (
        WindowsUpdateField::TargetReleaseVersionInfo,
        WU,
        "TargetReleaseVersionInfo",
        false,
    ),
    (
        WindowsUpdateField::DeliveryOptimizationMode,
        DO,
        "DODownloadMode",
        true,
    ),
];
