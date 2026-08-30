//! Bounded HKLM observation adapter for the native capability 04 subset.

use crate::{PlatformError, policy_registry};
use baselineops_capabilities::{OfficeBrowserField, OfficeBrowserObservation, PolicyValueSnapshot};
use std::collections::BTreeMap;

/// Observes the finite Office 16 and mandatory-Edge fields supported by v3.
/// Firefox and dynamic Edge startup URLs are explicitly outside this adapter.
///
/// # Errors
///
/// Returns an error for an unavailable platform, denied registry access, or a
/// present value whose Windows registry type does not match its allowlisted
/// policy field.
pub fn observe_office_browser_policy() -> Result<OfficeBrowserObservation, PlatformError> {
    let mut values = BTreeMap::new();
    for (field, path, name, dword, current_user) in FIELDS {
        values.insert(field, read(path, name, dword, current_user)?);
    }
    Ok(OfficeBrowserObservation { values })
}
fn read(
    path: &'static str,
    name: &'static str,
    dword: bool,
    current_user: bool,
) -> Result<PolicyValueSnapshot, PlatformError> {
    if current_user {
        policy_registry::read_hkcu_dword(path, name)
    } else if dword {
        policy_registry::read_dword(path, name)
    } else {
        policy_registry::read_string(path, name)
    }
}

const EDGE: &str = r"SOFTWARE\Policies\Microsoft\Edge";
const WORD: &str = r"SOFTWARE\Policies\Microsoft\Office\16.0\word\security";
const EXCEL: &str = r"SOFTWARE\Policies\Microsoft\Office\16.0\excel\security";
const POWERPOINT: &str = r"SOFTWARE\Policies\Microsoft\Office\16.0\powerpoint\security";
const FIELDS: [(OfficeBrowserField, &str, &str, bool, bool); 29] = [
    (
        OfficeBrowserField::WordVbaWarnings,
        WORD,
        "VBAWarnings",
        true,
        true,
    ),
    (
        OfficeBrowserField::ExcelVbaWarnings,
        EXCEL,
        "VBAWarnings",
        true,
        true,
    ),
    (
        OfficeBrowserField::PowerPointVbaWarnings,
        POWERPOINT,
        "VBAWarnings",
        true,
        true,
    ),
    (
        OfficeBrowserField::WordBlockMacrosFromInternet,
        WORD,
        "blockcontentexecutionfrominternet",
        true,
        true,
    ),
    (
        OfficeBrowserField::ExcelBlockMacrosFromInternet,
        EXCEL,
        "blockcontentexecutionfrominternet",
        true,
        true,
    ),
    (
        OfficeBrowserField::PowerPointBlockMacrosFromInternet,
        POWERPOINT,
        "blockcontentexecutionfrominternet",
        true,
        true,
    ),
    (
        OfficeBrowserField::WordAccessVbom,
        WORD,
        "AccessVBOM",
        true,
        true,
    ),
    (
        OfficeBrowserField::ExcelAccessVbom,
        EXCEL,
        "AccessVBOM",
        true,
        true,
    ),
    (
        OfficeBrowserField::PowerPointAccessVbom,
        POWERPOINT,
        "AccessVBOM",
        true,
        true,
    ),
    (
        OfficeBrowserField::WordProtectedViewInternet,
        concat!(
            r"SOFTWARE\Policies\Microsoft\Office\16.0\word\security",
            r"\protectedview"
        ),
        "DisableInternetFilesInPV",
        true,
        true,
    ),
    (
        OfficeBrowserField::ExcelProtectedViewInternet,
        concat!(
            r"SOFTWARE\Policies\Microsoft\Office\16.0\excel\security",
            r"\protectedview"
        ),
        "DisableInternetFilesInPV",
        true,
        true,
    ),
    (
        OfficeBrowserField::PowerPointProtectedViewInternet,
        concat!(
            r"SOFTWARE\Policies\Microsoft\Office\16.0\powerpoint\security",
            r"\protectedview"
        ),
        "DisableInternetFilesInPV",
        true,
        true,
    ),
    (
        OfficeBrowserField::WordProtectedViewUnsafeLocations,
        concat!(
            r"SOFTWARE\Policies\Microsoft\Office\16.0\word\security",
            r"\protectedview"
        ),
        "DisableUnsafeLocationsInPV",
        true,
        true,
    ),
    (
        OfficeBrowserField::ExcelProtectedViewUnsafeLocations,
        concat!(
            r"SOFTWARE\Policies\Microsoft\Office\16.0\excel\security",
            r"\protectedview"
        ),
        "DisableUnsafeLocationsInPV",
        true,
        true,
    ),
    (
        OfficeBrowserField::PowerPointProtectedViewUnsafeLocations,
        concat!(
            r"SOFTWARE\Policies\Microsoft\Office\16.0\powerpoint\security",
            r"\protectedview"
        ),
        "DisableUnsafeLocationsInPV",
        true,
        true,
    ),
    (
        OfficeBrowserField::WordProtectedViewOutlook,
        concat!(
            r"SOFTWARE\Policies\Microsoft\Office\16.0\word\security",
            r"\protectedview"
        ),
        "DisableAttachmentsInPV",
        true,
        true,
    ),
    (
        OfficeBrowserField::ExcelProtectedViewOutlook,
        concat!(
            r"SOFTWARE\Policies\Microsoft\Office\16.0\excel\security",
            r"\protectedview"
        ),
        "DisableAttachmentsInPV",
        true,
        true,
    ),
    (
        OfficeBrowserField::PowerPointProtectedViewOutlook,
        concat!(
            r"SOFTWARE\Policies\Microsoft\Office\16.0\powerpoint\security",
            r"\protectedview"
        ),
        "DisableAttachmentsInPV",
        true,
        true,
    ),
    (
        OfficeBrowserField::WordDisableTrustedLocations,
        concat!(
            r"SOFTWARE\Policies\Microsoft\Office\16.0\word\security",
            r"\trusted locations"
        ),
        "AllLocationsDisabled",
        true,
        true,
    ),
    (
        OfficeBrowserField::ExcelDisableTrustedLocations,
        concat!(
            r"SOFTWARE\Policies\Microsoft\Office\16.0\excel\security",
            r"\trusted locations"
        ),
        "AllLocationsDisabled",
        true,
        true,
    ),
    (
        OfficeBrowserField::PowerPointDisableTrustedLocations,
        concat!(
            r"SOFTWARE\Policies\Microsoft\Office\16.0\powerpoint\security",
            r"\trusted locations"
        ),
        "AllLocationsDisabled",
        true,
        true,
    ),
    (
        OfficeBrowserField::EdgeSmartScreen,
        EDGE,
        "SmartScreenEnabled",
        true,
        false,
    ),
    (
        OfficeBrowserField::EdgePua,
        EDGE,
        "SmartScreenPuaEnabled",
        true,
        false,
    ),
    (
        OfficeBrowserField::EdgePasswordManager,
        EDGE,
        "PasswordManagerEnabled",
        true,
        false,
    ),
    (
        OfficeBrowserField::EdgeAutofillAddress,
        EDGE,
        "AutofillAddressEnabled",
        true,
        false,
    ),
    (
        OfficeBrowserField::EdgeAutofillCreditCard,
        EDGE,
        "AutofillCreditCardEnabled",
        true,
        false,
    ),
    (
        OfficeBrowserField::EdgeSyncDisabled,
        EDGE,
        "SyncDisabled",
        true,
        false,
    ),
    (
        OfficeBrowserField::EdgeSslVersionMin,
        EDGE,
        "SSLVersionMin",
        false,
        false,
    ),
    (
        OfficeBrowserField::EdgeTrackingPrevention,
        EDGE,
        "TrackingPrevention",
        true,
        false,
    ),
];
