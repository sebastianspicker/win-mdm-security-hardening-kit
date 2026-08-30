//! Fixed read-only acquisition for Windows Defender Application Guard readiness.

use crate::PlatformError;
#[cfg(windows)]
use crate::{
    NativeArgumentRule, NativeEncoding, NativeExecutableTrust, NativeProcessPolicy,
    NativeProcessSpec, decode_native_output, run_native,
};
use baselineops_capabilities::WdagReadinessObservation;
#[cfg(windows)]
use baselineops_capabilities::{Observation, OptionalFeatureState};
#[cfg(windows)]
use std::collections::BTreeMap;
#[cfg(windows)]
use std::ffi::OsString;
#[cfg(windows)]
use std::time::Duration;

#[cfg(windows)]
const TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(windows)]
const OUTPUT_LIMIT: usize = 256 * 1024;
#[cfg(windows)]
const WDAG_FEATURE: &str = "Windows-Defender-ApplicationGuard";
#[cfg(windows)]
const HYPER_V_FEATURE: &str = "Microsoft-Hyper-V-All";

/// Observe fixed WDAG readiness inputs without applying Windows features or policy.
///
/// The DISM invocation accepts only the two compile-time feature names and is
/// executed directly, never through PowerShell, CMD, or another shell.
///
/// # Errors
///
/// Returns [`PlatformError::UnsupportedPlatform`] outside Windows.
pub fn audit_wdag_readiness() -> Result<WdagReadinessObservation, PlatformError> {
    #[cfg(windows)]
    {
        Ok(platform::audit_wdag_readiness())
    }
    #[cfg(not(windows))]
    {
        platform::audit_wdag_readiness()
    }
}

#[cfg(windows)]
fn feature(feature_name: &str) -> Observation<OptionalFeatureState> {
    let Ok(executable) = crate::trust::windows_system32_file("dism.exe") else {
        return Observation::Unparsed;
    };
    let working_directory = executable
        .parent()
        .expect("an API-resolved System32 executable has a parent")
        .to_path_buf();
    let policy = NativeProcessPolicy {
        executable,
        executable_trust: NativeExecutableTrust::WindowsSystemPublisher,
        working_directory,
        argument_patterns: vec![
            vec![
                NativeArgumentRule::Exact("/Online".into()),
                NativeArgumentRule::Exact("/Get-FeatureInfo".into()),
                NativeArgumentRule::Exact(format!("/FeatureName:{WDAG_FEATURE}")),
                NativeArgumentRule::Exact("/English".into()),
            ],
            vec![
                NativeArgumentRule::Exact("/Online".into()),
                NativeArgumentRule::Exact("/Get-FeatureInfo".into()),
                NativeArgumentRule::Exact(format!("/FeatureName:{HYPER_V_FEATURE}")),
                NativeArgumentRule::Exact("/English".into()),
            ],
        ],
        environment: BTreeMap::<OsString, OsString>::new(),
        max_timeout: TIMEOUT,
        max_output_limit: OUTPUT_LIMIT,
    };
    let args = vec![
        "/Online".into(),
        "/Get-FeatureInfo".into(),
        format!("/FeatureName:{feature_name}"),
        "/English".into(),
    ];
    match run_native(
        &policy,
        &NativeProcessSpec {
            args,
            timeout: TIMEOUT,
            output_limit: OUTPUT_LIMIT,
        },
    ) {
        Ok(result) => {
            let stdout = decode_native_output(&result.stdout, NativeEncoding::Utf8);
            let stderr = decode_native_output(&result.stderr, NativeEncoding::Utf8);
            match (stdout, stderr) {
                (Ok(stdout), Ok(stderr)) if result.exit_code == 0 && stderr.trim().is_empty() => {
                    parse_dism_feature_info(&stdout, feature_name)
                }
                (Ok(stdout), Ok(stderr))
                    if is_exact_absent_feature_error(
                        &format!("{stdout}\n{stderr}"),
                        feature_name,
                    ) =>
                {
                    Observation::Present(OptionalFeatureState::Absent)
                }
                (Ok(_), Ok(_)) => Observation::Failed {
                    exit_code: result.exit_code,
                },
                _ => Observation::Unparsed,
            }
        }
        Err(PlatformError::ProcessTimeout { .. }) => Observation::TimedOut,
        Err(PlatformError::OutputTooLarge { .. }) => Observation::Truncated,
        Err(PlatformError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            Observation::Missing
        }
        Err(PlatformError::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            Observation::AccessDenied
        }
        Err(_) => Observation::Unparsed,
    }
}

/// Parse only the complete English `DISM` feature grammar selected with `/English`.
#[cfg(windows)]
#[must_use]
pub fn parse_dism_feature_info(
    output: &str,
    expected_feature: &str,
) -> Observation<OptionalFeatureState> {
    if output.is_empty() || output.len() > OUTPUT_LIMIT {
        return Observation::Unparsed;
    }
    let mut feature_names = output
        .lines()
        .filter_map(|line| line.trim().strip_prefix("Feature Name : "));
    if feature_names.next() != Some(expected_feature) || feature_names.next().is_some() {
        return Observation::Unparsed;
    }
    let mut states = output
        .lines()
        .filter_map(|line| line.trim().strip_prefix("State : "));
    let (Some(state), None) = (states.next(), states.next()) else {
        return Observation::Unparsed;
    };
    match state {
        "Enabled" => Observation::Present(OptionalFeatureState::Enabled),
        "Disabled" => Observation::Present(OptionalFeatureState::Disabled),
        "Disabled with Payload Removed" => {
            Observation::Present(OptionalFeatureState::DisabledWithPayloadRemoved)
        }
        _ => Observation::Unparsed,
    }
}

#[cfg(windows)]
fn is_exact_absent_feature_error(output: &str, expected_feature: &str) -> bool {
    let lines = output.lines().map(str::trim).collect::<Vec<_>>();
    lines.contains(&"Error: 0x800f080c")
        && lines
            .iter()
            .any(|line| *line == format!("Feature name {expected_feature} is unknown."))
}

#[cfg(not(windows))]
mod platform {
    use super::{PlatformError, WdagReadinessObservation};

    pub(super) fn audit_wdag_readiness() -> Result<WdagReadinessObservation, PlatformError> {
        Err(PlatformError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
mod platform {
    #![allow(unsafe_code, unsafe_op_in_unsafe_fn)]

    use super::{HYPER_V_FEATURE, WDAG_FEATURE, WdagReadinessObservation, feature};
    use baselineops_capabilities::{Observation, WindowsEdition};
    use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
    use windows::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_READ, RegCloseKey, RegOpenKeyExW,
    };
    use windows::Win32::System::SystemInformation::{
        GetProductInfo, OS_PRODUCT_TYPE, PRODUCT_PRO_WORKSTATION, PRODUCT_PRO_WORKSTATION_N,
        PRODUCT_PROFESSIONAL, PRODUCT_PROFESSIONAL_E, PRODUCT_PROFESSIONAL_N,
        PRODUCT_PROFESSIONAL_WMC,
    };
    use windows::Win32::System::Threading::{IsProcessorFeaturePresent, PF_VIRT_FIRMWARE_ENABLED};
    use windows::core::PCWSTR;

    const APP_HVSI: &str = r"SOFTWARE\Policies\Microsoft\AppHVSI";

    pub(super) fn audit_wdag_readiness() -> WdagReadinessObservation {
        WdagReadinessObservation {
            hyper_v: feature(HYPER_V_FEATURE),
            wdag: feature(WDAG_FEATURE),
            edition: edition(),
            virtualization_firmware_enabled: Observation::Present(unsafe {
                IsProcessorFeaturePresent(PF_VIRT_FIRMWARE_ENABLED).as_bool()
            }),
            policy_configured: app_hvsi_key(),
        }
    }

    fn edition() -> Observation<WindowsEdition> {
        let mut product = OS_PRODUCT_TYPE::default();
        if !unsafe { GetProductInfo(10, 0, 0, 0, &raw mut product) }.as_bool() {
            return Observation::Unparsed;
        }
        let professional = [
            PRODUCT_PROFESSIONAL,
            PRODUCT_PROFESSIONAL_E,
            PRODUCT_PROFESSIONAL_N,
            PRODUCT_PROFESSIONAL_WMC,
            PRODUCT_PRO_WORKSTATION,
            PRODUCT_PRO_WORKSTATION_N,
        ];
        if professional.contains(&product) {
            Observation::Present(WindowsEdition::Professional)
        } else {
            Observation::Present(WindowsEdition::Other(product.0))
        }
    }

    fn app_hvsi_key() -> Observation<bool> {
        let path = APP_HVSI.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
        let mut key = HKEY::default();
        let status = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(path.as_ptr()),
                None,
                KEY_READ,
                &raw mut key,
            )
        };
        if status == ERROR_FILE_NOT_FOUND {
            return Observation::Present(false);
        }
        if status == ERROR_ACCESS_DENIED {
            return Observation::AccessDenied;
        }
        if status != ERROR_SUCCESS {
            return Observation::Unparsed;
        }
        unsafe {
            let _ = RegCloseKey(key);
        }
        Observation::Present(true)
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn parser_rejects_localized_or_partial_dism_output() {
        assert!(matches!(
            parse_dism_feature_info("State : Enabled", WDAG_FEATURE),
            Observation::Unparsed
        ));
        assert!(matches!(
            parse_dism_feature_info("Feature Name : X\nState : Aktiviert", WDAG_FEATURE),
            Observation::Unparsed
        ));
    }

    #[test]
    fn parser_accepts_only_the_expected_english_feature() {
        let output = "Feature Name : Windows-Defender-ApplicationGuard\nState : Enabled";
        assert!(matches!(
            parse_dism_feature_info(output, WDAG_FEATURE),
            Observation::Present(OptionalFeatureState::Enabled)
        ));
    }
}
