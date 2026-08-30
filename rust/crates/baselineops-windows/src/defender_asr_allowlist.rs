//! Fixed, shell-free Defender WMI acquisition for capability 01.
//!
//! The adapter reads only aggregate ASR metadata from a compile-time WMI query.
//! It never invokes a shell or Defender cmdlet, and never retains exclusion text,
//! file paths, process names, extensions, or ASR rule identifiers.

use crate::PlatformError;
use baselineops_capabilities::DefenderAsrAllowlistObservation;

/// Maximum fixed ASR action values retained while aggregating non-sensitive metadata.
#[cfg(windows)]
const MAX_ASR_RULE_ACTIONS: usize = 256;
/// Maximum count accepted for the sensitive ASR-only exclusion array without reading it.
#[cfg(windows)]
const MAX_ASR_ONLY_EXCLUSIONS: usize = 10_000;

/// Observe bounded Defender ASR allowlist metadata without mutation.
///
/// # Errors
///
/// Returns [`PlatformError::UnsupportedPlatform`] outside Windows. On Windows,
/// provider and property failures remain typed incomplete evidence so the policy
/// evaluator fails closed.
pub fn audit_defender_asr_allowlist() -> Result<DefenderAsrAllowlistObservation, PlatformError> {
    #[cfg(windows)]
    {
        Ok(platform::audit_defender_asr_allowlist())
    }

    #[cfg(not(windows))]
    platform::audit_defender_asr_allowlist()
}

#[cfg(not(windows))]
mod platform {
    use super::{DefenderAsrAllowlistObservation, PlatformError};

    #[allow(clippy::unnecessary_wraps)] // Public contract distinguishes unsupported platforms.
    pub(super) fn audit_defender_asr_allowlist()
    -> Result<DefenderAsrAllowlistObservation, PlatformError> {
        Err(PlatformError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
#[allow(unsafe_code)] // Windows COM/WMI APIs require tightly scoped unsafe calls below.
mod platform {
    use super::{DefenderAsrAllowlistObservation, MAX_ASR_ONLY_EXCLUSIONS, MAX_ASR_RULE_ACTIONS};
    use baselineops_capabilities::{AsrRuleActionCounts, Observation};
    use windows::Win32::Foundation::{E_ACCESSDENIED, RPC_E_TOO_LATE};
    use windows::Win32::System::Com::{
        CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
        CoInitializeSecurity, CoSetProxyBlanket, CoUninitialize, EOAC_NONE, RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
    };
    use windows::Win32::System::Ole::{
        SafeArrayGetDim, SafeArrayGetElement, SafeArrayGetLBound, SafeArrayGetUBound,
    };
    use windows::Win32::System::Variant::{
        VARENUM, VARIANT, VARIANT_0_0, VT_ARRAY, VT_BSTR, VT_I2, VT_I4, VT_UI1, VT_UI2, VT_UI4,
        VariantClear,
    };
    use windows::Win32::System::Wmi::{
        IEnumWbemClassObject, IWbemClassObject, IWbemLocator, WBEM_E_NOT_FOUND,
        WBEM_FLAG_FORWARD_ONLY, WBEM_FLAG_RETURN_IMMEDIATELY, WBEM_INFINITE, WbemLocator,
    };
    use windows::core::{BSTR, PCWSTR};

    const DEFENDER_NAMESPACE: &str = r"ROOT\Microsoft\Windows\Defender";
    const PREFERENCE_QUERY: &str = "SELECT AttackSurfaceReductionOnlyExclusions, AttackSurfaceReductionRules_Actions FROM MSFT_MpPreference";
    const RPC_C_AUTHN_WINNT: u32 = 10;
    const RPC_C_AUTHZ_NONE: u32 = 0;

    pub(super) fn audit_defender_asr_allowlist() -> DefenderAsrAllowlistObservation {
        let provider = provider_evidence();
        match provider {
            Ok(provider) => DefenderAsrAllowlistObservation {
                asr_only_exclusion_count: provider.asr_only_exclusion_count,
                asr_rule_actions: provider.asr_rule_actions,
            },
            Err(error) => DefenderAsrAllowlistObservation {
                asr_only_exclusion_count: incomplete(&error),
                asr_rule_actions: incomplete(&error),
            },
        }
    }

    struct ProviderEvidence {
        asr_only_exclusion_count: Observation<u32>,
        asr_rule_actions: Observation<AsrRuleActionCounts>,
    }

    fn provider_evidence() -> Result<ProviderEvidence, Observation<()>> {
        // SAFETY: COM initialization and teardown are paired on this thread; all
        // interface calls use only fixed constants and locally owned buffers.
        unsafe {
            CoInitializeEx(None, COINIT_MULTITHREADED)
                .ok()
                .map_err(|error| classify(&error))?;
            let result = provider_evidence_initialized();
            CoUninitialize();
            result
        }
    }

    unsafe fn provider_evidence_initialized() -> Result<ProviderEvidence, Observation<()>> {
        // SAFETY: calls use fixed process-wide COM security settings, then only
        // provider interfaces and BSTRs owned for the duration of this function.
        unsafe {
            if let Err(error) = CoInitializeSecurity(
                None,
                -1,
                None,
                None,
                RPC_C_AUTHN_LEVEL_CALL,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                None,
                EOAC_NONE,
                None,
            ) && error.code().0 != RPC_E_TOO_LATE.0
            {
                return Err(classify(&error));
            }
            let locator: IWbemLocator = CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER)
                .map_err(|error| classify(&error))?;
            let empty = BSTR::new();
            let services = locator
                .ConnectServer(
                    &BSTR::from(DEFENDER_NAMESPACE),
                    &empty,
                    &empty,
                    &empty,
                    0,
                    &empty,
                    None,
                )
                .map_err(|error| classify(&error))?;
            CoSetProxyBlanket(
                &services,
                RPC_C_AUTHN_WINNT,
                RPC_C_AUTHZ_NONE,
                PCWSTR::null(),
                RPC_C_AUTHN_LEVEL_CALL,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                None,
                EOAC_NONE,
            )
            .map_err(|error| classify(&error))?;
            let enumerator: IEnumWbemClassObject = services
                .ExecQuery(
                    &BSTR::from("WQL"),
                    &BSTR::from(PREFERENCE_QUERY),
                    WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                    None,
                )
                .map_err(|error| classify(&error))?;
            let mut values = [None];
            let mut returned = 0_u32;
            enumerator
                .Next(WBEM_INFINITE, &mut values, &raw mut returned)
                .ok()
                .map_err(|error| classify(&error))?;
            if returned != 1 {
                return Err(Observation::Missing);
            }
            let object = values[0].take().ok_or(Observation::Unparsed)?;
            let mut additional_values = [None];
            let mut additional_returned = 0_u32;
            enumerator
                .Next(
                    WBEM_INFINITE,
                    &mut additional_values,
                    &raw mut additional_returned,
                )
                .ok()
                .map_err(|error| classify(&error))?;
            if additional_returned != 0 {
                return Err(Observation::Unparsed);
            }
            Ok(ProviderEvidence {
                asr_only_exclusion_count: exclusion_count_property(
                    &object,
                    "AttackSurfaceReductionOnlyExclusions",
                ),
                asr_rule_actions: action_counts_property(
                    &object,
                    "AttackSurfaceReductionRules_Actions",
                ),
            })
        }
    }

    unsafe fn exclusion_count_property(object: &IWbemClassObject, name: &str) -> Observation<u32> {
        // SAFETY: `object` is a valid WMI object, `wide` creates a terminated
        // property name, and `VARIANT` remains live through `VariantClear`.
        unsafe {
            let mut value = VARIANT::default();
            let name = wide(name);
            if let Err(error) = object.Get(PCWSTR(name.as_ptr()), 0, &raw mut value, None, None) {
                return property_error(&error);
            }
            let body = variant_body(&value);
            let result = if body.vt == array_type(VT_BSTR) {
                array_count(body.Anonymous.parray, MAX_ASR_ONLY_EXCLUSIONS)
            } else {
                Observation::Unparsed
            };
            let _ = VariantClear(&raw mut value);
            result
        }
    }

    unsafe fn action_counts_property(
        object: &IWbemClassObject,
        name: &str,
    ) -> Observation<AsrRuleActionCounts> {
        // SAFETY: `object` is a valid WMI object, and only scalar action bytes or
        // integers are copied from a validated one-dimensional SAFEARRAY.
        unsafe {
            let mut value = VARIANT::default();
            let name = wide(name);
            if let Err(error) = object.Get(PCWSTR(name.as_ptr()), 0, &raw mut value, None, None) {
                return property_error(&error);
            }
            let body = variant_body(&value);
            let result = action_counts_from_variant(&body);
            let _ = VariantClear(&raw mut value);
            result
        }
    }

    unsafe fn action_counts_from_variant(value: &VARIANT_0_0) -> Observation<AsrRuleActionCounts> {
        // SAFETY: each branch validates the SAFEARRAY element VARTYPE before
        // copying one value at a time within its reported bounds.
        unsafe {
            let array = value.Anonymous.parray;
            if value.vt == array_type(VT_UI1) {
                return action_counts_u8(array);
            }
            if value.vt == array_type(VT_UI2) {
                return action_counts_u16(array);
            }
            if value.vt == array_type(VT_UI4) {
                return action_counts_u32(array);
            }
            if value.vt == array_type(VT_I2) {
                return action_counts_i16(array);
            }
            if value.vt == array_type(VT_I4) {
                return action_counts_i32(array);
            }
            Observation::Unparsed
        }
    }

    unsafe fn action_counts_u8(
        array: *mut windows::Win32::System::Com::SAFEARRAY,
    ) -> Observation<AsrRuleActionCounts> {
        // SAFETY: `array` is validated by `array_bounds`; `SafeArrayGetElement`
        // writes exactly one `u8` because the VARTYPE was checked by the caller.
        unsafe {
            action_counts(array, |index| {
                safe_array_element::<u8>(array, index).map(u32::from)
            })
        }
    }

    unsafe fn action_counts_u16(
        array: *mut windows::Win32::System::Com::SAFEARRAY,
    ) -> Observation<AsrRuleActionCounts> {
        // SAFETY: element representation is validated as `VT_UI2` before reads.
        unsafe {
            action_counts(array, |index| {
                safe_array_element::<u16>(array, index).map(u32::from)
            })
        }
    }

    unsafe fn action_counts_u32(
        array: *mut windows::Win32::System::Com::SAFEARRAY,
    ) -> Observation<AsrRuleActionCounts> {
        // SAFETY: element representation is validated as `VT_UI4` before reads.
        unsafe { action_counts(array, |index| safe_array_element::<u32>(array, index)) }
    }

    unsafe fn action_counts_i16(
        array: *mut windows::Win32::System::Com::SAFEARRAY,
    ) -> Observation<AsrRuleActionCounts> {
        // SAFETY: element representation is validated as `VT_I2` before reads.
        unsafe {
            action_counts(array, |index| {
                safe_array_element::<i16>(array, index).and_then(|value| u32::try_from(value).ok())
            })
        }
    }

    unsafe fn action_counts_i32(
        array: *mut windows::Win32::System::Com::SAFEARRAY,
    ) -> Observation<AsrRuleActionCounts> {
        // SAFETY: element representation is validated as `VT_I4` before reads.
        unsafe {
            action_counts(array, |index| {
                safe_array_element::<i32>(array, index).and_then(|value| u32::try_from(value).ok())
            })
        }
    }

    unsafe fn action_counts(
        array: *mut windows::Win32::System::Com::SAFEARRAY,
        read: impl FnMut(i32) -> Option<u32>,
    ) -> Observation<AsrRuleActionCounts> {
        // SAFETY: the callback only receives indexes from the validated array bounds.
        unsafe {
            let Some((lower, count)) = array_bounds(array, MAX_ASR_RULE_ACTIONS) else {
                return Observation::Truncated;
            };
            let mut counts = AsrRuleActionCounts::default();
            let mut read = read;
            for offset in 0..count {
                let Some(index) =
                    lower.checked_add(i32::try_from(offset).expect("bounded offset fits i32"))
                else {
                    return Observation::Unparsed;
                };
                let Some(value) = read(index) else {
                    return Observation::Unparsed;
                };
                counts.record(value);
            }
            Observation::Present(counts)
        }
    }

    unsafe fn safe_array_element<T: Default>(
        array: *mut windows::Win32::System::Com::SAFEARRAY,
        index: i32,
    ) -> Option<T> {
        // SAFETY: `array` and `index` come from `array_bounds`; the caller matches
        // `T` to the SAFEARRAY VARTYPE before this value is copied.
        unsafe {
            let mut value = T::default();
            SafeArrayGetElement(array, &raw const index, (&raw mut value).cast()).ok()?;
            Some(value)
        }
    }

    unsafe fn array_count(
        array: *mut windows::Win32::System::Com::SAFEARRAY,
        maximum: usize,
    ) -> Observation<u32> {
        // SAFETY: `array_bounds` validates pointer dimensionality and derives the
        // count without reading any sensitive SAFEARRAY elements.
        unsafe {
            let Some((_, count)) = array_bounds(array, maximum) else {
                return Observation::Truncated;
            };
            u32::try_from(count).map_or(Observation::Unparsed, Observation::Present)
        }
    }

    unsafe fn array_bounds(
        array: *mut windows::Win32::System::Com::SAFEARRAY,
        maximum: usize,
    ) -> Option<(i32, usize)> {
        // SAFETY: the pointer is supplied by a live VARIANT and inspected only via
        // OleAut APIs before the owning VARIANT is cleared.
        unsafe {
            if array.is_null() || SafeArrayGetDim(array) != 1 {
                return None;
            }
            let lower = SafeArrayGetLBound(array, 1).ok()?;
            let upper = SafeArrayGetUBound(array, 1).ok()?;
            let count = if upper < lower {
                0
            } else {
                usize::try_from(i64::from(upper) - i64::from(lower) + 1).ok()?
            };
            (count <= maximum).then_some((lower, count))
        }
    }

    fn array_type(element: VARENUM) -> VARENUM {
        VARENUM(VT_ARRAY.0 | element.0)
    }

    fn property_error<T>(error: &windows::core::Error) -> Observation<T> {
        if error.code().0 == WBEM_E_NOT_FOUND.0 {
            Observation::Missing
        } else {
            incomplete(&classify(error))
        }
    }

    unsafe fn variant_body(value: &VARIANT) -> VARIANT_0_0 {
        // SAFETY: `VARIANT_0_0` is the discriminant-bearing prefix of the
        // `VARIANT` anonymous storage; the caller keeps `value` alive.
        unsafe {
            std::ptr::read_unaligned(std::ptr::from_ref(&value.Anonymous).cast::<VARIANT_0_0>())
        }
    }

    fn classify(error: &windows::core::Error) -> Observation<()> {
        if error.code().0 == E_ACCESSDENIED.0 {
            Observation::AccessDenied
        } else {
            Observation::Unparsed
        }
    }

    fn incomplete<T>(value: &Observation<()>) -> Observation<T> {
        match value {
            Observation::Missing => Observation::Missing,
            Observation::AccessDenied => Observation::AccessDenied,
            Observation::TimedOut => Observation::TimedOut,
            Observation::Truncated => Observation::Truncated,
            Observation::Failed { exit_code } => Observation::Failed {
                exit_code: *exit_code,
            },
            Observation::NotRun => Observation::NotRun,
            Observation::Present(()) | Observation::Unparsed => Observation::Unparsed,
        }
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn non_windows_acquisition_is_explicitly_unsupported() {
        #[cfg(not(windows))]
        assert!(matches!(
            super::audit_defender_asr_allowlist(),
            Err(super::PlatformError::UnsupportedPlatform)
        ));
    }
}
