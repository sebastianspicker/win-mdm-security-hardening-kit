use super::signer::{canonical_x500_subject, verify_certificate_identity};
use crate::{PlatformError, SignerSpkiSha256};
use std::mem::size_of;
use std::path::Path;
use windows::Win32::Foundation::{HANDLE, HWND};
use windows::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
    WTD_CHOICE_FILE, WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, WTD_REVOKE_WHOLECHAIN,
    WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTD_UICONTEXT_EXECUTE,
    WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust,
};
use windows::core::PCWSTR;

pub(super) fn verify_subject(
    handle: HANDLE,
    final_path: &Path,
    expected_subject: &str,
) -> Result<(), PlatformError> {
    verify_identity(handle, final_path, expected_subject, None)
}

pub(super) fn verify(
    handle: HANDLE,
    final_path: &Path,
    expected_subject: &str,
    expected_spki_sha256: &SignerSpkiSha256,
) -> Result<(), PlatformError> {
    verify_identity(
        handle,
        final_path,
        expected_subject,
        Some(expected_spki_sha256),
    )
}

fn verify_identity(
    handle: HANDLE,
    final_path: &Path,
    expected_subject: &str,
    expected_spki_sha256: Option<&SignerSpkiSha256>,
) -> Result<(), PlatformError> {
    let path = wide_path(final_path)?;
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: u32::try_from(size_of::<WINTRUST_FILE_INFO>()).expect("WINTRUST_FILE_INFO size"),
        pcwszFilePath: PCWSTR(path.as_ptr()),
        hFile: handle,
        pgKnownSubject: std::ptr::null_mut(),
    };
    let mut trust_data = WINTRUST_DATA {
        cbStruct: u32::try_from(size_of::<WINTRUST_DATA>()).expect("WINTRUST_DATA size"),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &raw mut file_info,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
        dwUIContext: WTD_UICONTEXT_EXECUTE,
        ..Default::default()
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let status = unsafe {
        WinVerifyTrust(
            HWND::default(),
            &raw mut action,
            (&raw mut trust_data).cast(),
        )
    };
    let verification_result = if status != 0 {
        Err(PlatformError::TrustFailure(format!(
            "WinVerifyTrust rejected the executable (0x{:08x})",
            status.cast_unsigned()
        )))
    } else {
        unsafe {
            signed_certificate(trust_data.hWVTStateData).and_then(|context| {
                match expected_spki_sha256 {
                    Some(expected_spki_sha256) => {
                        verify_certificate_identity(context, expected_subject, expected_spki_sha256)
                    }
                    None => verify_subject_only(context, expected_subject),
                }
            })
        }
    };
    // A VERIFY call must always be paired with exactly one CLOSE call, including
    // a rejected verification whose state data cannot be inspected.
    let close_status = unsafe { close_state(&mut action, &mut trust_data) };
    finish_verification(verification_result, close_status)
}

fn finish_verification(
    verification_result: Result<(), PlatformError>,
    close_status: i32,
) -> Result<(), PlatformError> {
    verification_result?;
    if close_status != 0 {
        return Err(PlatformError::TrustFailure(format!(
            "WinVerifyTrust state cleanup failed (0x{:08x})",
            close_status.cast_unsigned()
        )));
    }
    Ok(())
}

unsafe fn verify_subject_only(
    context: *const windows::Win32::Security::Cryptography::CERT_CONTEXT,
    expected_subject: &str,
) -> Result<(), PlatformError> {
    let certificate = unsafe { context.as_ref() }.ok_or_else(|| {
        PlatformError::TrustFailure("signer certificate context is missing".into())
    })?;
    let info = unsafe { certificate.pCertInfo.as_ref() }
        .ok_or_else(|| PlatformError::TrustFailure("signer certificate has no subject".into()))?;
    if canonical_x500_subject(&info.Subject)? != expected_subject {
        return Err(PlatformError::TrustFailure(
            "Authenticode signer subject does not exactly match the canonical policy subject"
                .into(),
        ));
    }
    Ok(())
}

unsafe fn signed_certificate(
    state: HANDLE,
) -> Result<*const windows::Win32::Security::Cryptography::CERT_CONTEXT, PlatformError> {
    // WinTrust owns the returned provider data until the matching CLOSE call.
    let provider = unsafe { WTHelperProvDataFromStateData(state) };
    if provider.is_null() {
        return Err(PlatformError::TrustFailure(
            "WinVerifyTrust did not expose signer data".into(),
        ));
    }
    let signer = unsafe { WTHelperGetProvSignerFromChain(provider, 0, false, 0) };
    if signer.is_null() || unsafe { (*signer).csCertChain } == 0 {
        return Err(PlatformError::TrustFailure(
            "WinVerifyTrust did not expose an embedded signer certificate".into(),
        ));
    }
    let certificate = unsafe { (*signer).pasCertChain };
    if certificate.is_null() || unsafe { (*certificate).pCert }.is_null() {
        return Err(PlatformError::TrustFailure(
            "WinVerifyTrust signer certificate is missing".into(),
        ));
    }
    let context = unsafe { (*certificate).pCert };
    Ok(context)
}

unsafe fn close_state(action: &mut windows::core::GUID, trust_data: &mut WINTRUST_DATA) -> i32 {
    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe {
        WinVerifyTrust(
            HWND::default(),
            action,
            std::ptr::from_mut::<WINTRUST_DATA>(trust_data).cast(),
        )
    }
}

fn wide_path(path: &Path) -> Result<Vec<u16>, PlatformError> {
    use std::os::windows::ffi::OsStrExt;

    let mut value: Vec<u16> = path.as_os_str().encode_wide().collect();
    if value.contains(&0) {
        return Err(PlatformError::TrustFailure(
            "executable path contains an interior NUL".into(),
        ));
    }
    value.push(0);
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_with_interior_nul_is_rejected() {
        assert!(wide_path(Path::new("C:\\bad\0.exe")).is_err());
    }

    #[test]
    fn failed_verification_remains_primary_when_state_cleanup_also_fails() {
        let primary = PlatformError::TrustFailure("primary verification failure".into());
        let result = finish_verification(Err(primary), -1);
        assert!(matches!(
            result,
            Err(PlatformError::TrustFailure(message)) if message == "primary verification failure"
        ));
    }

    #[test]
    fn state_cleanup_failure_is_reported_after_successful_verification() {
        let result = finish_verification(Ok(()), -1);
        assert!(matches!(
            result,
            Err(PlatformError::TrustFailure(message)) if message.contains("state cleanup failed")
        ));
    }
}
