//! Detached PKCS#7 manifest-signature verification.

#![allow(unsafe_code)] // Windows CryptoAPI requires FFI and explicit ownership.

use super::windows::signer::{canonical_x500_subject, verify_certificate_identity};
use crate::{PlatformError, SignerSpkiSha256};
use std::mem::size_of;
use windows::Win32::Security::Cryptography::{
    CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL, CERT_CHAIN_CONTEXT, CERT_CHAIN_PARA,
    CERT_CHAIN_POLICY_AUTHENTICODE, CERT_CHAIN_POLICY_PARA, CERT_CHAIN_POLICY_STATUS,
    CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY, CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
    CERT_CONTEXT, CERT_USAGE_MATCH, CRYPT_VERIFY_MESSAGE_PARA, CTL_USAGE, CertFreeCertificateChain,
    CertFreeCertificateContext, CertGetCertificateChain, CertVerifyCertificateChainPolicy,
    CryptVerifyDetachedMessageSignature, PKCS_7_ASN_ENCODING, USAGE_MATCH_TYPE_AND,
    X509_ASN_ENCODING, szOID_PKIX_KP_CODE_SIGNING,
};
use windows::core::PSTR;

pub(super) fn verify(
    manifest_bytes: &[u8],
    signature_bytes: &[u8],
    expected_subject: &str,
    expected_spki_sha256: &SignerSpkiSha256,
) -> Result<(), PlatformError> {
    verify_identity(
        manifest_bytes,
        signature_bytes,
        expected_subject,
        Some(expected_spki_sha256),
    )
}

pub(super) fn verify_subject(
    manifest_bytes: &[u8],
    signature_bytes: &[u8],
    expected_subject: &str,
) -> Result<(), PlatformError> {
    verify_identity(manifest_bytes, signature_bytes, expected_subject, None)
}

fn verify_identity(
    manifest_bytes: &[u8],
    signature_bytes: &[u8],
    expected_subject: &str,
    expected_spki_sha256: Option<&SignerSpkiSha256>,
) -> Result<(), PlatformError> {
    let mut signer = std::ptr::null_mut::<CERT_CONTEXT>();
    let parameters = CRYPT_VERIFY_MESSAGE_PARA {
        cbSize: u32::try_from(size_of::<CRYPT_VERIFY_MESSAGE_PARA>())
            .expect("CRYPT_VERIFY_MESSAGE_PARA size"),
        dwMsgAndCertEncodingType: X509_ASN_ENCODING.0 | PKCS_7_ASN_ENCODING.0,
        ..Default::default()
    };
    let signed_data = [manifest_bytes.as_ptr()];
    let signed_lengths = [u32::try_from(manifest_bytes.len()).map_err(|_| {
        PlatformError::TrustFailure("manifest exceeds CryptoAPI detached-signature limit".into())
    })?];
    unsafe {
        CryptVerifyDetachedMessageSignature(
            &raw const parameters,
            0,
            signature_bytes,
            1,
            signed_data.as_ptr(),
            signed_lengths.as_ptr(),
            Some(&raw mut signer),
        )
    }
    .map_err(|error| {
        PlatformError::TrustFailure(format!(
            "detached PKCS#7 signature verification failed: {error}"
        ))
    })?;
    let signer = SignerCertificate::new(signer)?;
    match expected_spki_sha256 {
        Some(expected_spki_sha256) => {
            verify_certificate_identity(signer.as_ptr(), expected_subject, expected_spki_sha256)?;
        }
        None if canonical_subject_only(signer.as_ptr())? != expected_subject => {
            return Err(PlatformError::TrustFailure(
                "detached manifest signer subject does not exactly match the external policy"
                    .into(),
            ));
        }
        None => {}
    }
    verify_code_signing_chain(signer.as_ptr())
}

fn canonical_subject_only(context: *const CERT_CONTEXT) -> Result<String, PlatformError> {
    let certificate = unsafe { context.as_ref() }.ok_or_else(|| {
        PlatformError::TrustFailure("detached signature did not return a signer certificate".into())
    })?;
    let info = unsafe { certificate.pCertInfo.as_ref() }
        .ok_or_else(|| PlatformError::TrustFailure("signer certificate has no subject".into()))?;
    canonical_x500_subject(&info.Subject)
}

fn verify_code_signing_chain(signer: *const CERT_CONTEXT) -> Result<(), PlatformError> {
    let mut code_signing_oid = PSTR(szOID_PKIX_KP_CODE_SIGNING.0.cast_mut());
    let usage = CTL_USAGE {
        cUsageIdentifier: 1,
        rgpszUsageIdentifier: &raw mut code_signing_oid,
    };
    let parameters = CERT_CHAIN_PARA {
        cbSize: u32::try_from(size_of::<CERT_CHAIN_PARA>()).expect("CERT_CHAIN_PARA size"),
        RequestedUsage: CERT_USAGE_MATCH {
            dwType: USAGE_MATCH_TYPE_AND,
            Usage: usage,
        },
        ..Default::default()
    };
    let mut chain = std::ptr::null_mut::<CERT_CHAIN_CONTEXT>();
    unsafe {
        CertGetCertificateChain(
            None,
            signer,
            None, // Current time: deliberately no timestamp lifetime semantics.
            None,
            &raw const parameters,
            CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL
                | CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY
                | CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
            None,
            &raw mut chain,
        )
    }
    .map_err(|error| {
        PlatformError::TrustFailure(format!(
            "code-signing certificate chain validation failed: {error}"
        ))
    })?;
    let chain = CertificateChain::new(chain)?;
    let policy_parameters = CERT_CHAIN_POLICY_PARA {
        cbSize: u32::try_from(size_of::<CERT_CHAIN_POLICY_PARA>())
            .expect("CERT_CHAIN_POLICY_PARA size"),
        ..Default::default()
    };
    let mut policy_status = CERT_CHAIN_POLICY_STATUS {
        cbSize: u32::try_from(size_of::<CERT_CHAIN_POLICY_STATUS>())
            .expect("CERT_CHAIN_POLICY_STATUS size"),
        ..Default::default()
    };
    let policy_call = unsafe {
        CertVerifyCertificateChainPolicy(
            CERT_CHAIN_POLICY_AUTHENTICODE,
            chain.as_ptr(),
            &raw const policy_parameters,
            &raw mut policy_status,
        )
    };
    if !policy_call.as_bool() || policy_status.dwError != 0 {
        return Err(PlatformError::TrustFailure(format!(
            "Authenticode certificate chain policy rejected detached signer (0x{:08x})",
            policy_status.dwError
        )));
    }
    Ok(())
}

struct SignerCertificate(*const CERT_CONTEXT);

impl SignerCertificate {
    fn new(context: *mut CERT_CONTEXT) -> Result<Self, PlatformError> {
        if context.is_null() {
            return Err(PlatformError::TrustFailure(
                "detached signature did not return a signer certificate".into(),
            ));
        }
        Ok(Self(context.cast_const()))
    }

    fn as_ptr(&self) -> *const CERT_CONTEXT {
        self.0
    }
}

impl Drop for SignerCertificate {
    fn drop(&mut self) {
        let _ = unsafe { CertFreeCertificateContext(Some(self.0)) };
    }
}

struct CertificateChain(*const CERT_CHAIN_CONTEXT);

impl CertificateChain {
    fn new(chain: *mut CERT_CHAIN_CONTEXT) -> Result<Self, PlatformError> {
        if chain.is_null() {
            return Err(PlatformError::TrustFailure(
                "certificate chain API returned no chain context".into(),
            ));
        }
        Ok(Self(chain.cast_const()))
    }

    fn as_ptr(&self) -> *const CERT_CHAIN_CONTEXT {
        self.0
    }
}

impl Drop for CertificateChain {
    fn drop(&mut self) {
        unsafe { CertFreeCertificateChain(self.0) };
    }
}
