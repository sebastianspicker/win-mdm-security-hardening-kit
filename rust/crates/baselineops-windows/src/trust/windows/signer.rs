//! Windows certificate identity helpers for Authenticode trust decisions.

use crate::{PlatformError, SignerSpkiSha256};
use sha2::{Digest, Sha256};
use windows::Win32::Security::Cryptography::{
    CERT_CONTEXT, CERT_X500_NAME_STR, CertNameToStrW, CryptEncodeObject, X509_ASN_ENCODING,
    X509_PUBLIC_KEY_INFO,
};

pub(in crate::trust) fn verify_certificate_identity(
    context: *const CERT_CONTEXT,
    expected_subject: &str,
    expected_spki_sha256: &SignerSpkiSha256,
) -> Result<(), PlatformError> {
    let certificate = unsafe { context.as_ref() }.ok_or_else(|| {
        PlatformError::TrustFailure("signer certificate context is missing".into())
    })?;
    let info = unsafe { certificate.pCertInfo.as_ref() }
        .ok_or_else(|| PlatformError::TrustFailure("signer certificate has no subject".into()))?;
    if canonical_x500_subject(&info.Subject)? != expected_subject {
        return Err(PlatformError::TrustFailure(
            "signer subject does not exactly match the canonical policy subject".into(),
        ));
    }
    let actual_spki = Sha256::digest(encode_subject_public_key_info(&info.SubjectPublicKeyInfo)?);
    let actual_spki: [u8; 32] = actual_spki.into();
    if !expected_spki_sha256.matches_digest(&actual_spki) {
        return Err(PlatformError::TrustFailure(
            "signer SubjectPublicKeyInfo SHA-256 does not match the external policy".into(),
        ));
    }
    Ok(())
}

pub(in crate::trust) fn canonical_x500_subject(
    encoded_subject: &windows::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB,
) -> Result<String, PlatformError> {
    let characters =
        unsafe { CertNameToStrW(X509_ASN_ENCODING, encoded_subject, CERT_X500_NAME_STR, None) };
    if characters == 0 {
        return Err(PlatformError::TrustFailure(
            "could not canonicalize the signer X.500 subject".into(),
        ));
    }
    let mut buffer = vec![0_u16; usize::try_from(characters).expect("subject length")];
    let written = unsafe {
        CertNameToStrW(
            X509_ASN_ENCODING,
            encoded_subject,
            CERT_X500_NAME_STR,
            Some(&mut buffer),
        )
    };
    if written != characters || buffer.last() != Some(&0) {
        return Err(PlatformError::TrustFailure(
            "could not read the canonical signer X.500 subject".into(),
        ));
    }
    buffer.pop();
    String::from_utf16(&buffer)
        .map_err(|_| PlatformError::TrustFailure("signer X.500 subject is not valid UTF-16".into()))
}

fn encode_subject_public_key_info(
    public_key_info: &windows::Win32::Security::Cryptography::CERT_PUBLIC_KEY_INFO,
) -> Result<Vec<u8>, PlatformError> {
    let mut length = 0_u32;
    unsafe {
        CryptEncodeObject(
            X509_ASN_ENCODING,
            X509_PUBLIC_KEY_INFO,
            std::ptr::from_ref(public_key_info).cast(),
            None,
            &raw mut length,
        )
    }
    .map_err(|error| {
        PlatformError::TrustFailure(format!(
            "could not encode signer SubjectPublicKeyInfo: {error}"
        ))
    })?;
    if length == 0 {
        return Err(PlatformError::TrustFailure(
            "signer SubjectPublicKeyInfo encoding is empty".into(),
        ));
    }
    let mut encoded = vec![0_u8; usize::try_from(length).expect("SPKI encoding length")];
    unsafe {
        CryptEncodeObject(
            X509_ASN_ENCODING,
            X509_PUBLIC_KEY_INFO,
            std::ptr::from_ref(public_key_info).cast(),
            Some(encoded.as_mut_ptr()),
            &raw mut length,
        )
    }
    .map_err(|error| {
        PlatformError::TrustFailure(format!(
            "could not encode signer SubjectPublicKeyInfo: {error}"
        ))
    })?;
    encoded.truncate(usize::try_from(length).expect("SPKI encoding length"));
    if encoded.is_empty() {
        return Err(PlatformError::TrustFailure(
            "signer SubjectPublicKeyInfo encoding is empty".into(),
        ));
    }
    Ok(encoded)
}
