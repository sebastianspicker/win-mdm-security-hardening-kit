//! Fixed read-only machine certificate-store and `AutoEnrollment` policy acquisition.

use crate::PlatformError;
use baselineops_capabilities::CertHealthObservation;

/// Maximum fixed records retained from `LocalMachine/My` before reporting truncation.
#[cfg(windows)]
const MAX_MACHINE_CERTIFICATES: usize = 256;
/// Fixed machine group-policy key used for `AutoEnrollment` configuration.
#[cfg(windows)]
const AUTO_ENROLLMENT_POLICY_KEY: &str = r"SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment";
/// Fixed `LocalMachine` system-store name. No user-controlled paths are accepted.
#[cfg(windows)]
const MACHINE_MY_STORE_NAME: [u16; 3] = [b'M' as u16, b'y' as u16, 0];

/// Acquires fixed certificate-health evidence without enrollment, deletion, or mutation.
///
/// # Errors
///
/// Returns [`PlatformError::UnsupportedPlatform`] outside Windows. Missing,
/// denied, malformed, and bounded-incomplete Windows evidence stays typed in
/// the returned observation.
pub fn audit_cert_health() -> Result<CertHealthObservation, PlatformError> {
    #[cfg(windows)]
    {
        Ok(CertHealthObservation {
            auto_enrollment_policy: auto_enrollment_policy(),
            machine_certificates: machine_certificates(),
        })
    }
    #[cfg(not(windows))]
    {
        Err(PlatformError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
fn auto_enrollment_policy()
-> baselineops_capabilities::Observation<baselineops_capabilities::AutoEnrollmentPolicy> {
    use baselineops_capabilities::{AutoEnrollmentPolicy, Observation, PolicyValueSnapshot};

    match crate::policy_registry::read_dword(AUTO_ENROLLMENT_POLICY_KEY, "AEPolicy") {
        Ok(PolicyValueSnapshot::Dword(flags @ 0..=7)) => u8::try_from(flags)
            .map_or(Observation::Unparsed, |flags| {
                Observation::Present(AutoEnrollmentPolicy { flags })
            }),
        Ok(PolicyValueSnapshot::Missing) => Observation::Missing,
        Err(PlatformError::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            Observation::AccessDenied
        }
        Ok(PolicyValueSnapshot::Dword(_) | PolicyValueSnapshot::String(_)) | Err(_) => {
            Observation::Unparsed
        }
    }
}

#[cfg(windows)]
fn machine_certificates()
-> baselineops_capabilities::Observation<Vec<baselineops_capabilities::MachineCertificateMetadata>>
{
    platform::machine_certificates()
}

#[cfg(windows)]
mod platform {
    #![allow(unsafe_code)] // Crypt32 handles are confined to this read-only adapter.

    use baselineops_capabilities::{MachineCertificateMetadata, Observation};
    use windows::Win32::Security::Cryptography::{
        CERT_CONTEXT, CERT_OPEN_STORE_FLAGS, CERT_QUERY_ENCODING_TYPE, CERT_SHA1_HASH_PROP_ID,
        CERT_STORE_OPEN_EXISTING_FLAG, CERT_STORE_PROV_SYSTEM_W, CERT_STORE_READONLY_FLAG,
        CERT_SYSTEM_STORE_LOCAL_MACHINE, CertCloseStore, CertEnumCertificatesInStore,
        CertFreeCertificateContext, CertGetCertificateContextProperty, CertOpenStore, HCERTSTORE,
    };

    use super::{MACHINE_MY_STORE_NAME, MAX_MACHINE_CERTIFICATES};

    pub(super) fn machine_certificates() -> Observation<Vec<MachineCertificateMetadata>> {
        let Ok(store) = open_machine_my_store() else {
            return Observation::Unparsed;
        };
        let mut certificates: Vec<MachineCertificateMetadata> = Vec::new();
        let mut previous = None;
        loop {
            let raw = unsafe {
                CertEnumCertificatesInStore(
                    store.0,
                    previous.take().map(CertificateContext::into_raw),
                )
            };
            if raw.is_null() {
                certificates
                    .sort_by(|left, right| left.sha1_thumbprint.cmp(&right.sha1_thumbprint));
                return Observation::Present(certificates);
            }
            let context = CertificateContext(raw);
            let Some(metadata) = metadata(&context) else {
                return Observation::Unparsed;
            };
            certificates.push(metadata);
            if certificates.len() == MAX_MACHINE_CERTIFICATES {
                return Observation::Truncated;
            }
            previous = Some(context);
        }
    }

    fn open_machine_my_store() -> windows::core::Result<Store> {
        let flags = CERT_OPEN_STORE_FLAGS(
            CERT_SYSTEM_STORE_LOCAL_MACHINE
                | CERT_STORE_OPEN_EXISTING_FLAG.0
                | CERT_STORE_READONLY_FLAG.0,
        );
        let raw = unsafe {
            CertOpenStore(
                CERT_STORE_PROV_SYSTEM_W,
                CERT_QUERY_ENCODING_TYPE(0),
                None,
                flags,
                Some(MACHINE_MY_STORE_NAME.as_ptr().cast()),
            )?
        };
        Ok(Store(raw))
    }

    fn metadata(context: &CertificateContext) -> Option<MachineCertificateMetadata> {
        let certificate = unsafe { context.0.as_ref() }?;
        let info = unsafe { certificate.pCertInfo.as_ref() }?;
        let not_after_unix_seconds = filetime_to_unix_seconds(info.NotAfter)?;
        let sha1_thumbprint = sha1_thumbprint(context)?;
        Some(MachineCertificateMetadata {
            sha1_thumbprint,
            not_after_unix_seconds,
            has_private_key: has_private_key(context),
        })
    }

    fn sha1_thumbprint(context: &CertificateContext) -> Option<String> {
        let mut length = 0_u32;
        unsafe {
            CertGetCertificateContextProperty(
                context.0,
                CERT_SHA1_HASH_PROP_ID,
                None,
                &raw mut length,
            )
        }
        .ok()?;
        if length != 20 {
            return None;
        }
        let mut bytes = [0_u8; 20];
        unsafe {
            CertGetCertificateContextProperty(
                context.0,
                CERT_SHA1_HASH_PROP_ID,
                Some(bytes.as_mut_ptr().cast()),
                &raw mut length,
            )
        }
        .ok()?;
        (length == 20).then(|| hex::encode(bytes))
    }

    fn has_private_key(context: &CertificateContext) -> bool {
        const CERT_KEY_PROV_INFO_PROP_ID: u32 = 2;
        let mut length = 0_u32;
        unsafe {
            CertGetCertificateContextProperty(
                context.0,
                CERT_KEY_PROV_INFO_PROP_ID,
                None,
                &raw mut length,
            )
        }
        .is_ok()
            && length > 0
    }

    fn filetime_to_unix_seconds(value: windows::Win32::Foundation::FILETIME) -> Option<i64> {
        const WINDOWS_TO_UNIX_EPOCH_SECONDS: u64 = 11_644_473_600;
        let ticks = (u64::from(value.dwHighDateTime) << 32) | u64::from(value.dwLowDateTime);
        let seconds = ticks / 10_000_000;
        let seconds = seconds.checked_sub(WINDOWS_TO_UNIX_EPOCH_SECONDS)?;
        i64::try_from(seconds).ok()
    }

    struct Store(HCERTSTORE);

    impl Drop for Store {
        fn drop(&mut self) {
            unsafe {
                let _ = CertCloseStore(Some(self.0), 0);
            }
        }
    }

    struct CertificateContext(*const CERT_CONTEXT);

    impl CertificateContext {
        fn into_raw(self) -> *const CERT_CONTEXT {
            let raw = self.0;
            std::mem::forget(self);
            raw
        }
    }

    impl Drop for CertificateContext {
        fn drop(&mut self) {
            unsafe {
                let _ = CertFreeCertificateContext(Some(self.0));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn non_windows_acquisition_is_explicitly_unsupported() {
        #[cfg(not(windows))]
        assert!(matches!(
            super::audit_cert_health(),
            Err(super::PlatformError::UnsupportedPlatform)
        ));
    }
}
