//! Shell-free installed-software and Windows Update history acquisition.

use crate::PlatformError;
use baselineops_capabilities::{Observation, SoftwareInventoryObservation};

/// Enumerate bounded HKLM 32-bit and 64-bit uninstall entries without execution data.
///
/// # Errors
///
/// Returns [`PlatformError::UnsupportedPlatform`] outside Windows. Per-value
/// access failures remain in the returned typed observation.
pub fn audit_software_inventory() -> Result<SoftwareInventoryObservation, PlatformError> {
    platform::audit_software_inventory()
}

/// Observe installed KB identities from bounded Windows Update Agent history.
///
/// The WUA history title is used only to extract canonical `KB` identities;
/// unrecognized localized titles are not guessed and make the source incomplete.
///
/// # Errors
///
/// Returns an error when the platform is unsupported or the Windows Update Agent cannot be read.
pub fn audit_installed_kbs() -> Result<Observation<Vec<String>>, PlatformError> {
    platform::audit_installed_kbs()
}

#[cfg(not(windows))]
mod platform {
    use super::{Observation, PlatformError, SoftwareInventoryObservation};
    pub(super) fn audit_software_inventory() -> Result<SoftwareInventoryObservation, PlatformError>
    {
        Err(PlatformError::UnsupportedPlatform)
    }
    pub(super) fn audit_installed_kbs() -> Result<Observation<Vec<String>>, PlatformError> {
        Err(PlatformError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
mod platform {
    #![allow(unsafe_code, unsafe_op_in_unsafe_fn)]
    use super::{Observation, PlatformError, SoftwareInventoryObservation};
    use baselineops_capabilities::{
        MAX_INSTALLED_KBS, MAX_SOFTWARE_RECORDS, SoftwareInventoryRecord, SoftwareRegistryView,
        canonical_kb,
    };
    use std::collections::BTreeSet;
    use windows::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS,
        ERROR_SUCCESS,
    };
    use windows::Win32::System::Com::{
        CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
        CoUninitialize,
    };
    use windows::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY, REG_SAM_FLAGS,
        REG_SZ, REG_VALUE_TYPE, RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW,
    };
    use windows::Win32::System::UpdateAgent::{IUpdateSession, UpdateSession};
    use windows::core::{PCWSTR, PWSTR};

    const UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    const MAX_VALUE_BYTES: u32 = 64 * 1024;

    pub(super) fn audit_software_inventory() -> Result<SoftwareInventoryObservation, PlatformError>
    {
        unsafe {
            let (mut records, first_complete) =
                uninstall_view(SoftwareRegistryView::Registry64, KEY_WOW64_64KEY)?;
            let (second, second_complete) =
                uninstall_view(SoftwareRegistryView::Registry32, KEY_WOW64_32KEY)?;
            records.extend(second);
            Ok(SoftwareInventoryObservation {
                records,
                enumeration_complete: first_complete && second_complete,
            })
        }
    }

    pub(super) fn audit_installed_kbs() -> Result<Observation<Vec<String>>, PlatformError> {
        unsafe {
            let _apartment = ComApartment::initialize()?;
            update_history()
        }
    }

    unsafe fn uninstall_view(
        view: SoftwareRegistryView,
        wow: REG_SAM_FLAGS,
    ) -> Result<(Vec<Observation<SoftwareInventoryRecord>>, bool), PlatformError> {
        let path = wide(UNINSTALL);
        let mut root = HKEY::default();
        let status = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(path.as_ptr()),
            None,
            KEY_READ | wow,
            &raw mut root,
        );
        if status == ERROR_ACCESS_DENIED {
            return Ok((vec![Observation::AccessDenied], true));
        }
        if status != ERROR_SUCCESS {
            return Err(PlatformError::TrustFailure(format!(
                "uninstall registry open failed: {}",
                status.0
            )));
        }
        let root = OwnedKey(root);
        let mut records = Vec::new();
        let mut complete = true;
        for index in 0..u32::try_from(MAX_SOFTWARE_RECORDS).expect("software bound fits u32") {
            let mut name = vec![0_u16; 512];
            let mut length = u32::try_from(name.len()).expect("key buffer fits u32");
            let status = RegEnumKeyExW(
                root.0,
                index,
                Some(PWSTR(name.as_mut_ptr())),
                &raw mut length,
                None,
                None,
                None,
                None,
            );
            if status == ERROR_NO_MORE_ITEMS {
                break;
            }
            if status == ERROR_MORE_DATA {
                records.push(Observation::Truncated);
                continue;
            }
            if status == ERROR_ACCESS_DENIED {
                records.push(Observation::AccessDenied);
                continue;
            }
            if status != ERROR_SUCCESS {
                records.push(Observation::Unparsed);
                continue;
            }
            let Ok(key_name) = String::from_utf16(&name[..usize::try_from(length).unwrap_or(0)])
            else {
                records.push(Observation::Unparsed);
                continue;
            };
            records.push(read_entry(root.0, &key_name, view));
            if index + 1 == u32::try_from(MAX_SOFTWARE_RECORDS).expect("software bound fits u32") {
                complete = false;
            }
        }
        Ok((records, complete))
    }

    unsafe fn read_entry(
        root: HKEY,
        key_name: &str,
        source_view: SoftwareRegistryView,
    ) -> Observation<SoftwareInventoryRecord> {
        let key = wide(key_name);
        let mut handle = HKEY::default();
        let status = RegOpenKeyExW(root, PCWSTR(key.as_ptr()), None, KEY_READ, &raw mut handle);
        if status == ERROR_ACCESS_DENIED {
            return Observation::AccessDenied;
        }
        if status != ERROR_SUCCESS {
            return Observation::Unparsed;
        }
        let handle = OwnedKey(handle);
        let record = SoftwareInventoryRecord {
            source_view,
            key_name: key_name.into(),
            display_name: read_string(handle.0, "DisplayName"),
            display_version: read_string(handle.0, "DisplayVersion"),
            publisher: read_string(handle.0, "Publisher"),
        };
        Observation::Present(record)
    }

    unsafe fn read_string(key: HKEY, name: &str) -> Observation<String> {
        let name = wide(name);
        let mut kind = REG_VALUE_TYPE::default();
        let mut bytes = 0_u32;
        let status = RegQueryValueExW(
            key,
            PCWSTR(name.as_ptr()),
            None,
            Some(&raw mut kind),
            None,
            Some(&raw mut bytes),
        );
        if status == ERROR_FILE_NOT_FOUND {
            return Observation::Missing;
        }
        if status == ERROR_ACCESS_DENIED {
            return Observation::AccessDenied;
        }
        if status != ERROR_SUCCESS {
            return Observation::Unparsed;
        }
        if kind != REG_SZ || bytes == 0 {
            return Observation::Missing;
        }
        if bytes > MAX_VALUE_BYTES || !bytes.is_multiple_of(2) {
            return Observation::Truncated;
        }
        let mut value = vec![0_u16; bytes as usize / 2];
        let capacity = bytes;
        let status = RegQueryValueExW(
            key,
            PCWSTR(name.as_ptr()),
            None,
            Some(&raw mut kind),
            Some(value.as_mut_ptr().cast()),
            Some(&raw mut bytes),
        );
        if status == ERROR_ACCESS_DENIED {
            return Observation::AccessDenied;
        }
        if status != ERROR_SUCCESS || bytes > capacity || !bytes.is_multiple_of(2) {
            return Observation::Unparsed;
        }
        let length = value[..usize::try_from(bytes / 2).unwrap_or(0)]
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(usize::try_from(bytes / 2).unwrap_or(0));
        String::from_utf16(&value[..length]).map_or(Observation::Unparsed, Observation::Present)
    }

    unsafe fn update_history() -> Result<Observation<Vec<String>>, PlatformError> {
        let session: IUpdateSession = CoCreateInstance(&UpdateSession, None, CLSCTX_INPROC_SERVER)
            .map_err(|error| com_error(&error))?;
        let searcher = session
            .CreateUpdateSearcher()
            .map_err(|error| com_error(&error))?;
        let total = searcher
            .GetTotalHistoryCount()
            .map_err(|error| com_error(&error))?;
        if total < 0 {
            return Ok(Observation::Unparsed);
        }
        let retained = usize::try_from(total)
            .unwrap_or(usize::MAX)
            .min(MAX_INSTALLED_KBS);
        let history = searcher
            .QueryHistory(0, i32::try_from(retained).expect("KB bound fits i32"))
            .map_err(|error| com_error(&error))?;
        let mut kbs = BTreeSet::new();
        let mut complete = retained == usize::try_from(total).unwrap_or(usize::MAX);
        for index in 0..history.Count().map_err(|error| com_error(&error))? {
            match history.get_Item(index).and_then(|entry| entry.Title()) {
                Ok(title) => {
                    if let Some(kb) = kb_from_title(&title.to_string()) {
                        kbs.insert(kb);
                    } else {
                        complete = false;
                    }
                }
                Err(_) => complete = false,
            }
        }
        Ok(if complete {
            Observation::Present(kbs.into_iter().collect())
        } else {
            Observation::Truncated
        })
    }

    fn kb_from_title(title: &str) -> Option<String> {
        let mut identities = title
            .split(|character: char| !character.is_ascii_alphanumeric())
            .filter_map(canonical_kb);
        let kb = identities.next()?;
        identities.next().is_none().then_some(kb)
    }
    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }
    fn com_error(error: &windows::core::Error) -> PlatformError {
        PlatformError::TrustFailure(format!("Windows Update Agent COM failed: {error}"))
    }
    struct OwnedKey(HKEY);
    impl Drop for OwnedKey {
        fn drop(&mut self) {
            unsafe {
                let _ = RegCloseKey(self.0);
            }
        }
    }
    struct ComApartment;
    impl ComApartment {
        unsafe fn initialize() -> Result<Self, PlatformError> {
            CoInitializeEx(None, COINIT_MULTITHREADED)
                .ok()
                .map_err(|error| com_error(&error))?;
            Ok(Self)
        }
    }
    impl Drop for ComApartment {
        fn drop(&mut self) {
            unsafe {
                CoUninitialize();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn non_windows_inventory_adapters_are_explicitly_unsupported() {
        #[cfg(not(windows))]
        {
            assert!(matches!(
                super::audit_software_inventory(),
                Err(super::PlatformError::UnsupportedPlatform)
            ));
            assert!(matches!(
                super::audit_installed_kbs(),
                Err(super::PlatformError::UnsupportedPlatform)
            ));
        }
    }
}
