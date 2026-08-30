//! Fixed, read-only local Administrators membership acquisition through `NetAPI`.
//!
//! This module uses the built-in Administrators SID to resolve the localized
//! group name, then calls `NetLocalGroupGetMembers` at level 2. It executes no
//! shell, PowerShell, command processor, or membership-changing API.

use crate::PlatformError;
use baselineops_capabilities::LocalAdminsObservation;

/// Observes direct local Administrators members without changing membership.
///
/// # Errors
///
/// Returns [`PlatformError::UnsupportedPlatform`] outside Windows. Windows
/// access denial, missing groups, malformed data, and bounded enumeration are
/// retained as typed observation states instead of being inferred as healthy.
pub fn audit_local_admins() -> Result<LocalAdminsObservation, PlatformError> {
    #[cfg(windows)]
    {
        Ok(platform::audit_local_admins())
    }
    #[cfg(not(windows))]
    {
        platform::audit_local_admins()
    }
}

#[cfg(not(windows))]
mod platform {
    use super::{LocalAdminsObservation, PlatformError};

    pub(super) fn audit_local_admins() -> Result<LocalAdminsObservation, PlatformError> {
        Err(PlatformError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
mod platform {
    #![allow(unsafe_code, unsafe_op_in_unsafe_fn)]

    use super::LocalAdminsObservation;
    use baselineops_capabilities::{LocalAdministratorMember, Observation};
    use std::ffi::c_void;
    use std::slice;
    use windows::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA, ERROR_NONE_MAPPED, HLOCAL,
        LocalFree,
    };
    use windows::Win32::NetworkManagement::NetManagement::{
        LOCALGROUP_MEMBERS_INFO_2, MAX_PREFERRED_LENGTH, NERR_GroupNotFound, NERR_Success,
        NetApiBufferFree, NetApiBufferSize, NetLocalGroupGetMembers,
    };
    use windows::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW};
    use windows::Win32::Security::{LookupAccountSidW, PSID, SID_NAME_USE};
    use windows::core::{PCWSTR, PWSTR};

    const ADMINISTRATORS_SID: &str = "S-1-5-32-544";
    const MAX_DIRECT_MEMBERS: usize = 4_096;
    const MAX_MEMBER_BUFFER_BYTES: usize = 4 * 1024 * 1024;
    const MAX_ACCOUNT_NAME_UNITS: u32 = 2_048;

    pub(super) fn audit_local_admins() -> LocalAdminsObservation {
        let group_name = administrators_group_name();
        let (members, enumeration_complete) = match &group_name {
            Observation::Present(name) => direct_members(name),
            Observation::Missing => (Observation::Missing, true),
            Observation::AccessDenied => (Observation::AccessDenied, true),
            Observation::TimedOut => (Observation::TimedOut, false),
            Observation::Truncated => (Observation::Truncated, false),
            Observation::Failed { exit_code } => (
                Observation::Failed {
                    exit_code: *exit_code,
                },
                false,
            ),
            Observation::NotRun | Observation::Unparsed => (Observation::NotRun, false),
        };
        LocalAdminsObservation {
            group_name,
            members,
            enumeration_complete,
        }
    }

    fn administrators_group_name() -> Observation<String> {
        let sid = match SidAllocation::from_text(ADMINISTRATORS_SID) {
            Ok(sid) => sid,
            Err(status) => return state(status),
        };
        lookup_account_name(sid.0)
    }

    fn lookup_account_name(sid: PSID) -> Observation<String> {
        let mut account_len = 0_u32;
        let mut domain_len = 0_u32;
        let mut use_type = SID_NAME_USE::default();
        let first = unsafe {
            LookupAccountSidW(
                PCWSTR::null(),
                sid,
                None,
                &raw mut account_len,
                None,
                &raw mut domain_len,
                &raw mut use_type,
            )
        };
        if first.is_ok() || account_len == 0 || domain_len > MAX_ACCOUNT_NAME_UNITS {
            return Observation::Unparsed;
        }
        if account_len > MAX_ACCOUNT_NAME_UNITS {
            return Observation::Truncated;
        }
        let account_len = usize::try_from(account_len).unwrap_or_default();
        let domain_len = usize::try_from(domain_len).unwrap_or_default();
        let mut account = vec![0_u16; account_len];
        let mut domain = vec![0_u16; domain_len];
        let mut account_len = u32::try_from(account.len()).unwrap_or(u32::MAX);
        let mut domain_len = u32::try_from(domain.len()).unwrap_or(u32::MAX);
        let result = unsafe {
            LookupAccountSidW(
                PCWSTR::null(),
                sid,
                Some(PWSTR(account.as_mut_ptr())),
                &raw mut account_len,
                Some(PWSTR(domain.as_mut_ptr())),
                &raw mut domain_len,
                &raw mut use_type,
            )
        };
        if let Err(error) = result {
            return state(win32_error(error.code().0));
        }
        let account = utf16_from_buffer(&account, account_len).unwrap_or_default();
        let domain = utf16_from_buffer(&domain, domain_len).unwrap_or_default();
        if account.is_empty() {
            return Observation::Unparsed;
        }
        Observation::Present(if domain.is_empty() {
            account
        } else {
            format!("{domain}\\{account}")
        })
    }

    fn direct_members(group_name: &str) -> (Observation<Vec<LocalAdministratorMember>>, bool) {
        let group_name = wide(group_name);
        let mut members = Vec::new();
        let mut resume = 0_usize;
        loop {
            let mut buffer = std::ptr::null_mut::<u8>();
            let mut read = 0_u32;
            let mut total = 0_u32;
            let status = unsafe {
                NetLocalGroupGetMembers(
                    PCWSTR::null(),
                    PCWSTR(group_name.as_ptr()),
                    2,
                    &raw mut buffer,
                    MAX_PREFERRED_LENGTH,
                    &raw mut read,
                    &raw mut total,
                    Some(&raw mut resume),
                )
            };
            let allocation = NetApiAllocation(buffer.cast());
            let remaining = MAX_DIRECT_MEMBERS.saturating_sub(members.len());
            let read = usize::try_from(read).unwrap_or(MAX_DIRECT_MEMBERS + 1);
            let Some(appended_all) =
                append_members_from_buffer(&mut members, buffer, read, remaining)
            else {
                return (Observation::Unparsed, false);
            };
            if !appended_all {
                return (Observation::Present(members), false);
            }
            drop(allocation);
            if status == NERR_Success {
                return (Observation::Present(members), true);
            }
            if status != ERROR_MORE_DATA.0 || read == 0 {
                return (state(status), false);
            }
            if members.len() == MAX_DIRECT_MEMBERS
                || usize::try_from(total).unwrap_or(MAX_DIRECT_MEMBERS + 1) > MAX_DIRECT_MEMBERS
            {
                return (Observation::Present(members), false);
            }
        }
    }

    fn append_members_from_buffer(
        members: &mut Vec<LocalAdministratorMember>,
        buffer: *mut u8,
        count: usize,
        limit: usize,
    ) -> Option<bool> {
        if count == 0 {
            return Some(true);
        }
        if buffer.is_null()
            || !buffer
                .addr()
                .is_multiple_of(std::mem::align_of::<LOCALGROUP_MEMBERS_INFO_2>())
        {
            return None;
        }
        let mut allocation_bytes = 0_u32;
        if unsafe { NetApiBufferSize(buffer.cast(), &raw mut allocation_bytes) } != NERR_Success {
            return None;
        }
        let allocation_bytes = usize::try_from(allocation_bytes).ok()?;
        let entry_bytes = count.checked_mul(size_of::<LOCALGROUP_MEMBERS_INFO_2>())?;
        if allocation_bytes > MAX_MEMBER_BUFFER_BYTES || entry_bytes > allocation_bytes {
            return None;
        }
        // SAFETY: alignment, checked count × element size, and NetAPI's reported
        // allocation extent were validated above while `allocation` remains live.
        #[allow(clippy::cast_ptr_alignment)]
        let entries =
            unsafe { slice::from_raw_parts(buffer.cast::<LOCALGROUP_MEMBERS_INFO_2>(), count) };
        let retained = count.min(limit);
        append_members(members, &entries[..retained]);
        Some(retained == count)
    }

    fn append_members(
        members: &mut Vec<LocalAdministratorMember>,
        entries: &[LOCALGROUP_MEMBERS_INFO_2],
    ) {
        members.extend(entries.iter().map(|entry| LocalAdministratorMember {
            sid: sid_text(entry.lgrmi2_sid),
            account_name: pwstr_text(entry.lgrmi2_domainandname),
            sid_use: entry.lgrmi2_sidusage.0.cast_unsigned(),
        }));
    }

    fn sid_text(sid: PSID) -> Observation<String> {
        if sid.is_invalid() {
            return Observation::Unparsed;
        }
        let mut text = PWSTR::null();
        if unsafe { ConvertSidToStringSidW(sid, &raw mut text) }.is_err() || text.is_null() {
            return Observation::Unparsed;
        }
        let allocation = LocalAllocation(text.0.cast());
        let result = unsafe { text.to_string() }.map_err(|_| ());
        drop(allocation);
        result.map_or(Observation::Unparsed, Observation::Present)
    }

    fn pwstr_text(value: PWSTR) -> Observation<String> {
        if value.is_null() {
            return Observation::Missing;
        }
        unsafe { value.to_string() }.map_or(Observation::Unparsed, Observation::Present)
    }

    fn utf16_from_buffer(buffer: &[u16], length: u32) -> Option<String> {
        let length = usize::try_from(length).ok()?;
        let length = length.min(buffer.len());
        let text = &buffer[..length];
        let text = if text.last() == Some(&0) {
            &text[..text.len().saturating_sub(1)]
        } else {
            text
        };
        String::from_utf16(text).ok()
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(Some(0)).collect()
    }

    fn state<T>(status: u32) -> Observation<T> {
        match status {
            value if value == ERROR_ACCESS_DENIED.0 => Observation::AccessDenied,
            value if value == NERR_GroupNotFound || value == ERROR_NONE_MAPPED.0 => {
                Observation::Missing
            }
            _ => Observation::Failed {
                exit_code: i32::try_from(status).unwrap_or(i32::MAX),
            },
        }
    }

    fn win32_error(hresult: i32) -> u32 {
        u32::from_ne_bytes(hresult.to_ne_bytes()) & 0xffff
    }

    struct SidAllocation(PSID);

    impl SidAllocation {
        fn from_text(value: &str) -> Result<Self, u32> {
            let value = wide(value);
            let mut sid = PSID::default();
            unsafe { ConvertStringSidToSidW(PCWSTR(value.as_ptr()), &raw mut sid) }
                .map_err(|error| win32_error(error.code().0))?;
            if sid.is_invalid() {
                return Err(ERROR_INSUFFICIENT_BUFFER.0);
            }
            Ok(Self(sid))
        }
    }

    impl Drop for SidAllocation {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                unsafe {
                    let _ = LocalFree(Some(HLOCAL(self.0.0.cast())));
                }
            }
        }
    }

    struct LocalAllocation(*mut c_void);

    impl Drop for LocalAllocation {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    let _ = LocalFree(Some(HLOCAL(self.0.cast())));
                }
            }
        }
    }

    struct NetApiAllocation(*const c_void);

    impl Drop for NetApiAllocation {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    let _ = NetApiBufferFree(Some(self.0));
                }
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
            super::audit_local_admins(),
            Err(super::PlatformError::UnsupportedPlatform)
        ));
    }
}
