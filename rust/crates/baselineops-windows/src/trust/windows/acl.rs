use super::handle_path::OpenedPath;
use crate::PlatformError;
use std::ffi::c_void;
use std::mem::{align_of, size_of};
use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
use windows::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, EqualSid, GetSecurityDescriptorControl,
    GetSecurityDescriptorLength, IsValidSecurityDescriptor, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
};
use windows::core::{PCWSTR, w};

const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;
const TRUSTED_INSTALLER_SID: &str =
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
const GENERIC_ALL: u32 = 0x1000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const WRITE_OR_REPLACE_MASK: u32 = 0x000f_0176 | GENERIC_ALL | GENERIC_WRITE;
const ACL_HEADER_SIZE: usize = 8;
const ACE_HEADER_SIZE: usize = 4;
const ACCESS_ACE_PREFIX_SIZE: usize = 8;
const SID_HEADER_SIZE: usize = 8;
const SID_SUBAUTHORITY_SIZE: usize = 4;
const SID_REVISION: u8 = 1;
const SID_MAX_SUBAUTHORITIES: usize = 15;
const DWORD_ALIGNMENT: usize = align_of::<u32>();

pub(super) struct TrustedSids {
    system: SidAllocation,
    administrators: SidAllocation,
    trusted_installer: SidAllocation,
}

impl TrustedSids {
    pub(super) fn new() -> Result<Self, PlatformError> {
        Ok(Self {
            system: SidAllocation::from_sddl(w!("S-1-5-18"))?,
            administrators: SidAllocation::from_sddl(w!("S-1-5-32-544"))?,
            trusted_installer: SidAllocation::from_text(TRUSTED_INSTALLER_SID)?,
        })
    }

    fn contains(&self, sid: PSID) -> bool {
        for trusted in [&self.system, &self.administrators, &self.trusted_installer] {
            if unsafe { EqualSid(sid, trusted.sid) }.is_ok() {
                return true;
            }
        }
        false
    }
}

struct SidAllocation {
    sid: PSID,
}

impl SidAllocation {
    fn from_sddl(value: PCWSTR) -> Result<Self, PlatformError> {
        let mut sid = PSID::default();
        unsafe {
            windows::Win32::Security::Authorization::ConvertStringSidToSidW(value, &raw mut sid)
        }
        .map_err(|error| {
            PlatformError::TrustFailure(format!("could not build trusted SID: {error}"))
        })?;
        if sid.is_invalid() {
            return Err(PlatformError::TrustFailure(
                "trusted SID allocation was null".into(),
            ));
        }
        Ok(Self { sid })
    }

    fn from_text(value: &str) -> Result<Self, PlatformError> {
        let mut wide: Vec<u16> = value.encode_utf16().collect();
        wide.push(0);
        Self::from_sddl(PCWSTR(wide.as_ptr()))
    }
}

impl Drop for SidAllocation {
    fn drop(&mut self) {
        let _ = unsafe { LocalFree(Some(HLOCAL(self.sid.0))) };
    }
}

pub(super) fn verify_object_acl(
    object: &OpenedPath,
    trusted_sids: &TrustedSids,
    require_protected_dacl: bool,
) -> Result<(), PlatformError> {
    let descriptor = SecurityDescriptor::for_handle(object.handle())?;
    if !trusted_sids.contains(descriptor.owner) {
        return Err(trust_error(
            "protected path owner is not SYSTEM, Administrators, or TrustedInstaller",
        ));
    }
    if require_protected_dacl && !descriptor.dacl_protected()? {
        return Err(trust_error(
            "protected root DACL is not protected from inheritance",
        ));
    }
    descriptor.reject_untrusted_writers(trusted_sids)
}

struct SecurityDescriptor {
    owner: PSID,
    dacl: *mut ACL,
    descriptor: PSECURITY_DESCRIPTOR,
    extent: DescriptorExtent,
}

impl SecurityDescriptor {
    fn for_handle(handle: windows::Win32::Foundation::HANDLE) -> Result<Self, PlatformError> {
        let mut owner = PSID::default();
        let mut dacl = std::ptr::null_mut();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        let status = unsafe {
            GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                Some(&raw mut owner),
                None,
                Some(&raw mut dacl),
                None,
                Some(&raw mut descriptor),
            )
        };
        if status.0 != 0 || owner.is_invalid() || dacl.is_null() || descriptor.is_invalid() {
            return Err(trust_error("could not obtain an explicit owner and DACL"));
        }
        let extent = DescriptorExtent::from_security_descriptor(descriptor)?;
        validate_sid_pointer(extent, owner)?;
        extent.bytes_at(dacl.cast(), size_of::<ACL>(), DWORD_ALIGNMENT)?;
        Ok(Self {
            owner,
            dacl,
            descriptor,
            extent,
        })
    }

    fn dacl_protected(&self) -> Result<bool, PlatformError> {
        let mut control = 0_u16;
        let mut revision = 0_u32;
        unsafe {
            GetSecurityDescriptorControl(self.descriptor, &raw mut control, &raw mut revision)
        }
        .map_err(|error| trust_error(&format!("could not read DACL control: {error}")))?;
        Ok(control & SE_DACL_PROTECTED.0 != 0)
    }

    fn reject_untrusted_writers(&self, trusted_sids: &TrustedSids) -> Result<(), PlatformError> {
        let acl_header =
            self.extent
                .bytes_at(self.dacl.cast(), ACL_HEADER_SIZE, DWORD_ALIGNMENT)?;
        let acl_size = usize::from(read_u16(acl_header, 2)?);
        if acl_size < ACL_HEADER_SIZE {
            return Err(trust_error("DACL is smaller than its required header"));
        }
        let acl = self
            .extent
            .bytes_at(self.dacl.cast(), acl_size, DWORD_ALIGNMENT)?;

        walk_acl_aces(acl, |ace_type, ace| {
            if ace_type == ACCESS_ALLOWED_ACE_TYPE
                && read_u32(ace, ACE_HEADER_SIZE)? & WRITE_OR_REPLACE_MASK != 0
            {
                let sid = PSID(
                    ace.as_ptr()
                        .wrapping_add(ACCESS_ACE_PREFIX_SIZE)
                        .cast_mut()
                        .cast::<c_void>(),
                );
                if !trusted_sids.contains(sid) {
                    return Err(trust_error(
                        "DACL grants write or replacement rights to an untrusted SID",
                    ));
                }
            }
            Ok(())
        })?;
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct DescriptorExtent {
    start: usize,
    end: usize,
}

impl DescriptorExtent {
    fn from_security_descriptor(descriptor: PSECURITY_DESCRIPTOR) -> Result<Self, PlatformError> {
        // SAFETY: GetSecurityInfo allocated and returned this descriptor. Validate its
        // structure before asking Windows for the extent, because that API has undefined
        // behavior for an invalid descriptor.
        if !unsafe { IsValidSecurityDescriptor(descriptor) }.as_bool() {
            return Err(trust_error(
                "Windows returned an invalid security descriptor",
            ));
        }
        // SAFETY: IsValidSecurityDescriptor accepted the LocalAlloc-backed descriptor.
        let length = usize::try_from(unsafe { GetSecurityDescriptorLength(descriptor) })
            .map_err(|_| trust_error("security descriptor length does not fit this process"))?;
        Self::new(descriptor.0, length)
            .ok_or_else(|| trust_error("security descriptor has an invalid allocation extent"))
    }

    fn new(start: *mut c_void, length: usize) -> Option<Self> {
        let start = start as usize;
        let end = start.checked_add(length)?;
        (start != 0 && length != 0).then_some(Self { start, end })
    }

    fn bytes_at<'a>(
        self,
        pointer: *const c_void,
        length: usize,
        alignment: usize,
    ) -> Result<&'a [u8], PlatformError> {
        if !self.contains(pointer as usize, length, alignment) {
            return Err(trust_error(
                "security descriptor contains an unaligned or out-of-bounds component",
            ));
        }
        // SAFETY: the checks above prove that the requested byte range lies within the
        // LocalAlloc-backed descriptor extent returned by GetSecurityDescriptorLength.
        Ok(unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), length) })
    }

    fn contains(self, pointer: usize, length: usize, alignment: usize) -> bool {
        alignment != 0
            && pointer.is_multiple_of(alignment)
            && pointer >= self.start
            && pointer
                .checked_add(length)
                .is_some_and(|end| end <= self.end)
    }
}

fn validate_sid_pointer(extent: DescriptorExtent, sid: PSID) -> Result<(), PlatformError> {
    let header = extent.bytes_at(sid.0, SID_HEADER_SIZE, DWORD_ALIGNMENT)?;
    let sid_length = sid_length(header)?;
    extent.bytes_at(sid.0, sid_length, DWORD_ALIGNMENT)?;
    Ok(())
}

fn walk_acl_aces(
    acl: &[u8],
    mut visitor: impl FnMut(u8, &[u8]) -> Result<(), PlatformError>,
) -> Result<(), PlatformError> {
    if acl.len() < ACL_HEADER_SIZE {
        return Err(trust_error("DACL is smaller than its required header"));
    }
    let acl_size = usize::from(read_u16(acl, 2)?);
    if acl_size != acl.len() {
        return Err(trust_error("DACL extent does not match its declared size"));
    }
    let ace_count = usize::from(read_u16(acl, 4)?);
    let mut offset = ACL_HEADER_SIZE;
    for _ in 0..ace_count {
        let header = acl
            .get(
                offset
                    ..offset
                        .checked_add(ACE_HEADER_SIZE)
                        .ok_or_else(|| trust_error("DACL ACE offset overflows this process"))?,
            )
            .ok_or_else(|| trust_error("DACL ACE header exceeds the declared DACL size"))?;
        let ace_length = usize::from(read_u16(header, 2)?);
        if ace_length < ACCESS_ACE_PREFIX_SIZE || !ace_length.is_multiple_of(DWORD_ALIGNMENT) {
            return Err(trust_error("DACL ACE has an invalid size or alignment"));
        }
        let end = offset
            .checked_add(ace_length)
            .ok_or_else(|| trust_error("DACL ACE size overflows this process"))?;
        let ace = acl
            .get(offset..end)
            .ok_or_else(|| trust_error("DACL ACE exceeds the declared DACL size"))?;
        let ace_type = ace[0];
        if ace_type != ACCESS_ALLOWED_ACE_TYPE && ace_type != ACCESS_DENIED_ACE_TYPE {
            return Err(trust_error(
                "DACL contains an unsupported ACE type; cannot prove writer policy",
            ));
        }
        validate_sid_bytes(&ace[ACCESS_ACE_PREFIX_SIZE..])?;
        visitor(ace_type, ace)?;
        offset = end;
    }
    Ok(())
}

fn validate_sid_bytes(sid: &[u8]) -> Result<(), PlatformError> {
    let sid_length = sid_length(sid)?;
    if sid_length > sid.len() {
        return Err(trust_error("DACL ACE SID exceeds the declared ACE size"));
    }
    Ok(())
}

fn sid_length(sid: &[u8]) -> Result<usize, PlatformError> {
    let header = sid
        .get(..SID_HEADER_SIZE)
        .ok_or_else(|| trust_error("SID is smaller than its required header"))?;
    if header[0] != SID_REVISION {
        return Err(trust_error("SID has an unsupported revision"));
    }
    let subauthorities = usize::from(header[1]);
    if subauthorities > SID_MAX_SUBAUTHORITIES {
        return Err(trust_error("SID has too many subauthorities"));
    }
    SID_HEADER_SIZE
        .checked_add(
            subauthorities
                .checked_mul(SID_SUBAUTHORITY_SIZE)
                .ok_or_else(|| trust_error("SID size overflows this process"))?,
        )
        .ok_or_else(|| trust_error("SID size overflows this process"))
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, PlatformError> {
    let value = bytes
        .get(
            offset..offset.checked_add(size_of::<u16>()).ok_or_else(|| {
                trust_error("security descriptor field offset overflows this process")
            })?,
        )
        .ok_or_else(|| trust_error("security descriptor field exceeds its declared extent"))?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, PlatformError> {
    let value = bytes
        .get(
            offset..offset.checked_add(size_of::<u32>()).ok_or_else(|| {
                trust_error("security descriptor field offset overflows this process")
            })?,
        )
        .ok_or_else(|| trust_error("security descriptor field exceeds its declared extent"))?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        let _ = unsafe { LocalFree(Some(HLOCAL(self.descriptor.0))) };
    }
}

fn trust_error(reason: &str) -> PlatformError {
    PlatformError::TrustFailure(reason.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_acl() -> Vec<u8> {
        let mut acl = vec![0_u8; ACL_HEADER_SIZE];
        acl[2..4].copy_from_slice(&24_u16.to_le_bytes());
        acl[4..6].copy_from_slice(&1_u16.to_le_bytes());
        acl.extend_from_slice(&[
            ACCESS_ALLOWED_ACE_TYPE,
            0,
            16,
            0,
            0,
            0,
            0,
            0,
            SID_REVISION,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ]);
        acl
    }

    #[test]
    fn write_mask_covers_content_and_security_descriptor_replacement() {
        assert_ne!(WRITE_OR_REPLACE_MASK & 0x0000_0002, 0);
        assert_ne!(WRITE_OR_REPLACE_MASK & 0x0001_0000, 0);
        assert_ne!(WRITE_OR_REPLACE_MASK & 0x0004_0000, 0);
        assert_ne!(WRITE_OR_REPLACE_MASK & 0x0008_0000, 0);
        assert_ne!(WRITE_OR_REPLACE_MASK & GENERIC_WRITE, 0);
        assert_ne!(WRITE_OR_REPLACE_MASK & GENERIC_ALL, 0);
    }

    #[test]
    fn trustedinstaller_sid_is_fixed_service_identity() {
        assert!(TRUSTED_INSTALLER_SID.starts_with("S-1-5-80-"));
    }

    #[test]
    fn acl_walker_accepts_a_fully_bounded_allowed_ace() {
        let acl = valid_acl();
        let mut observed = 0;
        walk_acl_aces(&acl, |ace_type, ace| {
            assert_eq!(ace_type, ACCESS_ALLOWED_ACE_TYPE);
            assert_eq!(read_u32(ace, ACE_HEADER_SIZE)?, 0);
            observed += 1;
            Ok(())
        })
        .expect("well-formed ACL must be accepted");
        assert_eq!(observed, 1);
    }

    #[test]
    fn acl_walker_rejects_ace_that_does_not_contain_a_complete_sid() {
        let mut acl = valid_acl();
        acl[ACL_HEADER_SIZE + 9] = 15;
        assert!(walk_acl_aces(&acl, |_, _| Ok(())).is_err());
    }

    #[test]
    fn acl_walker_rejects_truncated_and_unsupported_aces() {
        let mut truncated = valid_acl();
        truncated[ACL_HEADER_SIZE + 2..ACL_HEADER_SIZE + 4].copy_from_slice(&8_u16.to_le_bytes());
        truncated.truncate(ACL_HEADER_SIZE + 8);
        let truncated_size = u16::try_from(truncated.len()).expect("test ACL fits a u16");
        truncated[2..4].copy_from_slice(&truncated_size.to_le_bytes());
        assert!(walk_acl_aces(&truncated, |_, _| Ok(())).is_err());

        let mut unsupported = valid_acl();
        unsupported[ACL_HEADER_SIZE] = 0x42;
        assert!(walk_acl_aces(&unsupported, |_, _| Ok(())).is_err());
    }

    #[test]
    fn descriptor_extent_rejects_unaligned_or_out_of_range_components() {
        let extent = DescriptorExtent::new(0x1000_usize as *mut c_void, 32)
            .expect("non-empty non-overflowing extent");
        assert!(extent.contains(0x1004, 8, 4));
        assert!(!extent.contains(0x1002, 8, 4));
        assert!(!extent.contains(0x101c, 8, 4));
    }
}
