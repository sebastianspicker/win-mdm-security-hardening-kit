//! Bounded token and process inspection for mutual named-pipe authentication.

#![allow(unsafe_code)]

use crate::PlatformError;
use std::ffi::c_void;
use std::path::PathBuf;

const INVALID_HANDLE_VALUE: isize = -1;
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
const TOKEN_QUERY: u32 = 0x0008;
const TOKEN_USER: u32 = 1;
const TOKEN_GROUPS: u32 = 2;
const TOKEN_INTEGRITY_LEVEL: u32 = 25;
const SE_GROUP_LOGON_ID: u32 = 0xc000_0000;
const MAX_TOKEN_BYTES: u32 = 65_536;
const MAX_SID_TEXT_UNITS: usize = 1024;
const SID_HEADER_BYTES: usize = 8;
const SID_SUBAUTHORITY_BYTES: usize = 4;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CloseHandle(handle: isize) -> i32;
    fn GetLastError() -> u32;
    fn LocalFree(memory: *mut c_void) -> *mut c_void;
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> isize;
    fn ProcessIdToSessionId(process_id: u32, session_id: *mut u32) -> i32;
    fn QueryFullProcessImageNameW(
        process: isize,
        flags: u32,
        buffer: *mut u16,
        size: *mut u32,
    ) -> i32;
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn ConvertSidToStringSidW(sid: *const c_void, text: *mut *mut u16) -> i32;
    fn GetLengthSid(sid: *const c_void) -> u32;
    fn GetTokenInformation(
        token: isize,
        class: u32,
        buffer: *mut c_void,
        length: u32,
        returned: *mut u32,
    ) -> i32;
    fn IsValidSid(sid: *const c_void) -> i32;
    fn OpenProcessToken(process: isize, access: u32, token: *mut isize) -> i32;
}

/// Process and token data captured from owned process/token handles.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessTokenIdentity {
    /// OS-assigned process identifier.
    pub process_id: u32,
    /// Terminal-services session identifier.
    pub session_id: u32,
    /// Account SID of the primary token user.
    pub user_sid: String,
    /// Token logon SID; this distinguishes simultaneous sessions of one account.
    pub logon_sid: String,
    /// Mandatory integrity RID from the primary token.
    pub integrity_rid: u32,
    /// Process image path reported by Windows before protected-install verification.
    pub image_path: PathBuf,
}

/// Inspect a process using owned handles and fully validated token-information buffers.
///
/// # Errors
///
/// Returns an error when process/token inspection, SID validation, or image lookup fails.
pub fn inspect_process(process_id: u32) -> Result<ProcessTokenIdentity, PlatformError> {
    if process_id == 0 {
        return Err(rejected("process identifier may not be zero"));
    }
    let process =
        Handle::new(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) })?;
    let image_path = query_image(process.0)?;
    let mut raw_token = 0_isize;
    if unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &raw mut raw_token) } == 0
        || raw_token == 0
    {
        return Err(last_error("OpenProcessToken"));
    }
    let token = Handle::new(raw_token)?;
    let user_sid = token_sid(&token, TOKEN_USER)?;
    let integrity_sid = token_sid(&token, TOKEN_INTEGRITY_LEVEL)?;
    let logon_sid = token_logon_sid(&token)?;
    let mut session_id = 0_u32;
    if unsafe { ProcessIdToSessionId(process_id, &raw mut session_id) } == 0 {
        return Err(last_error("ProcessIdToSessionId"));
    }
    Ok(ProcessTokenIdentity {
        process_id,
        session_id,
        user_sid,
        logon_sid,
        integrity_rid: integrity_rid(&integrity_sid)?,
        image_path,
    })
}

struct Handle(isize);

impl Handle {
    fn new(handle: isize) -> Result<Self, PlatformError> {
        if handle == INVALID_HANDLE_VALUE || handle == 0 {
            return Err(last_error("Windows handle creation"));
        }
        Ok(Self(handle))
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.0) };
    }
}

fn query_image(process: isize) -> Result<PathBuf, PlatformError> {
    let mut buffer = vec![0_u16; 32_768];
    let mut length =
        u32::try_from(buffer.len()).map_err(|_| rejected("image buffer length overflow"))?;
    if unsafe { QueryFullProcessImageNameW(process, 0, buffer.as_mut_ptr(), &raw mut length) } == 0
    {
        return Err(last_error("QueryFullProcessImageNameW"));
    }
    let length = usize::try_from(length).map_err(|_| rejected("image path length overflow"))?;
    if length == 0 || length > buffer.len() {
        return Err(rejected("image path length is invalid"));
    }
    Ok(PathBuf::from(String::from_utf16_lossy(&buffer[..length])))
}

fn token_information(token: &Handle, class: u32) -> Result<Vec<u8>, PlatformError> {
    let mut required = 0_u32;
    let _ =
        unsafe { GetTokenInformation(token.0, class, std::ptr::null_mut(), 0, &raw mut required) };
    if required == 0 || required > MAX_TOKEN_BYTES {
        return Err(rejected("token information size is invalid"));
    }
    let mut bytes = vec![
        0_u8;
        usize::try_from(required)
            .map_err(|_| rejected("token information size overflow"))?
    ];
    let mut returned = 0_u32;
    if unsafe {
        GetTokenInformation(
            token.0,
            class,
            bytes.as_mut_ptr().cast(),
            required,
            &raw mut returned,
        )
    } == 0
        || returned == 0
        || returned > required
    {
        return Err(last_error("GetTokenInformation"));
    }
    bytes.truncate(
        usize::try_from(returned)
            .map_err(|_| rejected("returned token information size overflow"))?,
    );
    Ok(bytes)
}

fn token_sid(token: &Handle, class: u32) -> Result<String, PlatformError> {
    let bytes = token_information(token, class)?;
    sid_text_from_buffer(&bytes, read_pointer(&bytes, 0)?)
}

fn token_logon_sid(token: &Handle) -> Result<String, PlatformError> {
    let bytes = token_information(token, TOKEN_GROUPS)?;
    let pointer_size = std::mem::size_of::<usize>();
    let start = align_up(4, pointer_size)?;
    let stride = align_up(pointer_size.saturating_add(4), pointer_size)?;
    let count = usize::try_from(read_u32(&bytes, 0)?)
        .map_err(|_| rejected("token group count overflow"))?;
    if start
        .checked_add(
            stride
                .checked_mul(count)
                .ok_or_else(|| rejected("token group array overflows its buffer"))?,
        )
        .is_none_or(|end| end > bytes.len())
    {
        return Err(rejected("token group array is truncated"));
    }
    for index in 0..count {
        let offset = start + index * stride;
        if read_u32(&bytes, offset + pointer_size)? & SE_GROUP_LOGON_ID == SE_GROUP_LOGON_ID {
            return sid_text_from_buffer(&bytes, read_pointer(&bytes, offset)?);
        }
    }
    Err(rejected("token has no logon SID"))
}

fn sid_text_from_buffer(bytes: &[u8], address: usize) -> Result<String, PlatformError> {
    let start = bytes.as_ptr() as usize;
    let end = start
        .checked_add(bytes.len())
        .ok_or_else(|| rejected("token buffer address overflows"))?;
    if address < start || address >= end {
        return Err(rejected("token SID is outside its buffer"));
    }
    let offset = address
        .checked_sub(start)
        .ok_or_else(|| rejected("token SID offset underflows"))?;
    let declared_length = sid_length_in_buffer(bytes, offset)?;
    let sid = address as *const c_void;
    if unsafe { IsValidSid(sid) } == 0 {
        return Err(rejected("token contains an invalid SID"));
    }
    let length = usize::try_from(unsafe { GetLengthSid(sid) })
        .map_err(|_| rejected("SID length overflow"))?;
    if length != declared_length {
        return Err(rejected("token SID length disagrees with its header"));
    }
    sid_to_string(sid)
}

/// Bound a SID before passing its address to Win32 validation helpers.
fn sid_length_in_buffer(bytes: &[u8], offset: usize) -> Result<usize, PlatformError> {
    let header = bytes
        .get(
            offset
                ..offset
                    .checked_add(SID_HEADER_BYTES)
                    .ok_or_else(|| rejected("token SID header offset overflows"))?,
        )
        .ok_or_else(|| rejected("token SID header is truncated"))?;
    let sub_authority_count = usize::from(header[1]);
    let length = SID_HEADER_BYTES
        .checked_add(
            SID_SUBAUTHORITY_BYTES
                .checked_mul(sub_authority_count)
                .ok_or_else(|| rejected("token SID subauthorities overflow"))?,
        )
        .ok_or_else(|| rejected("token SID length overflows"))?;
    if bytes
        .get(
            offset
                ..offset
                    .checked_add(length)
                    .ok_or_else(|| rejected("token SID end offset overflows"))?,
        )
        .is_none()
    {
        return Err(rejected("token SID exceeds its buffer"));
    }
    Ok(length)
}

fn sid_to_string(sid: *const c_void) -> Result<String, PlatformError> {
    let mut text = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &raw mut text) } == 0 || text.is_null() {
        return Err(last_error("ConvertSidToStringSidW"));
    }
    let allocation = LocalAllocation(text.cast());
    let mut length = 0_usize;
    while unsafe { *text.add(length) } != 0 {
        length += 1;
        if length > MAX_SID_TEXT_UNITS {
            return Err(rejected("SID text exceeds bounds"));
        }
    }
    let value = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, length) });
    drop(allocation);
    if !valid_sid_text(&value) {
        return Err(rejected("formatted SID is invalid"));
    }
    Ok(value)
}

struct LocalAllocation(*mut c_void);
impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            let _ = unsafe { LocalFree(self.0) };
        }
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, PlatformError> {
    let raw = bytes
        .get(
            offset
                ..offset
                    .checked_add(4)
                    .ok_or_else(|| rejected("token field offset overflows"))?,
        )
        .ok_or_else(|| rejected("token field is truncated"))?;
    Ok(u32::from_ne_bytes(
        raw.try_into()
            .map_err(|_| rejected("token u32 field is invalid"))?,
    ))
}
fn read_pointer(bytes: &[u8], offset: usize) -> Result<usize, PlatformError> {
    let size = std::mem::size_of::<usize>();
    let raw = bytes
        .get(
            offset
                ..offset
                    .checked_add(size)
                    .ok_or_else(|| rejected("token pointer offset overflows"))?,
        )
        .ok_or_else(|| rejected("token pointer field is truncated"))?;
    let value = if size == 8 {
        usize::try_from(u64::from_ne_bytes(
            raw.try_into()
                .map_err(|_| rejected("token pointer field is invalid"))?,
        ))
        .map_err(|_| rejected("token pointer overflows usize"))?
    } else {
        usize::try_from(u32::from_ne_bytes(
            raw.try_into()
                .map_err(|_| rejected("token pointer field is invalid"))?,
        ))
        .map_err(|_| rejected("token pointer overflows usize"))?
    };
    if value == 0 {
        return Err(rejected("token SID pointer is null"));
    }
    Ok(value)
}
fn align_up(value: usize, alignment: usize) -> Result<usize, PlatformError> {
    value
        .checked_add(alignment.saturating_sub(1))
        .map(|value| value / alignment * alignment)
        .ok_or_else(|| rejected("token alignment overflows"))
}
fn integrity_rid(sid: &str) -> Result<u32, PlatformError> {
    sid.rsplit('-')
        .next()
        .ok_or_else(|| rejected("integrity SID is malformed"))?
        .parse()
        .map_err(|_| rejected("integrity SID is malformed"))
}
fn valid_sid_text(value: &str) -> bool {
    value.len() >= 5
        && value.len() <= MAX_SID_TEXT_UNITS
        && value.starts_with("S-")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'-' || byte == b'S')
}
fn rejected(message: &str) -> PlatformError {
    PlatformError::ProtocolRejected(message.into())
}
fn last_error(operation: &str) -> PlatformError {
    PlatformError::Io(std::io::Error::other(format!(
        "{operation}: Win32 error {}",
        unsafe { GetLastError() }
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sid_header_requires_all_declared_subauthorities() {
        let mut sid = [0_u8; SID_HEADER_BYTES + SID_SUBAUTHORITY_BYTES];
        sid[1] = 1;
        assert_eq!(
            sid_length_in_buffer(&sid, 0).expect("complete SID"),
            sid.len()
        );
        assert!(sid_length_in_buffer(&sid[..SID_HEADER_BYTES], 0).is_err());
    }

    #[test]
    fn sid_header_cannot_start_past_the_token_buffer() {
        assert!(sid_length_in_buffer(&[0; SID_HEADER_BYTES], 1).is_err());
    }
}
