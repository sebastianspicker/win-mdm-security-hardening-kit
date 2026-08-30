//! Windows named-pipe transport and authenticated process inspection.

#![allow(unsafe_code)]

use super::{BrokerFrame, FrameCodec, PeerIdentity};
use crate::PlatformError;
use std::ffi::{OsStr, c_void};
use std::os::windows::ffi::OsStrExt;

const INVALID_HANDLE_VALUE: isize = -1;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const OPEN_EXISTING: u32 = 3;
const PIPE_ACCESS_DUPLEX: u32 = 3;
const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x0008_0000;
const PIPE_TYPE_MESSAGE: u32 = 4;
const PIPE_READMODE_MESSAGE: u32 = 2;
const PIPE_WAIT: u32 = 0;
const PIPE_REJECT_REMOTE_CLIENTS: u32 = 8;
const ERROR_PIPE_CONNECTED: u32 = 535;
const ERROR_MORE_DATA: u32 = 234;

#[repr(C)]
struct SecurityAttributes {
    length: u32,
    security_descriptor: *mut c_void,
    inherit_handle: i32,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateNamedPipeW(
        name: *const u16,
        open_mode: u32,
        pipe_mode: u32,
        maximum_instances: u32,
        output_buffer_size: u32,
        input_buffer_size: u32,
        default_timeout: u32,
        security_attributes: *const SecurityAttributes,
    ) -> isize;
    fn CreateFileW(
        name: *const u16,
        desired_access: u32,
        share_mode: u32,
        security_attributes: *const c_void,
        creation_disposition: u32,
        flags_and_attributes: u32,
        template_file: isize,
    ) -> isize;
    fn ConnectNamedPipe(pipe: isize, overlapped: *mut c_void) -> i32;
    fn DisconnectNamedPipe(pipe: isize) -> i32;
    fn ReadFile(
        handle: isize,
        buffer: *mut c_void,
        bytes_to_read: u32,
        bytes_read: *mut u32,
        overlapped: *mut c_void,
    ) -> i32;
    fn WriteFile(
        handle: isize,
        buffer: *const c_void,
        bytes_to_write: u32,
        bytes_written: *mut u32,
        overlapped: *mut c_void,
    ) -> i32;
    fn CloseHandle(handle: isize) -> i32;
    fn GetLastError() -> u32;
    fn GetNamedPipeClientProcessId(pipe: isize, process_id: *mut u32) -> i32;
    fn GetNamedPipeServerProcessId(pipe: isize, process_id: *mut u32) -> i32;
    fn ProcessIdToSessionId(process_id: u32, session_id: *mut u32) -> i32;
    fn LocalFree(memory: *mut c_void) -> *mut c_void;
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        text: *const u16,
        revision: u32,
        descriptor: *mut *mut c_void,
        descriptor_size: *mut u32,
    ) -> i32;
}

/// Verifies Windows peer credentials after the pipe supplies its process ID.
pub trait PipePeerVerifier: Send + Sync {
    /// Fail closed unless the peer is authorized for this one broker operation.
    ///
    /// # Errors
    ///
    /// Returns an error whenever the peer is not authorized.
    fn verify(&self, peer: &PeerIdentity) -> Result<(), PlatformError>;
}

/// First-instance, local-only Windows message-mode pipe listener.
pub struct NamedPipeServer {
    handle: Handle,
}

/// Connected broker pipe client or accepted server connection.
pub struct NamedPipeClient {
    handle: Handle,
}

impl NamedPipeServer {
    /// Bind a pipe for exactly the launched client's logon SID, SYSTEM, and Administrators.
    ///
    /// # Errors
    ///
    /// Returns an error when the name or SID is invalid, another first instance
    /// exists, or Windows rejects the restrictive security descriptor.
    pub fn bind(name: &str, expected_logon_sid: &str) -> Result<Self, PlatformError> {
        let name = pipe_name(name)?;
        let descriptor = SecurityDescriptor::for_client_logon_sid(expected_logon_sid)?;
        let attributes = SecurityAttributes {
            length: u32::try_from(std::mem::size_of::<SecurityAttributes>()).map_err(|_| {
                PlatformError::ProtocolRejected("security attributes size overflow".into())
            })?,
            security_descriptor: descriptor.0,
            inherit_handle: 0,
        };
        let handle = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                64 * 1024,
                64 * 1024,
                0,
                &raw const attributes,
            )
        };
        Handle::new(handle).map(|handle| Self { handle })
    }

    /// Wait for one client and run the caller verifier against its OS PID/session.
    ///
    /// # Errors
    ///
    /// Returns an error when connection, identity collection, or verification fails.
    pub fn accept(self, verifier: &dyn PipePeerVerifier) -> Result<NamedPipeClient, PlatformError> {
        let connected = unsafe { ConnectNamedPipe(self.handle.0, std::ptr::null_mut()) } != 0
            || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED;
        if !connected {
            return Err(last_error("ConnectNamedPipe"));
        }
        let peer = pipe_peer_identity(self.handle.0, true)?;
        verifier.verify(&peer)?;
        let server = std::mem::ManuallyDrop::new(self);
        let handle = unsafe { std::ptr::read(&raw const server.handle) };
        Ok(NamedPipeClient { handle })
    }
}

impl NamedPipeClient {
    /// Connect to an existing local broker pipe. No remote pipe path is accepted.
    ///
    /// # Errors
    ///
    /// Returns an error when the pipe is absent, busy, or cannot be opened.
    pub fn connect(name: &str) -> Result<Self, PlatformError> {
        let name = pipe_name(name)?;
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                0,
            )
        };
        Handle::new(handle).map(|handle| Self { handle })
    }

    /// Return the server PID/session before the client sends any broker bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when Windows cannot identify the pipe server.
    pub fn server_peer_identity(&self) -> Result<PeerIdentity, PlatformError> {
        pipe_peer_identity(self.handle.0, false)
    }

    /// Send one already-encoded bounded frame.
    ///
    /// # Errors
    ///
    /// Returns an error when the frame cannot be written in full.
    pub fn send(&mut self, frame: &BrokerFrame) -> Result<(), PlatformError> {
        if frame.0.len() < 4 || frame.0.len() > super::MAX_FRAME_BYTES.saturating_add(4) {
            return Err(PlatformError::ProtocolRejected(
                "pipe frame is outside explicit bounds".into(),
            ));
        }
        let _: serde_json::Value = FrameCodec::decode(&frame.0)?;
        write_message(self.handle.0, &frame.0)
    }

    /// Receive one bounded frame after validating its length and JSON shape.
    ///
    /// # Errors
    ///
    /// Returns an error when the peer closes or sends an invalid bounded frame.
    pub fn receive(&mut self) -> Result<BrokerFrame, PlatformError> {
        let mut prefix = [0_u8; 4];
        let prefix_more_data = read_message_part(self.handle.0, &mut prefix)?;
        let body = usize::try_from(u32::from_be_bytes(prefix))
            .map_err(|_| PlatformError::ProtocolRejected("pipe frame length is invalid".into()))?;
        if body > super::MAX_FRAME_BYTES {
            return Err(PlatformError::ProtocolRejected(
                "pipe frame exceeds maximum size".into(),
            ));
        }
        if !prefix_has_expected_boundary(body, prefix_more_data) {
            return Err(PlatformError::ProtocolRejected(
                "pipe message disagrees with its declared frame body".into(),
            ));
        }
        let mut frame = Vec::with_capacity(body.saturating_add(4));
        frame.extend_from_slice(&prefix);
        frame.resize(body.saturating_add(4), 0);
        if body != 0 && read_message_part(self.handle.0, &mut frame[4..])? {
            return Err(PlatformError::ProtocolRejected(
                "pipe message contains bytes after its bounded frame".into(),
            ));
        }
        let _: serde_json::Value = FrameCodec::decode(&frame)?;
        Ok(BrokerFrame(frame))
    }
}

impl Drop for NamedPipeServer {
    fn drop(&mut self) {
        let _ = unsafe { DisconnectNamedPipe(self.handle.0) };
    }
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

struct SecurityDescriptor(*mut c_void);

impl SecurityDescriptor {
    fn for_client_logon_sid(logon_sid: &str) -> Result<Self, PlatformError> {
        if !valid_sid_text(logon_sid) {
            return Err(PlatformError::ProtocolRejected(
                "logon SID is invalid".into(),
            ));
        }
        let sddl = format!("D:P(A;;GRGW;;;{logon_sid})(A;;GRGW;;;SY)(A;;GRGW;;;BA)");
        let text = OsStr::new(&sddl)
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let mut descriptor = std::ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                1,
                &raw mut descriptor,
                std::ptr::null_mut(),
            )
        } == 0
            || descriptor.is_null()
        {
            return Err(last_error(
                "ConvertStringSecurityDescriptorToSecurityDescriptorW",
            ));
        }
        Ok(Self(descriptor))
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            let _ = unsafe { LocalFree(self.0) };
        }
    }
}

fn pipe_name(name: &str) -> Result<Vec<u16>, PlatformError> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(PlatformError::ProtocolRejected(
            "pipe name is outside the BaselineOps namespace".into(),
        ));
    }
    Ok(OsStr::new(&format!(r"\\.\pipe\BaselineOps-{name}"))
        .encode_wide()
        .chain(Some(0))
        .collect())
}

fn pipe_peer_identity(pipe: isize, client: bool) -> Result<PeerIdentity, PlatformError> {
    let mut process_id = 0_u32;
    let result = unsafe {
        if client {
            GetNamedPipeClientProcessId(pipe, &raw mut process_id)
        } else {
            GetNamedPipeServerProcessId(pipe, &raw mut process_id)
        }
    };
    if result == 0 || process_id == 0 {
        return Err(last_error(if client {
            "GetNamedPipeClientProcessId"
        } else {
            "GetNamedPipeServerProcessId"
        }));
    }
    let mut session_id = 0_u32;
    if unsafe { ProcessIdToSessionId(process_id, &raw mut session_id) } == 0 {
        return Err(last_error("ProcessIdToSessionId"));
    }
    Ok(PeerIdentity {
        process_id,
        session_id,
        user_sid: String::new(),
        integrity_rid: 0,
        image_path: String::new(),
    })
}

fn valid_sid_text(value: &str) -> bool {
    value.len() >= 5
        && value.len() <= 1024
        && value.starts_with("S-")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'-' || byte == b'S')
}

/// Read exactly one known-sized portion of the current message.
///
/// In message-read mode, a short buffer returns `ERROR_MORE_DATA` after
/// copying valid bytes. The prefix intentionally uses that behavior to learn
/// the bounded body length. A later `ERROR_MORE_DATA` means the peer appended
/// bytes beyond the declared frame and is rejected by `receive`.
fn read_message_part(handle: isize, bytes: &mut [u8]) -> Result<bool, PlatformError> {
    let count = u32::try_from(bytes.len())
        .map_err(|_| PlatformError::ProtocolRejected("pipe read exceeds Win32 bound".into()))?;
    if count == 0 {
        return Ok(false);
    }
    let mut read = 0_u32;
    let succeeded = unsafe {
        ReadFile(
            handle,
            bytes.as_mut_ptr().cast(),
            count,
            &raw mut read,
            std::ptr::null_mut(),
        )
    } != 0;
    let error = if succeeded {
        0
    } else {
        unsafe { GetLastError() }
    };
    message_read_progress(
        succeeded,
        error,
        usize::try_from(read).expect("u32 fits usize"),
        bytes.len(),
    )
}

fn message_read_progress(
    succeeded: bool,
    error: u32,
    actual: usize,
    expected: usize,
) -> Result<bool, PlatformError> {
    if actual != expected {
        return Err(if succeeded {
            PlatformError::ProtocolRejected("pipe message is shorter than its frame".into())
        } else {
            last_error_code("ReadFile", error)
        });
    }
    if succeeded {
        Ok(false)
    } else if error == ERROR_MORE_DATA {
        Ok(true)
    } else {
        Err(last_error_code("ReadFile", error))
    }
}

fn prefix_has_expected_boundary(body: usize, prefix_more_data: bool) -> bool {
    (body == 0) != prefix_more_data
}

/// Preserve the frame-to-message boundary: a retry would create a new pipe
/// message and let a receiver desynchronize its length-prefix state.
fn write_message(handle: isize, bytes: &[u8]) -> Result<(), PlatformError> {
    let count = u32::try_from(bytes.len())
        .map_err(|_| PlatformError::ProtocolRejected("pipe write exceeds Win32 bound".into()))?;
    let mut written = 0_u32;
    if unsafe {
        WriteFile(
            handle,
            bytes.as_ptr().cast(),
            count,
            &raw mut written,
            std::ptr::null_mut(),
        )
    } == 0
        || usize::try_from(written).expect("u32 fits usize") != bytes.len()
    {
        return Err(last_error("WriteFile"));
    }
    Ok(())
}

fn last_error(operation: &str) -> PlatformError {
    last_error_code(operation, unsafe { GetLastError() })
}

fn last_error_code(operation: &str, code: u32) -> PlatformError {
    PlatformError::Io(std::io::Error::other(format!(
        "{operation}: Win32 error {code}",
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_read_accepts_more_data_as_prefix_progress() {
        assert!(message_read_progress(false, ERROR_MORE_DATA, 4, 4).expect("progress"));
        assert!(!message_read_progress(true, 0, 4, 4).expect("complete"));
        assert!(message_read_progress(false, ERROR_MORE_DATA, 3, 4).is_err());
        assert!(message_read_progress(false, 5, 4, 4).is_err());
    }

    #[test]
    fn prefix_state_cannot_cross_pipe_message_boundaries() {
        assert!(prefix_has_expected_boundary(0, false));
        assert!(prefix_has_expected_boundary(1, true));
        assert!(!prefix_has_expected_boundary(0, true));
        assert!(!prefix_has_expected_boundary(1, false));
    }
}
