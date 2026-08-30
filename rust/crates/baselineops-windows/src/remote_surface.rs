//! Fixed read-only acquisition for remote-surface capability 37.

use crate::PlatformError;
#[cfg(windows)]
use crate::{KnownService, observe_service};
use baselineops_capabilities::RemoteSurfaceObservation;
#[cfg(windows)]
use baselineops_capabilities::{Observation, TcpListenerObservation};
#[cfg(any(windows, test))]
use std::mem::size_of;

#[cfg(windows)]
const REMOTE_PORTS: [u16; 5] = [5985, 5986, 22, 3389, 445];

/// Observe fixed local remote-administration surface indicators without mutation.
///
/// Listener records establish only local port binding. They deliberately do not
/// assert firewall traversal or network reachability.
///
/// # Errors
///
/// Returns [`PlatformError::UnsupportedPlatform`] outside Windows.
pub fn audit_remote_surface() -> Result<RemoteSurfaceObservation, PlatformError> {
    #[cfg(windows)]
    {
        Ok(platform::audit_remote_surface())
    }
    #[cfg(not(windows))]
    {
        platform::audit_remote_surface()
    }
}

#[cfg(not(windows))]
mod platform {
    use super::{PlatformError, RemoteSurfaceObservation};

    pub(super) fn audit_remote_surface() -> Result<RemoteSurfaceObservation, PlatformError> {
        Err(PlatformError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
mod platform {
    #![allow(unsafe_code, unsafe_op_in_unsafe_fn)]

    use super::{
        KnownService, Observation, REMOTE_PORTS, RemoteSurfaceObservation, TcpListenerObservation,
        checked_table_rows, observe_service,
    };
    use windows::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_BUFFER_OVERFLOW, ERROR_FILE_NOT_FOUND, ERROR_SUCCESS,
        WIN32_ERROR,
    };
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID,
        TCP_TABLE_OWNER_PID_LISTENER,
    };
    use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};
    use windows::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_DWORD, REG_VALUE_TYPE, RegCloseKey, RegOpenKeyExW,
        RegQueryValueExW,
    };
    use windows::core::PCWSTR;

    const MAX_TABLE_BYTES: usize = 1024 * 1024;
    const WSMAN_LISTENER: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Listener";
    const TERMINAL_SERVER: &str = r"SYSTEM\CurrentControlSet\Control\Terminal Server";

    pub(super) fn audit_remote_surface() -> RemoteSurfaceObservation {
        RemoteSurfaceObservation {
            winrm_service: service(KnownService::WinRm),
            winrm_listener_configured: key_present(WSMAN_LISTENER),
            sshd_service: service(KnownService::OpenSshServer),
            rdp_enabled: rdp_enabled(),
            rdp_service: service(KnownService::RemoteDesktop),
            smb_server_service: service(KnownService::SmbServer),
            tcp_listeners: listeners(),
        }
    }

    fn service(
        requested: KnownService,
    ) -> Observation<baselineops_capabilities::ServiceObservation> {
        observe_service(requested).unwrap_or(Observation::Unparsed)
    }

    fn key_present(path: &str) -> Observation<bool> {
        let path = wide(path);
        let mut key = HKEY::default();
        let status = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(path.as_ptr()),
                None,
                KEY_READ,
                &raw mut key,
            )
        };
        if status == ERROR_FILE_NOT_FOUND {
            return Observation::Present(false);
        }
        if status == ERROR_ACCESS_DENIED {
            return Observation::AccessDenied;
        }
        if status != ERROR_SUCCESS {
            return Observation::Unparsed;
        }
        unsafe {
            let _ = RegCloseKey(key);
        }
        Observation::Present(true)
    }

    fn rdp_enabled() -> Observation<bool> {
        let path = wide(TERMINAL_SERVER);
        let name = wide("fDenyTSConnections");
        let mut key = HKEY::default();
        let status = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(path.as_ptr()),
                None,
                KEY_READ,
                &raw mut key,
            )
        };
        if status == ERROR_FILE_NOT_FOUND {
            return Observation::Missing;
        }
        if status == ERROR_ACCESS_DENIED {
            return Observation::AccessDenied;
        }
        if status != ERROR_SUCCESS {
            return Observation::Unparsed;
        }
        let mut kind = REG_VALUE_TYPE::default();
        let mut size = 4_u32;
        let mut bytes = [0_u8; 4];
        let status = unsafe {
            RegQueryValueExW(
                key,
                PCWSTR(name.as_ptr()),
                None,
                Some(&raw mut kind),
                Some(bytes.as_mut_ptr()),
                Some(&raw mut size),
            )
        };
        unsafe {
            let _ = RegCloseKey(key);
        }
        if status == ERROR_FILE_NOT_FOUND {
            return Observation::Missing;
        }
        if status == ERROR_ACCESS_DENIED {
            return Observation::AccessDenied;
        }
        if status != ERROR_SUCCESS || kind != REG_DWORD || size != 4 {
            return Observation::Unparsed;
        }
        match u32::from_le_bytes(bytes) {
            0 => Observation::Present(true),
            1 => Observation::Present(false),
            _ => Observation::Unparsed,
        }
    }

    fn listeners() -> Observation<Vec<TcpListenerObservation>> {
        let mut counts = [0_u16; REMOTE_PORTS.len()];
        if count_ipv4(&mut counts).is_err() || count_ipv6(&mut counts).is_err() {
            return Observation::Unparsed;
        }
        Observation::Present(
            REMOTE_PORTS
                .iter()
                .zip(counts)
                .map(|(port, endpoint_count)| TcpListenerObservation {
                    port: *port,
                    endpoint_count,
                })
                .collect(),
        )
    }

    fn count_ipv4(counts: &mut [u16; REMOTE_PORTS.len()]) -> Result<(), ()> {
        let buffer = table_buffer(u32::from(AF_INET.0))?;
        let rows = rows::<MIB_TCPROW_OWNER_PID>(&buffer)?;
        for row in rows {
            count_port(u16::from_be((row.dwLocalPort & 0xffff) as u16), counts);
        }
        Ok(())
    }

    fn count_ipv6(counts: &mut [u16; REMOTE_PORTS.len()]) -> Result<(), ()> {
        let buffer = table_buffer(u32::from(AF_INET6.0))?;
        let rows = rows::<MIB_TCP6ROW_OWNER_PID>(&buffer)?;
        for row in rows {
            count_port(u16::from_be((row.dwLocalPort & 0xffff) as u16), counts);
        }
        Ok(())
    }

    fn count_port(port: u16, counts: &mut [u16; REMOTE_PORTS.len()]) {
        if let Some(index) = REMOTE_PORTS.iter().position(|candidate| *candidate == port) {
            counts[index] = counts[index].saturating_add(1);
        }
    }

    struct TcpTableBuffer {
        storage: Vec<usize>,
        bytes: usize,
    }

    fn table_buffer(family: u32) -> Result<TcpTableBuffer, ()> {
        let mut bytes = 0_u32;
        let status = unsafe {
            GetExtendedTcpTable(
                None,
                &raw mut bytes,
                false,
                family,
                TCP_TABLE_OWNER_PID_LISTENER,
                0,
            )
        };
        if status != ERROR_BUFFER_OVERFLOW.0 || bytes < 4 || bytes as usize > MAX_TABLE_BYTES {
            return Err(());
        }
        let mut buffer = vec![0_usize; (bytes as usize).div_ceil(size_of::<usize>())];
        let status = unsafe {
            GetExtendedTcpTable(
                Some(buffer.as_mut_ptr().cast()),
                &raw mut bytes,
                false,
                family,
                TCP_TABLE_OWNER_PID_LISTENER,
                0,
            )
        };
        if status != WIN32_ERROR(0).0 {
            return Err(());
        }
        Ok(TcpTableBuffer {
            storage: buffer,
            bytes: usize::try_from(bytes).map_err(|_| ())?,
        })
    }

    fn rows<T>(buffer: &TcpTableBuffer) -> Result<&[T], ()> {
        let allocation = buffer
            .storage
            .len()
            .checked_mul(size_of::<usize>())
            .ok_or(())?;
        if buffer.bytes > allocation || buffer.bytes < size_of::<u32>() {
            return Err(());
        }
        let bytes = unsafe {
            std::slice::from_raw_parts(buffer.storage.as_ptr().cast::<u8>(), buffer.bytes)
        };
        let count = u32::from_ne_bytes(bytes[..size_of::<u32>()].try_into().map_err(|_| ())?);
        let rows = bytes.as_ptr().wrapping_add(size_of::<u32>());
        let count = checked_table_rows(
            count,
            buffer.bytes,
            size_of::<T>(),
            std::mem::align_of::<T>(),
            rows.addr(),
        )
        .ok_or(())?;
        if count == 0 {
            return Ok(&[]);
        }
        if rows.is_null() {
            return Err(());
        }
        Ok(unsafe { std::slice::from_raw_parts(rows.cast::<T>(), count) })
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(Some(0)).collect()
    }
}

#[cfg(any(windows, test))]
fn checked_table_rows(
    count: u32,
    bytes: usize,
    row_size: usize,
    row_alignment: usize,
    row_address: usize,
) -> Option<usize> {
    let header = size_of::<u32>();
    if bytes < header || row_alignment == 0 || !row_address.is_multiple_of(row_alignment) {
        return None;
    }
    let count = usize::try_from(count).ok()?;
    let row_bytes = count.checked_mul(row_size)?;
    (row_bytes <= bytes.checked_sub(header)?).then_some(count)
}

#[cfg(test)]
mod tests {
    use super::checked_table_rows;

    #[test]
    fn non_windows_remote_surface_observation_is_explicitly_unsupported() {
        #[cfg(not(windows))]
        assert!(matches!(
            super::audit_remote_surface(),
            Err(super::PlatformError::UnsupportedPlatform)
        ));
    }

    #[test]
    fn tcp_table_layout_rejects_misaligned_and_oversized_row_claims() {
        assert_eq!(checked_table_rows(2, 12, 4, 4, 4), Some(2));
        assert_eq!(checked_table_rows(3, 12, 4, 4, 4), None);
        assert_eq!(checked_table_rows(1, 8, 4, 8, 4), None);
    }
}
