//! Windows 11 x64 host identity collection at the execution boundary.

use crate::PlatformError;
use baselineops_domain::HostIdentityV3;
#[cfg(windows)]
use baselineops_domain::OsFamily;

#[cfg(any(windows, test))]
const WINDOWS_11_24H2_MIN_BUILD: u32 = 26_100;
#[cfg(any(windows, test))]
const PROCESSOR_ARCHITECTURE_AMD64: u16 = 9;

#[cfg(any(windows, test))]
const SYSTEM_TIME_OF_DAY_INFORMATION_BYTES: usize = 48;
#[cfg(any(windows, test))]
const BOOT_TIME_BYTES: usize = 8;

#[cfg(any(windows, test))]
#[repr(align(8))]
struct SystemTimeOfDayBuffer([u8; SYSTEM_TIME_OF_DAY_INFORMATION_BYTES]);

#[cfg(any(windows, test))]
fn boot_time_from_system_time_of_day(bytes: &[u8], returned: usize) -> Result<i64, PlatformError> {
    if returned < BOOT_TIME_BYTES || returned > bytes.len() {
        return Err(PlatformError::TrustFailure(
            "native Windows boot time buffer is incomplete".into(),
        ));
    }
    let boot_time = i64::from_ne_bytes(
        bytes[..BOOT_TIME_BYTES]
            .try_into()
            .map_err(|_| PlatformError::TrustFailure("native boot time is malformed".into()))?,
    );
    if boot_time <= 0 {
        return Err(PlatformError::TrustFailure(
            "native Windows boot time could not be read".into(),
        ));
    }
    Ok(boot_time)
}

/// Collect a validated identity bound to the native Windows boot and logon session.
///
/// # Errors
///
/// Returns an error unless the host can be proven to be Windows 11 24H2 or later
/// on native x64, and every identity input can be read inside its explicit bounds.
pub fn collect_host_identity() -> Result<HostIdentityV3, PlatformError> {
    platform::collect()
}

#[cfg(not(windows))]
mod platform {
    use super::{HostIdentityV3, PlatformError};

    pub fn collect() -> Result<HostIdentityV3, PlatformError> {
        Err(PlatformError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
mod platform {
    #![allow(unsafe_code)]

    use super::{
        HostIdentityV3, OsFamily, PlatformError, SYSTEM_TIME_OF_DAY_INFORMATION_BYTES,
        SystemTimeOfDayBuffer, boot_time_from_system_time_of_day, classify_host,
    };
    use std::mem::size_of;
    use windows::Win32::System::SystemInformation::{
        ComputerNamePhysicalDnsHostname, GetComputerNameExW,
    };
    use windows::core::PWSTR;

    #[repr(C)]
    struct OsVersionInfo {
        size: u32,
        major: u32,
        minor: u32,
        build: u32,
        platform_id: u32,
        csd_version: [u16; 128],
    }

    #[repr(C)]
    struct SystemInfo {
        processor_architecture: u16,
        reserved: u16,
        page_size: u32,
        minimum_application_address: usize,
        maximum_application_address: usize,
        active_processor_mask: usize,
        number_of_processors: u32,
        processor_type: u32,
        allocation_granularity: u32,
        processor_level: u16,
        processor_revision: u16,
    }

    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn RtlGetVersion(version: *mut OsVersionInfo) -> i32;
        fn NtQuerySystemInformation(
            class: u32,
            information: *mut core::ffi::c_void,
            length: u32,
            return_length: *mut u32,
        ) -> i32;
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetNativeSystemInfo(info: *mut SystemInfo);
        fn GetCurrentProcessId() -> u32;
        fn ProcessIdToSessionId(process_id: u32, session_id: *mut u32) -> i32;
        fn GetVolumeInformationW(
            root_path: *const u16,
            volume_name: *mut u16,
            volume_name_size: u32,
            serial: *mut u32,
            maximum_component_length: *mut u32,
            file_system_flags: *mut u32,
            file_system_name: *mut u16,
            file_system_name_size: u32,
        ) -> i32;
    }

    pub fn collect() -> Result<HostIdentityV3, PlatformError> {
        let version = os_version()?;
        let architecture = native_architecture();
        let sku = edition_sku(version.major, version.minor)?;
        let edition = classify_host(
            version.major,
            version.minor,
            version.build,
            architecture,
            sku,
        )?;
        let hostname = hostname()?;
        let session_id = session_id()?;
        let boot_id = boot_id()?;
        let host_id = format!(
            "{}-{:08x}",
            hostname.to_ascii_lowercase(),
            system_volume_serial()?
        );
        let mut identity = HostIdentityV3 {
            host_id,
            boot_id,
            session_id: session_id.to_string(),
            hostname,
            os_family: OsFamily::Windows,
            os_version: format!(
                "Windows {}.{}.{} edition {} (sku-{sku:08x})",
                version.major, version.minor, version.build, edition
            ),
            architecture: "x86_64".into(),
            fingerprint: baselineops_domain::Sha256Digest::of_bytes([]),
        };
        identity.fingerprint = identity.calculated_fingerprint().map_err(|error| {
            PlatformError::TrustFailure(format!("host fingerprint failed: {error}"))
        })?;
        identity.validate().map_err(|error| {
            PlatformError::TrustFailure(format!("host identity validation failed: {error}"))
        })?;
        Ok(identity)
    }

    fn os_version() -> Result<OsVersionInfo, PlatformError> {
        let mut version = OsVersionInfo {
            size: u32::try_from(size_of::<OsVersionInfo>()).expect("version size"),
            major: 0,
            minor: 0,
            build: 0,
            platform_id: 0,
            csd_version: [0; 128],
        };
        if unsafe { RtlGetVersion(&raw mut version) } < 0 {
            return Err(PlatformError::TrustFailure(
                "Windows 11 build identity could not be proved".into(),
            ));
        }
        Ok(version)
    }

    fn native_architecture() -> u16 {
        let mut info = SystemInfo {
            processor_architecture: 0,
            reserved: 0,
            page_size: 0,
            minimum_application_address: 0,
            maximum_application_address: 0,
            active_processor_mask: 0,
            number_of_processors: 0,
            processor_type: 0,
            allocation_granularity: 0,
            processor_level: 0,
            processor_revision: 0,
        };
        unsafe { GetNativeSystemInfo(&raw mut info) };
        info.processor_architecture
    }

    fn hostname() -> Result<String, PlatformError> {
        let mut length = 0_u32;
        let _ =
            unsafe { GetComputerNameExW(ComputerNamePhysicalDnsHostname, None, &raw mut length) };
        if length == 0 || length > 255 {
            return Err(PlatformError::TrustFailure(
                "Windows returned an invalid hostname length".into(),
            ));
        }
        let mut buffer = vec![0_u16; usize::try_from(length).expect("hostname length")];
        unsafe {
            GetComputerNameExW(
                ComputerNamePhysicalDnsHostname,
                Some(PWSTR(buffer.as_mut_ptr())),
                &raw mut length,
            )
        }
        .map_err(|error| {
            PlatformError::TrustFailure(format!("GetComputerNameExW failed: {error}"))
        })?;
        buffer.truncate(usize::try_from(length).expect("hostname length"));
        String::from_utf16(&buffer).map_err(|error| {
            PlatformError::TrustFailure(format!("hostname was not UTF-16: {error}"))
        })
    }

    fn session_id() -> Result<u32, PlatformError> {
        let mut session_id = 0_u32;
        if unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &raw mut session_id) } == 0 {
            return Err(PlatformError::TrustFailure(
                "ProcessIdToSessionId failed".into(),
            ));
        }
        Ok(session_id)
    }

    fn boot_id() -> Result<String, PlatformError> {
        const SYSTEM_TIME_OF_DAY_INFORMATION: u32 = 3;
        let mut information = SystemTimeOfDayBuffer([0; SYSTEM_TIME_OF_DAY_INFORMATION_BYTES]);
        let mut returned = 0_u32;
        let status = unsafe {
            NtQuerySystemInformation(
                SYSTEM_TIME_OF_DAY_INFORMATION,
                (&raw mut information).cast(),
                u32::try_from(size_of::<SystemTimeOfDayBuffer>()).expect("time-of-day size"),
                &raw mut returned,
            )
        };
        if status < 0 {
            return Err(PlatformError::TrustFailure(
                "native Windows boot time could not be read".into(),
            ));
        }
        let boot_time = boot_time_from_system_time_of_day(
            &information.0,
            usize::try_from(returned).expect("u32 fits usize"),
        )?;
        Ok(format!(
            "windows-boot-filetime-{:016x}",
            boot_time.cast_unsigned()
        ))
    }

    fn system_volume_serial() -> Result<u32, PlatformError> {
        let root = [u16::from(b'C'), u16::from(b':'), u16::from(b'\\'), 0];
        let mut serial = 0_u32;
        if unsafe {
            GetVolumeInformationW(
                root.as_ptr(),
                std::ptr::null_mut(),
                0,
                &raw mut serial,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
            )
        } == 0
        {
            return Err(PlatformError::TrustFailure(
                "system volume serial could not be read".into(),
            ));
        }
        Ok(serial)
    }

    fn edition_sku(major: u32, minor: u32) -> Result<u32, PlatformError> {
        let mut sku = 0_u32;
        if unsafe { GetProductInfo(major, minor, 0, 0, &raw mut sku) } == 0 {
            return Err(PlatformError::TrustFailure(
                "Windows edition SKU could not be read".into(),
            ));
        }
        Ok(sku)
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetProductInfo(
            major: u32,
            minor: u32,
            service_pack_major: u32,
            service_pack_minor: u32,
            product_type: *mut u32,
        ) -> i32;
    }
}

#[cfg(any(windows, test))]
fn classify_host(
    major: u32,
    minor: u32,
    build: u32,
    architecture: u16,
    sku: u32,
) -> Result<&'static str, PlatformError> {
    if architecture != PROCESSOR_ARCHITECTURE_AMD64 {
        return Err(PlatformError::UnsupportedHost(
            "native x64 Windows is required".into(),
        ));
    }
    if (major, minor) != (10, 0) || build < WINDOWS_11_24H2_MIN_BUILD {
        return Err(PlatformError::UnsupportedHost(format!(
            "Windows 11 24H2 build {WINDOWS_11_24H2_MIN_BUILD} or later is required (reported {major}.{minor}.{build})"
        )));
    }
    supported_edition(sku).ok_or_else(|| {
        PlatformError::UnsupportedHost(format!("Windows edition sku-{sku:08x} is not supported"))
    })
}

#[cfg(any(windows, test))]
const fn supported_edition(sku: u32) -> Option<&'static str> {
    match sku {
        0x0000_0030 => Some("Pro"),
        0x0000_0031 => Some("Pro N"),
        0x0000_0045 => Some("Pro E"),
        0x0000_0004 => Some("Enterprise"),
        0x0000_001b => Some("Enterprise N"),
        0x0000_0046 => Some("Enterprise E"),
        0x0000_007d => Some("Enterprise LTSC"),
        0x0000_007e => Some("Enterprise LTSC N"),
        0x0000_0081 => Some("Enterprise LTSC Evaluation"),
        0x0000_0082 => Some("Enterprise LTSC N Evaluation"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_time_parser_requires_complete_aligned_layout() {
        let aligned_buffer = SystemTimeOfDayBuffer([0; SYSTEM_TIME_OF_DAY_INFORMATION_BYTES]);
        assert_eq!(
            std::mem::size_of::<SystemTimeOfDayBuffer>(),
            SYSTEM_TIME_OF_DAY_INFORMATION_BYTES
        );
        assert!(std::mem::align_of::<SystemTimeOfDayBuffer>() >= std::mem::align_of::<i64>());
        assert_eq!(aligned_buffer.0.len(), SYSTEM_TIME_OF_DAY_INFORMATION_BYTES);
        let mut buffer = [0_u8; SYSTEM_TIME_OF_DAY_INFORMATION_BYTES];
        buffer[..BOOT_TIME_BYTES].copy_from_slice(&123_i64.to_ne_bytes());
        assert_eq!(
            boot_time_from_system_time_of_day(&buffer, BOOT_TIME_BYTES).expect("boot time"),
            123
        );
        assert!(boot_time_from_system_time_of_day(&buffer, BOOT_TIME_BYTES - 1).is_err());
        assert!(boot_time_from_system_time_of_day(&buffer, buffer.len() + 1).is_err());
    }

    #[test]
    fn boot_time_format_input_is_stable_across_repeated_parses() {
        let mut buffer = [0_u8; SYSTEM_TIME_OF_DAY_INFORMATION_BYTES];
        buffer[..BOOT_TIME_BYTES].copy_from_slice(&456_i64.to_ne_bytes());
        let first = boot_time_from_system_time_of_day(&buffer, buffer.len()).expect("first");
        let second = boot_time_from_system_time_of_day(&buffer, buffer.len()).expect("second");
        assert_eq!(first, second);
    }

    #[test]
    fn host_contract_allows_only_supported_24h2_x64_skus() {
        for (sku, edition) in [
            (0x0000_0030, "Pro"),
            (0x0000_0031, "Pro N"),
            (0x0000_0045, "Pro E"),
            (0x0000_0004, "Enterprise"),
            (0x0000_001b, "Enterprise N"),
            (0x0000_0046, "Enterprise E"),
            (0x0000_007d, "Enterprise LTSC"),
            (0x0000_007e, "Enterprise LTSC N"),
            (0x0000_0081, "Enterprise LTSC Evaluation"),
            (0x0000_0082, "Enterprise LTSC N Evaluation"),
        ] {
            assert_eq!(
                classify_host(
                    10,
                    0,
                    WINDOWS_11_24H2_MIN_BUILD,
                    PROCESSOR_ARCHITECTURE_AMD64,
                    sku
                )
                .expect("supported host"),
                edition
            );
        }
    }

    #[test]
    fn host_contract_rejects_unsupported_build_architecture_and_skus() {
        for (major, minor, build, architecture, sku) in [
            (
                10,
                0,
                WINDOWS_11_24H2_MIN_BUILD - 1,
                PROCESSOR_ARCHITECTURE_AMD64,
                0x30,
            ),
            (10, 0, WINDOWS_11_24H2_MIN_BUILD, 12, 0x30),
            (
                10,
                0,
                WINDOWS_11_24H2_MIN_BUILD,
                PROCESSOR_ARCHITECTURE_AMD64,
                0x65,
            ),
            (
                10,
                0,
                WINDOWS_11_24H2_MIN_BUILD,
                PROCESSOR_ARCHITECTURE_AMD64,
                0x79,
            ),
            (
                10,
                0,
                WINDOWS_11_24H2_MIN_BUILD,
                PROCESSOR_ARCHITECTURE_AMD64,
                0x07,
            ),
        ] {
            assert!(matches!(
                classify_host(major, minor, build, architecture, sku),
                Err(PlatformError::UnsupportedHost(_))
            ));
        }
    }

    #[cfg(windows)]
    #[test]
    fn repeated_identity_collection_is_stable_within_one_boot_session() {
        let first = collect_host_identity().expect("supported Windows host");
        let second = collect_host_identity().expect("supported Windows host");
        assert_eq!(first, second);
    }

    #[cfg(not(windows))]
    #[test]
    fn unsupported_hosts_fail_closed() {
        assert!(matches!(
            collect_host_identity(),
            Err(PlatformError::UnsupportedPlatform)
        ));
    }
}
