//! Windows-specific trust and execution boundary.
//!
//! Cross-platform callers can validate untrusted files and construct policies.
//! Endpoint operations return [`PlatformError::UnsupportedPlatform`] outside Windows.

mod advanced_audit;
mod amsi;
mod app_control;
mod applocker;
mod archive;
mod backup_readiness;
mod boot_security;
mod cert_health;
mod client_baseline;
mod defender_asr_allowlist;
mod defender_ransomware;
mod driver_integrity;
mod elevation;
mod eventlog;
mod exploit_protection;
mod firewall;
mod firewall_baseline;
mod hardware_trust;
mod host_identity;
mod inventory;
pub mod ipc;
mod laps_hygiene;
mod local_admins;
mod native_process;
mod network;
mod observations;
mod office_browser;
mod output;
mod policy_registry;
pub mod powershell_logging;
pub mod registry;
mod remote_guardrails;
mod remote_surface;
mod safe_path;
mod scheduled_tasks;
mod security_options;
mod service_process_inventory;
mod services;
mod smb_encryption;
mod storage_reliability;
mod sysmon;
mod time_sync;
mod trust;
mod update_health;
mod wdag_readiness;
mod wef;
mod windows_update;
mod winget;

pub use advanced_audit::audit_advanced_policy;
pub use amsi::audit_amsi;
pub use app_control::audit_app_control;
pub use applocker::audit_applocker;
pub use backup_readiness::audit_backup_readiness;
pub use boot_security::audit_boot_security;
pub use cert_health::audit_cert_health;
pub use client_baseline::audit_client_baseline;
pub use defender_asr_allowlist::audit_defender_asr_allowlist;
pub use defender_ransomware::audit_defender_ransomware;
pub use driver_integrity::audit_driver_integrity;
pub use elevation::{
    ElevatedLaunchPolicy, ElevatedLaunchResult, ElevatedLaunchStatus, launch_elevated,
};
pub use eventlog::audit_event_log;
pub use exploit_protection::audit_exploit_protection;
pub use firewall::observe_firewall;
pub use firewall_baseline::observe_firewall_baseline;
pub use hardware_trust::{audit_bitlocker_os_volume, audit_hardware_tpm, audit_secure_boot};
pub use host_identity::collect_host_identity;
pub use inventory::{audit_installed_kbs, audit_software_inventory};
pub use ipc::{
    BrokerBinding, BrokerFrame, BrokerMessage, FrameCodec, MAX_FRAME_BYTES, PROTOCOL_VERSION,
    PeerIdentity, ReplayNonceCache,
};
pub use laps_hygiene::audit_laps_hygiene;
pub use local_admins::audit_local_admins;
pub use native_process::{
    NativeArgumentRule, NativeExecutableTrust, NativeProcessPolicy, NativeProcessResult,
    NativeProcessSpec, run_native,
};
pub use network::audit_network_inventory;
pub use observations::{
    DefenderHealthObservation, DomainRole, IdentityObservation, audit_defender_health,
    audit_identity,
};
pub use office_browser::observe_office_browser_policy;
pub use output::{NativeEncoding, decode_native_output};
pub use powershell_logging::observe_powershell_logging;
pub use remote_guardrails::audit_remote_guardrails;
pub use remote_surface::audit_remote_surface;
pub use safe_path::{
    MAX_INPUT_BYTES, PathPolicy, atomic_write, read_bounded_utf8, read_bounded_utf8_no_follow,
};
pub use scheduled_tasks::audit_scheduled_tasks;
pub use security_options::observe_security_options;
pub use service_process_inventory::audit_service_process_inventory;
pub use services::{KnownService, observe_service};
pub use smb_encryption::audit_smb_encryption;
pub use storage_reliability::audit_storage_reliability;
pub use sysmon::audit_sysmon;
pub use time_sync::audit_time_sync;
pub use trust::{
    FileDigest, InstallationTrustPolicy, SignerSpkiSha256, TrustedInstallation,
    verify_authenticode, verify_authenticode_subject, verify_detached_manifest,
    verify_detached_manifest_signature, verify_file_digest, verify_protected_install,
};
pub use update_health::audit_update_health;
pub use wdag_readiness::audit_wdag_readiness;
pub use wef::audit_wef_readiness;
pub use windows_update::observe_windows_update_policy;
pub use winget::audit_winget;

use std::io;
use std::path::PathBuf;

/// Fail-closed errors produced at the operating-system boundary.
#[derive(Debug, thiserror::Error)]
pub enum PlatformError {
    /// The requested operation is unavailable on this host.
    #[error("the operation is unsupported on this platform")]
    UnsupportedPlatform,
    /// The Windows host does not meet `BaselineOps`' supported endpoint contract.
    #[error("the Windows host is unsupported: {0}")]
    UnsupportedHost(String),
    /// A path failed containment or reparse-point checks.
    #[error("untrusted path {path}: {reason}")]
    UntrustedPath {
        /// Rejected path.
        path: PathBuf,
        /// Policy rule that rejected it.
        reason: String,
    },
    /// The input exceeded its explicit byte limit.
    #[error("input {path} exceeded the {limit}-byte limit")]
    InputTooLarge {
        /// Oversized input path.
        path: PathBuf,
        /// Maximum permitted bytes.
        limit: u64,
    },
    /// The input was not valid UTF-8.
    #[error("input {path} is not valid UTF-8")]
    InvalidUtf8 {
        /// Non-UTF-8 input path.
        path: PathBuf,
    },
    /// A native executable or argument was outside its capability policy.
    #[error("native process policy rejected the request: {0}")]
    ProcessRejected(String),
    /// The process did not complete inside its bounded runtime.
    #[error("native process timed out after {seconds} seconds")]
    ProcessTimeout {
        /// Configured timeout in whole seconds.
        seconds: u64,
    },
    /// Captured process output exceeded a configured limit.
    #[error("native process {stream} exceeded the {limit}-byte output limit")]
    OutputTooLarge {
        /// Captured stream name.
        stream: &'static str,
        /// Maximum permitted bytes.
        limit: usize,
    },
    /// A digest or publisher trust check failed.
    #[error("trust verification failed: {0}")]
    TrustFailure(String),
    /// An archive failed structural or quota validation.
    #[error("archive verification failed: {0}")]
    ArchiveRejected(String),
    /// A local broker message was malformed, oversized, or violated its contract.
    #[error("broker protocol rejected the message: {0}")]
    ProtocolRejected(String),
    /// A local broker request reused a nonce inside its replay window.
    #[error("broker protocol rejected a replayed nonce")]
    ReplayDetected,
    /// The elevation request was dismissed by the interactive user.
    #[error("elevation was cancelled by the user")]
    ElevationCancelled,
    /// The elevated worker did not finish inside its bounded runtime.
    #[error("elevated worker timed out after {seconds} seconds")]
    ElevationTimeout {
        /// Configured timeout in whole seconds.
        seconds: u64,
    },
    /// An operating-system operation failed.
    #[error(transparent)]
    Io(#[from] io::Error),
}

impl PlatformError {
    /// Returns whether this error represents an unsupported host or platform.
    #[must_use]
    pub const fn is_unsupported_host(&self) -> bool {
        matches!(self, Self::UnsupportedPlatform | Self::UnsupportedHost(_))
    }
}
pub use archive::{ArchivePolicy, extract_zip_safely};
