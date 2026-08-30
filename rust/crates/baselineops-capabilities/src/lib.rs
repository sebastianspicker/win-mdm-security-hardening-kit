//! Compile-time registry for the 52 legacy `BaselineOps` endpoint capabilities.
//!
//! The registry describes the legacy PowerShell surface without claiming that a
//! Rust implementation exists. Callers select a descriptor first, then provide
//! a platform-aware executor. On unsupported hosts or absent executor hooks the
//! outcome is explicitly typed as [`CapabilityOutcome::Unsupported`].

mod advanced_audit_policy;
mod amsi_policy;
mod app_control_policy;
mod applocker_policy;
mod audit_policy;
mod backup_readiness_policy;
mod boot_security_policy;
mod catalog;
mod cert_health_policy;
mod client_baseline_policy;
mod defender_asr_allowlist_policy;
mod defender_ransomware_policy;
mod driver_integrity_policy;
mod event_triage_policy;
mod exploit_protection_policy;
mod firewall_baseline_policy;
mod firewall_logging_policy;
mod hardware_trust_policy;
mod laps_hygiene_policy;
mod local_admins_policy;
mod missing_patch_policy;
mod network_service_inventory_policy;
mod office_browser_policy;
mod powershell_logging_policy;
mod registry;
mod remote_guardrails_policy;
mod remote_surface_policy;
mod scheduled_tasks_policy;
mod security_options_policy;
mod smb_encryption_policy;
mod software_inventory_policy;
mod storage_reliability_policy;
mod support_bundle_parser_policy;
mod sysmon_policy;
mod types;
mod update_health_policy;
mod wdag_readiness_policy;
mod wef_time_policy;
mod windows_update_policy;
mod winget_policy;

pub use advanced_audit_policy::{
    AdvancedAuditObservation, AdvancedAuditPolicy, AdvancedAuditResult,
    AuditSubcategoryObservation, DesiredAuditSubcategory, MAX_AUDIT_SUBCATEGORIES,
    evaluate_advanced_audit, parse_auditpol_csv, validate_advanced_audit_policy,
};
pub use amsi_policy::{AmsiAudit, AmsiObservation, AmsiPolicy, evaluate_amsi};
pub use app_control_policy::{
    APP_CONTROL_EVENT_TIMEOUT_MS, AppControlAudit, AppControlObservation, AppControlPolicy,
    AppControlPolicyFile, CODE_INTEGRITY_EVENT_IDS, MAX_APP_CONTROL_EVENT_XML_BYTES,
    MAX_APP_CONTROL_EVENTS, evaluate_app_control,
};
pub use applocker_policy::{
    AppLockerAudit, AppLockerCollection, AppLockerCollectionObservation, AppLockerObservation,
    AppLockerPolicy, evaluate_applocker,
};
pub use audit_policy::{
    DohAudit, DohObservation, NtlmAudit, NtlmPolicy, PolicyFinding, evaluate_doh, evaluate_ntlm,
};
pub use backup_readiness_policy::{
    BackupReadinessAudit, BackupReadinessObservation, BackupReadinessPolicy, OsVolumeSpace,
    VssWriter, evaluate_backup_readiness, parse_vss_writers,
};
pub use boot_security_policy::{
    BootSecurityField, BootSecurityObservation, BootSecurityResult, CredentialGuardPolicy,
    LsaProtectionPolicy, LsassHardeningPolicy, evaluate_credential_guard, evaluate_lsa_protection,
    evaluate_lsass_hardening, validate_credential_guard, validate_lsa_protection,
};
pub use catalog::CAPABILITIES;
pub use cert_health_policy::{
    AutoEnrollmentPolicy, CertHealthAudit, CertHealthObservation, CertHealthParameters,
    MAX_EXPIRY_WARNING_DAYS, MachineCertificateMetadata, evaluate_cert_health,
};
pub use client_baseline_policy::{
    ClientBaselineAudit, ClientBaselineField, ClientBaselineObservation, ClientBaselinePolicy,
    evaluate_client_baseline,
};
pub use defender_asr_allowlist_policy::{
    AsrRuleActionCounts, DefenderAsrAllowlistAudit, DefenderAsrAllowlistObservation,
    DefenderAsrAllowlistPlan, DefenderAsrAllowlistPolicy, build_defender_asr_allowlist_plan,
    evaluate_defender_asr_allowlist,
};
pub use defender_ransomware_policy::{
    ControlledFolderAccessState, DefenderRansomwareAudit, DefenderRansomwareDrift,
    DefenderRansomwareObservation, DefenderRansomwarePlan, DefenderRansomwarePolicy,
    NetworkProtectionState, build_defender_ransomware_plan, evaluate_defender_ransomware,
};
pub use driver_integrity_policy::{
    BootIntegrityFlags, DriverIntegrityAudit, DriverIntegrityObservation, DriverIntegrityPolicy,
    evaluate_driver_integrity, parse_bcd_integrity,
};
pub use event_triage_policy::{
    EventLogObservation, EventLogQueryParameters, EventLogRecord, EventLogTriageAudit,
    MAX_EVENT_MESSAGE_BYTES, MAX_EVENT_QUERY_BYTES, MAX_EVENT_RECORDS, MAX_EVENT_TIMEOUT_MS,
    MAX_EVENT_XML_BYTES, evaluate_event_triage, validate_event_query,
};
pub use exploit_protection_policy::{
    AsrRuleObservation, ExploitProtectionAudit, ExploitProtectionObservation,
    ExploitProtectionPolicy, SystemDepPolicy, evaluate_exploit_protection,
};
pub use firewall_baseline_policy::{
    FirewallBaselineAudit, FirewallBaselineDrift, FirewallBaselineField,
    FirewallBaselineObservation, FirewallBaselineParameters, FirewallBaselinePlan,
    FirewallBaselineProfileDesiredState, FirewallBaselineProfileObservation,
    FirewallBaselineProfileObservations, FirewallBaselineProfiles, FirewallDefaultAction,
    build_firewall_baseline_plan, evaluate_firewall_baseline,
    fixed_profiles as fixed_firewall_baseline_profiles,
};
pub use firewall_logging_policy::{
    FirewallEvidence, FirewallLoggingConfig, FirewallLoggingDesiredState, FirewallLoggingDrift,
    FirewallLoggingField, FirewallLoggingParameters, FirewallLoggingPlan, FirewallObservation,
    FirewallPolicyModifyState, FirewallProfile, FirewallProfileObservation,
    MAX_LOG_FILE_PATH_BYTES, MAX_LOG_SIZE_KILOBYTES, MIN_LOG_SIZE_KILOBYTES,
    build_firewall_logging_plan, fixed_profiles, resolve_firewall_logging_desired_state,
};
pub use hardware_trust_policy::{
    BitLockerAudit, BitLockerObservation, BitLockerPolicy, FirmwareType, HardwareTpmAudit,
    HardwareTpmObservation, HardwareTpmPolicy, SecureBootAudit, SecureBootObservation,
    SecureBootPolicy, TpmDeviceObservation, evaluate_bitlocker, evaluate_hardware_tpm,
    evaluate_secure_boot,
};
pub use laps_hygiene_policy::{
    LapsHygieneAudit, LapsHygieneObservation, LapsHygieneParameters, LapsOperationalEvent,
    LapsPolicyEvidence, LapsPolicySource, MAX_EARLY_ROTATION_DAYS, RotationEligibility,
    evaluate_laps_hygiene,
};
pub use local_admins_policy::{
    LocalAdministratorMember, LocalAdminsAudit, LocalAdminsObservation, LocalAdminsParameters,
    MAX_ALLOWED_SIDS, evaluate_local_admins,
};
pub use missing_patch_policy::{
    MAX_INSTALLED_KBS, MAX_PATCH_FEED_ENTRIES, MissingPatchAudit, MissingPatchObservation,
    PatchFeed, PatchFeedEntry, canonical_kb, evaluate_missing_patches, validate_patch_feed,
};
pub use network_service_inventory_policy::{
    EmptyAuditParameters, MAX_INVENTORY_RECORDS, NetworkInterfaceObservation,
    NetworkInventoryAudit, NetworkInventoryObservation, ProcessInventoryRecord,
    ServiceInventoryRecord, ServiceProcessInventoryAudit, ServiceProcessInventoryObservation,
    evaluate_network_inventory, evaluate_service_process_inventory,
};
pub use office_browser_policy::{
    EdgeConfig, MacrosMode, OfficeBrowserConfig, OfficeBrowserDesiredState, OfficeBrowserField,
    OfficeBrowserMutation, OfficeBrowserObservation, OfficeBrowserParameters, OfficeBrowserPlan,
    OfficeConfig, PolicyValueSnapshot, ProtectedViewConfig, TlsMinimum, TrackingPrevention,
    build_plan as build_office_browser_plan,
    resolve_desired_state as resolve_office_browser_desired_state,
};
pub use powershell_logging_policy::{
    MAX_MODULE_NAMES, MAX_POLICY_STRING_BYTES, ModuleNamesSnapshot, PolicyField,
    PowerShellLoggingConfig, PowerShellLoggingDesiredState, PowerShellLoggingHiveSnapshot,
    PowerShellLoggingMutation, PowerShellLoggingObservation, PowerShellLoggingParameters,
    PowerShellLoggingPlan, ValueSnapshot, build_plan as build_powershell_logging_plan,
    resolve_desired_state as resolve_powershell_logging_desired_state,
};
pub use registry::{RegistryCapability, adapter_for, list, lookup, lookup_legacy, select_batch};
pub use remote_guardrails_policy::{
    GuardrailSwitch, RdpAccess, RdpMinimumEncryption, RdpSecurityLayer,
    RemoteAssistanceTicketLifetime, RemoteGuardrailDrift, RemoteGuardrailField,
    RemoteGuardrailsAudit, RemoteGuardrailsObservation, RemoteGuardrailsPlan,
    RemoteGuardrailsPolicy, build_remote_guardrails_plan, evaluate_remote_guardrails,
};
pub use remote_surface_policy::{
    RemoteSurfaceAudit, RemoteSurfaceObservation, RemoteSurfacePolicy, TcpListenerObservation,
    evaluate_remote_surface,
};
pub use scheduled_tasks_policy::{
    FIXED_SCHEDULED_TASKS, ScheduledTask, ScheduledTaskSnapshot, ScheduledTaskState,
    ScheduledTasksAudit, ScheduledTasksObservation, ScheduledTasksParameters,
    ScheduledTasksReadOnlyPlan, build_scheduled_tasks_read_only_plan, evaluate_scheduled_tasks,
};
pub use security_options_policy::{
    AnonymousRestriction, Enabled, LmCompatibilityLevel, SecurityOptionEvidence,
    SecurityOptionsAudit, SecurityOptionsDrift, SecurityOptionsField, SecurityOptionsObservation,
    SecurityOptionsPlan, SecurityOptionsPolicy, build_security_options_plan,
    evaluate_security_options,
};
pub use smb_encryption_policy::{
    SmbEncryptionAudit, SmbEncryptionDrift, SmbEncryptionField, SmbEncryptionObservation,
    SmbEncryptionPlan, SmbEncryptionPolicy, build_smb_encryption_plan, evaluate_smb_encryption,
};
pub use software_inventory_policy::{
    MAX_SOFTWARE_RECORDS, SoftwareInventoryAudit, SoftwareInventoryObservation,
    SoftwareInventoryRecord, SoftwareRegistryView, evaluate_software_inventory,
};
pub use storage_reliability_policy::{
    PhysicalDiskObservation, ReliabilityCounters, StorageReliabilityAudit,
    StorageReliabilityObservation, StorageReliabilityPolicy, evaluate_storage_reliability,
};
pub use support_bundle_parser_policy::{
    BundleArtifact, EXPECTED_PROOFS, KbStatus, MAX_JSON_BYTES, MAX_SUMMARY_ITEMS, ProofObservation,
    SummaryRecord, SupportBundleParserAudit, SupportBundleParserObservation,
    SupportBundleParserParameters, SupportBundleSummary, evaluate_support_bundle_parser,
};
pub use sysmon_policy::{
    MAX_SYSMON_EVENT_XML_BYTES, MAX_SYSMON_EVENTS, SYSMON_EVENT_TIMEOUT_MS, SysmonAudit,
    SysmonBinaryEvidence, SysmonImageEvidence, SysmonObservation, SysmonPolicy, SysmonReadOnlyPlan,
    SysmonServiceIdentity, SysmonServiceObservation, SysmonSignatureEvidence,
    build_sysmon_read_only_plan, evaluate_sysmon,
};
pub use types::{
    Batch, Capability, CapabilityDescriptor, CapabilityExecutor, CapabilityOutcome,
    CapabilityRequest, ExecutionEnvironment, ImplementationMaturity, Operation, Operations,
    Privilege, Reboot, Reversibility, Risk, Unsupported,
};
pub use update_health_policy::{
    FIXED_UPDATE_HEALTH_SERVICES, FIXED_UPDATE_HEALTH_TASKS, MAX_UPDATE_HISTORY_RECORDS,
    MAX_UPDATE_TITLE_BYTES, UpdateAgentMetadata, UpdateHealthAudit, UpdateHealthObservation,
    UpdateHealthParameters, UpdateHealthReadOnlyPlan, UpdateHealthService, UpdateHealthTask,
    UpdateHealthTaskSnapshot, UpdateHealthTaskState, UpdateHistoryRecord,
    build_update_health_read_only_plan, evaluate_update_health,
};
pub use wdag_readiness_policy::{
    OptionalFeatureState, WdagReadinessAudit, WdagReadinessObservation, WdagReadinessPolicy,
    WindowsEdition, evaluate_wdag_readiness,
};
pub use wef_time_policy::{
    Observation, ServiceObservation, ServiceStartMode, ServiceState, TimeSyncAudit,
    TimeSyncObservation, TimeSyncPolicy, WecutilQc, WefReadinessAudit, WefReadinessObservation,
    WefReadinessPolicy, evaluate_time_sync, evaluate_wef_readiness, parse_w32tm_source,
    parse_w32tm_status, parse_wecutil_qc,
};
pub use windows_update_policy::{
    Deferrals, DeliveryOptimization, DownloadMode, TargetRelease, UpdateSource,
    WindowsUpdateConfig, WindowsUpdateField, WindowsUpdateMutation, WindowsUpdateObservation,
    WindowsUpdateParameters, WindowsUpdatePlan, build_plan as build_windows_update_plan,
    resolve_desired_state as resolve_windows_update_desired_state,
};
pub use winget_policy::{
    APP_INSTALLER_PACKAGE_FAMILY, MAX_WINGET_APP_PATH_BYTES, WINGET_APP_PATHS_KEY,
    WINGET_CONFIGURATION_ID, WINGET_SELF_HEAL_ID, WingetAudit, WingetConfigurationEvidence,
    WingetExecutableEvidence, WingetObservation, WingetParameters, WingetReadOnlyPlan,
    WingetSourceEvidence, WingetVersion, build_winget_read_only_plan,
    evaluate_winget_configuration, evaluate_winget_self_heal, parse_winget_version,
};

#[cfg(test)]
mod tests;
