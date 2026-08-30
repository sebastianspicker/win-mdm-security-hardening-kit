//! `BaselineOps` v3 orchestration, approval, journaling, and reporting.

mod app_control;
mod apply_authority;
mod approval;
mod evidence;
mod installed_package;
mod journal;
mod orchestrator;
mod package;
mod planner;
mod registry_deriver;
mod reporting;
mod scheduler;
mod support_bundle_parser;
mod wave_advanced_audit;
mod wave_application_control;
mod wave_boot_security;
mod wave_cert_health;
mod wave_defender_asr_allowlist;
mod wave_defender_ransomware;
mod wave_firewall_baseline;
mod wave_firewall_logging;
mod wave_hardware_trust;
mod wave_inventory;
mod wave_laps_hygiene;
mod wave_local_admins;
mod wave_network_services;
mod wave_office_browser;
mod wave_one;
mod wave_powershell_logging;
mod wave_remote_guardrails;
mod wave_remote_wdag;
mod wave_scheduled_tasks;
mod wave_security_options;
mod wave_smb_encryption;
mod wave_storage_backup;
mod wave_sysmon;
mod wave_two;
mod wave_update_health;
mod wave_wef_time;
mod wave_windows_update;
mod wave_winget;

pub use app_control::AppControlWindowsExecutor;
pub use apply_authority::{
    ApprovedWorkerApply, NativeObservationSource, TrustedObservationSource, WorkerApplyAuthority,
    prepare_worker_apply, reobserve_profile,
};
pub use approval::{ApprovalError, VerifiedPlan};
pub use evidence::{
    EvidenceError, EvidenceLimits, EvidenceManifest, EvidenceProtection, EvidenceStore,
    EvidenceWrite,
};
pub use installed_package::{
    InstalledPackageExpectation, InstalledPackageIdentity, verify_installed_package,
};
pub use journal::{Journal, JournalEvent, JournalRecord, JournalRecovery, JournalSnapshot};
pub use orchestrator::{
    ApplyOutcome, ApplyService, AuditService, EngineOrchestrator, ExecutionDisposition,
    OrchestratorError, PlanService, aggregate_disposition,
};
pub use package::{
    DetachedSignatureVerifier, ManifestFile, PackageError, PackageManifestV1, PackageVerification,
    SignatureVerifier, verify_package,
};
pub use planner::{PlanBuildContext, PlanningError, TrustedActionDeriver, WorkerPlan, build_plan};
pub use registry_deriver::RegistryActionDeriver;
pub use reporting::{
    AggregateReport, ReportError, aggregate, validate_result_consistency, write_csv, write_json,
    write_json_lines,
};
pub use scheduler::{
    ActionExecution, ActionRunner, CancellationToken, ExecutionPolicy, ExecutionSummary,
    SchedulerError, execute_verified_plan,
};
pub use support_bundle_parser::{SupportBundleParserExecutor, parse_support_bundle};
pub use wave_advanced_audit::WaveAdvancedAuditWindowsExecutor;
pub use wave_application_control::WaveApplicationControlWindowsExecutor;
pub use wave_boot_security::WaveBootSecurityWindowsExecutor;
pub use wave_cert_health::WaveCertHealthWindowsExecutor;
pub use wave_defender_asr_allowlist::WaveDefenderAsrAllowlistWindowsExecutor;
pub use wave_defender_ransomware::WaveDefenderRansomwareWindowsExecutor;
pub use wave_firewall_baseline::WaveFirewallBaselineWindowsExecutor;
pub use wave_firewall_logging::WaveFirewallLoggingWindowsExecutor;
pub use wave_hardware_trust::WaveHardwareTrustWindowsExecutor;
pub use wave_inventory::WaveInventoryWindowsExecutor;
pub use wave_laps_hygiene::WaveLapsHygieneWindowsExecutor;
pub use wave_local_admins::WaveLocalAdminsWindowsExecutor;
pub use wave_network_services::WaveNetworkServicesWindowsExecutor;
pub use wave_office_browser::WaveOfficeBrowserWindowsExecutor;
pub use wave_one::WaveOneWindowsExecutor;
pub use wave_powershell_logging::WavePowerShellLoggingWindowsExecutor;
pub use wave_remote_guardrails::WaveRemoteGuardrailsWindowsExecutor;
pub use wave_remote_wdag::WaveRemoteWdagWindowsExecutor;
pub use wave_scheduled_tasks::WaveScheduledTasksWindowsExecutor;
pub use wave_security_options::WaveSecurityOptionsWindowsExecutor;
pub use wave_smb_encryption::WaveSmbEncryptionWindowsExecutor;
pub use wave_storage_backup::WaveStorageBackupWindowsExecutor;
pub use wave_sysmon::WaveSysmonWindowsExecutor;
pub use wave_two::WaveTwoWindowsExecutor;
pub use wave_update_health::WaveUpdateHealthWindowsExecutor;
pub use wave_wef_time::WaveWefTimeWindowsExecutor;
pub use wave_windows_update::WaveWindowsUpdateWindowsExecutor;
pub use wave_winget::WaveWingetWindowsExecutor;
