//! Shell-free controller for the native read-only GUI capability slice.

use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use baselineops_capabilities::{
    Capability, CapabilityOutcome, CapabilityRequest, ExecutionEnvironment, Operation, adapter_for,
    lookup,
};
use baselineops_engine::{
    AppControlWindowsExecutor, WaveAdvancedAuditWindowsExecutor,
    WaveApplicationControlWindowsExecutor, WaveBootSecurityWindowsExecutor,
    WaveCertHealthWindowsExecutor, WaveDefenderAsrAllowlistWindowsExecutor,
    WaveDefenderRansomwareWindowsExecutor, WaveFirewallBaselineWindowsExecutor,
    WaveFirewallLoggingWindowsExecutor, WaveHardwareTrustWindowsExecutor,
    WaveInventoryWindowsExecutor, WaveLapsHygieneWindowsExecutor, WaveLocalAdminsWindowsExecutor,
    WaveNetworkServicesWindowsExecutor, WaveOfficeBrowserWindowsExecutor, WaveOneWindowsExecutor,
    WaveRemoteGuardrailsWindowsExecutor, WaveRemoteWdagWindowsExecutor,
    WaveScheduledTasksWindowsExecutor, WaveSecurityOptionsWindowsExecutor,
    WaveSmbEncryptionWindowsExecutor, WaveStorageBackupWindowsExecutor, WaveSysmonWindowsExecutor,
    WaveTwoWindowsExecutor, WaveUpdateHealthWindowsExecutor, WaveWefTimeWindowsExecutor,
    WaveWindowsUpdateWindowsExecutor, WaveWingetWindowsExecutor,
};

/// The only in-development capability IDs backed by native read-only executors.
pub const NATIVE_AUDIT_IDS: [&str; 44] = [
    "v3.defender.asr-allowlist",
    "v3.laps.hygiene",
    "v3.local-admins.guardrail",
    "v3.office-browser.hardening",
    "v3.windows-update.policy",
    "v3.update-health.ssu",
    "v3.scheduled-tasks.hygiene",
    "v3.winget.self-heal",
    "v3.lsass.vbs-hardening",
    "v3.remote-access.guardrails",
    "v3.hardware.tpm-posture",
    "v3.sysmon.config",
    "v3.sysmon.rule-drift",
    "v3.firewall.baseline",
    "v3.software.inventory",
    "v3.smb.encryption",
    "v3.bitlocker.operations",
    "v3.cert.autoenrollment-health",
    "v3.winget.configuration",
    "v3.defender.health",
    "v3.identity.join",
    "v3.network.configuration",
    "v3.service-process.inventory",
    "v3.firewall.logging",
    "v3.advanced-audit-policy",
    "v3.time-sync.health",
    "v3.storage.reliability",
    "v3.backup.readiness",
    "v3.remote-surface.audit",
    "v3.security-options.drift",
    "v3.credential-guard.vbs",
    "v3.lsa.protection",
    "v3.ntlm.client",
    "v3.client-security-baseline",
    "v3.app-control.audit",
    "v3.defender.ransomware-network-protection",
    "v3.wef.client-readiness",
    "v3.secure-boot.uefi",
    "v3.wdag.readiness",
    "v3.exploit-protection.audit",
    "v3.driver-signing.integrity",
    "v3.amsi.audit",
    "v3.applocker.audit",
    "v3.doh.audit",
];

/// A selectable capability from the native audit catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CatalogItem {
    /// Stable registry identifier.
    pub id: &'static str,
    /// Legacy script number retained for operator orientation.
    pub number: u8,
    /// Human-readable registry name.
    pub name: &'static str,
    /// Human-readable registry description.
    pub description: &'static str,
}

/// UI-friendly terminal state of an audit attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuditState {
    /// No audit has started.
    Ready,
    /// A read-only platform observation is in progress.
    Running,
    /// Cancellation was requested; the current native observation is allowed to finish safely.
    Cancelling,
    /// The request was cancelled and its result deliberately discarded.
    Cancelled,
    /// The native executor returned structured, trustworthy output.
    Completed,
    /// Registry dispatch intentionally did not run.
    Unsupported,
    /// The executor could not produce a trustworthy result.
    Failed,
}

/// Renderable result returned from a direct native executor invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditReport {
    /// Terminal or progress state.
    pub state: AuditState,
    /// One-line status for the UI status bar.
    pub status: String,
    /// Pretty-printed structured result when one exists.
    pub result: String,
    /// Bounded diagnostic shown separately from a successful result.
    pub error: Option<String>,
    /// Existing artifact path, if a future native executor explicitly returns one.
    pub artifact: Option<PathBuf>,
}

impl AuditReport {
    /// Initial state before a capability is selected or audited.
    #[must_use]
    pub fn ready() -> Self {
        Self {
            state: AuditState::Ready,
            status: "Ready. Native executors are in development; the GUI remains unelevated and audit-only.".into(),
            result: String::new(),
            error: None,
            artifact: None,
        }
    }

    /// Progress state that communicates the cancellation boundary honestly.
    #[must_use]
    pub fn running() -> Self {
        Self {
            state: AuditState::Running,
            status: "Running an in-development read-only native audit. No changes can be applied."
                .into(),
            result: String::new(),
            error: None,
            artifact: None,
        }
    }

    /// Cancellation progress where a platform call cannot safely be interrupted.
    #[must_use]
    pub fn cancelling() -> Self {
        Self {
            state: AuditState::Cancelling,
            status: "Cancellation requested. The current observation will finish, then its result is discarded.".into(),
            result: String::new(),
            error: None,
            artifact: None,
        }
    }
}

/// Lists only catalog entries whose native executor is intentionally exposed by this GUI.
#[must_use]
pub fn catalog() -> Vec<CatalogItem> {
    NATIVE_AUDIT_IDS
        .iter()
        .filter_map(|id| lookup(id))
        .map(|descriptor| CatalogItem {
            id: descriptor.id,
            number: descriptor.legacy_number,
            name: descriptor.display_name,
            description: descriptor.description,
        })
        .collect()
}

/// Returns an accessible description for a selected catalog item.
#[must_use]
pub fn selection_summary(item: CatalogItem) -> String {
    format!(
        "{:02} {}. {}. Native implementation status: in development. This read-only audit does not establish legacy parity; Apply is intentionally unavailable.",
        item.number, item.name, item.description
    )
}

/// Runs one allowlisted native audit without starting a shell or compatibility runner.
///
/// Cancellation is cooperative at the controller boundary: existing native observations have no
/// cancellation parameter, so the controller discards a completed result after cancellation.
#[must_use]
pub fn audit(id: &str, cancelled: &Arc<AtomicBool>) -> AuditReport {
    if cancelled.load(Ordering::Acquire) {
        return cancelled_report();
    }
    if !NATIVE_AUDIT_IDS.contains(&id) {
        return unsupported(format!("{id} is not exposed by the native read-only GUI."));
    }
    if let Err(error) = baselineops_windows::collect_host_identity() {
        return unsupported(error.to_string());
    }
    let Some(adapter) = adapter_for(id) else {
        return unsupported(format!(
            "{id} is absent from the compiled capability registry."
        ));
    };
    let descriptor = adapter.descriptor();
    let parameters = serde_json::json!({});
    let request = CapabilityRequest {
        operation: Operation::Audit,
        parameters: &parameters,
    };
    let environment = ExecutionEnvironment {
        is_windows: cfg!(windows),
        available_requirements: descriptor.requirements,
    };
    let outcome = dispatch_native(id, &adapter, environment, request);
    if cancelled.load(Ordering::Acquire) {
        return cancelled_report();
    }
    report_outcome(outcome)
}

fn dispatch_native(
    id: &str,
    adapter: &impl Capability,
    environment: ExecutionEnvironment<'_>,
    request: CapabilityRequest<'_>,
) -> CapabilityOutcome {
    let executor: &dyn baselineops_capabilities::CapabilityExecutor = match id {
        "v3.defender.asr-allowlist" => &WaveDefenderAsrAllowlistWindowsExecutor,
        "v3.defender.health" | "v3.identity.join" => &WaveOneWindowsExecutor,
        "v3.office-browser.hardening" => &WaveOfficeBrowserWindowsExecutor,
        "v3.windows-update.policy" => &WaveWindowsUpdateWindowsExecutor,
        "v3.laps.hygiene" => &WaveLapsHygieneWindowsExecutor,
        "v3.local-admins.guardrail" => &WaveLocalAdminsWindowsExecutor,
        "v3.update-health.ssu" => &WaveUpdateHealthWindowsExecutor,
        "v3.scheduled-tasks.hygiene" => &WaveScheduledTasksWindowsExecutor,
        "v3.winget.self-heal" | "v3.winget.configuration" => &WaveWingetWindowsExecutor,
        "v3.ntlm.client" | "v3.doh.audit" => &WaveTwoWindowsExecutor,
        "v3.time-sync.health" | "v3.wef.client-readiness" => &WaveWefTimeWindowsExecutor,
        "v3.network.configuration" | "v3.service-process.inventory" => {
            &WaveNetworkServicesWindowsExecutor
        }
        "v3.firewall.logging" => &WaveFirewallLoggingWindowsExecutor,
        "v3.firewall.baseline" => &WaveFirewallBaselineWindowsExecutor,
        "v3.advanced-audit-policy" => &WaveAdvancedAuditWindowsExecutor,
        "v3.security-options.drift" => &WaveSecurityOptionsWindowsExecutor,
        "v3.remote-access.guardrails" => &WaveRemoteGuardrailsWindowsExecutor,
        "v3.sysmon.config" | "v3.sysmon.rule-drift" => &WaveSysmonWindowsExecutor,
        "v3.smb.encryption" => &WaveSmbEncryptionWindowsExecutor,
        "v3.cert.autoenrollment-health" => &WaveCertHealthWindowsExecutor,
        "v3.lsass.vbs-hardening" | "v3.credential-guard.vbs" | "v3.lsa.protection" => {
            &WaveBootSecurityWindowsExecutor
        }
        "v3.software.inventory" => &WaveInventoryWindowsExecutor,
        "v3.hardware.tpm-posture" | "v3.bitlocker.operations" | "v3.secure-boot.uefi" => {
            &WaveHardwareTrustWindowsExecutor
        }
        "v3.storage.reliability" | "v3.backup.readiness" => &WaveStorageBackupWindowsExecutor,
        "v3.remote-surface.audit" | "v3.wdag.readiness" => &WaveRemoteWdagWindowsExecutor,
        "v3.app-control.audit" => &AppControlWindowsExecutor,
        "v3.defender.ransomware-network-protection" => &WaveDefenderRansomwareWindowsExecutor,
        "v3.client-security-baseline"
        | "v3.driver-signing.integrity"
        | "v3.exploit-protection.audit"
        | "v3.amsi.audit"
        | "v3.applocker.audit" => &WaveApplicationControlWindowsExecutor,
        _ => unreachable!("native ID allowlist was checked above"),
    };
    adapter.execute(environment, request, Some(executor))
}

fn report_outcome(outcome: CapabilityOutcome) -> AuditReport {
    match outcome {
        CapabilityOutcome::Completed { result } => AuditReport {
            state: AuditState::Completed,
            status: "In-development native audit completed. Review the structured result below; legacy parity is not asserted.".into(),
            result: format!(
                "Native implementation status: in development\nLegacy parity: not asserted\n\n{}",
                serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|error| format!("Result rendering failed: {error}"))
            ),
            error: None,
            artifact: existing_artifact(&result),
        },
        CapabilityOutcome::Unsupported { reason } => {
            unsupported(serde_json::to_string(&reason).unwrap_or_else(|error| {
                format!("unsupported state could not be rendered: {error}")
            }))
        }
        CapabilityOutcome::Failed {
            capability_id,
            message,
        } => AuditReport {
            state: AuditState::Failed,
            status: format!(
                "In-development native audit failed for {capability_id}; legacy parity is not asserted."
            ),
            result: String::new(),
            error: Some(message),
            artifact: None,
        },
    }
}

fn unsupported(reason: String) -> AuditReport {
    AuditReport {
        state: AuditState::Unsupported,
        status: "In-development native audit is unsupported on this host or build.".into(),
        result: String::new(),
        error: Some(reason),
        artifact: None,
    }
}

fn cancelled_report() -> AuditReport {
    AuditReport {
        state: AuditState::Cancelled,
        status: "In-development native audit cancelled. No result was retained.".into(),
        result: String::new(),
        error: None,
        artifact: None,
    }
}

fn existing_artifact(result: &serde_json::Value) -> Option<PathBuf> {
    let path = result.get("artifact_path")?.as_str()?;
    let path = PathBuf::from(path);
    path.is_file().then_some(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_is_limited_to_native_read_only_ids() {
        let entries = catalog();
        assert_eq!(entries.len(), NATIVE_AUDIT_IDS.len());
        assert_eq!(
            entries.iter().map(|entry| entry.number).collect::<Vec<_>>(),
            vec![
                1, 2, 3, 4, 5, 6, 7, 8, 13, 14, 15, 16, 17, 18, 19, 22, 23, 24, 25, 27, 28, 29, 30,
                32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52
            ]
        );
        assert!(
            entries
                .iter()
                .all(|entry| NATIVE_AUDIT_IDS.contains(&entry.id))
        );
    }

    #[test]
    fn selection_copy_never_advertises_apply() {
        assert!(selection_summary(catalog()[0]).contains("Apply is intentionally unavailable"));
    }

    #[test]
    fn cancellation_prevents_native_dispatch() {
        let cancelled = Arc::new(AtomicBool::new(true));
        let report = audit("v3.defender.health", &cancelled);
        assert_eq!(report.state, AuditState::Cancelled);
        assert!(report.result.is_empty());
    }

    #[test]
    fn unknown_capability_remains_unsupported() {
        let cancelled = Arc::new(AtomicBool::new(false));
        let report = audit("v3.not-a-capability", &cancelled);
        assert_eq!(report.state, AuditState::Unsupported);
        assert!(report.error.is_some());
    }

    #[cfg(not(windows))]
    #[test]
    fn unsupported_host_preflight_prevents_native_dispatch() {
        let cancelled = Arc::new(AtomicBool::new(false));
        let report = audit("v3.defender.health", &cancelled);
        assert_eq!(report.state, AuditState::Unsupported);
        assert!(
            report
                .error
                .as_deref()
                .is_some_and(|error| error.contains("unsupported"))
        );
    }

    #[test]
    fn artifact_is_exposed_only_for_an_existing_file() {
        let result = serde_json::json!({ "artifact_path": "/path/that/does/not/exist" });
        assert_eq!(existing_artifact(&result), None);
    }

    #[test]
    fn progress_reports_are_explicitly_read_only() {
        assert_eq!(AuditReport::ready().state, AuditState::Ready);
        assert_eq!(AuditReport::running().state, AuditState::Running);
        assert_eq!(AuditReport::cancelling().state, AuditState::Cancelling);
    }
}
