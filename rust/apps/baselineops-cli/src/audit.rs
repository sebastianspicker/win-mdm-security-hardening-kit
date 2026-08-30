//! Read-only native audit composition and `ResultV3` normalization.

use crate::{Selection, resolve_selection, unsupported_response};
use anyhow::{Result, anyhow};
use baselineops_capabilities::{
    Capability, CapabilityDescriptor, CapabilityExecutor, CapabilityOutcome, CapabilityRequest,
    ExecutionEnvironment, ImplementationMaturity, Operation,
};
use baselineops_domain::{
    ActionId, ActionResultV3, ActionStatus, ExitCode, FindingId, FindingStatus, PlanId, ProfileId,
    ResultId, ResultStatus, ResultV3, RunId, SchemaVersion, Severity,
};
use chrono::Utc;
use std::collections::BTreeMap;

const NATIVE_AUDIT_IDS: [&str; 47] = [
    "v3.defender.asr-allowlist",
    "v3.laps.hygiene",
    "v3.local-admins.guardrail",
    "v3.office-browser.hardening",
    "v3.windows-update.policy",
    "v3.update-health.ssu",
    "v3.scheduled-tasks.hygiene",
    "v3.winget.self-heal",
    "v3.support-bundle.parse",
    "v3.lsass.vbs-hardening",
    "v3.remote-access.guardrails",
    "v3.hardware.tpm-posture",
    "v3.sysmon.config",
    "v3.sysmon.rule-drift",
    "v3.firewall.baseline",
    "v3.software.inventory",
    "v3.patch.missing",
    "v3.smb.encryption",
    "v3.bitlocker.operations",
    "v3.cert.autoenrollment-health",
    "v3.winget.configuration",
    "v3.eventlog.fast-triage",
    "v3.defender.health",
    "v3.identity.join",
    "v3.network.configuration",
    "v3.service-process.inventory",
    "v3.firewall.logging",
    "v3.advanced-audit-policy",
    "v3.security-options.drift",
    "v3.storage.reliability",
    "v3.backup.readiness",
    "v3.remote-surface.audit",
    "v3.time-sync.health",
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

pub(crate) fn run(selection: &Selection) -> Result<ExitCode> {
    let (targets, profile_id) = resolve_targets(selection)?;
    let unsupported = targets
        .iter()
        .filter(|target| !native_audit_supported(target.descriptor))
        .map(|target| target.descriptor.id)
        .collect::<Vec<_>>();
    if !unsupported.is_empty() {
        return unsupported_response("audit", &unsupported);
    }
    let host = baselineops_windows::collect_host_identity().map_err(|error| anyhow!(error))?;
    let started_at = Utc::now();
    let mut accumulated = AuditAccumulator {
        actions: Vec::with_capacity(targets.len()),
        findings: Vec::new(),
        status: ResultStatus::Completed,
    };
    for target in targets {
        let descriptor = target.descriptor;
        let action_id = ActionId::new();
        let outcome = dispatch_native_audit(descriptor, &target.parameters);
        let completed_at = Utc::now();
        record_outcome(
            outcome,
            descriptor,
            action_id,
            started_at,
            completed_at,
            &mut accumulated,
        )?;
    }
    let capability_id =
        (accumulated.actions.len() == 1).then(|| accumulated.actions[0].capability.clone());
    let result = ResultV3 {
        schema_version: SchemaVersion::V3,
        id: ResultId::new(),
        run_id: RunId::new(),
        plan_id: PlanId::new(),
        profile_id: profile_id.unwrap_or_else(ProfileId::new),
        capability_id,
        operation: baselineops_domain::Operation::Audit,
        host,
        status: accumulated.status,
        started_at,
        completed_at: Utc::now(),
        actions: accumulated.actions,
        findings: accumulated.findings,
        summary: "standard-user native audit completed without mutation".into(),
        artifacts: Vec::new(),
        metadata: BTreeMap::new(),
    };
    result.validate()?;
    crate::print_json(&result)?;
    Ok(result.exit_code())
}

struct AuditTarget {
    descriptor: &'static CapabilityDescriptor,
    parameters: serde_json::Value,
}

struct AuditAccumulator {
    status: ResultStatus,
    findings: Vec<baselineops_domain::FindingV3>,
    actions: Vec<ActionResultV3>,
}

fn record_outcome(
    outcome: CapabilityOutcome,
    descriptor: &'static CapabilityDescriptor,
    action_id: ActionId,
    started_at: chrono::DateTime<Utc>,
    completed_at: chrono::DateTime<Utc>,
    accumulated: &mut AuditAccumulator,
) -> Result<()> {
    match outcome {
        CapabilityOutcome::Completed { result } => {
            let has_findings = result
                .get("findings")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|items| !items.is_empty());
            if has_findings {
                raise_status(&mut accumulated.status, ResultStatus::Warnings);
            }
            let (finding_status, severity, message, action_status) = if has_findings {
                (
                    FindingStatus::Warning,
                    Severity::Medium,
                    "audit completed with incomplete or adverse evidence",
                    ActionStatus::Findings,
                )
            } else {
                (
                    FindingStatus::Info,
                    Severity::Info,
                    "audit observation collected",
                    ActionStatus::Succeeded,
                )
            };
            accumulated.findings.push(finding(
                descriptor,
                action_id,
                finding_status,
                severity,
                message,
                result.clone(),
            ));
            accumulated.actions.push(action_result(
                descriptor,
                action_id,
                action_status,
                started_at,
                completed_at,
                result,
            ));
        }
        CapabilityOutcome::Unsupported { reason } => {
            raise_status(&mut accumulated.status, ResultStatus::Unsupported);
            accumulated.findings.push(finding(
                descriptor,
                action_id,
                FindingStatus::Skipped,
                Severity::Info,
                "native audit is unavailable",
                serde_json::to_value(reason)?,
            ));
            accumulated.actions.push(action_result(
                descriptor,
                action_id,
                ActionStatus::Blocked,
                started_at,
                completed_at,
                serde_json::json!({}),
            ));
        }
        CapabilityOutcome::Failed { message, .. } => {
            raise_status(&mut accumulated.status, ResultStatus::ExecutionFailed);
            accumulated.findings.push(finding(
                descriptor,
                action_id,
                FindingStatus::Error,
                Severity::High,
                "native audit failed",
                serde_json::json!({"error": message}),
            ));
            accumulated.actions.push(action_result(
                descriptor,
                action_id,
                ActionStatus::Failed,
                started_at,
                completed_at,
                serde_json::json!({}),
            ));
        }
    }
    Ok(())
}

fn raise_status(current: &mut ResultStatus, candidate: ResultStatus) {
    fn priority(status: ResultStatus) -> u8 {
        match status {
            ResultStatus::Completed => 0,
            ResultStatus::Warnings => 1,
            ResultStatus::Unsupported => 2,
            ResultStatus::ExecutionFailed => 3,
            ResultStatus::Cancelled => 4,
            ResultStatus::Rejected => 5,
        }
    }
    if priority(candidate) > priority(*current) {
        *current = candidate;
    }
}

fn resolve_targets(selection: &Selection) -> Result<(Vec<AuditTarget>, Option<ProfileId>)> {
    if let Some(path) = &selection.profile {
        let profile: baselineops_domain::ProfileV3 = baselineops_domain::load_json_file(
            path,
            baselineops_domain::JsonLoadLimits::default(),
        )?;
        let validation = profile.validate()?;
        let mut targets = Vec::with_capacity(profile.steps.len());
        for step_id in validation.topological_order.as_slice() {
            let step = profile
                .steps
                .iter()
                .find(|step| &step.step_id == step_id)
                .ok_or_else(|| anyhow!("validated profile step is unavailable"))?;
            let descriptor = baselineops_capabilities::lookup(step.capability_id.as_str())
                .ok_or_else(|| {
                    anyhow!(
                        "profile references unknown capability: {}",
                        step.capability_id
                    )
                })?;
            targets.push(AuditTarget {
                descriptor,
                parameters: serde_json::to_value(&step.parameters)?,
            });
        }
        return Ok((targets, Some(profile.id)));
    }
    let (descriptors, profile_id) = resolve_selection(selection)?;
    let targets = descriptors
        .into_iter()
        .map(|descriptor| {
            Ok(AuditTarget {
                descriptor,
                parameters: direct_parameters(descriptor, selection)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((targets, profile_id))
}

fn direct_parameters(
    descriptor: &CapabilityDescriptor,
    selection: &Selection,
) -> Result<serde_json::Value> {
    if descriptor.id != "v3.support-bundle.parse" {
        return Ok(serde_json::json!({}));
    }
    let support_dir = selection
        .support_dir
        .as_ref()
        .ok_or_else(|| anyhow!("v3.support-bundle.parse requires --support-dir DIR"))?;
    Ok(serde_json::json!({"support_dir": support_dir}))
}

pub(crate) fn native_audit_supported(descriptor: &CapabilityDescriptor) -> bool {
    descriptor.maturity == ImplementationMaturity::InDevelopment
        && NATIVE_AUDIT_IDS.contains(&descriptor.id)
}

pub(crate) fn dispatch_native_audit(
    descriptor: &'static CapabilityDescriptor,
    parameters: &serde_json::Value,
) -> CapabilityOutcome {
    let environment = ExecutionEnvironment {
        is_windows: cfg!(windows),
        available_requirements: descriptor.requirements,
    };
    let request = CapabilityRequest {
        operation: Operation::Audit,
        parameters,
    };
    let executor: &dyn CapabilityExecutor = match descriptor.id {
        "v3.defender.asr-allowlist" => &baselineops_engine::WaveDefenderAsrAllowlistWindowsExecutor,
        "v3.defender.health" | "v3.identity.join" => &baselineops_engine::WaveOneWindowsExecutor,
        "v3.office-browser.hardening" => &baselineops_engine::WaveOfficeBrowserWindowsExecutor,
        "v3.windows-update.policy" => &baselineops_engine::WaveWindowsUpdateWindowsExecutor,
        "v3.laps.hygiene" => &baselineops_engine::WaveLapsHygieneWindowsExecutor,
        "v3.local-admins.guardrail" => &baselineops_engine::WaveLocalAdminsWindowsExecutor,
        "v3.update-health.ssu" => &baselineops_engine::WaveUpdateHealthWindowsExecutor,
        "v3.scheduled-tasks.hygiene" => &baselineops_engine::WaveScheduledTasksWindowsExecutor,
        "v3.winget.self-heal" | "v3.winget.configuration" => {
            &baselineops_engine::WaveWingetWindowsExecutor
        }
        "v3.ntlm.client" | "v3.doh.audit" => &baselineops_engine::WaveTwoWindowsExecutor,
        "v3.time-sync.health" | "v3.wef.client-readiness" => {
            &baselineops_engine::WaveWefTimeWindowsExecutor
        }
        "v3.network.configuration" | "v3.service-process.inventory" => {
            &baselineops_engine::WaveNetworkServicesWindowsExecutor
        }
        "v3.firewall.logging" => &baselineops_engine::WaveFirewallLoggingWindowsExecutor,
        "v3.firewall.baseline" => &baselineops_engine::WaveFirewallBaselineWindowsExecutor,
        "v3.advanced-audit-policy" => &baselineops_engine::WaveAdvancedAuditWindowsExecutor,
        "v3.security-options.drift" => &baselineops_engine::WaveSecurityOptionsWindowsExecutor,
        "v3.remote-access.guardrails" => &baselineops_engine::WaveRemoteGuardrailsWindowsExecutor,
        "v3.sysmon.config" | "v3.sysmon.rule-drift" => {
            &baselineops_engine::WaveSysmonWindowsExecutor
        }
        "v3.smb.encryption" => &baselineops_engine::WaveSmbEncryptionWindowsExecutor,
        "v3.cert.autoenrollment-health" => &baselineops_engine::WaveCertHealthWindowsExecutor,
        "v3.lsass.vbs-hardening" | "v3.credential-guard.vbs" | "v3.lsa.protection" => {
            &baselineops_engine::WaveBootSecurityWindowsExecutor
        }
        "v3.support-bundle.parse" => &baselineops_engine::SupportBundleParserExecutor,
        "v3.software.inventory" | "v3.patch.missing" | "v3.eventlog.fast-triage" => {
            &baselineops_engine::WaveInventoryWindowsExecutor
        }
        "v3.hardware.tpm-posture" | "v3.bitlocker.operations" | "v3.secure-boot.uefi" => {
            &baselineops_engine::WaveHardwareTrustWindowsExecutor
        }
        "v3.storage.reliability" | "v3.backup.readiness" => {
            &baselineops_engine::WaveStorageBackupWindowsExecutor
        }
        "v3.remote-surface.audit" | "v3.wdag.readiness" => {
            &baselineops_engine::WaveRemoteWdagWindowsExecutor
        }
        "v3.app-control.audit" => &baselineops_engine::AppControlWindowsExecutor,
        "v3.defender.ransomware-network-protection" => {
            &baselineops_engine::WaveDefenderRansomwareWindowsExecutor
        }
        "v3.client-security-baseline"
        | "v3.driver-signing.integrity"
        | "v3.exploit-protection.audit"
        | "v3.amsi.audit"
        | "v3.applocker.audit" => &baselineops_engine::WaveApplicationControlWindowsExecutor,
        _ => {
            return CapabilityOutcome::Unsupported {
                reason: baselineops_capabilities::Unsupported::ExecutorUnavailable {
                    capability_id: descriptor.id.into(),
                },
            };
        }
    };
    baselineops_capabilities::adapter_for(descriptor.id)
        .expect("catalog IDs are valid")
        .execute(environment, request, Some(executor))
}

fn action_result(
    descriptor: &CapabilityDescriptor,
    action_id: ActionId,
    status: ActionStatus,
    started_at: chrono::DateTime<Utc>,
    completed_at: chrono::DateTime<Utc>,
    result: serde_json::Value,
) -> ActionResultV3 {
    ActionResultV3 {
        action_id,
        capability: baselineops_domain::CapabilityId::try_from(descriptor.id)
            .expect("catalog IDs are valid"),
        status,
        started_at,
        completed_at,
        metadata: BTreeMap::from([("native_result".into(), result)]),
    }
}
fn finding(
    descriptor: &CapabilityDescriptor,
    action_id: ActionId,
    status: FindingStatus,
    severity: Severity,
    message: &str,
    evidence: serde_json::Value,
) -> baselineops_domain::FindingV3 {
    baselineops_domain::FindingV3 {
        id: FindingId::new(),
        capability: baselineops_domain::CapabilityId::try_from(descriptor.id)
            .expect("catalog IDs are valid"),
        action_id: Some(action_id),
        code: format!("{}.observation", descriptor.id),
        status,
        severity,
        message: message.into(),
        observed_at: Utc::now(),
        evidence: BTreeMap::from([("result".into(), evidence)]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn profile_targets_preserve_topological_order_and_typed_parameters() {
        let selection = Selection {
            capability: None,
            profile: Some(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../../examples/profiles/inventory-patch-events.v3.json"),
            ),
            batch: None,
            support_dir: None,
        };
        let (targets, profile_id) = resolve_targets(&selection).expect("resolve audit profile");
        assert!(profile_id.is_some());
        assert_eq!(
            targets
                .iter()
                .map(|target| target.descriptor.id)
                .collect::<Vec<_>>(),
            vec![
                "v3.software.inventory",
                "v3.patch.missing",
                "v3.eventlog.fast-triage"
            ]
        );
        assert_eq!(targets[1].parameters["entries"][0]["kb"], "KB5030219");
        assert_eq!(targets[2].parameters["channel"], "System");
    }

    #[test]
    fn later_findings_cannot_downgrade_terminal_status() {
        let mut status = ResultStatus::ExecutionFailed;
        raise_status(&mut status, ResultStatus::Warnings);
        assert_eq!(status, ResultStatus::ExecutionFailed);

        let mut status = ResultStatus::Warnings;
        raise_status(&mut status, ResultStatus::Unsupported);
        assert_eq!(status, ResultStatus::Unsupported);
    }
}
