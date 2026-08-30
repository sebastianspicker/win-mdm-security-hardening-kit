//! Pure, read-only policy evaluation for Defender ransomware and network protection.
//!
//! This bounded capability deliberately covers only the fixed `MSFT_MpPreference`
//! properties used by legacy capability 44. It neither invokes Defender cmdlets nor
//! claims that WMI observation substitutes for legacy-oracle or Windows VM evidence.

use crate::{Observation, PolicyFinding};
use baselineops_domain::{FindingStatus, JsonMap, Severity};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Finite Controlled Folder Access modes supported by Defender.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlledFolderAccessState {
    /// Controlled Folder Access is disabled.
    Disabled,
    /// Controlled Folder Access blocks protected-folder changes.
    #[default]
    Enabled,
    /// Controlled Folder Access records would-be blocks without blocking.
    AuditMode,
    /// Controlled Folder Access blocks disk modification only.
    BlockDiskModificationOnly,
    /// Controlled Folder Access audits disk modification only.
    AuditDiskModificationOnly,
}

impl ControlledFolderAccessState {
    /// Converts the documented `MSFT_MpPreference` numeric value.
    #[must_use]
    pub const fn from_wmi(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Disabled),
            1 => Some(Self::Enabled),
            2 => Some(Self::AuditMode),
            3 => Some(Self::BlockDiskModificationOnly),
            4 => Some(Self::AuditDiskModificationOnly),
            _ => None,
        }
    }
}

/// Finite Defender Network Protection modes.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkProtectionState {
    /// Network Protection is disabled.
    Disabled,
    /// Network Protection blocks malicious network destinations.
    #[default]
    Enabled,
    /// Network Protection reports would-be blocks without blocking.
    AuditMode,
}

impl NetworkProtectionState {
    /// Converts the documented `MSFT_MpPreference` numeric value.
    #[must_use]
    pub const fn from_wmi(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Disabled),
            1 => Some(Self::Enabled),
            2 => Some(Self::AuditMode),
            _ => None,
        }
    }
}

/// Strict desired state for the fixed, read-only capability 44 subset.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, rename_all = "snake_case", deny_unknown_fields)]
pub struct DefenderRansomwarePolicy {
    /// Desired Controlled Folder Access mode.
    pub controlled_folder_access: ControlledFolderAccessState,
    /// Desired Network Protection mode.
    pub network_protection: NetworkProtectionState,
    /// Assess fixed Server Network Protection prerequisite properties.
    pub apply_network_protection_server_prereqs: bool,
    /// On Server, recommend that datagram processing is disabled.
    pub disable_datagram_processing_on_win_server: bool,
}

impl Default for DefenderRansomwarePolicy {
    fn default() -> Self {
        Self {
            controlled_folder_access: ControlledFolderAccessState::Enabled,
            network_protection: NetworkProtectionState::Enabled,
            apply_network_protection_server_prereqs: false,
            disable_datagram_processing_on_win_server: true,
        }
    }
}

/// Fixed native evidence used by capability 44.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct DefenderRansomwareObservation {
    /// `EnableControlledFolderAccess` from the local Defender WMI provider.
    pub controlled_folder_access: Observation<ControlledFolderAccessState>,
    /// `EnableNetworkProtection` from the local Defender WMI provider.
    pub network_protection: Observation<NetworkProtectionState>,
    /// Whether the fixed operating-system product type is Server.
    pub is_server: Observation<bool>,
    /// `AllowNetworkProtectionOnWinServer` from the fixed provider object.
    pub allow_network_protection_on_win_server: Observation<bool>,
    /// `AllowNetworkProtectionDownLevel` from the fixed provider object.
    pub allow_network_protection_down_level: Observation<bool>,
    /// `AllowDatagramProcessingOnWinServer` from the fixed provider object.
    pub allow_datagram_processing_on_win_server: Observation<bool>,
}

/// Deterministic, read-only audit result for capability 44.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct DefenderRansomwareAudit {
    /// Retained fixed native evidence.
    pub observation: DefenderRansomwareObservation,
    /// Desired finite policy used for this evaluation.
    pub policy: DefenderRansomwarePolicy,
    /// Drift, incomplete evidence, and intentionally excluded validation lanes.
    pub findings: Vec<PolicyFinding>,
    /// Explicit gaps that prevent implementation or parity claims.
    pub exclusions: Vec<&'static str>,
}

/// Read-only proposed differences for a future, separately approved worker path.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct DefenderRansomwarePlan {
    /// Full audit evidence and evaluation.
    pub audit: DefenderRansomwareAudit,
    /// Fixed fields that differ from the policy; no mutation is performed.
    pub proposed_changes: Vec<DefenderRansomwareDrift>,
    /// Raw capability Apply remains unavailable.
    pub apply_available: bool,
}

/// One fixed desired field that differs from trustworthy observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct DefenderRansomwareDrift {
    /// Fixed provider property name, not caller input.
    pub field: &'static str,
    /// Desired value rendered as JSON for a future plan consumer.
    pub desired: serde_json::Value,
}

/// Evaluate fixed Defender evidence without Windows I/O or mutation.
#[must_use]
pub fn evaluate_defender_ransomware(
    observation: DefenderRansomwareObservation,
    policy: &DefenderRansomwarePolicy,
) -> DefenderRansomwareAudit {
    let mut findings = Vec::new();
    evaluate_setting(
        "DEF-CFA-NotDesired",
        "Controlled Folder Access",
        &observation.controlled_folder_access,
        policy.controlled_folder_access,
        &mut findings,
    );
    evaluate_setting(
        "DEF-NP-NotDesired",
        "Network Protection",
        &observation.network_protection,
        policy.network_protection,
        &mut findings,
    );
    evaluate_server(&observation, policy, &mut findings);
    findings.push(finding(
        "DEF-WMI-CoverageExcluded",
        FindingStatus::Warning,
        Severity::Low,
        "This read-only foundation observes fixed Defender WMI preference properties only; WMI/provider behavior, legacy-oracle parity, and Windows VM validation remain excluded.",
    ));
    DefenderRansomwareAudit {
        observation,
        policy: policy.clone(),
        findings,
        exclusions: exclusions(),
    }
}

/// Build a bounded read-only plan from the same pure evaluation.
#[must_use]
pub fn build_defender_ransomware_plan(
    observation: DefenderRansomwareObservation,
    policy: &DefenderRansomwarePolicy,
) -> DefenderRansomwarePlan {
    let audit = evaluate_defender_ransomware(observation, policy);
    let mut proposed_changes = Vec::new();
    if matches!(&audit.observation.controlled_folder_access, Observation::Present(value) if *value != policy.controlled_folder_access)
    {
        proposed_changes.push(drift(
            "EnableControlledFolderAccess",
            policy.controlled_folder_access,
        ));
    }
    if matches!(&audit.observation.network_protection, Observation::Present(value) if *value != policy.network_protection)
    {
        proposed_changes.push(drift("EnableNetworkProtection", policy.network_protection));
    }
    if matches!(&audit.observation.is_server, Observation::Present(true)) {
        if policy.apply_network_protection_server_prereqs {
            if matches!(
                &audit.observation.allow_network_protection_on_win_server,
                Observation::Present(false)
            ) {
                proposed_changes.push(drift("AllowNetworkProtectionOnWinServer", true));
            }
            if matches!(
                &audit.observation.allow_network_protection_down_level,
                Observation::Present(false)
            ) {
                proposed_changes.push(drift("AllowNetworkProtectionDownLevel", true));
            }
        }
        if policy.disable_datagram_processing_on_win_server
            && matches!(
                &audit.observation.allow_datagram_processing_on_win_server,
                Observation::Present(true)
            )
        {
            proposed_changes.push(drift("AllowDatagramProcessingOnWinServer", false));
        }
    }
    DefenderRansomwarePlan {
        audit,
        proposed_changes,
        apply_available: false,
    }
}

fn evaluate_setting<T: Copy + Eq + Serialize>(
    code: &'static str,
    label: &'static str,
    observed: &Observation<T>,
    desired: T,
    findings: &mut Vec<PolicyFinding>,
) {
    match observed {
        Observation::Present(value) if *value == desired => {}
        Observation::Present(value) => findings.push(PolicyFinding {
            code,
            status: FindingStatus::Warning,
            severity: Severity::Medium,
            message: format!("{label} does not match the bounded desired state."),
            evidence: JsonMap::from([
                ("observed".into(), json!(value)),
                ("desired".into(), json!(desired)),
            ]),
        }),
        value => incomplete(code, label, value, findings),
    }
}

fn evaluate_server(
    observation: &DefenderRansomwareObservation,
    policy: &DefenderRansomwarePolicy,
    findings: &mut Vec<PolicyFinding>,
) {
    let Observation::Present(is_server) = observation.is_server else {
        incomplete(
            "DEF-NP-ServerEvidence",
            "Windows Server applicability",
            &observation.is_server,
            findings,
        );
        return;
    };
    if !is_server {
        return;
    }
    if policy.apply_network_protection_server_prereqs {
        evaluate_server_bool(
            "DEF-NP-ServerPrereq-Missing",
            "AllowNetworkProtectionOnWinServer",
            &observation.allow_network_protection_on_win_server,
            true,
            findings,
        );
        evaluate_server_bool(
            "DEF-NP-DownLevelPrereq-Missing",
            "AllowNetworkProtectionDownLevel",
            &observation.allow_network_protection_down_level,
            true,
            findings,
        );
    }
    if policy.disable_datagram_processing_on_win_server {
        evaluate_server_bool(
            "DEF-NP-DatagramProcessing-NotRecommended",
            "AllowDatagramProcessingOnWinServer",
            &observation.allow_datagram_processing_on_win_server,
            false,
            findings,
        );
    }
}

fn evaluate_server_bool(
    code: &'static str,
    label: &'static str,
    observed: &Observation<bool>,
    desired: bool,
    findings: &mut Vec<PolicyFinding>,
) {
    evaluate_setting(code, label, observed, desired, findings);
}

fn incomplete<T>(
    code: &'static str,
    label: &'static str,
    observed: &Observation<T>,
    findings: &mut Vec<PolicyFinding>,
) {
    findings.push(finding(
        code,
        FindingStatus::Error,
        Severity::High,
        &format!(
            "{label} evidence is incomplete: {}.",
            observation_state(observed)
        ),
    ));
}

fn finding(
    code: &'static str,
    status: FindingStatus,
    severity: Severity,
    message: &str,
) -> PolicyFinding {
    PolicyFinding {
        code,
        status,
        severity,
        message: message.into(),
        evidence: JsonMap::from([("read_only".into(), json!(true))]),
    }
}

fn drift(field: &'static str, desired: impl Serialize) -> DefenderRansomwareDrift {
    DefenderRansomwareDrift {
        field,
        desired: serde_json::to_value(desired).expect("finite policy values serialize"),
    }
}

fn exclusions() -> Vec<&'static str> {
    vec![
        "Defender WMI/provider availability, authorization, and property semantics are not independently verified.",
        "Legacy PowerShell script parity and its remediation behavior are not claimed.",
        "Windows client and Server VM validation is not included.",
        "No external oracle, cloud protection telemetry, or blocked-event effectiveness evidence is collected.",
        "Apply and all state mutation are intentionally unavailable.",
    ]
}

fn observation_state<T>(value: &Observation<T>) -> &'static str {
    match value {
        Observation::Present(_) => "present",
        Observation::Missing => "missing",
        Observation::AccessDenied => "access denied",
        Observation::TimedOut => "timed out",
        Observation::Truncated => "truncated",
        Observation::Failed { .. } => "failed",
        Observation::NotRun => "not run",
        Observation::Unparsed => "unparsed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled() -> DefenderRansomwareObservation {
        DefenderRansomwareObservation {
            controlled_folder_access: Observation::Present(ControlledFolderAccessState::Enabled),
            network_protection: Observation::Present(NetworkProtectionState::Enabled),
            is_server: Observation::Present(false),
            allow_network_protection_on_win_server: Observation::NotRun,
            allow_network_protection_down_level: Observation::NotRun,
            allow_datagram_processing_on_win_server: Observation::NotRun,
        }
    }

    #[test]
    fn unknown_parameters_and_unknown_provider_values_are_rejected_or_incomplete() {
        assert!(
            serde_json::from_value::<DefenderRansomwarePolicy>(
                json!({"command":"Set-MpPreference"})
            )
            .is_err()
        );
        assert_eq!(ControlledFolderAccessState::from_wmi(99), None);
        let mut observation = enabled();
        observation.network_protection = Observation::Unparsed;
        let audit = evaluate_defender_ransomware(observation, &DefenderRansomwarePolicy::default());
        assert!(audit.findings.iter().any(|item| item.code == "DEF-NP-NotDesired" && item.status == FindingStatus::Error));
    }

    #[test]
    fn plan_only_proposes_trustworthy_fixed_drift() {
        let mut observation = enabled();
        observation.controlled_folder_access =
            Observation::Present(ControlledFolderAccessState::AuditMode);
        let plan =
            build_defender_ransomware_plan(observation, &DefenderRansomwarePolicy::default());
        assert_eq!(plan.proposed_changes.len(), 1);
        assert_eq!(
            plan.proposed_changes[0].field,
            "EnableControlledFolderAccess"
        );
        assert!(!plan.apply_available);
    }
}
