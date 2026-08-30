//! Fixed, read-only remote-access guardrail policy for capability 14.
//!
//! This foundation is narrower than the legacy script. It evaluates a fixed
//! local RDP and Remote Assistance registry subset and retains local RDP
//! service/listener indicators. It does not accept remote targets, RDP ports,
//! firewall rules, group or user identities, registry paths, or commands.
//! Local indicators do not prove remote reachability.

use crate::{Observation, PolicyFinding, RemoteSurfaceObservation};
use baselineops_domain::{FindingStatus, JsonMap, Severity};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Fixed RDP access state represented by `fDenyTSConnections`.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RdpAccess {
    /// Deny new Remote Desktop connections.
    #[default]
    Disabled,
    /// Permit Remote Desktop connections subject to separate local policy.
    Enabled,
}

impl RdpAccess {
    const fn enabled(self) -> bool {
        matches!(self, Self::Enabled)
    }
}
/// Finite enabled or disabled state for a fixed guardrail.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardrailSwitch {
    /// Disable the fixed guardrail.
    Disabled,
    /// Enable the fixed guardrail.
    #[default]
    Enabled,
}

impl GuardrailSwitch {
    const fn dword(self) -> u32 {
        match self {
            Self::Disabled => 0,
            Self::Enabled => 1,
        }
    }
}
/// Finite RDP security-layer values supported by Windows.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RdpSecurityLayer {
    /// Native RDP security layer.
    Rdp,
    /// Negotiate the security layer.
    Negotiate,
    /// Require TLS transport security.
    #[default]
    Tls,
}

impl RdpSecurityLayer {
    const fn dword(self) -> u32 {
        match self {
            Self::Rdp => 0,
            Self::Negotiate => 1,
            Self::Tls => 2,
        }
    }
}

/// Finite RDP minimum-encryption values supported by Windows.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RdpMinimumEncryption {
    /// Client-compatible encryption.
    ClientCompatible,
    /// High encryption.
    #[default]
    High,
    /// FIPS encryption.
    Fips,
}

impl RdpMinimumEncryption {
    const fn dword(self) -> u32 {
        match self {
            Self::ClientCompatible => 2,
            Self::High => 3,
            Self::Fips => 4,
        }
    }
}

/// Fixed Remote Assistance ticket lifetimes accepted by this foundation.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteAssistanceTicketLifetime {
    /// Limit Remote Assistance tickets to sixty minutes.
    #[default]
    OneHour,
    /// Limit Remote Assistance tickets to one hundred and twenty minutes.
    TwoHours,
}

impl RemoteAssistanceTicketLifetime {
    const fn minutes(self) -> u32 {
        match self {
            Self::OneHour => 60,
            Self::TwoHours => 120,
        }
    }
}

/// Strict finite desired state for capability 14.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "snake_case")]
pub struct RemoteGuardrailsPolicy {
    /// Whether this host accepts RDP connections.
    pub rdp_access: RdpAccess,
    /// Whether RDP Network Level Authentication is required.
    pub require_network_level_authentication: GuardrailSwitch,
    /// Fixed RDP security layer.
    pub security_layer: RdpSecurityLayer,
    /// Fixed RDP minimum encryption setting.
    pub minimum_encryption: RdpMinimumEncryption,
    /// Whether Restricted Admin mode is enabled server-side.
    pub restricted_admin: GuardrailSwitch,
    /// Whether the Terminal Services policy disables RDP password saving.
    pub disable_password_saving: GuardrailSwitch,
    /// Whether solicited Remote Assistance is allowed.
    pub allow_solicited_remote_assistance: GuardrailSwitch,
    /// Whether unsolicited Remote Assistance is allowed.
    pub allow_unsolicited_remote_assistance: GuardrailSwitch,
    /// Fixed maximum lifetime for Remote Assistance tickets.
    pub remote_assistance_ticket_lifetime: RemoteAssistanceTicketLifetime,
}

impl Default for RemoteGuardrailsPolicy {
    fn default() -> Self {
        Self {
            rdp_access: RdpAccess::Disabled,
            require_network_level_authentication: GuardrailSwitch::Enabled,
            security_layer: RdpSecurityLayer::Tls,
            minimum_encryption: RdpMinimumEncryption::High,
            restricted_admin: GuardrailSwitch::Enabled,
            disable_password_saving: GuardrailSwitch::Enabled,
            allow_solicited_remote_assistance: GuardrailSwitch::Disabled,
            allow_unsolicited_remote_assistance: GuardrailSwitch::Disabled,
            remote_assistance_ticket_lifetime: RemoteAssistanceTicketLifetime::OneHour,
        }
    }
}

/// Fixed local registry field evaluated by this foundation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteGuardrailField {
    /// `fDenyTSConnections`, expressed as RDP access enabled/disabled.
    RdpAccess,
    /// `UserAuthentication` in `RDP-Tcp`.
    NetworkLevelAuthentication,
    /// `SecurityLayer` in `RDP-Tcp`.
    SecurityLayer,
    /// `MinEncryptionLevel` in `RDP-Tcp`.
    MinimumEncryption,
    /// `DisableRestrictedAdmin` in the LSA key.
    RestrictedAdmin,
    /// `DisablePasswordSaving` in Terminal Services policy.
    DisablePasswordSaving,
    /// `fAllowToGetHelp` in Terminal Services policy.
    SolicitedRemoteAssistance,
    /// `fAllowUnsolicited` in Terminal Services policy.
    UnsolicitedRemoteAssistance,
    /// `MaxTicketExpiry` in Terminal Services policy.
    RemoteAssistanceTicketLifetime,
}

/// Typed fixed registry evidence and local RDP indicators.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RemoteGuardrailsObservation {
    /// Local RDP service and listener indicators. They are not reachability proof.
    pub remote_surface: RemoteSurfaceObservation,
    /// `UserAuthentication` from the fixed RDP-Tcp key.
    pub network_level_authentication: Observation<u32>,
    /// `SecurityLayer` from the fixed RDP-Tcp key.
    pub security_layer: Observation<u32>,
    /// `MinEncryptionLevel` from the fixed RDP-Tcp key.
    pub minimum_encryption: Observation<u32>,
    /// `DisableRestrictedAdmin` from the fixed LSA key.
    pub disable_restricted_admin: Observation<u32>,
    /// `DisablePasswordSaving` from fixed Terminal Services policy.
    pub disable_password_saving: Observation<u32>,
    /// `fAllowToGetHelp` from fixed Terminal Services policy.
    pub allow_solicited_remote_assistance: Observation<u32>,
    /// `fAllowUnsolicited` from fixed Terminal Services policy.
    pub allow_unsolicited_remote_assistance: Observation<u32>,
    /// `MaxTicketExpiry` from fixed Terminal Services policy.
    pub remote_assistance_ticket_lifetime: Observation<u32>,
}

impl RemoteGuardrailsObservation {
    /// Returns whether every field needed for a fixed registry plan is present.
    ///
    /// Service and listener indicators are intentionally not plan prerequisites:
    /// no proposed change starts, stops, or otherwise controls a service, and no
    /// local observation can prove remote reachability.
    #[must_use]
    pub const fn registry_plan_evidence_is_complete(&self) -> bool {
        matches!(self.remote_surface.rdp_enabled, Observation::Present(_))
            && matches!(self.network_level_authentication, Observation::Present(_))
            && matches!(self.security_layer, Observation::Present(_))
            && matches!(self.minimum_encryption, Observation::Present(_))
            && matches!(self.disable_restricted_admin, Observation::Present(_))
            && matches!(self.disable_password_saving, Observation::Present(_))
            && matches!(
                self.allow_solicited_remote_assistance,
                Observation::Present(_)
            )
            && matches!(
                self.allow_unsolicited_remote_assistance,
                Observation::Present(_)
            )
            && matches!(
                self.remote_assistance_ticket_lifetime,
                Observation::Present(_)
            )
    }
}

/// One fixed desired field that differs from retained observation evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RemoteGuardrailDrift {
    /// Fixed field whose present or incomplete evidence prevents compliance.
    pub field: RemoteGuardrailField,
    /// Fixed desired DWORD value, or one for enabled RDP access.
    pub desired: u32,
}

/// Deterministic read-only assessment for capability 14.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RemoteGuardrailsAudit {
    /// Complete native evidence, including incomplete states.
    pub observation: RemoteGuardrailsObservation,
    /// Parsed finite desired state.
    pub desired: RemoteGuardrailsPolicy,
    /// Read-only findings for local indicators and fixed registry values.
    pub findings: Vec<PolicyFinding>,
    /// Fixed differences and incomplete evidence retained for any future plan.
    pub drift: Vec<RemoteGuardrailDrift>,
    /// Reasons a non-mutating proposal is unavailable.
    pub plan_blockers: Vec<&'static str>,
}

/// Non-mutating proposal for a separately approved future worker route.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RemoteGuardrailsPlan {
    /// Exact audit used to derive the proposal.
    pub audit: RemoteGuardrailsAudit,
    /// Fixed registry differences only; this object has no executable action.
    pub proposed_changes: Vec<RemoteGuardrailDrift>,
    /// Any future writer would require an Administrator token.
    pub requires_administrator: bool,
    /// Raw capability Apply is deliberately unavailable.
    pub apply_available: bool,
    /// Out-of-scope legacy authority and unverified parity gaps.
    pub exclusions: Vec<&'static str>,
}

/// Evaluate local evidence against the finite desired state without Windows I/O.
#[must_use]
pub fn evaluate_remote_guardrails(
    observation: RemoteGuardrailsObservation,
    policy: &RemoteGuardrailsPolicy,
) -> RemoteGuardrailsAudit {
    let mut findings = vec![finding(
        "REMOTE-GUARDRAILS-LocalEvidenceOnly",
        FindingStatus::Info,
        Severity::Info,
        "RDP service and listener observations are local indicators only; this audit does not test or claim remote reachability.",
    )];
    let mut drift = Vec::new();
    assess_bool(
        RemoteGuardrailField::RdpAccess,
        "RDP access",
        &observation.remote_surface.rdp_enabled,
        policy.rdp_access.enabled(),
        &mut findings,
        &mut drift,
    );
    assess_dword(
        RemoteGuardrailField::NetworkLevelAuthentication,
        "RDP Network Level Authentication",
        &observation.network_level_authentication,
        policy.require_network_level_authentication.dword(),
        &mut findings,
        &mut drift,
    );
    assess_dword(
        RemoteGuardrailField::SecurityLayer,
        "RDP security layer",
        &observation.security_layer,
        policy.security_layer.dword(),
        &mut findings,
        &mut drift,
    );
    assess_dword(
        RemoteGuardrailField::MinimumEncryption,
        "RDP minimum encryption",
        &observation.minimum_encryption,
        policy.minimum_encryption.dword(),
        &mut findings,
        &mut drift,
    );
    assess_dword(
        RemoteGuardrailField::RestrictedAdmin,
        "RDP Restricted Admin",
        &observation.disable_restricted_admin,
        1 - policy.restricted_admin.dword(),
        &mut findings,
        &mut drift,
    );
    assess_dword(
        RemoteGuardrailField::DisablePasswordSaving,
        "RDP password-saving policy",
        &observation.disable_password_saving,
        policy.disable_password_saving.dword(),
        &mut findings,
        &mut drift,
    );
    assess_dword(
        RemoteGuardrailField::SolicitedRemoteAssistance,
        "solicited Remote Assistance",
        &observation.allow_solicited_remote_assistance,
        policy.allow_solicited_remote_assistance.dword(),
        &mut findings,
        &mut drift,
    );
    assess_dword(
        RemoteGuardrailField::UnsolicitedRemoteAssistance,
        "unsolicited Remote Assistance",
        &observation.allow_unsolicited_remote_assistance,
        policy.allow_unsolicited_remote_assistance.dword(),
        &mut findings,
        &mut drift,
    );
    assess_dword(
        RemoteGuardrailField::RemoteAssistanceTicketLifetime,
        "Remote Assistance ticket lifetime",
        &observation.remote_assistance_ticket_lifetime,
        policy.remote_assistance_ticket_lifetime.minutes(),
        &mut findings,
        &mut drift,
    );
    let plan_blockers = (!observation.registry_plan_evidence_is_complete())
        .then_some("fixed RDP or Remote Assistance registry evidence is incomplete")
        .into_iter()
        .collect();
    RemoteGuardrailsAudit {
        observation,
        desired: policy.clone(),
        findings,
        drift,
        plan_blockers,
    }
}

/// Build a non-mutating proposal only when all proposed registry changes have evidence.
///
/// # Errors
///
/// Returns an error when any required fixed registry value is missing, denied,
/// or unparsed. The caller must not turn incomplete evidence into a plan.
pub fn build_remote_guardrails_plan(
    observation: RemoteGuardrailsObservation,
    policy: &RemoteGuardrailsPolicy,
) -> Result<RemoteGuardrailsPlan, String> {
    let audit = evaluate_remote_guardrails(observation, policy);
    if !audit.plan_blockers.is_empty() {
        return Err(format!(
            "remote guardrails plan is unavailable: {}",
            audit.plan_blockers.join("; ")
        ));
    }
    Ok(RemoteGuardrailsPlan {
        proposed_changes: audit.drift.clone(),
        audit,
        requires_administrator: true,
        apply_available: false,
        exclusions: vec![
            "all RDP and Remote Assistance registry mutation, rollback, and service control",
            "firewall rule, profile, policy-store, port, and remote-address evaluation or mutation",
            "Remote Desktop Users group and arbitrary user or group membership",
            "remote hosts, remote reachability probes, shell commands, and PowerShell",
            "legacy-script semantic-oracle and Windows VM parity validation",
        ],
    })
}

fn assess_bool(
    field: RemoteGuardrailField,
    label: &'static str,
    observed: &Observation<bool>,
    desired: bool,
    findings: &mut Vec<PolicyFinding>,
    drift: &mut Vec<RemoteGuardrailDrift>,
) {
    match observed {
        Observation::Present(actual) if *actual == desired => findings.push(finding(
            "REMOTE-GUARDRAILS-Compliant",
            FindingStatus::Pass,
            Severity::Low,
            format!("{label} matches the fixed desired state."),
        )),
        Observation::Present(actual) => {
            findings.push(drift_finding(label, json!(actual), desired.into()));
            drift.push(RemoteGuardrailDrift {
                field,
                desired: desired.into(),
            });
        }
        state => {
            findings.push(incomplete_finding(label, state));
            drift.push(RemoteGuardrailDrift {
                field,
                desired: desired.into(),
            });
        }
    }
}

fn assess_dword(
    field: RemoteGuardrailField,
    label: &'static str,
    observed: &Observation<u32>,
    desired: u32,
    findings: &mut Vec<PolicyFinding>,
    drift: &mut Vec<RemoteGuardrailDrift>,
) {
    match observed {
        Observation::Present(actual) if *actual == desired => findings.push(finding(
            "REMOTE-GUARDRAILS-Compliant",
            FindingStatus::Pass,
            Severity::Low,
            format!("{label} matches the fixed desired DWORD."),
        )),
        Observation::Present(actual) => {
            findings.push(drift_finding(label, json!(actual), desired));
            drift.push(RemoteGuardrailDrift { field, desired });
        }
        state => {
            findings.push(incomplete_finding(label, state));
            drift.push(RemoteGuardrailDrift { field, desired });
        }
    }
}

fn drift_finding(label: &'static str, observed: serde_json::Value, desired: u32) -> PolicyFinding {
    PolicyFinding {
        code: "REMOTE-GUARDRAILS-Drift",
        status: FindingStatus::Fail,
        severity: Severity::High,
        message: format!("{label} differs from its fixed desired value."),
        evidence: JsonMap::from([
            ("observed".into(), observed),
            ("desired".into(), json!(desired)),
        ]),
    }
}

fn incomplete_finding<T>(label: &'static str, observed: &Observation<T>) -> PolicyFinding {
    finding(
        "REMOTE-GUARDRAILS-IncompleteEvidence",
        FindingStatus::Error,
        Severity::High,
        format!(
            "{label} evidence is incomplete: {}.",
            observation_state(observed)
        ),
    )
}

fn finding(
    code: &'static str,
    status: FindingStatus,
    severity: Severity,
    message: impl Into<String>,
) -> PolicyFinding {
    PolicyFinding {
        code,
        status,
        severity,
        message: message.into(),
        evidence: JsonMap::from([("read_only".into(), json!(true))]),
    }
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
    use crate::{ServiceObservation, ServiceStartMode, ServiceState, TcpListenerObservation};

    fn service() -> Observation<ServiceObservation> {
        Observation::Present(ServiceObservation {
            name: "TermService".into(),
            state: ServiceState::Running,
            start_mode: ServiceStartMode::Automatic,
        })
    }

    fn complete_observation() -> RemoteGuardrailsObservation {
        RemoteGuardrailsObservation {
            remote_surface: RemoteSurfaceObservation {
                winrm_service: service(),
                winrm_listener_configured: Observation::Present(false),
                sshd_service: Observation::Missing,
                rdp_enabled: Observation::Present(false),
                rdp_service: service(),
                smb_server_service: service(),
                tcp_listeners: Observation::Present(vec![TcpListenerObservation {
                    port: 3389,
                    endpoint_count: 1,
                }]),
            },
            network_level_authentication: Observation::Present(1),
            security_layer: Observation::Present(2),
            minimum_encryption: Observation::Present(3),
            disable_restricted_admin: Observation::Present(0),
            disable_password_saving: Observation::Present(1),
            allow_solicited_remote_assistance: Observation::Present(0),
            allow_unsolicited_remote_assistance: Observation::Present(0),
            remote_assistance_ticket_lifetime: Observation::Present(60),
        }
    }

    #[test]
    fn policy_rejects_dynamic_legacy_authority() {
        for value in [
            serde_json::json!({"rdp_port": 3389}),
            serde_json::json!({"firewall_rule": "Remote Desktop"}),
            serde_json::json!({"allowed_groups": ["DOMAIN\\RDP-Admins"]}),
            serde_json::json!({"remote_host": "host.example"}),
            serde_json::json!({"command": "netsh"}),
            serde_json::json!({"disable_password_saving": true}),
        ] {
            assert!(serde_json::from_value::<RemoteGuardrailsPolicy>(value).is_err());
        }
    }

    #[test]
    fn complete_fixed_evidence_produces_read_only_plan() {
        let plan = build_remote_guardrails_plan(
            complete_observation(),
            &RemoteGuardrailsPolicy::default(),
        )
        .expect("complete fixed evidence");
        assert!(!plan.apply_available);
        assert!(plan.proposed_changes.is_empty());
        assert!(plan.audit.findings.iter().any(|item| {
            item.message
                .contains("does not test or claim remote reachability")
        }));
    }

    #[test]
    fn denied_or_unparsed_evidence_cannot_produce_plan() {
        let mut observation = complete_observation();
        observation.network_level_authentication = Observation::AccessDenied;
        observation.minimum_encryption = Observation::Unparsed;
        let audit =
            evaluate_remote_guardrails(observation.clone(), &RemoteGuardrailsPolicy::default());
        assert!(
            audit
                .findings
                .iter()
                .any(|item| item.code == "REMOTE-GUARDRAILS-IncompleteEvidence")
        );
        assert!(
            build_remote_guardrails_plan(observation, &RemoteGuardrailsPolicy::default()).is_err()
        );
    }
}
