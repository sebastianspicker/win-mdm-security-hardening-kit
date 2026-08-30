//! Pure, read-only evaluation for remote administration surface indicators.
//!
//! A local listener is evidence that a port is bound on this host, not proof
//! that a remote peer can reach it through every firewall or network path.

use crate::{Observation, PolicyFinding, ServiceObservation};
use baselineops_domain::{FindingStatus, JsonMap, Severity};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Strict parameter object for capability 37. No caller-selected target exists.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RemoteSurfacePolicy {}

/// A fixed local TCP port and the count of bound endpoints observed for it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TcpListenerObservation {
    /// Fixed local TCP port associated with one remote surface.
    pub port: u16,
    /// Number of local endpoints bound to this port, capped by acquisition.
    pub endpoint_count: u16,
}

/// Native evidence for `WinRM`, `OpenSSH`, `RDP`, and `SMB`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RemoteSurfaceObservation {
    /// `WinRM` service state; it does not establish remote reachability.
    pub winrm_service: Observation<ServiceObservation>,
    /// Fixed `WSMan` listener configuration key presence.
    pub winrm_listener_configured: Observation<bool>,
    /// OpenSSH server service state; it does not establish remote reachability.
    pub sshd_service: Observation<ServiceObservation>,
    /// RDP enablement from `fDenyTSConnections`.
    pub rdp_enabled: Observation<bool>,
    /// Remote Desktop Services state; it does not establish remote reachability.
    pub rdp_service: Observation<ServiceObservation>,
    /// SMB server service state; it does not establish remote reachability.
    pub smb_server_service: Observation<ServiceObservation>,
    /// Bound endpoints for ports 5985, 5986, 22, 3389, and 445.
    pub tcp_listeners: Observation<Vec<TcpListenerObservation>>,
}

/// Deterministic capability 37 output.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RemoteSurfaceAudit {
    /// Native input evidence.
    pub observation: RemoteSurfaceObservation,
    /// Surface configuration, listener, and incomplete-evidence findings.
    pub findings: Vec<PolicyFinding>,
}

/// Evaluate remote-surface indicators without Windows I/O.
#[must_use]
pub fn evaluate_remote_surface(
    observation: RemoteSurfaceObservation,
    _policy: &RemoteSurfacePolicy,
) -> RemoteSurfaceAudit {
    let mut findings = Vec::new();
    evaluate_winrm(&observation, &mut findings);
    evaluate_service(
        "REMOTE-OpenSsh",
        "OpenSSH",
        &observation.sshd_service,
        &mut findings,
    );
    evaluate_rdp(&observation.rdp_enabled, &mut findings);
    evaluate_service(
        "REMOTE-RdpService",
        "Remote Desktop Services",
        &observation.rdp_service,
        &mut findings,
    );
    evaluate_service(
        "REMOTE-SmbServer",
        "SMB server",
        &observation.smb_server_service,
        &mut findings,
    );
    evaluate_listeners(&observation.tcp_listeners, &mut findings);
    RemoteSurfaceAudit {
        observation,
        findings,
    }
}

fn evaluate_winrm(observation: &RemoteSurfaceObservation, findings: &mut Vec<PolicyFinding>) {
    match observation.winrm_listener_configured {
        Observation::Present(true) => findings.push(finding(
            "REMOTE-WinRmListenerConfigured",
            FindingStatus::Warning,
            Severity::Medium,
            "WinRM listener configuration is present; inspect listener bindings and authentication.",
        )),
        Observation::Present(false) => {}
        ref value => incomplete("REMOTE-WinRmListenerIncomplete", value, findings),
    }
    evaluate_service(
        "REMOTE-WinRm",
        "WinRM",
        &observation.winrm_service,
        findings,
    );
}

fn evaluate_rdp(value: &Observation<bool>, findings: &mut Vec<PolicyFinding>) {
    match value {
        Observation::Present(true) => findings.push(finding(
            "REMOTE-RdpEnabled",
            FindingStatus::Warning,
            Severity::Medium,
            "RDP is enabled by fDenyTSConnections=0; local listener evidence is reported separately.",
        )),
        Observation::Present(false) => {}
        value => incomplete("REMOTE-RdpEnablementIncomplete", value, findings),
    }
}

fn evaluate_service(
    code_prefix: &'static str,
    label: &'static str,
    value: &Observation<ServiceObservation>,
    findings: &mut Vec<PolicyFinding>,
) {
    match value {
        Observation::Present(service) => findings.push(finding(
            code_prefix,
            FindingStatus::Info,
            Severity::Info,
            format!(
                "{label} service is {:?}; service state alone does not prove remote reachability.",
                service.state
            ),
        )),
        Observation::Missing => {}
        value => incomplete(concat_code(code_prefix, "Incomplete"), value, findings),
    }
}

fn evaluate_listeners(
    value: &Observation<Vec<TcpListenerObservation>>,
    findings: &mut Vec<PolicyFinding>,
) {
    match value {
        Observation::Present(listeners) => {
            for listener in listeners {
                if listener.endpoint_count > 0 {
                    findings.push(finding(
                        "REMOTE-LocalTcpListener",
                        FindingStatus::Warning,
                        Severity::Medium,
                        format!(
                            "{} local TCP endpoint(s) listen on port {}; this is not proof of remote reachability.",
                            listener.endpoint_count, listener.port
                        ),
                    ));
                }
            }
        }
        value => incomplete("REMOTE-LocalListenerEvidenceIncomplete", value, findings),
    }
}

fn concat_code(prefix: &'static str, suffix: &'static str) -> &'static str {
    match (prefix, suffix) {
        ("REMOTE-WinRm", "Incomplete") => "REMOTE-WinRmIncomplete",
        ("REMOTE-OpenSsh", "Incomplete") => "REMOTE-OpenSshIncomplete",
        ("REMOTE-SmbServer", "Incomplete") => "REMOTE-SmbServerIncomplete",
        _ => "REMOTE-EvidenceIncomplete",
    }
}

fn incomplete<T>(code: &'static str, value: &Observation<T>, findings: &mut Vec<PolicyFinding>) {
    findings.push(finding(
        code,
        FindingStatus::Warning,
        Severity::Medium,
        format!(
            "Required remote-surface evidence is incomplete: {}.",
            observation_state(value)
        ),
    ));
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
    use crate::{ServiceStartMode, ServiceState};

    fn service() -> Observation<ServiceObservation> {
        Observation::Present(ServiceObservation {
            name: "fixture".into(),
            state: ServiceState::Running,
            start_mode: ServiceStartMode::Automatic,
        })
    }

    #[test]
    fn listener_evidence_does_not_claim_remote_reachability() {
        let audit = evaluate_remote_surface(
            RemoteSurfaceObservation {
                winrm_service: service(),
                winrm_listener_configured: Observation::Present(false),
                sshd_service: service(),
                rdp_enabled: Observation::Present(false),
                rdp_service: service(),
                smb_server_service: service(),
                tcp_listeners: Observation::Present(vec![TcpListenerObservation {
                    port: 22,
                    endpoint_count: 1,
                }]),
            },
            &RemoteSurfacePolicy::default(),
        );
        assert!(
            audit
                .findings
                .iter()
                .any(|item| item.message.contains("not proof"))
        );
    }

    #[test]
    fn access_denied_is_never_healthy() {
        let audit = evaluate_remote_surface(
            RemoteSurfaceObservation {
                winrm_service: Observation::AccessDenied,
                winrm_listener_configured: Observation::AccessDenied,
                sshd_service: Observation::AccessDenied,
                rdp_enabled: Observation::AccessDenied,
                rdp_service: Observation::AccessDenied,
                smb_server_service: Observation::AccessDenied,
                tcp_listeners: Observation::AccessDenied,
            },
            &RemoteSurfacePolicy::default(),
        );
        assert_eq!(audit.findings.len(), 7);
    }
}
