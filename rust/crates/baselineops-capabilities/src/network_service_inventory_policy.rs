//! Pure, read-only policy evaluation for network and service/process inventory.
//!
//! Acquisition belongs to the Windows crate.  Incomplete records stay typed so
//! an access denial cannot be misreported as a healthy interface or inventory.

use crate::{Observation, PolicyFinding};
use baselineops_domain::{FindingStatus, JsonMap, Severity};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Maximum records retained by a native inventory collector.
pub const MAX_INVENTORY_RECORDS: usize = 4_096;

/// Strict parameter object for the two parameterless read-only capabilities.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EmptyAuditParameters {}

/// A source-independent network interface observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct NetworkInterfaceObservation {
    /// Windows interface index.
    pub interface_index: u32,
    /// Friendly interface name, when supplied by the system.
    pub interface_alias: String,
    /// IPv4 addresses assigned to the interface.
    pub ipv4_addresses: Vec<String>,
    /// IPv6 addresses assigned to the interface.
    pub ipv6_addresses: Vec<String>,
    /// IPv4 default-gateway addresses.
    pub ipv4_gateways: Vec<String>,
    /// IPv6 default-gateway addresses.
    pub ipv6_gateways: Vec<String>,
    /// Configured DNS server addresses.
    pub dns_servers: Vec<String>,
}

/// Bounded native network inventory before policy evaluation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct NetworkInventoryObservation {
    /// Each retained record, including typed access failures.
    pub interfaces: Vec<Observation<NetworkInterfaceObservation>>,
    /// Whether enumeration completed before its explicit bound.
    pub enumeration_complete: bool,
}

/// Deterministic network audit output.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct NetworkInventoryAudit {
    /// Original bounded observations.
    pub observation: NetworkInventoryObservation,
    /// Legacy-compatible deterministic findings.
    pub findings: Vec<PolicyFinding>,
}

/// A process record retained by the native `ToolHelp`/process-query collector.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ProcessInventoryRecord {
    /// Process identifier.
    pub process_id: u32,
    /// `ToolHelp` executable name.
    pub name: String,
    /// Cumulative CPU time in 100-nanosecond units when accessible.
    pub cpu_time_100ns: Observation<u64>,
    /// Current working set in bytes when accessible.
    pub working_set_bytes: Observation<u64>,
    /// Full executable path when the process permits a query.
    pub image_path: Observation<String>,
}

/// Service details retained after an SCM query.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ServiceInventoryRecord {
    /// Service key name.
    pub name: String,
    /// Display name from SCM enumeration.
    pub display_name: String,
    /// SCM state code, retained without interpretation.
    pub state: u32,
    /// Service process identifier when running.
    pub process_id: u32,
    /// SCM start-type code when configuration was readable.
    pub start_mode: Observation<u32>,
    /// SCM binary path when configuration was readable.
    pub image_path: Observation<String>,
    /// SCM account name when configuration was readable.
    pub start_name: Observation<String>,
}

/// Bounded native service/process inventory before policy evaluation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ServiceProcessInventoryObservation {
    /// ToolHelp/process-query records.
    pub processes: Vec<ProcessInventoryRecord>,
    /// Each SCM record, including typed per-service access denials.
    pub services: Vec<Observation<ServiceInventoryRecord>>,
    /// Whether process enumeration completed before the explicit bound.
    pub process_enumeration_complete: bool,
    /// Whether SCM enumeration completed before the explicit bound.
    pub service_enumeration_complete: bool,
}

/// Deterministic service/process inventory output.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ServiceProcessInventoryAudit {
    /// Original bounded observations.
    pub observation: ServiceProcessInventoryObservation,
    /// Counts derived only from retained records.
    pub process_count: usize,
    /// Count of enumerated service records.
    pub service_count: usize,
    /// Count of retained services in the SCM running state.
    pub running_services: usize,
    /// Findings for incomplete record evidence only.
    pub findings: Vec<PolicyFinding>,
}

/// Evaluate legacy `NET-InterfaceIssue` semantics without platform I/O.
#[must_use]
pub fn evaluate_network_inventory(
    observation: NetworkInventoryObservation,
) -> NetworkInventoryAudit {
    let mut findings = Vec::new();
    for interface in observation.interfaces.iter().take(MAX_INVENTORY_RECORDS) {
        match interface {
            Observation::Present(interface) => evaluate_interface(interface, &mut findings),
            other => incomplete(
                &mut findings,
                "NET-InterfaceIncomplete",
                other,
                "network interface",
            ),
        }
    }
    if !observation.enumeration_complete || observation.interfaces.len() > MAX_INVENTORY_RECORDS {
        findings.push(finding(
            "NET-InventoryIncomplete",
            Severity::Medium,
            "Network interface enumeration did not complete within its bounded record limit.",
            JsonMap::new(),
        ));
    }
    NetworkInventoryAudit {
        observation,
        findings,
    }
}

/// Evaluate service and process inventory completeness without platform I/O.
#[must_use]
pub fn evaluate_service_process_inventory(
    observation: ServiceProcessInventoryObservation,
) -> ServiceProcessInventoryAudit {
    let mut findings = Vec::new();
    evaluate_process_findings(&observation.processes, &mut findings);
    evaluate_service_findings(&observation.services, &mut findings);
    if service_process_enumeration_incomplete(&observation) {
        findings.push(finding(
            "INV-EnumerationIncomplete",
            Severity::Medium,
            "Process or service enumeration did not complete within its bounded record limit.",
            JsonMap::new(),
        ));
    }
    let service_count = observation.services.len().min(MAX_INVENTORY_RECORDS);
    let running_services = observation
        .services
        .iter()
        .take(MAX_INVENTORY_RECORDS)
        .filter(|service| matches!(service, Observation::Present(service) if service.state == 4))
        .count();
    ServiceProcessInventoryAudit {
        process_count: observation.processes.len().min(MAX_INVENTORY_RECORDS),
        service_count,
        running_services,
        observation,
        findings,
    }
}

fn service_process_enumeration_incomplete(
    observation: &ServiceProcessInventoryObservation,
) -> bool {
    let enumeration_incomplete =
        !observation.process_enumeration_complete || !observation.service_enumeration_complete;
    let record_limit_exceeded = observation.processes.len() > MAX_INVENTORY_RECORDS
        || observation.services.len() > MAX_INVENTORY_RECORDS;
    enumeration_incomplete || record_limit_exceeded
}

fn evaluate_process_findings(
    processes: &[ProcessInventoryRecord],
    findings: &mut Vec<PolicyFinding>,
) {
    for process in processes.iter().take(MAX_INVENTORY_RECORDS) {
        incomplete(
            findings,
            "INV-ProcessImageIncomplete",
            &process.image_path,
            "process image",
        );
        incomplete(
            findings,
            "INV-ProcessCpuIncomplete",
            &process.cpu_time_100ns,
            "process CPU",
        );
        incomplete(
            findings,
            "INV-ProcessMemoryIncomplete",
            &process.working_set_bytes,
            "process memory",
        );
    }
}

fn evaluate_service_findings(
    services: &[Observation<ServiceInventoryRecord>],
    findings: &mut Vec<PolicyFinding>,
) {
    for service in services.iter().take(MAX_INVENTORY_RECORDS) {
        match service {
            Observation::Present(service) => {
                incomplete(
                    findings,
                    "INV-ServiceConfigIncomplete",
                    &service.start_mode,
                    "service configuration",
                );
                incomplete(
                    findings,
                    "INV-ServiceImageIncomplete",
                    &service.image_path,
                    "service image",
                );
                incomplete(
                    findings,
                    "INV-ServiceAccountIncomplete",
                    &service.start_name,
                    "service account",
                );
            }
            other => incomplete(findings, "INV-ServiceIncomplete", other, "service"),
        }
    }
}

fn evaluate_interface(interface: &NetworkInterfaceObservation, findings: &mut Vec<PolicyFinding>) {
    let missing_dns = interface.dns_servers.is_empty();
    let missing_gateway = interface.ipv4_gateways.is_empty() && interface.ipv6_gateways.is_empty();
    if !missing_dns && !missing_gateway {
        return;
    }
    let issue = match (missing_dns, missing_gateway) {
        (true, true) => "missing DNS and missing gateway",
        (true, false) => "missing DNS",
        (false, true) => "missing gateway",
        (false, false) => unreachable!("non-issue returned before formatting"),
    };
    findings.push(finding(
        "NET-InterfaceIssue",
        Severity::Medium,
        format!("Interface '{}' has {issue}", interface.interface_alias),
        JsonMap::from([
            ("interface_alias".into(), json!(interface.interface_alias)),
            ("interface_index".into(), json!(interface.interface_index)),
            ("ipv4_addresses".into(), json!(interface.ipv4_addresses)),
            ("dns_servers".into(), json!(interface.dns_servers)),
        ]),
    ));
}

fn incomplete<T>(
    findings: &mut Vec<PolicyFinding>,
    code: &'static str,
    value: &Observation<T>,
    label: &str,
) {
    if matches!(value, Observation::Present(_)) {
        return;
    }
    findings.push(finding(
        code,
        Severity::Medium,
        format!(
            "{label} observation is incomplete: {}.",
            observation_status(value)
        ),
        JsonMap::from([(
            "observation_status".into(),
            json!(observation_status(value)),
        )]),
    ));
}

fn observation_status<T>(value: &Observation<T>) -> &'static str {
    match value {
        Observation::Present(_) => "present",
        Observation::Missing => "missing",
        Observation::AccessDenied => "access_denied",
        Observation::TimedOut => "timed_out",
        Observation::Truncated => "truncated",
        Observation::Failed { .. } => "failed",
        Observation::NotRun => "not_run",
        Observation::Unparsed => "unparsed",
    }
}

fn finding(
    code: &'static str,
    severity: Severity,
    message: impl Into<String>,
    evidence: JsonMap,
) -> PolicyFinding {
    PolicyFinding {
        code,
        status: FindingStatus::Warning,
        severity,
        message: message.into(),
        evidence,
    }
}

#[cfg(test)]
#[path = "network_service_inventory_policy_tests.rs"]
mod tests;
