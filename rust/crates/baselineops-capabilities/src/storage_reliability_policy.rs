//! Pure, read-only policy evaluation for physical-disk reliability.

use crate::{Observation, PolicyFinding};
use baselineops_domain::{FindingStatus, JsonMap, Severity};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Strict bounded thresholds for legacy capability 35.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, rename_all = "snake_case", deny_unknown_fields)]
pub struct StorageReliabilityPolicy {
    /// Warning threshold for reported disk temperature in Celsius.
    pub temperature_warning_c: u16,
    /// Critical threshold for reported disk temperature in Celsius.
    pub temperature_critical_c: u16,
    /// Warning threshold for percent wear remaining.
    pub wear_warning_percent_remaining: u8,
    /// First uncorrectable-error count that fails the audit.
    pub uncorrectable_errors_threshold: u64,
    /// First read-error count that fails the audit.
    pub read_errors_threshold: u64,
    /// First write-error count that fails the audit.
    pub write_errors_threshold: u64,
}

impl Default for StorageReliabilityPolicy {
    fn default() -> Self {
        Self {
            temperature_warning_c: 55,
            temperature_critical_c: 65,
            wear_warning_percent_remaining: 20,
            uncorrectable_errors_threshold: 1,
            read_errors_threshold: 1,
            write_errors_threshold: 1,
        }
    }
}

impl StorageReliabilityPolicy {
    /// Validate operator parameters before native acquisition.
    ///
    /// # Errors
    ///
    /// Returns an error when a threshold is zero, outside a bounded range, or
    /// the temperature warning and critical boundaries are not ordered.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !(1..=120).contains(&self.temperature_warning_c)
            || !(self.temperature_warning_c..=120).contains(&self.temperature_critical_c)
        {
            return Err("temperature thresholds must be 1 through 120 C and ordered");
        }
        if self.wear_warning_percent_remaining == 0
            || self.uncorrectable_errors_threshold == 0
            || self.read_errors_threshold == 0
            || self.write_errors_threshold == 0
        {
            return Err("storage reliability thresholds must be non-zero");
        }
        Ok(())
    }
}

/// One non-secret physical-disk identity and health observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct PhysicalDiskObservation {
    /// Non-secret Storage provider disk identity.
    pub id: String,
    /// Normalized `MSFT_PhysicalDisk.HealthStatus` state.
    pub health_healthy: Observation<bool>,
    /// Normalized `MSFT_PhysicalDisk.OperationalStatus` state.
    pub operational_ok: Observation<bool>,
    /// Matched `MSFT_StorageReliabilityCounter` evidence.
    pub reliability: Observation<ReliabilityCounters>,
}

/// Storage provider counters normalized without controller-specific raw data.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ReliabilityCounters {
    /// Controller-reported disk temperature in Celsius.
    pub temperature_c: Observation<u16>,
    /// Controller-reported percentage of wear remaining.
    pub wear_percent_remaining: Observation<u8>,
    /// Controller-reported uncorrectable error count.
    pub uncorrectable_errors: Observation<u64>,
    /// Controller-reported total read error count.
    pub read_errors: Observation<u64>,
    /// Controller-reported total write error count.
    pub write_errors: Observation<u64>,
}

/// Native storage evidence before pure policy evaluation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct StorageReliabilityObservation {
    /// All physical disks, or a typed incomplete observation.
    pub physical_disks: Observation<Vec<PhysicalDiskObservation>>,
}

/// Deterministic result for capability 35.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct StorageReliabilityAudit {
    /// Native input evidence.
    pub observation: StorageReliabilityObservation,
    /// Deterministic drift and incomplete-evidence findings.
    pub findings: Vec<PolicyFinding>,
}

/// Evaluate legacy capability 35 without Windows I/O.
#[must_use]
pub fn evaluate_storage_reliability(
    observation: StorageReliabilityObservation,
    policy: &StorageReliabilityPolicy,
) -> StorageReliabilityAudit {
    let mut findings = Vec::new();
    match &observation.physical_disks {
        Observation::Present(disks) if !disks.is_empty() => {
            for disk in disks {
                evaluate_disk(disk, policy, &mut findings);
            }
        }
        Observation::Present(_) => incomplete(
            "STO-NoPhysicalDisks",
            "no physical disks were returned",
            &mut findings,
        ),
        other => incomplete(
            "STO-PhysicalDisksIncomplete",
            observation_state(other),
            &mut findings,
        ),
    }
    StorageReliabilityAudit {
        observation,
        findings,
    }
}

fn evaluate_disk(
    disk: &PhysicalDiskObservation,
    policy: &StorageReliabilityPolicy,
    findings: &mut Vec<PolicyFinding>,
) {
    evaluate_bool(
        &DiskRule::new(
            "STO-HealthNotHealthy",
            "STO-HealthIncomplete",
            "physical-disk health",
            0,
            Severity::High,
        ),
        &disk.id,
        &disk.health_healthy,
        findings,
    );
    evaluate_bool(
        &DiskRule::new(
            "STO-OperationalNotOk",
            "STO-OperationalIncomplete",
            "physical-disk operational state",
            0,
            Severity::High,
        ),
        &disk.id,
        &disk.operational_ok,
        findings,
    );
    let Observation::Present(counters) = &disk.reliability else {
        incomplete(
            "STO-ReliabilityIncomplete",
            observation_state(&disk.reliability),
            findings,
        );
        return;
    };
    threshold(
        &RangeRule {
            warning: DiskRule::new(
                "STO-TemperatureWarning",
                "STO-TemperatureIncomplete",
                "temperature",
                u64::from(policy.temperature_warning_c),
                Severity::Medium,
            ),
            critical_code: "STO-TemperatureCritical",
            critical_threshold: u64::from(policy.temperature_critical_c),
        },
        &disk.id,
        &counters.temperature_c,
        findings,
    );
    below_threshold(
        &DiskRule::new(
            "STO-WearLow",
            "STO-WearIncomplete",
            "wear remaining",
            u64::from(policy.wear_warning_percent_remaining),
            Severity::Medium,
        ),
        &disk.id,
        &counters.wear_percent_remaining,
        findings,
    );
    minimum(
        &DiskRule::new(
            "STO-UncorrectableErrors",
            "STO-UncorrectableErrorsIncomplete",
            "uncorrectable errors",
            policy.uncorrectable_errors_threshold,
            Severity::High,
        ),
        &disk.id,
        &counters.uncorrectable_errors,
        findings,
    );
    minimum(
        &DiskRule::new(
            "STO-ReadErrors",
            "STO-ReadErrorsIncomplete",
            "read errors",
            policy.read_errors_threshold,
            Severity::Medium,
        ),
        &disk.id,
        &counters.read_errors,
        findings,
    );
    minimum(
        &DiskRule::new(
            "STO-WriteErrors",
            "STO-WriteErrorsIncomplete",
            "write errors",
            policy.write_errors_threshold,
            Severity::Medium,
        ),
        &disk.id,
        &counters.write_errors,
        findings,
    );
}

struct DiskRule {
    code: &'static str,
    incomplete_code: &'static str,
    label: &'static str,
    threshold: u64,
    severity: Severity,
}
impl DiskRule {
    const fn new(
        code: &'static str,
        incomplete_code: &'static str,
        label: &'static str,
        threshold: u64,
        severity: Severity,
    ) -> Self {
        Self {
            code,
            incomplete_code,
            label,
            threshold,
            severity,
        }
    }
}
struct RangeRule {
    warning: DiskRule,
    critical_code: &'static str,
    critical_threshold: u64,
}

fn evaluate_bool(
    rule: &DiskRule,
    id: &str,
    value: &Observation<bool>,
    findings: &mut Vec<PolicyFinding>,
) {
    match value {
        Observation::Present(true) => {}
        Observation::Present(false) => findings.push(finding(
            rule.code,
            FindingStatus::Fail,
            rule.severity,
            format!("{} is not healthy for disk {id}.", rule.label),
            id,
        )),
        other => incomplete(rule.incomplete_code, observation_state(other), findings),
    }
}

fn threshold(
    rule: &RangeRule,
    id: &str,
    value: &Observation<u16>,
    findings: &mut Vec<PolicyFinding>,
) {
    match value {
        Observation::Present(value) if u64::from(*value) >= rule.critical_threshold => findings
            .push(finding(
                rule.critical_code,
                FindingStatus::Fail,
                Severity::High,
                format!(
                    "Disk {id} {} is {value}, at or above {}.",
                    rule.warning.label, rule.critical_threshold
                ),
                id,
            )),
        Observation::Present(value) if u64::from(*value) >= rule.warning.threshold => findings
            .push(finding(
                rule.warning.code,
                FindingStatus::Warning,
                rule.warning.severity,
                format!(
                    "Disk {id} {} is {value}, at or above {}.",
                    rule.warning.label, rule.warning.threshold
                ),
                id,
            )),
        Observation::Present(_) => {}
        other => incomplete(
            rule.warning.incomplete_code,
            observation_state(other),
            findings,
        ),
    }
}

fn below_threshold(
    rule: &DiskRule,
    id: &str,
    value: &Observation<u8>,
    findings: &mut Vec<PolicyFinding>,
) {
    match value {
        Observation::Present(value) if u64::from(*value) <= rule.threshold => {
            findings.push(finding(
                rule.code,
                FindingStatus::Warning,
                Severity::Medium,
                format!(
                    "Disk {id} {} is {value}, at or below {}.",
                    rule.label, rule.threshold
                ),
                id,
            ));
        }
        Observation::Present(_) => {}
        other => incomplete(rule.incomplete_code, observation_state(other), findings),
    }
}

fn minimum(rule: &DiskRule, id: &str, value: &Observation<u64>, findings: &mut Vec<PolicyFinding>) {
    match value {
        Observation::Present(value) if *value >= rule.threshold => findings.push(finding(
            rule.code,
            FindingStatus::Fail,
            rule.severity,
            format!(
                "Disk {id} {} is {value}, at or above {}.",
                rule.label, rule.threshold
            ),
            id,
        )),
        Observation::Present(_) => {}
        other => incomplete(rule.incomplete_code, observation_state(other), findings),
    }
}

fn incomplete(code: &'static str, state: &str, findings: &mut Vec<PolicyFinding>) {
    findings.push(PolicyFinding {
        code,
        status: FindingStatus::Warning,
        severity: Severity::Medium,
        message: format!("Required storage evidence is incomplete: {state}."),
        evidence: JsonMap::new(),
    });
}

fn finding(
    code: &'static str,
    status: FindingStatus,
    severity: Severity,
    message: String,
    disk_id: &str,
) -> PolicyFinding {
    PolicyFinding {
        code,
        status,
        severity,
        message,
        evidence: JsonMap::from([("disk_id".into(), json!(disk_id))]),
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
    #[test]
    fn incomplete_counter_cannot_be_healthy() {
        let audit = evaluate_storage_reliability(
            StorageReliabilityObservation {
                physical_disks: Observation::Present(vec![PhysicalDiskObservation {
                    id: "disk-1".into(),
                    health_healthy: Observation::Present(true),
                    operational_ok: Observation::Present(true),
                    reliability: Observation::Missing,
                }]),
            },
            &StorageReliabilityPolicy::default(),
        );
        assert!(
            audit
                .findings
                .iter()
                .any(|finding| finding.code == "STO-ReliabilityIncomplete")
        );
    }
    #[test]
    fn rejects_unbounded_thresholds() {
        let policy = StorageReliabilityPolicy {
            temperature_warning_c: 100,
            temperature_critical_c: 90,
            ..StorageReliabilityPolicy::default()
        };
        assert!(policy.validate().is_err());
    }
}
