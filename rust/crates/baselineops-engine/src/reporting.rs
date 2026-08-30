use baselineops_domain::{ActionId, ArtifactId, ResultStatus, ResultV3};
use baselineops_windows::atomic_write;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;

use crate::{EvidenceManifest, VerifiedPlan};

/// Cross-run report summary.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct AggregateReport {
    /// Number of valid results.
    pub result_count: usize,
    /// Overall status using worst-outcome aggregation.
    pub status: ResultStatus,
    /// Total action outcomes.
    pub action_count: usize,
    /// Total findings.
    pub finding_count: usize,
    /// Total retained artifacts.
    pub artifact_count: usize,
}

/// Aggregate already validated v3 results without discarding duplicates or finding order.
///
/// # Errors
///
/// Returns an error when no results are supplied or any result fails domain validation.
pub fn aggregate(results: &[ResultV3]) -> Result<AggregateReport, ReportError> {
    if results.is_empty() {
        return Err(ReportError::EmptyInput);
    }
    for result in results {
        result.validate()?;
    }
    let status = results
        .iter()
        .map(|result| result.status)
        .reduce(|left, right| {
            if status_rank(left) >= status_rank(right) {
                left
            } else {
                right
            }
        })
        .ok_or(ReportError::EmptyInput)?;
    Ok(AggregateReport {
        result_count: results.len(),
        status,
        action_count: results.iter().map(|result| result.actions.len()).sum(),
        finding_count: results.iter().map(|result| result.findings.len()).sum(),
        artifact_count: results.iter().map(|result| result.artifacts.len()).sum(),
    })
}

/// Validate that a final result retains the exact approved plan identity and evidence inventory.
///
/// This is deliberately an engine-level check: callers cannot substitute a raw
/// deserialized plan for [`VerifiedPlan`] when validating an apply result.
///
/// # Errors
///
/// Returns an error when the result is structurally invalid, identifies a
/// different plan/run/host/operation, omits or invents action results, or cites
/// an artifact that differs from the canonical evidence manifest.
pub fn validate_result_consistency(
    result: &ResultV3,
    approved_plan: &VerifiedPlan,
    evidence: &EvidenceManifest,
) -> Result<(), ReportError> {
    result.validate()?;
    let plan = approved_plan.plan();
    validate_result_plan_bindings(result, plan)?;
    let retained = evidence
        .artifacts
        .iter()
        .map(|artifact| (artifact.id, artifact))
        .collect::<BTreeMap<ArtifactId, _>>();
    for artifact in &result.artifacts {
        if retained.get(&artifact.id) != Some(&artifact) {
            return Err(ReportError::ArtifactMismatch);
        }
    }
    Ok(())
}

fn validate_result_plan_bindings(
    result: &ResultV3,
    plan: &baselineops_domain::PlanV3,
) -> Result<(), ReportError> {
    if result.plan_id != plan.id
        || result.run_id != plan.run_id
        || result.profile_id != plan.profile_id
        || result.host != plan.host
        || result.operation != plan.intent.into()
    {
        return Err(ReportError::ResultPlanMismatch);
    }
    let planned = plan
        .actions
        .iter()
        .map(|action| (action.id, &action.capability))
        .collect::<BTreeMap<ActionId, _>>();
    if result.actions.len() != planned.len() {
        return Err(ReportError::ActionSetMismatch);
    }
    for action in &result.actions {
        if planned.get(&action.action_id) != Some(&&action.capability) {
            return Err(ReportError::ActionSetMismatch);
        }
    }
    Ok(())
}

/// Write one authoritative pretty JSON result atomically.
///
/// # Errors
///
/// Returns an error when result validation, JSON serialization, or atomic output fails.
pub fn write_json(path: impl AsRef<Path>, result: &ResultV3) -> Result<(), ReportError> {
    result.validate()?;
    let mut bytes = serde_json::to_vec_pretty(result)?;
    bytes.push(b'\n');
    atomic_write(path, &bytes)?;
    Ok(())
}

/// Write JSON Lines derived from the result model, one complete result per line.
///
/// # Errors
///
/// Returns an error when any result is invalid or serialization or atomic output fails.
pub fn write_json_lines(path: impl AsRef<Path>, results: &[ResultV3]) -> Result<(), ReportError> {
    let mut bytes = Vec::new();
    for result in results {
        result.validate()?;
        serde_json::to_writer(&mut bytes, result)?;
        bytes.push(b'\n');
    }
    atomic_write(path, &bytes)?;
    Ok(())
}

/// Write a flattened finding-oriented CSV with a UTF-8 BOM.
///
/// # Errors
///
/// Returns an error when any result is invalid or CSV generation or atomic output fails.
pub fn write_csv(path: impl AsRef<Path>, results: &[ResultV3]) -> Result<(), ReportError> {
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    {
        let mut writer = csv::Writer::from_writer(&mut bytes);
        writer.write_record([
            "result_id",
            "plan_id",
            "profile_id",
            "host",
            "result_status",
            "capability_id",
            "finding_code",
            "finding_status",
            "severity",
            "message",
            "observed_at",
        ])?;
        for result in results {
            result.validate()?;
            if result.findings.is_empty() {
                writer.write_record([
                    result.id.to_string(),
                    result.plan_id.to_string(),
                    result.profile_id.to_string(),
                    result.host.hostname.clone(),
                    format!("{:?}", result.status),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                ])?;
            } else {
                for finding in &result.findings {
                    writer.write_record([
                        result.id.to_string(),
                        result.plan_id.to_string(),
                        result.profile_id.to_string(),
                        result.host.hostname.clone(),
                        format!("{:?}", result.status),
                        finding.capability.to_string(),
                        finding.code.clone(),
                        format!("{:?}", finding.status),
                        format!("{:?}", finding.severity),
                        finding.message.clone(),
                        finding.observed_at.to_rfc3339(),
                    ])?;
                }
            }
        }
        writer.flush().map_err(csv::Error::from)?;
    }
    atomic_write(path, &bytes)?;
    Ok(())
}

fn status_rank(status: ResultStatus) -> u8 {
    match status {
        ResultStatus::Completed => 0,
        ResultStatus::Warnings => 1,
        ResultStatus::Unsupported => 2,
        ResultStatus::Rejected => 3,
        ResultStatus::ExecutionFailed => 4,
        ResultStatus::Cancelled => 5,
    }
}

/// Reporting and aggregation failures.
#[derive(Debug, thiserror::Error)]
pub enum ReportError {
    /// At least one result is required.
    #[error("at least one result is required")]
    EmptyInput,
    /// Result-domain validation failed.
    #[error(transparent)]
    Domain(#[from] baselineops_domain::DomainError),
    /// JSON serialization failed.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// CSV serialization failed.
    #[error(transparent)]
    Csv(#[from] csv::Error),
    /// Atomic output failed.
    #[error(transparent)]
    Platform(#[from] baselineops_windows::PlatformError),
    /// Result identity or bindings differ from the approved execution plan.
    #[error("result does not match the approved plan")]
    ResultPlanMismatch,
    /// Result action outcomes do not represent the approved action set exactly once.
    #[error("result action outcomes do not match the approved action set")]
    ActionSetMismatch,
    /// A result artifact is absent from or differs from the canonical evidence manifest.
    #[error("result artifact does not match the canonical evidence manifest")]
    ArtifactMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;
    use baselineops_domain::{
        ActionResultV3, ActionStatus, CapabilityId, ExecutionIntent, HostIdentityV3,
        InputIdentityV3, JsonMap, ObservedStateV3, Operation, OsFamily, PlanId, PlannedActionV3,
        ProfileId, RebootRequirement, Reversibility, RiskLevel, RunId, SchemaVersion,
        SourceIdentityV3, SourceKind, ToolIdentityV3,
    };
    use chrono::Utc;
    use std::collections::BTreeMap;

    fn plan_and_result() -> (baselineops_domain::PlanV3, ResultV3) {
        let now = Utc::now();
        let mut host = HostIdentityV3 {
            host_id: "host".into(),
            boot_id: "boot".into(),
            session_id: "session".into(),
            hostname: "endpoint".into(),
            os_family: OsFamily::Windows,
            os_version: "10.0".into(),
            architecture: "x86_64".into(),
            fingerprint: baselineops_domain::Sha256Digest::of_bytes(b"placeholder"),
        };
        host.fingerprint = host.calculated_fingerprint().expect("fingerprint");
        let capability = CapabilityId::new("v3.test.capability").expect("capability");
        let action = PlannedActionV3 {
            id: ActionId::new(),
            source_step: ActionId::new(),
            capability: capability.clone(),
            operation: Operation::Apply,
            parameters: JsonMap::new(),
            depends_on: Vec::new(),
            continue_on_error: false,
            facts_digest: baselineops_domain::Sha256Digest::of_bytes(b"facts"),
            preconditions: Vec::new(),
            risk: RiskLevel::Low,
            reversibility: Reversibility::NotApplicable,
            reboot: RebootRequirement::NotRequired,
            privileges: Vec::new(),
            metadata: JsonMap::new(),
        };
        let plan = baselineops_domain::PlanV3 {
            schema_version: SchemaVersion::V3,
            id: PlanId::new(),
            run_id: RunId::new(),
            intent: ExecutionIntent::Apply,
            profile_id: ProfileId::new(),
            profile_digest: baselineops_domain::Sha256Digest::of_bytes(b"profile"),
            host: host.clone(),
            tool: ToolIdentityV3 {
                name: "baselineops".into(),
                version: "3.0.0".into(),
                build_digest: None,
            },
            package_digest: baselineops_domain::Sha256Digest::of_bytes(b"package"),
            source: SourceIdentityV3 {
                kind: SourceKind::Api,
                locator: "test".into(),
                digest: baselineops_domain::Sha256Digest::of_bytes(b"source"),
            },
            input: InputIdentityV3 {
                digest: baselineops_domain::Sha256Digest::of_bytes(b"input"),
                size_bytes: 1,
            },
            observed_state: ObservedStateV3 {
                captured_at: now,
                digest: baselineops_domain::Sha256Digest::of_bytes(b"facts"),
                values: BTreeMap::default(),
            },
            issued_at: now,
            expires_at: now + chrono::Duration::minutes(1),
            actions: vec![action.clone()],
            metadata: JsonMap::new(),
        };
        let result = ResultV3 {
            schema_version: SchemaVersion::V3,
            id: baselineops_domain::ResultId::new(),
            run_id: plan.run_id,
            plan_id: plan.id,
            profile_id: plan.profile_id,
            capability_id: None,
            operation: Operation::Apply,
            host,
            status: ResultStatus::Completed,
            started_at: now,
            completed_at: now,
            actions: vec![ActionResultV3 {
                action_id: action.id,
                capability,
                status: ActionStatus::Succeeded,
                started_at: now,
                completed_at: now,
                metadata: JsonMap::new(),
            }],
            findings: Vec::new(),
            summary: "completed".into(),
            artifacts: Vec::new(),
            metadata: JsonMap::new(),
        };
        (plan, result)
    }

    #[test]
    fn result_mismatch_is_rejected_before_reporting() {
        let (plan, mut result) = plan_and_result();
        result.validate().expect("valid result fixture");
        result.plan_id = PlanId::new();
        assert!(matches!(
            validate_result_plan_bindings(&result, &plan),
            Err(ReportError::ResultPlanMismatch)
        ));
    }
}
