use super::*;
use crate::{ServiceStartMode, ServiceState};

fn complete_observation() -> UpdateHealthObservation {
    UpdateHealthObservation {
        services: FIXED_UPDATE_HEALTH_SERVICES
            .into_iter()
            .map(|service| {
                (
                    service,
                    Observation::Present(ServiceObservation {
                        name: service.name().into(),
                        state: ServiceState::Stopped,
                        start_mode: ServiceStartMode::Manual,
                    }),
                )
            })
            .collect(),
        tasks: FIXED_UPDATE_HEALTH_TASKS
            .into_iter()
            .map(|task| {
                (
                    task,
                    Observation::Present(UpdateHealthTaskSnapshot {
                        enabled: Observation::Present(false),
                        state: Observation::Present(UpdateHealthTaskState::Disabled),
                    }),
                )
            })
            .collect(),
        update_agent: Observation::Present(UpdateAgentMetadata {
            total_history_count: 1,
            recent_history: vec![UpdateHistoryRecord {
                title: "Servicing Stack Update".into(),
                result_code: 2,
                hresult: 0,
            }],
        }),
    }
}

#[test]
fn fixed_states_are_evidence_not_remediation_directives() {
    let observation = complete_observation();
    let audit = evaluate_update_health(observation.clone());
    assert_eq!(audit.observation, observation);
    assert!(audit.findings.is_empty());
    let plan = build_update_health_read_only_plan(audit.observation);
    assert_eq!(plan.mutation_count, 0);
}

#[test]
fn incomplete_evidence_fails_closed_and_is_preserved() {
    let mut observation = complete_observation();
    observation.services.insert(
        UpdateHealthService::WindowsUpdate,
        Observation::AccessDenied,
    );
    observation.tasks.insert(
        UpdateHealthTask::WindowsUpdateScheduledStart,
        Observation::Truncated,
    );
    observation.update_agent = Observation::Unparsed;
    let audit = evaluate_update_health(observation);
    assert_eq!(
        audit.findings,
        vec![
            expected_incomplete_finding(
                "UPDATE-ServiceEvidenceIncomplete",
                "service",
                "wuauserv",
                "access_denied",
            ),
            expected_incomplete_finding(
                "UPDATE-TaskEvidenceIncomplete",
                "task",
                r"\Microsoft\Windows\WindowsUpdate\Scheduled Start",
                "truncated",
            ),
            expected_incomplete_finding(
                "UPDATE-AgentEvidenceIncomplete",
                "update_agent",
                "Windows Update Agent COM",
                "unparsed",
            ),
        ]
    );
}

#[test]
fn incomplete_task_snapshot_fields_are_ordered_and_exact() {
    let mut observation = complete_observation();
    observation.tasks.insert(
        UpdateHealthTask::WindowsUpdateScheduledStart,
        Observation::Present(UpdateHealthTaskSnapshot {
            enabled: Observation::AccessDenied,
            state: Observation::NotRun,
        }),
    );

    let audit = evaluate_update_health(observation);

    assert_eq!(
        audit.findings,
        vec![
            expected_incomplete_finding(
                "UPDATE-TaskEnabledEvidenceIncomplete",
                "task",
                r"\Microsoft\Windows\WindowsUpdate\Scheduled Start",
                "access_denied",
            ),
            expected_incomplete_finding(
                "UPDATE-TaskStateEvidenceIncomplete",
                "task",
                r"\Microsoft\Windows\WindowsUpdate\Scheduled Start",
                "not_run",
            ),
        ]
    );
}

#[test]
fn every_fixed_identity_is_traversed_in_order() {
    let audit = evaluate_update_health(all_fixed_identities_incomplete_observation());
    assert_eq!(audit.findings, expected_fixed_identity_findings());
}

#[test]
fn missing_observations_and_absent_fixed_keys_are_distinct() {
    let mut missing_observation = complete_observation();
    missing_observation
        .services
        .insert(UpdateHealthService::WindowsUpdate, Observation::Missing);
    missing_observation.tasks.insert(
        UpdateHealthTask::WindowsUpdateScheduledStart,
        Observation::Missing,
    );
    assert_eq!(
        evaluate_update_health(missing_observation).findings,
        vec![
            expected_incomplete_finding(
                "UPDATE-ServiceEvidenceIncomplete",
                "service",
                "wuauserv",
                "missing",
            ),
            expected_incomplete_finding(
                "UPDATE-TaskEvidenceIncomplete",
                "task",
                r"\Microsoft\Windows\WindowsUpdate\Scheduled Start",
                "missing",
            ),
        ]
    );

    let mut absent_fixed_key = complete_observation();
    absent_fixed_key
        .services
        .remove(&UpdateHealthService::WindowsUpdate);
    absent_fixed_key
        .tasks
        .remove(&UpdateHealthTask::WindowsUpdateScheduledStart);
    assert_eq!(
        evaluate_update_health(absent_fixed_key).findings,
        vec![
            expected_incomplete_finding(
                "UPDATE-FixedEvidenceMissing",
                "service",
                "wuauserv",
                "missing",
            ),
            expected_incomplete_finding(
                "UPDATE-FixedEvidenceMissing",
                "task",
                r"\Microsoft\Windows\WindowsUpdate\Scheduled Start",
                "missing",
            ),
        ]
    );
}

#[test]
fn parameters_reject_arbitrary_mutation_and_input() {
    for value in [
        serde_json::json!({ "service": "wuauserv" }),
        serde_json::json!({ "task_path": "\\\\untrusted" }),
        serde_json::json!({ "kb": "KB123456" }),
        serde_json::json!({ "command": "dism.exe" }),
        serde_json::json!({ "restart": true }),
    ] {
        assert!(serde_json::from_value::<UpdateHealthParameters>(value).is_err());
    }
}

fn expected_incomplete_finding(
    code: &'static str,
    kind: &'static str,
    identity: &'static str,
    state: &'static str,
) -> PolicyFinding {
    PolicyFinding {
        code,
        status: FindingStatus::Warning,
        severity: Severity::Medium,
        message: format!("Required fixed {kind} evidence is {state}: {identity}."),
        evidence: JsonMap::from([
            ("read_only".into(), json!(true)),
            ("identity_kind".into(), json!(kind)),
            ("identity".into(), json!(identity)),
            ("observation_state".into(), json!(state)),
        ]),
    }
}

fn all_fixed_identities_incomplete_observation() -> UpdateHealthObservation {
    UpdateHealthObservation {
        services: BTreeMap::from([
            (UpdateHealthService::UpdateHealth, Observation::Missing),
            (
                UpdateHealthService::UpdateOrchestrator,
                Observation::Missing,
            ),
            (
                UpdateHealthService::WindowsUpdateMedic,
                Observation::Missing,
            ),
            (UpdateHealthService::WindowsUpdate, Observation::Missing),
            (
                UpdateHealthService::DeliveryOptimization,
                Observation::Missing,
            ),
            (UpdateHealthService::Bits, Observation::Missing),
            (
                UpdateHealthService::CryptographicServices,
                Observation::Missing,
            ),
        ]),
        tasks: BTreeMap::from([
            (
                UpdateHealthTask::WindowsUpdateScheduledStart,
                Observation::Present(UpdateHealthTaskSnapshot {
                    enabled: Observation::Missing,
                    state: Observation::Missing,
                }),
            ),
            (
                UpdateHealthTask::UpdateOrchestratorScheduleScan,
                Observation::Present(UpdateHealthTaskSnapshot {
                    enabled: Observation::Missing,
                    state: Observation::Missing,
                }),
            ),
        ]),
        update_agent: Observation::Present(UpdateAgentMetadata {
            total_history_count: 0,
            recent_history: Vec::new(),
        }),
    }
}

fn expected_fixed_identity_findings() -> Vec<PolicyFinding> {
    vec![
        expected_incomplete_finding(
            "UPDATE-ServiceEvidenceIncomplete",
            "service",
            "uhssvc",
            "missing",
        ),
        expected_incomplete_finding(
            "UPDATE-ServiceEvidenceIncomplete",
            "service",
            "UsoSvc",
            "missing",
        ),
        expected_incomplete_finding(
            "UPDATE-ServiceEvidenceIncomplete",
            "service",
            "WaaSMedicSvc",
            "missing",
        ),
        expected_incomplete_finding(
            "UPDATE-ServiceEvidenceIncomplete",
            "service",
            "wuauserv",
            "missing",
        ),
        expected_incomplete_finding(
            "UPDATE-ServiceEvidenceIncomplete",
            "service",
            "DoSvc",
            "missing",
        ),
        expected_incomplete_finding(
            "UPDATE-ServiceEvidenceIncomplete",
            "service",
            "BITS",
            "missing",
        ),
        expected_incomplete_finding(
            "UPDATE-ServiceEvidenceIncomplete",
            "service",
            "cryptsvc",
            "missing",
        ),
        expected_incomplete_finding(
            "UPDATE-TaskEnabledEvidenceIncomplete",
            "task",
            r"\Microsoft\Windows\WindowsUpdate\Scheduled Start",
            "missing",
        ),
        expected_incomplete_finding(
            "UPDATE-TaskStateEvidenceIncomplete",
            "task",
            r"\Microsoft\Windows\WindowsUpdate\Scheduled Start",
            "missing",
        ),
        expected_incomplete_finding(
            "UPDATE-TaskEnabledEvidenceIncomplete",
            "task",
            r"\Microsoft\Windows\UpdateOrchestrator\Schedule Scan",
            "missing",
        ),
        expected_incomplete_finding(
            "UPDATE-TaskStateEvidenceIncomplete",
            "task",
            r"\Microsoft\Windows\UpdateOrchestrator\Schedule Scan",
            "missing",
        ),
    ]
}
