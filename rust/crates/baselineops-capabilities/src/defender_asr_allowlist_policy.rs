//! Pure, read-only policy evaluation for bounded Defender ASR metadata.
//!
//! Capability 01 intentionally exposes neither allowlist contents nor caller-selected
//! rules. It evaluates only fixed counts and a finite, non-sensitive subset of
//! `MSFT_MpPreference` ASR action values.

use crate::{Observation, PolicyFinding};
use baselineops_domain::{FindingStatus, JsonMap, Severity};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Strict capability 01 parameters.
///
/// There are deliberately no paths, command arguments, exclusion entries, or rule
/// identifiers in this parameter surface.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct DefenderAsrAllowlistPolicy {}

/// Counts for the fixed Defender ASR action subset.
///
/// Values are aggregate metadata only. The collector never retains rule identifiers
/// or pairs an action with a specific rule.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct AsrRuleActionCounts {
    /// Rules explicitly disabled (`0`).
    pub disabled: u32,
    /// Rules configured to block (`1`).
    pub block: u32,
    /// Rules configured to audit (`2`).
    pub audit: u32,
    /// Rules configured to warn (`6`).
    pub warn: u32,
    /// Values outside the fixed supported subset.
    pub unsupported: u32,
}

impl AsrRuleActionCounts {
    /// Records one raw, non-sensitive Defender ASR action value.
    pub fn record(&mut self, value: u32) {
        match value {
            0 => self.disabled += 1,
            1 => self.block += 1,
            2 => self.audit += 1,
            6 => self.warn += 1,
            _ => self.unsupported += 1,
        }
    }

    /// Returns the number of action values represented by this fixed subset.
    #[must_use]
    pub const fn total(&self) -> u32 {
        self.disabled + self.block + self.audit + self.warn + self.unsupported
    }
}

/// Native evidence retained by the capability 01 adapter.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct DefenderAsrAllowlistObservation {
    /// Count of ASR-only exclusions; their values are intentionally not retained.
    pub asr_only_exclusion_count: Observation<u32>,
    /// Aggregate actions from the fixed `AttackSurfaceReductionRules_Actions` field.
    pub asr_rule_actions: Observation<AsrRuleActionCounts>,
}

/// Deterministic, read-only capability 01 audit output.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct DefenderAsrAllowlistAudit {
    /// Fixed native evidence, including incomplete evidence states.
    pub observation: DefenderAsrAllowlistObservation,
    /// Findings from the bounded evaluator.
    pub findings: Vec<PolicyFinding>,
    /// Explicitly excluded behavior and evidence lanes.
    pub exclusions: Vec<&'static str>,
}

/// A truthful, zero-mutation Plan result for the in-development capability.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct DefenderAsrAllowlistPlan {
    /// Audit evidence and deterministic evaluation.
    pub audit: DefenderAsrAllowlistAudit,
    /// This foundation proposes no allowlist or Defender changes.
    pub proposed_mutation_count: u32,
    /// Raw Apply is deliberately unavailable.
    pub apply_available: bool,
}

/// Evaluate bounded ASR metadata without platform I/O or mutation.
#[must_use]
pub fn evaluate_defender_asr_allowlist(
    observation: DefenderAsrAllowlistObservation,
    _policy: &DefenderAsrAllowlistPolicy,
) -> DefenderAsrAllowlistAudit {
    let mut findings = Vec::new();
    evaluate_exclusion_count(&observation.asr_only_exclusion_count, &mut findings);
    evaluate_rule_actions(&observation.asr_rule_actions, &mut findings);
    findings.push(finding(
        "ASR-Allowlist-CoverageExcluded",
        FindingStatus::Warning,
        Severity::Low,
        "Only fixed Defender WMI aggregate metadata is observed; this is not a legacy-oracle or Windows VM parity claim.",
    ));
    DefenderAsrAllowlistAudit {
        observation,
        findings,
        exclusions: exclusions(),
    }
}

/// Build the bounded capability 01 Plan without proposing any mutation.
#[must_use]
pub fn build_defender_asr_allowlist_plan(
    observation: DefenderAsrAllowlistObservation,
    policy: &DefenderAsrAllowlistPolicy,
) -> DefenderAsrAllowlistPlan {
    DefenderAsrAllowlistPlan {
        audit: evaluate_defender_asr_allowlist(observation, policy),
        proposed_mutation_count: 0,
        apply_available: false,
    }
}

fn evaluate_exclusion_count(value: &Observation<u32>, findings: &mut Vec<PolicyFinding>) {
    match value {
        Observation::Present(0) => {}
        Observation::Present(count) => findings.push(PolicyFinding {
            code: "ASR-Allowlist-EntriesPresent",
            status: FindingStatus::Warning,
            severity: Severity::Medium,
            message: format!(
                "{count} ASR-only exclusion entr{} present; contents were not collected.",
                if *count == 1 { "y is" } else { "ies are" }
            ),
            evidence: JsonMap::from([("asr_only_exclusion_count".into(), json!(count))]),
        }),
        other => incomplete("ASR-Allowlist-EvidenceIncomplete", other, findings),
    }
}

fn evaluate_rule_actions(
    value: &Observation<AsrRuleActionCounts>,
    findings: &mut Vec<PolicyFinding>,
) {
    let Observation::Present(counts) = value else {
        incomplete("ASR-RuleActions-EvidenceIncomplete", value, findings);
        return;
    };
    if counts.total() == 0 {
        findings.push(finding(
            "ASR-RuleActions-NotConfigured",
            FindingStatus::Warning,
            Severity::Low,
            "No Defender ASR rule action metadata was returned by the fixed provider property.",
        ));
    }
    if counts.disabled > 0 {
        findings.push(count_finding(
            "ASR-RuleActions-Disabled",
            FindingStatus::Warning,
            Severity::Medium,
            "fixed ASR action value(s) are explicitly disabled.",
            "disabled",
            counts.disabled,
        ));
    }
    if counts.unsupported > 0 {
        findings.push(count_finding(
            "ASR-RuleActions-Unsupported",
            FindingStatus::Error,
            Severity::High,
            "ASR action value(s) are outside the supported fixed subset.",
            "unsupported",
            counts.unsupported,
        ));
    }
}

fn incomplete<T>(code: &'static str, value: &Observation<T>, findings: &mut Vec<PolicyFinding>) {
    findings.push(PolicyFinding {
        code,
        status: FindingStatus::Error,
        severity: Severity::High,
        message: format!(
            "Required Defender ASR metadata is incomplete: {}.",
            observation_state(value)
        ),
        evidence: JsonMap::from([("read_only".into(), json!(true))]),
    });
}

fn count_finding(
    code: &'static str,
    status: FindingStatus,
    severity: Severity,
    suffix: &'static str,
    key: &'static str,
    count: u32,
) -> PolicyFinding {
    PolicyFinding {
        code,
        status,
        severity,
        message: format!("{count} {suffix}"),
        evidence: JsonMap::from([(key.into(), json!(count))]),
    }
}

fn finding(
    code: &'static str,
    status: FindingStatus,
    severity: Severity,
    message: &'static str,
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
        Observation::AccessDenied => "access_denied",
        Observation::TimedOut => "timed_out",
        Observation::Truncated => "truncated",
        Observation::Failed { .. } => "failed",
        Observation::NotRun => "not_run",
        Observation::Unparsed => "unparsed",
    }
}

fn exclusions() -> Vec<&'static str> {
    vec![
        "Allowlist mutation, synchronization, and any Defender preference write are unavailable.",
        "ASR-only exclusion paths and Controlled Folder Access path/application entries are not collected.",
        "Defender exclusion paths, extensions, processes, and their contents are not collected.",
        "No caller-selected paths, commands, executable arguments, or arbitrary ASR rule identifiers are accepted.",
        "Legacy PowerShell capability 01 behavior and remediation are not used as an oracle or claimed as parity.",
        "Windows client and Server VM evidence is not included.",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameters_reject_sensitive_or_unbounded_inputs() {
        for value in [
            json!({"path":"C:\\\\temp"}),
            json!({"command":"Set-MpPreference"}),
            json!({"rule_id":"00000000-0000-0000-0000-000000000000"}),
            json!({"exclusion":"example.exe"}),
        ] {
            assert!(serde_json::from_value::<DefenderAsrAllowlistPolicy>(value).is_err());
        }
    }

    #[test]
    fn evaluator_reports_metadata_without_retaining_allowlist_contents() {
        let audit = evaluate_defender_asr_allowlist(
            DefenderAsrAllowlistObservation {
                asr_only_exclusion_count: Observation::Present(2),
                asr_rule_actions: Observation::Present(AsrRuleActionCounts {
                    disabled: 1,
                    unsupported: 1,
                    ..AsrRuleActionCounts::default()
                }),
            },
            &DefenderAsrAllowlistPolicy {},
        );
        for code in [
            "ASR-Allowlist-EntriesPresent",
            "ASR-RuleActions-Disabled",
            "ASR-RuleActions-Unsupported",
            "ASR-Allowlist-CoverageExcluded",
        ] {
            assert!(audit.findings.iter().any(|finding| finding.code == code));
        }
        assert!(
            audit
                .exclusions
                .iter()
                .any(|item| item.contains("Defender exclusion paths, extensions, processes"))
        );
    }

    #[test]
    fn incomplete_metadata_fails_closed_and_plan_is_non_mutating() {
        let observation = DefenderAsrAllowlistObservation {
            asr_only_exclusion_count: Observation::AccessDenied,
            asr_rule_actions: Observation::Unparsed,
        };
        let plan = build_defender_asr_allowlist_plan(observation, &DefenderAsrAllowlistPolicy {});
        assert_eq!(plan.proposed_mutation_count, 0);
        assert!(!plan.apply_available);
        assert!(
            plan.audit
                .findings
                .iter()
                .filter(|finding| finding.status == FindingStatus::Error)
                .count()
                >= 2
        );
    }
}
