//! Pure policy for a supplied, bounded missing-patch feed.

use crate::{Observation, PolicyFinding};
use baselineops_domain::{FindingStatus, JsonMap, Severity};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeSet;

/// Maximum curated entries accepted from a supplied feed.
pub const MAX_PATCH_FEED_ENTRIES: usize = 1_024;
/// Maximum installed KBs retained by the Windows source adapter.
pub const MAX_INSTALLED_KBS: usize = 4_096;

/// Strict operator-supplied feed; fetch, URLs, commands, and paths are intentionally absent.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PatchFeed {
    /// Curated KB requirements.
    pub entries: Vec<PatchFeedEntry>,
}

/// One curated KB requirement.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PatchFeedEntry {
    /// Canonical KB identifier such as `KB5030219`.
    pub kb: String,
    /// Human title retained as supplied, within the bounded feed.
    pub title: String,
    /// Whether the entry is an urgent zero-day requirement.
    pub is_zero_day: bool,
    /// Optional curator-assigned severity.
    pub severity: Option<Severity>,
}

/// Complete input to the missing-patch evaluator.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct MissingPatchObservation {
    /// Supplied feed; unavailable or malformed input must never imply health.
    pub feed: Observation<PatchFeed>,
    /// Installed KB identities from Windows Update history.
    pub installed_kbs: Observation<Vec<String>>,
}

/// Deterministic missing-patch output.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct MissingPatchAudit {
    /// Original feed and source evidence.
    pub observation: MissingPatchObservation,
    /// Findings for missing required updates or incomplete evidence.
    pub findings: Vec<PolicyFinding>,
}

/// Validates the strict bounded feed shape and content before platform access.
///
/// # Errors
///
/// Returns an explanation when an entry is absent, malformed, oversized, or duplicated.
pub fn validate_patch_feed(feed: PatchFeed) -> Result<PatchFeed, String> {
    if feed.entries.is_empty() || feed.entries.len() > MAX_PATCH_FEED_ENTRIES {
        return Err(format!(
            "feed entries must contain 1 through {MAX_PATCH_FEED_ENTRIES} records"
        ));
    }
    let mut seen = BTreeSet::new();
    for entry in &feed.entries {
        let kb = canonical_kb(&entry.kb)
            .ok_or_else(|| "feed KB must be KB followed by 1 through 12 digits".to_owned())?;
        if entry.title.trim().is_empty() || entry.title.len() > 512 {
            return Err("feed title must contain 1 through 512 characters".into());
        }
        if !seen.insert(kb) {
            return Err("feed KB values must be unique".into());
        }
    }
    Ok(feed)
}

/// Evaluate supplied feed and installed-KB evidence without Windows I/O.
#[must_use]
pub fn evaluate_missing_patches(observation: MissingPatchObservation) -> MissingPatchAudit {
    let mut findings = Vec::new();
    let Observation::Present(feed) = &observation.feed else {
        incomplete(
            &mut findings,
            "PATCH-FeedIncomplete",
            "patch feed",
            &observation.feed,
        );
        return MissingPatchAudit {
            observation,
            findings,
        };
    };
    let Observation::Present(installed) = &observation.installed_kbs else {
        incomplete(
            &mut findings,
            "PATCH-InstalledKbIncomplete",
            "installed KB inventory",
            &observation.installed_kbs,
        );
        return MissingPatchAudit {
            observation,
            findings,
        };
    };
    let installed: BTreeSet<_> = installed.iter().filter_map(|kb| canonical_kb(kb)).collect();
    for entry in feed.entries.iter().take(MAX_PATCH_FEED_ENTRIES) {
        let Some(kb) = canonical_kb(&entry.kb) else {
            continue;
        };
        if !installed.contains(&kb) {
            let (code, severity) = if entry.is_zero_day {
                ("PATCH-MissingZeroDay", Severity::Critical)
            } else if entry.severity == Some(Severity::Critical) {
                ("PATCH-MissingCritical", Severity::Critical)
            } else {
                ("PATCH-Missing", entry.severity.unwrap_or(Severity::Medium))
            };
            findings.push(PolicyFinding {
                code,
                status: FindingStatus::Fail,
                severity,
                message: format!("Required update {kb} is not installed: {}.", entry.title),
                evidence: JsonMap::from([
                    ("kb".into(), json!(kb)),
                    ("is_zero_day".into(), json!(entry.is_zero_day)),
                ]),
            });
        }
    }
    MissingPatchAudit {
        observation,
        findings,
    }
}

/// Canonicalizes the identity only; it does not infer update applicability.
#[must_use]
pub fn canonical_kb(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let digits = trimmed
        .strip_prefix("KB")
        .or_else(|| trimmed.strip_prefix("kb"))?;
    ((1..=12).contains(&digits.len()) && digits.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| format!("KB{digits}"))
}

fn incomplete<T>(
    findings: &mut Vec<PolicyFinding>,
    code: &'static str,
    label: &str,
    value: &Observation<T>,
) {
    let status = match value {
        Observation::Present(_) => "present",
        Observation::Missing => "missing",
        Observation::AccessDenied => "access_denied",
        Observation::TimedOut => "timed_out",
        Observation::Truncated => "truncated",
        Observation::Failed { .. } => "failed",
        Observation::NotRun => "not_run",
        Observation::Unparsed => "unparsed",
    };
    findings.push(PolicyFinding {
        code,
        status: FindingStatus::Warning,
        severity: Severity::High,
        message: format!("{label} observation is incomplete: {status}."),
        evidence: JsonMap::from([("observation_status".into(), json!(status))]),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    fn feed() -> PatchFeed {
        PatchFeed {
            entries: vec![
                PatchFeedEntry {
                    kb: "KB5000001".into(),
                    title: "Urgent security update".into(),
                    is_zero_day: true,
                    severity: Some(Severity::Critical),
                },
                PatchFeedEntry {
                    kb: "KB5000002".into(),
                    title: "Critical security update".into(),
                    is_zero_day: false,
                    severity: Some(Severity::Critical),
                },
            ],
        }
    }

    #[test]
    fn zero_day_and_critical_findings_are_stable() {
        let audit = evaluate_missing_patches(MissingPatchObservation {
            feed: Observation::Present(feed()),
            installed_kbs: Observation::Present(vec![]),
        });
        assert_eq!(
            audit
                .findings
                .iter()
                .map(|item| item.code)
                .collect::<Vec<_>>(),
            vec!["PATCH-MissingZeroDay", "PATCH-MissingCritical"]
        );
    }
    #[test]
    fn unavailable_feed_is_not_healthy() {
        let audit = evaluate_missing_patches(MissingPatchObservation {
            feed: Observation::AccessDenied,
            installed_kbs: Observation::Present(vec![]),
        });
        assert_eq!(audit.findings[0].code, "PATCH-FeedIncomplete");
    }
    #[test]
    fn feed_validation_rejects_duplicate_or_malformed_kbs() {
        assert!(
            validate_patch_feed(PatchFeed {
                entries: vec![PatchFeedEntry {
                    kb: "invalid".into(),
                    title: "title".into(),
                    is_zero_day: false,
                    severity: None
                }]
            })
            .is_err()
        );
        let mut duplicate = feed();
        duplicate.entries[1].kb = "KB5000001".into();
        assert!(validate_patch_feed(duplicate).is_err());
    }
}
