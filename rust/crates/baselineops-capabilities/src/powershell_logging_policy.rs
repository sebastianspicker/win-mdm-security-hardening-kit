//! Typed desired-state, drift, and rollback records for PowerShell logging.
//!
//! This module deliberately has no Windows I/O. The Windows crate obtains the
//! allowlisted HKLM/HKCU snapshots and performs the narrow registry mutation;
//! the engine owns operation dispatch. HKCU is observation-only: HKLM remains
//! authoritative whenever it has a value.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Maximum numbered module-name values accepted by this capability.
pub const MAX_MODULE_NAMES: u16 = 64;
/// Maximum UTF-8 bytes accepted for one policy string or transcript path.
pub const MAX_POLICY_STRING_BYTES: usize = 16 * 1024;

/// A missing registry value is distinct from a configured value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", content = "value", rename_all = "snake_case")]
pub enum ValueSnapshot<T> {
    /// The key or named value is absent.
    Missing,
    /// The named value was read with its required type.
    Value(T),
}

/// All bounded values observed from one policy hive.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct PowerShellLoggingHiveSnapshot {
    /// `Transcription\\EnableTranscripting` (spelling retained by Windows policy).
    pub enable_transcription: ValueSnapshot<u32>,
    /// `Transcription\\OutputDirectory`.
    pub transcript_output_directory: ValueSnapshot<String>,
    /// `Transcription\\EnableInvocationHeader`.
    pub enable_invocation_header: ValueSnapshot<u32>,
    /// `ScriptBlockLogging\\EnableScriptBlockLogging`.
    pub enable_script_block_logging: ValueSnapshot<u32>,
    /// `ScriptBlockLogging\\EnableScriptBlockInvocationLogging`.
    pub enable_script_block_invocation_logging: ValueSnapshot<u32>,
    /// `ModuleLogging\\EnableModuleLogging`.
    pub enable_module_logging: ValueSnapshot<u32>,
    /// Every numbered `ModuleNames` value when enumeration completed.
    pub module_names: ModuleNamesSnapshot,
}

/// Complete snapshot status for the numbered `ModuleNames` registry subkey.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ModuleNamesSnapshot {
    /// The values keyed by their bounded numeric registry value name.
    pub values: BTreeMap<u16, String>,
    /// False means enumeration did not establish a safe replacement baseline.
    pub complete: bool,
}

/// HKLM is always observed; HKCU appears only when explicitly requested.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct PowerShellLoggingObservation {
    /// Machine policy snapshot used for every mutation.
    pub hklm: PowerShellLoggingHiveSnapshot,
    /// Optional user policy snapshot, never changed by this capability.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hkcu: Option<PowerShellLoggingHiveSnapshot>,
}

/// Strict, partial configuration accepted from a profile's capability config.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, rename_all = "snake_case", deny_unknown_fields)]
pub struct PowerShellLoggingConfig {
    /// Default transcription enablement.
    pub enable_transcription: Option<bool>,
    /// Default bounded transcript output directory.
    pub transcript_output_directory: Option<String>,
    /// Default invocation-header enablement.
    pub enable_invocation_header: Option<bool>,
    /// Default script-block logging enablement.
    pub enable_script_block_logging: Option<bool>,
    /// Default script-block invocation logging enablement.
    pub enable_script_block_invocation_logging: Option<bool>,
    /// Default module logging enablement.
    pub enable_module_logging: Option<bool>,
    /// Default bounded module-name set.
    pub module_names: Option<Vec<String>>,
}

/// Strict operation parameters. Explicit values override `config`, then defaults.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, rename_all = "snake_case", deny_unknown_fields)]
pub struct PowerShellLoggingParameters {
    /// Optional bounded configuration-catalog defaults.
    pub config: Option<PowerShellLoggingConfig>,
    /// Explicit transcription enablement.
    pub enable_transcription: Option<bool>,
    /// Explicit bounded transcript output directory.
    pub transcript_output_directory: Option<String>,
    /// Explicit invocation-header enablement.
    pub enable_invocation_header: Option<bool>,
    /// Explicit script-block logging enablement.
    pub enable_script_block_logging: Option<bool>,
    /// Explicit script-block invocation logging enablement.
    pub enable_script_block_invocation_logging: Option<bool>,
    /// Explicit module logging enablement.
    pub enable_module_logging: Option<bool>,
    /// Explicit bounded module-name set.
    pub module_names: Option<Vec<String>>,
    /// Required before changing the numbered `ModuleNames` set.
    pub replace_module_names: bool,
    /// Includes HKCU in the returned observation only.
    pub include_hkcu: bool,
}

/// Fully-resolved policy values ready for planning or application.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[allow(clippy::struct_excessive_bools)]
pub struct PowerShellLoggingDesiredState {
    /// Whether transcription is enabled.
    pub enable_transcription: bool,
    /// Bounded transcript output directory.
    pub transcript_output_directory: String,
    /// Whether invocation headers are enabled.
    pub enable_invocation_header: bool,
    /// Whether script-block logging is enabled.
    pub enable_script_block_logging: bool,
    /// Whether script-block invocation logging is enabled.
    pub enable_script_block_invocation_logging: bool,
    /// Whether module logging is enabled.
    pub enable_module_logging: bool,
    /// Bounded module-name set.
    pub module_names: Vec<String>,
    /// Whether complete numbered module-name replacement is authorized.
    pub replace_module_names: bool,
}

/// One mutation to an exact allowlisted registry value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PowerShellLoggingMutation {
    /// Set one fixed DWORD policy value.
    SetDword {
        /// Fixed field identity.
        field: PolicyField,
        /// Desired DWORD value.
        value: u32,
    },
    /// Set one fixed string policy value.
    SetString {
        /// Fixed field identity.
        field: PolicyField,
        /// Desired bounded string value.
        value: String,
    },
    /// Replace the complete numbered module-name set.
    ReplaceModuleNames {
        /// Desired values keyed by bounded numeric names.
        values: BTreeMap<u16, String>,
    },
}

/// Field identifiers prevent raw registry paths and value names entering plans.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyField {
    /// Transcription enablement.
    EnableTranscription,
    /// Transcript output directory.
    TranscriptOutputDirectory,
    /// Invocation-header enablement.
    EnableInvocationHeader,
    /// Script-block logging enablement.
    EnableScriptBlockLogging,
    /// Script-block invocation logging enablement.
    EnableScriptBlockInvocationLogging,
    /// Module logging enablement.
    EnableModuleLogging,
}

/// A planned change contains before-state suitable for durable rollback records.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct PowerShellLoggingPlan {
    /// Observation used to derive the plan.
    pub observation: PowerShellLoggingObservation,
    /// Validated desired state.
    pub desired: PowerShellLoggingDesiredState,
    /// Finite mutations against allowlisted fields.
    pub mutations: Vec<PowerShellLoggingMutation>,
    /// A caller may retain this record; apply never rolls back automatically.
    pub rollback: PowerShellLoggingHiveSnapshot,
    /// Whether applying the mutations requires Administrator authority.
    pub requires_administrator: bool,
    /// Whether applying the mutations requires a reboot.
    pub reboot_required: bool,
    /// Whether new PowerShell sessions may be needed for policy activation.
    pub new_sessions_may_be_needed: bool,
}

/// Resolve explicit parameters over config values and fixed safe defaults.
///
/// # Errors
///
/// Returns an error for an oversized, empty, or invalid module-name set.
pub fn resolve_desired_state(
    parameters: &PowerShellLoggingParameters,
) -> Result<PowerShellLoggingDesiredState, String> {
    let config = parameters.config.as_ref();
    let transcript = choose_string(
        parameters.transcript_output_directory.as_ref(),
        config.and_then(|value| value.transcript_output_directory.as_ref()),
        r"C:\ProgramData\PowerShellTranscripts",
    );
    if transcript.len() > MAX_POLICY_STRING_BYTES || transcript.trim().is_empty() {
        return Err("transcript output directory must be a bounded non-empty string".into());
    }
    let modules = choose_modules(
        parameters.module_names.as_ref(),
        config.and_then(|value| value.module_names.as_ref()),
    )?;
    Ok(PowerShellLoggingDesiredState {
        enable_transcription: choose_bool(
            parameters.enable_transcription,
            config.and_then(|value| value.enable_transcription),
            true,
        ),
        transcript_output_directory: transcript,
        enable_invocation_header: choose_bool(
            parameters.enable_invocation_header,
            config.and_then(|value| value.enable_invocation_header),
            true,
        ),
        enable_script_block_logging: choose_bool(
            parameters.enable_script_block_logging,
            config.and_then(|value| value.enable_script_block_logging),
            true,
        ),
        enable_script_block_invocation_logging: choose_bool(
            parameters.enable_script_block_invocation_logging,
            config.and_then(|value| value.enable_script_block_invocation_logging),
            false,
        ),
        enable_module_logging: choose_bool(
            parameters.enable_module_logging,
            config.and_then(|value| value.enable_module_logging),
            true,
        ),
        module_names: modules,
        replace_module_names: parameters.replace_module_names,
    })
}

/// Build an idempotent plan from an already-observed snapshot.
///
/// # Errors
///
/// Rejects a module-name replacement unless the caller explicitly authorized it
/// and the complete existing numbered set was captured.
pub fn build_plan(
    observation: PowerShellLoggingObservation,
    desired: PowerShellLoggingDesiredState,
) -> Result<PowerShellLoggingPlan, String> {
    let mut mutations = Vec::new();
    add_dword_drift(
        &mut mutations,
        PolicyField::EnableTranscription,
        &observation.hklm.enable_transcription,
        desired.enable_transcription,
    );
    add_string_drift(
        &mut mutations,
        PolicyField::TranscriptOutputDirectory,
        &observation.hklm.transcript_output_directory,
        &desired.transcript_output_directory,
    );
    add_dword_drift(
        &mut mutations,
        PolicyField::EnableInvocationHeader,
        &observation.hklm.enable_invocation_header,
        desired.enable_invocation_header,
    );
    add_dword_drift(
        &mut mutations,
        PolicyField::EnableScriptBlockLogging,
        &observation.hklm.enable_script_block_logging,
        desired.enable_script_block_logging,
    );
    add_dword_drift(
        &mut mutations,
        PolicyField::EnableScriptBlockInvocationLogging,
        &observation.hklm.enable_script_block_invocation_logging,
        desired.enable_script_block_invocation_logging,
    );
    add_dword_drift(
        &mut mutations,
        PolicyField::EnableModuleLogging,
        &observation.hklm.enable_module_logging,
        desired.enable_module_logging,
    );
    let desired_names = numbered(&desired.module_names)?;
    if observation.hklm.module_names.values != desired_names {
        if !desired.replace_module_names || !observation.hklm.module_names.complete {
            return Err("ModuleNames replacement requires replace_module_names=true and a complete numbered snapshot".into());
        }
        mutations.push(PowerShellLoggingMutation::ReplaceModuleNames {
            values: desired_names,
        });
    }
    Ok(PowerShellLoggingPlan {
        rollback: observation.hklm.clone(),
        observation,
        desired,
        mutations,
        requires_administrator: true,
        reboot_required: false,
        new_sessions_may_be_needed: true,
    })
}

fn choose_bool(explicit: Option<bool>, configured: Option<bool>, default: bool) -> bool {
    explicit.or(configured).unwrap_or(default)
}

fn choose_string(explicit: Option<&String>, configured: Option<&String>, default: &str) -> String {
    explicit
        .or(configured)
        .cloned()
        .unwrap_or_else(|| default.into())
}

fn choose_modules(
    explicit: Option<&Vec<String>>,
    configured: Option<&Vec<String>>,
) -> Result<Vec<String>, String> {
    explicit
        .or(configured)
        .cloned()
        .unwrap_or_else(|| vec!["*".into()])
        .into_iter()
        .map(validate_module_name)
        .collect()
}

fn validate_module_name(value: String) -> Result<String, String> {
    if value.is_empty() || value.len() > MAX_POLICY_STRING_BYTES || value.contains('\0') {
        return Err("module names must be bounded non-empty strings without NUL".into());
    }
    Ok(value)
}

fn numbered(values: &[String]) -> Result<BTreeMap<u16, String>, String> {
    if values.is_empty() || values.len() > usize::from(MAX_MODULE_NAMES) {
        return Err("module_names must contain between one and 64 entries".into());
    }
    values
        .iter()
        .cloned()
        .map(validate_module_name)
        .enumerate()
        .map(|(index, value)| {
            let value = value?;
            u16::try_from(index + 1)
                .map(|number| (number, value))
                .map_err(|_| "module_names index overflow".to_owned())
        })
        .collect()
}

fn add_dword_drift(
    mutations: &mut Vec<PowerShellLoggingMutation>,
    field: PolicyField,
    before: &ValueSnapshot<u32>,
    desired: bool,
) {
    let value = u32::from(desired);
    if before != &ValueSnapshot::Value(value) {
        mutations.push(PowerShellLoggingMutation::SetDword { field, value });
    }
}

fn add_string_drift(
    mutations: &mut Vec<PowerShellLoggingMutation>,
    field: PolicyField,
    before: &ValueSnapshot<String>,
    desired: &str,
) {
    if before != &ValueSnapshot::Value(desired.into()) {
        mutations.push(PowerShellLoggingMutation::SetString {
            field,
            value: desired.into(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn missing_hive() -> PowerShellLoggingHiveSnapshot {
        PowerShellLoggingHiveSnapshot {
            enable_transcription: ValueSnapshot::Missing,
            transcript_output_directory: ValueSnapshot::Missing,
            enable_invocation_header: ValueSnapshot::Missing,
            enable_script_block_logging: ValueSnapshot::Missing,
            enable_script_block_invocation_logging: ValueSnapshot::Missing,
            enable_module_logging: ValueSnapshot::Missing,
            module_names: ModuleNamesSnapshot {
                values: BTreeMap::new(),
                complete: true,
            },
        }
    }

    #[test]
    fn explicit_values_override_config_and_defaults() {
        let desired = resolve_desired_state(&PowerShellLoggingParameters {
            config: Some(PowerShellLoggingConfig {
                enable_transcription: Some(false),
                module_names: Some(vec!["configured".into()]),
                ..PowerShellLoggingConfig::default()
            }),
            enable_transcription: Some(true),
            module_names: Some(vec!["explicit".into()]),
            ..PowerShellLoggingParameters::default()
        })
        .expect("typed desired state");
        assert!(desired.enable_transcription);
        assert_eq!(desired.module_names, ["explicit"]);
        assert!(desired.enable_module_logging);
    }

    #[test]
    fn hklm_snapshot_drives_drift_not_optional_hkcu() {
        let desired = resolve_desired_state(&PowerShellLoggingParameters {
            replace_module_names: true,
            ..PowerShellLoggingParameters::default()
        })
        .expect("desired state");
        let plan = build_plan(
            PowerShellLoggingObservation {
                hklm: missing_hive(),
                hkcu: Some(missing_hive()),
            },
            desired,
        )
        .expect("plan");
        assert_eq!(plan.mutations.len(), 7);
        assert!(
            plan.requires_administrator && !plan.reboot_required && plan.new_sessions_may_be_needed
        );
    }

    #[test]
    fn second_plan_after_desired_snapshot_is_idempotent() {
        let desired = resolve_desired_state(&PowerShellLoggingParameters {
            replace_module_names: true,
            ..PowerShellLoggingParameters::default()
        })
        .expect("desired state");
        let hklm = PowerShellLoggingHiveSnapshot {
            enable_transcription: ValueSnapshot::Value(1),
            transcript_output_directory: ValueSnapshot::Value(
                desired.transcript_output_directory.clone(),
            ),
            enable_invocation_header: ValueSnapshot::Value(1),
            enable_script_block_logging: ValueSnapshot::Value(1),
            enable_script_block_invocation_logging: ValueSnapshot::Value(0),
            enable_module_logging: ValueSnapshot::Value(1),
            module_names: ModuleNamesSnapshot {
                values: numbered(&desired.module_names).expect("numbered modules"),
                complete: true,
            },
        };
        let plan =
            build_plan(PowerShellLoggingObservation { hklm, hkcu: None }, desired).expect("plan");
        assert!(plan.mutations.is_empty());
    }

    #[test]
    fn module_replacement_requires_explicit_guard_and_complete_snapshot() {
        let desired =
            resolve_desired_state(&PowerShellLoggingParameters::default()).expect("desired state");
        let mut incomplete = missing_hive();
        incomplete.module_names.complete = false;
        assert!(
            build_plan(
                PowerShellLoggingObservation {
                    hklm: incomplete,
                    hkcu: None
                },
                desired
            )
            .is_err()
        );
    }

    #[test]
    fn missing_values_are_retained_for_rollback() {
        let desired = resolve_desired_state(&PowerShellLoggingParameters {
            replace_module_names: true,
            ..PowerShellLoggingParameters::default()
        })
        .expect("desired state");
        let plan = build_plan(
            PowerShellLoggingObservation {
                hklm: missing_hive(),
                hkcu: None,
            },
            desired,
        )
        .expect("plan");
        assert_eq!(plan.rollback.enable_transcription, ValueSnapshot::Missing);
        assert!(matches!(
            plan.mutations.first(),
            Some(PowerShellLoggingMutation::SetDword { .. })
        ));
    }
}
