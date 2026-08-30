//! Windows observation and guarded mutation for PowerShell logging policy.

use crate::{PlatformError, registry};
use baselineops_capabilities::{
    ModuleNamesSnapshot, PolicyField, PowerShellLoggingHiveSnapshot, PowerShellLoggingMutation,
    PowerShellLoggingObservation, PowerShellLoggingPlan, ValueSnapshot,
    build_powershell_logging_plan,
};
use registry::{RegistryLocation, RegistryRead, RegistryValue, RegistryValueName};
#[cfg(windows)]
use std::path::Path;

/// Maximum numbered module-name values supported by the Windows allowlist.
pub const MAX_MODULE_NAMES: u16 = baselineops_capabilities::MAX_MODULE_NAMES;

/// A complete or intentionally missing `ModuleNames` enumeration result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModuleNamesRead {
    /// Numeric values captured from the allowlisted `ModuleNames` key.
    pub values: std::collections::BTreeMap<u16, String>,
    /// True only when enumeration completed without unknown values or types.
    pub complete: bool,
}

impl ModuleNamesRead {
    /// Construct the complete empty snapshot for an absent `ModuleNames` key.
    #[must_use]
    pub const fn missing() -> Self {
        Self {
            values: std::collections::BTreeMap::new(),
            complete: true,
        }
    }
}

/// Captured before/after state for a single, no-auto-rollback application.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub struct PowerShellLoggingApplyReceipt {
    /// The exact HKLM snapshot captured immediately before mutation.
    pub before: PowerShellLoggingHiveSnapshot,
    /// Exact HKLM snapshot read after every requested change completed.
    pub after: PowerShellLoggingHiveSnapshot,
    /// A retained caller can use this snapshot to build an explicit rollback action.
    pub rollback: PowerShellLoggingHiveSnapshot,
    /// Mutations actually performed; an empty list is an idempotent apply.
    pub applied: Vec<PowerShellLoggingMutation>,
    /// No reboot is required for this policy mutation.
    pub reboot_required: bool,
    /// Policy may take effect only for new PowerShell sessions.
    pub new_sessions_may_be_needed: bool,
}

/// Observe the typed PowerShell policy locations. HKCU is optional and never mutated.
///
/// # Errors
///
/// Returns an error for access failure, unsupported types, or a non-Windows host.
pub fn observe_powershell_logging(
    include_hkcu: bool,
) -> Result<PowerShellLoggingObservation, PlatformError> {
    let hklm = read_hive(false)?;
    let hkcu = include_hkcu.then(|| read_hive(true)).transpose()?;
    Ok(PowerShellLoggingObservation { hklm, hkcu })
}

/// Apply a prebuilt plan without automatic rollback.
///
/// The live HKLM state is re-observed and re-planned before each application, so
/// only still-drifted allowlisted values are written. A first native failure
/// stops the sequence; the returned receipt exists only on an exact read-back.
/// Transcript content is never read or written.
///
/// # Errors
///
/// Returns an error when administrator authority, transcript-path validation,
/// registry mutation, or post-apply exact-state verification fails.
#[allow(dead_code)]
pub(crate) fn apply_powershell_logging_plan(
    plan: &PowerShellLoggingPlan,
) -> Result<PowerShellLoggingApplyReceipt, PlatformError> {
    require_administrator()?;
    validate_transcript_directory(&plan.desired.transcript_output_directory)?;
    let live = observe_powershell_logging(false)?;
    let effective = build_powershell_logging_plan(live, plan.desired.clone())
        .map_err(PlatformError::TrustFailure)?;
    for mutation in &effective.mutations {
        apply_mutation(mutation)?;
    }
    let after = observe_powershell_logging(false)?.hklm;
    let verify = build_powershell_logging_plan(
        PowerShellLoggingObservation {
            hklm: after.clone(),
            hkcu: None,
        },
        effective.desired.clone(),
    )
    .map_err(PlatformError::TrustFailure)?;
    if !verify.mutations.is_empty() {
        return Err(PlatformError::TrustFailure(
            "PowerShell logging policy did not reach exact desired state".into(),
        ));
    }
    Ok(PowerShellLoggingApplyReceipt {
        before: effective.rollback.clone(),
        rollback: effective.rollback,
        after,
        applied: effective.mutations,
        reboot_required: false,
        new_sessions_may_be_needed: true,
    })
}

fn read_hive(current_user: bool) -> Result<PowerShellLoggingHiveSnapshot, PlatformError> {
    let read = |location, name| {
        if current_user {
            registry::read_hkcu_value(location, name)
        } else {
            registry::read_hklm_value(location, name)
        }
    };
    let module_names = if current_user {
        ModuleNamesSnapshot {
            values: std::collections::BTreeMap::default(),
            complete: false,
        }
    } else {
        let values = registry::list_hklm_module_names()?;
        ModuleNamesSnapshot {
            values: values.values,
            complete: values.complete,
        }
    };
    Ok(PowerShellLoggingHiveSnapshot {
        enable_transcription: dword(&read(
            RegistryLocation::PowerShellTranscription,
            RegistryValueName::EnableTranscripting,
        )?)?,
        transcript_output_directory: string(read(
            RegistryLocation::PowerShellTranscription,
            RegistryValueName::OutputDirectory,
        )?)?,
        enable_invocation_header: dword(&read(
            RegistryLocation::PowerShellTranscription,
            RegistryValueName::EnableInvocationHeader,
        )?)?,
        enable_script_block_logging: dword(&read(
            RegistryLocation::PowerShellScriptBlockLogging,
            RegistryValueName::EnableScriptBlockLogging,
        )?)?,
        enable_script_block_invocation_logging: dword(&read(
            RegistryLocation::PowerShellScriptBlockLogging,
            RegistryValueName::EnableScriptBlockInvocationLogging,
        )?)?,
        enable_module_logging: dword(&read(
            RegistryLocation::PowerShellModuleLogging,
            RegistryValueName::EnableModuleLogging,
        )?)?,
        module_names,
    })
}

fn dword(read: &RegistryRead) -> Result<ValueSnapshot<u32>, PlatformError> {
    match read {
        RegistryRead::Missing => Ok(ValueSnapshot::Missing),
        RegistryRead::Present(RegistryValue::Dword(value)) => Ok(ValueSnapshot::Value(*value)),
        RegistryRead::Present(_) => Err(PlatformError::TrustFailure(
            "PowerShell policy value is not REG_DWORD".into(),
        )),
    }
}

fn string(read: RegistryRead) -> Result<ValueSnapshot<String>, PlatformError> {
    match read {
        RegistryRead::Missing => Ok(ValueSnapshot::Missing),
        RegistryRead::Present(RegistryValue::String(value)) => Ok(ValueSnapshot::Value(value)),
        RegistryRead::Present(_) => Err(PlatformError::TrustFailure(
            "PowerShell policy value is not REG_SZ".into(),
        )),
    }
}

fn apply_mutation(mutation: &PowerShellLoggingMutation) -> Result<(), PlatformError> {
    match mutation {
        PowerShellLoggingMutation::SetDword { field, value } => {
            let (location, name) = field_pair(*field);
            registry::set_hklm_value(location, name, RegistryValue::Dword(*value))
        }
        PowerShellLoggingMutation::SetString { field, value } => {
            let (location, name) = field_pair(*field);
            registry::set_hklm_value(location, name, RegistryValue::String(value.clone()))
        }
        PowerShellLoggingMutation::ReplaceModuleNames { values } => {
            let before = registry::list_hklm_module_names()?;
            if !before.complete {
                return Err(PlatformError::TrustFailure(
                    "ModuleNames replacement requires a complete snapshot".into(),
                ));
            }
            for number in before.values.keys() {
                registry::delete_hklm_value(
                    RegistryLocation::PowerShellModuleNames,
                    RegistryValueName::ModuleName(*number),
                )?;
            }
            for (number, value) in values {
                registry::set_hklm_value(
                    RegistryLocation::PowerShellModuleNames,
                    RegistryValueName::ModuleName(*number),
                    RegistryValue::String(value.clone()),
                )?;
            }
            Ok(())
        }
    }
}

fn field_pair(field: PolicyField) -> (RegistryLocation, RegistryValueName) {
    match field {
        PolicyField::EnableTranscription => (
            RegistryLocation::PowerShellTranscription,
            RegistryValueName::EnableTranscripting,
        ),
        PolicyField::TranscriptOutputDirectory => (
            RegistryLocation::PowerShellTranscription,
            RegistryValueName::OutputDirectory,
        ),
        PolicyField::EnableInvocationHeader => (
            RegistryLocation::PowerShellTranscription,
            RegistryValueName::EnableInvocationHeader,
        ),
        PolicyField::EnableScriptBlockLogging => (
            RegistryLocation::PowerShellScriptBlockLogging,
            RegistryValueName::EnableScriptBlockLogging,
        ),
        PolicyField::EnableScriptBlockInvocationLogging => (
            RegistryLocation::PowerShellScriptBlockLogging,
            RegistryValueName::EnableScriptBlockInvocationLogging,
        ),
        PolicyField::EnableModuleLogging => (
            RegistryLocation::PowerShellModuleLogging,
            RegistryValueName::EnableModuleLogging,
        ),
    }
}

fn require_administrator() -> Result<(), PlatformError> {
    Err(PlatformError::TrustFailure(
        "PowerShell logging mutation requires verified Administrator-plan authority".into(),
    ))
}

#[cfg(not(windows))]
fn validate_transcript_directory(_value: &str) -> Result<(), PlatformError> {
    Err(PlatformError::UnsupportedPlatform)
}

#[cfg(windows)]
fn validate_transcript_directory(value: &str) -> Result<(), PlatformError> {
    if value.len() > baselineops_capabilities::MAX_POLICY_STRING_BYTES || value.starts_with(r"\\") {
        return Err(PlatformError::TrustFailure(
            "transcript directory must be a bounded local path".into(),
        ));
    }
    let path = Path::new(value);
    if !path.is_absolute() {
        return Err(PlatformError::TrustFailure(
            "transcript directory must be absolute".into(),
        ));
    }
    let canonical = std::fs::canonicalize(path)?;
    if std::fs::symlink_metadata(path)?.file_type().is_symlink() || canonical != path {
        return Err(PlatformError::TrustFailure(
            "transcript directory must be canonical and non-reparse".into(),
        ));
    }
    if !canonical.is_dir() {
        return Err(PlatformError::TrustFailure(
            "transcript directory must be an existing directory".into(),
        ));
    }
    Ok(())
}
