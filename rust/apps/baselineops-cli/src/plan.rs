//! Worker-plan-only proposal composition. Current registry entries reject mutations.

use crate::{Selection, resolve_selection, unsupported_response};
use anyhow::{Context, Result, anyhow, bail};
use baselineops_domain::{
    ExecutionIntent, ExitCode, InputIdentityV3, JsonLoadLimits, ObservedStateV3, ObservedValueV3,
    ProfileV3, SourceIdentityV3, SourceKind, ToolIdentityV3,
};
use baselineops_engine::{InstalledPackageExpectation, verify_installed_package};
use baselineops_engine::{PlanBuildContext, RegistryActionDeriver, build_plan};
use chrono::{Duration, Utc};
use std::{collections::BTreeMap, path::Path};

pub(crate) fn run(selection: &Selection, output: &Path) -> Result<ExitCode> {
    if output.as_os_str().is_empty() {
        bail!("plan output path is empty");
    }
    if !cfg!(windows) {
        return unsupported_response("plan", &["Windows protected worker"]);
    }
    let profile_path = selection.profile.as_ref().ok_or_else(|| {
        anyhow!("plan requires a profile so source and input bindings can be retained")
    })?;
    let profile_path = std::fs::canonicalize(profile_path)?;
    let bytes = baselineops_windows::read_bounded_utf8(
        &profile_path,
        baselineops_windows::MAX_INPUT_BYTES,
    )?
    .into_bytes();
    let profile: ProfileV3 = baselineops_domain::load_json(&bytes, JsonLoadLimits::default())?;
    profile.validate()?;
    let (descriptors, _) = resolve_selection(selection)?;
    let host = baselineops_windows::collect_host_identity()?;
    let observed_state = observe(&profile, &descriptors)?;
    let digest = baselineops_domain::Sha256Digest::of_bytes(&bytes);
    let executable = std::env::current_exe()?;
    let package_digest = installed_package_digest(&executable)?;
    let context = PlanBuildContext {
        intent: ExecutionIntent::Apply,
        host,
        tool: ToolIdentityV3 {
            name: "baselineops".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            build_digest: Some(package_digest),
        },
        package_digest,
        source: SourceIdentityV3 {
            kind: SourceKind::LocalFile,
            locator: profile_path.display().to_string(),
            digest,
        },
        input: InputIdentityV3 {
            digest,
            size_bytes: u64::try_from(bytes.len())?,
        },
        observed_state,
        lifetime: Duration::minutes(5),
    };
    match build_plan(&profile, context, &RegistryActionDeriver, Utc::now()) {
        Ok(worker_plan) => {
            let body = serde_json::to_vec_pretty(worker_plan.proposal())?;
            baselineops_windows::atomic_write(output, &body)?;
            crate::print_json(
                &serde_json::json!({"status":"proposed","digest":worker_plan.digest().to_hex(),"plan":worker_plan.proposal()}),
            )?;
            Ok(ExitCode::Completed)
        }
        Err(baselineops_engine::PlanningError::Derivation(_)) => unsupported_response(
            "plan",
            &descriptors
                .iter()
                .map(|descriptor| descriptor.id)
                .collect::<Vec<_>>(),
        ),
        Err(error) => Err(error.into()),
    }
}

fn installed_package_digest(executable: &Path) -> Result<baselineops_domain::Sha256Digest> {
    let bin = executable
        .parent()
        .context("CLI executable has no package bin directory")?;
    let root = bin
        .parent()
        .context("CLI executable has no installation root")?;
    let signer = crate::release_signer_identity()?;
    let installation = baselineops_windows::verify_protected_install(
        &baselineops_windows::InstallationTrustPolicy {
            root: root.to_path_buf(),
            publisher_subject: signer.subject.clone(),
            publisher_spki_sha256: signer.spki_sha256.clone(),
            validate_ancestors: true,
        },
        executable,
    )?;
    Ok(verify_installed_package(
        installation.root(),
        InstalledPackageExpectation {
            product: "BaselineOps for Windows",
            package_version: env!("CARGO_PKG_VERSION"),
            target: "x86_64-pc-windows-msvc",
            signer_subject: &signer.subject,
        },
        &crate::PlatformDetachedSignatureVerifier::new(&signer),
        &crate::PlatformSignatureVerifier::new(&signer),
    )?
    .binding_digest())
}

fn observe(
    profile: &ProfileV3,
    descriptors: &[&'static baselineops_capabilities::CapabilityDescriptor],
) -> Result<ObservedStateV3> {
    let mut values = BTreeMap::new();
    for step in &profile.steps {
        let descriptor = descriptors
            .iter()
            .copied()
            .find(|descriptor| descriptor.id == step.capability_id.as_str())
            .ok_or_else(|| anyhow!("profile descriptor is unavailable"))?;
        let parameters = serde_json::to_value(&step.parameters)?;
        let outcome = crate::audit::dispatch_native_audit(descriptor, &parameters);
        let baselineops_capabilities::CapabilityOutcome::Completed { result } = outcome else {
            bail!("trusted observation failed for {}", descriptor.id)
        };
        values.insert(
            step.capability_id.clone(),
            ObservedValueV3 {
                observed_at: Utc::now(),
                facts: BTreeMap::from([("native_result".into(), result)]),
            },
        );
    }
    let mut observed = ObservedStateV3 {
        captured_at: Utc::now(),
        digest: baselineops_domain::Sha256Digest::of_bytes([]),
        values,
    };
    observed.digest = observed.calculated_digest()?;
    Ok(observed)
}
