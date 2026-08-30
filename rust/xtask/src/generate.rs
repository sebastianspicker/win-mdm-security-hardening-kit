use crate::Roots;
use anyhow::{Context, Result, bail};
use baselineops_domain::{FindingV3, PlanV3, ProfileV3, ResultV3};
use serde_json::{Value, json};
use std::fs;
use std::process::Command;

pub(crate) fn generate(roots: &Roots) -> Result<()> {
    fs::create_dir_all(roots.rust.join("schemas"))?;
    for (name, bytes) in generated_schemas()? {
        baselineops_windows::atomic_write(roots.rust.join("schemas").join(name), &bytes)?;
    }
    let sbom = generate_sbom(roots)?;
    baselineops_windows::atomic_write(roots.rust.join("schemas/workspace.cdx.json"), &sbom)?;
    Ok(())
}

pub(crate) fn generated_schemas() -> Result<Vec<(&'static str, Vec<u8>)>> {
    Ok(vec![
        (
            "profile-v3.schema.json",
            schema_bytes(&schemars::schema_for!(ProfileV3))?,
        ),
        (
            "plan-v3.schema.json",
            schema_bytes(&schemars::schema_for!(PlanV3))?,
        ),
        (
            "result-v3.schema.json",
            schema_bytes(&schemars::schema_for!(ResultV3))?,
        ),
        (
            "finding-v3.schema.json",
            schema_bytes(&schemars::schema_for!(FindingV3))?,
        ),
    ])
}

fn schema_bytes(schema: &schemars::Schema) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(schema)?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub(crate) fn generate_sbom(roots: &Roots) -> Result<Vec<u8>> {
    let output = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--locked"])
        .current_dir(&roots.rust)
        .output()?;
    if !output.status.success() {
        bail!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let metadata: Value = serde_json::from_slice(&output.stdout)?;
    let components = metadata["packages"]
        .as_array()
        .context("cargo metadata packages are absent")?
        .iter()
        .map(|package| {
            json!({
                "type": "library",
                "name": package["name"],
                "version": package["version"],
                "purl": format!("pkg:cargo/{}@{}", package["name"].as_str().unwrap_or_default(), package["version"].as_str().unwrap_or_default())
            })
        })
        .collect::<Vec<_>>();
    let sbom = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": { "component": { "type": "application", "name": "BaselineOps for Windows", "version": env!("CARGO_PKG_VERSION") } },
        "components": components
    });
    let mut bytes = serde_json::to_vec_pretty(&sbom)?;
    bytes.push(b'\n');
    Ok(bytes)
}
