use crate::Roots;
use crate::generate::generated_schemas;
use crate::support::{sorted_files, sorted_files_recursive};
use anyhow::{Context, Result, bail};
use baselineops_domain::{JsonLoadLimits, ProfileV3};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

pub(crate) fn verify(roots: &Roots) -> Result<()> {
    verify_registry_and_ledger(roots)?;
    verify_rust_source_hygiene(roots)?;
    for (name, expected) in generated_schemas()? {
        let path = roots.rust.join("schemas").join(name);
        let actual = fs::read(&path)
            .with_context(|| format!("missing generated schema {}", path.display()))?;
        if actual != expected {
            bail!(
                "schema snapshot is stale: {} (run cargo run -p xtask -- generate)",
                path.display()
            );
        }
    }
    for profile in sorted_files(&roots.rust.join("examples/profiles"))? {
        let profile: ProfileV3 =
            baselineops_domain::load_json_file(&profile, JsonLoadLimits::default())?;
        profile
            .validate()
            .with_context(|| format!("invalid example profile {}", profile.id))?;
    }
    verify_external_evidence_inventory(roots, false)?;
    verify_no_shell_contract(roots)
}

pub(crate) fn release_check(
    roots: &Roots,
    expected_signer: &str,
    expected_signer_spki_sha256: &str,
    release_tag: &str,
) -> Result<()> {
    verify(roots)?;
    verify_release_identity(expected_signer, expected_signer_spki_sha256, release_tag)?;
    verify_capability_closure()?;
    verify_external_evidence_inventory(roots, true)
}

fn verify_release_identity(
    expected_signer: &str,
    expected_signer_spki_sha256: &str,
    release_tag: &str,
) -> Result<()> {
    let expected_tag = format!("rust-v{}", env!("CARGO_PKG_VERSION"));
    if release_tag != expected_tag {
        bail!("release tag {release_tag} does not match workspace version {expected_tag}");
    }
    if expected_signer.trim().is_empty() || expected_signer == "UNSIGNED-LOCAL-BUILD" {
        bail!("release requires a non-empty external Authenticode signer identity");
    }
    baselineops_windows::SignerSpkiSha256::from_hex(expected_signer_spki_sha256)
        .map_err(|error| anyhow::anyhow!(error))?;
    Ok(())
}

fn verify_capability_closure() -> Result<()> {
    let incomplete = baselineops_capabilities::list()
        .iter()
        .filter(|descriptor| {
            descriptor.maturity != baselineops_capabilities::ImplementationMaturity::Implemented
        })
        .map(|descriptor| descriptor.id)
        .collect::<Vec<_>>();
    if !incomplete.is_empty() {
        bail!(
            "release requires all 52 native capabilities to be implemented; incomplete: {}",
            incomplete.join(", ")
        );
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseEvidenceFile {
    schema_version: u8,
    gates: BTreeMap<String, ReleaseEvidenceGate>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseEvidenceGate {
    closed: bool,
    evidence: String,
}

fn verify_external_evidence_inventory(roots: &Roots, require_closed: bool) -> Result<()> {
    const REQUIRED: [&str; 14] = [
        "authenticated_package_closure",
        "protected_install_runtime",
        "process_spy",
        "gui_accessibility",
        "local_system",
        "windows_11_pro_24h2",
        "windows_11_pro_25h2",
        "windows_11_pro_26h1",
        "windows_11_enterprise_24h2",
        "windows_11_enterprise_25h2",
        "windows_11_enterprise_26h1",
        "hardware_tpm",
        "hardware_secure_boot",
        "hardware_bitlocker",
    ];
    let path = roots.rust.join("release/evidence-gates.json");
    let evidence: ReleaseEvidenceFile = serde_json::from_slice(&fs::read(&path)?)?;
    if evidence.schema_version != 1 || evidence.gates.len() != REQUIRED.len() {
        bail!("release evidence gate inventory is incomplete");
    }
    let mut open = Vec::new();
    for required in REQUIRED {
        let gate = evidence
            .gates
            .get(required)
            .with_context(|| format!("release evidence gate is absent: {required}"))?;
        if gate.evidence.trim().is_empty() {
            bail!("release evidence gate has no evidence reference: {required}");
        }
        if !gate.closed {
            open.push(required);
        }
    }
    if require_closed && !open.is_empty() {
        bail!("release evidence gates remain open: {}", open.join(", "));
    }
    Ok(())
}

fn verify_registry_and_ledger(roots: &Roots) -> Result<()> {
    let registry = baselineops_capabilities::list();
    verify_registry_sequence(registry)?;
    let ledger_path = roots.rust.join("ledger/capability-parity.json");
    let ledger: Value = serde_json::from_slice(&fs::read(ledger_path)?)?;
    let entries = ledger["entries"]
        .as_array()
        .context("ledger entries must be an array")?;
    verify_ledger_alignment(registry, entries)
}

fn verify_registry_sequence(
    registry: &[baselineops_capabilities::CapabilityDescriptor],
) -> Result<()> {
    if registry.len() != 52 {
        bail!("registry must contain exactly 52 capabilities");
    }
    let mut ids = BTreeSet::new();
    for (index, descriptor) in registry.iter().enumerate() {
        if descriptor.legacy_number != u8::try_from(index + 1)? || !ids.insert(descriptor.id) {
            bail!("registry IDs or legacy numbers are incomplete/duplicated");
        }
    }
    Ok(())
}

fn verify_ledger_alignment(
    registry: &[baselineops_capabilities::CapabilityDescriptor],
    entries: &[Value],
) -> Result<()> {
    if entries.len() != 52 {
        bail!("parity ledger must contain exactly 52 entries");
    }
    for (descriptor, entry) in registry.iter().zip(entries) {
        if entry["number"].as_u64() != Some(u64::from(descriptor.legacy_number))
            || entry["id"].as_str() != Some(descriptor.id)
            || entry["script"].as_str() != Some(descriptor.legacy_script)
        {
            bail!("parity ledger diverges at capability {}", descriptor.id);
        }
        verify_implemented_evidence(descriptor, entry)?;
    }
    Ok(())
}

fn verify_implemented_evidence(
    descriptor: &baselineops_capabilities::CapabilityDescriptor,
    entry: &Value,
) -> Result<()> {
    if descriptor.maturity != baselineops_capabilities::ImplementationMaturity::Implemented {
        return Ok(());
    }
    let evidence = entry["evidence"].as_str().unwrap_or_default();
    if entry["status"].as_str() != Some("implemented") || evidence.trim().is_empty() {
        bail!(
            "implemented capability lacks closed evidence: {}",
            descriptor.id
        );
    }
    Ok(())
}

fn verify_no_shell_contract(roots: &Roots) -> Result<()> {
    let forbidden = forbidden_shell_names();
    for path in sorted_files_recursive(&roots.rust)? {
        if !is_handwritten_rust_source(&path, &roots.rust) {
            continue;
        }
        let text = fs::read_to_string(&path)?;
        for token in &forbidden {
            if text.to_ascii_lowercase().contains(token) {
                bail!(
                    "forbidden shell executable token {token} in {}",
                    path.display()
                );
            }
        }
    }
    Ok(())
}

pub(crate) fn forbidden_shell_names() -> [String; 3] {
    [
        ["power", "shell.exe"].concat(),
        ["pw", "sh.exe"].concat(),
        ["c", "md.exe"].concat(),
    ]
}

fn verify_rust_source_hygiene(roots: &Roots) -> Result<()> {
    const MAX_SOURCE_LINES: usize = 600;
    for path in sorted_files_recursive(&roots.rust)? {
        if !is_handwritten_rust_source(&path, &roots.rust) {
            continue;
        }
        let bytes = fs::read(&path)?;
        let line_count = bytes.split(|byte| *byte == b'\n').count();
        if line_count > MAX_SOURCE_LINES {
            bail!(
                "hand-written Rust source exceeds {MAX_SOURCE_LINES} lines: {} ({line_count})",
                path.display()
            );
        }
        if bytes.windows(2).any(|pair| pair == b"\r\n") {
            bail!("hand-written Rust source uses CRLF: {}", path.display());
        }
    }
    Ok(())
}

fn is_handwritten_rust_source(path: &Path, rust_root: &Path) -> bool {
    if path.extension().and_then(|value| value.to_str()) != Some("rs") {
        return false;
    }
    let Ok(relative) = path.strip_prefix(rust_root) else {
        return false;
    };
    !relative
        .components()
        .any(|component| component.as_os_str() == "target" || component.as_os_str() == ".git")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_identity_binds_exact_tag_and_external_signer() {
        let tag = format!("rust-v{}", env!("CARGO_PKG_VERSION"));
        let pin = "ab".repeat(32);
        assert!(verify_release_identity("CN=BaselineOps", &pin, &tag).is_ok());
        assert!(verify_release_identity("CN=BaselineOps", &pin, "rust-v0.0.0").is_err());
        assert!(verify_release_identity("UNSIGNED-LOCAL-BUILD", &pin, &tag).is_err());
        assert!(verify_release_identity(" ", &pin, &tag).is_err());
        assert!(verify_release_identity("CN=BaselineOps", &"AB".repeat(32), &tag).is_err());
    }
}
