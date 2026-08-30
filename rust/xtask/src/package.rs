use crate::Roots;
use crate::generate::{generate, generate_sbom};
use crate::support::{copy_regular, copy_tree, hash_file, sorted_files_recursive};
use crate::verify::forbidden_shell_names;
use anyhow::{Context, Result, bail};
use baselineops_engine::{
    DetachedSignatureVerifier, ManifestFile, PackageError, PackageManifestV1, SignatureVerifier,
    verify_package,
};
use std::fs::{self, File};
use std::path::Path;
use zip::write::SimpleFileOptions;

const MANIFEST_NAME: &str = "manifest.json";
const MANIFEST_SIGNATURE_NAME: &str = "manifest.json.p7";

pub(crate) fn stage_package(
    roots: &Roots,
    target: &str,
    output: &Path,
    expected_signer: Option<String>,
    expected_signer_spki_sha256: Option<String>,
) -> Result<()> {
    if target != "x86_64-pc-windows-msvc" {
        bail!("v3 alpha packages only x86_64-pc-windows-msvc");
    }
    generate(roots)?;
    let signer = stage_signer_identity(expected_signer, expected_signer_spki_sha256)?;
    prepare_stage_root(output)?;
    stage_package_inputs(roots, target, output)?;
    reject_shell_payload(output)?;

    let manifest = PackageManifestV1 {
        schema_version: "1.0".into(),
        product: "BaselineOps for Windows".into(),
        package_version: env!("CARGO_PKG_VERSION").into(),
        target: target.into(),
        signer_subject: signer,
        files: manifest_files(output)?,
    };
    let mut manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    manifest_bytes.push(b'\n');
    baselineops_windows::atomic_write(output.join(MANIFEST_NAME), &manifest_bytes)?;
    Ok(())
}

/// Finalize an archive from a signed stage without modifying its authoritative bytes.
pub(crate) fn finalize_package(stage: &Path, output: &Path) -> Result<()> {
    let manifest = stage.join(MANIFEST_NAME);
    let signature = stage.join(MANIFEST_SIGNATURE_NAME);
    for required in [&manifest, &signature] {
        let metadata = fs::symlink_metadata(required)
            .with_context(|| format!("missing staged package member {}", required.display()))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            bail!(
                "staged package member is not a regular file: {}",
                required.display()
            );
        }
    }
    let manifest_bytes = fs::read(&manifest)?;
    write_package_outputs(stage, output, &manifest_bytes)
}

fn prepare_stage_root(stage: &Path) -> Result<()> {
    match fs::symlink_metadata(stage) {
        Ok(metadata) if !metadata.is_dir() || metadata.file_type().is_symlink() => {
            bail!("staging path is not a directory: {}", stage.display())
        }
        Ok(_) if fs::read_dir(stage)?.next().transpose()?.is_some() => {
            bail!("staging directory must be empty: {}", stage.display())
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(stage)?;
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

fn stage_package_inputs(roots: &Roots, target: &str, stage_root: &Path) -> Result<()> {
    let binaries = roots.rust.join("target").join(target).join("release");
    for name in [
        "baselineops.exe",
        "baselineops-gui.exe",
        "baselineops-worker.exe",
    ] {
        copy_regular(&binaries.join(name), &stage_root.join("bin").join(name))?;
    }
    copy_tree(&roots.rust.join("schemas"), &stage_root.join("schemas"))?;
    copy_tree(&roots.rust.join("examples"), &stage_root.join("examples"))?;
    copy_tree(&roots.rust.join("docs"), &stage_root.join("docs"))?;
    copy_tree(&roots.rust.join("ledger"), &stage_root.join("ledger"))?;
    copy_tree(&roots.rust.join("release"), &stage_root.join("release"))?;
    copy_regular(&roots.rust.join("README.md"), &stage_root.join("README.md"))?;
    copy_regular(
        &roots.repository.join("LICENSE"),
        &stage_root.join("LICENSE"),
    )?;
    let sbom = generate_sbom(roots)?;
    baselineops_windows::atomic_write(stage_root.join("sbom.cdx.json"), &sbom)?;
    Ok(())
}

fn write_package_outputs(root: &Path, output: &Path, manifest_bytes: &[u8]) -> Result<()> {
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    write_zip(root, output)?;
    let package_digest = hash_file(output)?;
    let file_name = output
        .file_name()
        .and_then(|name| name.to_str())
        .context("ZIP name is not Unicode")?;
    baselineops_windows::atomic_write(
        output.with_extension("zip.sha256"),
        format!("{}  {file_name}\n", package_digest.to_hex()).as_bytes(),
    )?;
    baselineops_windows::atomic_write(output.with_extension("zip.manifest.json"), manifest_bytes)?;
    Ok(())
}

pub(crate) fn package_verify(
    package: &Path,
    expected_signer: &str,
    expected_signer_spki_sha256: &str,
) -> Result<()> {
    let spki_sha256 = baselineops_windows::SignerSpkiSha256::from_hex(expected_signer_spki_sha256)
        .map_err(|error| anyhow::anyhow!(error))?;
    let result = verify_package(
        package,
        expected_signer,
        &WindowsDetachedSignature {
            spki_sha256: spki_sha256.clone(),
        },
        &ExpectedSignature {
            subject: expected_signer,
            spki_sha256,
        },
    )?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

struct WindowsDetachedSignature {
    spki_sha256: baselineops_windows::SignerSpkiSha256,
}

impl DetachedSignatureVerifier for WindowsDetachedSignature {
    fn verify(
        &self,
        signed_bytes: &[u8],
        signature_bytes: &[u8],
        expected_subject: &str,
    ) -> Result<(), PackageError> {
        baselineops_windows::verify_detached_manifest(
            signed_bytes,
            signature_bytes,
            expected_subject,
            &self.spki_sha256,
        )
        .map_err(|error| PackageError::Signature(error.to_string()))
    }
}

struct ExpectedSignature<'a> {
    subject: &'a str,
    spki_sha256: baselineops_windows::SignerSpkiSha256,
}

impl SignatureVerifier for ExpectedSignature<'_> {
    fn verify(&self, executable: &Path, expected_subject: &str) -> Result<(), PackageError> {
        if expected_subject != self.subject {
            return Err(PackageError::Signature(
                "package verifier received an untrusted signer".into(),
            ));
        }
        baselineops_windows::verify_authenticode(executable, self.subject, &self.spki_sha256)
            .map_err(|error| PackageError::Signature(error.to_string()))
    }
}

fn stage_signer_identity(
    expected_signer: Option<String>,
    expected_signer_spki_sha256: Option<String>,
) -> Result<String> {
    match (expected_signer, expected_signer_spki_sha256) {
        (None, None) => Ok("UNSIGNED-LOCAL-BUILD".into()),
        (Some(subject), Some(pin))
            if !subject.trim().is_empty() && subject != "UNSIGNED-LOCAL-BUILD" =>
        {
            baselineops_windows::SignerSpkiSha256::from_hex(&pin)
                .map_err(|error| anyhow::anyhow!(error))?;
            Ok(subject)
        }
        _ => bail!(
            "signed package staging requires both a non-empty external signer subject and lowercase SPKI SHA-256 pin"
        ),
    }
}

fn manifest_files(root: &Path) -> Result<Vec<ManifestFile>> {
    let mut files = Vec::new();
    for path in sorted_files_recursive(root)? {
        let relative = path
            .strip_prefix(root)?
            .to_string_lossy()
            .replace('\\', "/");
        if relative == MANIFEST_NAME || relative == MANIFEST_SIGNATURE_NAME {
            continue;
        }
        files.push(ManifestFile {
            path: relative,
            size_bytes: path.metadata()?.len(),
            sha256: hash_file(&path)?,
        });
    }
    files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(files)
}

fn write_zip(root: &Path, output: &Path) -> Result<()> {
    let file = File::create(output)?;
    let mut writer = zip::ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .unix_permissions(0o644);
    for path in sorted_files_recursive(root)? {
        let relative = path
            .strip_prefix(root)?
            .to_string_lossy()
            .replace('\\', "/");
        writer.start_file(relative, options)?;
        let mut source = File::open(path)?;
        std::io::copy(&mut source, &mut writer)?;
    }
    writer.finish()?.sync_all()?;
    Ok(())
}

fn reject_shell_payload(root: &Path) -> Result<()> {
    let shell_names = forbidden_shell_names();
    for path in sorted_files_recursive(root)? {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        let forbidden_extension = Path::new(&name).extension().is_some_and(|extension| {
            extension.eq_ignore_ascii_case("ps1")
                || extension.eq_ignore_ascii_case("bat")
                || extension.eq_ignore_ascii_case("cmd")
        });
        if forbidden_extension || shell_names.contains(&name) {
            bail!(
                "package would ship a forbidden shell payload: {}",
                path.display()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_staging_requires_an_external_subject_and_canonical_pin() {
        let pin = "ab".repeat(32);
        assert_eq!(
            stage_signer_identity(Some("CN=BaselineOps".into()), Some(pin)).expect("signer"),
            "CN=BaselineOps"
        );
        assert_eq!(
            stage_signer_identity(None, None).expect("unsigned local build"),
            "UNSIGNED-LOCAL-BUILD"
        );
        assert!(stage_signer_identity(Some("CN=BaselineOps".into()), None).is_err());
        assert!(stage_signer_identity(None, Some("ab".repeat(32))).is_err());
        assert!(
            stage_signer_identity(Some("CN=BaselineOps".into()), Some("AB".repeat(32))).is_err()
        );
    }
}
