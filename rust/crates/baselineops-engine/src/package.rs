use baselineops_domain::Sha256Digest;
use baselineops_windows::{ArchivePolicy, extract_zip_safely};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

pub(crate) const MANIFEST_PATH: &str = "manifest.json";
pub(crate) const MANIFEST_SIGNATURE_PATH: &str = "manifest.json.p7";
pub(crate) const REQUIRED_EXECUTABLES: [&str; 3] = [
    "bin/baselineops.exe",
    "bin/baselineops-gui.exe",
    "bin/baselineops-worker.exe",
];

/// One immutable file in a v3 package.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ManifestFile {
    /// Portable forward-slash path relative to package root.
    pub path: String,
    /// Exact byte length.
    pub size_bytes: u64,
    /// SHA-256 over the packaged bytes.
    pub sha256: Sha256Digest,
}

/// Signed-payload manifest shipped inside every package.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PackageManifestV1 {
    /// Manifest schema marker.
    pub schema_version: String,
    /// Distribution identity.
    pub product: String,
    /// Rust package version.
    pub package_version: String,
    /// Rust target triple.
    pub target: String,
    /// Exact expected Authenticode certificate subject.
    pub signer_subject: String,
    /// Complete package inventory excluding manifest bytes and their detached signature.
    pub files: Vec<ManifestFile>,
}

/// Result of structural, digest, inventory, and signature verification.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct PackageVerification {
    /// Parsed manifest.
    pub manifest: PackageManifestV1,
    /// Digest of the outer ZIP bytes.
    pub package_sha256: Sha256Digest,
    /// Number of payload files verified.
    pub verified_files: usize,
    /// Number of executable signatures verified.
    pub verified_signatures: usize,
}

/// Platform signature port. Windows production uses `WinVerifyTrust`, while tests use a fixture.
pub trait SignatureVerifier {
    /// Verify one executable and its exact expected signer.
    ///
    /// # Errors
    ///
    /// Returns [`PackageError::Signature`] when trust cannot be proved.
    fn verify(&self, executable: &Path, expected_subject: &str) -> Result<(), PackageError>;
}

/// Detached PKCS#7 verifier for the exact manifest bytes.
///
/// The expected subject comes from an external release policy. Implementations
/// must validate the signature before any manifest field becomes trusted.
pub trait DetachedSignatureVerifier {
    /// Verify a detached signature over exactly `signed_bytes`.
    ///
    /// # Errors
    ///
    /// Returns [`PackageError::Signature`] when the signature, signer, or
    /// certificate chain cannot be proved.
    fn verify(
        &self,
        signed_bytes: &[u8],
        signature_bytes: &[u8],
        expected_subject: &str,
    ) -> Result<(), PackageError>;
}

/// Verify a package from a fresh extraction without executing its contents.
///
/// # Errors
///
/// Rejects malformed archives, incomplete inventories, digest mismatches, and untrusted signers.
pub fn verify_package(
    package: impl AsRef<Path>,
    expected_signer_subject: &str,
    detached_signature_verifier: &dyn DetachedSignatureVerifier,
    signature_verifier: &dyn SignatureVerifier,
) -> Result<PackageVerification, PackageError> {
    if expected_signer_subject.trim().is_empty() {
        return Err(PackageError::Signature(
            "an external release signer subject is required".into(),
        ));
    }
    let snapshot = snapshot_package(package.as_ref())?;
    let package_sha256 = hash_file(snapshot.path())?;
    let extraction = tempfile::tempdir()?;
    let extraction_root = fs::canonicalize(extraction.path())?;
    let archive = File::open(snapshot.path())?;
    let extracted = extract_zip_safely(archive, &extraction_root, ArchivePolicy::default())?;
    let mut actual = BTreeMap::new();
    for path in extracted {
        let relative = path
            .strip_prefix(&extraction_root)
            .map_err(|_| {
                PackageError::InvalidManifest("extracted path escaped package root".into())
            })?
            .to_string_lossy()
            .replace('\\', "/");
        let metadata = path.metadata()?;
        actual.insert(relative, (path, metadata.len()));
    }
    let manifest_path = require_unique_special_member(&actual, MANIFEST_PATH)?;
    let manifest_signature_path = require_unique_special_member(&actual, MANIFEST_SIGNATURE_PATH)?;
    let manifest_bytes = fs::read(manifest_path)?;
    let manifest_signature_bytes = fs::read(manifest_signature_path)?;
    detached_signature_verifier.verify(
        &manifest_bytes,
        &manifest_signature_bytes,
        expected_signer_subject,
    )?;
    let manifest: PackageManifestV1 = serde_json::from_slice(&manifest_bytes)?;
    validate_manifest(&manifest)?;
    if manifest.signer_subject != expected_signer_subject {
        return Err(PackageError::Signature(
            "manifest signer differs from the trusted release signer".into(),
        ));
    }
    actual.remove(MANIFEST_PATH);
    actual.remove(MANIFEST_SIGNATURE_PATH);
    if actual.len() != manifest.files.len() {
        return Err(PackageError::InventoryMismatch(format!(
            "manifest lists {} files but package contains {}",
            manifest.files.len(),
            actual.len()
        )));
    }
    for expected in &manifest.files {
        let (path, size) = actual.get(&expected.path).ok_or_else(|| {
            PackageError::InventoryMismatch(format!("manifest file is absent: {}", expected.path))
        })?;
        if *size != expected.size_bytes || hash_file(path)? != expected.sha256 {
            return Err(PackageError::InventoryMismatch(format!(
                "size or digest mismatch: {}",
                expected.path
            )));
        }
    }
    for executable in REQUIRED_EXECUTABLES {
        let (path, _) = actual.get(executable).ok_or_else(|| {
            PackageError::InventoryMismatch(format!("required executable is absent: {executable}"))
        })?;
        signature_verifier.verify(path, expected_signer_subject)?;
    }
    Ok(PackageVerification {
        verified_files: manifest.files.len(),
        verified_signatures: REQUIRED_EXECUTABLES.len(),
        manifest,
        package_sha256,
    })
}

fn require_unique_special_member<'a>(
    actual: &'a BTreeMap<String, (std::path::PathBuf, u64)>,
    member: &str,
) -> Result<&'a Path, PackageError> {
    actual
        .get(member)
        .map(|(path, _)| path.as_path())
        .ok_or_else(|| PackageError::Signature(format!("package is missing required {member}")))
}

fn snapshot_package(package: &Path) -> Result<tempfile::NamedTempFile, PackageError> {
    let mut source = File::open(package)?;
    let mut snapshot = tempfile::NamedTempFile::new()?;
    std::io::copy(&mut source, snapshot.as_file_mut())?;
    snapshot.as_file_mut().sync_all()?;
    Ok(snapshot)
}

pub(crate) fn validate_manifest(manifest: &PackageManifestV1) -> Result<(), PackageError> {
    validate_manifest_identity(manifest)?;
    validate_manifest_paths(&manifest.files)?;
    validate_required_executables(&manifest.files)
}

fn validate_manifest_identity(manifest: &PackageManifestV1) -> Result<(), PackageError> {
    if manifest.schema_version != "1.0" {
        return invalid_manifest_identity();
    }
    if manifest.product != "BaselineOps for Windows" {
        return invalid_manifest_identity();
    }
    if manifest.package_version.trim().is_empty() {
        return invalid_manifest_identity();
    }
    if manifest.target != "x86_64-pc-windows-msvc" {
        return invalid_manifest_identity();
    }
    if manifest.signer_subject.trim().is_empty() {
        return invalid_manifest_identity();
    }
    Ok(())
}

fn invalid_manifest_identity<T>() -> Result<T, PackageError> {
    Err(PackageError::InvalidManifest(
        "manifest identity, target, version, or signer is invalid".into(),
    ))
}

fn validate_manifest_paths(files: &[ManifestFile]) -> Result<(), PackageError> {
    let mut paths = BTreeSet::new();
    for file in files {
        if !is_safe_manifest_path(&file.path) || !paths.insert(file.path.to_ascii_lowercase()) {
            return Err(PackageError::InvalidManifest(format!(
                "manifest path is unsafe or ambiguous: {}",
                file.path
            )));
        }
    }
    Ok(())
}

fn is_safe_manifest_path(value: &str) -> bool {
    if value.is_empty() || value.contains(['\\', ':']) {
        return false;
    }
    let path = Path::new(value);
    if path.is_absolute() {
        return false;
    }
    if value
        .split('/')
        .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return false;
    }
    path.components()
        .all(|component| matches!(component, std::path::Component::Normal(_)))
}

fn validate_required_executables(files: &[ManifestFile]) -> Result<(), PackageError> {
    for required in REQUIRED_EXECUTABLES {
        if !files.iter().any(|file| file.path == required) {
            return Err(PackageError::InvalidManifest(format!(
                "manifest omits required executable: {required}"
            )));
        }
    }
    Ok(())
}

pub(crate) fn hash_file(path: impl AsRef<Path>) -> Result<Sha256Digest, PackageError> {
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(Sha256Digest::from_digest_bytes(hash.finalize().into()))
}

/// Package validation failures map to rejected input/trust exit code 4.
#[derive(Debug, thiserror::Error)]
pub enum PackageError {
    /// File operation failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Safe extraction rejected the ZIP.
    #[error(transparent)]
    Platform(#[from] baselineops_windows::PlatformError),
    /// Strict manifest parsing failed.
    #[error(transparent)]
    Domain(#[from] baselineops_domain::DomainError),
    /// Strict manifest parsing failed after authenticating the exact bytes.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// Manifest fields were invalid.
    #[error("invalid package manifest: {0}")]
    InvalidManifest(String),
    /// ZIP bytes and manifest inventory disagreed.
    #[error("package inventory mismatch: {0}")]
    InventoryMismatch(String),
    /// Authenticode or signer validation failed.
    #[error("package signature verification failed: {0}")]
    Signature(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use zip::write::SimpleFileOptions;

    struct CountingVerifier(AtomicUsize);

    impl SignatureVerifier for CountingVerifier {
        fn verify(&self, executable: &Path, expected_subject: &str) -> Result<(), PackageError> {
            assert!(executable.is_file());
            assert_eq!(expected_subject, "CN=BaselineOps Test");
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    struct DetachedFixtureVerifier {
        calls: AtomicUsize,
        subject: &'static str,
    }

    impl DetachedSignatureVerifier for DetachedFixtureVerifier {
        fn verify(
            &self,
            signed_bytes: &[u8],
            signature_bytes: &[u8],
            expected_subject: &str,
        ) -> Result<(), PackageError> {
            if expected_subject != self.subject
                || signature_bytes != b"fixture detached signature"
                || !signed_bytes.starts_with(b"{\"schema_version\"")
            {
                return Err(PackageError::Signature(
                    "fixture rejected detached signature bytes or signer".into(),
                ));
            }
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    struct RejectingDetachedVerifier(AtomicUsize);

    impl DetachedSignatureVerifier for RejectingDetachedVerifier {
        fn verify(&self, _: &[u8], _: &[u8], _: &str) -> Result<(), PackageError> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Err(PackageError::Signature(
                "fixture rejected detached signature".into(),
            ))
        }
    }

    fn write_fixture_package(
        tamper_digest: bool,
        include_signature: bool,
        signer: &str,
        signature: &[u8],
    ) -> tempfile::NamedTempFile {
        let payloads = [
            ("bin/baselineops.exe", b"cli".as_slice()),
            ("bin/baselineops-gui.exe", b"gui".as_slice()),
            ("bin/baselineops-worker.exe", b"worker".as_slice()),
            ("schemas/profile-v3.schema.json", b"{}".as_slice()),
        ];
        let mut files = payloads
            .iter()
            .map(|(path, bytes)| ManifestFile {
                path: (*path).to_owned(),
                size_bytes: u64::try_from(bytes.len()).expect("fixture size"),
                sha256: Sha256Digest::of_bytes(bytes),
            })
            .collect::<Vec<_>>();
        if tamper_digest {
            files[0].sha256 = Sha256Digest::of_bytes(b"different");
        }
        let manifest = PackageManifestV1 {
            schema_version: "1.0".into(),
            product: "BaselineOps for Windows".into(),
            package_version: "3.0.0-alpha.1".into(),
            target: "x86_64-pc-windows-msvc".into(),
            signer_subject: signer.into(),
            files,
        };
        let output = tempfile::NamedTempFile::new().expect("package");
        {
            let mut zip = zip::ZipWriter::new(output.reopen().expect("package writer"));
            for (path, bytes) in payloads {
                zip.start_file(path, SimpleFileOptions::default())
                    .expect("payload member");
                zip.write_all(bytes).expect("payload bytes");
            }
            zip.start_file(MANIFEST_PATH, SimpleFileOptions::default())
                .expect("manifest member");
            zip.write_all(&serde_json::to_vec(&manifest).expect("manifest JSON"))
                .expect("manifest bytes");
            if include_signature {
                zip.start_file(MANIFEST_SIGNATURE_PATH, SimpleFileOptions::default())
                    .expect("signature member");
                zip.write_all(signature).expect("signature bytes");
            }
            zip.finish().expect("finish ZIP");
        }
        output
    }

    #[test]
    fn complete_package_verifies_every_required_signature() {
        let package = write_fixture_package(
            false,
            true,
            "CN=BaselineOps Test",
            b"fixture detached signature",
        );
        let detached = DetachedFixtureVerifier {
            calls: AtomicUsize::new(0),
            subject: "CN=BaselineOps Test",
        };
        let verifier = CountingVerifier(AtomicUsize::new(0));
        let result = verify_package(package.path(), "CN=BaselineOps Test", &detached, &verifier)
            .expect("valid package");
        assert_eq!(result.verified_files, 4);
        assert_eq!(result.verified_signatures, 3);
        assert_eq!(verifier.0.load(Ordering::Relaxed), 3);
        assert_eq!(detached.calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn digest_tampering_is_rejected_before_signature_checks() {
        let package = write_fixture_package(
            true,
            true,
            "CN=BaselineOps Test",
            b"fixture detached signature",
        );
        let detached = DetachedFixtureVerifier {
            calls: AtomicUsize::new(0),
            subject: "CN=BaselineOps Test",
        };
        let verifier = CountingVerifier(AtomicUsize::new(0));
        assert!(matches!(
            verify_package(package.path(), "CN=BaselineOps Test", &detached, &verifier),
            Err(PackageError::InventoryMismatch(_))
        ));
        assert_eq!(verifier.0.load(Ordering::Relaxed), 0);
        assert_eq!(detached.calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn signer_identity_requires_an_external_trust_anchor() {
        let package = write_fixture_package(
            false,
            true,
            "CN=BaselineOps Test",
            b"fixture detached signature",
        );
        let detached = DetachedFixtureVerifier {
            calls: AtomicUsize::new(0),
            subject: "CN=Another Publisher",
        };
        let verifier = CountingVerifier(AtomicUsize::new(0));
        assert!(matches!(
            verify_package(package.path(), "CN=Another Publisher", &detached, &verifier),
            Err(PackageError::Signature(_))
        ));
        assert_eq!(verifier.0.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn missing_detached_signature_fails_closed_before_manifest_parse() {
        let package = write_fixture_package(false, false, "CN=BaselineOps Test", b"");
        let detached = RejectingDetachedVerifier(AtomicUsize::new(0));
        let verifier = CountingVerifier(AtomicUsize::new(0));
        assert!(matches!(
            verify_package(package.path(), "CN=BaselineOps Test", &detached, &verifier),
            Err(PackageError::Signature(_))
        ));
        assert_eq!(detached.0.load(Ordering::Relaxed), 0);
        assert_eq!(verifier.0.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn detached_failure_precedes_manifest_trust_and_executable_checks() {
        let package = write_fixture_package(
            false,
            true,
            "CN=Another Publisher",
            b"fixture detached signature",
        );
        let detached = RejectingDetachedVerifier(AtomicUsize::new(0));
        let verifier = CountingVerifier(AtomicUsize::new(0));
        assert!(matches!(
            verify_package(package.path(), "CN=BaselineOps Test", &detached, &verifier),
            Err(PackageError::Signature(_))
        ));
        assert_eq!(detached.0.load(Ordering::Relaxed), 1);
        assert_eq!(verifier.0.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn tampered_detached_signature_is_rejected_before_manifest_parse() {
        let package = write_fixture_package(false, true, "CN=BaselineOps Test", b"tampered");
        let detached = DetachedFixtureVerifier {
            calls: AtomicUsize::new(0),
            subject: "CN=BaselineOps Test",
        };
        let verifier = CountingVerifier(AtomicUsize::new(0));
        assert!(matches!(
            verify_package(package.path(), "CN=BaselineOps Test", &detached, &verifier),
            Err(PackageError::Signature(_))
        ));
        assert_eq!(detached.calls.load(Ordering::Relaxed), 0);
        assert_eq!(verifier.0.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn manifest_paths_are_portable_and_unambiguous() {
        for invalid in [
            "",
            "/bin/tool.exe",
            "bin\\tool.exe",
            "C:/bin/tool.exe",
            "bin//tool.exe",
            "./bin/tool.exe",
            "bin/../tool.exe",
            "bin/tool.exe/",
        ] {
            assert!(!is_safe_manifest_path(invalid), "accepted {invalid:?}");
        }
        assert!(is_safe_manifest_path("bin/baselineops.exe"));
    }
}
