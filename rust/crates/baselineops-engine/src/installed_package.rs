//! Authentication of a package already installed below a protected root.

use crate::package::{
    DetachedSignatureVerifier, MANIFEST_PATH, MANIFEST_SIGNATURE_PATH, PackageError,
    PackageManifestV1, REQUIRED_EXECUTABLES, SignatureVerifier, hash_file, validate_manifest,
};
use baselineops_domain::Sha256Digest;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_MANIFEST_SIGNATURE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_PAYLOAD_BYTES: u64 = 1024 * 1024 * 1024;

/// External immutable identity expected of an installed release package.
#[derive(Clone, Copy, Debug)]
pub struct InstalledPackageExpectation<'a> {
    /// Exact product label compiled into this release.
    pub product: &'a str,
    /// Exact package version compiled into this release.
    pub package_version: &'a str,
    /// Exact supported Windows target triple.
    pub target: &'a str,
    /// Exact signer subject compiled into the releasing executable.
    pub signer_subject: &'a str,
}

/// Opaque identity of a fully authenticated installed package.
#[derive(Clone, Debug)]
pub struct InstalledPackageIdentity {
    binding_digest: Sha256Digest,
}

impl InstalledPackageIdentity {
    /// SHA-256 of the exact detached-signature-authenticated manifest bytes.
    #[must_use]
    pub fn binding_digest(&self) -> Sha256Digest {
        self.binding_digest
    }
}

/// Authenticate every payload in an already protected installation root.
///
/// The detached signature is verified over the exact, bounded manifest bytes
/// before the manifest is parsed or any of its fields are trusted. The returned
/// identity intentionally binds plans to those authenticated bytes, not to an
/// executable or an archive that is absent from an installed layout.
///
/// # Errors
///
/// Returns an error for unsafe paths, malformed or untrusted manifests,
/// inventory drift, digest mismatch, or an untrusted required executable.
pub fn verify_installed_package(
    root: impl AsRef<Path>,
    expected: InstalledPackageExpectation<'_>,
    detached_signature_verifier: &dyn DetachedSignatureVerifier,
    signature_verifier: &dyn SignatureVerifier,
) -> Result<InstalledPackageIdentity, PackageError> {
    validate_expectation(expected)?;
    let policy = baselineops_windows::PathPolicy::new(root)?;
    let manifest_path = policy.existing_file(MANIFEST_PATH)?;
    let signature_path = policy.existing_file(MANIFEST_SIGNATURE_PATH)?;
    let manifest_bytes =
        baselineops_windows::read_bounded_utf8_no_follow(&manifest_path, MAX_MANIFEST_BYTES)?
            .into_bytes();
    let manifest_signature_bytes =
        read_bounded_file(&signature_path, MAX_MANIFEST_SIGNATURE_BYTES)?;
    detached_signature_verifier.verify(
        &manifest_bytes,
        &manifest_signature_bytes,
        expected.signer_subject,
    )?;
    let manifest: PackageManifestV1 = serde_json::from_slice(&manifest_bytes)?;
    validate_manifest(&manifest)?;
    validate_exact_identity(&manifest, expected)?;

    let actual = collect_regular_payloads(policy.root())?;
    validate_inventory(&policy, &manifest, &actual)?;
    for executable in REQUIRED_EXECUTABLES {
        let path = policy.existing_file(executable)?;
        signature_verifier.verify(&path, expected.signer_subject)?;
    }
    Ok(InstalledPackageIdentity {
        binding_digest: Sha256Digest::of_bytes(manifest_bytes),
    })
}

fn validate_expectation(expected: InstalledPackageExpectation<'_>) -> Result<(), PackageError> {
    if expected.product.trim().is_empty()
        || expected.package_version.trim().is_empty()
        || expected.target.trim().is_empty()
        || expected.signer_subject.trim().is_empty()
    {
        return Err(PackageError::Signature(
            "an external exact package identity and signer subject are required".into(),
        ));
    }
    Ok(())
}

fn validate_exact_identity(
    manifest: &PackageManifestV1,
    expected: InstalledPackageExpectation<'_>,
) -> Result<(), PackageError> {
    if manifest.product != expected.product
        || manifest.package_version != expected.package_version
        || manifest.target != expected.target
        || manifest.signer_subject != expected.signer_subject
    {
        return Err(PackageError::Signature(
            "authenticated manifest identity differs from the embedded release identity".into(),
        ));
    }
    Ok(())
}

fn collect_regular_payloads(root: &Path) -> Result<BTreeMap<String, PathBuf>, PackageError> {
    let mut files = BTreeMap::new();
    collect_regular_payloads_at(root, root, &mut files)?;
    Ok(files)
}

fn collect_regular_payloads_at(
    root: &Path,
    directory: &Path,
    files: &mut BTreeMap<String, PathBuf>,
) -> Result<(), PackageError> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
            return Err(PackageError::InventoryMismatch(
                "installed package contains a symbolic link or reparse point".into(),
            ));
        }
        if metadata.is_dir() {
            collect_regular_payloads_at(root, &path, files)?;
            continue;
        }
        if !metadata.is_file() {
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|_| PackageError::InventoryMismatch("payload escaped package root".into()))?
            .to_string_lossy()
            .replace('\\', "/");
        let key = relative.to_ascii_lowercase();
        if files.insert(key, path).is_some() {
            return Err(PackageError::InventoryMismatch(
                "installed package has case-ambiguous payload paths".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
const fn is_reparse_point(_: &fs::Metadata) -> bool {
    false
}

fn validate_inventory(
    policy: &baselineops_windows::PathPolicy,
    manifest: &PackageManifestV1,
    actual: &BTreeMap<String, PathBuf>,
) -> Result<(), PackageError> {
    let special = BTreeSet::from([
        MANIFEST_PATH.to_ascii_lowercase(),
        MANIFEST_SIGNATURE_PATH.to_ascii_lowercase(),
    ]);
    let expected = manifest
        .files
        .iter()
        .map(|file| (file.path.to_ascii_lowercase(), file))
        .collect::<BTreeMap<_, _>>();
    for key in actual.keys() {
        if !special.contains(key) && !expected.contains_key(key) {
            return Err(PackageError::InventoryMismatch(format!(
                "unexpected regular payload file: {key}"
            )));
        }
    }
    for (key, file) in expected {
        let path = actual.get(&key).ok_or_else(|| {
            PackageError::InventoryMismatch(format!("manifest file is absent: {}", file.path))
        })?;
        let verified_path = policy.existing_file(&file.path)?;
        if verified_path != *path {
            return Err(PackageError::InventoryMismatch(format!(
                "payload path changed while being verified: {}",
                file.path
            )));
        }
        let size = verified_path.metadata()?.len();
        if size != file.size_bytes
            || size > MAX_PAYLOAD_BYTES
            || hash_file(&verified_path)? != file.sha256
        {
            return Err(PackageError::InventoryMismatch(format!(
                "size or digest mismatch: {}",
                file.path
            )));
        }
    }
    if actual.len() != manifest.files.len() + special.len() {
        return Err(PackageError::InventoryMismatch(
            "installed package inventory has duplicate or non-regular manifest members".into(),
        ));
    }
    Ok(())
}

fn read_bounded_file(path: &Path, limit: u64) -> Result<Vec<u8>, PackageError> {
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > limit {
        return Err(PackageError::Signature(
            "manifest signature is not a bounded regular file".into(),
        ));
    }
    let capacity = usize::try_from(metadata.len()).map_err(|_| {
        PackageError::Signature(
            "manifest signature exceeds this platform's allocation bounds".into(),
        )
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    file.by_ref()
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)?;
    let observed_size = u64::try_from(bytes.len()).map_err(|_| {
        PackageError::Signature("manifest signature read exceeds u64 bounds".into())
    })?;
    if observed_size != metadata.len() {
        return Err(PackageError::Signature(
            "manifest signature changed while being read".into(),
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ManifestFile;
    use std::{
        io::Write,
        sync::atomic::{AtomicUsize, Ordering},
    };

    const EXPECTED: InstalledPackageExpectation<'static> = InstalledPackageExpectation {
        product: "BaselineOps for Windows",
        package_version: "3.0.0-alpha.1",
        target: "x86_64-pc-windows-msvc",
        signer_subject: "CN=BaselineOps Test",
    };

    struct Detached(AtomicUsize);
    impl DetachedSignatureVerifier for Detached {
        fn verify(
            &self,
            _bytes: &[u8],
            signature: &[u8],
            subject: &str,
        ) -> Result<(), PackageError> {
            if signature != b"fixture signature" || subject != EXPECTED.signer_subject {
                return Err(PackageError::Signature(
                    "fixture rejected detached signature".into(),
                ));
            }
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    struct Executables(AtomicUsize);
    impl SignatureVerifier for Executables {
        fn verify(&self, path: &Path, subject: &str) -> Result<(), PackageError> {
            assert!(path.is_file());
            assert_eq!(subject, EXPECTED.signer_subject);
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    fn fixture_root(extra: bool, malformed_manifest: bool) -> tempfile::TempDir {
        let root = tempfile::tempdir().expect("root");
        let payloads = [
            ("bin/baselineops.exe", b"cli".as_slice()),
            ("bin/baselineops-gui.exe", b"gui".as_slice()),
            ("bin/baselineops-worker.exe", b"worker".as_slice()),
        ];
        let files = payloads
            .iter()
            .map(|(path, bytes)| ManifestFile {
                path: (*path).into(),
                size_bytes: u64::try_from(bytes.len()).expect("size"),
                sha256: Sha256Digest::of_bytes(bytes),
            })
            .collect::<Vec<_>>();
        for (relative, bytes) in payloads {
            let path = root.path().join(relative);
            fs::create_dir_all(path.parent().expect("parent")).expect("directory");
            fs::write(path, bytes).expect("payload");
        }
        if extra {
            fs::write(root.path().join("unexpected.txt"), b"extra").expect("extra");
        }
        let manifest = PackageManifestV1 {
            schema_version: "1.0".into(),
            product: EXPECTED.product.into(),
            package_version: EXPECTED.package_version.into(),
            target: EXPECTED.target.into(),
            signer_subject: EXPECTED.signer_subject.into(),
            files,
        };
        let bytes = if malformed_manifest {
            b"not json".to_vec()
        } else {
            serde_json::to_vec(&manifest).expect("manifest")
        };
        fs::write(root.path().join(MANIFEST_PATH), bytes).expect("manifest");
        let mut signature =
            File::create(root.path().join(MANIFEST_SIGNATURE_PATH)).expect("signature");
        signature
            .write_all(b"fixture signature")
            .expect("signature bytes");
        root
    }

    #[test]
    fn installed_root_binds_the_exact_authenticated_manifest_bytes() {
        let root = fixture_root(false, false);
        let detached = Detached(AtomicUsize::new(0));
        let executables = Executables(AtomicUsize::new(0));
        let identity = verify_installed_package(root.path(), EXPECTED, &detached, &executables)
            .expect("verified");
        assert_eq!(
            identity.binding_digest(),
            Sha256Digest::of_bytes(fs::read(root.path().join(MANIFEST_PATH)).expect("manifest"))
        );
        assert_eq!(detached.0.load(Ordering::Relaxed), 1);
        assert_eq!(executables.0.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn unexpected_regular_payload_is_rejected() {
        let root = fixture_root(true, false);
        assert!(matches!(
            verify_installed_package(
                root.path(),
                EXPECTED,
                &Detached(AtomicUsize::new(0)),
                &Executables(AtomicUsize::new(0))
            ),
            Err(PackageError::InventoryMismatch(_))
        ));
    }

    #[test]
    fn detached_signature_precedes_manifest_parsing() {
        let root = fixture_root(false, true);
        let detached = Detached(AtomicUsize::new(0));
        assert!(matches!(
            verify_installed_package(
                root.path(),
                EXPECTED,
                &detached,
                &Executables(AtomicUsize::new(0))
            ),
            Err(PackageError::Json(_))
        ));
        assert_eq!(detached.0.load(Ordering::Relaxed), 1);
    }
}
