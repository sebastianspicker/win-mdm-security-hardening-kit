use baselineops_domain::{
    ArtifactId, ArtifactKind, ArtifactV3, JsonMap, Sha256Digest, canonical_json_bytes,
};
use baselineops_windows::atomic_write;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

const MANIFEST_NAME: &str = "evidence-manifest.v1.json";

/// Quotas applied before the evidence store retains a capability output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceLimits {
    /// Maximum bytes retained in one artifact.
    pub max_file_bytes: u64,
    /// Maximum bytes retained by the complete evidence store.
    pub max_total_bytes: u64,
    /// Maximum number of retained artifacts.
    pub max_artifacts: usize,
}

impl EvidenceLimits {
    /// Validate a policy before it is used to create or open a store.
    ///
    /// # Errors
    ///
    /// Returns an error when a quota is zero or the per-file quota exceeds the total quota.
    pub fn validate(self) -> Result<(), EvidenceError> {
        if self.max_file_bytes == 0
            || self.max_total_bytes == 0
            || self.max_artifacts == 0
            || self.max_file_bytes > self.max_total_bytes
        {
            return Err(EvidenceError::InvalidLimits);
        }
        Ok(())
    }
}

/// Platform protection boundary for the worker-controlled evidence root.
///
/// Production Windows code must implement this port using its installation or
/// run-directory policy. The engine deliberately makes no ACL claim itself.
pub trait EvidenceProtection: Send + Sync {
    /// Establish the required protection for a newly created evidence root.
    ///
    /// # Errors
    ///
    /// Returns an error when platform-specific protection cannot be established.
    fn protect(&self, root: &Path) -> Result<(), EvidenceError>;

    /// Prove that the evidence root remains protected before use.
    ///
    /// # Errors
    ///
    /// Returns an error when protection cannot be independently verified.
    fn verify(&self, root: &Path) -> Result<(), EvidenceError>;
}

/// One request to retain bytes as an artifact.
#[derive(Clone, Debug)]
pub struct EvidenceWrite<'a> {
    /// Worker-controlled relative artifact locator.
    pub locator: &'a str,
    /// Artifact classification retained in the result.
    pub kind: ArtifactKind,
    /// MIME type of the retained content.
    pub media_type: &'a str,
    /// Worker-trusted availability time.
    pub created_at: DateTime<Utc>,
    /// Capability metadata with no path or authority semantics.
    pub metadata: JsonMap,
}

/// Canonically serialized inventory for one evidence root.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct EvidenceManifest {
    /// Schema marker for strict readers.
    pub schema_version: String,
    /// Retained artifacts in deterministic locator order.
    pub artifacts: Vec<ArtifactV3>,
    /// Sum of the retained artifact sizes.
    pub total_bytes: u64,
}

impl EvidenceManifest {
    fn empty() -> Self {
        Self {
            schema_version: "1.0".into(),
            artifacts: Vec::new(),
            total_bytes: 0,
        }
    }
}

/// Protected, quota-bounded evidence store with digest-on-write retention.
pub struct EvidenceStore {
    root: PathBuf,
    limits: EvidenceLimits,
    protection: Arc<dyn EvidenceProtection>,
    manifest: EvidenceManifest,
}

impl EvidenceStore {
    /// Create an empty protected store. A protection implementation is required.
    ///
    /// # Errors
    ///
    /// Fails closed when protection cannot be established or verified, when the
    /// manifest already exists, or when the limits are invalid.
    pub fn create(
        root: impl AsRef<Path>,
        limits: EvidenceLimits,
        protection: Arc<dyn EvidenceProtection>,
    ) -> Result<Self, EvidenceError> {
        limits.validate()?;
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        protection.protect(&root)?;
        protection.verify(&root)?;
        let manifest_path = root.join(MANIFEST_NAME);
        if manifest_path.exists() {
            return Err(EvidenceError::AlreadyExists);
        }
        let store = Self {
            root,
            limits,
            protection,
            manifest: EvidenceManifest::empty(),
        };
        store.persist_manifest()?;
        Ok(store)
    }

    /// Open a protected store only after validating its canonical manifest and bytes.
    ///
    /// # Errors
    ///
    /// Fails when protection is absent or unverifiable, the manifest is noncanonical,
    /// or any retained artifact has changed since its digest was recorded.
    pub fn open(
        root: impl AsRef<Path>,
        limits: EvidenceLimits,
        protection: Arc<dyn EvidenceProtection>,
    ) -> Result<Self, EvidenceError> {
        limits.validate()?;
        let root = root.as_ref().to_path_buf();
        protection.verify(&root)?;
        let manifest = read_manifest(&root)?;
        validate_manifest(&root, &manifest, limits)?;
        Ok(Self {
            root,
            limits,
            protection,
            manifest,
        })
    }

    /// Retain one new artifact without allowing overwrite of an existing locator.
    ///
    /// # Errors
    ///
    /// Fails before writing when the protected root cannot be verified, a locator is
    /// unsafe, or a quota would be exceeded.
    pub fn write(
        &mut self,
        request: EvidenceWrite<'_>,
        bytes: &[u8],
    ) -> Result<ArtifactV3, EvidenceError> {
        self.protection.verify(&self.root)?;
        let relative = safe_relative_path(request.locator)?;
        let size_bytes = u64::try_from(bytes.len()).map_err(|_| EvidenceError::QuotaExceeded)?;
        if size_bytes > self.limits.max_file_bytes
            || self.manifest.artifacts.len() >= self.limits.max_artifacts
        {
            return Err(EvidenceError::QuotaExceeded);
        }
        let total_bytes = self
            .manifest
            .total_bytes
            .checked_add(size_bytes)
            .ok_or(EvidenceError::QuotaExceeded)?;
        if total_bytes > self.limits.max_total_bytes {
            return Err(EvidenceError::QuotaExceeded);
        }
        let path = self.root.join(&relative);
        ensure_safe_parent(&self.root, &relative)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        let artifact = ArtifactV3 {
            id: ArtifactId::new(),
            kind: request.kind,
            media_type: request.media_type.into(),
            locator: request.locator.into(),
            digest: Sha256Digest::of_bytes(bytes),
            size_bytes,
            created_at: request.created_at,
            metadata: request.metadata,
        };
        self.manifest.artifacts.push(artifact.clone());
        self.manifest
            .artifacts
            .sort_by(|left, right| left.locator.cmp(&right.locator));
        self.manifest.total_bytes = total_bytes;
        if let Err(error) = self.persist_manifest() {
            self.manifest
                .artifacts
                .retain(|candidate| candidate.id != artifact.id);
            self.manifest.total_bytes = self.manifest.total_bytes.saturating_sub(size_bytes);
            let _ = fs::remove_file(path);
            return Err(error);
        }
        Ok(artifact)
    }

    /// Read retained bytes only after re-verifying protection and recorded integrity.
    ///
    /// # Errors
    ///
    /// Returns an error when the locator is unknown, protection fails, or retained bytes differ.
    pub fn read(&self, locator: &str) -> Result<Vec<u8>, EvidenceError> {
        self.protection.verify(&self.root)?;
        let relative = safe_relative_path(locator)?;
        let artifact = self
            .manifest
            .artifacts
            .iter()
            .find(|artifact| artifact.locator == locator)
            .ok_or(EvidenceError::UnknownArtifact)?;
        let mut bytes = Vec::new();
        OpenOptions::new()
            .read(true)
            .open(self.root.join(relative))?
            .read_to_end(&mut bytes)?;
        if u64::try_from(bytes.len()).ok() != Some(artifact.size_bytes)
            || Sha256Digest::of_bytes(&bytes) != artifact.digest
        {
            return Err(EvidenceError::IntegrityMismatch(locator.into()));
        }
        Ok(bytes)
    }

    /// Return the current canonical inventory without exposing a mutable root path.
    #[must_use]
    pub fn manifest(&self) -> &EvidenceManifest {
        &self.manifest
    }

    fn persist_manifest(&self) -> Result<(), EvidenceError> {
        self.protection.verify(&self.root)?;
        atomic_write(
            self.root.join(MANIFEST_NAME),
            &canonical_json_bytes(&self.manifest)?,
        )?;
        Ok(())
    }
}

fn read_manifest(root: &Path) -> Result<EvidenceManifest, EvidenceError> {
    let bytes = fs::read(root.join(MANIFEST_NAME))?;
    let manifest = serde_json::from_slice::<EvidenceManifest>(&bytes)?;
    if canonical_json_bytes(&manifest)? != bytes {
        return Err(EvidenceError::NonCanonicalManifest);
    }
    Ok(manifest)
}

fn validate_manifest(
    root: &Path,
    manifest: &EvidenceManifest,
    limits: EvidenceLimits,
) -> Result<(), EvidenceError> {
    if manifest.schema_version != "1.0" || manifest.artifacts.len() > limits.max_artifacts {
        return Err(EvidenceError::InvalidManifest);
    }
    let mut locators = BTreeSet::new();
    let mut total = 0_u64;
    for artifact in &manifest.artifacts {
        let path = safe_relative_path(&artifact.locator)?;
        if !locators.insert(artifact.locator.as_str())
            || artifact.size_bytes > limits.max_file_bytes
        {
            return Err(EvidenceError::InvalidManifest);
        }
        let bytes = fs::read(root.join(path))?;
        if u64::try_from(bytes.len()).ok() != Some(artifact.size_bytes)
            || Sha256Digest::of_bytes(&bytes) != artifact.digest
        {
            return Err(EvidenceError::IntegrityMismatch(artifact.locator.clone()));
        }
        total = total
            .checked_add(artifact.size_bytes)
            .ok_or(EvidenceError::QuotaExceeded)?;
    }
    if total != manifest.total_bytes || total > limits.max_total_bytes {
        return Err(EvidenceError::InvalidManifest);
    }
    Ok(())
}

fn safe_relative_path(locator: &str) -> Result<PathBuf, EvidenceError> {
    let path = Path::new(locator);
    if locator.is_empty()
        || locator.contains(['\\', ':'])
        || path.is_absolute()
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(EvidenceError::UnsafeLocator(locator.into()));
    }
    Ok(path.to_path_buf())
}

fn ensure_safe_parent(root: &Path, relative: &Path) -> Result<(), EvidenceError> {
    let mut current = root.to_path_buf();
    if let Some(parent) = relative.parent() {
        for part in parent.components() {
            let Component::Normal(part) = part else {
                return Err(EvidenceError::UnsafeLocator(relative.display().to_string()));
            };
            current.push(part);
            fs::create_dir(&current).or_else(|error| {
                if error.kind() == io::ErrorKind::AlreadyExists {
                    Ok(())
                } else {
                    Err(error)
                }
            })?;
            let metadata = fs::symlink_metadata(&current)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(EvidenceError::UnsafeLocator(relative.display().to_string()));
            }
        }
    }
    Ok(())
}

/// Evidence retention failures. Protection failures deliberately reject use.
#[derive(Debug, thiserror::Error)]
pub enum EvidenceError {
    /// File operation failed.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// Canonical serialization failed.
    #[error(transparent)]
    Domain(#[from] baselineops_domain::DomainError),
    /// Strict manifest decoding failed.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// Atomic manifest replacement failed.
    #[error(transparent)]
    Platform(#[from] baselineops_windows::PlatformError),
    /// Protection establishment or verification failed.
    #[error("evidence protection failed: {0}")]
    Protection(String),
    /// Limits are empty or internally inconsistent.
    #[error("evidence limits are invalid")]
    InvalidLimits,
    /// A new store would replace an existing manifest.
    #[error("evidence manifest already exists")]
    AlreadyExists,
    /// A locator is absolute, traversal-like, or platform-ambiguous.
    #[error("unsafe evidence locator: {0}")]
    UnsafeLocator(String),
    /// A quota would be exceeded.
    #[error("evidence quota exceeded")]
    QuotaExceeded,
    /// Manifest fields or retained inventory are inconsistent.
    #[error("evidence manifest is invalid")]
    InvalidManifest,
    /// The on-disk manifest is not its canonical serialization.
    #[error("evidence manifest is not canonical")]
    NonCanonicalManifest,
    /// A retained artifact changed after its digest was recorded.
    #[error("evidence integrity mismatch: {0}")]
    IntegrityMismatch(String),
    /// The requested locator does not appear in the manifest.
    #[error("unknown evidence artifact")]
    UnknownArtifact,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Protection;
    impl EvidenceProtection for Protection {
        fn protect(&self, _root: &Path) -> Result<(), EvidenceError> {
            Ok(())
        }
        fn verify(&self, _root: &Path) -> Result<(), EvidenceError> {
            Ok(())
        }
    }

    fn limits() -> EvidenceLimits {
        EvidenceLimits {
            max_file_bytes: 8,
            max_total_bytes: 10,
            max_artifacts: 2,
        }
    }

    #[test]
    fn store_rejects_traversal_and_enforces_quotas() {
        let root = tempfile::tempdir().expect("root");
        let mut store =
            EvidenceStore::create(root.path().join("evidence"), limits(), Arc::new(Protection))
                .expect("store");
        let request = |locator| EvidenceWrite {
            locator,
            kind: ArtifactKind::Evidence,
            media_type: "text/plain",
            created_at: Utc::now(),
            metadata: JsonMap::new(),
        };
        assert!(matches!(
            store.write(request("../outside"), b"x"),
            Err(EvidenceError::UnsafeLocator(_))
        ));
        store
            .write(request("first.txt"), b"12345678")
            .expect("first");
        assert!(matches!(
            store.write(request("second.txt"), b"123"),
            Err(EvidenceError::QuotaExceeded)
        ));
    }

    #[test]
    fn store_detects_tampered_artifacts_when_reopened() {
        let root = tempfile::tempdir().expect("root");
        let evidence_root = root.path().join("evidence");
        let mut store =
            EvidenceStore::create(&evidence_root, limits(), Arc::new(Protection)).expect("store");
        store
            .write(
                EvidenceWrite {
                    locator: "nested/receipt.txt",
                    kind: ArtifactKind::Evidence,
                    media_type: "text/plain",
                    created_at: Utc::now(),
                    metadata: JsonMap::new(),
                },
                b"original",
            )
            .expect("write");
        fs::write(evidence_root.join("nested/receipt.txt"), b"edited").expect("tamper");
        assert!(matches!(
            EvidenceStore::open(evidence_root, limits(), Arc::new(Protection)),
            Err(EvidenceError::IntegrityMismatch(_))
        ));
    }

    #[test]
    fn noncanonical_manifest_is_rejected() {
        let root = tempfile::tempdir().expect("root");
        let evidence_root = root.path().join("evidence");
        let _store =
            EvidenceStore::create(&evidence_root, limits(), Arc::new(Protection)).expect("store");
        let manifest = fs::read(evidence_root.join(MANIFEST_NAME)).expect("manifest");
        let value = serde_json::from_slice::<serde_json::Value>(&manifest).expect("json");
        fs::write(
            evidence_root.join(MANIFEST_NAME),
            serde_json::to_vec_pretty(&value).expect("pretty json"),
        )
        .expect("tamper");
        assert!(matches!(
            EvidenceStore::open(evidence_root, limits(), Arc::new(Protection)),
            Err(EvidenceError::NonCanonicalManifest)
        ));
    }
}
