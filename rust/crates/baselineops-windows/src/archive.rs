use crate::PlatformError;
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::{Component, Path, PathBuf};

/// Quotas for extracting an untrusted package or evidence archive.
#[derive(Clone, Copy, Debug)]
pub struct ArchivePolicy {
    /// Maximum number of regular files.
    pub max_files: usize,
    /// Maximum uncompressed size of one file.
    pub max_file_bytes: u64,
    /// Maximum total uncompressed bytes.
    pub max_total_bytes: u64,
    /// Maximum path depth below the extraction root.
    pub max_depth: usize,
}

impl Default for ArchivePolicy {
    fn default() -> Self {
        Self {
            max_files: 4096,
            max_file_bytes: 128 * 1024 * 1024,
            max_total_bytes: 512 * 1024 * 1024,
            max_depth: 16,
        }
    }
}

/// Extract a ZIP after rejecting ambiguous names, links, traversal, and quota abuse.
///
/// # Errors
///
/// Returns an error when the archive is malformed, violates a quota or path rule,
/// contains a link or special file, or cannot be extracted safely.
pub fn extract_zip_safely(
    reader: impl Read + Seek,
    destination: impl AsRef<Path>,
    policy: ArchivePolicy,
) -> Result<Vec<PathBuf>, PlatformError> {
    let destination = destination.as_ref();
    fs::create_dir_all(destination)?;
    let destination = fs::canonicalize(destination)?;
    if !destination.is_dir() {
        return Err(PlatformError::ArchiveRejected(
            "destination is not a directory".into(),
        ));
    }

    let mut archive = zip::ZipArchive::new(reader)
        .map_err(|error| PlatformError::ArchiveRejected(error.to_string()))?;
    if archive.len() > policy.max_files.saturating_mul(2) {
        return Err(PlatformError::ArchiveRejected(
            "archive contains too many entries".into(),
        ));
    }

    let mut total_bytes = 0_u64;
    let mut file_count = 0_usize;
    let mut normalized_names = BTreeSet::new();
    let mut extracted = Vec::new();
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| PlatformError::ArchiveRejected(error.to_string()))?;
        let relative = validate_entry_name(entry.name(), policy.max_depth)?;
        let normalized = relative.to_string_lossy().replace('\\', "/").to_lowercase();
        if !normalized_names.insert(normalized) {
            return Err(PlatformError::ArchiveRejected(
                "archive has duplicate or case-colliding paths".into(),
            ));
        }
        if is_link_or_special(entry.unix_mode()) {
            return Err(PlatformError::ArchiveRejected(
                "archive contains a link or special file".into(),
            ));
        }
        let output = destination.join(&relative);
        if entry.is_dir() {
            fs::create_dir_all(&output)?;
            reject_existing_link(&output)?;
            continue;
        }
        file_count = file_count.saturating_add(1);
        if file_count > policy.max_files {
            return Err(PlatformError::ArchiveRejected(
                "archive contains too many files".into(),
            ));
        }
        if entry.size() > policy.max_file_bytes {
            return Err(PlatformError::ArchiveRejected(format!(
                "archive member exceeds the per-file quota: {}",
                relative.display()
            )));
        }
        total_bytes = total_bytes
            .checked_add(entry.size())
            .ok_or_else(|| PlatformError::ArchiveRejected("archive size overflow".into()))?;
        if total_bytes > policy.max_total_bytes {
            return Err(PlatformError::ArchiveRejected(
                "archive exceeds the total uncompressed quota".into(),
            ));
        }
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)?;
            reject_existing_link(parent)?;
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&output)?;
        let copied = std::io::copy(
            &mut entry.by_ref().take(policy.max_file_bytes + 1),
            &mut file,
        )?;
        if copied != entry.size() || copied > policy.max_file_bytes {
            return Err(PlatformError::ArchiveRejected(format!(
                "archive member size changed while extracting: {}",
                relative.display()
            )));
        }
        file.flush()?;
        file.sync_all()?;
        extracted.push(output);
    }
    Ok(extracted)
}

fn validate_entry_name(name: &str, max_depth: usize) -> Result<PathBuf, PlatformError> {
    if name.is_empty() || name.as_bytes().contains(&0) || name.contains(':') {
        return Err(PlatformError::ArchiveRejected(
            "archive member has an invalid or alternate-stream name".into(),
        ));
    }
    let path = Path::new(name);
    let mut clean = PathBuf::new();
    let mut depth = 0_usize;
    for component in path.components() {
        match component {
            Component::Normal(part) => {
                validate_windows_component(part.to_string_lossy().as_ref())?;
                clean.push(part);
                depth = depth.saturating_add(1);
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(PlatformError::ArchiveRejected(
                    "archive member attempts path traversal".into(),
                ));
            }
        }
    }
    if clean.as_os_str().is_empty() || depth > max_depth {
        return Err(PlatformError::ArchiveRejected(
            "archive member has an empty or over-deep path".into(),
        ));
    }
    Ok(clean)
}

fn validate_windows_component(component: &str) -> Result<(), PlatformError> {
    if component.ends_with([' ', '.']) {
        return Err(PlatformError::ArchiveRejected(
            "archive member has a Windows-ambiguous suffix".into(),
        ));
    }
    let stem = component
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && matches!(stem.as_bytes()[3], b'1'..=b'9'));
    if reserved {
        return Err(PlatformError::ArchiveRejected(
            "archive member uses a reserved Windows device name".into(),
        ));
    }
    Ok(())
}

fn is_link_or_special(mode: Option<u32>) -> bool {
    let Some(mode) = mode else {
        return false;
    };
    let file_type = mode & 0o170_000;
    file_type != 0 && file_type != 0o100_000 && file_type != 0o040_000
}

fn reject_existing_link(path: &Path) -> Result<(), PlatformError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(PlatformError::ArchiveRejected(
            "extraction path contains a symbolic link".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use zip::write::SimpleFileOptions;

    fn archive_with(name: &str, bytes: &[u8]) -> Vec<u8> {
        let mut buffer = Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut buffer);
            writer
                .start_file(name, SimpleFileOptions::default())
                .expect("member");
            writer.write_all(bytes).expect("content");
            writer.finish().expect("finish");
        }
        buffer.into_inner()
    }

    #[test]
    fn extracts_a_regular_member() {
        let bytes = archive_with("schemas/profile.json", b"{}");
        let root = tempfile::tempdir().expect("root");
        let paths = extract_zip_safely(Cursor::new(bytes), root.path(), ArchivePolicy::default())
            .expect("extract");
        assert_eq!(paths.len(), 1);
        assert_eq!(fs::read(&paths[0]).expect("read"), b"{}");
    }

    #[test]
    fn rejects_traversal_and_reserved_names() {
        for name in ["../escape", "CON.txt", "data:stream"] {
            let bytes = archive_with(name, b"x");
            let root = tempfile::tempdir().expect("root");
            assert!(
                extract_zip_safely(Cursor::new(bytes), root.path(), ArchivePolicy::default())
                    .is_err()
            );
        }
    }
}
