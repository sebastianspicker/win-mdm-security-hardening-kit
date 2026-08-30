#![cfg_attr(windows, allow(unsafe_code))]

use crate::PlatformError;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Default upper bound for operator-supplied JSON documents.
pub const MAX_INPUT_BYTES: u64 = 1024 * 1024;

/// Containment requirements for an untrusted path.
#[derive(Clone, Debug)]
pub struct PathPolicy {
    root: PathBuf,
    allow_unc: bool,
    reject_reparse_points: bool,
}

impl PathPolicy {
    /// Create a fail-closed policy rooted at an existing directory.
    ///
    /// # Errors
    ///
    /// Returns an error when the root cannot be canonicalized or is not a directory.
    pub fn new(root: impl AsRef<Path>) -> Result<Self, PlatformError> {
        let root = fs::canonicalize(root.as_ref())?;
        if !root.is_dir() {
            return Err(PlatformError::UntrustedPath {
                path: root,
                reason: "policy root is not a directory".into(),
            });
        }
        Ok(Self {
            root,
            allow_unc: false,
            reject_reparse_points: true,
        })
    }

    /// Permit UNC paths. Disabled by default and never used for protected installs.
    #[must_use]
    pub fn with_unc(mut self, allow_unc: bool) -> Self {
        self.allow_unc = allow_unc;
        self
    }

    /// Return the canonical policy root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Resolve an existing file and prove that every component stays under the root.
    ///
    /// # Errors
    ///
    /// Returns an error when the path escapes the root, traverses a reparse point,
    /// is an unapproved UNC path, or does not name a regular file.
    pub fn existing_file(&self, candidate: impl AsRef<Path>) -> Result<PathBuf, PlatformError> {
        let candidate = candidate.as_ref();
        reject_lexical_escape(candidate)?;
        reject_unc(candidate, self.allow_unc)?;
        let joined = if candidate.is_absolute() {
            candidate.to_path_buf()
        } else {
            self.root.join(candidate)
        };
        if self.reject_reparse_points {
            reject_reparse_chain(&joined)?;
        }
        let canonical = fs::canonicalize(&joined)?;
        if !canonical.starts_with(&self.root) {
            return Err(PlatformError::UntrustedPath {
                path: joined,
                reason: "canonical path escaped the trusted root".into(),
            });
        }
        if !canonical.is_file() {
            return Err(PlatformError::UntrustedPath {
                path: canonical,
                reason: "expected a regular file".into(),
            });
        }
        Ok(canonical)
    }

    /// Resolve a future output path while proving its parent is trusted.
    ///
    /// # Errors
    ///
    /// Returns an error when the path or its parent violates containment, reparse,
    /// UNC, or file-name policy.
    pub fn output_file(&self, candidate: impl AsRef<Path>) -> Result<PathBuf, PlatformError> {
        let candidate = candidate.as_ref();
        reject_lexical_escape(candidate)?;
        reject_unc(candidate, self.allow_unc)?;
        let joined = if candidate.is_absolute() {
            candidate.to_path_buf()
        } else {
            self.root.join(candidate)
        };
        let parent = joined
            .parent()
            .ok_or_else(|| PlatformError::UntrustedPath {
                path: joined.clone(),
                reason: "output has no parent directory".into(),
            })?;
        reject_reparse_chain(parent)?;
        let canonical_parent = fs::canonicalize(parent)?;
        if !canonical_parent.starts_with(&self.root) {
            return Err(PlatformError::UntrustedPath {
                path: joined,
                reason: "output parent escaped the trusted root".into(),
            });
        }
        let name = joined
            .file_name()
            .ok_or_else(|| PlatformError::UntrustedPath {
                path: joined.clone(),
                reason: "output has no file name".into(),
            })?;
        if name == OsStr::new(".") || name == OsStr::new("..") {
            return Err(PlatformError::UntrustedPath {
                path: joined,
                reason: "invalid output file name".into(),
            });
        }
        Ok(canonical_parent.join(name))
    }
}

/// Read bounded UTF-8 from an already validated file.
///
/// # Errors
///
/// Returns an error when the file is not regular, exceeds the byte limit, cannot
/// be read, or is not valid UTF-8.
pub fn read_bounded_utf8(path: impl AsRef<Path>, limit: u64) -> Result<String, PlatformError> {
    let path = path.as_ref();
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(PlatformError::UntrustedPath {
            path: path.to_path_buf(),
            reason: "expected a regular file".into(),
        });
    }
    if metadata.len() > limit {
        return Err(PlatformError::InputTooLarge {
            path: path.to_path_buf(),
            limit,
        });
    }
    let capacity = usize::try_from(metadata.len()).unwrap_or(0);
    let mut bytes = Vec::with_capacity(capacity);
    file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(PlatformError::InputTooLarge {
            path: path.to_path_buf(),
            limit,
        });
    }
    String::from_utf8(bytes).map_err(|_| PlatformError::InvalidUtf8 {
        path: path.to_path_buf(),
    })
}

/// Read bounded UTF-8 through one retained, non-reparse file handle.
///
/// Callers must first establish parent containment with [`PathPolicy`]. On
/// Windows this rejects a leaf reparse point and reads the same handle whose
/// final identity was resolved, closing the validation/read reopen window.
///
/// # Errors
///
/// Returns an error when the file is a reparse point, exceeds the bound, is not
/// regular UTF-8 input, or its retained handle cannot be resolved.
pub fn read_bounded_utf8_no_follow(
    path: impl AsRef<Path>,
    limit: u64,
) -> Result<String, PlatformError> {
    #[cfg(windows)]
    {
        read_bounded_utf8_windows_no_follow(path.as_ref(), limit)
    }
    #[cfg(not(windows))]
    {
        read_bounded_utf8(path, limit)
    }
}

#[cfg(windows)]
fn read_bounded_utf8_windows_no_follow(path: &Path, limit: u64) -> Result<String, PlatformError> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_attributes() & 0x400 != 0 {
        return Err(PlatformError::UntrustedPath {
            path: path.to_path_buf(),
            reason: "retained input handle is not a regular non-reparse file".into(),
        });
    }
    let final_path = final_handle_path(&file)?;
    validate_retained_identity(path, &final_path)?;
    read_bounded_utf8_from_file(file, path, limit)
}

#[cfg(any(windows, test))]
fn validate_retained_identity(expected: &Path, actual: &Path) -> Result<(), PlatformError> {
    if normalize_final_path(actual) != normalize_final_path(expected) {
        return Err(PlatformError::UntrustedPath {
            path: actual.to_path_buf(),
            reason: "retained input handle identity differs from the validated path".into(),
        });
    }
    Ok(())
}

#[cfg(any(windows, test))]
fn normalize_final_path(path: &Path) -> String {
    let text = path.as_os_str().to_string_lossy();
    let text = text.strip_prefix(r"\\?\UNC\").map_or_else(
        || text.strip_prefix(r"\\?\").unwrap_or(&text).to_owned(),
        |unc| format!(r"\\{unc}"),
    );
    text.trim_end_matches(['\\', '/']).to_ascii_lowercase()
}

#[cfg(windows)]
fn final_handle_path(file: &File) -> Result<PathBuf, PlatformError> {
    use std::os::windows::io::AsRawHandle;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetFinalPathNameByHandleW(
            file: *mut core::ffi::c_void,
            path: *mut u16,
            length: u32,
            flags: u32,
        ) -> u32;
    }
    let mut path = vec![0_u16; 32_768];
    let length = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            path.as_mut_ptr(),
            u32::try_from(path.len()).expect("bounded final-path buffer"),
            0,
        )
    };
    if length == 0 || usize::try_from(length).map_or(true, |value| value >= path.len()) {
        return Err(PlatformError::TrustFailure(
            "could not resolve retained input handle identity".into(),
        ));
    }
    path.truncate(usize::try_from(length).expect("bounded final-path length"));
    Ok(PathBuf::from(String::from_utf16(&path).map_err(|_| {
        PlatformError::TrustFailure("retained input handle path was invalid UTF-16".into())
    })?))
}

#[cfg(windows)]
fn read_bounded_utf8_from_file(
    file: File,
    path: &Path,
    limit: u64,
) -> Result<String, PlatformError> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(PlatformError::UntrustedPath {
            path: path.to_path_buf(),
            reason: "expected a regular file".into(),
        });
    }
    if metadata.len() > limit {
        return Err(PlatformError::InputTooLarge {
            path: path.to_path_buf(),
            limit,
        });
    }
    let capacity = usize::try_from(metadata.len()).unwrap_or(0);
    let mut bytes = Vec::with_capacity(capacity);
    file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(PlatformError::InputTooLarge {
            path: path.to_path_buf(),
            limit,
        });
    }
    String::from_utf8(bytes).map_err(|_| PlatformError::InvalidUtf8 {
        path: path.to_path_buf(),
    })
}

/// Atomically replace one output using a same-directory temporary file.
///
/// # Errors
///
/// Returns an error when the output name is invalid or the temporary write,
/// synchronization, or atomic rename fails.
pub fn atomic_write(path: impl AsRef<Path>, bytes: &[u8]) -> Result<(), PlatformError> {
    let path = path.as_ref();
    let parent = path.parent().ok_or_else(|| PlatformError::UntrustedPath {
        path: path.to_path_buf(),
        reason: "output has no parent".into(),
    })?;
    let name =
        path.file_name()
            .and_then(OsStr::to_str)
            .ok_or_else(|| PlatformError::UntrustedPath {
                path: path.to_path_buf(),
                reason: "output file name is not Unicode".into(),
            })?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let temporary = parent.join(format!(".{name}.{}.{}.tmp", std::process::id(), nonce));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let write_result = (|| -> Result<(), PlatformError> {
        let mut file = options.open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    write_result
}

fn reject_lexical_escape(path: &Path) -> Result<(), PlatformError> {
    if path
        .components()
        .any(|component| component == Component::ParentDir)
    {
        return Err(PlatformError::UntrustedPath {
            path: path.to_path_buf(),
            reason: "parent traversal is forbidden".into(),
        });
    }
    Ok(())
}

fn reject_unc(path: &Path, allow_unc: bool) -> Result<(), PlatformError> {
    let text = path.as_os_str().to_string_lossy();
    if !allow_unc && (text.starts_with("\\\\") || text.starts_with("//")) {
        return Err(PlatformError::UntrustedPath {
            path: path.to_path_buf(),
            reason: "UNC paths are forbidden".into(),
        });
    }
    Ok(())
}

fn reject_reparse_chain(path: &Path) -> Result<(), PlatformError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_symlink() || has_windows_reparse_attribute(&metadata) {
            return Err(PlatformError::UntrustedPath {
                path: current,
                reason: "reparse points and symbolic links are forbidden".into(),
            });
        }
    }
    Ok(())
}

#[cfg(windows)]
fn has_windows_reparse_attribute(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
const fn has_windows_reparse_attribute(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_rejects_parent_traversal() {
        let root = tempfile::tempdir().expect("root");
        let policy = PathPolicy::new(root.path()).expect("policy");
        assert!(policy.output_file("../escape.json").is_err());
    }

    #[test]
    fn bounded_reader_rejects_oversized_input() {
        let root = tempfile::tempdir().expect("root");
        let path = root.path().join("large.json");
        fs::write(&path, b"12345").expect("write");
        assert!(matches!(
            read_bounded_utf8(path, 4),
            Err(PlatformError::InputTooLarge { .. })
        ));
    }

    #[test]
    fn retained_reader_uses_the_same_bounded_input_contract() {
        let root = tempfile::tempdir().expect("root");
        let path = root.path().join("profile.json");
        fs::write(&path, br#"{"schema_version":"v3"}"#).expect("write");
        assert_eq!(
            read_bounded_utf8_no_follow(&path, 1024).expect("retained read"),
            r#"{"schema_version":"v3"}"#
        );
        assert!(matches!(
            read_bounded_utf8_no_follow(&path, 4),
            Err(PlatformError::InputTooLarge { .. })
        ));
    }

    #[test]
    fn retained_identity_rejects_a_final_handle_path_that_changed() {
        assert!(
            validate_retained_identity(
                Path::new(r"C:\trusted\profile.json"),
                Path::new(r"\\?\C:\escaped\profile.json"),
            )
            .is_err()
        );
        assert!(
            validate_retained_identity(
                Path::new(r"C:\trusted\profile.json"),
                Path::new(r"\\?\C:\trusted\profile.json"),
            )
            .is_ok()
        );
    }

    #[test]
    fn atomic_write_replaces_the_complete_file() {
        let root = tempfile::tempdir().expect("root");
        let path = root.path().join("result.json");
        atomic_write(&path, b"first").expect("first");
        atomic_write(&path, b"second").expect("second");
        assert_eq!(fs::read(path).expect("read"), b"second");
    }
}
