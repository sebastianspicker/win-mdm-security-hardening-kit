use super::acl::{self, TrustedSids};
use crate::PlatformError;
use std::mem::MaybeUninit;
use std::path::{Path, PathBuf};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, GetFileInformationByHandle, GetFinalPathNameByHandleW, OPEN_EXISTING,
    READ_CONTROL,
};
use windows::core::PCWSTR;

pub(super) struct OpenedPath {
    handle: PendingHandle,
    final_path: PathBuf,
    information: BY_HANDLE_FILE_INFORMATION,
}

struct PendingHandle(HANDLE);

impl PendingHandle {
    fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for PendingHandle {
    fn drop(&mut self) {
        // Closing a handle cannot make a failed trust check succeed.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

impl OpenedPath {
    pub(super) fn handle(&self) -> HANDLE {
        self.handle.raw()
    }

    pub(super) fn final_path(&self) -> &Path {
        &self.final_path
    }

    fn information(&self) -> &BY_HANDLE_FILE_INFORMATION {
        &self.information
    }
}

pub(super) fn open_directory(path: &Path) -> Result<OpenedPath, PlatformError> {
    let opened = open_no_reparse(path, true)?;
    if opened.information().dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 == 0 {
        return Err(untrusted(path, "protected root is not a directory"));
    }
    Ok(opened)
}

pub(super) fn open_regular_file(path: &Path) -> Result<OpenedPath, PlatformError> {
    let opened = open_no_reparse(path, false)?;
    let attributes = opened.information().dwFileAttributes;
    if attributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0 {
        return Err(untrusted(path, "protected executable is a directory"));
    }
    Ok(opened)
}

pub(super) fn verify_containment(
    root: &OpenedPath,
    executable: &OpenedPath,
) -> Result<(), PlatformError> {
    if !path_is_within(executable.final_path(), root.final_path()) {
        return Err(untrusted(
            executable.final_path(),
            "executable final handle path escaped the protected root",
        ));
    }
    Ok(())
}

pub(super) fn verify_single_link(executable: &OpenedPath) -> Result<(), PlatformError> {
    if executable.information().nNumberOfLinks != 1 {
        return Err(untrusted(
            executable.final_path(),
            "protected executable must have exactly one hard link",
        ));
    }
    Ok(())
}

pub(super) fn verify_ancestors(
    root: &Path,
    trusted_sids: &TrustedSids,
) -> Result<(), PlatformError> {
    let mut current = root.parent().map(Path::to_path_buf);
    while let Some(path) = current {
        if is_volume_root(&path) {
            break;
        }
        let opened = open_directory(&path)?;
        acl::verify_object_acl(&opened, trusted_sids, false)?;
        current = path.parent().map(Path::to_path_buf);
    }
    Ok(())
}

fn open_no_reparse(path: &Path, directory: bool) -> Result<OpenedPath, PlatformError> {
    reject_lexical_escape(path)?;
    reject_unc(path)?;
    let wide = wide_path(path)?;
    let mut flags = FILE_FLAG_OPEN_REPARSE_POINT;
    if directory {
        flags |= FILE_FLAG_BACKUP_SEMANTICS;
    }
    let handle = PendingHandle(
        unsafe {
            CreateFileW(
                PCWSTR(wide.as_ptr()),
                (FILE_READ_ATTRIBUTES | READ_CONTROL).0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                flags,
                None,
            )
        }
        .map_err(|error| {
            PlatformError::TrustFailure(format!("could not open protected path: {error}"))
        })?,
    );
    let information = file_information(handle.raw())?;
    if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Err(untrusted(path, "reparse points are forbidden"));
    }
    let final_path = final_path(handle.raw())?;
    Ok(OpenedPath {
        handle,
        final_path,
        information,
    })
}

fn file_information(handle: HANDLE) -> Result<BY_HANDLE_FILE_INFORMATION, PlatformError> {
    let mut information = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::zeroed();
    unsafe { GetFileInformationByHandle(handle, information.as_mut_ptr()) }.map_err(|error| {
        PlatformError::TrustFailure(format!("could not read file identity: {error}"))
    })?;
    Ok(unsafe { information.assume_init() })
}

fn final_path(handle: HANDLE) -> Result<PathBuf, PlatformError> {
    let required = unsafe { GetFinalPathNameByHandleW(handle, &mut [], FILE_NAME_NORMALIZED) };
    if required == 0 {
        return Err(PlatformError::TrustFailure(
            "could not resolve final handle path".into(),
        ));
    }
    let mut buffer = vec![0_u16; usize::try_from(required).expect("final path length") + 1];
    let written = unsafe { GetFinalPathNameByHandleW(handle, &mut buffer, FILE_NAME_NORMALIZED) };
    if written == 0 || written >= u32::try_from(buffer.len()).expect("buffer length") {
        return Err(PlatformError::TrustFailure(
            "could not read final handle path".into(),
        ));
    }
    buffer.truncate(usize::try_from(written).expect("written length"));
    Ok(PathBuf::from(String::from_utf16(&buffer).map_err(
        |_| PlatformError::TrustFailure("final handle path is not valid UTF-16".into()),
    )?))
}

fn path_is_within(candidate: &Path, root: &Path) -> bool {
    let candidate = candidate.as_os_str().to_string_lossy();
    let root = root.as_os_str().to_string_lossy();
    if candidate.len() <= root.len() || !candidate[..root.len()].eq_ignore_ascii_case(&root) {
        return false;
    }
    matches!(candidate.as_bytes().get(root.len()), Some(b'\\' | b'/'))
}

fn is_volume_root(path: &Path) -> bool {
    path.parent().is_none() || path.components().count() <= 2
}

fn reject_lexical_escape(path: &Path) -> Result<(), PlatformError> {
    if path
        .components()
        .any(|component| component == std::path::Component::ParentDir)
    {
        return Err(untrusted(path, "parent traversal is forbidden"));
    }
    Ok(())
}

fn reject_unc(path: &Path) -> Result<(), PlatformError> {
    let value = path.as_os_str().to_string_lossy();
    if value.starts_with("\\\\") || value.starts_with("//") {
        return Err(untrusted(path, "UNC protected-install paths are forbidden"));
    }
    Ok(())
}

fn wide_path(path: &Path) -> Result<Vec<u16>, PlatformError> {
    use std::os::windows::ffi::OsStrExt;

    let mut value: Vec<u16> = path.as_os_str().encode_wide().collect();
    if value.is_empty() || value.contains(&0) {
        return Err(untrusted(path, "path contains an interior NUL or is empty"));
    }
    value.push(0);
    Ok(value)
}

fn untrusted(path: &Path, reason: &str) -> PlatformError {
    PlatformError::UntrustedPath {
        path: path.to_path_buf(),
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn containment_requires_a_component_boundary() {
        assert!(path_is_within(
            Path::new(r"\\?\C:\Program Files\BaselineOps\worker.exe"),
            Path::new(r"\\?\C:\Program Files\BaselineOps")
        ));
        assert!(!path_is_within(
            Path::new(r"\\?\C:\Program Files\BaselineOps-old\worker.exe"),
            Path::new(r"\\?\C:\Program Files\BaselineOps")
        ));
    }

    #[test]
    fn lexical_parent_traversal_is_rejected() {
        assert!(reject_lexical_escape(Path::new(r"C:\safe\..\worker.exe")).is_err());
    }
}
