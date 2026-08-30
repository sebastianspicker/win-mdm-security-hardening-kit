use anyhow::{Context, Result, bail};
use baselineops_domain::Sha256Digest;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

pub(crate) fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    for path in sorted_files_recursive(source)? {
        let relative = path.strip_prefix(source)?;
        copy_regular(&path, &destination.join(relative))?;
    }
    Ok(())
}

pub(crate) fn copy_regular(source: &Path, destination: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(source)
        .with_context(|| format!("missing package input {}", source.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        bail!("package input is not a regular file: {}", source.display());
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(source, destination)?;
    Ok(())
}

pub(crate) fn sorted_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = fs::read_dir(root)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    files.retain(|path| path.is_file());
    files.sort();
    Ok(files)
}

pub(crate) fn sorted_files_recursive(root: &Path) -> Result<Vec<PathBuf>> {
    if !root.is_dir() {
        bail!("directory is absent: {}", root.display());
    }
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(directory) = pending.pop() {
        collect_directory_entries(&directory, &mut pending, &mut files)?;
    }
    files.sort();
    Ok(files)
}

fn collect_directory_entries(
    directory: &Path,
    pending: &mut Vec<PathBuf>,
    files: &mut Vec<PathBuf>,
) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        collect_entry(entry?.path(), pending, files)?;
    }
    Ok(())
}

fn collect_entry(
    path: PathBuf,
    pending: &mut Vec<PathBuf>,
    files: &mut Vec<PathBuf>,
) -> Result<()> {
    let metadata = fs::symlink_metadata(&path)?;
    if metadata.file_type().is_symlink() {
        bail!(
            "symbolic links are forbidden in generated inputs: {}",
            path.display()
        );
    }
    if metadata.is_file() {
        files.push(path);
        return Ok(());
    }
    let is_build_output = path.file_name().and_then(|name| name.to_str()) == Some("target");
    if metadata.is_dir() && !is_build_output {
        pending.push(path);
    }
    Ok(())
}

pub(crate) fn hash_file(path: impl AsRef<Path>) -> Result<Sha256Digest> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(Sha256Digest::from_digest_bytes(digest.finalize().into()))
}
