//! Shell-free, bounded support-bundle archive parser.

use baselineops_capabilities::{
    BundleArtifact, CapabilityDescriptor, CapabilityExecutor, CapabilityOutcome, CapabilityRequest,
    EXPECTED_PROOFS, KbStatus, MAX_JSON_BYTES, MAX_SUMMARY_ITEMS, Operation, ProofObservation,
    SupportBundleParserAudit, SupportBundleParserObservation, SupportBundleParserParameters,
    SupportBundleSummary, evaluate_support_bundle_parser,
};
use baselineops_windows::{
    ArchivePolicy, PathPolicy, PlatformError, extract_zip_safely, read_bounded_utf8,
};
use std::{
    fs,
    fs::File,
    path::{Path, PathBuf},
};

const MAX_ARCHIVE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES: usize = 2_048;
const MAX_MEMBER_BYTES: u64 = 128 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
const MAX_COMPRESSION_RATIO: u64 = 100;
const MAX_PATH_BYTES: usize = 4_096;

/// Native executor for capability 10.
///
/// The protected extraction root is fixed by the installed runtime. It must
/// already exist and be provisioned outside this standard-user audit path.
pub struct SupportBundleParserExecutor;

impl CapabilityExecutor for SupportBundleParserExecutor {
    fn execute(
        &self,
        descriptor: &'static CapabilityDescriptor,
        request: CapabilityRequest<'_>,
    ) -> CapabilityOutcome {
        if request.operation != Operation::Audit {
            return failed(descriptor, "support-bundle parser is read-only");
        }
        let result = (|| {
            let parameters: SupportBundleParserParameters =
                serde_json::from_value(request.parameters.clone()).map_err(|error| {
                    PlatformError::TrustFailure(format!(
                        "invalid support-bundle parameters: {error}"
                    ))
                })?;
            let root = installed_extract_root()?;
            serde_json::to_value(parse_support_bundle(&parameters, &root)?)
                .map_err(|error| PlatformError::TrustFailure(error.to_string()))
        })();
        match result {
            Ok(result) => CapabilityOutcome::Completed { result },
            Err(error) => failed(descriptor, &error.to_string()),
        }
    }
}

/// Parses the newest local bundle below a fixed, pre-provisioned extraction root.
///
/// No archive content is executed. A temporary extraction directory is removed
/// before return, so a later run cannot consume stale sidecar evidence.
///
/// # Errors
///
/// Returns an error when a path, ZIP member, quota, or strict JSON contract is
/// untrusted, malformed, incomplete, or unavailable.
pub fn parse_support_bundle(
    parameters: &SupportBundleParserParameters,
    protected_extract_root: &Path,
) -> Result<SupportBundleParserAudit, PlatformError> {
    let support_dir = canonical_directory(&parameters.support_dir, "support directory")?;
    let extract_root = canonical_directory(protected_extract_root, "protected extraction root")?;
    let input_policy = PathPolicy::new(&support_dir)?;
    let bundle = newest_bundle(&support_dir, &input_policy)?;
    let archive_bytes = fs::metadata(&bundle)?.len();
    preflight_archive(&bundle, archive_bytes)?;

    let extraction = tempfile::Builder::new()
        .prefix("support-bundle-")
        .tempdir_in(&extract_root)
        .map_err(PlatformError::Io)?;
    let policy = ArchivePolicy {
        max_files: MAX_ARCHIVE_ENTRIES,
        max_file_bytes: MAX_MEMBER_BYTES,
        max_total_bytes: MAX_TOTAL_BYTES,
        max_depth: 16,
    };
    let paths = extract_zip_safely(File::open(&bundle)?, extraction.path(), policy)?;
    let extraction_policy = PathPolicy::new(extraction.path())?;
    let summary_path = extraction_policy
        .existing_file("Summary.json")
        .map_err(|_| PlatformError::ArchiveRejected("archive lacks a root Summary.json".into()))?;
    let summary = parse_json::<SupportBundleSummary>(&summary_path, "Summary.json")?;
    validate_summary(&summary)?;
    let members = retain_members(extraction.path(), &paths)?;
    let kb_status = find_kb_status(extraction.path(), &members)?;
    let observation = SupportBundleParserObservation {
        bundle_name: bundle_name(&bundle)?,
        bundle_path: bundle,
        archive_bytes,
        proofs: observe_proofs(&summary, &members),
        event_logs: event_logs(&members),
        artifacts: artifacts(&members),
        kb_status,
        summary,
    };
    Ok(evaluate_support_bundle_parser(observation))
}

fn installed_extract_root() -> Result<PathBuf, PlatformError> {
    let program_data = std::env::var_os("ProgramData").ok_or_else(|| {
        PlatformError::TrustFailure(
            "ProgramData is unavailable for the fixed extraction root".into(),
        )
    })?;
    Ok(PathBuf::from(program_data)
        .join("BaselineOpsForWindows")
        .join("SupportBundles")
        .join("_extracted"))
}

fn canonical_directory(path: &Path, label: &str) -> Result<PathBuf, PlatformError> {
    if path.as_os_str().to_string_lossy().len() > MAX_PATH_BYTES {
        return Err(PlatformError::TrustFailure(format!(
            "{label} path is too long"
        )));
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || has_windows_reparse_attribute(&metadata) {
        return Err(PlatformError::UntrustedPath {
            path: path.into(),
            reason: format!("{label} cannot be a reparse point or symbolic link"),
        });
    }
    let canonical = fs::canonicalize(path)?;
    if !canonical.is_dir() {
        return Err(PlatformError::UntrustedPath {
            path: canonical,
            reason: format!("{label} is not a directory"),
        });
    }
    Ok(canonical)
}

#[cfg(windows)]
fn has_windows_reparse_attribute(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
const fn has_windows_reparse_attribute(_: &fs::Metadata) -> bool {
    false
}

fn newest_bundle(root: &Path, policy: &PathPolicy) -> Result<PathBuf, PlatformError> {
    let mut candidates = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if is_bundle_name(&name) {
            let file = policy.existing_file(entry.path())?;
            candidates.push((fs::metadata(&file)?.modified()?, file));
        }
    }
    candidates
        .into_iter()
        .max_by_key(|(modified, _)| *modified)
        .map(|(_, path)| path)
        .ok_or_else(|| PlatformError::TrustFailure("no SupportBundle-*.zip was found".into()))
}

fn is_bundle_name(name: &str) -> bool {
    let folded = name.to_ascii_lowercase();
    folded.starts_with("supportbundle-")
        && Path::new(&folded)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("zip"))
}

fn bundle_name(path: &Path) -> Result<String, PlatformError> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .ok_or_else(|| PlatformError::TrustFailure("selected bundle name is not Unicode".into()))
}

fn preflight_archive(path: &Path, archive_bytes: u64) -> Result<(), PlatformError> {
    if archive_bytes > MAX_ARCHIVE_BYTES {
        return Err(PlatformError::ArchiveRejected(
            "archive exceeds compressed-size quota".into(),
        ));
    }
    let mut archive = zip::ZipArchive::new(File::open(path)?)
        .map_err(|error| PlatformError::ArchiveRejected(error.to_string()))?;
    if archive.len() > MAX_ARCHIVE_ENTRIES {
        return Err(PlatformError::ArchiveRejected(
            "archive has too many entries".into(),
        ));
    }
    let mut total = 0_u64;
    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .map_err(|error| PlatformError::ArchiveRejected(error.to_string()))?;
        if entry.size() > MAX_MEMBER_BYTES {
            return Err(PlatformError::ArchiveRejected(
                "archive member exceeds byte quota".into(),
            ));
        }
        total = total
            .checked_add(entry.size())
            .ok_or_else(|| PlatformError::ArchiveRejected("archive size overflow".into()))?;
        if total > MAX_TOTAL_BYTES {
            return Err(PlatformError::ArchiveRejected(
                "archive exceeds total byte quota".into(),
            ));
        }
        if entry.size() > 0
            && (entry.compressed_size() == 0
                || entry.size() / entry.compressed_size().max(1) > MAX_COMPRESSION_RATIO)
        {
            return Err(PlatformError::ArchiveRejected(
                "archive member exceeds compression-ratio quota".into(),
            ));
        }
    }
    Ok(())
}

fn parse_json<T>(path: &Path, label: &str) -> Result<T, PlatformError>
where
    T: for<'de> serde::Deserialize<'de>,
{
    let text = read_bounded_utf8(path, MAX_JSON_BYTES)?;
    serde_json::from_str(&text)
        .map_err(|error| PlatformError::ArchiveRejected(format!("invalid {label}: {error}")))
}

fn validate_summary(summary: &SupportBundleSummary) -> Result<(), PlatformError> {
    let lists = [&summary.errors, &summary.notes, &summary.outputs];
    if lists.iter().any(|items| items.len() > MAX_SUMMARY_ITEMS)
        || summary.records.len() > MAX_SUMMARY_ITEMS
    {
        return Err(PlatformError::ArchiveRejected(
            "summary list exceeds item quota".into(),
        ));
    }
    if lists
        .iter()
        .flat_map(|items| items.iter())
        .any(|value| value.len() > 8_192)
    {
        return Err(PlatformError::ArchiveRejected(
            "summary string exceeds byte quota".into(),
        ));
    }
    Ok(())
}

fn retain_members(root: &Path, paths: &[PathBuf]) -> Result<Vec<BundleArtifact>, PlatformError> {
    paths
        .iter()
        .map(|path| {
            let relative = path.strip_prefix(root).map_err(|_| {
                PlatformError::ArchiveRejected("extracted member escaped temporary root".into())
            })?;
            Ok(BundleArtifact {
                kind: "archive_member".into(),
                relative_path: relative.to_string_lossy().replace('\\', "/"),
                size_bytes: fs::metadata(path)?.len(),
            })
        })
        .collect()
}

fn find_kb_status(
    root: &Path,
    members: &[BundleArtifact],
) -> Result<Option<KbStatus>, PlatformError> {
    let Some(member) = members
        .iter()
        .find(|member| leaf(&member.relative_path) == "KBStatus.json")
    else {
        return Ok(None);
    };
    let path = root.join(
        member
            .relative_path
            .replace('/', std::path::MAIN_SEPARATOR_STR),
    );
    Ok(Some(parse_json(&path, "KBStatus.json")?))
}

fn observe_proofs(
    summary: &SupportBundleSummary,
    members: &[BundleArtifact],
) -> Vec<ProofObservation> {
    EXPECTED_PROOFS
        .iter()
        .map(|expected| {
            let member = members
                .iter()
                .find(|member| leaf(&member.relative_path) == *expected);
            ProofObservation {
                file_name: (*expected).into(),
                present_by_file: member.is_some(),
                present_by_output: summary
                    .outputs
                    .iter()
                    .any(|output| output.contains(expected)),
                relative_path: member.map(|member| member.relative_path.clone()),
            }
        })
        .collect()
}

fn event_logs(members: &[BundleArtifact]) -> Vec<BundleArtifact> {
    members
        .iter()
        .filter(|member| {
            member.relative_path.starts_with("eventlogs/")
                && member.relative_path.to_ascii_lowercase().ends_with(".evtx")
        })
        .map(|member| BundleArtifact {
            kind: "event_log".into(),
            relative_path: member.relative_path.clone(),
            size_bytes: member.size_bytes,
        })
        .collect()
}

fn artifacts(members: &[BundleArtifact]) -> Vec<BundleArtifact> {
    members
        .iter()
        .filter(|member| {
            member.relative_path == "Summary.json"
                || leaf(&member.relative_path) == "KBStatus.json"
                || EXPECTED_PROOFS.contains(&leaf(&member.relative_path))
                || (member.relative_path.starts_with("eventlogs/")
                    && member.relative_path.to_ascii_lowercase().ends_with(".evtx"))
        })
        .cloned()
        .collect()
}

fn leaf(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn failed(descriptor: &'static CapabilityDescriptor, message: &str) -> CapabilityOutcome {
    CapabilityOutcome::Failed {
        capability_id: descriptor.id.into(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};
    use zip::write::SimpleFileOptions;

    fn summary() -> &'static [u8] {
        br#"{"Hostname":"host","Outputs":["SysmonState.json"],"Records":[]}"#
    }

    fn bundle(root: &Path, members: &[(&str, &[u8], u32)]) -> PathBuf {
        let path = root.join("SupportBundle-fixture.zip");
        let mut bytes = Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut bytes);
            for (name, content, mode) in members {
                zip.start_file(*name, SimpleFileOptions::default().unix_permissions(*mode))
                    .expect("member");
                zip.write_all(content).expect("content");
            }
            zip.finish().expect("finish");
        }
        fs::write(&path, bytes.into_inner()).expect("write fixture");
        path
    }

    fn parse(root: &Path, extract: &Path) -> Result<SupportBundleParserAudit, PlatformError> {
        parse_support_bundle(
            &SupportBundleParserParameters {
                support_dir: root.into(),
            },
            extract,
        )
    }

    #[test]
    fn parses_only_archive_evidence_and_marks_missing_evidence() {
        let source = tempfile::tempdir().expect("source");
        let extract = tempfile::tempdir().expect("extract");
        bundle(
            source.path(),
            &[
                ("Summary.json", summary(), 0o100_644),
                ("eventlogs/System.evtx", b"evtx", 0o100_644),
                ("KBStatus.json", br#"{"Installed":[]}"#, 0o100_644),
            ],
        );
        fs::write(source.path().join("Summary.json"), b"not JSON").expect("stale sidecar");
        let audit = parse(source.path(), extract.path()).expect("parse archive");
        assert_eq!(audit.observation.summary.hostname.as_deref(), Some("host"));
        assert!(
            audit
                .findings
                .iter()
                .any(|finding| finding.code == "SB-MissingProof")
        );
    }

    #[test]
    fn rejects_adversarial_zip_members_and_json() {
        for (name, content, mode) in [
            ("../Summary.json", summary(), 0o100_644),
            ("CON.json", b"{}".as_slice(), 0o100_644),
            ("link", b"target".as_slice(), 0o120_777),
        ] {
            let source = tempfile::tempdir().expect("source");
            let extract = tempfile::tempdir().expect("extract");
            bundle(source.path(), &[(name, content, mode)]);
            assert!(parse(source.path(), extract.path()).is_err(), "{name}");
        }
        let source = tempfile::tempdir().expect("source");
        let extract = tempfile::tempdir().expect("extract");
        bundle(
            source.path(),
            &[("Summary.json", br#"{"Unknown":true}"#, 0o100_644)],
        );
        assert!(parse(source.path(), extract.path()).is_err());
    }

    #[test]
    fn preflight_rejects_duplicates_case_collisions_and_limits() {
        let source = tempfile::tempdir().expect("source");
        let extract = tempfile::tempdir().expect("extract");
        bundle(
            source.path(),
            &[
                ("Summary.json", summary(), 0o100_644),
                ("summary.JSON", summary(), 0o100_644),
            ],
        );
        assert!(parse(source.path(), extract.path()).is_err());

        let source = tempfile::tempdir().expect("source");
        let oversized_summary = vec![0; 32 * 1024];
        let path = bundle(
            source.path(),
            &[("Summary.json", &oversized_summary, 0o100_644)],
        );
        assert!(preflight_archive(&path, fs::metadata(&path).expect("metadata").len()).is_err());

        let source = tempfile::tempdir().expect("source");
        let path = source.path().join("SupportBundle-many.zip");
        let file = File::create(&path).expect("archive");
        let mut zip = zip::ZipWriter::new(file);
        for index in 0..=MAX_ARCHIVE_ENTRIES {
            zip.start_file(format!("proofs/{index}.json"), SimpleFileOptions::default())
                .expect("member");
            zip.write_all(b"{}").expect("content");
        }
        zip.finish().expect("finish");
        assert!(preflight_archive(&path, fs::metadata(&path).expect("metadata").len()).is_err());
    }
}
