//! Reproducible developer, schema, verification, and package tasks for `BaselineOps` v3.

mod generate;
mod package;
mod support;
mod verify;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "xtask", version)]
struct Arguments {
    #[command(subcommand)]
    command: Task,
}

#[derive(Debug, Subcommand)]
enum Task {
    /// Generate checked-in schemas and SBOM source data.
    Generate,
    /// Verify schemas, examples, registry parity, and no-shell package rules.
    Verify,
    /// Enforce release-only closure requirements before signing or packaging.
    ReleaseCheck {
        /// Exact Authenticode subject configured for this release.
        #[arg(long)]
        expected_signer: String,
        /// Lowercase SHA-256 pin of the signer's canonical DER `SubjectPublicKeyInfo`.
        #[arg(long)]
        expected_signer_spki_sha256: String,
        /// Exact Git tag being packaged.
        #[arg(long)]
        release_tag: String,
    },
    /// Stage payload bytes and an authoritative manifest before detached signing.
    PackageStage {
        /// Rust target containing release binaries.
        #[arg(long)]
        target: String,
        /// Empty or new staging directory.
        #[arg(long)]
        output: PathBuf,
        /// Exact signer embedded in the package manifest. Defaults to release env or unsigned marker.
        #[arg(long)]
        expected_signer: Option<String>,
        /// Lowercase SHA-256 pin required with --expected-signer for signed staging.
        #[arg(long)]
        expected_signer_spki_sha256: Option<String>,
    },
    /// Finalize a ZIP only after the staged detached manifest signature exists.
    PackageFinalize {
        /// Fully staged package directory containing manifest.json.p7.
        #[arg(long)]
        stage: PathBuf,
        /// Destination ZIP.
        #[arg(long)]
        output: PathBuf,
    },
    /// Independently extract and verify a release package.
    PackageVerify {
        /// ZIP package to verify.
        #[arg(long)]
        package: PathBuf,
        /// Exact expected Authenticode subject.
        #[arg(long)]
        expected_signer: String,
        /// Lowercase SHA-256 pin of the externally trusted signer.
        #[arg(long)]
        expected_signer_spki_sha256: String,
    },
}

fn main() -> Result<()> {
    let roots = Roots::discover()?;
    match Arguments::parse().command {
        Task::Generate => generate::generate(&roots),
        Task::Verify => verify::verify(&roots),
        Task::ReleaseCheck {
            expected_signer,
            expected_signer_spki_sha256,
            release_tag,
        } => verify::release_check(
            &roots,
            &expected_signer,
            &expected_signer_spki_sha256,
            &release_tag,
        ),
        Task::PackageStage {
            target,
            output,
            expected_signer,
            expected_signer_spki_sha256,
        } => package::stage_package(
            &roots,
            &target,
            &output,
            expected_signer,
            expected_signer_spki_sha256,
        ),
        Task::PackageFinalize { stage, output } => package::finalize_package(&stage, &output),
        Task::PackageVerify {
            package,
            expected_signer,
            expected_signer_spki_sha256,
        } => package::package_verify(&package, &expected_signer, &expected_signer_spki_sha256),
    }
}

struct Roots {
    rust: PathBuf,
    repository: PathBuf,
}

impl Roots {
    fn discover() -> Result<Self> {
        let xtask = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let rust = xtask
            .parent()
            .context("xtask must be inside the Rust workspace")?
            .to_path_buf();
        let repository = rust
            .parent()
            .context("Rust workspace must be inside the repository")?
            .to_path_buf();
        Ok(Self { rust, repository })
    }
}
