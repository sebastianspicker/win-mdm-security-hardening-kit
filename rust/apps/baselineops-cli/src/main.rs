//! Standard-user `BaselineOps` v3 command-line interface.

#[cfg(windows)]
mod apply;
mod audit;
mod plan;

use anyhow::{Context, Result, anyhow, bail};
use baselineops_capabilities::{Batch, CapabilityDescriptor};
use baselineops_domain::{ExitCode, JsonLoadLimits, PlanV3, ProfileId, ProfileV3, ResultV3};
use baselineops_engine::{
    DetachedSignatureVerifier, PackageError, SignatureVerifier, aggregate, verify_package,
};
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::{Path, PathBuf};

#[derive(Debug, Parser)]
#[command(name = "baselineops", version, about = "BaselineOps for Windows v3")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Catalog {
        #[command(subcommand)]
        command: CatalogCommand,
    },
    /// Observe supported endpoint state without changing configuration.
    Audit(Selection),
    /// Produce a proposal only when a worker-owned mutation deriver is available.
    Plan {
        #[command(flatten)]
        selection: Selection,
        #[arg(long)]
        output: PathBuf,
    },
    /// Ask the protected UAC worker to revalidate and refuse or apply a plan.
    Apply {
        plan_file: PathBuf,
        /// Exact digest displayed by the worker proposal; required with `--yes`.
        #[arg(long)]
        approve_digest: Option<String>,
        #[arg(long)]
        yes: bool,
    },
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
    },
    Report {
        #[command(subcommand)]
        command: ReportCommand,
    },
    Package {
        #[command(subcommand)]
        command: PackageCommand,
    },
}

#[derive(Debug, Subcommand)]
enum CatalogCommand {
    List,
    Show { id: String },
}

#[derive(Debug, Args)]
pub(crate) struct Selection {
    #[arg(long, conflicts_with_all = ["profile", "batch"], required_unless_present_any = ["profile", "batch"])]
    capability: Option<String>,
    #[arg(long, conflicts_with_all = ["capability", "batch"])]
    profile: Option<PathBuf>,
    #[arg(long, value_enum, conflicts_with_all = ["capability", "profile"])]
    batch: Option<BatchArg>,
    /// Local archive directory required by the support-bundle parser.
    #[arg(long, requires = "capability", value_name = "DIR")]
    support_dir: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum BatchArg {
    Audit,
    Remediation,
    Collection,
    Utility,
    Monitoring,
    All,
}

impl From<BatchArg> for Batch {
    fn from(value: BatchArg) -> Self {
        match value {
            BatchArg::Audit => Self::Audit,
            BatchArg::Remediation => Self::Remediation,
            BatchArg::Collection => Self::Collection,
            BatchArg::Utility => Self::Utility,
            BatchArg::Monitoring => Self::Monitoring,
            BatchArg::All => Self::All,
        }
    }
}

#[derive(Debug, Subcommand)]
enum ProfileCommand {
    Validate { file: PathBuf },
}

#[derive(Debug, Subcommand)]
enum ReportCommand {
    Aggregate {
        #[arg(required = true, num_args = 1..)]
        inputs: Vec<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum PackageCommand {
    Verify { package: PathBuf },
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
    let exit = match run(Cli::parse()) {
        Ok(exit) => exit,
        Err(error) => {
            eprintln!("baselineops: {error:#}");
            classify_error(&error)
        }
    };
    std::process::exit(exit.as_i32());
}

fn run(cli: Cli) -> Result<ExitCode> {
    match cli.command {
        Command::Catalog { command } => catalog(command),
        Command::Audit(selection) => audit::run(&selection),
        Command::Plan { selection, output } => plan::run(&selection, &output),
        Command::Apply {
            plan_file,
            approve_digest,
            yes,
        } => {
            baselineops_windows::collect_host_identity()?;
            apply(&plan_file, approve_digest.as_deref(), yes)
        }
        Command::Profile { command } => profile(command),
        Command::Report { command } => report(command),
        Command::Package { command } => package(command),
    }
}

fn catalog(command: CatalogCommand) -> Result<ExitCode> {
    match command {
        CatalogCommand::List => print_json(baselineops_capabilities::list())?,
        CatalogCommand::Show { id } => print_json(
            baselineops_capabilities::lookup(&id)
                .ok_or_else(|| anyhow!("unknown capability ID: {id}"))?,
        )?,
    }
    Ok(ExitCode::Completed)
}

fn apply(path: &Path, approve_digest: Option<&str>, yes: bool) -> Result<ExitCode> {
    let plan: PlanV3 = baselineops_domain::load_json_file(path, JsonLoadLimits::default())?;
    plan.validate_structure()?;
    if yes && approve_digest.is_none() {
        bail!(
            "--yes requires --approve-digest from the worker proposal; it never approves a local plan"
        );
    }
    #[cfg(windows)]
    {
        apply::run(&plan, approve_digest)
    }
    #[cfg(not(windows))]
    unsupported_response("apply", &["Windows protected worker"])
}

pub(crate) fn unsupported_response(operation: &str, capabilities: &[&str]) -> Result<ExitCode> {
    print_json(
        &serde_json::json!({"status":"unsupported", "operation": operation, "capabilities": capabilities, "reason":"no worker-owned native mutation implementation is available"}),
    )?;
    Ok(ExitCode::Unsupported)
}

pub(crate) fn resolve_selection(
    selection: &Selection,
) -> Result<(Vec<&'static CapabilityDescriptor>, Option<ProfileId>)> {
    if let Some(id) = &selection.capability {
        return baselineops_capabilities::lookup(id)
            .map(|descriptor| (vec![descriptor], None))
            .ok_or_else(|| anyhow!("unknown capability ID: {id}"));
    }
    if let Some(path) = &selection.profile {
        let profile: ProfileV3 =
            baselineops_domain::load_json_file(path, JsonLoadLimits::default())?;
        profile.validate()?;
        let descriptors = profile
            .steps
            .iter()
            .map(|step| {
                baselineops_capabilities::lookup(step.capability_id.as_str()).ok_or_else(|| {
                    anyhow!(
                        "profile references unknown capability: {}",
                        step.capability_id
                    )
                })
            })
            .collect::<Result<Vec<_>>>()?;
        return Ok((descriptors, Some(profile.id)));
    }
    selection
        .batch
        .map(|batch| (baselineops_capabilities::select_batch(batch.into()), None))
        .ok_or_else(|| anyhow!("exactly one selector is required"))
}

fn profile(command: ProfileCommand) -> Result<ExitCode> {
    match command {
        ProfileCommand::Validate { file } => {
            let profile: ProfileV3 =
                baselineops_domain::load_json_file(file, JsonLoadLimits::default())?;
            let validation = profile.validate()?;
            print_json(
                &serde_json::json!({"status":"valid","profileId":profile.id,"stepCount":profile.steps.len(),"topologicalOrder":validation.topological_order.as_slice()}),
            )?;
            Ok(ExitCode::Completed)
        }
    }
}
fn report(command: ReportCommand) -> Result<ExitCode> {
    match command {
        ReportCommand::Aggregate { inputs } => {
            let results = inputs
                .iter()
                .map(|path| {
                    baselineops_domain::load_json_file::<ResultV3>(path, JsonLoadLimits::default())
                        .with_context(|| format!("invalid result {}", path.display()))
                })
                .collect::<Result<Vec<_>>>()?;
            print_json(&aggregate(&results)?)?;
            Ok(ExitCode::Completed)
        }
    }
}
fn package(command: PackageCommand) -> Result<ExitCode> {
    match command {
        PackageCommand::Verify { package } => {
            let signer = release_signer_identity()?;
            print_json(&verify_package(
                package,
                &signer.subject,
                &PlatformDetachedSignatureVerifier::new(&signer),
                &PlatformSignatureVerifier::new(&signer),
            )?)?;
            Ok(ExitCode::Completed)
        }
    }
}

#[derive(Clone)]
pub(crate) struct ReleaseSignerIdentity {
    pub(crate) subject: String,
    pub(crate) spki_sha256: baselineops_windows::SignerSpkiSha256,
}

pub(crate) fn release_signer_identity() -> Result<ReleaseSignerIdentity> {
    let subject = option_env!("BASELINEOPS_EXPECTED_SIGNER_SUBJECT")
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow!("this build has no embedded trusted release signer subject"))?;
    let spki_sha256 = option_env!("BASELINEOPS_EXPECTED_SIGNER_SPKI_SHA256")
        .ok_or_else(|| anyhow!("this build has no embedded trusted release signer SPKI pin"))
        .and_then(|value| {
            baselineops_windows::SignerSpkiSha256::from_hex(value).map_err(|error| anyhow!(error))
        })?;
    Ok(ReleaseSignerIdentity {
        subject: subject.into(),
        spki_sha256,
    })
}

pub(crate) struct PlatformDetachedSignatureVerifier {
    signer: ReleaseSignerIdentity,
}

impl PlatformDetachedSignatureVerifier {
    pub(crate) fn new(signer: &ReleaseSignerIdentity) -> Self {
        Self {
            signer: signer.clone(),
        }
    }
}

impl DetachedSignatureVerifier for PlatformDetachedSignatureVerifier {
    fn verify(
        &self,
        signed_bytes: &[u8],
        signature_bytes: &[u8],
        expected_subject: &str,
    ) -> Result<(), PackageError> {
        if expected_subject != self.signer.subject {
            return Err(PackageError::Signature(
                "package verifier received an untrusted signer subject".into(),
            ));
        }
        baselineops_windows::verify_detached_manifest(
            signed_bytes,
            signature_bytes,
            &self.signer.subject,
            &self.signer.spki_sha256,
        )
        .map_err(|error| PackageError::Signature(error.to_string()))
    }
}
pub(crate) struct PlatformSignatureVerifier {
    signer: ReleaseSignerIdentity,
}

impl PlatformSignatureVerifier {
    pub(crate) fn new(signer: &ReleaseSignerIdentity) -> Self {
        Self {
            signer: signer.clone(),
        }
    }
}

impl SignatureVerifier for PlatformSignatureVerifier {
    fn verify(&self, executable: &Path, expected_subject: &str) -> Result<(), PackageError> {
        if expected_subject != self.signer.subject {
            return Err(PackageError::Signature(
                "package verifier received an untrusted signer subject".into(),
            ));
        }
        baselineops_windows::verify_authenticode(
            executable,
            &self.signer.subject,
            &self.signer.spki_sha256,
        )
        .map_err(|error| PackageError::Signature(error.to_string()))
    }
}
fn print_json(value: &(impl serde::Serialize + ?Sized)) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}
fn classify_error(error: &anyhow::Error) -> ExitCode {
    if error
        .downcast_ref::<baselineops_windows::PlatformError>()
        .is_some_and(baselineops_windows::PlatformError::is_unsupported_host)
    {
        return ExitCode::Unsupported;
    }
    if error.downcast_ref::<PackageError>().is_some()
        || error
            .downcast_ref::<baselineops_domain::DomainError>()
            .is_some()
        || error
            .downcast_ref::<baselineops_windows::PlatformError>()
            .is_some()
    {
        ExitCode::Rejected
    } else {
        ExitCode::ExecutionFailure
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_explicit_read_only_native_slices_are_routable() {
        assert!(audit::native_audit_supported(
            baselineops_capabilities::lookup("v3.doh.audit").expect("descriptor")
        ));
        assert!(audit::native_audit_supported(
            baselineops_capabilities::lookup("v3.network.configuration").expect("descriptor")
        ));
        assert!(audit::native_audit_supported(
            baselineops_capabilities::lookup("v3.service-process.inventory").expect("descriptor")
        ));
        assert!(audit::native_audit_supported(
            baselineops_capabilities::lookup("v3.support-bundle.parse").expect("descriptor")
        ));
        assert!(audit::native_audit_supported(
            baselineops_capabilities::lookup("v3.firewall.logging").expect("descriptor")
        ));
        assert!(audit::native_audit_supported(
            baselineops_capabilities::lookup("v3.defender.asr-allowlist").expect("descriptor")
        ));
        assert!(!audit::native_audit_supported(
            baselineops_capabilities::lookup("v3.support-bundle.collect").expect("descriptor")
        ));
    }
    #[test]
    fn unsupported_exit_is_stable() {
        assert_eq!(
            ExitCode::for_status(baselineops_domain::ResultStatus::Unsupported).as_i32(),
            3
        );
    }

    #[test]
    fn unsupported_hosts_map_to_exit_three_without_reclassifying_trust_failures() {
        let unsupported = anyhow!(baselineops_windows::PlatformError::UnsupportedHost(
            "Windows Home is not supported".into()
        ));
        assert_eq!(classify_error(&unsupported), ExitCode::Unsupported);

        let unsupported_platform = anyhow!(baselineops_windows::PlatformError::UnsupportedPlatform);
        assert_eq!(classify_error(&unsupported_platform), ExitCode::Unsupported);

        let trust_failure = anyhow!(baselineops_windows::PlatformError::TrustFailure(
            "signature check failed".into()
        ));
        assert_eq!(classify_error(&trust_failure), ExitCode::Rejected);
    }
}
