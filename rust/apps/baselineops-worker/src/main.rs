//! Short-lived elevated `BaselineOps` v3 worker entry point.

#![cfg_attr(windows, allow(unsafe_code))]

use anyhow::{Context, Result, anyhow, bail};
#[cfg(windows)]
use baselineops_domain::{
    ExecutionIntent, InputIdentityV3, JsonLoadLimits, PlanValidationContext, ProfileV3,
    Sha256Digest, SourceIdentityV3, SourceKind, ToolIdentityV3, load_profile_json,
};
use baselineops_domain::{ExitCode, PlanV3};
#[cfg(windows)]
use baselineops_engine::{
    DetachedSignatureVerifier, InstalledPackageExpectation, NativeObservationSource, PackageError,
    PlanBuildContext, SignatureVerifier, prepare_worker_apply, reobserve_profile,
    verify_installed_package,
};
use baselineops_windows::{InstallationTrustPolicy, verify_protected_install};
use clap::Parser;
use serde::Deserialize;
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(name = "baselineops-worker", version)]
struct Arguments {
    /// Random local named-pipe session identifier supplied as a direct UAC token.
    #[arg(long, value_parser = parse_session)]
    session: Uuid,
    /// Exact standard-user CLI process that must own the pipe client endpoint.
    #[arg(long, value_parser = parse_process_id)]
    client_pid: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(not(windows), allow(dead_code))]
struct ProposalRequest {
    plan: PlanV3,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(not(windows), allow(dead_code))]
struct ApprovalRequest {
    approved_digest: String,
}

#[derive(Clone)]
struct ReleaseSignerIdentity {
    subject: String,
    spki_sha256: baselineops_windows::SignerSpkiSha256,
}

fn release_signer_identity() -> Result<ReleaseSignerIdentity> {
    let subject = option_env!("BASELINEOPS_EXPECTED_SIGNER_SUBJECT")
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow!("worker build does not embed the release signer subject"))?;
    let spki_sha256 = option_env!("BASELINEOPS_EXPECTED_SIGNER_SPKI_SHA256")
        .ok_or_else(|| anyhow!("worker build does not embed the release signer SPKI pin"))
        .and_then(|value| {
            baselineops_windows::SignerSpkiSha256::from_hex(value).map_err(|error| anyhow!(error))
        })?;
    Ok(ReleaseSignerIdentity {
        subject: subject.into(),
        spki_sha256,
    })
}

fn main() {
    #[cfg(windows)]
    sanitize_environment();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
    let exit = match run(&Arguments::parse()) {
        Ok(exit) => exit,
        Err(error) => {
            eprintln!("baselineops-worker: {error:#}");
            ExitCode::Rejected
        }
    };
    std::process::exit(exit.as_i32());
}

/// Retain only a bounded diagnostic filter before tracing or worker setup reads env.
#[cfg(windows)]
fn sanitize_environment() {
    let rust_log = std::env::var_os("RUST_LOG").filter(|value| safe_log_filter(value));
    let keys = std::env::vars_os().map(|(key, _)| key).collect::<Vec<_>>();
    for key in keys {
        // The worker must not inherit loader, path, proxy, or application configuration.
        unsafe { std::env::remove_var(key) };
    }
    if let Some(rust_log) = rust_log {
        unsafe { std::env::set_var("RUST_LOG", rust_log) };
    }
}

#[cfg(any(windows, test))]
fn safe_log_filter(value: &std::ffi::OsStr) -> bool {
    let value = value.to_string_lossy();
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
}

fn run(arguments: &Arguments) -> Result<ExitCode> {
    let current_executable = std::env::current_exe().context("resolve worker executable")?;
    let bin = current_executable
        .parent()
        .context("worker executable has no package bin directory")?;
    let root = bin
        .parent()
        .context("worker package has no protected root")?;
    let signer = release_signer_identity()?;
    let trust = verify_protected_install(
        &InstallationTrustPolicy {
            root: root.to_path_buf(),
            publisher_subject: signer.subject.clone(),
            publisher_spki_sha256: signer.spki_sha256.clone(),
            validate_ancestors: true,
        },
        &current_executable,
    )?;
    #[cfg(windows)]
    {
        let _installed_package = verify_current_installed_package(&trust, &signer)?;
        run_windows(arguments, &trust, &signer)
    }
    #[cfg(not(windows))]
    {
        let _ = (arguments, trust);
        bail!("protected UAC worker is only available on Windows");
    }
}

#[cfg(windows)]
fn run_windows(
    arguments: &Arguments,
    trust: &baselineops_windows::TrustedInstallation,
    signer: &ReleaseSignerIdentity,
) -> Result<ExitCode> {
    use baselineops_windows::ipc::NamedPipeServer;
    use baselineops_windows::{
        BrokerBinding, BrokerMessage, FrameCodec, PROTOCOL_VERSION, ReplayNonceCache,
    };
    use std::time::{Duration, Instant};
    let pipe_name = arguments.session.as_simple().to_string();
    let verifier = StrictClientVerifier::new(arguments.client_pid, trust, signer)?;
    let server = NamedPipeServer::bind(&pipe_name, verifier.expected_logon_sid())?;
    let mut client = server.accept(&verifier)?;
    let frame = client.receive()?;
    let message: BrokerMessage = FrameCodec::decode(&frame.0)?;
    message.validate()?;
    let mut replays = ReplayNonceCache::new(Duration::from_mins(2), 8)?;
    replays.accept(&message.nonce, Instant::now())?;
    let request = parse_proposal_request(&message)?;
    let submitted_digest = baselineops_domain::canonical_json_digest(&request.plan)?;
    message.binding.require_request(
        &pipe_name,
        &request.plan.id.to_string(),
        &submitted_digest.to_hex(),
    )?;
    let (profile, context) = reload_apply_inputs(&request.plan.source, trust, signer)?;
    let session = prepare_worker_apply(&request.plan, &profile, context)?;
    let proposal = BrokerMessage {
        version: PROTOCOL_VERSION,
        binding: BrokerBinding {
            session_id: pipe_name.clone(),
            plan_id: session.proposal().id.to_string(),
            plan_digest: session.digest().to_hex(),
            reply_to: Some(message.nonce.clone()),
        },
        nonce: Uuid::new_v4().simple().to_string(),
        kind: "plan.proposal".into(),
        payload: serde_json::json!({"plan":session.proposal(),"digest":session.digest().to_hex()}),
    };
    proposal.validate()?;
    client.send(&FrameCodec::encode(&proposal)?)?;
    let approval: BrokerMessage = FrameCodec::decode(&client.receive()?.0)?;
    approval.validate()?;
    replays.accept(&approval.nonce, Instant::now())?;
    approval.binding.require_reply_to(
        &pipe_name,
        &proposal.binding.plan_id,
        &proposal.binding.plan_digest,
        &proposal.nonce,
    )?;
    let approved_digest = parse_approval_request(&approval)?
        .approved_digest
        .parse::<Sha256Digest>()
        .map_err(|error| anyhow!(error))?;
    let (_, context) = reload_apply_inputs(&request.plan.source, trust, signer)?;
    let live = PlanValidationContext {
        now: chrono::Utc::now(),
        intent: context.intent,
        host: context.host,
        tool: context.tool,
        package_digest: context.package_digest,
        source: context.source,
        input: context.input,
        observed_state_digest: context.observed_state.digest,
    };
    let _verified = session.approve(approved_digest, &live, trust)?;
    // Mutation remains fail-closed until a worker-owned native executor is
    // registered. The opaque approval proof cannot reach a mutation scheduler.
    let reply = BrokerMessage {
        version: PROTOCOL_VERSION,
        binding: BrokerBinding {
            session_id: pipe_name,
            plan_id: proposal.binding.plan_id,
            plan_digest: proposal.binding.plan_digest,
            reply_to: Some(approval.nonce),
        },
        nonce: Uuid::new_v4().simple().to_string(),
        kind: "plan.result".into(),
        payload: serde_json::json!({"status":"unsupported","reason":"no worker-owned native mutation executor is registered","exitCode":ExitCode::Unsupported.as_i32()}),
    };
    reply.validate()?;
    client.send(&FrameCodec::encode(&reply)?)?;
    Ok(ExitCode::Unsupported)
}

#[cfg(windows)]
fn reload_apply_inputs(
    reviewed: &SourceIdentityV3,
    trust: &baselineops_windows::TrustedInstallation,
    signer: &ReleaseSignerIdentity,
) -> Result<(ProfileV3, PlanBuildContext)> {
    if reviewed.kind != SourceKind::LocalFile {
        bail!("apply accepts only a locally validated profile source");
    }
    let profile_path = std::path::PathBuf::from(&reviewed.locator);
    if !profile_path.is_absolute() {
        bail!("profile source must use an absolute canonical path");
    }
    let parent = profile_path
        .parent()
        .context("profile source has no parent directory")?;
    let policy = baselineops_windows::PathPolicy::new(parent)?;
    let profile_path = policy.existing_file(&profile_path)?;
    if profile_path.as_os_str() != reviewed.locator.as_str() {
        bail!("profile source must already be a canonical path");
    }
    let source_bytes = baselineops_windows::read_bounded_utf8_no_follow(
        &profile_path,
        baselineops_windows::MAX_INPUT_BYTES,
    )?
    .into_bytes();
    let profile = load_profile_json(&source_bytes, JsonLoadLimits::default())?;
    let source_digest = Sha256Digest::of_bytes(&source_bytes);
    let source = SourceIdentityV3 {
        kind: SourceKind::LocalFile,
        locator: profile_path.display().to_string(),
        digest: source_digest,
    };
    let package_digest = verify_current_installed_package(trust, signer)?.binding_digest();
    let now = chrono::Utc::now();
    let observed_state = reobserve_profile(&profile, &NativeObservationSource, now)
        .map_err(|error| anyhow!(error))?;
    Ok((
        profile,
        PlanBuildContext {
            intent: ExecutionIntent::Apply,
            host: baselineops_windows::collect_host_identity()?,
            tool: ToolIdentityV3 {
                name: "baselineops".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                build_digest: Some(package_digest),
            },
            package_digest,
            source,
            input: InputIdentityV3 {
                digest: source_digest,
                size_bytes: u64::try_from(source_bytes.len())?,
            },
            observed_state,
            lifetime: chrono::Duration::minutes(5),
        },
    ))
}

#[cfg(windows)]
fn verify_current_installed_package(
    trust: &baselineops_windows::TrustedInstallation,
    signer: &ReleaseSignerIdentity,
) -> Result<baselineops_engine::InstalledPackageIdentity> {
    Ok(verify_installed_package(
        trust.root(),
        InstalledPackageExpectation {
            product: "BaselineOps for Windows",
            package_version: env!("CARGO_PKG_VERSION"),
            target: "x86_64-pc-windows-msvc",
            signer_subject: &signer.subject,
        },
        &PlatformDetachedSignatureVerifier::new(signer),
        &PlatformSignatureVerifier::new(signer),
    )?)
}

#[cfg(windows)]
struct PlatformDetachedSignatureVerifier {
    signer: ReleaseSignerIdentity,
}

#[cfg(windows)]
impl PlatformDetachedSignatureVerifier {
    fn new(signer: &ReleaseSignerIdentity) -> Self {
        Self {
            signer: signer.clone(),
        }
    }
}

#[cfg(windows)]
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

#[cfg(windows)]
struct PlatformSignatureVerifier {
    signer: ReleaseSignerIdentity,
}

#[cfg(windows)]
impl PlatformSignatureVerifier {
    fn new(signer: &ReleaseSignerIdentity) -> Self {
        Self {
            signer: signer.clone(),
        }
    }
}

#[cfg(windows)]
impl SignatureVerifier for PlatformSignatureVerifier {
    fn verify(
        &self,
        executable: &std::path::Path,
        expected_subject: &str,
    ) -> Result<(), PackageError> {
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

#[cfg_attr(not(windows), allow(dead_code))]
fn parse_proposal_request(message: &baselineops_windows::BrokerMessage) -> Result<ProposalRequest> {
    if message.kind != "plan.propose" {
        bail!("worker only accepts plan.propose messages");
    }
    serde_json::from_value(message.payload.clone()).context("invalid bounded proposal request")
}

#[cfg_attr(not(windows), allow(dead_code))]
fn parse_approval_request(message: &baselineops_windows::BrokerMessage) -> Result<ApprovalRequest> {
    if message.kind != "plan.approve" {
        bail!("worker only accepts plan.approve messages");
    }
    let request: ApprovalRequest = serde_json::from_value(message.payload.clone())
        .context("invalid bounded approval request")?;
    if request.approved_digest.len() != 64
        || !request
            .approved_digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("approved digest must be lowercase SHA-256 hex");
    }
    Ok(request)
}

fn parse_session(value: &str) -> Result<Uuid, String> {
    let session = Uuid::parse_str(value).map_err(|error| error.to_string())?;
    if session.is_nil() {
        return Err("session identifier may not be nil".into());
    }
    Ok(session)
}

fn parse_process_id(value: &str) -> Result<u32, String> {
    let pid = value.parse::<u32>().map_err(|error| error.to_string())?;
    if pid == 0 {
        return Err("client process identifier may not be zero".into());
    }
    Ok(pid)
}

#[cfg(windows)]
struct StrictClientVerifier {
    expected_pid: u32,
    expected_session: u32,
    expected_image: std::path::PathBuf,
    expected_user_sid: String,
    expected_logon_sid: String,
    installation_root: std::path::PathBuf,
    publisher_subject: String,
    publisher_spki_sha256: baselineops_windows::SignerSpkiSha256,
}

#[cfg(windows)]
impl StrictClientVerifier {
    fn new(
        client_pid: u32,
        trust: &baselineops_windows::TrustedInstallation,
        signer: &ReleaseSignerIdentity,
    ) -> Result<Self> {
        let identity = baselineops_windows::ipc::inspect_process(client_pid)?;
        let bin = trust
            .executable()
            .parent()
            .context("trusted worker lacks bin directory")?;
        let expected_image = baselineops_windows::verify_protected_install(
            &InstallationTrustPolicy {
                root: trust.root().to_path_buf(),
                publisher_subject: signer.subject.clone(),
                publisher_spki_sha256: signer.spki_sha256.clone(),
                validate_ancestors: true,
            },
            bin.join("baselineops.exe"),
        )?
        .executable()
        .to_path_buf();
        Ok(Self {
            expected_pid: client_pid,
            expected_session: identity.session_id,
            expected_image,
            expected_user_sid: identity.user_sid,
            expected_logon_sid: identity.logon_sid,
            installation_root: trust.root().to_path_buf(),
            publisher_subject: signer.subject.clone(),
            publisher_spki_sha256: signer.spki_sha256.clone(),
        })
    }

    fn expected_logon_sid(&self) -> &str {
        &self.expected_logon_sid
    }
}

#[cfg(windows)]
impl baselineops_windows::ipc::PipePeerVerifier for StrictClientVerifier {
    fn verify(
        &self,
        peer: &baselineops_windows::PeerIdentity,
    ) -> Result<(), baselineops_windows::PlatformError> {
        if peer.process_id != self.expected_pid || peer.session_id != self.expected_session {
            return Err(protocol(
                "pipe PID or session does not match the UAC launch binding",
            ));
        }
        let identity = baselineops_windows::ipc::inspect_process(peer.process_id)?;
        if identity.user_sid != self.expected_user_sid
            || identity.logon_sid != self.expected_logon_sid
            || identity.integrity_rid < 0x2000
        {
            return Err(protocol(
                "pipe client token does not match the launched standard-user logon identity",
            ));
        }
        if !same_windows_path(&identity.image_path, &self.expected_image) {
            return Err(protocol(
                "pipe client image is not the protected BaselineOps CLI",
            ));
        }
        let verified = baselineops_windows::verify_protected_install(
            &InstallationTrustPolicy {
                root: self.installation_root.clone(),
                publisher_subject: self.publisher_subject.clone(),
                publisher_spki_sha256: self.publisher_spki_sha256.clone(),
                validate_ancestors: true,
            },
            &identity.image_path,
        )?;
        if !same_windows_path(verified.executable(), &self.expected_image) {
            return Err(protocol(
                "pipe client final image does not match protected CLI",
            ));
        }
        Ok(())
    }
}

#[cfg(windows)]
fn protocol(message: &str) -> baselineops_windows::PlatformError {
    baselineops_windows::PlatformError::ProtocolRejected(message.into())
}

#[cfg(windows)]
fn same_windows_path(actual: &std::path::Path, expected: &std::path::Path) -> bool {
    actual
        .to_string_lossy()
        .eq_ignore_ascii_case(&expected.to_string_lossy())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn process_and_session_inputs_are_strict() {
        assert!(parse_session("00000000-0000-0000-0000-000000000000").is_err());
        assert!(parse_process_id("0").is_err());
    }
    #[test]
    fn two_phase_request_kinds_are_checked() {
        let message = baselineops_windows::BrokerMessage {
            version: baselineops_windows::PROTOCOL_VERSION,
            binding: baselineops_windows::BrokerBinding {
                session_id: "aa".into(),
                plan_id: "plan".into(),
                plan_digest: "ab".repeat(32),
                reply_to: None,
            },
            nonce: "aa".into(),
            kind: "wrong".into(),
            payload: serde_json::json!({}),
        };
        assert!(parse_proposal_request(&message).is_err());
        assert!(parse_approval_request(&message).is_err());
    }

    #[test]
    fn diagnostic_environment_allowlist_is_bounded() {
        assert!(safe_log_filter(std::ffi::OsStr::new("info,worker=debug")));
        assert!(!safe_log_filter(std::ffi::OsStr::new("")));
        assert!(!safe_log_filter(std::ffi::OsStr::new("info\nworker=debug")));
    }
}
