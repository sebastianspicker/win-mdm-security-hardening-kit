//! Mutually authenticated elevated apply broker.

use anyhow::{Context, Result, anyhow, bail};
use baselineops_domain::{ExitCode, PlanV3, Sha256Digest, canonical_json_digest};
use baselineops_engine::{InstalledPackageExpectation, PackageError, verify_installed_package};
use baselineops_windows::ipc::{NamedPipeClient, ProcessTokenIdentity, inspect_process};
use baselineops_windows::{
    BrokerBinding, BrokerMessage, ElevatedLaunchPolicy, ElevatedLaunchStatus, FrameCodec,
    InstallationTrustPolicy, PROTOCOL_VERSION, PeerIdentity, ReplayNonceCache, TrustedInstallation,
    launch_elevated, verify_protected_install,
};
use std::{
    io::{BufRead as _, Write as _},
    path::Path,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

pub(super) fn run(plan: &PlanV3, preapproved_digest: Option<&str>) -> Result<ExitCode> {
    let signer = crate::release_signer_identity()?;
    let installation = verified_installation(plan, &signer)?;
    let cli_identity = inspect_process(std::process::id())?;
    let session = uuid::Uuid::new_v4();
    let arguments = vec![
        "--session".into(),
        session.to_string(),
        "--client-pid".into(),
        std::process::id().to_string(),
    ];
    let launch_installation = Arc::clone(&installation);
    let launch = thread::spawn(move || {
        launch_elevated(
            launch_installation.as_ref(),
            &ElevatedLaunchPolicy {
                arguments,
                timeout: Duration::from_mins(2),
            },
        )
    });
    let pipe_name = session.as_simple().to_string();
    let mut client = connect(&pipe_name)?;
    let mut server_replays = ReplayNonceCache::new(Duration::from_mins(2), 4)?;
    authenticate_worker_server(
        &client.server_peer_identity()?,
        &cli_identity,
        &installation,
        &signer,
    )?;
    let submitted_digest = canonical_json_digest(plan)?;
    let request = BrokerMessage {
        version: PROTOCOL_VERSION,
        binding: BrokerBinding {
            session_id: pipe_name.clone(),
            plan_id: plan.id.to_string(),
            plan_digest: submitted_digest.to_hex(),
            reply_to: None,
        },
        nonce: uuid::Uuid::new_v4().simple().to_string(),
        kind: "plan.propose".into(),
        payload: serde_json::json!({"plan": plan}),
    };
    request.validate()?;
    client.send(&FrameCodec::encode(&request)?)?;
    let (response, proposal_nonce) =
        receive_proposal(&mut client, &mut server_replays, &pipe_name, &request)?;
    super::print_json(
        &serde_json::json!({"status":"proposal","digest":response.digest,"plan":response.plan}),
    )?;
    let operator_digest = approval_digest(preapproved_digest)?;
    if operator_digest != response.digest {
        bail!("--approve-digest does not match the worker proposal");
    }
    let approval = BrokerMessage {
        version: PROTOCOL_VERSION,
        binding: BrokerBinding {
            session_id: pipe_name.clone(),
            plan_id: response.plan.id.to_string(),
            plan_digest: response.digest.clone(),
            reply_to: Some(proposal_nonce),
        },
        nonce: uuid::Uuid::new_v4().simple().to_string(),
        kind: "plan.approve".into(),
        payload: serde_json::json!({"approvedDigest": operator_digest}),
    };
    approval.validate()?;
    client.send(&FrameCodec::encode(&approval)?)?;
    let reply: BrokerMessage = FrameCodec::decode(&client.receive()?.0)?;
    reply.validate()?;
    server_replays.accept(&reply.nonce, Instant::now())?;
    reply.binding.require_reply_to(
        &pipe_name,
        &response.plan.id.to_string(),
        &response.digest,
        &approval.nonce,
    )?;
    let launched = launch
        .join()
        .map_err(|_| anyhow!("elevation launcher panicked"))??;
    let exit = match launched.status {
        ElevatedLaunchStatus::Exited(code) if code == ExitCode::Unsupported.as_i32() => {
            ExitCode::Unsupported
        }
        ElevatedLaunchStatus::Exited(code) if code == ExitCode::Rejected.as_i32() => {
            ExitCode::Rejected
        }
        ElevatedLaunchStatus::Exited(_) | ElevatedLaunchStatus::TimedOut => {
            ExitCode::ExecutionFailure
        }
        ElevatedLaunchStatus::Cancelled => ExitCode::Cancelled,
    };
    super::print_json(&reply.payload)?;
    Ok(exit)
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WorkerProposal {
    plan: PlanV3,
    digest: String,
}

fn verified_installation(
    plan: &PlanV3,
    signer: &crate::ReleaseSignerIdentity,
) -> Result<Arc<TrustedInstallation>> {
    let installation = Arc::new(verify_worker_install(signer)?);
    let installed_package = verify_installed_package(
        installation.root(),
        installed_expectation(signer),
        &crate::PlatformDetachedSignatureVerifier::new(signer),
        &crate::PlatformSignatureVerifier::new(signer),
    )?;
    if plan.package_digest != installed_package.binding_digest() {
        return Err(PackageError::Signature(
            "plan package digest does not match the authenticated installed manifest".into(),
        )
        .into());
    }
    Ok(installation)
}

fn receive_proposal(
    client: &mut NamedPipeClient,
    replay_cache: &mut ReplayNonceCache,
    pipe_name: &str,
    request: &BrokerMessage,
) -> Result<(WorkerProposal, String)> {
    let proposal: BrokerMessage = FrameCodec::decode(&client.receive()?.0)?;
    proposal.validate()?;
    replay_cache.accept(&proposal.nonce, Instant::now())?;
    if proposal.kind != "plan.proposal" {
        bail!("worker did not return a plan proposal");
    }
    let response: WorkerProposal = serde_json::from_value(proposal.payload.clone())?;
    response.plan.validate_structure()?;
    let digest = response
        .digest
        .parse::<Sha256Digest>()
        .map_err(|error| anyhow!(error))?;
    if canonical_json_digest(&response.plan)? != digest
        || proposal.binding.session_id != pipe_name
        || proposal.binding.plan_id != response.plan.id.to_string()
        || proposal.binding.plan_digest != response.digest
        || proposal.binding.reply_to.as_deref() != Some(&request.nonce)
    {
        bail!("worker proposal is not bound to this exact pipe session and request");
    }
    Ok((response, proposal.nonce))
}

fn connect(name: &str) -> Result<NamedPipeClient> {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match NamedPipeClient::connect(name) {
            Ok(client) => return Ok(client),
            Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(50)),
            Err(error) => return Err(anyhow!(error)),
        }
    }
}

fn approval_digest(provided: Option<&str>) -> Result<String> {
    if let Some(value) = provided {
        return Ok(value.to_owned());
    }
    eprint!("Approve this exact worker digest to continue (leave blank to cancel): ");
    std::io::stderr().flush()?;
    let mut value = String::new();
    std::io::stdin().lock().read_line(&mut value)?;
    let value = value.trim().to_owned();
    if value.is_empty() {
        bail!("worker proposal was not approved");
    }
    Ok(value)
}

fn verify_worker_install(signer: &crate::ReleaseSignerIdentity) -> Result<TrustedInstallation> {
    let executable = std::env::current_exe()?;
    let bin = executable
        .parent()
        .context("CLI executable has no bin directory")?;
    let root = bin
        .parent()
        .context("CLI executable has no installation root")?;
    verify_protected_install(
        &InstallationTrustPolicy {
            root: root.to_path_buf(),
            publisher_subject: signer.subject.clone(),
            publisher_spki_sha256: signer.spki_sha256.clone(),
            validate_ancestors: true,
        },
        bin.join("baselineops-worker.exe"),
    )
    .map_err(Into::into)
}

fn authenticate_worker_server(
    peer: &PeerIdentity,
    cli: &ProcessTokenIdentity,
    expected: &TrustedInstallation,
    signer: &crate::ReleaseSignerIdentity,
) -> Result<()> {
    let server = inspect_process(peer.process_id)?;
    if server.session_id != cli.session_id
        || peer.session_id != cli.session_id
        || server.user_sid != cli.user_sid
        || server.logon_sid != cli.logon_sid
        || server.integrity_rid < 0x3000
    {
        bail!("named-pipe server token is not the expected elevated logon identity");
    }
    if !same_windows_path(&server.image_path, expected.executable()) {
        bail!("named-pipe server image is not the expected protected worker");
    }
    let verified = verify_protected_install(
        &InstallationTrustPolicy {
            root: expected.root().to_path_buf(),
            publisher_subject: signer.subject.clone(),
            publisher_spki_sha256: signer.spki_sha256.clone(),
            validate_ancestors: true,
        },
        &server.image_path,
    )?;
    if !same_windows_path(verified.executable(), expected.executable()) {
        bail!("named-pipe server final handle identity differs from trusted worker");
    }
    Ok(())
}

fn installed_expectation(signer: &crate::ReleaseSignerIdentity) -> InstalledPackageExpectation<'_> {
    InstalledPackageExpectation {
        product: "BaselineOps for Windows",
        package_version: env!("CARGO_PKG_VERSION"),
        target: "x86_64-pc-windows-msvc",
        signer_subject: &signer.subject,
    }
}

fn same_windows_path(actual: &Path, expected: &Path) -> bool {
    actual
        .to_string_lossy()
        .eq_ignore_ascii_case(&expected.to_string_lossy())
}
