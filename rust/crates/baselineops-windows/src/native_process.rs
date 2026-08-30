use crate::{FileDigest, PlatformError, verify_file_digest};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

/// Per-capability policy for one approved native executable.
#[derive(Clone, Debug)]
pub struct NativeProcessPolicy {
    /// Absolute executable path owned by the trusted adapter.
    pub executable: PathBuf,
    /// Mandatory executable identity policy checked before process creation.
    pub executable_trust: NativeExecutableTrust,
    /// Absolute fixed working directory.
    pub working_directory: PathBuf,
    /// Complete argument patterns accepted by this adapter.
    pub argument_patterns: Vec<Vec<NativeArgumentRule>>,
    /// Explicit environment after the inherited environment is cleared.
    pub environment: BTreeMap<OsString, OsString>,
    /// Maximum deadline any request may select.
    pub max_timeout: Duration,
    /// Maximum bytes retained from each output stream.
    pub max_output_limit: usize,
}

/// Source identity accepted for one native executable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeExecutableTrust {
    /// The executable bytes must match this exact SHA-256 digest.
    ExactDigest(FileDigest),
    /// The executable must be a protected Microsoft-signed System32 binary.
    WindowsSystemPublisher,
}

/// One token rule in a complete native-tool argument pattern.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeArgumentRule {
    /// The token must match exactly, including case.
    Exact(String),
    /// The token is a bounded capability value rather than a command switch.
    BoundedValue {
        /// Maximum UTF-8 byte length.
        max_bytes: usize,
        /// Whether an empty value is accepted.
        allow_empty: bool,
        /// Whether the value may begin with `-` or `/`.
        allow_leading_switch: bool,
    },
}

/// One bounded, shell-free native process invocation.
#[derive(Clone, Debug)]
pub struct NativeProcessSpec {
    /// Argument tokens passed directly to `CreateProcess`/`exec`, never a shell.
    pub args: Vec<String>,
    /// Wall-clock execution deadline.
    pub timeout: Duration,
    /// Maximum captured bytes from each stream.
    pub output_limit: usize,
}

/// Captured native process result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeProcessResult {
    /// Process exit code, or `-1` when the platform did not provide one.
    pub exit_code: i32,
    /// Captured stdout bytes. Decoding belongs to a capability-specific parser.
    pub stdout: Vec<u8>,
    /// Captured stderr bytes. Decoding belongs to a capability-specific parser.
    pub stderr: Vec<u8>,
}

/// Execute a native process without a command shell and with bounded resources.
///
/// # Errors
///
/// Returns an error when the request violates its adapter policy, executable
/// verification fails, process creation or capture fails, output is truncated,
/// or the execution deadline expires.
pub fn run_native(
    policy: &NativeProcessPolicy,
    spec: &NativeProcessSpec,
) -> Result<NativeProcessResult, PlatformError> {
    let mut validated = validate_request(policy, spec)?;
    validated.executable = verify_executable(&validated.executable, &policy.executable_trust)?;

    platform::run(&validated, policy, spec)
}

fn verify_executable(
    executable: &std::path::Path,
    trust: &NativeExecutableTrust,
) -> Result<PathBuf, PlatformError> {
    match trust {
        NativeExecutableTrust::ExactDigest(digest) => {
            let executable = crate::trust::resolve_regular_executable(executable)?;
            verify_file_digest(&executable, digest)?;
            Ok(executable)
        }
        NativeExecutableTrust::WindowsSystemPublisher => {
            crate::trust::verify_windows_system_executable(executable)
        }
    }
}

#[cfg(not(windows))]
mod platform {
    use super::{
        NativeProcessPolicy, NativeProcessResult, NativeProcessSpec, ValidatedRequest, read_capped,
    };
    use crate::PlatformError;
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    pub(super) fn run(
        validated: &ValidatedRequest,
        policy: &NativeProcessPolicy,
        spec: &NativeProcessSpec,
    ) -> Result<NativeProcessResult, PlatformError> {
        let mut command = Command::new(&validated.executable);
        command
            .args(&spec.args)
            .current_dir(&validated.working_directory)
            .env_clear()
            .envs(&policy.environment)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn()?;
        let stdout = child.stdout.take().ok_or_else(|| {
            PlatformError::ProcessRejected("stdout capture was not established".into())
        })?;
        let stderr = child.stderr.take().ok_or_else(|| {
            PlatformError::ProcessRejected("stderr capture was not established".into())
        })?;
        let limit = spec.output_limit;
        let stdout_thread = thread::spawn(move || read_capped(stdout, limit, "stdout"));
        let stderr_thread = thread::spawn(move || read_capped(stderr, limit, "stderr"));
        let started = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if started.elapsed() >= spec.timeout {
                child.kill()?;
                let _ = child.wait();
                let _ = stdout_thread.join();
                let _ = stderr_thread.join();
                return Err(PlatformError::ProcessTimeout {
                    seconds: spec.timeout.as_secs(),
                });
            }
            thread::sleep(Duration::from_millis(10));
        };
        let stdout = stdout_thread
            .join()
            .map_err(|_| PlatformError::ProcessRejected("stdout reader panicked".into()))??;
        let stderr = stderr_thread
            .join()
            .map_err(|_| PlatformError::ProcessRejected("stderr reader panicked".into()))??;
        Ok(NativeProcessResult {
            exit_code: status.code().unwrap_or(-1),
            stdout,
            stderr,
        })
    }
}

#[cfg(windows)]
#[path = "native_process/windows.rs"]
mod platform;

fn validate_request(
    policy: &NativeProcessPolicy,
    spec: &NativeProcessSpec,
) -> Result<ValidatedRequest, PlatformError> {
    if !policy.executable.is_absolute() || !policy.working_directory.is_absolute() {
        return Err(PlatformError::ProcessRejected(
            "adapter executable and working directory must be absolute".into(),
        ));
    }
    let executable = std::fs::canonicalize(&policy.executable)?;
    if !executable.is_file() {
        return Err(PlatformError::ProcessRejected(
            "adapter executable is not a regular file".into(),
        ));
    }
    let working_directory = std::fs::canonicalize(&policy.working_directory)?;
    if !working_directory.is_dir() {
        return Err(PlatformError::ProcessRejected(
            "adapter working directory is not a directory".into(),
        ));
    }
    validate_limits(policy, spec)?;
    validate_arguments(policy, &spec.args)?;
    Ok(ValidatedRequest {
        executable,
        working_directory,
    })
}

fn validate_limits(
    policy: &NativeProcessPolicy,
    spec: &NativeProcessSpec,
) -> Result<(), PlatformError> {
    if spec.timeout.is_zero()
        || spec.timeout > policy.max_timeout
        || spec.output_limit == 0
        || spec.output_limit > policy.max_output_limit
    {
        return Err(PlatformError::ProcessRejected(
            "requested timeout or output limit is outside the adapter ceiling".into(),
        ));
    }
    Ok(())
}

fn validate_arguments(policy: &NativeProcessPolicy, args: &[String]) -> Result<(), PlatformError> {
    if args.iter().any(|argument| contains_separator(argument)) {
        return Err(PlatformError::ProcessRejected(
            "arguments may not contain control separators".into(),
        ));
    }
    if policy
        .argument_patterns
        .iter()
        .any(|pattern| matches_pattern(pattern, args))
    {
        return Ok(());
    }
    Err(PlatformError::ProcessRejected(
        "arguments do not match an approved adapter pattern".into(),
    ))
}

fn contains_separator(argument: &str) -> bool {
    argument.contains('\0') || argument.contains('\n') || argument.contains('\r')
}

fn matches_pattern(pattern: &[NativeArgumentRule], args: &[String]) -> bool {
    pattern.len() == args.len()
        && pattern
            .iter()
            .zip(args)
            .all(|(rule, argument)| rule.matches(argument))
}

impl NativeArgumentRule {
    fn matches(&self, argument: &str) -> bool {
        match self {
            Self::Exact(expected) => argument == expected,
            Self::BoundedValue {
                max_bytes,
                allow_empty,
                allow_leading_switch,
            } => {
                (*allow_empty || !argument.is_empty())
                    && argument.len() <= *max_bytes
                    && (*allow_leading_switch
                        || (!argument.starts_with('-') && !argument.starts_with('/')))
            }
        }
    }
}

struct ValidatedRequest {
    executable: PathBuf,
    working_directory: PathBuf,
}

/// Windows process-containment lifecycle; no child may resume after reaping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(not(windows), allow(dead_code))]
pub(super) enum ContainmentState {
    /// The suspended child was assigned to its kill-on-close Job Object.
    Assigned,
    /// The assigned primary thread was resumed.
    Running,
    /// The Job Object was terminated and its primary process was waited.
    Reaped,
}

#[cfg_attr(not(windows), allow(dead_code))]
impl ContainmentState {
    pub(super) fn may_resume(self) -> bool {
        matches!(self, Self::Assigned)
    }
}

pub(super) fn read_capped(
    reader: impl Read,
    limit: usize,
    stream: &'static str,
) -> Result<Vec<u8>, PlatformError> {
    let take_limit = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
    let mut output = Vec::with_capacity(limit.min(64 * 1024));
    reader.take(take_limit).read_to_end(&mut output)?;
    if output.len() > limit {
        return Err(PlatformError::OutputTooLarge { stream, limit });
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(patterns: Vec<Vec<NativeArgumentRule>>) -> NativeProcessPolicy {
        let executable = std::env::current_exe().expect("test executable");
        let working_directory = executable.parent().expect("test executable parent").into();
        NativeProcessPolicy {
            executable,
            executable_trust: NativeExecutableTrust::ExactDigest(
                FileDigest::from_hex(&"00".repeat(32)).expect("test digest"),
            ),
            working_directory,
            argument_patterns: patterns,
            environment: BTreeMap::new(),
            max_timeout: Duration::from_secs(5),
            max_output_limit: 1024,
        }
    }

    fn spec(args: Vec<String>) -> NativeProcessSpec {
        NativeProcessSpec {
            args,
            timeout: Duration::from_secs(1),
            output_limit: 10,
        }
    }

    #[test]
    fn relative_executables_are_rejected() {
        let policy = NativeProcessPolicy {
            executable: PathBuf::from("tool"),
            executable_trust: NativeExecutableTrust::ExactDigest(
                FileDigest::from_hex(&"00".repeat(32)).expect("test digest"),
            ),
            working_directory: PathBuf::from("."),
            argument_patterns: vec![vec![]],
            environment: BTreeMap::new(),
            max_timeout: Duration::from_secs(1),
            max_output_limit: 10,
        };
        assert!(matches!(
            validate_request(&policy, &spec(vec![])),
            Err(PlatformError::ProcessRejected(_))
        ));
    }

    #[test]
    fn complete_argument_patterns_reject_extra_or_switch_values() {
        let patterns = vec![vec![
            NativeArgumentRule::Exact("--name".into()),
            NativeArgumentRule::BoundedValue {
                max_bytes: 8,
                allow_empty: false,
                allow_leading_switch: false,
            },
        ]];
        let policy = policy(patterns);
        assert!(validate_request(&policy, &spec(vec!["--name".into(), "host".into()])).is_ok());
        for args in [
            vec!["--name".into()],
            vec!["--name".into(), "--other".into()],
            vec!["--name".into(), "too-long-value".into()],
            vec!["--name".into(), "host".into(), "extra".into()],
        ] {
            assert!(matches!(
                validate_request(&policy, &spec(args)),
                Err(PlatformError::ProcessRejected(_))
            ));
        }
    }

    #[test]
    fn adapter_resource_ceilings_are_enforced() {
        let policy = policy(vec![vec![]]);
        let too_slow = NativeProcessSpec {
            timeout: Duration::from_secs(6),
            ..spec(vec![])
        };
        let too_large = NativeProcessSpec {
            output_limit: 1025,
            ..spec(vec![])
        };
        assert!(validate_request(&policy, &too_slow).is_err());
        assert!(validate_request(&policy, &too_large).is_err());
    }

    #[test]
    fn containment_failure_state_cannot_resume_a_child() {
        assert!(ContainmentState::Assigned.may_resume());
        assert!(!ContainmentState::Running.may_resume());
        assert!(!ContainmentState::Reaped.may_resume());
    }
}
