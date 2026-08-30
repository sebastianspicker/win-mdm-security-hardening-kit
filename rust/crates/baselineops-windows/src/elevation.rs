//! UAC elevation launcher for the trusted worker executable.

use crate::{PlatformError, TrustedInstallation};
use std::path::PathBuf;
use std::time::Duration;

/// Preconditions and resource bounds for one UAC worker launch.
#[derive(Clone, Debug)]
pub struct ElevatedLaunchPolicy {
    /// Arguments passed as direct worker tokens, never through a command shell.
    pub arguments: Vec<String>,
    /// Maximum wall-clock wait for the worker process.
    pub timeout: Duration,
}

/// Terminal interpretation of an elevated worker process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ElevatedLaunchStatus {
    /// The worker exited and returned its process exit code.
    Exited(i32),
    /// UAC was declined before process creation.
    Cancelled,
    /// The worker did not finish before the policy deadline.
    TimedOut,
}

/// Result of launching the trusted worker through the `runas` verb.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ElevatedLaunchResult {
    /// The signed worker executable selected by protected-install verification.
    pub executable: PathBuf,
    /// UAC/process terminal state.
    pub status: ElevatedLaunchStatus,
}

/// Launch a previously verified worker with UAC elevation and wait up to policy timeout.
///
/// The executable path cannot be supplied independently: the caller must first
/// pass [`crate::verify_protected_install`] and provide that resulting authority.
///
/// # Errors
///
/// Returns a fail-closed error for malformed tokens, unsupported platforms,
/// UAC cancellation, timeout, or Win32 failures.
pub fn launch_elevated(
    installation: &TrustedInstallation,
    policy: &ElevatedLaunchPolicy,
) -> Result<ElevatedLaunchResult, PlatformError> {
    validate_policy(policy)?;
    platform::launch(installation, policy)
}

fn validate_policy(policy: &ElevatedLaunchPolicy) -> Result<(), PlatformError> {
    if policy.timeout.is_zero() || policy.timeout > Duration::from_hours(1) {
        return Err(PlatformError::ProcessRejected(
            "elevation timeout is outside the one-hour ceiling".into(),
        ));
    }
    if policy.timeout.as_millis() >= u128::from(u32::MAX) {
        return Err(PlatformError::ProcessRejected(
            "elevation timeout must remain below the Win32 INFINITE sentinel".into(),
        ));
    }
    if policy.arguments.len() > 64
        || policy.arguments.iter().any(|argument| {
            argument.is_empty() || argument.len() > 4096 || argument.contains(['\0', '\r', '\n'])
        })
    {
        return Err(PlatformError::ProcessRejected(
            "elevation arguments violate fixed bounds".into(),
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
mod platform {
    use super::{ElevatedLaunchPolicy, ElevatedLaunchResult, PlatformError, TrustedInstallation};

    pub fn launch(
        _installation: &TrustedInstallation,
        _policy: &ElevatedLaunchPolicy,
    ) -> Result<ElevatedLaunchResult, PlatformError> {
        Err(PlatformError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
mod platform {
    #![allow(unsafe_code)]

    use super::{
        ElevatedLaunchPolicy, ElevatedLaunchResult, ElevatedLaunchStatus, PlatformError,
        TrustedInstallation,
    };
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Foundation::{
        CloseHandle as CloseProcessHandle, ERROR_CANCELLED, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows::Win32::System::Threading::{
        GetExitCodeProcess, TerminateProcess, WaitForSingleObject,
    };
    use windows::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
    use windows::core::{PCWSTR, w};

    type RawHandle = isize;

    const INVALID_HANDLE_VALUE: RawHandle = -1;
    const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: u32 = 9;
    const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x0000_2000;
    const CLEANUP_WAIT_MILLISECONDS: u32 = 5_000;

    #[repr(C)]
    struct JobObjectBasicLimitInformation {
        per_process_user_time_limit: i64,
        per_job_user_time_limit: i64,
        limit_flags: u32,
        minimum_working_set_size: usize,
        maximum_working_set_size: usize,
        active_process_limit: u32,
        affinity: usize,
        priority_class: u32,
        scheduling_class: u32,
    }

    #[repr(C)]
    #[allow(clippy::struct_field_names)]
    struct IoCounters {
        read_operation_count: u64,
        write_operation_count: u64,
        other_operation_count: u64,
        read_transfer_count: u64,
        write_transfer_count: u64,
        other_transfer_count: u64,
    }

    #[repr(C)]
    struct JobObjectExtendedLimitInformation {
        basic_limit_information: JobObjectBasicLimitInformation,
        io_info: IoCounters,
        process_memory_limit: usize,
        job_memory_limit: usize,
        peak_process_memory_used: usize,
        peak_job_memory_used: usize,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateJobObjectW(attributes: *const core::ffi::c_void, name: *const u16) -> RawHandle;
        fn SetInformationJobObject(
            job: RawHandle,
            class: u32,
            information: *const core::ffi::c_void,
            length: u32,
        ) -> i32;
        fn AssignProcessToJobObject(job: RawHandle, process: RawHandle) -> i32;
        fn TerminateJobObject(job: RawHandle, exit_code: u32) -> i32;
        #[link_name = "CloseHandle"]
        fn RawCloseHandle(handle: RawHandle) -> i32;
        fn GetLastError() -> u32;
    }

    struct WorkerJob(RawHandle);

    impl WorkerJob {
        fn create() -> Result<Self, PlatformError> {
            let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if job == 0 || job == INVALID_HANDLE_VALUE {
                return Err(last_error("CreateJobObjectW"));
            }
            let limits = JobObjectExtendedLimitInformation {
                basic_limit_information: JobObjectBasicLimitInformation {
                    per_process_user_time_limit: 0,
                    per_job_user_time_limit: 0,
                    limit_flags: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                    minimum_working_set_size: 0,
                    maximum_working_set_size: 0,
                    active_process_limit: 0,
                    affinity: 0,
                    priority_class: 0,
                    scheduling_class: 0,
                },
                io_info: IoCounters {
                    read_operation_count: 0,
                    write_operation_count: 0,
                    other_operation_count: 0,
                    read_transfer_count: 0,
                    write_transfer_count: 0,
                    other_transfer_count: 0,
                },
                process_memory_limit: 0,
                job_memory_limit: 0,
                peak_process_memory_used: 0,
                peak_job_memory_used: 0,
            };
            if unsafe {
                SetInformationJobObject(
                    job,
                    JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                    (&raw const limits).cast(),
                    u32::try_from(std::mem::size_of_val(&limits)).expect("job limit size"),
                )
            } == 0
            {
                let error = last_error("SetInformationJobObject");
                let _ = unsafe { RawCloseHandle(job) };
                return Err(error);
            }
            Ok(Self(job))
        }

        fn assign(&self, process: windows::Win32::Foundation::HANDLE) -> Result<(), PlatformError> {
            if unsafe { AssignProcessToJobObject(self.0, process.0 as RawHandle) } == 0 {
                return Err(last_error("AssignProcessToJobObject"));
            }
            Ok(())
        }

        fn terminate(&self) -> Result<(), PlatformError> {
            if unsafe { TerminateJobObject(self.0, 1) } == 0 {
                return Err(last_error("TerminateJobObject"));
            }
            Ok(())
        }
    }

    impl Drop for WorkerJob {
        fn drop(&mut self) {
            // KILL_ON_JOB_CLOSE keeps descendants contained after the launcher returns.
            let _ = unsafe { RawCloseHandle(self.0) };
        }
    }

    struct OwnedProcess(Option<windows::Win32::Foundation::HANDLE>);

    impl OwnedProcess {
        fn from_shell(handle: windows::Win32::Foundation::HANDLE) -> Result<Self, PlatformError> {
            if handle.is_invalid() {
                return Err(PlatformError::TrustFailure(
                    "ShellExecuteExW did not return a process handle".into(),
                ));
            }
            Ok(Self(Some(handle)))
        }

        fn raw(&self) -> windows::Win32::Foundation::HANDLE {
            self.0.expect("owned process handle is present until close")
        }

        fn close(mut self) -> Result<(), PlatformError> {
            let handle = self.0.take().expect("owned process handle is present");
            unsafe { CloseProcessHandle(handle) }.map_err(|error| {
                PlatformError::TrustFailure(format!("CloseHandle failed: {error}"))
            })
        }
    }

    impl Drop for OwnedProcess {
        fn drop(&mut self) {
            if let Some(handle) = self.0.take() {
                let _ = unsafe { CloseProcessHandle(handle) };
            }
        }
    }

    pub fn launch(
        installation: &TrustedInstallation,
        policy: &ElevatedLaunchPolicy,
    ) -> Result<ElevatedLaunchResult, PlatformError> {
        // The Job is fully configured before the UAC launch. ShellExecute itself cannot
        // create a `runas` process suspended, so assignment immediately follows its handle.
        let job = WorkerJob::create()?;
        let executable = wide(installation.executable().as_os_str());
        let directory = installation.executable().parent().ok_or_else(|| {
            PlatformError::TrustFailure("trusted worker has no parent directory".into())
        })?;
        let directory = wide(directory.as_os_str());
        let parameters = wide(OsStr::new(&quote_arguments(&policy.arguments)));
        let mut execute = SHELLEXECUTEINFOW {
            cbSize: u32::try_from(std::mem::size_of::<SHELLEXECUTEINFOW>())
                .expect("SHELLEXECUTEINFOW size"),
            fMask: SEE_MASK_NOCLOSEPROCESS,
            lpVerb: w!("runas"),
            lpFile: PCWSTR(executable.as_ptr()),
            lpParameters: PCWSTR(parameters.as_ptr()),
            lpDirectory: PCWSTR(directory.as_ptr()),
            nShow: 0,
            ..Default::default()
        };
        unsafe { ShellExecuteExW(&raw mut execute) }.map_err(|error| {
            if error.code().0 == i32::try_from(ERROR_CANCELLED.0).expect("Win32 error code") {
                PlatformError::ElevationCancelled
            } else {
                PlatformError::TrustFailure(format!("ShellExecuteExW failed: {error}"))
            }
        })?;
        // `hProcess` is owned by this structure immediately after ShellExecuteExW.
        // Its Drop implementation closes it on every early-return path exactly once.
        let process = OwnedProcess::from_shell(execute.hProcess)?;
        if let Err(error) = job.assign(process.raw()) {
            terminate_process_and_wait(process.raw())?;
            return Err(error);
        }
        let milliseconds = u32::try_from(policy.timeout.as_millis()).unwrap_or(u32::MAX);
        let wait = unsafe { WaitForSingleObject(process.raw(), milliseconds) };
        let result = if wait == WAIT_TIMEOUT {
            terminate_job_and_wait(&job, process.raw())?;
            ElevatedLaunchStatus::TimedOut
        } else if wait == WAIT_OBJECT_0 {
            let mut exit_code = 0_u32;
            if let Err(error) = unsafe { GetExitCodeProcess(process.raw(), &raw mut exit_code) } {
                terminate_job_and_wait(&job, process.raw())?;
                return Err(PlatformError::TrustFailure(format!(
                    "GetExitCodeProcess failed: {error}"
                )));
            }
            ElevatedLaunchStatus::Exited(i32::try_from(exit_code).unwrap_or(-1))
        } else {
            terminate_job_and_wait(&job, process.raw())?;
            return Err(PlatformError::TrustFailure(
                "unexpected elevated process wait state".into(),
            ));
        };
        process.close()?;
        Ok(ElevatedLaunchResult {
            executable: installation.executable().to_path_buf(),
            status: result,
        })
    }

    fn terminate_process_and_wait(
        process: windows::Win32::Foundation::HANDLE,
    ) -> Result<(), PlatformError> {
        unsafe { TerminateProcess(process, 1) }.map_err(|error| {
            PlatformError::TrustFailure(format!("TerminateProcess failed: {error}"))
        })?;
        wait_for_cleanup(process)
    }

    fn terminate_job_and_wait(
        job: &WorkerJob,
        process: windows::Win32::Foundation::HANDLE,
    ) -> Result<(), PlatformError> {
        job.terminate()?;
        wait_for_cleanup(process)
    }

    fn wait_for_cleanup(process: windows::Win32::Foundation::HANDLE) -> Result<(), PlatformError> {
        match unsafe { WaitForSingleObject(process, CLEANUP_WAIT_MILLISECONDS) } {
            WAIT_OBJECT_0 => Ok(()),
            WAIT_TIMEOUT => Err(PlatformError::TrustFailure(
                "elevated worker did not exit inside the bounded cleanup wait".into(),
            )),
            _ => Err(last_error("WaitForSingleObject cleanup")),
        }
    }

    fn last_error(operation: &str) -> PlatformError {
        PlatformError::Io(std::io::Error::other(format!(
            "{operation}: Win32 error {}",
            unsafe { GetLastError() }
        )))
    }

    fn wide(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(Some(0)).collect()
    }

    fn quote_arguments(arguments: &[String]) -> String {
        arguments
            .iter()
            .map(|argument| quote_argument(argument))
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn quote_argument(argument: &str) -> String {
        // Win32 CommandLineToArgvW-compatible escaping. Input control characters were rejected.
        let mut output = String::from("\"");
        let mut backslashes = 0_usize;
        for character in argument.chars() {
            if character == '\\' {
                backslashes += 1;
            } else if character == '\"' {
                output.push_str(&"\\".repeat(backslashes.saturating_mul(2).saturating_add(1)));
                output.push(character);
                backslashes = 0;
            } else {
                output.push_str(&"\\".repeat(backslashes));
                output.push(character);
                backslashes = 0;
            }
        }
        output.push_str(&"\\".repeat(backslashes.saturating_mul(2)));
        output.push('\"');
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_launcher_bounds_fail_before_platform_dispatch() {
        assert!(
            validate_policy(&ElevatedLaunchPolicy {
                arguments: vec!["\n".into()],
                timeout: Duration::from_secs(1)
            })
            .is_err()
        );
        assert!(
            validate_policy(&ElevatedLaunchPolicy {
                arguments: vec![],
                timeout: Duration::ZERO
            })
            .is_err()
        );
    }
}
