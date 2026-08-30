//! Direct, shell-free Task Scheduler COM observation for capability 07.
//!
//! The adapter reads only the four compile-time paths in
//! `FIXED_SCHEDULED_TASKS`. It never enumerates arbitrary tasks, exports task
//! XML, reads task definitions or credentials, or invokes a shell.

use crate::PlatformError;
use baselineops_capabilities::ScheduledTasksObservation;

/// Observe the fixed Scheduled Tasks hygiene subset without mutation.
///
/// # Errors
///
/// Returns [`PlatformError::UnsupportedPlatform`] outside Windows. A failure
/// to initialize or connect to local Task Scheduler is returned as a typed
/// trust-boundary error; individual task failures are preserved in the
/// observation as missing, access-denied, or unparsed evidence.
pub fn audit_scheduled_tasks() -> Result<ScheduledTasksObservation, PlatformError> {
    #[cfg(windows)]
    {
        platform::audit_scheduled_tasks()
    }
    #[cfg(not(windows))]
    {
        Err(PlatformError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
mod platform {
    #![allow(unsafe_code, unsafe_op_in_unsafe_fn)]

    use super::{PlatformError, ScheduledTasksObservation};
    use baselineops_capabilities::{
        FIXED_SCHEDULED_TASKS, Observation, ScheduledTask, ScheduledTaskSnapshot,
        ScheduledTaskState,
    };
    use std::collections::BTreeMap;
    use windows::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND,
    };
    use windows::Win32::System::Com::{
        CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
        CoUninitialize,
    };
    use windows::Win32::System::TaskScheduler::{
        IRegisteredTask, ITaskFolder, ITaskService, TASK_STATE_DISABLED, TASK_STATE_QUEUED,
        TASK_STATE_READY, TASK_STATE_RUNNING, TaskScheduler,
    };
    use windows::Win32::System::Variant::VARIANT;
    use windows::core::{BSTR, Error};

    pub(super) fn audit_scheduled_tasks() -> Result<ScheduledTasksObservation, PlatformError> {
        let apartment = ComApartment::initialize()?;
        let result = unsafe { observe() };
        drop(apartment);
        result
    }

    unsafe fn observe() -> Result<ScheduledTasksObservation, PlatformError> {
        let service: ITaskService = CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER)
            .map_err(|error| com_error(&error))?;
        let empty = VARIANT::default();
        service
            .Connect(&empty, &empty, &empty, &empty)
            .map_err(|error| com_error(&error))?;
        let root = service
            .GetFolder(&BSTR::from("\\"))
            .map_err(|error| com_error(&error))?;
        Ok(ScheduledTasksObservation {
            tasks: FIXED_SCHEDULED_TASKS
                .into_iter()
                .map(|task| (task, observe_task(&root, task)))
                .collect::<BTreeMap<_, _>>(),
        })
    }

    unsafe fn observe_task(
        root: &ITaskFolder,
        task: ScheduledTask,
    ) -> Observation<ScheduledTaskSnapshot> {
        let path = BSTR::from(task.path());
        match root.GetTask(&path) {
            Ok(registered) => Observation::Present(snapshot(&registered)),
            Err(error) => observation_error(&error),
        }
    }

    unsafe fn snapshot(task: &IRegisteredTask) -> ScheduledTaskSnapshot {
        ScheduledTaskSnapshot {
            enabled: task.Enabled().map_or_else(
                |error| observation_error(&error),
                |value| Observation::Present(value.as_bool()),
            ),
            state: task
                .State()
                .map_or_else(|error| observation_error(&error), state),
        }
    }

    fn state(
        value: windows::Win32::System::TaskScheduler::TASK_STATE,
    ) -> Observation<ScheduledTaskState> {
        let state = if value == TASK_STATE_DISABLED {
            ScheduledTaskState::Disabled
        } else if value == TASK_STATE_QUEUED {
            ScheduledTaskState::Queued
        } else if value == TASK_STATE_READY {
            ScheduledTaskState::Ready
        } else if value == TASK_STATE_RUNNING {
            ScheduledTaskState::Running
        } else {
            ScheduledTaskState::Unknown
        };
        Observation::Present(state)
    }

    fn observation_error<T>(error: &Error) -> Observation<T> {
        match win32_code(error) {
            value if value == ERROR_FILE_NOT_FOUND.0 || value == ERROR_PATH_NOT_FOUND.0 => {
                Observation::Missing
            }
            value if value == ERROR_ACCESS_DENIED.0 => Observation::AccessDenied,
            _ => Observation::Unparsed,
        }
    }

    fn win32_code(error: &Error) -> u32 {
        u32::from_ne_bytes(error.code().0.to_ne_bytes()) & 0xffff
    }

    fn com_error(error: &Error) -> PlatformError {
        PlatformError::TrustFailure(format!("Task Scheduler COM observation failed: {error}"))
    }

    struct ComApartment;

    impl ComApartment {
        fn initialize() -> Result<Self, PlatformError> {
            unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) }
                .ok()
                .map(|()| Self)
                .map_err(|error| com_error(&error))
        }
    }

    impl Drop for ComApartment {
        fn drop(&mut self) {
            unsafe { CoUninitialize() };
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn non_windows_task_scheduler_observation_is_explicitly_unsupported() {
        #[cfg(not(windows))]
        assert!(matches!(
            super::audit_scheduled_tasks(),
            Err(super::PlatformError::UnsupportedPlatform)
        ));
    }
}
