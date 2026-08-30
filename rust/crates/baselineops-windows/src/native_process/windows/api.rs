//! Minimal raw Win32 declarations used by the suspended-process launcher.

#![allow(unsafe_code)]

pub(super) type Handle = isize;

pub(super) const INVALID_HANDLE_VALUE: Handle = -1;
pub(super) const HANDLE_FLAG_INHERIT: u32 = 1;
pub(super) const CREATE_SUSPENDED: u32 = 0x0000_0004;
pub(super) const EXTENDED_STARTUPINFO_PRESENT: u32 = 0x0008_0000;
pub(super) const CREATE_UNICODE_ENVIRONMENT: u32 = 0x0000_0400;
pub(super) const STARTF_USESTDHANDLES: u32 = 0x0000_0100;
pub(super) const PROC_THREAD_ATTRIBUTE_HANDLE_LIST: usize = 0x0002_0004;
pub(super) const WAIT_OBJECT_0: u32 = 0;
pub(super) const WAIT_TIMEOUT: u32 = 258;
pub(super) const WAIT_FAILED: u32 = u32::MAX;
pub(super) const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: u32 = 9;
pub(super) const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x0000_2000;
pub(super) const GENERIC_READ: u32 = 0x8000_0000;
pub(super) const FILE_SHARE_READ: u32 = 1;
pub(super) const FILE_SHARE_WRITE: u32 = 2;
pub(super) const OPEN_EXISTING: u32 = 3;
pub(super) const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;

#[repr(C)]
pub(super) struct SecurityAttributes {
    pub(super) length: u32,
    pub(super) security_descriptor: *mut core::ffi::c_void,
    pub(super) inherit_handle: i32,
}

#[repr(C)]
pub(super) struct StartupInfoW {
    pub(super) cb: u32,
    pub(super) reserved: *mut u16,
    pub(super) desktop: *mut u16,
    pub(super) title: *mut u16,
    pub(super) x: u32,
    pub(super) y: u32,
    pub(super) x_size: u32,
    pub(super) y_size: u32,
    pub(super) x_count_chars: u32,
    pub(super) y_count_chars: u32,
    pub(super) fill_attribute: u32,
    pub(super) flags: u32,
    pub(super) show_window: u16,
    pub(super) reserved2_count: u16,
    pub(super) reserved2: *mut u8,
    pub(super) stdin: Handle,
    pub(super) stdout: Handle,
    pub(super) stderr: Handle,
}

#[repr(C)]
pub(super) struct StartupInfoExW {
    pub(super) startup_info: StartupInfoW,
    pub(super) attributes: *mut core::ffi::c_void,
}

#[repr(C)]
pub(super) struct ProcessInformation {
    pub(super) process: Handle,
    pub(super) thread: Handle,
    pub(super) process_id: u32,
    pub(super) thread_id: u32,
}

#[repr(C)]
pub(super) struct JobObjectBasicLimitInformation {
    pub(super) per_process_user_time_limit: i64,
    pub(super) per_job_user_time_limit: i64,
    pub(super) limit_flags: u32,
    pub(super) minimum_working_set_size: usize,
    pub(super) maximum_working_set_size: usize,
    pub(super) active_process_limit: u32,
    pub(super) affinity: usize,
    pub(super) priority_class: u32,
    pub(super) scheduling_class: u32,
}

#[repr(C)]
#[allow(clippy::struct_field_names)]
pub(super) struct IoCounters {
    pub(super) read_operation_count: u64,
    pub(super) write_operation_count: u64,
    pub(super) other_operation_count: u64,
    pub(super) read_transfer_count: u64,
    pub(super) write_transfer_count: u64,
    pub(super) other_transfer_count: u64,
}

#[repr(C)]
pub(super) struct JobObjectExtendedLimitInformation {
    pub(super) basic_limit_information: JobObjectBasicLimitInformation,
    pub(super) io_info: IoCounters,
    pub(super) process_memory_limit: usize,
    pub(super) job_memory_limit: usize,
    pub(super) peak_process_memory_used: usize,
    pub(super) peak_job_memory_used: usize,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    pub(super) fn AssignProcessToJobObject(job: Handle, process: Handle) -> i32;
    pub(super) fn CloseHandle(handle: Handle) -> i32;
    pub(super) fn CreateFileW(
        name: *const u16,
        desired_access: u32,
        share_mode: u32,
        attributes: *const core::ffi::c_void,
        creation: u32,
        flags: u32,
        template: Handle,
    ) -> Handle;
    pub(super) fn CreateJobObjectW(
        attributes: *const core::ffi::c_void,
        name: *const u16,
    ) -> Handle;
    pub(super) fn CreatePipe(
        read: *mut Handle,
        write: *mut Handle,
        attributes: *const core::ffi::c_void,
        size: u32,
    ) -> i32;
    pub(super) fn CreateProcessW(
        application_name: *const u16,
        command_line: *mut u16,
        process_attributes: *const core::ffi::c_void,
        thread_attributes: *const core::ffi::c_void,
        inherit_handles: i32,
        creation_flags: u32,
        environment: *const core::ffi::c_void,
        current_directory: *const u16,
        startup_info: *const StartupInfoW,
        process_information: *mut ProcessInformation,
    ) -> i32;
    pub(super) fn DeleteProcThreadAttributeList(attributes: *mut core::ffi::c_void);
    pub(super) fn GetExitCodeProcess(process: Handle, exit_code: *mut u32) -> i32;
    pub(super) fn GetLastError() -> u32;
    pub(super) fn InitializeProcThreadAttributeList(
        attributes: *mut core::ffi::c_void,
        count: u32,
        flags: u32,
        size: *mut usize,
    ) -> i32;
    pub(super) fn ResumeThread(thread: Handle) -> u32;
    pub(super) fn SetHandleInformation(handle: Handle, mask: u32, flags: u32) -> i32;
    pub(super) fn SetInformationJobObject(
        job: Handle,
        class: u32,
        information: *const core::ffi::c_void,
        length: u32,
    ) -> i32;
    pub(super) fn TerminateProcess(process: Handle, exit_code: u32) -> i32;
    pub(super) fn TerminateJobObject(job: Handle, exit_code: u32) -> i32;
    pub(super) fn UpdateProcThreadAttribute(
        attributes: *mut core::ffi::c_void,
        flags: u32,
        attribute: usize,
        value: *const core::ffi::c_void,
        value_size: usize,
        previous_value: *mut core::ffi::c_void,
        return_size: *mut usize,
    ) -> i32;
    pub(super) fn WaitForSingleObject(handle: Handle, milliseconds: u32) -> u32;
}
