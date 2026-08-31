#![allow(unsafe_code)]
//! Windows-only contained-child substrate for separately signed B1 and RSO callers.
//!
//! This is the sole `unsafe` island in `cantor_ecosystem`. It owns raw Windows
//! handles through RAII, creates a child suspended, assigns it to a fresh
//! kill-on-close job, and only then resumes the primary thread. Each caller must
//! present its own crate-private, non-interchangeable execution capability; B1
//! remains locked when its activation digest is absent, while RSO admits only a
//! validated hash-pinned request and one closed Git operation.

use std::{
    ffi::c_void,
    fs::File,
    io::{Read, Write},
    mem::{ManuallyDrop, size_of, zeroed},
    os::windows::{
        ffi::OsStrExt,
        io::{FromRawHandle, RawHandle},
    },
    path::Path,
    ptr::{null, null_mut},
    sync::mpsc::{self, TryRecvError},
    thread,
    time::{Duration, Instant},
};

use windows_sys::Win32::{
    Foundation::{
        CloseHandle, FALSE, GetLastError, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE,
        SetHandleInformation, TRUE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Security::SECURITY_ATTRIBUTES,
    System::{
        JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectBasicAccountingInformation,
            JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
            TerminateJobObject,
        },
        Pipes::CreatePipe,
        Threading::{
            CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
            DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess,
            InitializeProcThreadAttributeList, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOEXW,
            TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
        },
    },
};

use crate::{
    B1CDrivePhysicalExecutionPermit, B1CDriveWindowsContainedChildObservation,
    B1CDriveWindowsContainedChildSpec,
    sjs_compiled_lookahead_repository_slice_observation::{
        SjsRsoContainedChildObservation, SjsRsoContainedChildSpec, SjsRsoGitRunner,
    },
};

const MAX_ARGUMENTS: usize = 32;
const MAX_STDIN_BYTES: usize = 2 * 1024 * 1024;
const MAX_STDOUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_STDERR_BYTES: usize = 2 * 1024 * 1024;
const MAX_TIMEOUT_MILLIS: u32 = 30_000;
const MAX_ACTIVE_PROCESSES: u32 = 2;
const MAX_TOTAL_PROCESSES: u32 = 4;
const TERMINATION_EXIT_CODE: u32 = 0xC0A7_0001;
const ENVIRONMENT_NAMES: [&str; 7] = [
    "CODEX_HOME",
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "WINDIR",
];

pub(crate) fn run_contained_child(
    permit: &B1CDrivePhysicalExecutionPermit,
    spec: &B1CDriveWindowsContainedChildSpec,
) -> Result<B1CDriveWindowsContainedChildObservation, String> {
    validate_spec(permit, spec)?;

    run_validated_contained_child(spec)
}

pub(crate) fn run_sjs_rso_contained_child(
    runner: &SjsRsoGitRunner,
    spec: &SjsRsoContainedChildSpec,
) -> Result<SjsRsoContainedChildObservation, String> {
    runner
        .authorize_contained_spec(spec)
        .map_err(|error| error.to_string())?;

    run_validated_contained_child(spec)
}

fn run_validated_contained_child<S>(spec: &S) -> Result<S::Observation, String>
where
    S: WindowsContainedChildContract,
{
    let mut application = wide_nul(spec.executable())?;
    let mut command_line = wide_nul(&build_command_line(spec.executable(), spec.arguments())?)?;
    let environment = encode_environment_block(spec.environment())?;
    let current_directory = wide_nul(spec.working_directory())?;

    let job = create_job(spec.maximum_active_processes())?;
    let mut pipes = PipeSet::new()?;
    let child_handles = [
        pipes.stdin_child.raw(),
        pipes.stdout_child.raw(),
        pipes.stderr_child.raw(),
    ];
    let mut attributes = ProcThreadAttributeList::new(&child_handles)?;

    let mut startup: STARTUPINFOEXW = unsafe { zeroed() };
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = pipes.stdin_child.raw();
    startup.StartupInfo.hStdOutput = pipes.stdout_child.raw();
    startup.StartupInfo.hStdError = pipes.stderr_child.raw();
    startup.lpAttributeList = attributes.as_mut_ptr();

    let mut process_info: PROCESS_INFORMATION = unsafe { zeroed() };
    let creation_flags = CREATE_SUSPENDED
        | CREATE_UNICODE_ENVIRONMENT
        | CREATE_NO_WINDOW
        | EXTENDED_STARTUPINFO_PRESENT;
    let created = unsafe {
        CreateProcessW(
            application.as_mut_ptr(),
            command_line.as_mut_ptr(),
            null(),
            null(),
            TRUE,
            creation_flags,
            environment.as_ptr().cast::<c_void>(),
            current_directory.as_ptr(),
            &startup.StartupInfo as *const _,
            &mut process_info,
        )
    };
    if created == FALSE {
        return Err(last_error("CreateProcessW"));
    }

    let process = OwnedHandle::new(process_info.hProcess, "CreateProcessW process")?;
    let thread_handle = match OwnedHandle::new(process_info.hThread, "CreateProcessW thread") {
        Ok(handle) => handle,
        Err(error) => {
            terminate_suspended_process(&process);
            return Err(error);
        }
    };
    pipes.close_child_sides();

    let assigned = unsafe { AssignProcessToJobObject(job.raw(), process.raw()) };
    if assigned == FALSE {
        let error = last_error("AssignProcessToJobObject");
        terminate_suspended_process(&process);
        return Err(error);
    }

    let resume_previous_count = unsafe { ResumeThread(thread_handle.raw()) };
    if resume_previous_count != 1 {
        terminate_job(&job);
        wait_after_termination(&process);
        return Err(format!(
            "ResumeThread previous suspend count differs: {resume_previous_count}"
        ));
    }

    let stdout_file = pipes
        .stdout_parent
        .take()
        .ok_or_else(|| "stdout parent pipe is absent".to_owned())?
        .into_file();
    let stderr_file = pipes
        .stderr_parent
        .take()
        .ok_or_else(|| "stderr parent pipe is absent".to_owned())?
        .into_file();
    let (event_tx, event_rx) = mpsc::channel();
    let stdout_reader = spawn_drain(
        stdout_file,
        spec.maximum_stdout_bytes(),
        StreamKind::Stdout,
        event_tx.clone(),
    );
    let stderr_reader = spawn_drain(
        stderr_file,
        spec.maximum_stderr_bytes(),
        StreamKind::Stderr,
        event_tx,
    );

    if let Some(stdin_parent) = pipes.stdin_parent.take() {
        let mut stdin_file = stdin_parent.into_file();
        if let Err(error) = stdin_file.write_all(spec.stdin()) {
            terminate_job(&job);
            wait_after_termination(&process);
            let _ = join_drain(stdout_reader, "stdout");
            let _ = join_drain(stderr_reader, "stderr");
            return Err(format!("stdin write failed: {error}"));
        }
        if let Err(error) = stdin_file.flush() {
            terminate_job(&job);
            wait_after_termination(&process);
            let _ = join_drain(stdout_reader, "stdout");
            let _ = join_drain(stderr_reader, "stderr");
            return Err(format!("stdin flush failed: {error}"));
        }
    }

    let deadline = Instant::now() + Duration::from_millis(u64::from(spec.timeout_millis()));
    let mut forced_termination = false;
    loop {
        match event_rx.try_recv() {
            Ok(DrainEvent::OverBound(kind, observed)) => {
                terminate_job(&job);
                wait_after_termination(&process);
                let _ = join_drain(stdout_reader, "stdout");
                let _ = join_drain(stderr_reader, "stderr");
                return Err(format!(
                    "{} output exceeded bound at {observed} bytes",
                    kind.label()
                ));
            }
            Ok(DrainEvent::Fault(kind, message)) => {
                terminate_job(&job);
                wait_after_termination(&process);
                let _ = join_drain(stdout_reader, "stdout");
                let _ = join_drain(stderr_reader, "stderr");
                return Err(format!("{} drain failed: {message}", kind.label()));
            }
            Err(TryRecvError::Disconnected | TryRecvError::Empty) => {}
        }

        let now = Instant::now();
        if now >= deadline {
            forced_termination = true;
            terminate_job(&job);
            wait_after_termination(&process);
            break;
        }
        let remaining = deadline.saturating_duration_since(now);
        let quantum = remaining.min(Duration::from_millis(10));
        let wait = unsafe { WaitForSingleObject(process.raw(), duration_millis_u32(quantum)) };
        match wait {
            WAIT_OBJECT_0 => break,
            WAIT_TIMEOUT => {}
            WAIT_FAILED => {
                let error = last_error("WaitForSingleObject");
                terminate_job(&job);
                wait_after_termination(&process);
                let _ = join_drain(stdout_reader, "stdout");
                let _ = join_drain(stderr_reader, "stderr");
                return Err(error);
            }
            other => {
                terminate_job(&job);
                wait_after_termination(&process);
                let _ = join_drain(stdout_reader, "stdout");
                let _ = join_drain(stderr_reader, "stderr");
                return Err(format!(
                    "WaitForSingleObject returned unexpected status {other}"
                ));
            }
        }
    }

    let mut accounting = match query_accounting(&job) {
        Ok(accounting) => accounting,
        Err(error) => {
            terminate_job(&job);
            wait_after_termination(&process);
            let _ = join_drain(stdout_reader, "stdout");
            let _ = join_drain(stderr_reader, "stderr");
            return Err(error);
        }
    };
    while accounting.ActiveProcesses != 0 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(1));
        accounting = match query_accounting(&job) {
            Ok(accounting) => accounting,
            Err(error) => {
                terminate_job(&job);
                wait_after_termination(&process);
                let _ = join_drain(stdout_reader, "stdout");
                let _ = join_drain(stderr_reader, "stderr");
                return Err(error);
            }
        };
    }
    if accounting.ActiveProcesses != 0 {
        forced_termination = true;
        terminate_job(&job);
        accounting = match wait_for_zero_active(&job, deadline) {
            Ok(accounting) => accounting,
            Err(error) => {
                let _ = join_drain(stdout_reader, "stdout");
                let _ = join_drain(stderr_reader, "stderr");
                return Err(error);
            }
        };
    }

    let stdout = join_drain(stdout_reader, "stdout")?;
    let stderr = join_drain(stderr_reader, "stderr")?;
    let mut exit_code = 0_u32;
    if unsafe { GetExitCodeProcess(process.raw(), &mut exit_code) } == FALSE {
        return Err(last_error("GetExitCodeProcess"));
    }
    if accounting.TotalProcesses > spec.maximum_total_processes() {
        return Err(format!(
            "job total process count {} exceeds {}",
            accounting.TotalProcesses,
            spec.maximum_total_processes()
        ));
    }

    Ok(spec.make_observation(RawContainedChildObservation {
        exit_code,
        stdout: stdout.retained,
        stderr: stderr.retained,
        stdout_observed_bytes: stdout.observed,
        stderr_observed_bytes: stderr.observed,
        stdout_over_bound: stdout.over_bound,
        stderr_over_bound: stderr.over_bound,
        forced_termination,
        total_processes: accounting.TotalProcesses,
        active_processes_at_terminal: accounting.ActiveProcesses,
        resume_previous_count,
    }))
}

struct RawContainedChildObservation {
    exit_code: u32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_observed_bytes: u64,
    stderr_observed_bytes: u64,
    stdout_over_bound: bool,
    stderr_over_bound: bool,
    forced_termination: bool,
    total_processes: u32,
    active_processes_at_terminal: u32,
    resume_previous_count: u32,
}

trait WindowsContainedChildContract {
    type Observation;

    fn executable(&self) -> &str;
    fn arguments(&self) -> &[String];
    fn working_directory(&self) -> &str;
    fn environment(&self) -> &[(String, String)];
    fn stdin(&self) -> &[u8];
    fn maximum_stdout_bytes(&self) -> usize;
    fn maximum_stderr_bytes(&self) -> usize;
    fn timeout_millis(&self) -> u32;
    fn maximum_active_processes(&self) -> u32;
    fn maximum_total_processes(&self) -> u32;
    fn make_observation(&self, raw: RawContainedChildObservation) -> Self::Observation;
}

impl WindowsContainedChildContract for B1CDriveWindowsContainedChildSpec {
    type Observation = B1CDriveWindowsContainedChildObservation;

    fn executable(&self) -> &str {
        &self.executable
    }

    fn arguments(&self) -> &[String] {
        &self.arguments
    }

    fn working_directory(&self) -> &str {
        &self.working_directory
    }

    fn environment(&self) -> &[(String, String)] {
        &self.environment
    }

    fn stdin(&self) -> &[u8] {
        &self.stdin
    }

    fn maximum_stdout_bytes(&self) -> usize {
        self.maximum_stdout_bytes
    }

    fn maximum_stderr_bytes(&self) -> usize {
        self.maximum_stderr_bytes
    }

    fn timeout_millis(&self) -> u32 {
        self.timeout_millis
    }

    fn maximum_active_processes(&self) -> u32 {
        self.maximum_active_processes
    }

    fn maximum_total_processes(&self) -> u32 {
        self.maximum_total_processes
    }

    fn make_observation(&self, raw: RawContainedChildObservation) -> Self::Observation {
        B1CDriveWindowsContainedChildObservation {
            exit_code: raw.exit_code,
            stdout: raw.stdout,
            stderr: raw.stderr,
            stdout_observed_bytes: raw.stdout_observed_bytes,
            stderr_observed_bytes: raw.stderr_observed_bytes,
            stdout_over_bound: raw.stdout_over_bound,
            stderr_over_bound: raw.stderr_over_bound,
            forced_termination: raw.forced_termination,
            total_processes: raw.total_processes,
            active_processes_at_terminal: raw.active_processes_at_terminal,
            resume_previous_count: raw.resume_previous_count,
        }
    }
}

impl WindowsContainedChildContract for SjsRsoContainedChildSpec {
    type Observation = SjsRsoContainedChildObservation;

    fn executable(&self) -> &str {
        &self.executable
    }

    fn arguments(&self) -> &[String] {
        &self.arguments
    }

    fn working_directory(&self) -> &str {
        &self.working_directory
    }

    fn environment(&self) -> &[(String, String)] {
        &self.environment
    }

    fn stdin(&self) -> &[u8] {
        &self.stdin
    }

    fn maximum_stdout_bytes(&self) -> usize {
        self.maximum_stdout_bytes
    }

    fn maximum_stderr_bytes(&self) -> usize {
        self.maximum_stderr_bytes
    }

    fn timeout_millis(&self) -> u32 {
        self.timeout_millis
    }

    fn maximum_active_processes(&self) -> u32 {
        self.maximum_active_processes
    }

    fn maximum_total_processes(&self) -> u32 {
        self.maximum_total_processes
    }

    fn make_observation(&self, raw: RawContainedChildObservation) -> Self::Observation {
        SjsRsoContainedChildObservation {
            exit_code: raw.exit_code,
            stdout: raw.stdout,
            stderr: raw.stderr,
            stdout_observed_bytes: raw.stdout_observed_bytes,
            stderr_observed_bytes: raw.stderr_observed_bytes,
            stdout_over_bound: raw.stdout_over_bound,
            stderr_over_bound: raw.stderr_over_bound,
            forced_termination: raw.forced_termination,
            total_processes: raw.total_processes,
            active_processes_at_terminal: raw.active_processes_at_terminal,
            resume_previous_count: raw.resume_previous_count,
        }
    }
}

fn validate_spec(
    permit: &B1CDrivePhysicalExecutionPermit,
    spec: &B1CDriveWindowsContainedChildSpec,
) -> Result<(), String> {
    if permit.attempt_sha256() != &spec.attempt_sha256 {
        return Err("contained-child attempt digest differs from permit".to_owned());
    }
    validate_text("executable", &spec.executable)?;
    validate_text("working directory", &spec.working_directory)?;
    if !is_absolute_c_drive_path(&spec.executable)
        || !is_absolute_c_drive_path(&spec.working_directory)
    {
        return Err("executable and working directory must be absolute C-drive paths".to_owned());
    }
    if !Path::new(&spec.executable).is_absolute()
        || !Path::new(&spec.working_directory).is_absolute()
    {
        return Err("Windows path parser rejected executable or working directory".to_owned());
    }
    if spec.arguments.len() > MAX_ARGUMENTS {
        return Err("argument count exceeds bound".to_owned());
    }
    for argument in &spec.arguments {
        validate_text("argument", argument)?;
        if contains_d_drive_coordinate(argument) {
            return Err("argument contains a D-drive coordinate".to_owned());
        }
    }
    if spec.stdin.len() > MAX_STDIN_BYTES {
        return Err("stdin exceeds bound".to_owned());
    }
    if spec.maximum_stdout_bytes == 0 || spec.maximum_stdout_bytes > MAX_STDOUT_BYTES {
        return Err("stdout bound differs".to_owned());
    }
    if spec.maximum_stderr_bytes == 0 || spec.maximum_stderr_bytes > MAX_STDERR_BYTES {
        return Err("stderr bound differs".to_owned());
    }
    if spec.timeout_millis == 0 || spec.timeout_millis > MAX_TIMEOUT_MILLIS {
        return Err("timeout differs".to_owned());
    }
    if !(1..=MAX_ACTIVE_PROCESSES).contains(&spec.maximum_active_processes)
        || !(spec.maximum_active_processes..=MAX_TOTAL_PROCESSES)
            .contains(&spec.maximum_total_processes)
    {
        return Err("job process bounds differ".to_owned());
    }
    validate_environment(&spec.environment)
}

fn validate_environment(environment: &[(String, String)]) -> Result<(), String> {
    if environment.len() != ENVIRONMENT_NAMES.len() {
        return Err("environment name count differs".to_owned());
    }
    for ((name, value), expected) in environment.iter().zip(ENVIRONMENT_NAMES) {
        if name != expected {
            return Err("environment names or case-insensitive order differ".to_owned());
        }
        validate_text("environment name", name)?;
        validate_text("environment value", value)?;
        if name.contains('=') || contains_d_drive_coordinate(value) {
            return Err("environment name or drive coordinate differs".to_owned());
        }
    }
    let value = |name: &str| {
        environment
            .iter()
            .find(|(candidate, _)| candidate == name)
            .map(|(_, value)| value.as_str())
            .unwrap_or_default()
    };
    if value("PATH") != r"C:\Windows\System32;C:\Windows"
        || value("PATHEXT") != ".COM;.EXE;.BAT;.CMD"
        || value("SYSTEMROOT") != r"C:\Windows"
        || value("WINDIR") != r"C:\Windows"
    {
        return Err("fixed Windows environment values differ".to_owned());
    }
    for name in ["CODEX_HOME", "TEMP", "TMP"] {
        if !is_absolute_c_drive_path(value(name)) {
            return Err(format!("{name} is not an absolute C-drive path"));
        }
    }
    Ok(())
}

fn validate_text(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty() || value.contains(['\0', '\r', '\n']) {
        return Err(format!(
            "{label} is empty or contains a forbidden character"
        ));
    }
    if value.encode_utf16().count() >= 32_767 {
        return Err(format!("{label} exceeds the Windows UTF-16 bound"));
    }
    Ok(())
}

fn is_absolute_c_drive_path(value: &str) -> bool {
    value.len() >= 3
        && value.as_bytes()[0].eq_ignore_ascii_case(&b'C')
        && value.as_bytes()[1] == b':'
        && matches!(value.as_bytes()[2], b'\\' | b'/')
        && !value.split(['\\', '/']).any(|part| part == "..")
}

fn contains_d_drive_coordinate(value: &str) -> bool {
    value.as_bytes().windows(3).any(|part| {
        part[0].eq_ignore_ascii_case(&b'D') && part[1] == b':' && matches!(part[2], b'\\' | b'/')
    })
}

fn quote_windows_argument(value: &str) -> String {
    if !value.is_empty()
        && !value
            .chars()
            .any(|character| character.is_whitespace() || character == '"')
    {
        return value.to_owned();
    }
    let mut quoted = String::from('"');
    let mut backslashes = 0_usize;
    for character in value.chars() {
        match character {
            '\\' => backslashes += 1,
            '"' => {
                quoted.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                quoted.push('"');
                backslashes = 0;
            }
            _ => {
                quoted.extend(std::iter::repeat_n('\\', backslashes));
                quoted.push(character);
                backslashes = 0;
            }
        }
    }
    quoted.extend(std::iter::repeat_n('\\', backslashes * 2));
    quoted.push('"');
    quoted
}

fn build_command_line(executable: &str, arguments: &[String]) -> Result<String, String> {
    let mut fields = Vec::with_capacity(arguments.len() + 1);
    fields.push(quote_windows_argument(executable));
    fields.extend(
        arguments
            .iter()
            .map(|argument| quote_windows_argument(argument)),
    );
    let command_line = fields.join(" ");
    if command_line.encode_utf16().count() + 1 > 32_767 {
        return Err("command line exceeds Windows UTF-16 bound".to_owned());
    }
    Ok(command_line)
}

#[cfg(test)]
fn build_environment_block(environment: &[(String, String)]) -> Result<Vec<u16>, String> {
    validate_environment(environment)?;
    encode_environment_block(environment)
}

fn encode_environment_block(environment: &[(String, String)]) -> Result<Vec<u16>, String> {
    let mut block = Vec::new();
    for (name, value) in environment {
        validate_text("environment name", name)?;
        validate_text("environment value", value)?;
        if name.contains('=') {
            return Err("environment name contains equals".to_owned());
        }
        block.extend(name.encode_utf16());
        block.push('=' as u16);
        block.extend(value.encode_utf16());
        block.push(0);
    }
    block.push(0);
    Ok(block)
}

fn wide_nul(value: &str) -> Result<Vec<u16>, String> {
    validate_text("Windows string", value)?;
    Ok(std::ffi::OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect())
}

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn new(handle: HANDLE, label: &str) -> Result<Self, String> {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(format!("{label} returned an invalid handle"));
        }
        Ok(Self(handle))
    }

    fn raw(&self) -> HANDLE {
        self.0
    }

    fn into_file(self) -> File {
        let this = ManuallyDrop::new(self);
        unsafe { File::from_raw_handle(this.0 as RawHandle) }
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.0);
            }
            self.0 = null_mut();
        }
    }
}

struct PipeSet {
    stdin_child: OwnedHandle,
    stdin_parent: Option<OwnedHandle>,
    stdout_child: OwnedHandle,
    stdout_parent: Option<OwnedHandle>,
    stderr_child: OwnedHandle,
    stderr_parent: Option<OwnedHandle>,
}

impl PipeSet {
    fn new() -> Result<Self, String> {
        let (stdin_child, stdin_parent) = create_pipe_pair(false)?;
        let (stdout_parent, stdout_child) = create_pipe_pair(true)?;
        let (stderr_parent, stderr_child) = create_pipe_pair(true)?;
        Ok(Self {
            stdin_child,
            stdin_parent: Some(stdin_parent),
            stdout_child,
            stdout_parent: Some(stdout_parent),
            stderr_child,
            stderr_parent: Some(stderr_parent),
        })
    }

    fn close_child_sides(&mut self) {
        let placeholder = null_mut();
        let stdin = std::mem::replace(&mut self.stdin_child, OwnedHandle(placeholder));
        let stdout = std::mem::replace(&mut self.stdout_child, OwnedHandle(placeholder));
        let stderr = std::mem::replace(&mut self.stderr_child, OwnedHandle(placeholder));
        drop((stdin, stdout, stderr));
    }
}

fn create_pipe_pair(parent_reads: bool) -> Result<(OwnedHandle, OwnedHandle), String> {
    let mut read_handle = null_mut();
    let mut write_handle = null_mut();
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: TRUE,
    };
    if unsafe { CreatePipe(&mut read_handle, &mut write_handle, &attributes, 0) } == FALSE {
        return Err(last_error("CreatePipe"));
    }
    let read = OwnedHandle::new(read_handle, "CreatePipe read")?;
    let write = OwnedHandle::new(write_handle, "CreatePipe write")?;
    let parent = if parent_reads {
        read.raw()
    } else {
        write.raw()
    };
    if unsafe { SetHandleInformation(parent, HANDLE_FLAG_INHERIT, 0) } == FALSE {
        return Err(last_error("SetHandleInformation"));
    }
    Ok((read, write))
}

struct ProcThreadAttributeList {
    storage: Vec<usize>,
}

impl ProcThreadAttributeList {
    fn new(handles: &[HANDLE; 3]) -> Result<Self, String> {
        let mut bytes = 0_usize;
        unsafe {
            InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut bytes);
        }
        if bytes == 0 {
            return Err(last_error("InitializeProcThreadAttributeList size query"));
        }
        let words = bytes.div_ceil(size_of::<usize>());
        let mut storage = vec![0_usize; words];
        let pointer = storage.as_mut_ptr().cast();
        if unsafe { InitializeProcThreadAttributeList(pointer, 1, 0, &mut bytes) } == FALSE {
            return Err(last_error("InitializeProcThreadAttributeList"));
        }
        if unsafe {
            UpdateProcThreadAttribute(
                pointer,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_ptr().cast(),
                size_of_val(handles),
                null_mut(),
                null(),
            )
        } == FALSE
        {
            unsafe {
                DeleteProcThreadAttributeList(pointer);
            }
            return Err(last_error("UpdateProcThreadAttribute handle list"));
        }
        Ok(Self { storage })
    }

    fn as_mut_ptr(&mut self) -> *mut c_void {
        self.storage.as_mut_ptr().cast()
    }
}

impl Drop for ProcThreadAttributeList {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(self.storage.as_mut_ptr().cast());
        }
    }
}

fn create_job(maximum_active_processes: u32) -> Result<OwnedHandle, String> {
    let job = OwnedHandle::new(
        unsafe { CreateJobObjectW(null(), null()) },
        "CreateJobObjectW",
    )?;
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
    limits.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
    limits.BasicLimitInformation.ActiveProcessLimit = maximum_active_processes;
    if unsafe {
        SetInformationJobObject(
            job.raw(),
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    } == FALSE
    {
        return Err(last_error("SetInformationJobObject"));
    }
    Ok(job)
}

fn query_accounting(job: &OwnedHandle) -> Result<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, String> {
    let mut accounting: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { zeroed() };
    if unsafe {
        QueryInformationJobObject(
            job.raw(),
            JobObjectBasicAccountingInformation,
            (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
            size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
            null_mut(),
        )
    } == FALSE
    {
        return Err(last_error("QueryInformationJobObject"));
    }
    Ok(accounting)
}

fn wait_for_zero_active(
    job: &OwnedHandle,
    original_deadline: Instant,
) -> Result<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, String> {
    let deadline = original_deadline.max(Instant::now() + Duration::from_secs(5));
    loop {
        let accounting = query_accounting(job)?;
        if accounting.ActiveProcesses == 0 {
            return Ok(accounting);
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "job retained {} active processes after termination",
                accounting.ActiveProcesses
            ));
        }
        thread::sleep(Duration::from_millis(1));
    }
}

fn terminate_suspended_process(process: &OwnedHandle) {
    unsafe {
        TerminateProcess(process.raw(), TERMINATION_EXIT_CODE);
    }
    wait_after_termination(process);
}

fn terminate_job(job: &OwnedHandle) {
    unsafe {
        TerminateJobObject(job.raw(), TERMINATION_EXIT_CODE);
    }
}

fn wait_after_termination(process: &OwnedHandle) {
    unsafe {
        WaitForSingleObject(process.raw(), 5_000);
    }
}

#[derive(Clone, Copy)]
enum StreamKind {
    Stdout,
    Stderr,
}

impl StreamKind {
    fn label(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }
}

enum DrainEvent {
    OverBound(StreamKind, u64),
    Fault(StreamKind, String),
}

struct DrainResult {
    retained: Vec<u8>,
    observed: u64,
    over_bound: bool,
}

fn spawn_drain(
    mut file: File,
    bound: usize,
    kind: StreamKind,
    events: mpsc::Sender<DrainEvent>,
) -> thread::JoinHandle<Result<DrainResult, String>> {
    thread::spawn(move || {
        let mut retained = Vec::with_capacity(bound.min(64 * 1024));
        let mut observed = 0_u64;
        let mut buffer = [0_u8; 8192];
        let mut reported_over_bound = false;
        loop {
            match file.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => {
                    observed = observed.saturating_add(count as u64);
                    let remaining = bound.saturating_sub(retained.len());
                    retained.extend_from_slice(&buffer[..count.min(remaining)]);
                    if observed > bound as u64 && !reported_over_bound {
                        reported_over_bound = true;
                        let _ = events.send(DrainEvent::OverBound(kind, observed));
                    }
                }
                Err(error) => {
                    let message = error.to_string();
                    let _ = events.send(DrainEvent::Fault(kind, message.clone()));
                    return Err(message);
                }
            }
        }
        Ok(DrainResult {
            retained,
            observed,
            over_bound: observed > bound as u64,
        })
    })
}

fn join_drain(
    handle: thread::JoinHandle<Result<DrainResult, String>>,
    label: &str,
) -> Result<DrainResult, String> {
    handle
        .join()
        .map_err(|_| format!("{label} drain thread panicked"))?
}

fn duration_millis_u32(duration: Duration) -> u32 {
    u32::try_from(duration.as_millis())
        .unwrap_or(u32::MAX)
        .max(1)
}

fn last_error(operation: &str) -> String {
    let code = unsafe { GetLastError() };
    format!("{operation} failed with Windows error {code}")
}

#[cfg(test)]
mod tests {
    use super::{build_command_line, build_environment_block, quote_windows_argument};

    fn environment() -> Vec<(String, String)> {
        [
            ("CODEX_HOME", r"C:\Project\CantorWorktrees\x\codex-home"),
            ("PATH", r"C:\Windows\System32;C:\Windows"),
            ("PATHEXT", ".COM;.EXE;.BAT;.CMD"),
            ("SYSTEMROOT", r"C:\Windows"),
            ("TEMP", r"C:\Project\CantorWorktrees\x\temp"),
            ("TMP", r"C:\Project\CantorWorktrees\x\temp"),
            ("WINDIR", r"C:\Windows"),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect()
    }

    #[test]
    fn windows_argument_quote_covers_empty_spaces_quotes_and_trailing_slashes() {
        assert_eq!(quote_windows_argument("plain"), "plain");
        assert_eq!(quote_windows_argument(""), "\"\"");
        assert_eq!(quote_windows_argument("two words"), "\"two words\"");
        assert_eq!(quote_windows_argument("a\\\"b"), "\"a\\\\\\\"b\"");
        assert_eq!(quote_windows_argument(r"trail \"), r#""trail \\""#);
    }

    #[test]
    fn command_line_quotes_application_and_each_argument() {
        let line = build_command_line(
            r"C:\Program Files\Cantor\broker.exe",
            &["app-server".to_owned(), "two words".to_owned()],
        )
        .expect("command line");
        assert_eq!(
            line,
            r#""C:\Program Files\Cantor\broker.exe" app-server "two words""#
        );
    }

    #[test]
    fn environment_block_is_exactly_double_nul_terminated() {
        let block = build_environment_block(&environment()).expect("environment block");
        assert_eq!(block.last(), Some(&0));
        assert_eq!(block.get(block.len() - 2), Some(&0));
        assert_eq!(block.iter().filter(|value| **value == 0).count(), 8);
    }

    #[test]
    fn environment_block_refuses_reordered_or_d_drive_values() {
        let mut reordered = environment();
        reordered.swap(0, 1);
        assert!(build_environment_block(&reordered).is_err());
        let mut d_drive = environment();
        d_drive[4].1 = r"D:\temp".to_owned();
        assert!(build_environment_block(&d_drive).is_err());
        d_drive[4].1 = "d:/temp".to_owned();
        assert!(build_environment_block(&d_drive).is_err());
    }
}
