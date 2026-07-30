use std::{
    io::Read,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use super::*;

pub(super) struct ProcessObservationRunner;

impl ObservationRunner for ProcessObservationRunner {
    fn run(
        &mut self,
        kind: ObservationKind,
        arguments: &[String],
        request: &ValidatedRequest,
        deadline: Instant,
    ) -> Result<RawObservation, AdmissionFault> {
        let account = empty_account(request.source.budget.timeout_millis);
        if hash_file(&request.git_executable, kind.operation(), account.clone())?
            != request.source.git_executable_sha256
        {
            return Err(fault(
                AdmissionFaultCode::Executable,
                kind.operation(),
                "Git executable changed after request validation",
                account,
            ));
        }
        let mut child = Command::new(&request.git_executable)
            .args(arguments)
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE")
            .env_remove("GIT_OBJECT_DIRECTORY")
            .env_remove("GIT_COMMON_DIR")
            .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
            .env_remove("GIT_CONFIG")
            .env_remove("GIT_CONFIG_COUNT")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GCM_INTERACTIVE", "Never")
            .env("GIT_PAGER", "cat")
            .env("PAGER", "cat")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| {
                fault(
                    AdmissionFaultCode::Process,
                    kind.operation(),
                    format!("could not launch pinned Git executable: {error}"),
                    account.clone(),
                )
            })?;
        let Some(stdout) = child.stdout.take() else {
            terminate_child(&mut child);
            return Err(fault(
                AdmissionFaultCode::Process,
                kind.operation(),
                "Git stdout is unavailable",
                account,
            ));
        };
        let Some(stderr) = child.stderr.take() else {
            terminate_child(&mut child);
            return Err(fault(
                AdmissionFaultCode::Process,
                kind.operation(),
                "Git stderr is unavailable",
                account,
            ));
        };
        let retain_limit = request.source.budget.maximum_command_bytes;
        let stdout_reader = thread::spawn(move || drain_bounded(stdout, retain_limit));
        let stderr_reader = thread::spawn(move || drain_bounded(stderr, retain_limit));
        let wait_result = wait_for_child(&mut child, deadline, kind, &account);
        let stdout_result = stdout_reader.join().map_err(|_| {
            fault(
                AdmissionFaultCode::Internal,
                kind.operation(),
                "stdout reader panicked",
                account.clone(),
            )
        })?;
        let stderr_result = stderr_reader.join().map_err(|_| {
            fault(
                AdmissionFaultCode::Internal,
                kind.operation(),
                "stderr reader panicked",
                account.clone(),
            )
        })?;
        let exit_code = wait_result?;
        let (stdout, stdout_count) = stdout_result.map_err(|error| {
            fault(
                AdmissionFaultCode::Process,
                kind.operation(),
                format!("could not read Git stdout: {error}"),
                account.clone(),
            )
        })?;
        let (stderr, stderr_count) = stderr_result.map_err(|error| {
            fault(
                AdmissionFaultCode::Process,
                kind.operation(),
                format!("could not read Git stderr: {error}"),
                account.clone(),
            )
        })?;
        let observed_bytes = stdout_count.checked_add(stderr_count).ok_or_else(|| {
            fault(
                AdmissionFaultCode::Budget,
                kind.operation(),
                "command byte count overflowed",
                account.clone(),
            )
        })?;
        Ok(RawObservation {
            exit_code,
            stdout,
            stderr,
            observed_bytes,
        })
    }
}

fn wait_for_child(
    child: &mut Child,
    deadline: Instant,
    kind: ObservationKind,
    account: &AdmissionResourceAccount,
) -> Result<i32, AdmissionFault> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status.code().unwrap_or(-1)),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
            Ok(None) => {
                terminate_child(child);
                return Err(fault(
                    AdmissionFaultCode::Budget,
                    kind.operation(),
                    "Git observation exceeded the admission deadline",
                    account.clone(),
                ));
            }
            Err(error) => {
                terminate_child(child);
                return Err(fault(
                    AdmissionFaultCode::Process,
                    kind.operation(),
                    error.to_string(),
                    account.clone(),
                ));
            }
        }
    }
}

fn drain_bounded(mut reader: impl Read, retain_limit: usize) -> std::io::Result<(Vec<u8>, usize)> {
    let mut retained = Vec::new();
    let mut observed = 0_usize;
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        match reader.read(&mut buffer)? {
            0 => break,
            count => {
                observed = observed.saturating_add(count);
                let remaining = retain_limit.saturating_sub(retained.len());
                retained.extend_from_slice(&buffer[..count.min(remaining)]);
            }
        }
    }
    Ok((retained, observed))
}

fn terminate_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}
