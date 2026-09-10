//! Fixed-profile contained Cargo child for the EVO-X2 scratch-build experiment.
//!
//! Validation is pure. Physical execution is available only on Windows and is
//! delegated to the crate's existing audited job-object containment island.

use std::collections::BTreeSet;

use cantor_core::{
    EVOX2_SCRATCH_BUILD_EXECUTOR_PATH, EVOX2_SCRATCH_BUILD_SERVICE_ROOT,
    EVOX2_SCRATCH_BUILD_TARGET_ROOT, EVOX2_SCRATCH_BUILD_WORKSPACE_ROOT,
    Evox2ScratchBuildCargoEnvironment, evox2_scratch_build_expected_arguments,
    fixed_evox2_scratch_build_environment,
};

pub const EVOX2_SCRATCH_BUILD_CONTAINED_PROCESS_PROFILE: &str =
    "cantor-evox2-scratch-build-contained-process/0.1";
// Reserve ten seconds inside the commissioned 7,200-second operation bound for
// job termination, drain joins, and durable evidence emission.
pub const EVOX2_SCRATCH_BUILD_PROCESS_TIMEOUT_MILLIS: u32 = 7_190_000;
pub const EVOX2_SCRATCH_BUILD_PROCESS_MAXIMUM_STREAM_BYTES: usize = 16_777_216;
pub const EVOX2_SCRATCH_BUILD_PROCESS_MAXIMUM_ACTIVE_PROCESSES: u32 = 64;
pub const EVOX2_SCRATCH_BUILD_PROCESS_MAXIMUM_TOTAL_PROCESSES: u32 = 16_384;
const MAX_ENVIRONMENT_ENTRIES: usize = 64;
const MAX_ENVIRONMENT_BYTES: usize = 131_072;
const TOOLCHAIN_PROBE_ARGUMENTS: [&str; 5] =
    ["metadata", "--locked", "--offline", "--format-version", "1"];

pub fn evox2_scratch_build_toolchain_probe_arguments() -> Vec<String> {
    TOOLCHAIN_PROBE_ARGUMENTS
        .iter()
        .map(|value| (*value).to_owned())
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evox2ScratchBuildContainedProcessSpec {
    pub profile: String,
    pub ordinal: u32,
    pub executable: String,
    pub executable_sha256: String,
    pub arguments: Vec<String>,
    pub working_directory: String,
    pub cargo_environment: Evox2ScratchBuildCargoEnvironment,
    pub process_environment: Vec<(String, String)>,
    pub maximum_stdout_bytes: usize,
    pub maximum_stderr_bytes: usize,
    pub timeout_millis: u32,
    pub maximum_active_processes: u32,
    pub maximum_total_processes: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evox2ScratchBuildContainedProcessObservation {
    pub exit_code: u32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_observed_bytes: u64,
    pub stderr_observed_bytes: u64,
    pub stdout_over_bound: bool,
    pub stderr_over_bound: bool,
    pub forced_termination: bool,
    pub total_processes: u32,
    pub active_processes_at_terminal: u32,
    pub resume_previous_count: u32,
}

impl Evox2ScratchBuildContainedProcessSpec {
    pub fn validate(&self) -> Result<(), String> {
        let expected_arguments = if self.ordinal == 0 {
            evox2_scratch_build_toolchain_probe_arguments()
        } else {
            evox2_scratch_build_expected_arguments(self.ordinal)
        };
        if self.profile != EVOX2_SCRATCH_BUILD_CONTAINED_PROCESS_PROFILE
            || self.ordinal > 7
            || self.arguments != expected_arguments
            || self.cargo_environment != fixed_evox2_scratch_build_environment()
        {
            return Err("contained operation identity differs".to_owned());
        }
        let expected_working_directory = match self.ordinal {
            1 => EVOX2_SCRATCH_BUILD_SERVICE_ROOT,
            2 => "C:/AI/workspaces",
            7 => EVOX2_SCRATCH_BUILD_TARGET_ROOT,
            _ => EVOX2_SCRATCH_BUILD_WORKSPACE_ROOT,
        };
        if self.working_directory != expected_working_directory {
            return Err("contained operation working directory differs".to_owned());
        }
        if !is_absolute_c_drive_path(&self.executable) || !is_lower_hex(&self.executable_sha256, 64)
        {
            return Err("contained operation executable identity differs".to_owned());
        }
        if matches!(self.ordinal, 1 | 2 | 7) && self.executable != EVOX2_SCRATCH_BUILD_EXECUTOR_PATH
        {
            return Err("contained executor identity differs".to_owned());
        }
        if self.maximum_stdout_bytes != EVOX2_SCRATCH_BUILD_PROCESS_MAXIMUM_STREAM_BYTES
            || self.maximum_stderr_bytes != EVOX2_SCRATCH_BUILD_PROCESS_MAXIMUM_STREAM_BYTES
            || self.timeout_millis != EVOX2_SCRATCH_BUILD_PROCESS_TIMEOUT_MILLIS
            || self.maximum_active_processes != EVOX2_SCRATCH_BUILD_PROCESS_MAXIMUM_ACTIVE_PROCESSES
            || self.maximum_total_processes != EVOX2_SCRATCH_BUILD_PROCESS_MAXIMUM_TOTAL_PROCESSES
        {
            return Err("contained Cargo resource boundary differs".to_owned());
        }
        validate_process_environment(&self.process_environment, &self.cargo_environment)
    }
}

#[cfg(windows)]
pub fn run_evox2_scratch_build_contained_process(
    spec: &Evox2ScratchBuildContainedProcessSpec,
) -> Result<Evox2ScratchBuildContainedProcessObservation, String> {
    spec.validate()?;
    crate::self_work_update_broker_b1_cdrive_windows_containment::run_evox2_scratch_build_contained_process(spec)
}

#[cfg(not(windows))]
pub fn run_evox2_scratch_build_contained_process(
    spec: &Evox2ScratchBuildContainedProcessSpec,
) -> Result<Evox2ScratchBuildContainedProcessObservation, String> {
    spec.validate()?;
    Err("contained Cargo execution is available only on Windows".to_owned())
}

fn validate_process_environment(
    environment: &[(String, String)],
    cargo: &Evox2ScratchBuildCargoEnvironment,
) -> Result<(), String> {
    if environment.is_empty() || environment.len() > MAX_ENVIRONMENT_ENTRIES {
        return Err("contained Cargo environment cardinality differs".to_owned());
    }
    let mut total = 0_usize;
    let mut seen = BTreeSet::new();
    let mut previous = None::<String>;
    for (name, value) in environment {
        if name.is_empty()
            || value.is_empty()
            || name.contains('=')
            || name.chars().any(char::is_control)
            || value.chars().any(|character| character == '\0')
        {
            return Err("contained Cargo environment entry differs".to_owned());
        }
        let folded = name.to_ascii_uppercase();
        if previous.as_ref().is_some_and(|entry| entry >= &folded) || !seen.insert(folded.clone()) {
            return Err("contained Cargo environment ordering differs".to_owned());
        }
        previous = Some(folded);
        total = total
            .checked_add(name.len() + value.len() + 2)
            .ok_or_else(|| "contained Cargo environment bytes overflow".to_owned())?;
    }
    if total > MAX_ENVIRONMENT_BYTES {
        return Err("contained Cargo environment bytes exceed bound".to_owned());
    }
    for (name, expected) in [
        ("CARGO_BUILD_JOBS", cargo.CARGO_BUILD_JOBS.to_string()),
        ("CARGO_INCREMENTAL", cargo.CARGO_INCREMENTAL.to_string()),
        (
            "CARGO_NET_OFFLINE",
            cargo.CARGO_NET_OFFLINE.to_string().to_ascii_lowercase(),
        ),
        ("CARGO_TARGET_DIR", cargo.CARGO_TARGET_DIR.clone()),
        ("RUST_MIN_STACK", cargo.RUST_MIN_STACK.to_string()),
        ("RUST_TEST_THREADS", cargo.RUST_TEST_THREADS.to_string()),
    ] {
        if environment_value(environment, name) != Some(expected.as_str()) {
            return Err("contained Cargo fixed environment differs".to_owned());
        }
    }
    for required in ["PATH", "PATHEXT", "SYSTEMROOT", "TEMP", "TMP", "WINDIR"] {
        if environment_value(environment, required).is_none() {
            return Err("contained Cargo platform environment is incomplete".to_owned());
        }
    }
    for forbidden in [
        "CARGO_ENCODED_RUSTFLAGS",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "RUSTDOCFLAGS",
        "RUSTFLAGS",
    ] {
        if environment_value(environment, forbidden).is_some() {
            return Err("contained Cargo ambient override refused".to_owned());
        }
    }
    if environment.iter().any(|(name, _)| {
        let folded = name.to_ascii_uppercase();
        (folded.starts_with("CARGO_PROFILE_") || folded.starts_with("CARGO_TARGET_"))
            && folded != "CARGO_TARGET_DIR"
    }) {
        return Err("contained Cargo ambient profile or target override refused".to_owned());
    }
    if cargo.CARGO_TARGET_DIR != EVOX2_SCRATCH_BUILD_TARGET_ROOT {
        return Err("contained Cargo target root differs".to_owned());
    }
    Ok(())
}

fn environment_value<'a>(environment: &'a [(String, String)], name: &str) -> Option<&'a str> {
    environment
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn is_absolute_c_drive_path(value: &str) -> bool {
    value.len() >= 3
        && value.as_bytes()[0].eq_ignore_ascii_case(&b'C')
        && value.as_bytes()[1] == b':'
        && matches!(value.as_bytes()[2], b'\\' | b'/')
        && !value.split(['\\', '/']).any(|part| part == "..")
        && !value.chars().any(char::is_control)
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn environment() -> Vec<(String, String)> {
        let cargo = fixed_evox2_scratch_build_environment();
        let mut values = vec![
            (
                "CARGO_BUILD_JOBS".to_owned(),
                cargo.CARGO_BUILD_JOBS.to_string(),
            ),
            (
                "CARGO_INCREMENTAL".to_owned(),
                cargo.CARGO_INCREMENTAL.to_string(),
            ),
            ("CARGO_NET_OFFLINE".to_owned(), "true".to_owned()),
            (
                "CARGO_TARGET_DIR".to_owned(),
                cargo.CARGO_TARGET_DIR.clone(),
            ),
            (
                "PATH".to_owned(),
                r"C:\Tools;C:\Windows\System32".to_owned(),
            ),
            ("PATHEXT".to_owned(), ".COM;.EXE;.BAT;.CMD".to_owned()),
            (
                "RUST_MIN_STACK".to_owned(),
                cargo.RUST_MIN_STACK.to_string(),
            ),
            (
                "RUST_TEST_THREADS".to_owned(),
                cargo.RUST_TEST_THREADS.to_string(),
            ),
            ("SYSTEMROOT".to_owned(), r"C:\Windows".to_owned()),
            ("TEMP".to_owned(), r"C:\AI\temp".to_owned()),
            ("TMP".to_owned(), r"C:\AI\temp".to_owned()),
            ("WINDIR".to_owned(), r"C:\Windows".to_owned()),
        ];
        values.sort_by_key(|(name, _)| name.to_ascii_uppercase());
        values
    }

    fn spec() -> Evox2ScratchBuildContainedProcessSpec {
        Evox2ScratchBuildContainedProcessSpec {
            profile: EVOX2_SCRATCH_BUILD_CONTAINED_PROCESS_PROFILE.to_owned(),
            ordinal: 3,
            executable: r"C:\Users\cantor\.cargo\bin\cargo.exe".to_owned(),
            executable_sha256: "a".repeat(64),
            arguments: evox2_scratch_build_expected_arguments(3),
            working_directory: EVOX2_SCRATCH_BUILD_WORKSPACE_ROOT.to_owned(),
            cargo_environment: fixed_evox2_scratch_build_environment(),
            process_environment: environment(),
            maximum_stdout_bytes: EVOX2_SCRATCH_BUILD_PROCESS_MAXIMUM_STREAM_BYTES,
            maximum_stderr_bytes: EVOX2_SCRATCH_BUILD_PROCESS_MAXIMUM_STREAM_BYTES,
            timeout_millis: EVOX2_SCRATCH_BUILD_PROCESS_TIMEOUT_MILLIS,
            maximum_active_processes: EVOX2_SCRATCH_BUILD_PROCESS_MAXIMUM_ACTIVE_PROCESSES,
            maximum_total_processes: EVOX2_SCRATCH_BUILD_PROCESS_MAXIMUM_TOTAL_PROCESSES,
        }
    }

    #[test]
    fn exact_fixed_cargo_process_spec_is_admitted() {
        spec().validate().unwrap();
        let mut executor = spec();
        executor.ordinal = 1;
        executor.executable = EVOX2_SCRATCH_BUILD_EXECUTOR_PATH.to_owned();
        executor.arguments = evox2_scratch_build_expected_arguments(1);
        executor.working_directory = EVOX2_SCRATCH_BUILD_SERVICE_ROOT.to_owned();
        executor.validate().unwrap();
        let mut probe = spec();
        probe.ordinal = 0;
        probe.arguments = evox2_scratch_build_toolchain_probe_arguments();
        probe.validate().unwrap();
    }

    #[test]
    fn operation_resource_environment_and_override_drift_refuse() {
        let mut changed = spec();
        changed.ordinal = 7;
        assert!(changed.validate().is_err());
        let mut changed = spec();
        changed.maximum_stdout_bytes -= 1;
        assert!(changed.validate().is_err());
        let mut changed = spec();
        changed
            .process_environment
            .push(("RUSTFLAGS".to_owned(), "-C overflow-checks=off".to_owned()));
        changed
            .process_environment
            .sort_by_key(|(name, _)| name.to_ascii_uppercase());
        assert!(changed.validate().is_err());
        let mut changed = spec();
        changed.process_environment.swap(0, 1);
        assert!(changed.validate().is_err());
    }
}
