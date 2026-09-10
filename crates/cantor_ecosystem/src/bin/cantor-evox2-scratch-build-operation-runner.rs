#![cfg_attr(not(windows), allow(dead_code, unused_imports))]

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use cantor_core::{
    EVOX2_SCRATCH_BUILD_SERVICE_ROOT, EVOX2_SCRATCH_BUILD_TARGET_ROOT,
    EVOX2_SCRATCH_BUILD_WORKSPACE_ROOT, Evox2ScratchBuildCargoEnvironment,
    Evox2ScratchBuildOperationRecord, evox2_scratch_build_expected_arguments,
    fixed_evox2_scratch_build_bounds, fixed_evox2_scratch_build_environment,
};
use cantor_ecosystem::{
    EVOX2_SCRATCH_BUILD_CONTAINED_PROCESS_PROFILE,
    EVOX2_SCRATCH_BUILD_PROCESS_MAXIMUM_ACTIVE_PROCESSES,
    EVOX2_SCRATCH_BUILD_PROCESS_MAXIMUM_STREAM_BYTES,
    EVOX2_SCRATCH_BUILD_PROCESS_MAXIMUM_TOTAL_PROCESSES,
    EVOX2_SCRATCH_BUILD_PROCESS_TIMEOUT_MILLIS, Evox2ScratchBuildContainedProcessSpec,
    evox2_scratch_build_toolchain_probe_arguments, run_evox2_scratch_build_contained_process,
};
use sha2::{Digest, Sha256};

const PLATFORM_ENVIRONMENT_NAMES: [&str; 32] = [
    "ALLUSERSPROFILE",
    "APPDATA",
    "CARGO_HOME",
    "COMMONPROGRAMFILES",
    "COMMONPROGRAMFILES(X86)",
    "COMMONPROGRAMW6432",
    "COMSPEC",
    "DRIVERDATA",
    "HOMEDRIVE",
    "HOMEPATH",
    "INCLUDE",
    "LIB",
    "LIBPATH",
    "LOCALAPPDATA",
    "NUMBER_OF_PROCESSORS",
    "OS",
    "PATH",
    "PATHEXT",
    "PROCESSOR_ARCHITECTURE",
    "PROCESSOR_IDENTIFIER",
    "PROCESSOR_LEVEL",
    "PROCESSOR_REVISION",
    "PROGRAMDATA",
    "PROGRAMFILES",
    "PROGRAMFILES(X86)",
    "PROGRAMW6432",
    "RUSTUP_HOME",
    "SYSTEMDRIVE",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "WINDIR",
];

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

#[cfg(not(windows))]
fn run() -> Result<(), String> {
    Err("contained Cargo execution is available only on Windows".to_owned())
}

#[cfg(windows)]
fn run() -> Result<(), String> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if let [
        operation,
        path_flag,
        executable_path,
        sha_flag,
        executable_sha256,
    ] = arguments.as_slice()
        && operation == "probe"
        && path_flag == "--executable-path"
        && sha_flag == "--executable-sha256"
    {
        return run_toolchain_probe(executable_path, executable_sha256);
    }
    let [
        operation,
        ordinal_flag,
        ordinal_raw,
        path_flag,
        executable_path,
        sha_flag,
        executable_sha256,
    ] = arguments.as_slice()
    else {
        return Err(usage());
    };
    if operation != "run"
        || ordinal_flag != "--ordinal"
        || path_flag != "--executable-path"
        || sha_flag != "--executable-sha256"
    {
        return Err(usage());
    }
    let ordinal = ordinal_raw
        .parse::<u32>()
        .map_err(|_| "scratch-build operation ordinal refused".to_owned())?;
    if !(1..=7).contains(&ordinal) {
        return Err("scratch-build operation ordinal refused".to_owned());
    }

    let working_directory = match ordinal {
        1 => EVOX2_SCRATCH_BUILD_SERVICE_ROOT,
        2 => "C:/AI/workspaces",
        7 => EVOX2_SCRATCH_BUILD_TARGET_ROOT,
        _ => EVOX2_SCRATCH_BUILD_WORKSPACE_ROOT,
    };
    require_current_directory(working_directory)?;
    let executable = PathBuf::from(executable_path);
    let before_sha256 = file_sha256(&executable)?;
    if before_sha256 != executable_sha256.as_str() {
        return Err("operation executable digest differs before execution".to_owned());
    }

    let cargo_environment = fixed_evox2_scratch_build_environment();
    let process_environment = build_process_environment(&cargo_environment)?;
    let spec = Evox2ScratchBuildContainedProcessSpec {
        profile: EVOX2_SCRATCH_BUILD_CONTAINED_PROCESS_PROFILE.to_owned(),
        ordinal,
        executable: executable_path.clone(),
        executable_sha256: executable_sha256.clone(),
        arguments: evox2_scratch_build_expected_arguments(ordinal),
        working_directory: working_directory.to_owned(),
        cargo_environment: cargo_environment.clone(),
        process_environment,
        maximum_stdout_bytes: EVOX2_SCRATCH_BUILD_PROCESS_MAXIMUM_STREAM_BYTES,
        maximum_stderr_bytes: EVOX2_SCRATCH_BUILD_PROCESS_MAXIMUM_STREAM_BYTES,
        timeout_millis: EVOX2_SCRATCH_BUILD_PROCESS_TIMEOUT_MILLIS,
        maximum_active_processes: EVOX2_SCRATCH_BUILD_PROCESS_MAXIMUM_ACTIVE_PROCESSES,
        maximum_total_processes: EVOX2_SCRATCH_BUILD_PROCESS_MAXIMUM_TOTAL_PROCESSES,
    };

    let started_at = unix_millis()?;
    let started = Instant::now();
    let observation = run_evox2_scratch_build_contained_process(&spec)?;
    let duration_ms = u64::try_from(started.elapsed().as_millis())
        .map_err(|_| "Cargo operation duration overflow".to_owned())?;
    let ended_at = unix_millis()?;
    if duration_ms > u64::from(fixed_evox2_scratch_build_bounds().maximum_process_seconds) * 1_000 {
        return Err("Cargo operation exceeded commissioned duration bound".to_owned());
    }
    if observation.active_processes_at_terminal != 0 || observation.resume_previous_count != 1 {
        return Err("contained Cargo process closure differs".to_owned());
    }
    if file_sha256(&executable)? != before_sha256 {
        return Err("operation executable digest differs after execution".to_owned());
    }
    if ordinal == 7 {
        return report_seal_process(observation, duration_ms, executable_path, executable_sha256);
    }

    let output_root = target_path();
    ensure_output_root(&output_root)?;
    let captures = output_root.join("captures");
    ensure_directory(&captures)?;
    let stdout_path = captures.join(format!("operation-{ordinal}.stdout.bin"));
    let stderr_path = captures.join(format!("operation-{ordinal}.stderr.bin"));
    write_new(&stdout_path, &observation.stdout)?;
    write_new(&stderr_path, &observation.stderr)?;

    let output_failure = observation.stdout_over_bound || observation.stderr_over_bound;
    let exit_code = if observation.forced_termination && observation.exit_code == 0 {
        124
    } else {
        observation.exit_code as i32
    };
    let mut record = Evox2ScratchBuildOperationRecord {
        ordinal,
        kind: match ordinal {
            1 => "verify_source_archive",
            2 => "materialize_absent_workspace",
            3 => "workspace_debug",
            4 => "workspace_release",
            5 => "workspace_clippy",
            6 => "workspace_format",
            _ => unreachable!(),
        }
        .to_owned(),
        admitted: true,
        started_at,
        ended_at,
        duration_ms,
        executable_path: executable_path.clone(),
        executable_sha256: executable_sha256.clone(),
        arguments: evox2_scratch_build_expected_arguments(ordinal),
        working_directory: working_directory.to_owned(),
        environment: cargo_environment,
        exit_code,
        stdout_bytes: u32::try_from(observation.stdout.len())
            .map_err(|_| "retained stdout byte count overflow".to_owned())?,
        stdout_sha256: sha256_hex(&observation.stdout),
        stdout_truncated: observation.stdout_over_bound,
        stderr_bytes: u32::try_from(observation.stderr.len())
            .map_err(|_| "retained stderr byte count overflow".to_owned())?,
        stderr_sha256: sha256_hex(&observation.stderr),
        stderr_truncated: observation.stderr_over_bound,
        target_bytes_after: 0,
        evidence_sha256: String::new(),
    };
    if observation.stdout_observed_bytes < u64::from(record.stdout_bytes)
        || observation.stderr_observed_bytes < u64::from(record.stderr_bytes)
        || (observation.stdout_observed_bytes > u64::from(record.stdout_bytes)
            && !record.stdout_truncated)
        || (observation.stderr_observed_bytes > u64::from(record.stderr_bytes)
            && !record.stderr_truncated)
        || (observation.forced_termination && exit_code == 0 && !output_failure)
    {
        return Err("contained Cargo observation correspondence differs".to_owned());
    }

    let record_path = output_root.join(format!("operation-{ordinal}.json"));
    let baseline = directory_bytes(&output_root)?;
    let maximum_target = fixed_evox2_scratch_build_bounds().maximum_target_bytes;
    let mut machine = String::new();
    for _ in 0..4 {
        machine = serde_json::to_string(&record)
            .map_err(|_| "Cargo operation record serialization failed".to_owned())?;
        let expected = baseline
            .checked_add(machine.len() as u64)
            .ok_or_else(|| "target byte account overflow".to_owned())?;
        if expected > maximum_target {
            return Err("target byte account exceeds commissioned bound".to_owned());
        }
        if record.target_bytes_after == expected {
            break;
        }
        record.target_bytes_after = expected;
    }
    if record.target_bytes_after != baseline + machine.len() as u64 {
        return Err("Cargo operation target-byte fixed point failed".to_owned());
    }
    write_new(&record_path, machine.as_bytes())?;
    if directory_bytes(&output_root)? != record.target_bytes_after {
        return Err("Cargo operation target byte account differs".to_owned());
    }
    println!("{machine}");
    Ok(())
}

#[cfg(windows)]
fn run_toolchain_probe(executable_path: &str, executable_sha256: &str) -> Result<(), String> {
    require_current_directory(EVOX2_SCRATCH_BUILD_WORKSPACE_ROOT)?;
    let executable = PathBuf::from(executable_path);
    let before_sha256 = file_sha256(&executable)?;
    if before_sha256 != executable_sha256 {
        return Err("probe executable digest differs before execution".to_owned());
    }
    let cargo_environment = fixed_evox2_scratch_build_environment();
    let spec = Evox2ScratchBuildContainedProcessSpec {
        profile: EVOX2_SCRATCH_BUILD_CONTAINED_PROCESS_PROFILE.to_owned(),
        ordinal: 0,
        executable: executable_path.to_owned(),
        executable_sha256: executable_sha256.to_owned(),
        arguments: evox2_scratch_build_toolchain_probe_arguments(),
        working_directory: EVOX2_SCRATCH_BUILD_WORKSPACE_ROOT.to_owned(),
        cargo_environment: cargo_environment.clone(),
        process_environment: build_process_environment(&cargo_environment)?,
        maximum_stdout_bytes: EVOX2_SCRATCH_BUILD_PROCESS_MAXIMUM_STREAM_BYTES,
        maximum_stderr_bytes: EVOX2_SCRATCH_BUILD_PROCESS_MAXIMUM_STREAM_BYTES,
        timeout_millis: EVOX2_SCRATCH_BUILD_PROCESS_TIMEOUT_MILLIS,
        maximum_active_processes: EVOX2_SCRATCH_BUILD_PROCESS_MAXIMUM_ACTIVE_PROCESSES,
        maximum_total_processes: EVOX2_SCRATCH_BUILD_PROCESS_MAXIMUM_TOTAL_PROCESSES,
    };
    let started = Instant::now();
    let observation = run_evox2_scratch_build_contained_process(&spec)?;
    let duration_ms = u64::try_from(started.elapsed().as_millis())
        .map_err(|_| "toolchain probe duration overflow".to_owned())?;
    if duration_ms > u64::from(fixed_evox2_scratch_build_bounds().maximum_process_seconds) * 1_000
        || observation.exit_code != 0
        || observation.stdout_over_bound
        || observation.stderr_over_bound
        || observation.forced_termination
        || observation.active_processes_at_terminal != 0
        || observation.resume_previous_count != 1
    {
        return Err("locked-offline toolchain probe failed".to_owned());
    }
    if file_sha256(&executable)? != before_sha256 {
        return Err("probe executable digest differs after execution".to_owned());
    }
    let probe = ToolchainProbeRecord {
        profile: "cantor-evox2-scratch-build-toolchain-probe/0.1",
        status: "passed",
        executable_path,
        executable_sha256,
        arguments: spec.arguments,
        duration_ms,
        exit_code: observation.exit_code,
        stdout_bytes: observation.stdout.len() as u64,
        stdout_observed_bytes: observation.stdout_observed_bytes,
        stdout_sha256: sha256_hex(&observation.stdout),
        stderr_bytes: observation.stderr.len() as u64,
        stderr_observed_bytes: observation.stderr_observed_bytes,
        stderr_sha256: sha256_hex(&observation.stderr),
        total_processes: observation.total_processes,
        persistent_processes: observation.active_processes_at_terminal,
        effects: 0,
    };
    let machine = serde_json::to_string(&probe)
        .map_err(|_| "toolchain probe serialization failed".to_owned())?;
    let output_root = target_path();
    ensure_existing_directory(&output_root, "target root")?;
    let captures = output_root.join("captures");
    ensure_directory(&captures)?;
    write_new(
        &captures.join("toolchain-probe.stdout.bin"),
        &observation.stdout,
    )?;
    write_new(
        &captures.join("toolchain-probe.stderr.bin"),
        &observation.stderr,
    )?;
    write_new(
        &output_root.join("toolchain_probe.json"),
        machine.as_bytes(),
    )?;
    println!("{machine}");
    Ok(())
}

#[derive(serde::Serialize)]
struct ToolchainProbeRecord<'a> {
    profile: &'static str,
    status: &'static str,
    executable_path: &'a str,
    executable_sha256: &'a str,
    arguments: Vec<String>,
    duration_ms: u64,
    exit_code: u32,
    stdout_bytes: u64,
    stdout_observed_bytes: u64,
    stdout_sha256: String,
    stderr_bytes: u64,
    stderr_observed_bytes: u64,
    stderr_sha256: String,
    total_processes: u32,
    persistent_processes: u32,
    effects: u32,
}

fn usage() -> String {
    "usage: cantor-evox2-scratch-build-operation-runner (probe | run --ordinal <1..7>) --executable-path <absolute-C-path> --executable-sha256 <lower-hex>".to_owned()
}

#[cfg(windows)]
fn report_seal_process(
    observation: cantor_ecosystem::Evox2ScratchBuildContainedProcessObservation,
    duration_ms: u64,
    executable_path: &str,
    executable_sha256: &str,
) -> Result<(), String> {
    if observation.exit_code != 0
        || !observation.stdout.is_empty()
        || !observation.stderr.is_empty()
        || observation.stdout_over_bound
        || observation.stderr_over_bound
        || observation.forced_termination
        || observation.active_processes_at_terminal != 0
        || observation.resume_previous_count != 1
    {
        return Err("receipt-seal process failed".to_owned());
    }
    let record = SealProcessRecord {
        profile: "cantor-evox2-scratch-build-seal-process/0.1",
        status: "passed",
        executable_path,
        executable_sha256,
        arguments: evox2_scratch_build_expected_arguments(7),
        duration_ms,
        exit_code: observation.exit_code,
        stdout_bytes: 0,
        stderr_bytes: 0,
        total_processes: observation.total_processes,
        persistent_processes: observation.active_processes_at_terminal,
        effects: 0,
    };
    println!(
        "{}",
        serde_json::to_string(&record)
            .map_err(|_| "receipt-seal process serialization failed".to_owned())?
    );
    Ok(())
}

#[derive(serde::Serialize)]
struct SealProcessRecord<'a> {
    profile: &'static str,
    status: &'static str,
    executable_path: &'a str,
    executable_sha256: &'a str,
    arguments: Vec<String>,
    duration_ms: u64,
    exit_code: u32,
    stdout_bytes: u32,
    stderr_bytes: u32,
    total_processes: u32,
    persistent_processes: u32,
    effects: u32,
}

fn build_process_environment(
    cargo: &Evox2ScratchBuildCargoEnvironment,
) -> Result<Vec<(String, String)>, String> {
    let inherited = std::env::vars().collect::<Vec<_>>();
    let mut environment = PLATFORM_ENVIRONMENT_NAMES
        .iter()
        .filter_map(|name| {
            inherited
                .iter()
                .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
                .map(|(_, value)| ((*name).to_owned(), value.clone()))
        })
        .collect::<Vec<_>>();
    for (name, value) in [
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
        environment.retain(|(candidate, _)| !candidate.eq_ignore_ascii_case(name));
        environment.push((name.to_owned(), value));
    }
    environment.sort_by_key(|(name, _)| name.to_ascii_uppercase());
    Ok(environment)
}

fn target_path() -> PathBuf {
    PathBuf::from(EVOX2_SCRATCH_BUILD_TARGET_ROOT.replace('/', "\\"))
}

fn require_current_directory(expected: &str) -> Result<(), String> {
    let current =
        std::env::current_dir().map_err(|_| "working directory unavailable".to_owned())?;
    let observed = current.to_string_lossy().replace('\\', "/");
    if !observed.eq_ignore_ascii_case(expected) {
        return Err(format!("working directory differs: expected {expected}"));
    }
    let metadata = fs::symlink_metadata(&current)
        .map_err(|_| "working directory metadata unavailable".to_owned())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("working directory boundary refused".to_owned());
    }
    Ok(())
}

fn ensure_output_root(path: &Path) -> Result<(), String> {
    if !path.exists() {
        fs::create_dir(path).map_err(|error| format!("target root creation failed: {error}"))?;
    }
    ensure_existing_directory(path, "target root")
}

fn ensure_directory(path: &Path) -> Result<(), String> {
    if !path.exists() {
        fs::create_dir(path).map_err(|error| format!("capture root creation failed: {error}"))?;
    }
    ensure_existing_directory(path, "capture root")
}

fn ensure_existing_directory(path: &Path, label: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| format!("{label} unavailable"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(format!("{label} boundary refused"));
    }
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("evidence creation failed: {error}"))?;
    output
        .write_all(bytes)
        .and_then(|_| output.flush())
        .map_err(|error| format!("evidence write failed: {error}"))
}

fn unix_millis() -> Result<String, String> {
    Ok(format!(
        "unix-ms:{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system time unavailable".to_owned())?
            .as_millis()
    ))
}

fn file_sha256(path: &Path) -> Result<String, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| "operation executable unavailable".to_owned())?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("operation executable boundary refused".to_owned());
    }
    let mut file =
        fs::File::open(path).map_err(|_| "operation executable read failed".to_owned())?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 65_536];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| "operation executable read failed".to_owned())?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(hex_digest(&digest.finalize()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_digest(&Sha256::digest(bytes))
}

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn directory_bytes(root: &Path) -> Result<u64, String> {
    let mut total = 0_u64;
    for entry in fs::read_dir(root).map_err(|_| "target enumeration failed".to_owned())? {
        let entry = entry.map_err(|_| "target enumeration failed".to_owned())?;
        let path = entry.path();
        let metadata =
            fs::symlink_metadata(&path).map_err(|_| "target member metadata failed".to_owned())?;
        if metadata.file_type().is_symlink() {
            return Err("target link refused".to_owned());
        }
        if metadata.is_dir() {
            total = total
                .checked_add(directory_bytes(&path)?)
                .ok_or_else(|| "target byte account overflow".to_owned())?;
        } else if metadata.is_file() {
            total = total
                .checked_add(metadata.len())
                .ok_or_else(|| "target byte account overflow".to_owned())?;
        } else {
            return Err("target special member refused".to_owned());
        }
    }
    Ok(total)
}
