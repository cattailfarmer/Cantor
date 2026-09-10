use std::fs::{self, OpenOptions};
use std::io::Read;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use cantor_core::{
    EVOX2_SCRATCH_BUILD_EXECUTOR_PATH, EVOX2_SCRATCH_BUILD_MAX_MACHINE_BYTES,
    EVOX2_SCRATCH_BUILD_SERVICE_ROOT, EVOX2_SCRATCH_BUILD_TARGET_ROOT,
    EVOX2_SCRATCH_BUILD_WORKSPACE_ROOT, Evox2ScratchBuildOperationRecord,
    evox2_scratch_build_expected_arguments, from_evox2_scratch_build_commission_machine_form,
    from_evox2_scratch_build_unsealed_receipt_candidate_machine_form,
    materialize_evox2_scratch_build_source_archive,
    seal_evox2_scratch_build_receipt_candidate_machine_form,
    verify_evox2_scratch_build_source_archive,
};
use sha2::{Digest, Sha256};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    match arguments.as_slice() {
        [operation, flag] if operation == "verify" && flag == "--sha256" => verify_archive(),
        [operation, flag] if operation == "materialize" && flag == "--absent-root" => {
            materialize_workspace()
        }
        [operation, flag, value]
            if operation == "seal" && flag == "--effect-account" && value == "exact" =>
        {
            seal_receipt()
        }
        [operation, flag] if operation == "seal-candidate" && flag == "--stdin" => {
            seal_candidate_from_stdin()
        }
        _ => Err("usage: cantor-evox2-scratch-build-executor (verify --sha256 | materialize --absent-root | seal --effect-account exact | seal-candidate --stdin)".to_owned()),
    }
}

fn seal_candidate_from_stdin() -> Result<(), String> {
    require_current_directory(EVOX2_SCRATCH_BUILD_SERVICE_ROOT)?;
    let service = PathBuf::from(EVOX2_SCRATCH_BUILD_SERVICE_ROOT.replace('/', "\\"));
    let commission_raw = read_bounded(&service.join("commission.json"), "commission")?;
    let commission = from_evox2_scratch_build_commission_machine_form(&commission_raw)
        .map_err(|error| error.to_string())?;
    let mut bytes = Vec::new();
    std::io::stdin()
        .take((EVOX2_SCRATCH_BUILD_MAX_MACHINE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "receipt candidate stdin read failed".to_owned())?;
    if bytes.is_empty() || bytes.len() > EVOX2_SCRATCH_BUILD_MAX_MACHINE_BYTES {
        return Err("receipt candidate stdin boundary refused".to_owned());
    }
    let candidate =
        String::from_utf8(bytes).map_err(|_| "receipt candidate stdin UTF-8 refused".to_owned())?;
    let receipt = seal_evox2_scratch_build_receipt_candidate_machine_form(&commission, &candidate)
        .map_err(|error| error.to_string())?;
    println!("{receipt}");
    Ok(())
}

fn verify_archive() -> Result<(), String> {
    require_current_directory(EVOX2_SCRATCH_BUILD_SERVICE_ROOT)?;
    let verification = verify_evox2_scratch_build_source_archive(Path::new("source.tar"))?;
    println!(
        "{}",
        serde_json::to_string(&verification)
            .map_err(|_| "archive verification serialization failed".to_owned())?
    );
    Ok(())
}

fn materialize_workspace() -> Result<(), String> {
    require_current_directory("C:/AI/workspaces")?;
    let workspace = PathBuf::from(EVOX2_SCRATCH_BUILD_WORKSPACE_ROOT.replace('/', "\\"));
    let stage_name = format!(
        ".cantor-build-4fdd29cb-stage-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "stage time unavailable".to_owned())?
            .as_nanos()
    );
    let stage = workspace
        .parent()
        .ok_or_else(|| "workspace parent unavailable".to_owned())?
        .join(stage_name);
    let archive =
        PathBuf::from(EVOX2_SCRATCH_BUILD_SERVICE_ROOT.replace('/', "\\")).join("source.tar");
    let verification =
        materialize_evox2_scratch_build_source_archive(&archive, &stage, &workspace)?;
    println!(
        "{}",
        serde_json::to_string(&verification)
            .map_err(|_| "materialization serialization failed".to_owned())?
    );
    Ok(())
}

fn seal_receipt() -> Result<(), String> {
    require_current_directory(EVOX2_SCRATCH_BUILD_TARGET_ROOT)?;
    let started = Instant::now();
    let started_at = unix_millis()?;
    let service = PathBuf::from(EVOX2_SCRATCH_BUILD_SERVICE_ROOT.replace('/', "\\"));
    let commission_raw = read_bounded(&service.join("commission.json"), "commission")?;
    let commission = from_evox2_scratch_build_commission_machine_form(&commission_raw)
        .map_err(|error| error.to_string())?;
    let candidate = read_bounded(Path::new("receipt_candidate.json"), "receipt candidate")?;
    let mut candidate =
        from_evox2_scratch_build_unsealed_receipt_candidate_machine_form(&candidate)
            .map_err(|error| error.to_string())?;
    if candidate.operation_records.len() != 6
        || candidate.disposition != "succeeded"
        || !candidate.physical_build_performed
    {
        return Err("successful six-operation receipt candidate required".to_owned());
    }
    let executable =
        std::env::current_exe().map_err(|_| "executor identity unavailable".to_owned())?;
    let executable_sha256 = file_sha256(&executable)?;
    let empty_sha256 = sha256_hex(&[]);
    let baseline_target_bytes = directory_bytes(Path::new("."))?;
    let ended_at = unix_millis()?;
    let duration_ms = started.elapsed().as_millis() as u64;
    candidate
        .operation_records
        .push(Evox2ScratchBuildOperationRecord {
            ordinal: 7,
            kind: "seal_build_receipt".to_owned(),
            admitted: true,
            started_at,
            ended_at,
            duration_ms,
            executable_path: EVOX2_SCRATCH_BUILD_EXECUTOR_PATH.to_owned(),
            executable_sha256,
            arguments: evox2_scratch_build_expected_arguments(7),
            working_directory: EVOX2_SCRATCH_BUILD_TARGET_ROOT.to_owned(),
            environment: commission.cargo_environment.clone(),
            exit_code: 0,
            stdout_bytes: 0,
            stdout_sha256: empty_sha256.clone(),
            stdout_truncated: false,
            stderr_bytes: 0,
            stderr_sha256: empty_sha256,
            stderr_truncated: false,
            target_bytes_after: baseline_target_bytes,
            evidence_sha256: String::new(),
        });
    let mut receipt = String::new();
    for _ in 0..4 {
        let candidate_raw = serde_json::to_string(&candidate)
            .map_err(|_| "receipt candidate serialization failed".to_owned())?;
        receipt =
            seal_evox2_scratch_build_receipt_candidate_machine_form(&commission, &candidate_raw)
                .map_err(|error| error.to_string())?;
        let expected = baseline_target_bytes
            .checked_add(receipt.len() as u64)
            .ok_or_else(|| "target byte account overflow".to_owned())?;
        if candidate.operation_records[6].target_bytes_after == expected {
            break;
        }
        candidate.operation_records[6].target_bytes_after = expected;
    }
    let expected = candidate.operation_records[6].target_bytes_after;
    if expected != baseline_target_bytes + receipt.len() as u64 {
        return Err("receipt target-byte fixed point failed".to_owned());
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open("receipt.json")
        .map_err(|error| format!("receipt creation failed: {error}"))?;
    output
        .write_all(receipt.as_bytes())
        .and_then(|_| output.flush())
        .map_err(|error| format!("receipt write failed: {error}"))?;
    if directory_bytes(Path::new("."))? != expected {
        return Err("sealed target byte account differs".to_owned());
    }
    Ok(())
}

fn require_current_directory(expected: &str) -> Result<(), String> {
    let current =
        std::env::current_dir().map_err(|_| "current directory unavailable".to_owned())?;
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

fn read_bounded(path: &Path, name: &str) -> Result<String, String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| format!("{name} unavailable"))?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > EVOX2_SCRATCH_BUILD_MAX_MACHINE_BYTES as u64
    {
        return Err(format!("{name} file boundary refused"));
    }
    let file = fs::File::open(path).map_err(|_| format!("{name} read failed"))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take((EVOX2_SCRATCH_BUILD_MAX_MACHINE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| format!("{name} read failed"))?;
    if bytes.len() as u64 != metadata.len() {
        return Err(format!("{name} stability refused"));
    }
    String::from_utf8(bytes).map_err(|_| format!("{name} UTF-8 refused"))
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
        fs::symlink_metadata(path).map_err(|_| "file identity unavailable".to_owned())?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("file identity boundary refused".to_owned());
    }
    let mut file = fs::File::open(path).map_err(|_| "file identity read failed".to_owned())?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 65_536];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| "file identity read failed".to_owned())?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
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
