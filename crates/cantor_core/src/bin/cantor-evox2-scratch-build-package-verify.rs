use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use cantor_core::{
    EVOX2_SCRATCH_BUILD_MAX_MACHINE_BYTES, Evox2BuildPlanVerification,
    from_evox2_build_plan_machine_form, from_evox2_build_plan_request_machine_form,
    from_evox2_scratch_build_command_set_machine_form,
    from_evox2_scratch_build_commission_machine_form,
    from_evox2_scratch_build_deployment_envelope_machine_form,
    from_evox2_scratch_build_implementation_manifest_machine_form,
    to_evox2_build_plan_verification_machine_form,
    to_evox2_scratch_build_package_verification_machine_form, verify_evox2_build_plan,
    verify_evox2_scratch_build_package_correspondence,
};
use sha2::{Digest, Sha256};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let arguments = std::env::args().collect::<Vec<_>>();
    if arguments.len() != 5
        || arguments[1] != "implementation_manifest.json"
        || arguments[2] != "command_set.json"
        || arguments[3] != "commission.json"
        || arguments[4] != "deployment_envelope.json"
    {
        return Err("usage: cantor-evox2-scratch-build-package-verify implementation_manifest.json command_set.json commission.json deployment_envelope.json".to_owned());
    }
    let root = std::env::current_dir().map_err(|_| "package root unavailable".to_owned())?;
    refuse_link(&root, true)?;
    let manifest_raw = read_bounded(&root.join("implementation_manifest.json"), "manifest")?;
    let command_set_raw = read_bounded(&root.join("command_set.json"), "command set")?;
    let commission_raw = read_bounded(&root.join("commission.json"), "commission")?;
    let envelope_raw = read_bounded(&root.join("deployment_envelope.json"), "envelope")?;
    let manifest = from_evox2_scratch_build_implementation_manifest_machine_form(&manifest_raw)
        .map_err(|error| error.to_string())?;
    let command_set = from_evox2_scratch_build_command_set_machine_form(&command_set_raw)
        .map_err(|error| error.to_string())?;
    let commission = from_evox2_scratch_build_commission_machine_form(&commission_raw)
        .map_err(|error| error.to_string())?;
    let envelope = from_evox2_scratch_build_deployment_envelope_machine_form(&envelope_raw)
        .map_err(|error| error.to_string())?;

    let mut expected = BTreeSet::new();
    let mut artifact_aggregate = 0_u64;
    for artifact in &manifest.artifacts {
        let relative = PathBuf::from(artifact.relative_path.replace('/', "\\"));
        let path = root.join(relative);
        let bytes = read_exact_artifact(&path, artifact.bytes)?;
        if sha256_hex(&bytes) != artifact.sha256 {
            return Err(format!(
                "artifact digest differs: {}",
                artifact.relative_path
            ));
        }
        artifact_aggregate = artifact_aggregate
            .checked_add(artifact.bytes)
            .ok_or_else(|| "artifact aggregate overflow".to_owned())?;
        expected.insert(artifact.relative_path.to_ascii_lowercase());
    }
    if artifact_aggregate != manifest.aggregate_bytes {
        return Err("artifact aggregate differs".to_owned());
    }
    expected.insert("implementation_manifest.json".to_owned());
    expected.insert("commission.json".to_owned());
    expected.insert("deployment_envelope.json".to_owned());

    let mut actual = Vec::new();
    collect_files(&root, &root, &mut actual)?;
    if actual.len() != expected.len() {
        return Err("package file cardinality differs".to_owned());
    }
    let mut package_aggregate = 0_u64;
    let mut seen = BTreeSet::new();
    for (relative, bytes) in actual {
        if !expected.contains(&relative) || !seen.insert(relative) {
            return Err("package membership differs".to_owned());
        }
        package_aggregate = package_aggregate
            .checked_add(bytes)
            .ok_or_else(|| "package aggregate overflow".to_owned())?;
    }
    if package_aggregate != envelope.package_aggregate_bytes {
        return Err("package aggregate differs".to_owned());
    }
    let request_raw = read_bounded(&root.join("request.json"), "request")?;
    let plan_raw = read_bounded(&root.join("plan.json"), "plan")?;
    let plan_verification_raw =
        read_bounded(&root.join("plan_verification.json"), "plan verification")?;
    let request = from_evox2_build_plan_request_machine_form(&request_raw)
        .map_err(|error| error.to_string())?;
    let plan = from_evox2_build_plan_machine_form(&plan_raw).map_err(|error| error.to_string())?;
    let recomputed = verify_evox2_build_plan(&request, &plan).map_err(|error| error.to_string())?;
    let provided: Evox2BuildPlanVerification = serde_json::from_str(&plan_verification_raw)
        .map_err(|_| "plan verification machine form refused".to_owned())?;
    let provided_raw = to_evox2_build_plan_verification_machine_form(&provided)
        .map_err(|error| error.to_string())?;
    let recomputed_raw = to_evox2_build_plan_verification_machine_form(&recomputed)
        .map_err(|error| error.to_string())?;
    if provided_raw != plan_verification_raw
        || provided_raw != recomputed_raw
        || request.request_sha256 != commission.request_sha256
        || plan.plan_sha256 != commission.plan_sha256
        || request.source_archive_sha256 != commission.source_archive_sha256
        || plan.source_archive_sha256 != commission.source_archive_sha256
    {
        return Err("predecessor plan correspondence differs".to_owned());
    }
    let verification = verify_evox2_scratch_build_package_correspondence(
        &manifest,
        &command_set,
        &commission,
        &envelope,
    )
    .map_err(|error| error.to_string())?;
    let output = to_evox2_scratch_build_package_verification_machine_form(&verification)
        .map_err(|error| error.to_string())?;
    println!("{output}");
    Ok(())
}

fn collect_files(
    root: &Path,
    directory: &Path,
    files: &mut Vec<(String, u64)>,
) -> Result<(), String> {
    refuse_link(directory, true)?;
    for entry in fs::read_dir(directory).map_err(|_| "package enumeration failed".to_owned())? {
        let entry = entry.map_err(|_| "package enumeration failed".to_owned())?;
        let path = entry.path();
        let metadata =
            fs::symlink_metadata(&path).map_err(|_| "package member metadata failed".to_owned())?;
        if metadata.file_type().is_symlink() {
            return Err("package link refused".to_owned());
        }
        if metadata.is_dir() {
            collect_files(root, &path, files)?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| "package coordinate refused".to_owned())?
                .to_string_lossy()
                .replace('\\', "/")
                .to_ascii_lowercase();
            files.push((relative, metadata.len()));
        } else {
            return Err("package special member refused".to_owned());
        }
    }
    Ok(())
}

fn refuse_link(path: &Path, directory: bool) -> Result<(), String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| "package boundary unavailable".to_owned())?;
    if metadata.file_type().is_symlink()
        || (directory && !metadata.is_dir())
        || (!directory && !metadata.is_file())
    {
        return Err("package boundary refused".to_owned());
    }
    Ok(())
}

fn read_exact_artifact(path: &Path, expected: u64) -> Result<Vec<u8>, String> {
    refuse_link(path, false)?;
    let metadata = fs::metadata(path).map_err(|_| "artifact unavailable".to_owned())?;
    if metadata.len() != expected || expected == 0 || expected > 536_870_912 {
        return Err("artifact byte boundary refused".to_owned());
    }
    let file = fs::File::open(path).map_err(|_| "artifact read failed".to_owned())?;
    let mut bytes = Vec::with_capacity(expected as usize);
    file.take(expected + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "artifact read failed".to_owned())?;
    if bytes.len() as u64 != expected {
        return Err("artifact stability refused".to_owned());
    }
    Ok(bytes)
}

fn read_bounded(path: &Path, name: &str) -> Result<String, String> {
    let bytes = read_exact_artifact(
        path,
        fs::symlink_metadata(path)
            .map_err(|_| format!("{name} unavailable"))?
            .len(),
    )?;
    if bytes.len() > EVOX2_SCRATCH_BUILD_MAX_MACHINE_BYTES {
        return Err(format!("{name} file boundary refused"));
    }
    String::from_utf8(bytes).map_err(|_| format!("{name} UTF-8 refused"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
