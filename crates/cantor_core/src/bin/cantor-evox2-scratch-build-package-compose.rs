use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use cantor_core::{
    EVOX2_SCRATCH_BUILD_CANONICAL_UUID, EVOX2_SCRATCH_BUILD_LOCAL_CORE_BOOKEND_COMMIT,
    EVOX2_SCRATCH_BUILD_MAX_MACHINE_BYTES, EVOX2_SCRATCH_BUILD_SOURCE_ARCHIVE_SHA256,
    EVOX2_SCRATCH_BUILD_SOURCE_COMMIT, EVOX2_SCRATCH_BUILD_TARGET_HOST,
    EVOX2_SCRATCH_BUILD_TARGET_ROOT, EVOX2_SCRATCH_BUILD_WORKSPACE_ROOT,
    Evox2ScratchBuildDeploymentEnvelope, Evox2ScratchBuildImplementationManifest,
    Evox2ScratchBuildPackageArtifact, evox2_scratch_build_package_artifacts,
    evox2_scratch_build_package_executions, from_evox2_scratch_build_command_set_machine_form,
    from_evox2_scratch_build_commission_machine_form,
    from_evox2_scratch_build_implementation_manifest_machine_form,
    seal_evox2_scratch_build_deployment_envelope, seal_evox2_scratch_build_implementation_manifest,
    to_evox2_scratch_build_deployment_envelope_machine_form,
    to_evox2_scratch_build_implementation_manifest_machine_form,
    verify_evox2_scratch_build_package_correspondence,
};
use sha2::{Digest, Sha256};

const IMPLEMENTATION_MANIFEST_UUID: &str = "0c749e63-bb2a-4e48-9cb4-f17ba4344464";
const DEPLOYMENT_ENVELOPE_UUID: &str = "c7d3ab75-974b-4c9b-9792-46037d066d71";
const MAX_PACKAGE_BYTES: u64 = 536_870_912;

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    match arguments.as_slice() {
        [mode, flag, implementation_commit]
            if mode == "manifest" && flag == "--implementation-commit" =>
        {
            compose_manifest(implementation_commit)
        }
        [mode, manifest, command_set, commission]
            if mode == "envelope"
                && manifest == "implementation_manifest.json"
                && command_set == "command_set.json"
                && commission == "commission.json" =>
        {
            compose_envelope()
        }
        _ => Err("usage: cantor-evox2-scratch-build-package-compose (manifest --implementation-commit <lower-hex-commit> | envelope implementation_manifest.json command_set.json commission.json)".to_owned()),
    }
}

fn compose_manifest(implementation_commit: &str) -> Result<(), String> {
    if !is_lower_hex(implementation_commit, 40) {
        return Err("implementation commit form refused".to_owned());
    }
    let root = package_root()?;
    let mut aggregate_bytes = 0_u64;
    let mut artifacts = Vec::new();
    for (relative_path, role) in evox2_scratch_build_package_artifacts() {
        let path = checked_member_path(&root, &relative_path)?;
        let bytes = read_regular_file(&path, MAX_PACKAGE_BYTES)?;
        aggregate_bytes = aggregate_bytes
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| "implementation aggregate overflow".to_owned())?;
        if aggregate_bytes > MAX_PACKAGE_BYTES {
            return Err("implementation aggregate exceeds bound".to_owned());
        }
        artifacts.push(Evox2ScratchBuildPackageArtifact {
            relative_path,
            role,
            bytes: bytes.len() as u64,
            sha256: sha256_hex(&bytes),
        });
    }
    let manifest =
        seal_evox2_scratch_build_implementation_manifest(Evox2ScratchBuildImplementationManifest {
            profile: "cantor-evox2-scratch-build-implementation-manifest/0.1".to_owned(),
            manifest_uuid: IMPLEMENTATION_MANIFEST_UUID.to_owned(),
            canonical_uuid: EVOX2_SCRATCH_BUILD_CANONICAL_UUID.to_owned(),
            local_core_bookend_commit: EVOX2_SCRATCH_BUILD_LOCAL_CORE_BOOKEND_COMMIT.to_owned(),
            implementation_commit: implementation_commit.to_owned(),
            source_commit: EVOX2_SCRATCH_BUILD_SOURCE_COMMIT.to_owned(),
            source_archive_sha256: EVOX2_SCRATCH_BUILD_SOURCE_ARCHIVE_SHA256.to_owned(),
            target_host: EVOX2_SCRATCH_BUILD_TARGET_HOST.to_owned(),
            workspace_root: EVOX2_SCRATCH_BUILD_WORKSPACE_ROOT.to_owned(),
            target_root: EVOX2_SCRATCH_BUILD_TARGET_ROOT.to_owned(),
            artifact_count: artifacts.len() as u32,
            aggregate_bytes,
            artifacts,
            allowed_executions: evox2_scratch_build_package_executions(),
            authority_grants: Vec::new(),
            effects: 0,
            manifest_sha256: String::new(),
        })
        .map_err(|error| error.to_string())?;
    println!(
        "{}",
        to_evox2_scratch_build_implementation_manifest_machine_form(&manifest)
            .map_err(|error| error.to_string())?
    );
    Ok(())
}

fn compose_envelope() -> Result<(), String> {
    let root = package_root()?;
    let manifest_raw = read_machine_form(&root.join("implementation_manifest.json"))?;
    let command_set_raw = read_machine_form(&root.join("command_set.json"))?;
    let commission_raw = read_machine_form(&root.join("commission.json"))?;
    let manifest = from_evox2_scratch_build_implementation_manifest_machine_form(&manifest_raw)
        .map_err(|error| error.to_string())?;
    let command_set = from_evox2_scratch_build_command_set_machine_form(&command_set_raw)
        .map_err(|error| error.to_string())?;
    let commission = from_evox2_scratch_build_commission_machine_form(&commission_raw)
        .map_err(|error| error.to_string())?;
    let fixed_bytes = manifest
        .aggregate_bytes
        .checked_add(manifest_raw.len() as u64)
        .and_then(|value| value.checked_add(commission_raw.len() as u64))
        .ok_or_else(|| "package aggregate overflow".to_owned())?;
    let mut package_aggregate_bytes = fixed_bytes;
    for _ in 0..8 {
        let envelope =
            seal_evox2_scratch_build_deployment_envelope(Evox2ScratchBuildDeploymentEnvelope {
                profile: "cantor-evox2-scratch-build-deployment-envelope/0.1".to_owned(),
                envelope_uuid: DEPLOYMENT_ENVELOPE_UUID.to_owned(),
                canonical_uuid: EVOX2_SCRATCH_BUILD_CANONICAL_UUID.to_owned(),
                implementation_manifest_sha256: manifest.manifest_sha256.clone(),
                commission_uuid: commission.commission_uuid.clone(),
                commission_sha256: commission.commission_sha256.clone(),
                command_set_sha256: command_set.command_set_sha256.clone(),
                package_file_count: manifest.artifact_count + 3,
                package_aggregate_bytes,
                disposition: "sealed_for_single_commission".to_owned(),
                envelope_sha256: String::new(),
            })
            .map_err(|error| error.to_string())?;
        let raw = to_evox2_scratch_build_deployment_envelope_machine_form(&envelope)
            .map_err(|error| error.to_string())?;
        let actual = fixed_bytes
            .checked_add(raw.len() as u64)
            .ok_or_else(|| "package aggregate overflow".to_owned())?;
        if actual > MAX_PACKAGE_BYTES {
            return Err("package aggregate exceeds bound".to_owned());
        }
        if actual == package_aggregate_bytes {
            verify_evox2_scratch_build_package_correspondence(
                &manifest,
                &command_set,
                &commission,
                &envelope,
            )
            .map_err(|error| error.to_string())?;
            println!("{raw}");
            return Ok(());
        }
        package_aggregate_bytes = actual;
    }
    Err("deployment envelope byte fixed point refused".to_owned())
}

fn package_root() -> Result<PathBuf, String> {
    let root = std::env::current_dir().map_err(|_| "package root unavailable".to_owned())?;
    let metadata =
        fs::symlink_metadata(&root).map_err(|_| "package root metadata unavailable".to_owned())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("package root boundary refused".to_owned());
    }
    Ok(root)
}

fn checked_member_path(root: &Path, relative: &str) -> Result<PathBuf, String> {
    let relative_path = Path::new(relative);
    if relative_path.is_absolute()
        || relative_path.components().any(|component| {
            !matches!(component, Component::Normal(_))
                || component
                    .as_os_str()
                    .to_string_lossy()
                    .contains([':', '\\'])
        })
    {
        return Err("package member coordinate refused".to_owned());
    }
    let mut path = root.to_path_buf();
    let components = relative_path.components().collect::<Vec<_>>();
    for (index, component) in components.iter().enumerate() {
        if let Component::Normal(segment) = component {
            path.push(segment);
        }
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| format!("package artifact unavailable: {relative}"))?;
        if metadata.file_type().is_symlink()
            || (index + 1 < components.len() && !metadata.is_dir())
            || (index + 1 == components.len() && !metadata.is_file())
        {
            return Err(format!("package artifact boundary refused: {relative}"));
        }
    }
    Ok(path)
}

fn read_machine_form(path: &Path) -> Result<String, String> {
    let bytes = read_regular_file(path, EVOX2_SCRATCH_BUILD_MAX_MACHINE_BYTES as u64)?;
    String::from_utf8(bytes).map_err(|_| "machine form UTF-8 refused".to_owned())
}

fn read_regular_file(path: &Path, maximum: u64) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "file unavailable".to_owned())?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err("file boundary refused".to_owned());
    }
    let file = fs::File::open(path).map_err(|_| "file read failed".to_owned())?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "file read failed".to_owned())?;
    if bytes.len() as u64 != metadata.len() {
        return Err("file stability refused".to_owned());
    }
    Ok(bytes)
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
