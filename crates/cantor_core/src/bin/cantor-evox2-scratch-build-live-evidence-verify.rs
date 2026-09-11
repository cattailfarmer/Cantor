use std::env;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use cantor_core::*;
use sha2::{Digest, Sha256};

const MAXIMUM_FORM_BYTES: u64 = 1_048_576;
const MAXIMUM_ARTIFACT_BYTES: u64 = 4_194_304;
const ARTIFACT_PATHS: [&str; 5] = [
    "commission.json",
    "controller_preflight.json",
    "receipt.json",
    "receipt_verification.json",
    "remote_run.json",
];

fn main() {
    match run() {
        Ok(output) => println!("{output}"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    }
}

fn run() -> Result<String, String> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    match arguments.as_slice() {
        [command, request, plan] if command == "program" => {
            let (request, plan) = read_controller(request, plan)?;
            let program = compile_evox2_scratch_build_effect_program(&request, &plan)
                .map_err(|error| error.to_string())?;
            to_evox2_scratch_build_effect_program_machine_form(&request, &plan, &program)
                .map_err(|error| error.to_string())
        }
        [command, request, plan, program] if command == "state" => {
            let (_, _, program) = read_program(request, plan, program)?;
            let state = initial_evox2_scratch_build_effect_state(&program)
                .map_err(|error| error.to_string())?;
            to_evox2_scratch_build_effect_state_machine_form(&program, &state)
                .map_err(|error| error.to_string())
        }
        [
            command,
            request,
            plan,
            program,
            ordinal,
            status,
            evidence_sha256,
        ] if command == "observation-fixture" => {
            let (_, _, program) = read_program(request, plan, program)?;
            let ordinal = ordinal
                .parse::<u32>()
                .map_err(|_| "effect observation ordinal differs".to_owned())?;
            let observation = fixed_evox2_scratch_build_effect_observation_fixture(
                &program,
                ordinal,
                status,
                evidence_sha256,
            )
            .map_err(|error| error.to_string())?;
            to_evox2_scratch_build_effect_observation_machine_form(&program, &observation)
                .map_err(|error| error.to_string())
        }
        [command, request, plan, program, state, observation] if command == "advance" => {
            let (_, _, program) = read_program(request, plan, program)?;
            let state_raw = read_form_file(state)?;
            let state = from_evox2_scratch_build_effect_state_machine_form(&program, &state_raw)
                .map_err(|error| error.to_string())?;
            let observation_raw = read_form_file(observation)?;
            let observation = from_evox2_scratch_build_effect_observation_machine_form(
                &program,
                &observation_raw,
            )
            .map_err(|error| error.to_string())?;
            let next = advance_evox2_scratch_build_effect_state(&program, &state, &observation)
                .map_err(|error| error.to_string())?;
            to_evox2_scratch_build_effect_state_machine_form(&program, &next)
                .map_err(|error| error.to_string())
        }
        [command, request, plan, program, outcome] if command == "preflight-fixture" => {
            let (request, plan, program) = read_program(request, plan, program)?;
            let admitted = match outcome.as_str() {
                "admitted" => true,
                "refused" => false,
                _ => return Err("preflight fixture outcome differs".to_owned()),
            };
            let preflight =
                fixed_evox2_scratch_build_preflight_fixture(&request, &plan, &program, admitted)
                    .map_err(|error| error.to_string())?;
            to_evox2_scratch_build_remote_preflight_machine_form(
                &request, &plan, &program, &preflight,
            )
            .map_err(|error| error.to_string())
        }
        [command, request, plan, program, observation] if command == "preflight-observation" => {
            let (request, plan, program) = read_program(request, plan, program)?;
            let observation_raw = read_form_file(observation)?;
            let observation = from_evox2_scratch_build_remote_preflight_observation_machine_form(
                &request,
                &plan,
                &program,
                &observation_raw,
            )
            .map_err(|error| error.to_string())?;
            let preflight = compile_evox2_scratch_build_remote_preflight_from_observation(
                &request,
                &plan,
                &program,
                &observation,
            )
            .map_err(|error| error.to_string())?;
            to_evox2_scratch_build_remote_preflight_machine_form(
                &request, &plan, &program, &preflight,
            )
            .map_err(|error| error.to_string())
        }
        [command, request, plan, program, preflight] if command == "refusal" => {
            let (request, plan, program, preflight) =
                read_preflight(request, plan, program, preflight)?;
            let refusal = fixed_evox2_scratch_build_operational_refusal(
                &request, &plan, &program, &preflight,
            )
            .map_err(|error| error.to_string())?;
            to_evox2_scratch_build_operational_refusal_machine_form(
                &request, &plan, &program, &preflight, &refusal,
            )
            .map_err(|error| error.to_string())
        }
        [command, request, plan, program, preflight, refusal] if command == "verify-refusal" => {
            let (request, plan, program, preflight) =
                read_preflight(request, plan, program, preflight)?;
            let refusal_raw = read_form_file(refusal)?;
            let refusal = from_evox2_scratch_build_operational_refusal_machine_form(
                &request,
                &plan,
                &program,
                &preflight,
                &refusal_raw,
            )
            .map_err(|error| error.to_string())?;
            let verification = verify_evox2_scratch_build_operational_refusal_evidence(
                &request, &plan, &program, &preflight, &refusal,
            )
            .map_err(|error| error.to_string())?;
            to_evox2_scratch_build_live_evidence_verification_machine_form(&verification)
                .map_err(|error| error.to_string())
        }
        [
            command,
            request,
            plan,
            program,
            preflight,
            outcome,
            evidence_root,
        ] if command == "inventory" => {
            let (request, plan, program, preflight) =
                read_preflight(request, plan, program, preflight)?;
            let root = exact_evidence_root(evidence_root)?;
            let artifacts = read_artifacts(&root)?;
            let identities = artifacts
                .iter()
                .map(|(path, bytes)| Evox2ScratchBuildRetrievedArtifact {
                    relative_path: path.clone(),
                    bytes: bytes.len() as u64,
                    sha256: sha256(bytes),
                })
                .collect();
            let inventory = seal_evox2_scratch_build_retrieval_inventory(
                &request, &plan, &program, &preflight, outcome, identities,
            )
            .map_err(|error| error.to_string())?;
            to_evox2_scratch_build_retrieval_inventory_machine_form(
                &request, &plan, &program, &preflight, &inventory,
            )
            .map_err(|error| error.to_string())
        }
        [
            command,
            request,
            plan,
            program,
            preflight,
            inventory,
            evidence_root,
        ] if command == "verify-live" => {
            let (request, plan, program, preflight) =
                read_preflight(request, plan, program, preflight)?;
            let inventory_raw = read_form_file(inventory)?;
            let inventory = from_evox2_scratch_build_retrieval_inventory_machine_form(
                &request,
                &plan,
                &program,
                &preflight,
                &inventory_raw,
            )
            .map_err(|error| error.to_string())?;
            let root = exact_evidence_root(evidence_root)?;
            let artifacts = read_artifacts(&root)?;
            let supplied = artifacts
                .iter()
                .map(|(path, bytes)| (path.as_str(), bytes.as_slice()))
                .collect::<Vec<_>>();
            let verification = verify_evox2_scratch_build_retrieved_receipt_evidence(
                &request, &plan, &program, &preflight, &inventory, &supplied,
            )
            .map_err(|error| error.to_string())?;
            to_evox2_scratch_build_live_evidence_verification_machine_form(&verification)
                .map_err(|error| error.to_string())
        }
        [] => {
            let raw = read_stdin_bounded()?;
            if raw.is_empty() {
                Err(usage())
            } else {
                Err("stdin-only mode is not defined; use an explicit operation".to_owned())
            }
        }
        _ => Err(usage()),
    }
}

fn read_controller(
    request_path: &str,
    plan_path: &str,
) -> Result<
    (
        Evox2ScratchBuildControllerRequest,
        Evox2ScratchBuildControllerPlan,
    ),
    String,
> {
    let request_raw = read_form_file(request_path)?;
    let request = from_evox2_scratch_build_controller_request_machine_form(&request_raw)
        .map_err(|error| error.to_string())?;
    let plan_raw = read_form_file(plan_path)?;
    let plan = from_evox2_scratch_build_controller_plan_machine_form(&request, &plan_raw)
        .map_err(|error| error.to_string())?;
    Ok((request, plan))
}

fn read_program(
    request_path: &str,
    plan_path: &str,
    program_path: &str,
) -> Result<
    (
        Evox2ScratchBuildControllerRequest,
        Evox2ScratchBuildControllerPlan,
        Evox2ScratchBuildEffectProgram,
    ),
    String,
> {
    let (request, plan) = read_controller(request_path, plan_path)?;
    let program_raw = read_form_file(program_path)?;
    let program =
        from_evox2_scratch_build_effect_program_machine_form(&request, &plan, &program_raw)
            .map_err(|error| error.to_string())?;
    Ok((request, plan, program))
}

fn read_preflight(
    request_path: &str,
    plan_path: &str,
    program_path: &str,
    preflight_path: &str,
) -> Result<
    (
        Evox2ScratchBuildControllerRequest,
        Evox2ScratchBuildControllerPlan,
        Evox2ScratchBuildEffectProgram,
        Evox2ScratchBuildRemotePreflight,
    ),
    String,
> {
    let (request, plan, program) = read_program(request_path, plan_path, program_path)?;
    let preflight_raw = read_form_file(preflight_path)?;
    let preflight = from_evox2_scratch_build_remote_preflight_machine_form(
        &request,
        &plan,
        &program,
        &preflight_raw,
    )
    .map_err(|error| error.to_string())?;
    Ok((request, plan, program, preflight))
}

fn read_form_file(path: &str) -> Result<String, String> {
    let bytes = read_file_bounded(Path::new(path), MAXIMUM_FORM_BYTES)?;
    let raw = String::from_utf8(bytes).map_err(|_| "form input UTF-8 differs".to_owned())?;
    let value = raw
        .strip_suffix("\r\n")
        .or_else(|| raw.strip_suffix('\n'))
        .ok_or_else(|| "form file requires one terminal line ending".to_owned())?;
    if value.is_empty() || value.ends_with(['\r', '\n']) {
        return Err("form file line-ending cardinality differs".to_owned());
    }
    Ok(value.to_owned())
}

fn read_stdin_bounded() -> Result<String, String> {
    let mut bytes = Vec::new();
    io::stdin()
        .take(MAXIMUM_FORM_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "stdin read failed".to_owned())?;
    if bytes.len() as u64 > MAXIMUM_FORM_BYTES {
        return Err("stdin byte bound differs".to_owned());
    }
    String::from_utf8(bytes).map_err(|_| "stdin UTF-8 differs".to_owned())
}

fn exact_evidence_root(value: &str) -> Result<PathBuf, String> {
    let input = Path::new(value);
    let metadata =
        fs::symlink_metadata(input).map_err(|_| "evidence root metadata failed".to_owned())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("evidence root boundary differs".to_owned());
    }
    fs::canonicalize(input).map_err(|_| "evidence root canonicalization failed".to_owned())
}

fn read_artifacts(root: &Path) -> Result<Vec<(String, Vec<u8>)>, String> {
    let mut aggregate = 0_u64;
    ARTIFACT_PATHS
        .iter()
        .map(|relative| {
            let path = root.join(relative);
            let metadata = fs::symlink_metadata(&path)
                .map_err(|_| format!("retrieved artifact metadata failed: {relative}"))?;
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata.len() == 0
                || metadata.len() > MAXIMUM_ARTIFACT_BYTES
            {
                return Err(format!("retrieved artifact boundary differs: {relative}"));
            }
            aggregate = aggregate
                .checked_add(metadata.len())
                .ok_or_else(|| "retrieved artifact aggregate overflowed".to_owned())?;
            if aggregate > MAXIMUM_ARTIFACT_BYTES {
                return Err("retrieved artifact aggregate differs".to_owned());
            }
            Ok((
                (*relative).to_owned(),
                fs::read(&path)
                    .map_err(|_| format!("retrieved artifact read failed: {relative}"))?,
            ))
        })
        .collect()
}

fn read_file_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "input metadata failed".to_owned())?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err("input file boundary differs".to_owned());
    }
    fs::read(path).map_err(|_| "input read failed".to_owned())
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn usage() -> String {
    "usage: cantor-evox2-scratch-build-live-evidence-verify [program REQUEST PLAN | state REQUEST PLAN PROGRAM | observation-fixture REQUEST PLAN PROGRAM ORDINAL passed|failed|refused EVIDENCE_SHA256 | advance REQUEST PLAN PROGRAM STATE OBSERVATION | preflight-fixture REQUEST PLAN PROGRAM admitted|refused | preflight-observation REQUEST PLAN PROGRAM OBSERVATION | refusal REQUEST PLAN PROGRAM PREFLIGHT | verify-refusal REQUEST PLAN PROGRAM PREFLIGHT REFUSAL | inventory REQUEST PLAN PROGRAM PREFLIGHT OUTCOME EVIDENCE_ROOT | verify-live REQUEST PLAN PROGRAM PREFLIGHT INVENTORY EVIDENCE_ROOT]".to_owned()
}
