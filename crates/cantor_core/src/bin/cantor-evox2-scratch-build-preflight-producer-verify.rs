use std::env;
use std::fs;
use std::path::Path;

use cantor_core::*;

const MAXIMUM_FORM_BYTES: u64 = 262_144;

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
        [command, request, plan, program, executable_sha256] if command == "plan" => {
            let (request, plan, program) = read_program(request, plan, program)?;
            let producer_plan = compile_evox2_scratch_build_remote_preflight_producer_plan(
                &request,
                &plan,
                &program,
                executable_sha256,
            )
            .map_err(|error| error.to_string())?;
            to_evox2_scratch_build_remote_preflight_producer_plan_machine_form(
                &request,
                &plan,
                &program,
                &producer_plan,
            )
            .map_err(|error| error.to_string())
        }
        [
            command,
            request,
            plan,
            program,
            producer_plan,
            process_record,
        ] if command == "compile" => {
            let (request, plan, program, producer_plan) =
                read_producer_plan(request, plan, program, producer_plan)?;
            let process_record_raw = read_form_file(process_record)?;
            let process_record =
                from_evox2_scratch_build_remote_preflight_process_record_machine_form(
                    &request,
                    &plan,
                    &program,
                    &producer_plan,
                    &process_record_raw,
                )
                .map_err(|error| error.to_string())?;
            let observation =
                compile_evox2_scratch_build_remote_preflight_observation_from_process_record(
                    &request,
                    &plan,
                    &program,
                    &producer_plan,
                    &process_record,
                )
                .map_err(|error| error.to_string())?;
            to_evox2_scratch_build_remote_preflight_observation_machine_form(
                &request,
                &plan,
                &program,
                &observation,
            )
            .map_err(|error| error.to_string())
        }
        [
            command,
            request,
            plan,
            program,
            producer_plan,
            process_record,
            observation,
        ] if command == "verify" => {
            let (request, plan, program, producer_plan) =
                read_producer_plan(request, plan, program, producer_plan)?;
            let process_record_raw = read_form_file(process_record)?;
            let process_record =
                from_evox2_scratch_build_remote_preflight_process_record_machine_form(
                    &request,
                    &plan,
                    &program,
                    &producer_plan,
                    &process_record_raw,
                )
                .map_err(|error| error.to_string())?;
            let observation_raw = read_form_file(observation)?;
            let observation = from_evox2_scratch_build_remote_preflight_observation_machine_form(
                &request,
                &plan,
                &program,
                &observation_raw,
            )
            .map_err(|error| error.to_string())?;
            let verification = verify_evox2_scratch_build_remote_preflight_producer(
                &request,
                &plan,
                &program,
                &producer_plan,
                &process_record,
                &observation,
            )
            .map_err(|error| error.to_string())?;
            to_evox2_scratch_build_remote_preflight_producer_verification_machine_form(
                &verification,
            )
            .map_err(|error| error.to_string())
        }
        _ => Err(usage()),
    }
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
    let request_raw = read_form_file(request_path)?;
    let request = from_evox2_scratch_build_controller_request_machine_form(&request_raw)
        .map_err(|error| error.to_string())?;
    let plan_raw = read_form_file(plan_path)?;
    let plan = from_evox2_scratch_build_controller_plan_machine_form(&request, &plan_raw)
        .map_err(|error| error.to_string())?;
    let program_raw = read_form_file(program_path)?;
    let program =
        from_evox2_scratch_build_effect_program_machine_form(&request, &plan, &program_raw)
            .map_err(|error| error.to_string())?;
    Ok((request, plan, program))
}

fn read_producer_plan(
    request_path: &str,
    plan_path: &str,
    program_path: &str,
    producer_plan_path: &str,
) -> Result<
    (
        Evox2ScratchBuildControllerRequest,
        Evox2ScratchBuildControllerPlan,
        Evox2ScratchBuildEffectProgram,
        Evox2ScratchBuildRemotePreflightProducerPlan,
    ),
    String,
> {
    let (request, plan, program) = read_program(request_path, plan_path, program_path)?;
    let producer_plan_raw = read_form_file(producer_plan_path)?;
    let producer_plan = from_evox2_scratch_build_remote_preflight_producer_plan_machine_form(
        &request,
        &plan,
        &program,
        &producer_plan_raw,
    )
    .map_err(|error| error.to_string())?;
    Ok((request, plan, program, producer_plan))
}

fn read_form_file(path: &str) -> Result<String, String> {
    let path = Path::new(path);
    let metadata = fs::symlink_metadata(path).map_err(|_| "input metadata failed".to_owned())?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > MAXIMUM_FORM_BYTES
    {
        return Err("input file boundary differs".to_owned());
    }
    let value = fs::read_to_string(path).map_err(|_| "input UTF-8 read failed".to_owned())?;
    if value.ends_with(['\r', '\n']) {
        return Err("form file line-ending cardinality differs".to_owned());
    }
    Ok(value)
}

fn usage() -> String {
    "usage: cantor-evox2-scratch-build-preflight-producer-verify [plan REQUEST PLAN PROGRAM EXECUTABLE_SHA256 | compile REQUEST PLAN PROGRAM PRODUCER_PLAN PROCESS_RECORD | verify REQUEST PLAN PROGRAM PRODUCER_PLAN PROCESS_RECORD OBSERVATION]".to_owned()
}
