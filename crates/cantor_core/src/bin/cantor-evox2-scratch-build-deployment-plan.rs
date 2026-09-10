use cantor_core::{
    compile_evox2_scratch_build_controller_plan, fixed_evox2_scratch_build_controller_request,
    from_evox2_scratch_build_controller_plan_machine_form,
    from_evox2_scratch_build_controller_request_machine_form,
    to_evox2_scratch_build_controller_plan_machine_form,
    to_evox2_scratch_build_controller_verification_machine_form,
    verify_evox2_scratch_build_controller_plan,
};
use std::env;
use std::fs;
use std::io::{self, Read};

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
    let arguments: Vec<String> = env::args().skip(1).collect();
    match arguments.as_slice() {
        [command, run_uuid, implementation, bookend] if command == "request" => {
            let request = fixed_evox2_scratch_build_controller_request(
                run_uuid,
                implementation,
                bookend,
            )
            .map_err(|error| error.to_string())?;
            cantor_core::to_evox2_scratch_build_controller_request_machine_form(&request)
                .map_err(|error| error.to_string())
        }
        [] => {
            let raw = read_stdin_bounded()?;
            let request = from_evox2_scratch_build_controller_request_machine_form(&raw)
                .map_err(|error| error.to_string())?;
            let plan = compile_evox2_scratch_build_controller_plan(&request)
                .map_err(|error| error.to_string())?;
            to_evox2_scratch_build_controller_plan_machine_form(&request, &plan)
                .map_err(|error| error.to_string())
        }
        [command, request_path] if command == "compile" => {
            let raw = read_file_bounded(request_path)?;
            let request = from_evox2_scratch_build_controller_request_machine_form(&raw)
                .map_err(|error| error.to_string())?;
            let plan = compile_evox2_scratch_build_controller_plan(&request)
                .map_err(|error| error.to_string())?;
            to_evox2_scratch_build_controller_plan_machine_form(&request, &plan)
                .map_err(|error| error.to_string())
        }
        [command, request_path, plan_path] if command == "verify" => {
            let request_raw = read_file_bounded(request_path)?;
            let plan_raw = read_file_bounded(plan_path)?;
            let request = from_evox2_scratch_build_controller_request_machine_form(&request_raw)
                .map_err(|error| error.to_string())?;
            let plan = from_evox2_scratch_build_controller_plan_machine_form(&request, &plan_raw)
                .map_err(|error| error.to_string())?;
            let verification = verify_evox2_scratch_build_controller_plan(&request, &plan)
                .map_err(|error| error.to_string())?;
            to_evox2_scratch_build_controller_verification_machine_form(&verification)
                .map_err(|error| error.to_string())
        }
        _ => Err(
            "usage: cantor-evox2-scratch-build-deployment-plan [request RUN_UUID IMPLEMENTATION_COMMIT BOOKEND_COMMIT | compile REQUEST | verify REQUEST PLAN]".to_owned(),
        ),
    }
}

fn read_stdin_bounded() -> Result<String, String> {
    let mut bytes = Vec::new();
    io::stdin()
        .take(65_537)
        .read_to_end(&mut bytes)
        .map_err(|_| "controller request read failed".to_owned())?;
    decode_bounded(bytes)
}

fn read_file_bounded(path: &str) -> Result<String, String> {
    let metadata = fs::metadata(path).map_err(|_| "controller input metadata failed".to_owned())?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 65_536 {
        return Err("controller input byte bound differs".to_owned());
    }
    let raw =
        decode_bounded(fs::read(path).map_err(|_| "controller input read failed".to_owned())?)?;
    let framed = if let Some(value) = raw.strip_suffix("\r\n") {
        value
    } else if let Some(value) = raw.strip_suffix('\n') {
        value
    } else {
        return Err("controller file requires one terminal line ending".to_owned());
    };
    if framed.is_empty() || framed.ends_with('\r') || framed.ends_with('\n') {
        return Err("controller file line-ending cardinality differs".to_owned());
    }
    Ok(framed.to_owned())
}

fn decode_bounded(bytes: Vec<u8>) -> Result<String, String> {
    if bytes.is_empty() || bytes.len() > 65_536 {
        return Err("controller input byte bound differs".to_owned());
    }
    String::from_utf8(bytes).map_err(|_| "controller input UTF-8 differs".to_owned())
}
