use cantor_ecosystem::sjs_compiled_lookahead_repository_stitch_projection::{
    build_sjs_rsp_evidence_bundle, compile_sjs_rsp, synthetic_sjs_rsp_request,
    to_sjs_rsp_evidence_bundle_machine_form, verify_sjs_rsp,
};

fn main() {
    run_on_bounded_stack(run);
}

fn run_on_bounded_stack(operation: fn() -> Result<(), String>) {
    let worker = match std::thread::Builder::new()
        .name("cantor-rsp-fixture".to_owned())
        .stack_size(16 * 1024 * 1024)
        .spawn(operation)
    {
        Ok(worker) => worker,
        Err(error) => {
            eprintln!("fixture worker launch failed: {error}");
            std::process::exit(2);
        }
    };
    match worker.join() {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
        Err(_) => {
            eprintln!("fixture worker panicked");
            std::process::exit(2);
        }
    }
}

fn run() -> Result<(), String> {
    if std::env::args().count() != 1 {
        return Err(
            "usage: cantor-sjs-compiled-lookahead-repository-stitch-projection-fixture".to_owned(),
        );
    }
    let request = synthetic_sjs_rsp_request().map_err(|error| error.to_string())?;
    let envelope = compile_sjs_rsp(&request).map_err(|error| error.to_string())?;
    let verification = verify_sjs_rsp(&envelope).map_err(|error| error.to_string())?;
    let replay_envelope = compile_sjs_rsp(&request).map_err(|error| error.to_string())?;
    let replay_verification =
        verify_sjs_rsp(&replay_envelope).map_err(|error| error.to_string())?;
    let bundle = build_sjs_rsp_evidence_bundle(
        &request,
        &envelope,
        &verification,
        &replay_envelope,
        &replay_verification,
    )
    .map_err(|error| error.to_string())?;
    let output =
        to_sjs_rsp_evidence_bundle_machine_form(&bundle).map_err(|error| error.to_string())?;
    println!("{output}");
    Ok(())
}
