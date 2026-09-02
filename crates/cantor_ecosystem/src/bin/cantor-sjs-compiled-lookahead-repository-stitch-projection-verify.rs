use std::io::{self, Read};

use cantor_ecosystem::sjs_compiled_lookahead_repository_stitch_projection::{
    SJS_RSP_MAX_EVIDENCE_BUNDLE_BYTES, from_sjs_rsp_evidence_bundle_machine_form,
    verify_sjs_rsp_evidence_bundle,
};

fn main() {
    run_on_bounded_stack(run);
}

fn run_on_bounded_stack(operation: fn() -> Result<(), String>) {
    let worker = match std::thread::Builder::new()
        .name("cantor-rsp-verifier".to_owned())
        .stack_size(16 * 1024 * 1024)
        .spawn(operation)
    {
        Ok(worker) => worker,
        Err(error) => {
            eprintln!("verifier worker launch failed: {error}");
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
            eprintln!("verifier worker panicked");
            std::process::exit(2);
        }
    }
}

fn run() -> Result<(), String> {
    if std::env::args().count() != 1 {
        return Err(
            "usage: cantor-sjs-compiled-lookahead-repository-stitch-projection-verify < evidence-bundle.json"
                .to_owned(),
        );
    }
    let mut input = String::new();
    io::stdin()
        .take((SJS_RSP_MAX_EVIDENCE_BUNDLE_BYTES + 3) as u64)
        .read_to_string(&mut input)
        .map_err(|error| format!("stdin read failed: {error}"))?;
    let body = input
        .strip_suffix("\r\n")
        .or_else(|| input.strip_suffix('\n'))
        .unwrap_or(&input);
    if body.len() > SJS_RSP_MAX_EVIDENCE_BUNDLE_BYTES {
        return Err("stdin exceeds evidence bundle bound".to_owned());
    }
    let bundle =
        from_sjs_rsp_evidence_bundle_machine_form(body).map_err(|error| error.to_string())?;
    let verification =
        verify_sjs_rsp_evidence_bundle(&bundle).map_err(|error| error.to_string())?;
    let output = serde_json::to_string(&verification)
        .map_err(|error| format!("verification serialization failed: {error}"))?;
    println!("{output}");
    Ok(())
}
