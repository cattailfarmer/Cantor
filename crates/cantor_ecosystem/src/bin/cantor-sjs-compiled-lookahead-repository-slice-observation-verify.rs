use std::io::{self, Read};

use cantor_ecosystem::sjs_compiled_lookahead_repository_slice_observation::{
    SJS_RSO_MAX_EVIDENCE_BUNDLE_BYTES, from_sjs_rso_evidence_bundle_machine_form,
    verify_sjs_rso_evidence_bundle,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    if std::env::args().count() != 1 {
        return Err(
            "usage: cantor-sjs-compiled-lookahead-repository-slice-observation-verify < evidence-bundle.json"
                .to_owned(),
        );
    }
    let mut input = String::new();
    io::stdin()
        .take((SJS_RSO_MAX_EVIDENCE_BUNDLE_BYTES + 3) as u64)
        .read_to_string(&mut input)
        .map_err(|error| format!("stdin read failed: {error}"))?;
    let body = input
        .strip_suffix("\r\n")
        .or_else(|| input.strip_suffix('\n'))
        .unwrap_or(&input);
    if body.len() > SJS_RSO_MAX_EVIDENCE_BUNDLE_BYTES {
        return Err("stdin exceeds evidence bundle bound".to_owned());
    }
    let bundle =
        from_sjs_rso_evidence_bundle_machine_form(body).map_err(|error| error.to_string())?;
    let verification =
        verify_sjs_rso_evidence_bundle(&bundle).map_err(|error| error.to_string())?;
    let output = serde_json::to_string(&verification)
        .map_err(|error| format!("verification serialization failed: {error}"))?;
    println!("{output}");
    Ok(())
}
