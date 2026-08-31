use cantor_core::{
    build_sjs_rcx_evidence_bundle, synthetic_sjs_rcx_request,
    to_sjs_rcx_evidence_bundle_machine_form,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    if std::env::args().count() != 1 {
        return Err("usage: cantor-sjs-compiled-lookahead-repository-candidate-fixture".to_owned());
    }
    let request = synthetic_sjs_rcx_request().map_err(|error| error.to_string())?;
    let bundle = build_sjs_rcx_evidence_bundle(&request).map_err(|error| error.to_string())?;
    let output =
        to_sjs_rcx_evidence_bundle_machine_form(&bundle).map_err(|error| error.to_string())?;
    println!("{output}");
    Ok(())
}
