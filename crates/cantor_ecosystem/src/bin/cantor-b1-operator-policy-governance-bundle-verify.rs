use std::{env, fs, io::Write, path::Path};

use cantor_ecosystem::{
    BPV_MAX_FORM_BYTES, from_b1oapr_packet_machine_form, from_b1oapr_request_machine_form,
    from_b1oapr_verification_machine_form, from_bpv_envelope_machine_form,
    from_bpv_request_machine_form, to_bpv_receipt_machine_form, verify_bpv_policy_bundle,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("cantor-b1-operator-policy-governance-bundle-verify: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let arguments: Vec<_> = env::args_os().skip(1).collect();
    if arguments.len() != 5 {
        return Err("expected exactly: <predecessor_request.json> <predecessor_packet.json> <predecessor_verification.json> <policy_envelope.json> <verification_request.json>".to_owned());
    }
    let predecessor_request_text = read_form(Path::new(&arguments[0]))?;
    let predecessor_request = from_b1oapr_request_machine_form(&predecessor_request_text)
        .map_err(|error| error.to_string())?;
    let predecessor_packet_text = read_form(Path::new(&arguments[1]))?;
    let predecessor_packet =
        from_b1oapr_packet_machine_form(&predecessor_request, &predecessor_packet_text)
            .map_err(|error| error.to_string())?;
    let predecessor_verification_text = read_form(Path::new(&arguments[2]))?;
    let predecessor_verification = from_b1oapr_verification_machine_form(
        &predecessor_request,
        &predecessor_packet,
        &predecessor_verification_text,
    )
    .map_err(|error| error.to_string())?;
    let envelope_text = read_form(Path::new(&arguments[3]))?;
    let envelope =
        from_bpv_envelope_machine_form(&envelope_text).map_err(|error| error.to_string())?;
    let request_text = read_form(Path::new(&arguments[4]))?;
    let request =
        from_bpv_request_machine_form(&request_text).map_err(|error| error.to_string())?;
    let receipt = verify_bpv_policy_bundle(
        &request,
        &predecessor_request,
        &predecessor_packet,
        &predecessor_verification,
        envelope_text.as_bytes(),
    )
    .map_err(|error| error.to_string())?;
    let output = to_bpv_receipt_machine_form(&request, &envelope, &receipt)
        .map_err(|error| error.to_string())?;
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(output.as_bytes())
        .and_then(|_| stdout.write_all(b"\n"))
        .map_err(|error| error.to_string())
}

fn read_form(path: &Path) -> Result<String, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || is_reparse_point(&metadata)
        || metadata.len() == 0
        || metadata.len() > BPV_MAX_FORM_BYTES as u64 + 1
    {
        return Err(format!(
            "input is not a bounded regular nonlink file: {}",
            path.display()
        ));
    }
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    if bytes.contains(&b'\r') {
        return Err(format!("CR framing refused: {}", path.display()));
    }
    let core = bytes.strip_suffix(b"\n").unwrap_or(&bytes);
    if core.is_empty() || core.contains(&b'\n') {
        return Err(format!("LF framing refused: {}", path.display()));
    }
    String::from_utf8(core.to_vec()).map_err(|error| error.to_string())
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}
