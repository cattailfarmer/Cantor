use std::{env, fs, io::Write, path::Path};

use cantor_ecosystem::{
    KRV_MAX_FORM_BYTES, from_b1oapr_packet_machine_form, from_b1oapr_request_machine_form,
    from_b1oapr_verification_machine_form, from_bpv_envelope_machine_form,
    from_bpv_receipt_machine_form, from_bpv_request_machine_form,
    from_kcv_attestation_machine_form, from_kcv_receipt_machine_form,
    from_kcv_request_machine_form, from_krv_request_machine_form, from_krv_snapshot_machine_form,
    to_krv_receipt_machine_form, verify_krv_revocation_snapshot,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("cantor-b1-public-verifying-key-revocation-snapshot-verify: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let arguments: Vec<_> = env::args_os().skip(1).collect();
    if arguments.len() != 11 {
        return Err("expected exactly: <predecessor_request.json> <predecessor_packet.json> <predecessor_verification.json> <a1_policy_envelope.json> <a1_verification_request.json> <a1_receipt.json> <custody_attestation.json> <a2_verification_request.json> <a2_receipt.json> <revocation_snapshot.json> <verification_request.json>".to_owned());
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
    let a1_envelope_text = read_form(Path::new(&arguments[3]))?;
    let a1_envelope =
        from_bpv_envelope_machine_form(&a1_envelope_text).map_err(|error| error.to_string())?;
    let a1_request_text = read_form(Path::new(&arguments[4]))?;
    let a1_request =
        from_bpv_request_machine_form(&a1_request_text).map_err(|error| error.to_string())?;
    let a1_receipt_text = read_form(Path::new(&arguments[5]))?;
    let a1_receipt = from_bpv_receipt_machine_form(&a1_request, &a1_envelope, &a1_receipt_text)
        .map_err(|error| error.to_string())?;
    let a2_attestation_text = read_form(Path::new(&arguments[6]))?;
    let a2_attestation = from_kcv_attestation_machine_form(&a2_attestation_text)
        .map_err(|error| error.to_string())?;
    let a2_request_text = read_form(Path::new(&arguments[7]))?;
    let a2_request =
        from_kcv_request_machine_form(&a2_request_text).map_err(|error| error.to_string())?;
    let a2_receipt_text = read_form(Path::new(&arguments[8]))?;
    let a2_receipt = from_kcv_receipt_machine_form(&a2_request, &a2_attestation, &a2_receipt_text)
        .map_err(|error| error.to_string())?;
    let snapshot_text = read_form(Path::new(&arguments[9]))?;
    let snapshot =
        from_krv_snapshot_machine_form(&snapshot_text).map_err(|error| error.to_string())?;
    let request_text = read_form(Path::new(&arguments[10]))?;
    let request =
        from_krv_request_machine_form(&request_text).map_err(|error| error.to_string())?;
    let receipt = verify_krv_revocation_snapshot(
        &request,
        &predecessor_request,
        &predecessor_packet,
        &predecessor_verification,
        &a1_envelope,
        a1_envelope_text.as_bytes(),
        &a1_request,
        &a1_receipt,
        &a2_attestation,
        a2_attestation_text.as_bytes(),
        &a2_request,
        &a2_receipt,
        snapshot_text.as_bytes(),
    )
    .map_err(|error| error.to_string())?;
    let output = to_krv_receipt_machine_form(&request, &snapshot, &receipt)
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
        || metadata.len() > KRV_MAX_FORM_BYTES as u64 + 1
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
