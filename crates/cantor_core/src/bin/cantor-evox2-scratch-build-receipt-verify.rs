use std::fs;
use std::io::Read;
use std::path::Path;

use cantor_core::{
    EVOX2_SCRATCH_BUILD_MAX_MACHINE_BYTES, build_evox2_scratch_build_receipt_verification,
    from_evox2_scratch_build_commission_machine_form,
    from_evox2_scratch_build_receipt_machine_form,
    to_evox2_scratch_build_receipt_verification_machine_form,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let arguments = std::env::args().collect::<Vec<_>>();
    if arguments.len() != 3 || arguments[1] != "commission.json" || arguments[2] != "receipt.json" {
        return Err(
            "usage: cantor-evox2-scratch-build-receipt-verify commission.json receipt.json"
                .to_owned(),
        );
    }
    let commission = read_bounded(Path::new("commission.json"), "commission")?;
    let receipt = read_bounded(Path::new("receipt.json"), "receipt")?;
    let commission = from_evox2_scratch_build_commission_machine_form(&commission)
        .map_err(|error| error.to_string())?;
    let receipt = from_evox2_scratch_build_receipt_machine_form(&commission, &receipt)
        .map_err(|error| error.to_string())?;
    let verification = build_evox2_scratch_build_receipt_verification(&commission, &receipt)
        .map_err(|error| error.to_string())?;
    let output = to_evox2_scratch_build_receipt_verification_machine_form(&verification)
        .map_err(|error| error.to_string())?;
    println!("{output}");
    Ok(())
}

fn read_bounded(path: &Path, name: &str) -> Result<String, String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| format!("{name} unavailable"))?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > EVOX2_SCRATCH_BUILD_MAX_MACHINE_BYTES as u64
    {
        return Err(format!("{name} file boundary refused"));
    }
    let file = fs::File::open(path).map_err(|_| format!("{name} read failed"))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take((EVOX2_SCRATCH_BUILD_MAX_MACHINE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| format!("{name} read failed"))?;
    if bytes.is_empty()
        || bytes.len() > EVOX2_SCRATCH_BUILD_MAX_MACHINE_BYTES
        || bytes.len() as u64 != metadata.len()
    {
        return Err(format!("{name} file stability refused"));
    }
    String::from_utf8(bytes).map_err(|_| format!("{name} UTF-8 refused"))
}
