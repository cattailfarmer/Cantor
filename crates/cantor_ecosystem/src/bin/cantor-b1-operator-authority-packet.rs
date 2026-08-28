use std::{env, fs, path::Path, process::ExitCode};

use cantor_ecosystem::{
    B1OAPR_MAX_FORM_BYTES, compile_b1oapr_packet, from_b1oapr_request_machine_form,
    to_b1oapr_packet_machine_form,
};

fn main() -> ExitCode {
    let arguments: Vec<String> = env::args().skip(1).collect();
    if arguments.len() != 1 {
        eprintln!("usage: cantor-b1-operator-authority-packet <request.json>");
        return ExitCode::from(2);
    }
    match run(Path::new(&arguments[0])) {
        Ok(packet) => {
            println!("{packet}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(1)
        }
    }
}

fn run(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > B1OAPR_MAX_FORM_BYTES as u64
    {
        return Err("request must be one bounded regular nonlink file".into());
    }
    let bytes = fs::read(path)?;
    let text = std::str::from_utf8(&bytes)?;
    let request = from_b1oapr_request_machine_form(text)?;
    let packet = compile_b1oapr_packet(&request)?;
    Ok(to_b1oapr_packet_machine_form(&request, &packet)?)
}
