use std::fs;
use std::io::Read;
use std::path::Path;

use cantor_core::{
    EVOX2_SCRATCH_BUILD_MAX_MACHINE_BYTES, commissioned_evox2_scratch_build,
    fixed_evox2_scratch_build_command_set, from_evox2_scratch_build_command_set_machine_form,
    from_evox2_scratch_build_implementation_manifest_machine_form,
    to_evox2_scratch_build_command_set_machine_form,
    to_evox2_scratch_build_commission_machine_form,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let arguments = std::env::args().collect::<Vec<_>>();
    if arguments.len() == 2 && arguments[1] == "command-set" {
        let output = to_evox2_scratch_build_command_set_machine_form(
            &fixed_evox2_scratch_build_command_set(),
        )
        .map_err(|error| error.to_string())?;
        println!("{output}");
        return Ok(());
    }
    if arguments.len() != 3
        || arguments[1] != "implementation_manifest.json"
        || arguments[2] != "command_set.json"
    {
        return Err("usage: cantor-evox2-scratch-build-commission (command-set | implementation_manifest.json command_set.json)".to_owned());
    }
    let manifest = read_bounded(Path::new("implementation_manifest.json"), "manifest")?;
    let command_set = read_bounded(Path::new("command_set.json"), "command set")?;
    let manifest = from_evox2_scratch_build_implementation_manifest_machine_form(&manifest)
        .map_err(|error| error.to_string())?;
    let command_set = from_evox2_scratch_build_command_set_machine_form(&command_set)
        .map_err(|error| error.to_string())?;
    let commission = commissioned_evox2_scratch_build(
        &manifest.manifest_sha256,
        &command_set.command_set_sha256,
    )
    .map_err(|error| error.to_string())?;
    let output = to_evox2_scratch_build_commission_machine_form(&commission)
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
