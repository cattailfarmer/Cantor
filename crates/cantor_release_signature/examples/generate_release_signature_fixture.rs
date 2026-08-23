use std::{env, fs, path::PathBuf};

use cantor_release_signature::generate_synthetic_release_signature_fixture;

fn main() -> Result<(), String> {
    let mut arguments = env::args().skip(1);
    let bundle_path = PathBuf::from(arguments.next().ok_or("bundle path is required")?);
    let evidence_path = PathBuf::from(arguments.next().ok_or("bundle evidence path is required")?);
    let output_path = PathBuf::from(arguments.next().ok_or("output directory is required")?);
    if arguments.next().is_some() {
        return Err("unexpected fixture-generator argument".to_owned());
    }
    if output_path.exists() {
        return Err("fixture output directory must be absent".to_owned());
    }
    let bundle = fs::read(bundle_path).map_err(|error| error.to_string())?;
    let evidence = fs::read(evidence_path).map_err(|error| error.to_string())?;
    let fixture = generate_synthetic_release_signature_fixture(&bundle, &evidence)?;
    fs::create_dir(&output_path).map_err(|error| error.to_string())?;
    write_json(output_path.join("policy.json"), &fixture.policy)?;
    write_json(output_path.join("envelope.json"), &fixture.envelope)?;
    write_json(output_path.join("receipt.json"), &fixture.receipt)?;
    write_json(output_path.join("fixture.json"), &fixture)?;
    println!("synthetic_release_signature_fixture_written=true files=4");
    Ok(())
}

fn write_json(path: PathBuf, value: &impl serde::Serialize) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    fs::write(path, bytes).map_err(|error| error.to_string())
}
