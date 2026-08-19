use std::env;

use cantor_coordination_measurement::{generate_measurement, pretty_measurement_bytes};

fn main() {
    if let Err(error) = run() {
        eprintln!("cantor-coordination-measurement: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    if env::args_os().nth(1).is_some() {
        return Err("usage: cantor-coordination-measurement".into());
    }
    let report = generate_measurement()?;
    let bytes = pretty_measurement_bytes(&report)?;
    use std::io::Write as _;
    std::io::stdout().lock().write_all(&bytes)?;
    Ok(())
}
