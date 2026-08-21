use std::env;
use std::fs;
use std::path::PathBuf;

use cantor_core::{generate_self_hosted_anchor_evidence, verify_self_hosted_anchor_evidence};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        [manifest, output] if manifest != "--verify" => {
            let evidence = generate_self_hosted_anchor_evidence(&PathBuf::from(manifest))?;
            let bytes = serde_json::to_vec_pretty(&evidence).map_err(|error| error.to_string())?;
            let path = PathBuf::from(output);
            if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
                fs::create_dir_all(parent).map_err(|error| error.to_string())?;
            }
            fs::write(path, [bytes.as_slice(), b"\n"].concat()).map_err(|error| error.to_string())
        }
        [flag, manifest, evidence] if flag == "--verify" => {
            let bytes = fs::read(evidence).map_err(|error| error.to_string())?;
            verify_self_hosted_anchor_evidence(&PathBuf::from(manifest), &bytes)
        }
        _ => Err("usage: cantor-self-hosted-anchor-evidence <manifest> <output> | --verify <manifest> <evidence>".to_owned()),
    }
}
