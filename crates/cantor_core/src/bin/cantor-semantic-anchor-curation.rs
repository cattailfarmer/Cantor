use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use cantor_core::{
    SemanticAnchorCuratorPolicy, SemanticAnchorCuratorSelectionPayload,
    SignedSemanticAnchorCuratorSelection, curator_selection_payload_bytes,
    generate_synthetic_semantic_anchor_curation_fixture, verify_semantic_anchor_curator_selection,
    verify_synthetic_semantic_anchor_curation_fixture,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        [flag, payload, output] if flag == "--canonicalize-payload" => {
            let payload: SemanticAnchorCuratorSelectionPayload = serde_json::from_slice(
                &fs::read(payload).map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
            write_bytes(Path::new(output), &curator_selection_payload_bytes(&payload)?)
        }
        [flag, baseline, output] if flag == "--generate-synthetic-fixture" => {
            let baseline = fs::read(baseline).map_err(|error| error.to_string())?;
            let fixture = generate_synthetic_semantic_anchor_curation_fixture(&baseline)?;
            write_pretty_json(Path::new(output), &fixture)
        }
        [flag, baseline, fixture] if flag == "--verify-synthetic-fixture" => {
            let baseline = fs::read(baseline).map_err(|error| error.to_string())?;
            let fixture = fs::read(fixture).map_err(|error| error.to_string())?;
            verify_synthetic_semantic_anchor_curation_fixture(&baseline, &fixture)
        }
        [flag, baseline, policy, selection, output] if flag == "--verify" => {
            let baseline = fs::read(baseline).map_err(|error| error.to_string())?;
            let policy: SemanticAnchorCuratorPolicy = serde_json::from_slice(
                &fs::read(policy).map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
            let selection: SignedSemanticAnchorCuratorSelection = serde_json::from_slice(
                &fs::read(selection).map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
            let receipt = verify_semantic_anchor_curator_selection(&baseline, &policy, &selection)?;
            write_pretty_json(Path::new(output), &receipt)
        }
        _ => Err("usage: cantor-semantic-anchor-curation --canonicalize-payload <payload> <output> | --generate-synthetic-fixture <baseline> <output> | --verify-synthetic-fixture <baseline> <fixture> | --verify <baseline> <policy> <selection> <receipt-output>".to_owned()),
    }
}

fn write_pretty_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), String> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    fs::write(PathBuf::from(path), [bytes.as_slice(), b"\n"].concat())
        .map_err(|error| error.to_string())
}

fn write_bytes(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    fs::write(PathBuf::from(path), bytes).map_err(|error| error.to_string())
}
