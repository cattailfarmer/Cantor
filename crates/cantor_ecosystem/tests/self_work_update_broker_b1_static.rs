use std::{fs, path::Path};

use serde::Deserialize;
use sha2::{Digest, Sha256};

const MODULE: &str = include_str!("../src/self_work_update_broker_b1.rs");
const LIB: &str = include_str!("../src/lib.rs");
const CLI: &str = include_str!("../src/bin/cantor-self-work-update-broker-b1.rs");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceManifest {
    profile: String,
    disposition: String,
    run_count: usize,
    transcript_frame_count: usize,
    provider_contact_count: usize,
    model_turn_count: usize,
    mcp_call_count: usize,
    external_network_count: usize,
    mutation_count: usize,
    physical_contact: bool,
    live_process_launched: bool,
    cleanup_performed: bool,
    artifacts: Vec<Artifact>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    path: String,
    bytes: u64,
    sha256: String,
}

#[test]
fn public_surface_is_one_read_only_not_run_verifier() {
    assert_eq!(
        LIB.matches("pub mod self_work_update_broker_b1;").count(),
        1
    );
    assert_eq!(
        LIB.matches("pub use self_work_update_broker_b1::*;")
            .count(),
        1
    );
    for required in [
        "selected_schema_missing_read_scope_control",
        "B1PreflightDisposition::NotRun",
        "run_count: 0",
        "transcript_frame_count: 0",
        "physical_contact: false",
        "may_have_mutated: false",
        "live_process_launched: false",
        "fixture_quarantined: true",
        "cleanup_performed: false",
        "NoDuplicateValue",
        "read_bounded_regular_file",
    ] {
        assert!(
            MODULE.contains(required),
            "required gate absent: {required}"
        );
    }
    for denied in [
        "std::process",
        "std::env",
        "std::time",
        "fs::write",
        "OpenOptions",
        "File::create",
        "remove_file",
        "remove_dir",
        "rename(",
        "Command::",
        "TcpStream",
        "UdpSocket",
        "reqwest",
        "thread/start",
        "turn/start",
        "command/exec",
    ] {
        assert!(
            !MODULE.contains(denied),
            "denied effect surface present: {denied}"
        );
    }
}

#[test]
fn cli_has_one_path_argument_and_stdout_only_result() {
    assert!(CLI.contains("verify_b1_preparation_evidence"));
    assert!(CLI.contains("println!"));
    for denied in ["fs::", "File::", "OpenOptions", "Command::", "output"] {
        assert!(
            !CLI.contains(denied),
            "CLI denied surface present: {denied}"
        );
    }
}

#[test]
fn checked_not_run_evidence_manifest_rehashes_every_member() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repository_root = crate_root.join("../..");
    let manifest: EvidenceManifest = serde_json::from_slice(
        &fs::read(
            crate_root.join("evidence/self_work_update_broker_b1_preflight/evidence_manifest.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        manifest.profile,
        "cantor-self-work-update-broker-b1-preflight-evidence/0.1"
    );
    assert_eq!(manifest.disposition, "not_run");
    assert_eq!(manifest.run_count, 0);
    assert_eq!(manifest.transcript_frame_count, 0);
    assert_eq!(manifest.provider_contact_count, 0);
    assert_eq!(manifest.model_turn_count, 0);
    assert_eq!(manifest.mcp_call_count, 0);
    assert_eq!(manifest.external_network_count, 0);
    assert_eq!(manifest.mutation_count, 0);
    assert!(!manifest.physical_contact);
    assert!(!manifest.live_process_launched);
    assert!(!manifest.cleanup_performed);
    assert!(!manifest.artifacts.is_empty());
    for artifact in manifest.artifacts {
        let bytes = fs::read(repository_root.join(&artifact.path)).unwrap();
        assert_eq!(bytes.len() as u64, artifact.bytes, "{}", artifact.path);
        let digest = Sha256::digest(&bytes)
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<String>();
        assert_eq!(digest, artifact.sha256, "{}", artifact.path);
    }
}
