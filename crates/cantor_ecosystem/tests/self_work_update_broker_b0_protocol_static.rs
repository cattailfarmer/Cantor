use std::{fs, path::Path};

use serde::Deserialize;
use sha2::{Digest, Sha256};

const MODULE: &str = include_str!("../src/workspace_admission/update_broker_protocol.rs");
const PARENT: &str = include_str!("../src/workspace_admission.rs");

#[derive(Deserialize)]
struct Manifest {
    profile: String,
    physical_contact: bool,
    capability_count: usize,
    granted_capability_count: usize,
    later_stage_receipt_types: usize,
    production_module_count: usize,
    parent_export_count: usize,
    cargo_delta: bool,
    effect_delta: bool,
    artifacts: Vec<Artifact>,
}

#[derive(Deserialize)]
struct Artifact {
    path: String,
    bytes: u64,
    sha256: String,
}

#[test]
fn public_surface_is_pure_b0_only() {
    assert_eq!(PARENT.matches("pub mod update_broker_protocol;").count(), 1);

    let capability_body = MODULE
        .split("pub enum CapabilityKind {")
        .nth(1)
        .and_then(|tail| tail.split("\n}").next())
        .expect("CapabilityKind body");
    assert_eq!(
        capability_body
            .lines()
            .filter(|line| line.trim_end().ends_with(','))
            .count(),
        22
    );

    for denied in [
        "std::fs",
        "std::process",
        "std::env",
        "std::time",
        "unsafe {",
        "cfg(windows)",
        "B1PreflightRecord",
        "B2MutationRunRecord",
        "B3PostStateEvidenceRecord",
        "B4IndependentReviewRecord",
        "B5RollbackRecord",
        "impl From<",
        "impl TryFrom<",
    ] {
        assert!(!MODULE.contains(denied), "denied surface present: {denied}");
    }

    for required in [
        "FormationOnly",
        "FormationValidated",
        "physical_contact: false",
        "expected.len() != 22",
        "account.granted.is_empty()",
        "account.explicitly_not_granted != expected",
    ] {
        assert!(
            MODULE.contains(required),
            "required gate absent: {required}"
        );
    }
}

#[test]
fn evidence_manifest_rehashes_every_member() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("evidence/self_work_update_broker_b0_protocol_evidence_manifest.json");
    let manifest: Manifest = serde_json::from_slice(&fs::read(manifest_path).unwrap()).unwrap();

    assert_eq!(
        manifest.profile,
        "cantor-self-work-update-broker-protocol-evidence/0.2"
    );
    assert!(!manifest.physical_contact);
    assert_eq!(manifest.capability_count, 22);
    assert_eq!(manifest.granted_capability_count, 0);
    assert_eq!(manifest.later_stage_receipt_types, 0);
    assert_eq!(manifest.production_module_count, 1);
    assert_eq!(manifest.parent_export_count, 1);
    assert!(!manifest.cargo_delta);
    assert!(!manifest.effect_delta);
    assert!(!manifest.artifacts.is_empty());

    for artifact in manifest.artifacts {
        let bytes = fs::read(root.join(&artifact.path)).unwrap();
        assert_eq!(bytes.len() as u64, artifact.bytes, "{}", artifact.path);
        let digest: String = Sha256::digest(&bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
            .to_uppercase();
        assert_eq!(digest, artifact.sha256);
    }
}
