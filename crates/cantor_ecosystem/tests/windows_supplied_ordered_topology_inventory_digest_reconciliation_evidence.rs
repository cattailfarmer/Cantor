use cantor_ecosystem::sha256_file;
use std::{fs, path::Path};

#[test]
fn supplied_ordered_inventory_digest_reconciliation_manifest_is_current_and_effect_free() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repository_root = crate_root
        .join("../..")
        .canonicalize()
        .expect("repository root");
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(crate_root.join(
            "evidence/windows_supplied_ordered_topology_inventory_digest_reconciliation_evidence_manifest.json",
        ))
        .expect("manifest"),
    )
    .expect("JSON");
    assert_eq!(
        manifest["schema"],
        "cantor-windows-supplied-ordered-topology-inventory-digest-reconciliation-evidence-manifest/0.1"
    );
    assert_eq!(
        manifest["evidence_manifest_uuid"],
        "b35763ec-0947-48ef-8bce-a51f9a4a3c7f"
    );
    assert_eq!(
        manifest["authority"]["satisfaction_signature_uuid"],
        "a763535f-3b13-4539-9aba-d74f09e3de5c"
    );
    assert_eq!(manifest["scope"]["complete_output_operands"], true);
    assert_eq!(manifest["scope"]["current_rederivation"], true);
    assert_eq!(manifest["scope"]["exact_complete_limits"], true);
    assert_eq!(manifest["scope"]["exact_root_scope"], true);
    assert_eq!(manifest["scope"]["closed_equal_or_different"], true);
    assert_eq!(manifest["scope"]["positional_non_temporal_operands"], true);
    for absent in [
        "physical_origin_authority",
        "enumeration_authority",
        "temporal_authority",
        "double_inventory_authority",
        "quiescence_authority",
        "receipt_authority",
        "admission_authority",
        "mutation_authority",
    ] {
        assert_eq!(manifest["scope"][absent], false, "absent: {absent}");
    }
    let artifacts = manifest["artifacts"].as_array().expect("artifacts");
    assert!(artifacts.len() >= 50);
    for artifact in artifacts {
        let path = artifact["path"].as_str().expect("path");
        assert!(!Path::new(path).is_absolute());
        let full = repository_root.join(path);
        let bytes = fs::read(&full).unwrap_or_else(|error| panic!("{path}: {error}"));
        assert_eq!(
            artifact["bytes"].as_u64(),
            u64::try_from(bytes.len()).ok(),
            "bytes: {path}"
        );
        assert_eq!(
            artifact["sha256"].as_str().unwrap().to_ascii_lowercase(),
            sha256_file(&full).unwrap(),
            "hash: {path}"
        );
    }
}
