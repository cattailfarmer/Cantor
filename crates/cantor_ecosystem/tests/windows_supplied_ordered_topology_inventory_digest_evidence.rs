use cantor_ecosystem::sha256_file;
use std::{fs, path::Path};

#[test]
fn supplied_ordered_inventory_digest_manifest_is_current_portable_and_effect_free() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repository_root = crate_root
        .join("../..")
        .canonicalize()
        .expect("repository root");
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(crate_root.join(
            "evidence/windows_supplied_ordered_topology_inventory_digest_evidence_manifest.json",
        ))
        .expect("manifest"),
    )
    .expect("JSON");
    assert_eq!(
        manifest["schema"],
        "cantor-windows-supplied-ordered-topology-inventory-digest-evidence-manifest/0.1"
    );
    assert_eq!(
        manifest["evidence_manifest_uuid"],
        "1b564e58-031f-4904-a6ee-d1d38d33e36d"
    );
    assert_eq!(
        manifest["authority"]["satisfaction_signature_uuid"],
        "63c58b74-0eb9-4ab8-9c95-4bfe3bb92af8"
    );
    assert_eq!(manifest["scope"]["complete_assembly_input_only"], true);
    assert_eq!(manifest["scope"]["current_m2a_revalidation"], true);
    assert_eq!(manifest["scope"]["exact_assembly_correlations"], true);
    assert_eq!(manifest["scope"]["fixed_big_endian"], true);
    assert_eq!(manifest["scope"]["explicit_tags"], true);
    assert_eq!(manifest["scope"]["explicit_option_presence"], true);
    assert_eq!(manifest["scope"]["fixed_hex_decode"], true);
    assert_eq!(manifest["scope"]["sequence_sensitive"], true);
    assert_eq!(manifest["scope"]["lineage_retained"], true);
    assert_eq!(manifest["scope"]["whole_inventory_buffer"], false);
    for absent in [
        "physical_origin_authority",
        "enumeration_authority",
        "inventory_completeness_authority",
        "traversal_authority",
        "git_authority",
        "double_inventory_authority",
        "receipt_authority",
        "admission_authority",
        "mutation_authority",
    ] {
        assert_eq!(manifest["scope"][absent], false, "absent: {absent}");
    }
    let artifacts = manifest["artifacts"].as_array().expect("artifacts");
    assert_eq!(artifacts.len(), 51);
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
