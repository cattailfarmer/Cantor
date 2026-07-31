use cantor_ecosystem::sha256_file;
use std::{fs, path::Path};

#[test]
fn supplied_topology_inventory_assembly_manifest_is_current_and_effect_free() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repository_root = crate_root
        .join("../..")
        .canonicalize()
        .expect("repository root");
    let manifest: serde_json::Value =
        serde_json::from_slice(
            &fs::read(crate_root.join(
                "evidence/windows_supplied_topology_inventory_assembly_evidence_manifest.json",
            ))
            .expect("manifest"),
        )
        .expect("JSON");
    assert_eq!(
        manifest["schema"],
        "cantor-windows-supplied-topology-inventory-assembly-evidence-manifest/0.1"
    );
    assert_eq!(
        manifest["evidence_manifest_uuid"],
        "db540992-0108-428e-a19a-1183b4196571"
    );
    assert_eq!(
        manifest["authority"]["satisfaction_signature_uuid"],
        "9c92f968-054a-42de-a27f-90925bb5081e"
    );
    assert_eq!(manifest["scope"]["complete_carrier_inputs_only"], true);
    assert_eq!(manifest["scope"]["current_m2a_revalidation"], true);
    assert_eq!(manifest["scope"]["exact_duplicate_classes"], 5);
    assert_eq!(manifest["scope"]["ordinal_repair"], false);
    for absent in [
        "physical_origin_authority",
        "enumeration_authority",
        "inventory_completeness_authority",
        "traversal_authority",
        "git_authority",
        "aggregate_digest_authority",
        "double_inventory_authority",
        "receipt_authority",
        "admission_authority",
        "mutation_authority",
    ] {
        assert_eq!(manifest["scope"][absent], false, "absent: {absent}");
    }
    let artifacts = manifest["artifacts"].as_array().expect("artifacts");
    assert_eq!(artifacts.len(), 50);
    for artifact in artifacts {
        let path = artifact["path"].as_str().expect("path");
        assert!(!Path::new(path).is_absolute());
        let full = repository_root.join(path);
        let bytes = fs::read(&full).unwrap_or_else(|e| panic!("{path}: {e}"));
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
