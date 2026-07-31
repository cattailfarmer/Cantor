use std::{fs, path::Path};

use cantor_core::sha256_bytes;

#[test]
fn phase3_topology_forms_manifest_is_clone_portable_and_effect_free() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repository_root = crate_root
        .join("../..")
        .canonicalize()
        .expect("repository root");
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(crate_root.join("evidence/phase3_topology_forms_evidence_manifest.json"))
            .expect("evidence manifest"),
    )
    .expect("manifest JSON");
    assert_eq!(
        manifest["schema"],
        "cantor-phase3-topology-forms-evidence-manifest/0.3"
    );
    assert_eq!(
        manifest["authority"]["canonical_specification"],
        "specifications/Cantor_Phase3_Inventory_Consistency_Evidence_Revision.sop"
    );
    assert_eq!(
        manifest["authority"]["satisfaction_signature_uuid"],
        "1edee945-9957-41d7-bd17-0765ec54f5cb"
    );
    assert_eq!(
        manifest["authority"]["joint_machine_forms_signature_uuid"],
        "c681b74d-7543-43be-96a1-a8ccb89181fb"
    );
    assert_eq!(
        manifest["scope"]["forms_profile"],
        "cantor-phase3-topology-forms/0.3"
    );
    assert_eq!(
        manifest["scope"]["receipt_profile"],
        "cantor-phase3-topology-receipt/0.3"
    );
    assert_eq!(
        manifest["scope"]["scanner_profile"],
        "cantor-windows-candidate-topology/0.1"
    );
    assert_eq!(manifest["scope"]["focused_tests"], 16);
    for authority in [
        "filesystem_authority",
        "windows_api_authority",
        "unsafe_authority",
        "clock_authority",
        "persistence_authority",
        "process_authority",
        "network_authority",
        "model_authority",
        "mutation_authority",
        "promotion_authority",
    ] {
        assert_eq!(manifest["scope"][authority], false, "{authority}");
    }
    let artifacts = manifest["artifacts"].as_array().expect("artifact records");
    assert!(artifacts.len() >= 44);
    for artifact in artifacts {
        let path = artifact["path"].as_str().expect("relative artifact path");
        assert!(
            !Path::new(path).is_absolute(),
            "evidence path must be clone-portable: {path}"
        );
        let bytes = fs::read(repository_root.join(path))
            .unwrap_or_else(|error| panic!("artifact {path:?} must read: {error}"));
        assert_eq!(
            artifact["bytes"].as_u64(),
            u64::try_from(bytes.len()).ok(),
            "size mismatch for {path}"
        );
        assert_eq!(
            artifact["sha256"]
                .as_str()
                .expect("artifact hash")
                .to_ascii_lowercase(),
            sha256_bytes(&bytes).value,
            "hash mismatch for {path}"
        );
    }
}
