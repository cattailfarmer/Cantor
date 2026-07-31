use std::{fs, path::Path};

use cantor_ecosystem::sha256_file;

#[test]
fn supplied_directory_topology_projection_manifest_is_current_and_effect_free() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repository_root = crate_root
        .join("../..")
        .canonicalize()
        .expect("repository root");
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(crate_root.join(
            "evidence/windows_supplied_directory_topology_projection_evidence_manifest.json",
        ))
        .expect("supplied directory topology projection evidence manifest"),
    )
    .expect("manifest JSON");

    assert_eq!(
        manifest["schema"],
        "cantor-windows-supplied-directory-topology-projection-evidence-manifest/0.1"
    );
    assert_eq!(
        manifest["evidence_manifest_uuid"],
        "46081753-f671-4042-a9e1-cb337b7aa103"
    );
    assert_eq!(
        manifest["authority"]["satisfaction_signature_uuid"],
        "2f24b78e-90ab-4413-9189-2c2bbcf65187"
    );
    assert_eq!(
        manifest["authority"]["stability_signature_uuid"],
        "cbeb4260-0db0-413c-89c6-2ca164775243"
    );
    assert_eq!(
        manifest["authority"]["topology_forms_signature_uuid"],
        "0e2cfacb-8659-41c2-b804-0eb1b49ff5b2"
    );
    assert_eq!(manifest["scope"]["focused_unit_tests"], 11);
    assert_eq!(manifest["scope"]["focused_static_tests"], 1);
    assert_eq!(manifest["scope"]["focused_evidence_tests"], 1);
    assert_eq!(manifest["scope"]["mandatory_stability_revalidation"], true);
    assert_eq!(manifest["scope"]["direct_stable_pair_input"], false);
    assert_eq!(manifest["scope"]["fixed_directory_mode"], true);
    assert_eq!(manifest["scope"]["absent_length"], true);
    assert_eq!(manifest["scope"]["absent_content_digest"], true);
    assert_eq!(manifest["scope"]["unsafe_blocks"], 0);
    assert_eq!(manifest["scope"]["windows_api_calls"], 0);
    assert_eq!(manifest["scope"]["cargo_delta"], 0);
    for absent_authority in [
        "physical_path_authority",
        "enumeration_authority",
        "traversal_authority",
        "inventory_authority",
        "stream_completeness_authority",
        "receipt_authority",
        "admission_authority",
        "mutation_authority",
        "physical_claim",
    ] {
        assert_eq!(
            manifest["scope"][absent_authority], false,
            "authority must remain absent: {absent_authority}"
        );
    }

    let artifacts = manifest["artifacts"].as_array().expect("artifact records");
    assert_eq!(artifacts.len(), 45);
    for artifact in artifacts {
        let path = artifact["path"].as_str().expect("relative path");
        assert!(!Path::new(path).is_absolute(), "absolute path: {path}");
        let full_path = repository_root.join(path);
        let bytes = fs::read(&full_path)
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
            sha256_file(&full_path).expect("artifact digest"),
            "hash mismatch for {path}"
        );
    }
}
