use std::{fs, path::Path};

use cantor_ecosystem::sha256_file;

#[test]
fn supplied_regular_file_topology_projection_manifest_is_current_and_effect_free() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repository_root = crate_root
        .join("../..")
        .canonicalize()
        .expect("repository root");
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(crate_root.join(
            "evidence/windows_supplied_regular_file_topology_projection_evidence_manifest.json",
        ))
        .expect("supplied topology projection evidence manifest"),
    )
    .expect("manifest JSON");

    assert_eq!(
        manifest["schema"],
        "cantor-windows-supplied-regular-file-topology-projection-evidence-manifest/0.1"
    );
    assert_eq!(
        manifest["evidence_manifest_uuid"],
        "7540ed95-5872-4ff7-9411-db45ef9264b2"
    );
    assert_eq!(
        manifest["authority"]["satisfaction_signature_uuid"],
        "dd8005c2-ae65-4b91-be87-88315a0334c2"
    );
    assert_eq!(
        manifest["authority"]["content_signature_uuid"],
        "44749466-30d8-44e9-85b8-e51f1bafea33"
    );
    assert_eq!(
        manifest["authority"]["topology_forms_signature_uuid"],
        "1edee945-9957-41d7-bd17-0765ec54f5cb"
    );
    assert_eq!(manifest["scope"]["focused_unit_tests"], 11);
    assert_eq!(manifest["scope"]["focused_static_tests"], 1);
    assert_eq!(manifest["scope"]["focused_evidence_tests"], 1);
    assert_eq!(manifest["scope"]["regular_mode_variants"], 2);
    assert_eq!(manifest["scope"]["unsafe_blocks"], 0);
    assert_eq!(manifest["scope"]["windows_api_calls"], 0);
    assert_eq!(manifest["scope"]["cargo_delta"], 0);
    for absent_authority in [
        "physical_path_authority",
        "physical_origin_authority",
        "git_mode_authority",
        "traversal_authority",
        "ordinal_assignment_authority",
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
    assert!(artifacts.len() >= 44);
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
