use std::{fs, path::Path};

use cantor_ecosystem::sha256_file;

#[test]
fn windows_supplied_content_digest_manifest_is_current_portable_and_effect_free() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repository_root = crate_root
        .join("../..")
        .canonicalize()
        .expect("repository root");
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(
            crate_root.join("evidence/windows_supplied_content_digest_evidence_manifest.json"),
        )
        .expect("supplied-content digest evidence manifest"),
    )
    .expect("manifest JSON");

    assert_eq!(
        manifest["schema"],
        "cantor-windows-supplied-content-digest-evidence-manifest/0.1"
    );
    assert_eq!(
        manifest["evidence_manifest_uuid"],
        "818ee9be-cc73-465e-9659-8b5e547e4678"
    );
    assert_eq!(
        manifest["authority"]["satisfaction_signature_uuid"],
        "44749466-30d8-44e9-85b8-e51f1bafea33"
    );
    assert_eq!(
        manifest["authority"]["stability_signature_uuid"],
        "cbeb4260-0db0-413c-89c6-2ca164775243"
    );
    assert_eq!(manifest["scope"]["focused_unit_tests"], 11);
    assert_eq!(manifest["scope"]["focused_static_tests"], 1);
    assert_eq!(manifest["scope"]["known_sha256_vectors"], 3);
    assert_eq!(manifest["scope"]["unsafe_blocks"], 0);
    assert_eq!(manifest["scope"]["windows_api_calls"], 0);
    assert_eq!(manifest["scope"]["cargo_delta"], 0);
    for absent_authority in [
        "physical_byte_origin_authority",
        "physical_read_authority",
        "temporal_order_authority",
        "same_handle_authority",
        "filesystem_authority",
        "path_authority",
        "traversal_authority",
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
