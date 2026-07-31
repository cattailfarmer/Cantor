use std::{fs, path::Path};

use cantor_ecosystem::sha256_file;

#[test]
fn windows_supplied_entry_stability_manifest_is_current_portable_and_effect_free() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repository_root = crate_root
        .join("../..")
        .canonicalize()
        .expect("repository root");
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(
            crate_root.join("evidence/windows_supplied_entry_stability_evidence_manifest.json"),
        )
        .expect("supplied-entry stability evidence manifest"),
    )
    .expect("manifest JSON");

    assert_eq!(
        manifest["schema"],
        "cantor-windows-supplied-entry-stability-evidence-manifest/0.1"
    );
    assert_eq!(
        manifest["evidence_manifest_uuid"],
        "7c52a0e7-fda0-48d6-8daf-bf9f0e59fad8"
    );
    assert_eq!(
        manifest["authority"]["satisfaction_signature_uuid"],
        "cbeb4260-0db0-413c-89c6-2ca164775243"
    );
    assert_eq!(
        manifest["authority"]["assembly_signature_uuid"],
        "4b2bf473-b10e-4ca6-a39b-f68c3a7f3719"
    );
    assert_eq!(manifest["scope"]["compared_fields"], 8);
    assert_eq!(manifest["scope"]["unsafe_blocks"], 0);
    assert_eq!(manifest["scope"]["windows_api_calls"], 0);
    assert_eq!(manifest["scope"]["cargo_delta"], 0);
    for absent_authority in [
        "physical_query_authority",
        "temporal_order_authority",
        "same_handle_authority",
        "filesystem_authority",
        "content_read_authority",
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
    assert!(artifacts.len() >= 40);
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
