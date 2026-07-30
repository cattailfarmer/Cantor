use std::{fs, path::Path};

use cantor_core::sha256_bytes;

#[test]
fn phase3_machine_forms_manifest_is_clone_portable_and_effect_free() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repository_root = crate_root
        .join("../..")
        .canonicalize()
        .expect("repository root");
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(crate_root.join("evidence/phase3_machine_forms_evidence_manifest.json"))
            .expect("evidence manifest"),
    )
    .expect("manifest JSON");
    assert_eq!(
        manifest["schema"],
        "cantor-phase3-machine-forms-evidence-manifest/0.1"
    );
    assert_eq!(
        manifest["authority"]["satisfaction_signature_uuid"],
        "ae44deed-29c7-4a6a-96d1-1a0091539575"
    );
    assert_eq!(manifest["scope"]["focused_tests"], 8);
    for authority in [
        "filesystem_authority",
        "process_authority",
        "network_authority",
        "model_authority",
        "mutation_authority",
        "seal_authority",
        "test_execution_authority",
        "promotion_authority",
    ] {
        assert_eq!(manifest["scope"][authority], false, "{authority}");
    }

    let artifacts = manifest["artifacts"].as_array().expect("artifact records");
    assert!(artifacts.len() >= 30);
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
