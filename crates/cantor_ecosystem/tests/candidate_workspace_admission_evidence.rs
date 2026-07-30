use std::{fs, path::Path};

use cantor_core::sha256_bytes;

#[test]
fn candidate_workspace_admission_manifest_is_clone_portable_and_effect_free() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repository_root = crate_root
        .join("../..")
        .canonicalize()
        .expect("repository root");
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(crate_root.join("evidence/candidate_workspace_admission_evidence_manifest.json"))
            .expect("evidence manifest"),
    )
    .expect("manifest JSON");
    assert_eq!(
        manifest["schema"],
        "cantor-candidate-workspace-admission-evidence-manifest/0.1"
    );
    assert_eq!(
        manifest["authority"]["satisfaction_signature_uuid"],
        "62600061-8479-458d-a3e1-121e315bff24"
    );
    assert_eq!(manifest["probe"]["admitted"], true);
    assert_eq!(manifest["probe"]["repeated_receipt_equal"], true);
    assert_eq!(manifest["probe"]["principal_clean_before_and_after"], true);
    assert_eq!(manifest["probe"]["candidate_clean_before_and_after"], true);
    assert_eq!(manifest["probe"]["process_count"], 12);
    assert_eq!(manifest["probe"]["mutation_authority"], false);
    assert_eq!(manifest["probe"]["promotion_authority"], false);

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
