use std::{fs, path::Path};

use cantor_ecosystem::sha256_file;

#[test]
fn windows_entry_policy_manifest_is_current_clone_portable_and_effect_free() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repository_root = crate_root
        .join("../..")
        .canonicalize()
        .expect("repository root");
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(crate_root.join("evidence/windows_entry_policy_evidence_manifest.json"))
            .expect("entry-policy evidence manifest"),
    )
    .expect("manifest JSON");

    assert_eq!(
        manifest["schema"],
        "cantor-windows-entry-policy-evidence-manifest/0.1"
    );
    assert_eq!(
        manifest["evidence_manifest_uuid"],
        "be4b80ed-da4c-4363-b075-b826c0c76fab"
    );
    assert_eq!(
        manifest["authority"]["satisfaction_signature_uuid"],
        "fbb835f2-5ab6-4362-a392-5d72692f8d1c"
    );
    assert_eq!(
        manifest["authority"]["superseded_signature_uuid"],
        "554e84a7-988c-4c86-b67d-45958ab7166c"
    );
    assert_eq!(manifest["scope"]["unsafe_blocks"], 0);
    assert_eq!(manifest["scope"]["windows_api_calls"], 0);
    assert_eq!(manifest["scope"]["cargo_delta"], 0);
    assert_eq!(manifest["scope"]["filesystem_authority"], false);
    assert_eq!(manifest["scope"]["traversal_authority"], false);
    assert_eq!(manifest["scope"]["receipt_authority"], false);
    assert_eq!(manifest["scope"]["physical_claim"], false);

    let artifacts = manifest["artifacts"].as_array().expect("artifact records");
    assert!(artifacts.len() >= 35);
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
