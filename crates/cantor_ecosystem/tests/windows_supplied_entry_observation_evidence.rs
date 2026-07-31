use std::{fs, path::Path};

use cantor_ecosystem::sha256_file;

#[test]
fn windows_supplied_entry_observation_manifest_is_current_portable_and_effect_free() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repository_root = crate_root
        .join("../..")
        .canonicalize()
        .expect("repository root");
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(
            crate_root.join("evidence/windows_supplied_entry_observation_evidence_manifest.json"),
        )
        .expect("supplied-entry evidence manifest"),
    )
    .expect("manifest JSON");

    assert_eq!(
        manifest["schema"],
        "cantor-windows-supplied-entry-observation-evidence-manifest/0.1"
    );
    assert_eq!(
        manifest["evidence_manifest_uuid"],
        "2973edde-d2dc-4d74-86ce-7e337ba7e614"
    );
    assert_eq!(
        manifest["authority"]["satisfaction_signature_uuid"],
        "4b2bf473-b10e-4ca6-a39b-f68c3a7f3719"
    );
    assert_eq!(
        manifest["authority"]["entry_policy_signature_uuid"],
        "fbb835f2-5ab6-4362-a392-5d72692f8d1c"
    );
    assert_eq!(
        manifest["authority"]["stream_parser_signature_uuid"],
        "f8ec9aa9-cf1e-46e9-8eeb-ab63e91332ee"
    );
    assert_eq!(manifest["scope"]["required_record_classes"], 5);
    assert_eq!(manifest["scope"]["unsafe_blocks"], 0);
    assert_eq!(manifest["scope"]["windows_api_calls"], 0);
    assert_eq!(manifest["scope"]["cargo_delta"], 0);
    assert_eq!(manifest["scope"]["physical_query_authority"], false);
    assert_eq!(manifest["scope"]["filesystem_authority"], false);
    assert_eq!(manifest["scope"]["traversal_authority"], false);
    assert_eq!(manifest["scope"]["receipt_authority"], false);
    assert_eq!(manifest["scope"]["mutation_authority"], false);
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
