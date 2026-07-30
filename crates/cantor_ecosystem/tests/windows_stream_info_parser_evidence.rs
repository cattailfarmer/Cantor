use std::{fs, path::Path};

use cantor_ecosystem::sha256_file;

#[test]
fn windows_stream_info_parser_manifest_is_current_portable_and_effect_free() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repository_root = crate_root.join("../..").canonicalize().expect("root");
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(crate_root.join("evidence/windows_stream_info_parser_evidence_manifest.json"))
            .expect("manifest"),
    )
    .expect("JSON");
    assert_eq!(
        manifest["schema"],
        "cantor-windows-stream-info-parser-evidence-manifest/0.1"
    );
    assert_eq!(
        manifest["evidence_manifest_uuid"],
        "263b3f53-8f37-4c4d-b465-c92733e95781"
    );
    assert_eq!(manifest["scope"]["unsafe_blocks"], 0);
    assert_eq!(manifest["scope"]["pointer_casts"], 0);
    assert_eq!(manifest["scope"]["windows_api_calls"], 0);
    assert_eq!(manifest["scope"]["complete_enumeration_claim"], false);
    assert_eq!(manifest["scope"]["stream_admission_authority"], false);
    assert_eq!(manifest["scope"]["traversal_authority"], false);
    assert_eq!(manifest["scope"]["physical_claim"], false);
    let artifacts = manifest["artifacts"].as_array().expect("artifacts");
    assert!(artifacts.len() >= 35);
    for artifact in artifacts {
        let path = artifact["path"].as_str().expect("path");
        assert!(!Path::new(path).is_absolute(), "{path}");
        let full = repository_root.join(path);
        let bytes = fs::read(&full).unwrap_or_else(|error| panic!("{path}: {error}"));
        assert_eq!(
            artifact["bytes"].as_u64(),
            Some(bytes.len() as u64),
            "{path}"
        );
        assert_eq!(
            artifact["sha256"]
                .as_str()
                .expect("hash")
                .to_ascii_lowercase(),
            sha256_file(&full).expect("digest"),
            "{path}"
        );
    }
}
