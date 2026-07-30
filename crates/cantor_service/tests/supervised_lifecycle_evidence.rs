use std::{fs, path::Path};

use cantor_core::sha256_bytes;

#[test]
fn supervised_lifecycle_evidence_manifest_hashes_clone_portable_artifacts() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repository_root = crate_root
        .join("../..")
        .canonicalize()
        .expect("repository root must resolve");
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(crate_root.join("evidence/supervised_lifecycle_evidence_manifest.json"))
            .expect("evidence manifest must read"),
    )
    .expect("evidence manifest must decode");
    assert_eq!(
        manifest["schema"],
        "cantor-supervised-local-lifecycle-evidence-manifest/0.1"
    );
    assert_eq!(
        manifest["authority"]["canonical_specification_uuid"],
        "59d4a953-7b78-4c19-b2a1-0e39851d2e4b"
    );
    let artifacts = manifest["artifacts"]
        .as_array()
        .expect("artifact records are required");
    assert!(artifacts.len() >= 28);
    for artifact in artifacts {
        let path = artifact["path"]
            .as_str()
            .expect("artifact path must be text");
        assert!(
            !Path::new(path).is_absolute(),
            "evidence path must remain clone-portable: {path}"
        );
        let bytes = fs::read(repository_root.join(path))
            .unwrap_or_else(|error| panic!("evidence artifact {path:?} must read: {error}"));
        assert_eq!(
            artifact["bytes"].as_u64(),
            u64::try_from(bytes.len()).ok(),
            "size mismatch for {path}"
        );
        assert_eq!(
            artifact["sha256"]
                .as_str()
                .expect("artifact hash must be text")
                .to_ascii_lowercase(),
            sha256_bytes(&bytes).value,
            "hash mismatch for {path}"
        );
    }
}
