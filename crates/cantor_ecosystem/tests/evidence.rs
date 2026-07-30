use std::{fs, path::Path};

use cantor_core::sha256_bytes;

#[test]
fn supervised_mock_loop_evidence_manifest_hashes_clone_portable_artifacts() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repository_root = crate_root
        .join("../..")
        .canonicalize()
        .expect("repository root must resolve");
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(crate_root.join("evidence/supervised_mock_loop_evidence_manifest.json"))
            .expect("evidence manifest must read"),
    )
    .expect("evidence manifest must decode");
    assert_eq!(
        manifest["schema"],
        "cantor-supervised-mock-loop-evidence-manifest/0.1"
    );
    assert_eq!(
        manifest["authority"]["canonical_specification_uuid"],
        "50f6f41c-f35b-4844-93cb-38593db6acc0"
    );
    assert_eq!(
        manifest["authority"]["satisfaction_signature_uuid"],
        "497849e2-8156-41e4-a76d-d679b5a3f2ed"
    );
    assert_eq!(
        manifest["deterministic_fixture_outcome_sha256"],
        "2ef72ed3edf4bf58e80e24c5d86bea18572ba10324e27e02aacc63569cd78b3c"
    );
    let artifacts = manifest["artifacts"]
        .as_array()
        .expect("artifact records are required");
    assert!(artifacts.len() >= 35);
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
