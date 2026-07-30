use std::{fs, path::Path};

use cantor_core::sha256_bytes;

#[test]
fn read_only_live_codex_manifest_hashes_probe_and_clone_portable_artifacts() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repository_root = crate_root
        .join("../..")
        .canonicalize()
        .expect("repository root must resolve");
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(crate_root.join("evidence/read_only_live_codex_evidence_manifest.json"))
            .expect("evidence manifest must read"),
    )
    .expect("evidence manifest must decode");
    assert_eq!(
        manifest["schema"],
        "cantor-read-only-live-codex-evidence-manifest/0.1"
    );
    assert_eq!(
        manifest["authority"]["canonical_specification_uuid"],
        "4090fcfc-b61d-41d4-896e-c9eb88d82409"
    );
    assert_eq!(
        manifest["authority"]["satisfaction_signature_uuid"],
        "49232cc8-86d5-43e6-b709-08b6e1cda884"
    );
    assert_eq!(
        manifest["live_probe"]["profile"],
        "cantor-read-only-live-codex/0.1"
    );
    assert_eq!(manifest["live_probe"]["tool_calls"], 1);
    assert_eq!(manifest["live_probe"]["requested_effects"], 0);
    assert_eq!(manifest["live_probe"]["review"], "accept");
    assert_eq!(manifest["live_probe"]["decision"], "accept");

    let artifacts = manifest["artifacts"]
        .as_array()
        .expect("artifact records are required");
    assert!(artifacts.len() >= 30);
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
