use std::{fs, path::Path};

use cantor_ecosystem::sha256_file;

#[test]
fn runtime_evidence_manifest_is_current_clone_portable_and_bounded() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repository_root = crate_root
        .join("../..")
        .canonicalize()
        .expect("repository root");
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(
            crate_root.join("evidence/windows_platform_preflight_runtime_evidence_manifest.json"),
        )
        .expect("runtime evidence manifest"),
    )
    .expect("manifest JSON");

    assert_eq!(
        manifest["schema"],
        "cantor-windows-platform-preflight-runtime-evidence-manifest/0.1"
    );
    assert_eq!(
        manifest["evidence_manifest_uuid"],
        "aec65378-786a-4aeb-96a4-6d7b13ca6a58"
    );
    assert_eq!(
        manifest["authority"]["satisfaction_signature_uuid"],
        "61c2b9cf-4608-4e7d-88ae-d674d52640e3"
    );
    assert_eq!(manifest["scope"]["physical_local_claim"], true);
    assert_eq!(manifest["scope"]["physical_remote_claim"], false);
    assert_eq!(manifest["scope"]["scanner_authority"], false);
    assert_eq!(manifest["scope"]["receipt_authority"], false);
    assert_eq!(manifest["scope"]["unsafe_blocks"], 6);
    assert_eq!(manifest["scope"]["safety_comments"], 6);
    assert_eq!(
        manifest["physical"]["complete_local_observation_sha256"],
        "3B52E87929AC4C42D640C7C29F70BA88D43A6417C31CEB361F59172803924D46"
    );

    let artifacts = manifest["artifacts"].as_array().expect("artifact records");
    assert!(artifacts.len() >= 50);
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
            sha256_file(&repository_root.join(path)).expect("artifact digest"),
            "hash mismatch for {path}"
        );
    }
}
