use std::{fs, path::Path};

use cantor_core::sha256_bytes;

#[test]
fn windows_platform_preflight_forms_manifest_is_clone_portable_and_effect_free() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repository_root = crate_root
        .join("../..")
        .canonicalize()
        .expect("repository root");
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(
            crate_root.join("evidence/windows_platform_preflight_forms_evidence_manifest.json"),
        )
        .expect("evidence manifest"),
    )
    .expect("manifest JSON");
    assert_eq!(
        manifest["schema"],
        "cantor-windows-platform-preflight-forms-evidence-manifest/0.2"
    );
    assert_eq!(
        manifest["authority"]["satisfaction_signature_uuid"],
        "43ac3353-ea22-4f02-894e-59302e6ef4a5"
    );
    assert_eq!(
        manifest["scope"]["request_profile"],
        "cantor-windows-platform-preflight-request/0.1"
    );
    assert_eq!(
        manifest["scope"]["result_profile"],
        "cantor-windows-platform-preflight/0.2"
    );
    assert_eq!(manifest["scope"]["outcomes"], 4);
    assert_eq!(manifest["scope"]["observation_fault_classes"], 3);
    assert_eq!(manifest["scope"]["focused_tests"], 12);
    assert_eq!(manifest["scope"]["windows_api_calls"], 0);
    assert_eq!(manifest["scope"]["unsafe_blocks"], 0);
    assert_eq!(manifest["scope"]["cargo_delta"], 0);
    assert_eq!(manifest["scope"]["filesystem_authority"], false);
    assert_eq!(manifest["scope"]["scanner_authority"], false);
    assert_eq!(manifest["scope"]["receipt_authority"], false);
    assert_eq!(manifest["scope"]["physical_claim"], false);

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
