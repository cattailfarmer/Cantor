use std::{fs, path::Path};

use cantor_core::sha256_bytes;

#[test]
fn windows_platform_preflight_forms_manifest_is_clone_portable_and_effect_free() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest_bytes = fs::read(
        crate_root.join("evidence/windows_platform_preflight_forms_evidence_manifest_0_2.json"),
    )
    .expect("historical evidence manifest");
    assert_eq!(
        sha256_bytes(&manifest_bytes).value,
        "2479ff9d83ee8e8ae2e737786c5625b8e35c56082c004a2b29514ad6e1fccc95"
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&manifest_bytes).expect("manifest JSON");
    assert_eq!(
        manifest["schema"],
        "cantor-windows-platform-preflight-forms-evidence-manifest/0.2"
    );
    assert_eq!(
        manifest["authority"]["satisfaction_signature_uuid"],
        "43ac3353-ea22-4f02-894e-59302e6ef4a5"
    );
    assert_eq!(
        manifest["evidence_manifest_uuid"],
        "e28c0fd9-2fca-4d9e-8f2c-c9556101fc66"
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
        assert!(
            artifact["bytes"].as_u64().is_some(),
            "missing size for {path}"
        );
        assert_eq!(
            artifact["sha256"].as_str().expect("artifact hash").len(),
            64,
            "invalid frozen digest for {path}"
        );
    }
}
