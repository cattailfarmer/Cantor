use std::{fs, path::Path};

use cantor_ecosystem::sha256_file;

#[test]
fn supplied_root_topology_projection_manifest_is_current_and_effect_free() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repository_root = crate_root
        .join("../..")
        .canonicalize()
        .expect("repository root");
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(
            crate_root
                .join("evidence/windows_supplied_root_topology_projection_evidence_manifest.json"),
        )
        .expect("supplied root topology projection evidence manifest"),
    )
    .expect("manifest JSON");

    assert_eq!(
        manifest["schema"],
        "cantor-windows-supplied-root-topology-projection-evidence-manifest/0.1"
    );
    assert_eq!(
        manifest["evidence_manifest_uuid"],
        "311a8d59-54a5-42f3-9b0a-244e96c461ee"
    );
    assert_eq!(
        manifest["authority"]["satisfaction_signature_uuid"],
        "6af7c461-07ed-426c-9684-819405223bf6"
    );
    assert_eq!(
        manifest["authority"]["platform_signature_uuid"],
        "61c2b9cf-4608-4e7d-88ae-d674d52640e3"
    );
    assert_eq!(
        manifest["authority"]["stability_signature_uuid"],
        "cbeb4260-0db0-413c-89c6-2ca164775243"
    );
    assert_eq!(
        manifest["authority"]["topology_forms_signature_uuid"],
        "0e2cfacb-8659-41c2-b804-0eb1b49ff5b2"
    );
    assert_eq!(manifest["scope"]["focused_unit_tests"], 11);
    assert_eq!(manifest["scope"]["focused_static_tests"], 1);
    assert_eq!(manifest["scope"]["focused_evidence_tests"], 1);
    for true_gate in [
        "mandatory_preflight_revalidation",
        "mandatory_stability_revalidation",
        "eligible_complete_local_only",
        "exact_entry_reference_gate",
        "exact_whole_identity_gate",
        "exact_dual_component_gate",
        "fixed_root_directory_shape",
        "current_topology_form_validation",
        "output_only_lineage_wrapper",
    ] {
        assert_eq!(
            manifest["scope"][true_gate], true,
            "required gate: {true_gate}"
        );
    }
    assert_eq!(manifest["scope"]["direct_preflight_fragment_input"], false);
    assert_eq!(manifest["scope"]["direct_stable_pair_input"], false);
    assert_eq!(manifest["scope"]["unsafe_blocks"], 0);
    assert_eq!(manifest["scope"]["windows_api_calls"], 0);
    assert_eq!(manifest["scope"]["cargo_delta"], 0);
    for absent_authority in [
        "runtime_origin_authority",
        "physical_root_authority",
        "same_handle_authority",
        "enumeration_authority",
        "traversal_authority",
        "inventory_authority",
        "receipt_authority",
        "admission_authority",
        "mutation_authority",
        "physical_claim",
    ] {
        assert_eq!(
            manifest["scope"][absent_authority], false,
            "authority must remain absent: {absent_authority}"
        );
    }

    let artifacts = manifest["artifacts"].as_array().expect("artifact records");
    assert_eq!(artifacts.len(), 48);
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
