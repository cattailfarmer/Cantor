use std::{fs, path::Path};

use cantor_core::sha256_bytes;

#[test]
fn three_run_summary_is_complete_correct_and_materially_better_than_reload() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let summary: serde_json::Value = serde_json::from_slice(
        &fs::read(root.join("artifacts/2026-07-29-three-run-summary.json"))
            .expect("summary must read"),
    )
    .expect("summary must decode");
    assert_eq!(summary["schema"], "cantor-resident-service-evidence/0.1");
    assert_eq!(summary["run_count"], 3);
    assert_eq!(summary["iterations_per_run"], 30);
    assert_eq!(summary["environment_bytes"], 1_145_513);
    assert_eq!(summary["package_count"], 1);
    assert_eq!(summary["correctness_mismatches"], 0);
    assert!(
        summary["ranges_microseconds"]["resident_dispatch"]["median_max"]
            .as_u64()
            .expect("resident median must be numeric")
            < 100
    );
    assert!(
        summary["ranges_microseconds"]["query_round_trip"]["median_max"]
            .as_u64()
            .expect("query median must be numeric")
            < 2_000
    );
    assert!(
        summary["ranges_microseconds"]["restart_preflight"]["median_min"]
            .as_u64()
            .expect("restart median must be numeric")
            > summary["ranges_microseconds"]["resident_dispatch"]["median_max"]
                .as_u64()
                .expect("resident median must be numeric")
    );
    let raw_reports = summary["raw_reports"]
        .as_array()
        .expect("raw reports must be an array");
    assert_eq!(raw_reports.len(), 3);
    for report in raw_reports {
        let path = report["path"]
            .as_str()
            .expect("raw report path must be text");
        assert!(
            !Path::new(path).is_absolute(),
            "raw report paths must remain clone-portable: {path}"
        );
        let repository_root = root
            .join("../..")
            .canonicalize()
            .expect("repository root must resolve");
        let bytes = fs::read(repository_root.join(path))
            .unwrap_or_else(|error| panic!("raw report {path:?} must read: {error}"));
        assert_eq!(
            report["sha256"]
                .as_str()
                .expect("raw report hash must be text")
                .to_ascii_lowercase(),
            sha256_bytes(&bytes).value
        );
    }
}

#[test]
fn evidence_manifest_hashes_every_declared_artifact() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repository_root = root
        .join("../..")
        .canonicalize()
        .expect("repository root must resolve");
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(root.join("artifacts/resident_service_evidence_manifest.json"))
            .expect("evidence manifest must read"),
    )
    .expect("evidence manifest must decode");
    assert_eq!(
        manifest["schema"],
        "cantor-resident-service-evidence-manifest/0.1"
    );
    assert_eq!(
        manifest["authority"]["canonical_specification_uuid"],
        "276ad3fd-d1fa-4b32-9bdd-5cd572bf1ece"
    );
    assert_eq!(
        manifest["authority"]["satisfaction_signature_uuid"],
        "bd09110a-d278-4177-bbcd-d7eb58fef217"
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
            "evidence paths must remain clone-portable: {path}"
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
