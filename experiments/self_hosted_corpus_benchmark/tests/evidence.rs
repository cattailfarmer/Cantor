use std::fs;
use std::path::Path;

use cantor_core::sha256_bytes;

#[test]
fn tracked_three_run_summary_has_complete_zero_mismatch_shape() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let summary: serde_json::Value = serde_json::from_slice(
        &fs::read(root.join("artifacts/2026-07-29-three-run-summary.json"))
            .expect("tracked summary must read"),
    )
    .expect("tracked summary must decode");
    assert_eq!(summary["profile"], "cantor-self-hosted-corpus-evidence/0.1");
    assert_eq!(summary["run_count"], 3);
    assert_eq!(summary["iterations_per_run"], 30);
    assert_eq!(summary["source_count"], 3);
    assert_eq!(summary["unit_count"], 417);
    assert_eq!(summary["relation_count"], 360);
    assert_eq!(summary["correctness_mismatches"], 0);
    for measurement in [
        "parse_lower",
        "compile_signed_package",
        "full_build_preflight",
        "environment_load",
        "direct_query",
        "prepared_hit",
    ] {
        let range = &summary["ranges_microseconds"][measurement];
        let median_min = range["median_min"]
            .as_f64()
            .expect("median minimum must be numeric");
        let median_max = range["median_max"]
            .as_f64()
            .expect("median maximum must be numeric");
        assert!(median_min > 0.0);
        assert!(median_max >= median_min);
    }
    assert_eq!(
        summary["raw_reports"]
            .as_object()
            .expect("raw report map is required")
            .len(),
        3
    );
}

#[test]
fn evidence_manifest_hashes_every_declared_artifact() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repository_root = root
        .join("../..")
        .canonicalize()
        .expect("repository root must resolve");
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(root.join("artifacts/self_hosted_corpus_evidence_manifest.json"))
            .expect("evidence manifest must read"),
    )
    .expect("evidence manifest must decode");
    assert_eq!(
        manifest["schema"],
        "cantor-self-hosted-corpus-evidence-manifest/0.1"
    );
    assert_eq!(
        manifest["authority"]["canonical_specification_uuid"],
        "470b328b-0b4c-432b-9e7b-b7d84a1cca0e"
    );
    assert_eq!(
        manifest["authority"]["satisfaction_signature_uuid"],
        "74f2cb02-84e4-45b2-98ca-1883c9e5d54d"
    );
    let artifacts = manifest["artifacts"]
        .as_array()
        .expect("artifact records are required");
    assert!(artifacts.len() >= 25);
    for artifact in artifacts {
        let path = artifact["path"]
            .as_str()
            .expect("artifact path must be text");
        assert!(
            !Path::new(path).is_absolute(),
            "evidence paths must remain clone-portable: {path}"
        );
        let bytes = fs::read(repository_root.join(path))
            .unwrap_or_else(|error| panic!("evidence artifact {path:?} must be readable: {error}"));
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
