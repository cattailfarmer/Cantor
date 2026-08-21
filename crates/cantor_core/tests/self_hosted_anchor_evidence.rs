use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use cantor_core::{
    SelfHostedAnchorEvidence, SopCorpusManifest, generate_self_hosted_anchor_evidence,
    validate_self_hosted_anchor_evidence_form, verify_self_hosted_anchor_evidence,
};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

#[test]
fn tracked_evidence_is_repeatable_complete_and_matches_checked_json() {
    let manifest = workspace_root().join("corpus/self_hosted/corpus.json");
    let first = generate_self_hosted_anchor_evidence(&manifest).expect("tracked replay succeeds");
    let second = generate_self_hosted_anchor_evidence(&manifest).expect("repeat replay succeeds");
    assert_eq!(first, second);
    assert_eq!(first.body.source_count, 3);
    assert_eq!(first.body.package_count, 1);
    assert_eq!(first.body.semantic_unit_count, 417);
    assert_eq!(first.body.relation_count, 360);
    assert_eq!(first.body.catalogue_identity_count, 417);
    assert_eq!(first.body.queries.len(), 3);
    assert_eq!(first.body.scanner_authority_project, "cantor");
    assert_eq!(
        first.body.scanner_purpose,
        "resolve governed Cantor meaning"
    );
    assert_eq!(first.body.scanner_operation, "read");
    assert!(first.body.proof_complete);
    assert!(first.body.queries.iter().all(|query| {
        query.scanner_candidate_count
            == query.eligible_count
                + query.ambiguous_count
                + query.unknown_count
                + query.excluded_count
                + query.contradicted_count
                + query.stale_count
                + query.unauthorized_count
                + query.unresolved_count
                + query.clipped_count
    }));
    let checked = fs::read(
        workspace_root()
            .join("experiments/semantic_anchor_catalogue_slice5a/self_hosted_anchor_evidence.json"),
    )
    .expect("checked evidence reads");
    verify_self_hosted_anchor_evidence(&manifest, &checked).expect("checked evidence replays");
}

#[test]
fn strict_form_and_digest_refuse_unknown_fields_and_tamper() {
    let manifest = workspace_root().join("corpus/self_hosted/corpus.json");
    let evidence =
        generate_self_hosted_anchor_evidence(&manifest).expect("tracked replay succeeds");
    let mut tampered = evidence.clone();
    tampered.body.semantic_unit_count += 1;
    assert!(validate_self_hosted_anchor_evidence_form(&tampered).is_err());

    let mut value = serde_json::to_value(&evidence).expect("evidence serializes");
    value
        .as_object_mut()
        .expect("report is object")
        .insert("unknown_field".to_owned(), serde_json::json!(true));
    assert!(serde_json::from_value::<SelfHostedAnchorEvidence>(value).is_err());
}

#[test]
fn governed_source_mutation_changes_report_identity() {
    let root = workspace_root();
    let original_manifest = root.join("corpus/self_hosted/corpus.json");
    let mut manifest: SopCorpusManifest =
        serde_json::from_slice(&fs::read(&original_manifest).expect("manifest reads"))
            .expect("manifest parses");
    let temporary = temporary_directory();
    for document in &manifest.documents {
        let target = temporary.join(&document.path);
        fs::create_dir_all(target.parent().expect("document has parent"))
            .expect("temporary source parent creates");
        fs::copy(root.join(&document.path), target).expect("governed source copies");
    }
    manifest.source_root = temporary.to_string_lossy().into_owned();
    let temporary_manifest = temporary.join("corpus.json");
    fs::write(
        &temporary_manifest,
        serde_json::to_vec_pretty(&manifest).expect("manifest serializes"),
    )
    .expect("temporary manifest writes");
    let before = generate_self_hosted_anchor_evidence(&temporary_manifest)
        .expect("temporary corpus generates");
    let changed_path = temporary.join(&manifest.documents[0].path);
    let mut bytes = fs::read(&changed_path).expect("temporary source reads");
    let position = bytes
        .iter()
        .position(|byte| *byte == b'a')
        .expect("fixture contains mutable byte");
    bytes[position] = b'A';
    fs::write(changed_path, bytes).expect("temporary source mutates");
    if let Ok(after) = generate_self_hosted_anchor_evidence(&temporary_manifest) {
        assert_ne!(before.report_digest, after.report_digest);
    }
    fs::remove_dir_all(temporary).expect("temporary fixture removes");
}

#[test]
fn manifest_bounds_refuse_before_corpus_work() {
    let root = workspace_root();
    let original = root.join("corpus/self_hosted/corpus.json");
    let mut manifest: SopCorpusManifest =
        serde_json::from_slice(&fs::read(original).expect("manifest reads"))
            .expect("manifest parses");
    let template = manifest.queries[0].clone();
    manifest.queries = (0..129)
        .map(|ordinal| {
            let mut value = template.clone();
            value.name = format!("bounded-{ordinal}");
            value
        })
        .collect();
    let temporary = temporary_directory();
    let path = temporary.join("overbound.json");
    fs::write(
        &path,
        serde_json::to_vec(&manifest).expect("manifest serializes"),
    )
    .expect("overbound manifest writes");
    let fault = generate_self_hosted_anchor_evidence(&path).expect_err("overbound queries refuse");
    assert!(fault.contains("query count"));
    fs::remove_dir_all(temporary).expect("temporary fixture removes");
}

#[test]
fn verifier_cli_accepts_bare_output_filename_and_replays_it() {
    let temporary = temporary_directory();
    let manifest = workspace_root().join("corpus/self_hosted/corpus.json");
    let binary = env!("CARGO_BIN_EXE_cantor-self-hosted-anchor-evidence");
    let generated = Command::new(binary)
        .current_dir(&temporary)
        .arg(&manifest)
        .arg("evidence.json")
        .output()
        .expect("generator CLI runs");
    assert!(
        generated.status.success(),
        "{}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let verified = Command::new(binary)
        .current_dir(&temporary)
        .arg("--verify")
        .arg(&manifest)
        .arg("evidence.json")
        .output()
        .expect("verifier CLI runs");
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stderr)
    );
    fs::remove_dir_all(temporary).expect("temporary fixture removes");
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("core crate is nested under workspace root")
        .to_path_buf()
}

fn temporary_directory() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "cantor-slice5a-{}-{}",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&path).expect("temporary directory creates");
    path
}
