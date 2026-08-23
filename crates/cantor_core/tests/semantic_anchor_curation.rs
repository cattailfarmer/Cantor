use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use cantor_core::{
    CURATION_NON_AUTHORITY, CURATOR_AUTHORITY_SCOPE, CURATOR_POLICY_PROFILE,
    CURATOR_SELECTION_PROFILE, CURATOR_SOURCE_REQUIREMENT, CuratorDecision,
    CuratorSelectionUseStatus, SemanticAnchorCuratorGrant, SemanticAnchorCuratorPolicy,
    SemanticAnchorCuratorSelectionPayload, SignedSemanticAnchorCuratorSelection,
    curator_selection_payload_bytes, generate_synthetic_semantic_anchor_curation_fixture,
    sha256_bytes, verify_semantic_anchor_curator_selection,
    verify_synthetic_semantic_anchor_curation_fixture,
};
use ed25519_dalek::{Signer, SigningKey};

#[test]
fn checked_synthetic_fixture_is_repeatable_and_exactly_replays() {
    let root = workspace_root();
    let baseline = fs::read(
        root.join("experiments/semantic_anchor_catalogue_slice5a/self_hosted_anchor_evidence.json"),
    )
    .expect("baseline reads");
    let first =
        generate_synthetic_semantic_anchor_curation_fixture(&baseline).expect("fixture generates");
    let second =
        generate_synthetic_semantic_anchor_curation_fixture(&baseline).expect("fixture repeats");
    assert_eq!(first, second);
    assert_eq!(
        first.policy.use_status,
        CuratorSelectionUseStatus::SyntheticFixtureOnly
    );
    assert_eq!(
        first.receipt.use_status,
        CuratorSelectionUseStatus::SyntheticFixtureOnly
    );
    let checked = fs::read(root.join(
        "experiments/semantic_anchor_catalogue_slice5f/synthetic_curator_selection_fixture.json",
    ))
    .expect("checked fixture reads");
    verify_synthetic_semantic_anchor_curation_fixture(&baseline, &checked)
        .expect("checked fixture exactly replays");
}

#[test]
fn supplied_governed_policy_and_signature_produce_bound_receipt() {
    let baseline = baseline();
    let (policy, selection) =
        signed_selection(&baseline, CuratorSelectionUseStatus::GovernedSelection);
    let receipt = verify_semantic_anchor_curator_selection(&baseline, &policy, &selection)
        .expect("governed supplied selection verifies");
    assert_eq!(
        receipt.use_status,
        CuratorSelectionUseStatus::GovernedSelection
    );
    assert!(receipt.signature_verified);
    assert_eq!(receipt.query_name, selection.payload.query_name);
    assert_eq!(
        receipt.candidate_unit_id,
        selection.payload.candidate_unit_id
    );
    assert_eq!(receipt.non_authority_statement, CURATION_NON_AUTHORITY);
}

#[test]
fn signature_candidate_and_status_tamper_refuse() {
    let baseline = baseline();
    let (policy, selection) =
        signed_selection(&baseline, CuratorSelectionUseStatus::GovernedSelection);

    let mut bad_signature = selection.clone();
    bad_signature.signature_hex.replace_range(0..2, "00");
    assert!(verify_semantic_anchor_curator_selection(&baseline, &policy, &bad_signature).is_err());

    let fixture = generate_synthetic_semantic_anchor_curation_fixture(&baseline)
        .expect("synthetic fixture generates");
    let mut wrong_candidate = selection.clone();
    wrong_candidate.payload.candidate_unit_id = fixture.selection.payload.candidate_unit_id;
    assert!(
        verify_semantic_anchor_curator_selection(&baseline, &policy, &wrong_candidate).is_err()
    );

    let mut wrong_status = selection.clone();
    wrong_status.payload.use_status = CuratorSelectionUseStatus::SyntheticFixtureOnly;
    assert!(verify_semantic_anchor_curator_selection(&baseline, &policy, &wrong_status).is_err());
}

#[test]
fn stale_baseline_source_anchor_and_policy_key_refuse() {
    let baseline = baseline();
    let (policy, selection) =
        signed_selection(&baseline, CuratorSelectionUseStatus::GovernedSelection);

    let mut stale = baseline.clone();
    let position = stale
        .iter()
        .position(|byte| *byte == b'a')
        .expect("baseline contains mutable byte");
    stale[position] = b'A';
    assert!(verify_semantic_anchor_curator_selection(&stale, &policy, &selection).is_err());

    let mut wrong_anchor = selection.clone();
    wrong_anchor.payload.selected_source_anchor.byte_start += 1;
    assert!(verify_semantic_anchor_curator_selection(&baseline, &policy, &wrong_anchor).is_err());

    let mut wrong_key = policy.clone();
    wrong_key
        .grants
        .iter_mut()
        .next()
        .expect("grant exists")
        .verifying_key_hex = "00".repeat(32);
    assert!(verify_semantic_anchor_curator_selection(&baseline, &wrong_key, &selection).is_err());
}

#[test]
fn unknown_fields_and_overbound_rationale_refuse() {
    let baseline = baseline();
    let (policy, mut selection) =
        signed_selection(&baseline, CuratorSelectionUseStatus::GovernedSelection);
    selection.payload.rationale = "x".repeat(4_097);
    assert!(verify_semantic_anchor_curator_selection(&baseline, &policy, &selection).is_err());

    let mut duplicate_grant = policy.clone();
    duplicate_grant
        .grants
        .push(duplicate_grant.grants[0].clone());
    let (_, valid_selection) =
        signed_selection(&baseline, CuratorSelectionUseStatus::GovernedSelection);
    assert!(
        verify_semantic_anchor_curator_selection(&baseline, &duplicate_grant, &valid_selection)
            .is_err()
    );

    let fixture = generate_synthetic_semantic_anchor_curation_fixture(&baseline)
        .expect("synthetic fixture generates");
    let mut value = serde_json::to_value(fixture).expect("fixture serializes");
    value
        .as_object_mut()
        .expect("fixture object")
        .insert("unknown".to_owned(), serde_json::json!(true));
    assert!(
        serde_json::from_value::<cantor_core::SyntheticSemanticAnchorCurationFixture>(value)
            .is_err()
    );
}

fn signed_selection(
    baseline_bytes: &[u8],
    use_status: CuratorSelectionUseStatus,
) -> (
    SemanticAnchorCuratorPolicy,
    SignedSemanticAnchorCuratorSelection,
) {
    let baseline: cantor_core::SelfHostedAnchorEvidence =
        serde_json::from_slice(baseline_bytes).expect("baseline parses");
    let query = baseline
        .body
        .queries
        .iter()
        .find(|query| query.name == "cantor")
        .expect("cantor query exists");
    let candidate = query
        .candidates
        .iter()
        .find(|candidate| candidate.exact_requested_expression)
        .expect("exact-expression candidate exists");
    let curator_id =
        cantor_core::SemanticId::new("curator:external_test").expect("curator identity valid");
    let key = SigningKey::from_bytes(&[101_u8; 32]);
    let policy = SemanticAnchorCuratorPolicy {
        profile: CURATOR_POLICY_PROFILE.to_owned(),
        use_status: use_status.clone(),
        baseline_sha256: sha256_bytes(baseline_bytes),
        grants: vec![SemanticAnchorCuratorGrant {
            curator_id: curator_id.clone(),
            verifying_key_hex: encode_hex(&key.verifying_key().to_bytes()),
            allowed_query_names: BTreeSet::from([query.name.clone()]),
            authority_scope: CURATOR_AUTHORITY_SCOPE.to_owned(),
            source_requirement: CURATOR_SOURCE_REQUIREMENT.to_owned(),
        }],
        non_authority_statement: CURATION_NON_AUTHORITY.to_owned(),
    };
    let payload = SemanticAnchorCuratorSelectionPayload {
        profile: CURATOR_SELECTION_PROFILE.to_owned(),
        use_status,
        baseline_sha256: sha256_bytes(baseline_bytes),
        baseline_report_digest: baseline.report_digest,
        curator_id,
        query_name: query.name.clone(),
        candidate_unit_id: candidate.unit_id.clone(),
        selected_source_anchor: candidate.source_anchors[0].clone(),
        decision: CuratorDecision::SelectExactIdentity,
        rationale: "externally supplied governed test selection".to_owned(),
        non_authority_statement: CURATION_NON_AUTHORITY.to_owned(),
    };
    let signature_hex = encode_hex(
        &key.sign(
            &curator_selection_payload_bytes(&payload).expect("payload serializes canonically"),
        )
        .to_bytes(),
    );
    (
        policy,
        SignedSemanticAnchorCuratorSelection {
            payload,
            signature_hex,
        },
    )
}

fn baseline() -> Vec<u8> {
    fs::read(
        workspace_root()
            .join("experiments/semantic_anchor_catalogue_slice5a/self_hosted_anchor_evidence.json"),
    )
    .expect("baseline reads")
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("core crate nested under workspace")
        .to_path_buf()
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
