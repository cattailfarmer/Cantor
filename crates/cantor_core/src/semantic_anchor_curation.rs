//! Provider-free verification for externally governed Semantic Anchor curator selections.

use std::collections::BTreeSet;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::{
    CandidateEligibility, ContentDigest, SelfHostedAnchorEvidence, SemanticId, SourceAnchor,
    sha256_bytes, sha256_digest, validate_self_hosted_anchor_evidence_form,
};

pub const CURATOR_POLICY_PROFILE: &str = "cantor-semantic-anchor-curator-policy/0.1";
pub const CURATOR_SELECTION_PROFILE: &str = "cantor-semantic-anchor-curator-selection/0.1";
pub const CURATOR_RECEIPT_PROFILE: &str = "cantor-semantic-anchor-curator-receipt/0.1";
pub const SYNTHETIC_CURATION_FIXTURE_PROFILE: &str =
    "cantor-semantic-anchor-synthetic-curation-fixture/0.1";
pub const CURATOR_AUTHORITY_SCOPE: &str = "semantic_anchor_exact_identity_curation";
pub const CURATOR_SOURCE_REQUIREMENT: &str = "selected_candidate_source_anchor";
pub const CURATION_NON_AUTHORITY: &str = "Signature verification proves payload integrity and possession of a policy-pinned key. The caller must independently prove policy governance. This receipt grants no semantic truth, training, execution, permission, safety, or effect authority.";
pub const SYNTHETIC_CURATION_NON_AUTHORITY: &str = "This deterministic synthetic fixture proves protocol mechanics only. It is not a governed curator policy or real target selection and grants no semantic truth, training, execution, permission, safety, or effect authority.";
pub const MAX_CURATOR_GRANTS: usize = 64;
pub const MAX_ALLOWED_QUERIES: usize = 128;
pub const MAX_RATIONALE_BYTES: usize = 4_096;
pub const MAX_CURATION_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CuratorSelectionUseStatus {
    GovernedSelection,
    SyntheticFixtureOnly,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CuratorDecision {
    SelectExactIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticAnchorCuratorGrant {
    pub curator_id: SemanticId,
    pub verifying_key_hex: String,
    pub allowed_query_names: BTreeSet<String>,
    pub authority_scope: String,
    pub source_requirement: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticAnchorCuratorPolicy {
    pub profile: String,
    pub use_status: CuratorSelectionUseStatus,
    pub baseline_sha256: ContentDigest,
    pub grants: Vec<SemanticAnchorCuratorGrant>,
    pub non_authority_statement: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticAnchorCuratorSelectionPayload {
    pub profile: String,
    pub use_status: CuratorSelectionUseStatus,
    pub baseline_sha256: ContentDigest,
    pub baseline_report_digest: ContentDigest,
    pub curator_id: SemanticId,
    pub query_name: String,
    pub candidate_unit_id: SemanticId,
    pub selected_source_anchor: SourceAnchor,
    pub decision: CuratorDecision,
    pub rationale: String,
    pub non_authority_statement: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedSemanticAnchorCuratorSelection {
    pub payload: SemanticAnchorCuratorSelectionPayload,
    pub signature_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedSemanticAnchorCuratorSelection {
    pub profile: String,
    pub use_status: CuratorSelectionUseStatus,
    pub baseline_sha256: ContentDigest,
    pub baseline_report_digest: ContentDigest,
    pub selection_digest: ContentDigest,
    pub curator_id: SemanticId,
    pub authority_scope: String,
    pub query_name: String,
    pub candidate_unit_id: SemanticId,
    pub selected_preferred_expression: String,
    pub selected_source_anchor: SourceAnchor,
    pub signature_verified: bool,
    pub non_authority_statement: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyntheticSemanticAnchorCurationFixture {
    pub profile: String,
    pub policy: SemanticAnchorCuratorPolicy,
    pub selection: SignedSemanticAnchorCuratorSelection,
    pub receipt: VerifiedSemanticAnchorCuratorSelection,
    pub non_authority_statement: String,
}

pub fn curator_selection_payload_bytes(
    payload: &SemanticAnchorCuratorSelectionPayload,
) -> Result<Vec<u8>, String> {
    validate_selection_payload_form(payload)?;
    serde_json::to_vec(payload).map_err(|error| error.to_string())
}

pub fn verify_semantic_anchor_curator_selection(
    baseline_bytes: &[u8],
    policy: &SemanticAnchorCuratorPolicy,
    selection: &SignedSemanticAnchorCuratorSelection,
) -> Result<VerifiedSemanticAnchorCuratorSelection, String> {
    if baseline_bytes.is_empty() || baseline_bytes.len() > MAX_CURATION_BYTES {
        return Err("curation baseline byte bound differs".to_owned());
    }
    validate_curator_policy_form(policy)?;
    validate_selection_payload_form(&selection.payload)?;
    let baseline: SelfHostedAnchorEvidence =
        serde_json::from_slice(baseline_bytes).map_err(|error| error.to_string())?;
    validate_self_hosted_anchor_evidence_form(&baseline)?;
    let baseline_sha256 = sha256_bytes(baseline_bytes);
    if policy.baseline_sha256 != baseline_sha256
        || selection.payload.baseline_sha256 != baseline_sha256
        || selection.payload.baseline_report_digest != baseline.report_digest
        || selection.payload.use_status != policy.use_status
    {
        return Err("curation baseline policy or status binding differs".to_owned());
    }
    let grant = policy
        .grants
        .iter()
        .find(|grant| grant.curator_id == selection.payload.curator_id)
        .ok_or("curator identity is not granted by supplied policy")?;
    if !grant
        .allowed_query_names
        .contains(&selection.payload.query_name)
    {
        return Err("curator grant does not include selected query".to_owned());
    }
    let query = baseline
        .body
        .queries
        .iter()
        .find(|query| query.name == selection.payload.query_name)
        .ok_or("selected query is absent from exact baseline")?;
    let candidate = query
        .candidates
        .iter()
        .find(|candidate| candidate.unit_id == selection.payload.candidate_unit_id)
        .ok_or("selected candidate is absent from exact query dossier")?;
    if candidate.eligibility != CandidateEligibility::Ambiguous {
        return Err("selected candidate is not an explicit ambiguous curation prospect".to_owned());
    }
    if !candidate
        .source_anchors
        .contains(&selection.payload.selected_source_anchor)
    {
        return Err("selected source anchor is absent from exact candidate dossier".to_owned());
    }
    let key = decode_fixed_hex::<32>(&grant.verifying_key_hex, "curator verifying key")?;
    let verifying_key = VerifyingKey::from_bytes(&key).map_err(|error| error.to_string())?;
    let signature_bytes = decode_fixed_hex::<64>(&selection.signature_hex, "curator signature")?;
    let signature = Signature::from_bytes(&signature_bytes);
    let payload_bytes = curator_selection_payload_bytes(&selection.payload)?;
    verifying_key
        .verify_strict(&payload_bytes, &signature)
        .map_err(|error| format!("curator signature refused: {error}"))?;
    let selection_digest =
        sha256_digest(&selection.payload).map_err(|error| format!("{error:?}"))?;
    Ok(VerifiedSemanticAnchorCuratorSelection {
        profile: CURATOR_RECEIPT_PROFILE.to_owned(),
        use_status: selection.payload.use_status.clone(),
        baseline_sha256,
        baseline_report_digest: baseline.report_digest,
        selection_digest,
        curator_id: selection.payload.curator_id.clone(),
        authority_scope: grant.authority_scope.clone(),
        query_name: query.name.clone(),
        candidate_unit_id: candidate.unit_id.clone(),
        selected_preferred_expression: candidate.preferred_expression.clone(),
        selected_source_anchor: selection.payload.selected_source_anchor.clone(),
        signature_verified: true,
        non_authority_statement: CURATION_NON_AUTHORITY.to_owned(),
    })
}

pub fn generate_synthetic_semantic_anchor_curation_fixture(
    baseline_bytes: &[u8],
) -> Result<SyntheticSemanticAnchorCurationFixture, String> {
    let baseline: SelfHostedAnchorEvidence =
        serde_json::from_slice(baseline_bytes).map_err(|error| error.to_string())?;
    validate_self_hosted_anchor_evidence_form(&baseline)?;
    let query = baseline
        .body
        .queries
        .first()
        .ok_or("synthetic fixture baseline lacks query")?;
    let candidate = query
        .candidates
        .iter()
        .find(|candidate| candidate.exact_requested_expression)
        .or_else(|| query.candidates.first())
        .ok_or("synthetic fixture query lacks candidate")?;
    let selected_source_anchor = candidate
        .source_anchors
        .first()
        .cloned()
        .ok_or("synthetic fixture candidate lacks source anchor")?;
    let signing_key = SigningKey::from_bytes(&[83_u8; 32]);
    let curator_id = semantic_id("curator:synthetic_fixture_only")?;
    let baseline_sha256 = sha256_bytes(baseline_bytes);
    let policy = SemanticAnchorCuratorPolicy {
        profile: CURATOR_POLICY_PROFILE.to_owned(),
        use_status: CuratorSelectionUseStatus::SyntheticFixtureOnly,
        baseline_sha256: baseline_sha256.clone(),
        grants: vec![SemanticAnchorCuratorGrant {
            curator_id: curator_id.clone(),
            verifying_key_hex: encode_hex(&signing_key.verifying_key().to_bytes()),
            allowed_query_names: BTreeSet::from([query.name.clone()]),
            authority_scope: CURATOR_AUTHORITY_SCOPE.to_owned(),
            source_requirement: CURATOR_SOURCE_REQUIREMENT.to_owned(),
        }],
        non_authority_statement: CURATION_NON_AUTHORITY.to_owned(),
    };
    let payload = SemanticAnchorCuratorSelectionPayload {
        profile: CURATOR_SELECTION_PROFILE.to_owned(),
        use_status: CuratorSelectionUseStatus::SyntheticFixtureOnly,
        baseline_sha256,
        baseline_report_digest: baseline.report_digest.clone(),
        curator_id,
        query_name: query.name.clone(),
        candidate_unit_id: candidate.unit_id.clone(),
        selected_source_anchor,
        decision: CuratorDecision::SelectExactIdentity,
        rationale: "synthetic protocol fixture; no governed target selection".to_owned(),
        non_authority_statement: CURATION_NON_AUTHORITY.to_owned(),
    };
    let signature_hex = encode_hex(
        &signing_key
            .sign(&curator_selection_payload_bytes(&payload)?)
            .to_bytes(),
    );
    let selection = SignedSemanticAnchorCuratorSelection {
        payload,
        signature_hex,
    };
    let receipt = verify_semantic_anchor_curator_selection(baseline_bytes, &policy, &selection)?;
    Ok(SyntheticSemanticAnchorCurationFixture {
        profile: SYNTHETIC_CURATION_FIXTURE_PROFILE.to_owned(),
        policy,
        selection,
        receipt,
        non_authority_statement: SYNTHETIC_CURATION_NON_AUTHORITY.to_owned(),
    })
}

pub fn verify_synthetic_semantic_anchor_curation_fixture(
    baseline_bytes: &[u8],
    fixture_bytes: &[u8],
) -> Result<(), String> {
    if fixture_bytes.is_empty() || fixture_bytes.len() > MAX_CURATION_BYTES {
        return Err("synthetic curation fixture byte bound differs".to_owned());
    }
    let observed: SyntheticSemanticAnchorCurationFixture =
        serde_json::from_slice(fixture_bytes).map_err(|error| error.to_string())?;
    if observed.profile != SYNTHETIC_CURATION_FIXTURE_PROFILE
        || observed.policy.use_status != CuratorSelectionUseStatus::SyntheticFixtureOnly
        || observed.selection.payload.use_status != CuratorSelectionUseStatus::SyntheticFixtureOnly
        || observed.receipt.use_status != CuratorSelectionUseStatus::SyntheticFixtureOnly
        || observed.non_authority_statement != SYNTHETIC_CURATION_NON_AUTHORITY
    {
        return Err("synthetic curation fixture identity or status differs".to_owned());
    }
    let expected = generate_synthetic_semantic_anchor_curation_fixture(baseline_bytes)?;
    if observed != expected {
        return Err("synthetic curation fixture differs from exact replay".to_owned());
    }
    Ok(())
}

fn validate_curator_policy_form(policy: &SemanticAnchorCuratorPolicy) -> Result<(), String> {
    if policy.profile != CURATOR_POLICY_PROFILE
        || policy.grants.is_empty()
        || policy.grants.len() > MAX_CURATOR_GRANTS
        || policy.baseline_sha256.algorithm != "sha256"
        || policy.baseline_sha256.value.len() != 64
        || policy.non_authority_statement != CURATION_NON_AUTHORITY
    {
        return Err("curator policy form or bound differs".to_owned());
    }
    let mut curator_ids = BTreeSet::new();
    for grant in &policy.grants {
        if grant.allowed_query_names.is_empty()
            || grant.allowed_query_names.len() > MAX_ALLOWED_QUERIES
            || grant.allowed_query_names.iter().any(|name| name.is_empty())
            || grant.authority_scope != CURATOR_AUTHORITY_SCOPE
            || grant.source_requirement != CURATOR_SOURCE_REQUIREMENT
            || !curator_ids.insert(grant.curator_id.clone())
        {
            return Err("curator grant form or bound differs".to_owned());
        }
        decode_fixed_hex::<32>(&grant.verifying_key_hex, "curator verifying key")?;
    }
    Ok(())
}

fn validate_selection_payload_form(
    payload: &SemanticAnchorCuratorSelectionPayload,
) -> Result<(), String> {
    if payload.profile != CURATOR_SELECTION_PROFILE
        || payload.baseline_sha256.algorithm != "sha256"
        || payload.baseline_sha256.value.len() != 64
        || payload.baseline_report_digest.algorithm != "sha256"
        || payload.baseline_report_digest.value.len() != 64
        || payload.query_name.is_empty()
        || payload.rationale.is_empty()
        || payload.rationale.len() > MAX_RATIONALE_BYTES
        || payload.non_authority_statement != CURATION_NON_AUTHORITY
    {
        return Err("curator selection payload form or bound differs".to_owned());
    }
    Ok(())
}

fn decode_fixed_hex<const N: usize>(value: &str, field: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{field} must contain exactly {} hex bytes", N));
    }
    let mut output = [0_u8; N];
    for (index, slot) in output.iter_mut().enumerate() {
        let start = index * 2;
        *slot = u8::from_str_radix(&value[start..start + 2], 16)
            .map_err(|error| format!("{field} hex refused: {error}"))?;
    }
    Ok(output)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn semantic_id(value: &str) -> Result<SemanticId, String> {
    SemanticId::new(value).map_err(|error| error.to_string())
}
