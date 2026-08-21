//! Deterministic Slice5A evidence over the tracked self-hosted SOP corpus.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    ANCHOR_QUERY_PROFILE, AnchorBudget, AnchorQuery, AssociationChannel, AuthorityContext,
    CandidateEligibility, CatalogueDerivationRequest, CompactAnchorProjectionBudget,
    CompactAnchorProjectionRequest, ContentDigest, LEXICAL_ANCHOR_LOOKUP_PROFILE,
    LEXICAL_TOKENIZER_PROFILE, LEXICALLY_SEEDED_ANCHOR_GATE_PROFILE, LexicalAnchorLookupBudget,
    LexicalAnchorLookupRequest, LexicalIndexDerivationRequest, LexicallySeededAnchorGateBudget,
    LexicallySeededAnchorGateRequest, RequestedDetailKind, SemanticFabric, SemanticId,
    SopCorpusManifest, SopDocumentInput, SopSigningKeys, admit_package, build_sop_corpus,
    derive_lexical_association_index, derive_semantic_anchor_catalogue,
    gate_lexical_anchor_matches, lookup_lexical_anchors, project_compact_semantic_anchors,
    sha256_digest,
};

pub const SELF_HOSTED_ANCHOR_EVIDENCE_PROFILE: &str = "cantor-self-hosted-anchor-evidence/0.1";
pub const MAX_EVIDENCE_DOCUMENTS: usize = 16;
pub const MAX_EVIDENCE_QUERIES: usize = 128;
pub const MAX_EVIDENCE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfHostedAnchorQueryEvidence {
    pub name: String,
    pub requested_terms: BTreeSet<String>,
    pub lexical_match_count: u32,
    pub unmatched_tokens: BTreeSet<String>,
    pub scanner_candidate_count: u32,
    pub eligible_count: u32,
    pub ambiguous_count: u32,
    pub unknown_count: u32,
    pub excluded_count: u32,
    pub contradicted_count: u32,
    pub stale_count: u32,
    pub unauthorized_count: u32,
    pub unresolved_count: u32,
    pub clipped_count: u32,
    pub compact_record_count: u32,
    pub lexical_response_bytes: u64,
    pub gate_response_bytes: u64,
    pub compact_response_bytes: u64,
    pub lexical_proof_digest: ContentDigest,
    pub gate_proof_digest: ContentDigest,
    pub compact_proof_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfHostedAnchorEvidenceBody {
    pub profile: String,
    pub manifest_digest: ContentDigest,
    pub source_digests: BTreeMap<String, ContentDigest>,
    pub source_count: u32,
    pub source_bytes: u64,
    pub package_count: u32,
    pub semantic_unit_count: u32,
    pub relation_count: u32,
    pub catalogue_identity_count: u32,
    pub catalogue_operation_count: u32,
    pub applicability_binding_count: u32,
    pub catalogue_omission_count: u32,
    pub lexical_token_count: u32,
    pub lexical_posting_count: u32,
    pub fabric_root: ContentDigest,
    pub catalogue_root: ContentDigest,
    pub catalogue_proof_digest: ContentDigest,
    pub lexical_index_root: ContentDigest,
    pub lexical_proof_digest: ContentDigest,
    pub queries: Vec<SelfHostedAnchorQueryEvidence>,
    pub total_response_bytes: u64,
    pub proof_complete: bool,
    pub latency_measurement: String,
    pub allocation_measurement: String,
    pub correction_examples_status: String,
    pub learned_readiness_gaps: BTreeSet<String>,
    pub non_authority_statement: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfHostedAnchorEvidence {
    #[serde(flatten)]
    pub body: SelfHostedAnchorEvidenceBody,
    pub report_digest: ContentDigest,
}

pub fn generate_self_hosted_anchor_evidence(
    manifest_path: &Path,
) -> Result<SelfHostedAnchorEvidence, String> {
    let manifest_bytes = fs::read(manifest_path).map_err(|error| error.to_string())?;
    let manifest: SopCorpusManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|error| error.to_string())?;
    if manifest.documents.is_empty() || manifest.documents.len() > MAX_EVIDENCE_DOCUMENTS {
        return Err("tracked corpus document count is outside Slice5A bounds".to_owned());
    }
    if manifest.queries.is_empty() || manifest.queries.len() > MAX_EVIDENCE_QUERIES {
        return Err("tracked corpus query count is outside Slice5A bounds".to_owned());
    }
    let root = manifest_path
        .parent()
        .ok_or("manifest path has no parent")?
        .join(&manifest.source_root)
        .canonicalize()
        .map_err(|error| error.to_string())?;
    let mut source_digests = BTreeMap::new();
    let mut source_bytes = 0_u64;
    let mut documents = Vec::new();
    for document in &manifest.documents {
        let bytes = fs::read(root.join(&document.path)).map_err(|error| error.to_string())?;
        source_bytes = source_bytes
            .checked_add(u64::try_from(bytes.len()).map_err(|error| error.to_string())?)
            .ok_or("source byte account overflow")?;
        source_digests.insert(document.path.clone(), raw_digest(&bytes));
        documents.push(SopDocumentInput {
            document_id: document.document_id.clone(),
            path: document.path.clone(),
            bytes,
        });
    }
    let built = build_sop_corpus(
        &manifest,
        documents,
        SopSigningKeys {
            authority: SigningKey::from_bytes(&[41_u8; 32]),
            compiler: SigningKey::from_bytes(&[43_u8; 32]),
        },
    )
    .map_err(|faults| format!("corpus build refused: {faults:?}"))?;
    let mut admitted = Vec::new();
    for package in &built.environment.packages {
        let certificate = package
            .certificate
            .as_ref()
            .ok_or("package lacks certificate")?;
        admitted.push(
            admit_package(
                package,
                &built.environment.trust_store,
                &certificate.authority_scope,
                built.environment.now_epoch_seconds,
            )
            .map_err(|fault| format!("package admission refused: {fault:?}"))?,
        );
    }
    let fabric = SemanticFabric::from_admitted(admitted)
        .map_err(|fault| format!("fabric refused: {fault:?}"))?;
    let metrics = fabric
        .metrics()
        .map_err(|fault| format!("metrics refused: {fault:?}"))?;
    let catalogue = derive_semantic_anchor_catalogue(
        &fabric,
        CatalogueDerivationRequest {
            catalogue_id: semantic_id("catalogue:self_hosted_slice5a")?,
            logical_revision: "self-hosted-slice5a/0.1".to_owned(),
        },
    )
    .map_err(|fault| format!("catalogue refused: {fault:?}"))?;
    let index = derive_lexical_association_index(
        &fabric,
        &catalogue,
        LexicalIndexDerivationRequest {
            index_id: semantic_id("lexical-index:self_hosted_slice5a")?,
            logical_revision: "self-hosted-slice5a/0.1".to_owned(),
            tokenizer_profile: LEXICAL_TOKENIZER_PROFILE.to_owned(),
        },
    )
    .map_err(|fault| format!("lexical index refused: {fault:?}"))?;

    let mut queries = Vec::new();
    let mut total_response_bytes = 0_u64;
    for template in &manifest.queries {
        let request_id = semantic_id(&format!("request:self_hosted_slice5a_{}", template.name))?;
        let lookup_request = LexicalAnchorLookupRequest {
            profile: LEXICAL_ANCHOR_LOOKUP_PROFILE.to_owned(),
            request_id: request_id.clone(),
            terms: template.terms.iter().cloned().collect(),
            budget: LexicalAnchorLookupBudget {
                maximum_terms: 128,
                maximum_query_bytes: 65_536,
                maximum_unique_tokens: 4_096,
                maximum_postings: 131_072,
                maximum_matches: 4_096,
                maximum_serialized_result_bytes: 67_108_864,
            },
        };
        let lookup = lookup_lexical_anchors(&fabric, &catalogue, &index, lookup_request.clone())
            .map_err(|fault| format!("lookup refused: {fault:?}"))?;
        let gate_request = LexicallySeededAnchorGateRequest {
            profile: LEXICALLY_SEEDED_ANCHOR_GATE_PROFILE.to_owned(),
            request_id: request_id.clone(),
            scanner_query: AnchorQuery {
                profile: ANCHOR_QUERY_PROFILE.to_owned(),
                request_id: request_id.clone(),
                term_set: BTreeSet::new(),
                subject: template.subject.clone(),
                purpose: "bounded self-hosted catalogue evidence".to_owned(),
                use_cases: BTreeSet::new(),
                include_boundaries: BTreeSet::new(),
                exclude_boundaries: BTreeSet::new(),
                known_identities: lookup
                    .matches
                    .iter()
                    .map(|value| value.address.unit_id.clone())
                    .collect(),
                requested_details: template.requested_detail_kinds.clone(),
                allowed_relations: BTreeSet::new(),
                allowed_channels: BTreeSet::from([AssociationChannel::ExactIdentity]),
                authority_context: AuthorityContext {
                    caller_id: semantic_id("caller:self_hosted_slice5a")?,
                    allowed_package_scopes: BTreeSet::from(["cantor".to_owned()]),
                    operation: "semantic_read".to_owned(),
                    effect_boundary: "read_only".to_owned(),
                },
                budget: AnchorBudget {
                    maximum_candidates: 1_024,
                    maximum_records: 1_024,
                    maximum_paths: 1,
                    maximum_depth: 1,
                    maximum_bytes: 16_777_216,
                    maximum_elapsed_milliseconds: 1_000,
                    maximum_continuations: 0,
                },
            },
            budget: LexicallySeededAnchorGateBudget {
                maximum_lexical_matches: 4_096,
                maximum_scanner_candidates: 4_096,
                maximum_serialized_result_bytes: 67_108_864,
            },
        };
        let gate = gate_lexical_anchor_matches(
            &fabric,
            &catalogue,
            &index,
            &lookup_request,
            &lookup,
            gate_request.clone(),
        )
        .map_err(|fault| format!("semantic gate refused: {fault:?}"))?;
        let requested_details = template
            .requested_detail_kinds
            .iter()
            .filter(|kind| {
                matches!(
                    kind,
                    RequestedDetailKind::Term
                        | RequestedDetailKind::Definition
                        | RequestedDetailKind::Description
                        | RequestedDetailKind::SourceSpan
                )
            })
            .cloned()
            .collect();
        let compact_request = CompactAnchorProjectionRequest {
            profile: crate::COMPACT_ANCHOR_PROJECTION_PROFILE.to_owned(),
            request_id: request_id.clone(),
            requested_details,
            budget: CompactAnchorProjectionBudget {
                maximum_records: 4_096,
                maximum_serialized_result_bytes: 67_108_864,
            },
        };
        let compact = project_compact_semantic_anchors(
            &fabric,
            &catalogue,
            &index,
            &lookup_request,
            &lookup,
            &gate_request,
            &gate,
            compact_request,
        )
        .map_err(|fault| format!("compact projection refused: {fault:?}"))?;
        let lexical_response_bytes = serialized_len(&lookup)?;
        let gate_response_bytes = serialized_len(&gate)?;
        let compact_response_bytes = serialized_len(&compact)?;
        total_response_bytes = total_response_bytes
            .checked_add(lexical_response_bytes + gate_response_bytes + compact_response_bytes)
            .ok_or("response byte account overflow")?;
        let count = |eligibility: CandidateEligibility| -> u32 {
            u32::try_from(
                gate.scanner_result
                    .candidates
                    .iter()
                    .filter(|candidate| candidate.eligibility == eligibility)
                    .count(),
            )
            .unwrap_or(u32::MAX)
        };
        queries.push(SelfHostedAnchorQueryEvidence {
            name: template.name.clone(),
            requested_terms: template.terms.clone(),
            lexical_match_count: u32::try_from(lookup.matches.len())
                .map_err(|error| error.to_string())?,
            unmatched_tokens: lookup.unmatched_tokens.clone(),
            scanner_candidate_count: u32::try_from(gate.scanner_result.candidates.len())
                .map_err(|error| error.to_string())?,
            eligible_count: count(CandidateEligibility::Eligible),
            ambiguous_count: count(CandidateEligibility::Ambiguous),
            unknown_count: count(CandidateEligibility::Unknown),
            excluded_count: count(CandidateEligibility::Excluded),
            contradicted_count: count(CandidateEligibility::Contradicted),
            stale_count: count(CandidateEligibility::Stale),
            unauthorized_count: count(CandidateEligibility::Unauthorized),
            unresolved_count: count(CandidateEligibility::Unresolved),
            clipped_count: count(CandidateEligibility::Clipped),
            compact_record_count: u32::try_from(compact.records.len())
                .map_err(|error| error.to_string())?,
            lexical_response_bytes,
            gate_response_bytes,
            compact_response_bytes,
            lexical_proof_digest: lookup.proof_digest,
            gate_proof_digest: gate.proof_digest,
            compact_proof_digest: compact.proof_digest,
        });
    }
    let lexical_posting_count = index
        .postings
        .values()
        .try_fold(0_u32, |sum, values| {
            sum.checked_add(u32::try_from(values.len()).ok()?)
        })
        .ok_or("lexical posting account overflow")?;
    let body = SelfHostedAnchorEvidenceBody {
        profile: SELF_HOSTED_ANCHOR_EVIDENCE_PROFILE.to_owned(),
        manifest_digest: raw_digest(&manifest_bytes),
        source_digests,
        source_count: u32::try_from(built.source_count).map_err(|error| error.to_string())?,
        source_bytes,
        package_count: u32::try_from(metrics.package_count).map_err(|error| error.to_string())?,
        semantic_unit_count: u32::try_from(metrics.semantic_unit_count).map_err(|error| error.to_string())?,
        relation_count: u32::try_from(metrics.relation_count).map_err(|error| error.to_string())?,
        catalogue_identity_count: u32::try_from(catalogue.catalogue.identity_entries.len()).map_err(|error| error.to_string())?,
        catalogue_operation_count: u32::try_from(catalogue.catalogue.operation_entries.len()).map_err(|error| error.to_string())?,
        applicability_binding_count: u32::try_from(catalogue.catalogue.applicability_bindings.len()).map_err(|error| error.to_string())?,
        catalogue_omission_count: u32::try_from(catalogue.omissions.len()).map_err(|error| error.to_string())?,
        lexical_token_count: u32::try_from(index.postings.len()).map_err(|error| error.to_string())?,
        lexical_posting_count,
        fabric_root: catalogue.generation.fabric_root.clone(),
        catalogue_root: catalogue.catalogue.identity.catalogue_root.clone(),
        catalogue_proof_digest: catalogue.proof_digest,
        lexical_index_root: index.index_root,
        lexical_proof_digest: index.proof_digest,
        queries,
        total_response_bytes,
        proof_complete: true,
        latency_measurement: "not_measured_in_deterministic_slice5a_lane".to_owned(),
        allocation_measurement: "not_measured_in_deterministic_slice5a_lane".to_owned(),
        correction_examples_status: "not_yet_labeled_or_authorized_for_training".to_owned(),
        learned_readiness_gaps: BTreeSet::from([
            "controlled_latency_and_allocation_measurement".to_owned(),
            "governed_labeled_correction_examples".to_owned(),
            "separate_learned_training_authorization".to_owned(),
        ]),
        non_authority_statement: "This provider-free structural baseline grants no learned-training, truth, permission, safety, execution, or effect authority.".to_owned(),
    };
    let report_digest = sha256_digest(&body).map_err(|error| format!("{error:?}"))?;
    let evidence = SelfHostedAnchorEvidence {
        body,
        report_digest,
    };
    validate_self_hosted_anchor_evidence_form(&evidence)?;
    Ok(evidence)
}

pub fn validate_self_hosted_anchor_evidence_form(
    evidence: &SelfHostedAnchorEvidence,
) -> Result<(), String> {
    if evidence.body.profile != SELF_HOSTED_ANCHOR_EVIDENCE_PROFILE
        || evidence.body.source_count == 0
        || evidence.body.source_count as usize > MAX_EVIDENCE_DOCUMENTS
        || evidence.body.queries.is_empty()
        || evidence.body.queries.len() > MAX_EVIDENCE_QUERIES
        || !evidence.body.proof_complete
        || evidence.body.latency_measurement != "not_measured_in_deterministic_slice5a_lane"
        || evidence.body.allocation_measurement != "not_measured_in_deterministic_slice5a_lane"
    {
        return Err("Slice5A evidence form or bounds differ".to_owned());
    }
    let expected = sha256_digest(&evidence.body).map_err(|error| format!("{error:?}"))?;
    if evidence.report_digest != expected {
        return Err("Slice5A report digest differs from exact body".to_owned());
    }
    if serde_json::to_vec(evidence)
        .map_err(|error| error.to_string())?
        .len()
        > MAX_EVIDENCE_BYTES
    {
        return Err("Slice5A evidence exceeds serialized byte bound".to_owned());
    }
    Ok(())
}

pub fn verify_self_hosted_anchor_evidence(
    manifest_path: &Path,
    evidence_bytes: &[u8],
) -> Result<(), String> {
    let observed: SelfHostedAnchorEvidence =
        serde_json::from_slice(evidence_bytes).map_err(|error| error.to_string())?;
    validate_self_hosted_anchor_evidence_form(&observed)?;
    let expected = generate_self_hosted_anchor_evidence(manifest_path)?;
    if observed != expected {
        return Err("Slice5A evidence differs from exact tracked-corpus replay".to_owned());
    }
    Ok(())
}

fn semantic_id(value: &str) -> Result<SemanticId, String> {
    SemanticId::new(value).map_err(|error| format!("invalid Slice5A identity: {error:?}"))
}

fn serialized_len<T: Serialize>(value: &T) -> Result<u64, String> {
    u64::try_from(
        serde_json::to_vec(value)
            .map_err(|error| error.to_string())?
            .len(),
    )
    .map_err(|error| error.to_string())
}

fn raw_digest(bytes: &[u8]) -> ContentDigest {
    let digest = Sha256::digest(bytes);
    let value = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value,
    }
}
