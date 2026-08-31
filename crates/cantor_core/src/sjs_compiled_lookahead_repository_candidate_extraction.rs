//! Provider-free compilation of a supplied repository slice into the existing
//! compiled-lookahead exact-pool selector.
//!
//! This module does not inspect a filesystem or Git repository, parse prose,
//! generate semantic labels, call a provider or model, mutate a prompt or
//! stitch, or perform an external effect. Every repository coordinate,
//! semantic field, metric, token estimate, and coverage relation is supplied.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::de::{DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    ContentDigest, SJS_LTO_CANONICAL_UUID, SJS_LTO_NON_AUTHORITY, SJS_LTO_SIGNATURE_UUID,
    SJS_LTO_SOURCE_UUID, SJS_LTO_STITCH_CANONICAL_UUID, SJS_LTO_STITCH_SOURCE_UUID, SemanticId,
    SjsLasSourceBindingClass, SjsLtoCoverageEdge, SjsLtoEffectAccount, SjsLtoEnvelope,
    SjsLtoInputClass, SjsLtoObligation, SjsLtoRequest, SjsLtoResultStatus, SjsLtoSelectionPolicy,
    SjsLtoSelectionScope, SjsLtoTermCandidate, SjsLtoVerification, optimize_sjs_lto,
    seal_sjs_lto_request, sha256_bytes, synthetic_sjs_lto_request, validate_sjs_lto_envelope,
    validate_sjs_lto_request, verify_sjs_lto,
};

pub const SJS_RCX_REQUEST_PROFILE: &str = "cantor-sjs-lookahead-repository-candidate-request/0.1";
pub const SJS_RCX_ENVELOPE_PROFILE: &str = "cantor-sjs-lookahead-repository-candidate-envelope/0.1";
pub const SJS_RCX_VERIFICATION_PROFILE: &str =
    "cantor-sjs-lookahead-repository-candidate-verification/0.1";
pub const SJS_RCX_EVIDENCE_PROFILE: &str = "cantor-sjs-lookahead-repository-candidate-evidence/0.1";
pub const SJS_RCX_CANONICAL_UUID: &str = "3359fdaf-f4bf-44f0-9892-3f8d8d5e027f";
pub const SJS_RCX_SIGNATURE_UUID: &str = "4d4b6518-942f-4219-9d63-55ec9dd66cc3";
pub const SJS_RCX_SOURCE_UUID: &str = "81ba4e67-0ebe-41db-bb8f-2437bc629c4c";
pub const SJS_RCX_PARENT_COMPLETION_SIGNATURE_UUID: &str = "f4e24a37-ada5-403f-b7e8-7dbfce69e64f";
pub const SJS_RCX_NON_AUTHORITY: &str = "Supplied repository-slice correspondence and provider-free compilation only. No retained coordinate, content digest, semantic label, metric, edge, selected set, receipt, or verifier result proves repository observation, generated-semantic truth, global optimality, tokenizer accuracy, prompt placement, live A/B speed or quality, learning, autonomy, durable custody, successor activation, host mutation, remote-machine state, FPGA state, Minecraft state, or any physical effect.";
pub const SJS_RCX_MAX_MACHINE_FORM_BYTES: usize = 1_048_576;
pub const SJS_RCX_MAX_EVIDENCE_BYTES: usize = 8_388_608;

const MAX_DEPTH: usize = 40;
const MAX_FIELDS: usize = 16_384;
const MAX_TEXT_BYTES: usize = 4_096;
const MAX_RECORDS: usize = 16;
const MAX_OBLIGATIONS: usize = 64;
const MAX_EDGES: usize = 256;
const MAX_REFERENCES: usize = 64;

const REQUEST_DOMAIN: &str = "cantor.sjs-rcx.request.v1";
const RECEIPT_DOMAIN: &str = "cantor.sjs-rcx.receipt.v1";
const ENVELOPE_DOMAIN: &str = "cantor.sjs-rcx.envelope.v1";
const REQUEST_FILE: &str = "request.json";
const ENVELOPE_FILE: &str = "envelope.json";
const VERIFICATION_FILE: &str = "verification.json";
const MANIFEST_FILE: &str = "evidence_manifest.json";

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SjsRcxInputClass {
    SyntheticProviderFreeFixture,
    SuppliedUnobservedRepositorySlice,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SjsRcxElementKind {
    GoverningRequirement,
    GoverningConstraint,
    NonauthorityDenial,
    OpenObligation,
    CurrentObjective,
    DependencyCoordinate,
    Frontier,
    FileCoordinate,
    SymbolCoordinate,
    ExpectedOutput,
    EvidenceGate,
    OperationalFault,
    Ambiguity,
    RejectedRoute,
    AttributedPriorReceipt,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SjsRcxAuthority {
    SuppliedRepositorySliceCorrespondenceOnly,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsRcxRepositorySliceScope {
    pub repository_id: SemanticId,
    pub repository: String,
    pub branch: String,
    pub commit_digest: ContentDigest,
    pub selection_scope: SjsLtoSelectionScope,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsRcxRepositoryCandidateRecord {
    pub element_id: SemanticId,
    pub locator: String,
    pub content_digest: ContentDigest,
    pub element_kind: SjsRcxElementKind,
    pub candidate: SjsLtoTermCandidate,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsRcxRequest {
    pub profile: String,
    pub request_id: SemanticId,
    pub run_id: SemanticId,
    pub receipt_id: SemanticId,
    pub downstream_request_id: SemanticId,
    pub downstream_run_id: SemanticId,
    pub downstream_receipt_id: SemanticId,
    pub input_class: SjsRcxInputClass,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub source_snapshot_uuid: String,
    pub parent_canonical_uuid: String,
    pub parent_completion_signature_uuid: String,
    pub scope: SjsRcxRepositorySliceScope,
    pub policy: SjsLtoSelectionPolicy,
    pub obligations: Vec<SjsLtoObligation>,
    pub records: Vec<SjsRcxRepositoryCandidateRecord>,
    pub coverage_edges: Vec<SjsLtoCoverageEdge>,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub non_authority: String,
    pub request_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsRcxReceipt {
    pub receipt_id: SemanticId,
    pub supplied_record_count: u32,
    pub admitted_record_count: u32,
    pub refused_record_count: u32,
    pub governing_record_count: u32,
    pub optional_record_count: u32,
    pub contrastive_record_count: u32,
    pub downstream_candidate_count: u32,
    pub downstream_obligation_count: u32,
    pub downstream_coverage_edge_count: u32,
    pub downstream_selected_count: u32,
    pub downstream_rejected_count: u32,
    pub downstream_dominated_count: u32,
    pub downstream_uncovered_count: u32,
    pub downstream_admitted_subset_count: u32,
    pub downstream_feasible_subset_count: u32,
    pub request_digest: ContentDigest,
    pub downstream_request_digest: ContentDigest,
    pub downstream_receipt_digest: ContentDigest,
    pub downstream_envelope_digest: ContentDigest,
    pub receipt_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsRcxEnvelope {
    pub profile: String,
    pub request: SjsRcxRequest,
    pub authority: SjsRcxAuthority,
    pub downstream_request: SjsLtoRequest,
    pub downstream_envelope: SjsLtoEnvelope,
    pub downstream_verification: SjsLtoVerification,
    pub receipt: SjsRcxReceipt,
    pub execution_authorized: bool,
    pub effects: SjsLtoEffectAccount,
    pub envelope_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsRcxVerification {
    pub profile: String,
    pub status: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub input_class: SjsRcxInputClass,
    pub downstream_result_status: SjsLtoResultStatus,
    pub request_digest: ContentDigest,
    pub envelope_digest: ContentDigest,
    pub receipt_digest: ContentDigest,
    pub record_count: u32,
    pub obligation_count: u32,
    pub coverage_edge_count: u32,
    pub selected_count: u32,
    pub rejected_count: u32,
    pub dominated_count: u32,
    pub uncovered_count: u32,
    pub admitted_subset_count: u32,
    pub feasible_subset_count: u32,
    pub execution_authorized: bool,
    pub effects: SjsLtoEffectAccount,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsRcxEvidenceFile {
    pub bytes: u64,
    pub sha256: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsRcxEvidenceManifest {
    pub profile: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub replay_count: u32,
    pub files: BTreeMap<String, SjsRcxEvidenceFile>,
    pub request_digest: ContentDigest,
    pub envelope_digest: ContentDigest,
    pub receipt_digest: ContentDigest,
    pub record_count: u32,
    pub selected_count: u32,
    pub rejected_count: u32,
    pub dominated_count: u32,
    pub uncovered_count: u32,
    pub execution_authorized: bool,
    pub effects: SjsLtoEffectAccount,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsRcxEvidenceBundle {
    pub request_file: String,
    pub envelope_file: String,
    pub verification_file: String,
    pub manifest_file: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SjsRcxFaultCode {
    InvalidProfile,
    InvalidInputClass,
    InvalidIdentity,
    InvalidText,
    InvalidDigest,
    InvalidBound,
    InvalidScope,
    InvalidRecord,
    InvalidLocator,
    InvalidCoverage,
    InvalidAuthority,
    InvalidAccount,
    InvalidMachineForm,
    DownstreamRefusal,
    ArithmeticOverflow,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SjsRcxFault {
    pub code: SjsRcxFaultCode,
    pub detail: String,
}

impl fmt::Display for SjsRcxFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.detail)
    }
}
impl std::error::Error for SjsRcxFault {}

pub fn seal_sjs_rcx_request(mut request: SjsRcxRequest) -> Result<SjsRcxRequest, SjsRcxFault> {
    request
        .records
        .sort_by(|a, b| a.element_id.cmp(&b.element_id));
    request
        .obligations
        .sort_by(|a, b| a.obligation_id.cmp(&b.obligation_id));
    request.coverage_edges.sort();
    for record in &mut request.records {
        record
            .candidate
            .invalidators
            .sort_by(|a, b| (&a.field, &a.equals).cmp(&(&b.field, &b.equals)));
    }
    request.request_digest = empty_digest();
    validate_request_body(&request)?;
    let downstream = downstream_request_from(&request)?;
    request.scope.selection_scope = downstream.scope.clone();
    request.policy = downstream.policy.clone();
    let sealed_candidates = downstream
        .candidates
        .iter()
        .map(|candidate| (candidate.candidate_id.clone(), candidate.clone()))
        .collect::<BTreeMap<_, _>>();
    for record in &mut request.records {
        record.candidate = sealed_candidates
            .get(&record.candidate.candidate_id)
            .ok_or_else(|| fault(SjsRcxFaultCode::InvalidRecord, "candidate seal disappeared"))?
            .clone();
    }
    request.request_digest = sha256_form(REQUEST_DOMAIN, &request)?;
    validate_sjs_rcx_request(&request)?;
    Ok(request)
}

pub fn validate_sjs_rcx_request(request: &SjsRcxRequest) -> Result<(), SjsRcxFault> {
    validate_request_body(request)?;
    let downstream = downstream_request_from(request)?;
    if request.scope.selection_scope != downstream.scope
        || request.policy != downstream.policy
        || request.obligations != downstream.obligations
        || request.coverage_edges != downstream.coverage_edges
        || request.evidence_refs != downstream.evidence_refs
        || request
            .records
            .iter()
            .any(|record| !downstream.candidates.contains(&record.candidate))
    {
        return Err(fault(
            SjsRcxFaultCode::InvalidDigest,
            "nested selector seals differ",
        ));
    }
    if request.request_digest != digest_without(request, REQUEST_DOMAIN, |v| &mut v.request_digest)?
    {
        return Err(fault(
            SjsRcxFaultCode::InvalidDigest,
            "request digest differs",
        ));
    }
    Ok(())
}

pub fn compile_sjs_rcx(request: &SjsRcxRequest) -> Result<SjsRcxEnvelope, SjsRcxFault> {
    validate_sjs_rcx_request(request)?;
    let envelope = compile_internal(request)?;
    validate_sjs_rcx_envelope(&envelope)?;
    Ok(envelope)
}

pub fn validate_sjs_rcx_envelope(envelope: &SjsRcxEnvelope) -> Result<(), SjsRcxFault> {
    if envelope.profile != SJS_RCX_ENVELOPE_PROFILE
        || envelope.authority != SjsRcxAuthority::SuppliedRepositorySliceCorrespondenceOnly
        || envelope.execution_authorized
        || envelope.effects != SjsLtoEffectAccount::default()
    {
        return Err(fault(
            SjsRcxFaultCode::InvalidAuthority,
            "envelope profile authority or effects differ",
        ));
    }
    validate_sjs_rcx_request(&envelope.request)?;
    validate_sjs_lto_request(&envelope.downstream_request).map_err(downstream_fault)?;
    validate_sjs_lto_envelope(&envelope.downstream_envelope).map_err(downstream_fault)?;
    if envelope.downstream_envelope.request != envelope.downstream_request
        || verify_sjs_lto(&envelope.downstream_envelope).map_err(downstream_fault)?
            != envelope.downstream_verification
    {
        return Err(fault(
            SjsRcxFaultCode::InvalidAccount,
            "retained downstream lineage differs",
        ));
    }
    if envelope.receipt.request_digest != envelope.request.request_digest
        || envelope.receipt.receipt_digest
            != digest_without(&envelope.receipt, RECEIPT_DOMAIN, |v| &mut v.receipt_digest)?
        || envelope.envelope_digest
            != digest_without(envelope, ENVELOPE_DOMAIN, |v| &mut v.envelope_digest)?
    {
        return Err(fault(
            SjsRcxFaultCode::InvalidDigest,
            "receipt or envelope digest differs",
        ));
    }
    let rebuilt = compile_internal(&envelope.request)?;
    if rebuilt.downstream_request != envelope.downstream_request
        || rebuilt.downstream_envelope != envelope.downstream_envelope
        || rebuilt.downstream_verification != envelope.downstream_verification
        || rebuilt.receipt != envelope.receipt
    {
        return Err(fault(
            SjsRcxFaultCode::InvalidAccount,
            "independent extraction replay differs",
        ));
    }
    Ok(())
}

fn compile_internal(request: &SjsRcxRequest) -> Result<SjsRcxEnvelope, SjsRcxFault> {
    let downstream_request = downstream_request_from(request)?;
    let downstream_envelope = optimize_sjs_lto(&downstream_request).map_err(downstream_fault)?;
    let downstream_verification = verify_sjs_lto(&downstream_envelope).map_err(downstream_fault)?;
    let governing = request
        .records
        .iter()
        .filter(|record| {
            record.candidate.source_binding.class == SjsLasSourceBindingClass::GoverningAnchor
        })
        .count();
    let optional = request.records.len().saturating_sub(governing);
    let contrastive = request
        .records
        .iter()
        .filter(|record| {
            matches!(
                record.element_kind,
                SjsRcxElementKind::NonauthorityDenial
                    | SjsRcxElementKind::Ambiguity
                    | SjsRcxElementKind::RejectedRoute
            )
        })
        .count();
    let dominated = downstream_envelope
        .receipt
        .candidate_accounts
        .iter()
        .filter(|account| account.disposition == crate::SjsLtoCandidateDisposition::Dominated)
        .count();
    let selected = downstream_envelope.selected_candidates.len();
    let mut receipt = SjsRcxReceipt {
        receipt_id: request.receipt_id.clone(),
        supplied_record_count: count_u32(request.records.len())?,
        admitted_record_count: count_u32(request.records.len())?,
        refused_record_count: 0,
        governing_record_count: count_u32(governing)?,
        optional_record_count: count_u32(optional)?,
        contrastive_record_count: count_u32(contrastive)?,
        downstream_candidate_count: downstream_verification.candidate_count,
        downstream_obligation_count: downstream_verification.obligation_count,
        downstream_coverage_edge_count: downstream_verification.coverage_edge_count,
        downstream_selected_count: downstream_verification.selected_count,
        downstream_rejected_count: downstream_verification.rejected_count,
        downstream_dominated_count: count_u32(dominated)?,
        downstream_uncovered_count: downstream_verification.uncovered_count,
        downstream_admitted_subset_count: downstream_verification.admitted_subset_count,
        downstream_feasible_subset_count: downstream_verification.feasible_subset_count,
        request_digest: request.request_digest.clone(),
        downstream_request_digest: downstream_request.request_digest.clone(),
        downstream_receipt_digest: downstream_envelope.receipt.receipt_digest.clone(),
        downstream_envelope_digest: downstream_envelope.envelope_digest.clone(),
        receipt_digest: empty_digest(),
    };
    debug_assert_eq!(selected, downstream_verification.selected_count as usize);
    receipt.receipt_digest = sha256_form(RECEIPT_DOMAIN, &receipt)?;
    let mut envelope = SjsRcxEnvelope {
        profile: SJS_RCX_ENVELOPE_PROFILE.to_owned(),
        request: request.clone(),
        authority: SjsRcxAuthority::SuppliedRepositorySliceCorrespondenceOnly,
        downstream_request,
        downstream_envelope,
        downstream_verification,
        receipt,
        execution_authorized: false,
        effects: SjsLtoEffectAccount::default(),
        envelope_digest: empty_digest(),
    };
    envelope.envelope_digest = sha256_form(ENVELOPE_DOMAIN, &envelope)?;
    Ok(envelope)
}

pub fn verify_sjs_rcx(envelope: &SjsRcxEnvelope) -> Result<SjsRcxVerification, SjsRcxFault> {
    validate_sjs_rcx_envelope(envelope)?;
    let first = compile_internal(&envelope.request)?;
    let second = compile_internal(&envelope.request)?;
    if to_sjs_rcx_envelope_machine_form(&first)? != to_sjs_rcx_envelope_machine_form(&second)?
        || first != *envelope
    {
        return Err(fault(
            SjsRcxFaultCode::InvalidAccount,
            "independent double replay differs",
        ));
    }
    Ok(SjsRcxVerification {
        profile: SJS_RCX_VERIFICATION_PROFILE.to_owned(),
        status: "verified_provider_free_repository_candidate_compilation".to_owned(),
        canonical_uuid: SJS_RCX_CANONICAL_UUID.to_owned(),
        signature_uuid: SJS_RCX_SIGNATURE_UUID.to_owned(),
        input_class: envelope.request.input_class,
        downstream_result_status: envelope.downstream_verification.result_status,
        request_digest: envelope.request.request_digest.clone(),
        envelope_digest: envelope.envelope_digest.clone(),
        receipt_digest: envelope.receipt.receipt_digest.clone(),
        record_count: envelope.receipt.supplied_record_count,
        obligation_count: envelope.receipt.downstream_obligation_count,
        coverage_edge_count: envelope.receipt.downstream_coverage_edge_count,
        selected_count: envelope.receipt.downstream_selected_count,
        rejected_count: envelope.receipt.downstream_rejected_count,
        dominated_count: envelope.receipt.downstream_dominated_count,
        uncovered_count: envelope.receipt.downstream_uncovered_count,
        admitted_subset_count: envelope.receipt.downstream_admitted_subset_count,
        feasible_subset_count: envelope.receipt.downstream_feasible_subset_count,
        execution_authorized: false,
        effects: SjsLtoEffectAccount::default(),
    })
}

fn downstream_request_from(request: &SjsRcxRequest) -> Result<SjsLtoRequest, SjsRcxFault> {
    seal_sjs_lto_request(SjsLtoRequest {
        profile: crate::SJS_LTO_REQUEST_PROFILE.to_owned(),
        request_id: request.downstream_request_id.clone(),
        run_id: request.downstream_run_id.clone(),
        receipt_id: request.downstream_receipt_id.clone(),
        input_class: SjsLtoInputClass::SuppliedUnobservedCandidatePool,
        canonical_uuid: SJS_LTO_CANONICAL_UUID.to_owned(),
        signature_uuid: SJS_LTO_SIGNATURE_UUID.to_owned(),
        source_snapshot_uuid: SJS_LTO_SOURCE_UUID.to_owned(),
        stitch_source_uuid: SJS_LTO_STITCH_SOURCE_UUID.to_owned(),
        stitch_canonical_uuid: SJS_LTO_STITCH_CANONICAL_UUID.to_owned(),
        scope: request.scope.selection_scope.clone(),
        policy: request.policy.clone(),
        obligations: request.obligations.clone(),
        candidates: request
            .records
            .iter()
            .map(|record| record.candidate.clone())
            .collect(),
        coverage_edges: request.coverage_edges.clone(),
        evidence_refs: request.evidence_refs.clone(),
        non_authority: SJS_LTO_NON_AUTHORITY.to_owned(),
        request_digest: empty_digest(),
    })
    .map_err(downstream_fault)
}

fn validate_request_body(request: &SjsRcxRequest) -> Result<(), SjsRcxFault> {
    if request.profile != SJS_RCX_REQUEST_PROFILE {
        return Err(fault(
            SjsRcxFaultCode::InvalidProfile,
            "request profile differs",
        ));
    }
    if request.canonical_uuid != SJS_RCX_CANONICAL_UUID
        || request.signature_uuid != SJS_RCX_SIGNATURE_UUID
        || request.source_snapshot_uuid != SJS_RCX_SOURCE_UUID
        || request.parent_canonical_uuid != SJS_LTO_CANONICAL_UUID
        || request.parent_completion_signature_uuid != SJS_RCX_PARENT_COMPLETION_SIGNATURE_UUID
        || request.non_authority != SJS_RCX_NON_AUTHORITY
    {
        return Err(fault(
            SjsRcxFaultCode::InvalidAuthority,
            "authority identity differs",
        ));
    }
    for (id, label) in [
        (&request.request_id, "request"),
        (&request.run_id, "run"),
        (&request.receipt_id, "receipt"),
        (&request.downstream_request_id, "downstream request"),
        (&request.downstream_run_id, "downstream run"),
        (&request.downstream_receipt_id, "downstream receipt"),
        (&request.scope.repository_id, "repository"),
    ] {
        validate_uuid_id(id, label)?;
    }
    for evidence_ref in &request.evidence_refs {
        validate_uuid_id(evidence_ref, "evidence reference")?;
    }
    if request.records.is_empty()
        || request.records.len() > MAX_RECORDS
        || request.obligations.is_empty()
        || request.obligations.len() > MAX_OBLIGATIONS
        || request.coverage_edges.len() > MAX_EDGES
        || request.evidence_refs.len() > MAX_REFERENCES
    {
        return Err(fault(
            SjsRcxFaultCode::InvalidBound,
            "request collection bound differs",
        ));
    }
    if !strictly_sorted_by(&request.records, |record| &record.element_id)
        || !strictly_sorted_by(&request.obligations, |obligation| &obligation.obligation_id)
        || !request
            .coverage_edges
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    {
        return Err(fault(
            SjsRcxFaultCode::InvalidMachineForm,
            "request collections are not canonical sets",
        ));
    }
    validate_text(&request.scope.repository, "repository")?;
    validate_text(&request.scope.branch, "branch")?;
    validate_digest(&request.scope.commit_digest, "commit digest")?;
    let element_ids = request
        .records
        .iter()
        .map(|record| record.element_id.clone())
        .collect::<BTreeSet<_>>();
    let candidate_ids = request
        .records
        .iter()
        .map(|record| record.candidate.candidate_id.clone())
        .collect::<BTreeSet<_>>();
    let semantic_ids = request
        .records
        .iter()
        .map(|record| record.candidate.semantic_identity.as_str())
        .collect::<BTreeSet<_>>();
    let obligation_ids = request
        .obligations
        .iter()
        .map(|obligation| obligation.obligation_id.clone())
        .collect::<BTreeSet<_>>();
    if element_ids.len() != request.records.len()
        || candidate_ids.len() != request.records.len()
        || semantic_ids.len() != request.records.len()
        || obligation_ids.len() != request.obligations.len()
    {
        return Err(fault(
            SjsRcxFaultCode::InvalidIdentity,
            "duplicate element candidate semantic or obligation identity",
        ));
    }
    let mut locator_digests = BTreeMap::<&str, &ContentDigest>::new();
    for record in &request.records {
        validate_uuid_id(&record.element_id, "element")?;
        validate_locator(&record.locator)?;
        validate_digest(&record.content_digest, "record content digest")?;
        if record.candidate.source_binding.locator != record.locator {
            return Err(fault(
                SjsRcxFaultCode::InvalidRecord,
                "record and candidate locator differ",
            ));
        }
        if let Some(existing) = locator_digests.insert(&record.locator, &record.content_digest)
            && existing != &record.content_digest
        {
            return Err(fault(
                SjsRcxFaultCode::InvalidLocator,
                "locator conflicts on content identity",
            ));
        }
    }
    let mut coordinates = BTreeSet::new();
    let mut referenced_candidates = BTreeSet::new();
    for edge in &request.coverage_edges {
        if !candidate_ids.contains(&edge.candidate_id)
            || !obligation_ids.contains(&edge.obligation_id)
            || !coordinates.insert((edge.candidate_id.clone(), edge.obligation_id.clone()))
        {
            return Err(fault(
                SjsRcxFaultCode::InvalidCoverage,
                "dangling or duplicate coverage coordinate",
            ));
        }
        referenced_candidates.insert(edge.candidate_id.clone());
        let record = request
            .records
            .iter()
            .find(|record| record.candidate.candidate_id == edge.candidate_id)
            .expect("candidate identity checked");
        let obligation = request
            .obligations
            .iter()
            .find(|obligation| obligation.obligation_id == edge.obligation_id)
            .expect("obligation identity checked");
        let governing_kind = matches!(
            record.element_kind,
            SjsRcxElementKind::GoverningRequirement
                | SjsRcxElementKind::GoverningConstraint
                | SjsRcxElementKind::NonauthorityDenial
                | SjsRcxElementKind::OpenObligation
        );
        let governing_source =
            record.candidate.source_binding.class == SjsLasSourceBindingClass::GoverningAnchor;
        if obligation.mandatory && !(governing_kind && governing_source) {
            return Err(fault(
                SjsRcxFaultCode::InvalidAuthority,
                "mandatory obligation lacks governing kind and source",
            ));
        }
        if !governing_source && obligation.mandatory {
            return Err(fault(
                SjsRcxFaultCode::InvalidAuthority,
                "nonauthority record covers mandatory obligation",
            ));
        }
    }
    if referenced_candidates.len() != request.records.len() {
        return Err(fault(
            SjsRcxFaultCode::InvalidCoverage,
            "unreferenced candidate record",
        ));
    }
    for obligation in request
        .obligations
        .iter()
        .filter(|obligation| obligation.mandatory)
    {
        if !request.coverage_edges.iter().any(|edge| {
            edge.obligation_id == obligation.obligation_id
                && request.records.iter().any(|record| {
                    record.candidate.candidate_id == edge.candidate_id
                        && record.candidate.source_binding.class
                            == SjsLasSourceBindingClass::GoverningAnchor
                        && matches!(
                            record.element_kind,
                            SjsRcxElementKind::GoverningRequirement
                                | SjsRcxElementKind::GoverningConstraint
                                | SjsRcxElementKind::NonauthorityDenial
                                | SjsRcxElementKind::OpenObligation
                        )
                })
        }) {
            return Err(fault(
                SjsRcxFaultCode::InvalidAuthority,
                "mandatory-authority preflight is uncovered",
            ));
        }
    }
    if request.input_class == SjsRcxInputClass::SyntheticProviderFreeFixture
        && (request.records.len() != 8
            || request.obligations.len() != 6
            || request.coverage_edges.len() != 12
            || request.policy.maximum_selected_count != 3)
    {
        return Err(fault(
            SjsRcxFaultCode::InvalidInputClass,
            "synthetic fixture shape differs",
        ));
    }
    Ok(())
}

pub fn synthetic_sjs_rcx_request() -> Result<SjsRcxRequest, SjsRcxFault> {
    let parent = synthetic_sjs_lto_request().map_err(downstream_fault)?;
    let kinds = [
        SjsRcxElementKind::GoverningRequirement,
        SjsRcxElementKind::NonauthorityDenial,
        SjsRcxElementKind::CurrentObjective,
        SjsRcxElementKind::OpenObligation,
        SjsRcxElementKind::DependencyCoordinate,
        SjsRcxElementKind::EvidenceGate,
        SjsRcxElementKind::OperationalFault,
        SjsRcxElementKind::Frontier,
    ];
    let records = parent
        .candidates
        .iter()
        .enumerate()
        .map(|(index, candidate)| {
            let locator = candidate.source_binding.locator.clone();
            SjsRcxRepositoryCandidateRecord {
                element_id: id(&format!(
                    "element:84000000-0000-4000-8001-{:012}",
                    index + 1
                ))
                .expect("fixed element id"),
                locator,
                content_digest: sha256_bytes(
                    format!("supplied fixture content {}", index + 1).as_bytes(),
                ),
                element_kind: kinds[index],
                candidate: candidate.clone(),
            }
        })
        .collect();
    seal_sjs_rcx_request(SjsRcxRequest {
        profile: SJS_RCX_REQUEST_PROFILE.to_owned(),
        request_id: id("request:84000000-0000-4000-8000-000000000021")?,
        run_id: id("run:84000000-0000-4000-8000-000000000022")?,
        receipt_id: id("receipt:84000000-0000-4000-8000-000000000023")?,
        downstream_request_id: parent.request_id.clone(),
        downstream_run_id: parent.run_id.clone(),
        downstream_receipt_id: parent.receipt_id.clone(),
        input_class: SjsRcxInputClass::SyntheticProviderFreeFixture,
        canonical_uuid: SJS_RCX_CANONICAL_UUID.to_owned(),
        signature_uuid: SJS_RCX_SIGNATURE_UUID.to_owned(),
        source_snapshot_uuid: SJS_RCX_SOURCE_UUID.to_owned(),
        parent_canonical_uuid: SJS_LTO_CANONICAL_UUID.to_owned(),
        parent_completion_signature_uuid: SJS_RCX_PARENT_COMPLETION_SIGNATURE_UUID.to_owned(),
        scope: SjsRcxRepositorySliceScope {
            repository_id: id("repository:84000000-0000-4000-8000-000000000001")?,
            repository: "C:/Project/Cantor".to_owned(),
            branch: "codex/self-hosted-corpus".to_owned(),
            commit_digest: sha256_bytes(b"synthetic supplied commit identity"),
            selection_scope: parent.scope.clone(),
        },
        policy: parent.policy.clone(),
        obligations: parent.obligations.clone(),
        records,
        coverage_edges: parent.coverage_edges.clone(),
        evidence_refs: BTreeSet::new(),
        non_authority: SJS_RCX_NON_AUTHORITY.to_owned(),
        request_digest: empty_digest(),
    })
}

pub fn to_sjs_rcx_request_machine_form(value: &SjsRcxRequest) -> Result<String, SjsRcxFault> {
    to_machine_form(value)
}
pub fn from_sjs_rcx_request_machine_form(value: &str) -> Result<SjsRcxRequest, SjsRcxFault> {
    parse_bounded(value)
}
pub fn to_sjs_rcx_envelope_machine_form(value: &SjsRcxEnvelope) -> Result<String, SjsRcxFault> {
    to_machine_form(value)
}
pub fn from_sjs_rcx_envelope_machine_form(value: &str) -> Result<SjsRcxEnvelope, SjsRcxFault> {
    parse_bounded(value)
}
pub fn to_sjs_rcx_verification_machine_form(
    value: &SjsRcxVerification,
) -> Result<String, SjsRcxFault> {
    to_machine_form(value)
}

pub fn build_sjs_rcx_evidence_bundle(
    request: &SjsRcxRequest,
) -> Result<SjsRcxEvidenceBundle, SjsRcxFault> {
    validate_sjs_rcx_request(request)?;
    let envelope = compile_sjs_rcx(request)?;
    let verification = verify_sjs_rcx(&envelope)?;
    let request_file = canonical_file(to_sjs_rcx_request_machine_form(request)?);
    let envelope_file = canonical_file(to_sjs_rcx_envelope_machine_form(&envelope)?);
    let verification_file = canonical_file(to_sjs_rcx_verification_machine_form(&verification)?);
    let manifest = evidence_manifest(
        &request_file,
        &envelope_file,
        &verification_file,
        &verification,
    )?;
    let manifest_file = canonical_file(to_machine_form(&manifest)?);
    Ok(SjsRcxEvidenceBundle {
        request_file,
        envelope_file,
        verification_file,
        manifest_file,
    })
}

pub fn verify_sjs_rcx_evidence_bundle(
    bundle: &SjsRcxEvidenceBundle,
) -> Result<SjsRcxVerification, SjsRcxFault> {
    ensure_bundle_bound(bundle)?;
    let request: SjsRcxRequest =
        parse_bounded(canonical_file_body(&bundle.request_file, REQUEST_FILE)?)?;
    validate_sjs_rcx_request(&request)?;
    let envelope: SjsRcxEnvelope =
        parse_bounded(canonical_file_body(&bundle.envelope_file, ENVELOPE_FILE)?)?;
    if envelope.request != request {
        return Err(fault(
            SjsRcxFaultCode::InvalidAccount,
            "retained request and envelope request differ",
        ));
    }
    let first = compile_sjs_rcx(&request)?;
    let second = compile_sjs_rcx(&request)?;
    if first != second || first != envelope {
        return Err(fault(
            SjsRcxFaultCode::InvalidAccount,
            "retained envelope differs from double replay",
        ));
    }
    let retained_verification: SjsRcxVerification = parse_bounded(canonical_file_body(
        &bundle.verification_file,
        VERIFICATION_FILE,
    )?)?;
    let verification = verify_sjs_rcx(&envelope)?;
    if retained_verification != verification {
        return Err(fault(
            SjsRcxFaultCode::InvalidAccount,
            "retained verification differs",
        ));
    }
    let retained_manifest: SjsRcxEvidenceManifest =
        parse_bounded(canonical_file_body(&bundle.manifest_file, MANIFEST_FILE)?)?;
    let rebuilt = evidence_manifest(
        &bundle.request_file,
        &bundle.envelope_file,
        &bundle.verification_file,
        &verification,
    )?;
    if retained_manifest != rebuilt {
        return Err(fault(
            SjsRcxFaultCode::InvalidAccount,
            "retained evidence manifest differs",
        ));
    }
    Ok(verification)
}

pub fn to_sjs_rcx_evidence_bundle_machine_form(
    value: &SjsRcxEvidenceBundle,
) -> Result<String, SjsRcxFault> {
    to_machine_form(value)
}
pub fn from_sjs_rcx_evidence_bundle_machine_form(
    value: &str,
) -> Result<SjsRcxEvidenceBundle, SjsRcxFault> {
    parse_bounded_with_limit(value, SJS_RCX_MAX_EVIDENCE_BYTES)
}

fn evidence_manifest(
    request_file: &str,
    envelope_file: &str,
    verification_file: &str,
    verification: &SjsRcxVerification,
) -> Result<SjsRcxEvidenceManifest, SjsRcxFault> {
    let mut files = BTreeMap::new();
    for (path, body) in [
        (REQUEST_FILE, request_file),
        (ENVELOPE_FILE, envelope_file),
        (VERIFICATION_FILE, verification_file),
    ] {
        files.insert(
            path.to_owned(),
            SjsRcxEvidenceFile {
                bytes: count_u64(body.len())?,
                sha256: sha256_bytes(body.as_bytes()),
            },
        );
    }
    Ok(SjsRcxEvidenceManifest {
        profile: SJS_RCX_EVIDENCE_PROFILE.to_owned(),
        canonical_uuid: SJS_RCX_CANONICAL_UUID.to_owned(),
        signature_uuid: SJS_RCX_SIGNATURE_UUID.to_owned(),
        replay_count: 2,
        files,
        request_digest: verification.request_digest.clone(),
        envelope_digest: verification.envelope_digest.clone(),
        receipt_digest: verification.receipt_digest.clone(),
        record_count: verification.record_count,
        selected_count: verification.selected_count,
        rejected_count: verification.rejected_count,
        dominated_count: verification.dominated_count,
        uncovered_count: verification.uncovered_count,
        execution_authorized: false,
        effects: SjsLtoEffectAccount::default(),
    })
}

fn ensure_bundle_bound(bundle: &SjsRcxEvidenceBundle) -> Result<(), SjsRcxFault> {
    for (name, value) in [
        (REQUEST_FILE, &bundle.request_file),
        (ENVELOPE_FILE, &bundle.envelope_file),
        (VERIFICATION_FILE, &bundle.verification_file),
        (MANIFEST_FILE, &bundle.manifest_file),
    ] {
        if value.len() > SJS_RCX_MAX_EVIDENCE_BYTES
            || !value.ends_with('\n')
            || value[..value.len() - 1].contains('\n')
        {
            return Err(fault(
                SjsRcxFaultCode::InvalidMachineForm,
                format!("{name} is not one compact LF-terminated file"),
            ));
        }
    }
    Ok(())
}

fn validate_locator(locator: &str) -> Result<(), SjsRcxFault> {
    validate_text(locator, "locator")?;
    if locator.starts_with('/')
        || locator.contains('\\')
        || locator.contains(':')
        || locator.contains('\0')
    {
        return Err(fault(
            SjsRcxFaultCode::InvalidLocator,
            "locator is absolute drive UNC backslash stream or NUL form",
        ));
    }
    for segment in locator.split('/') {
        let stem = segment
            .split('.')
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let reserved = matches!(stem.as_str(), "con" | "prn" | "aux" | "nul")
            || (stem.len() == 4
                && (stem.starts_with("com") || stem.starts_with("lpt"))
                && matches!(stem.as_bytes()[3], b'1'..=b'9'));
        if segment.is_empty()
            || matches!(segment, "." | "..")
            || segment.ends_with(['.', ' '])
            || reserved
        {
            return Err(fault(
                SjsRcxFaultCode::InvalidLocator,
                "locator contains empty dot traversal device or unstable segment",
            ));
        }
    }
    Ok(())
}

fn validate_digest(digest: &ContentDigest, label: &str) -> Result<(), SjsRcxFault> {
    if digest.algorithm == "sha256"
        && digest.value.len() == 64
        && digest
            .value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(fault(
            SjsRcxFaultCode::InvalidDigest,
            format!("{label} is not lowercase SHA256"),
        ))
    }
}

fn digest_without<T: Clone + Serialize>(
    value: &T,
    domain: &str,
    field: impl Fn(&mut T) -> &mut ContentDigest,
) -> Result<ContentDigest, SjsRcxFault> {
    let mut copy = value.clone();
    *field(&mut copy) = empty_digest();
    sha256_form(domain, &copy)
}
fn sha256_form<T: Serialize>(domain: &str, value: &T) -> Result<ContentDigest, SjsRcxFault> {
    let body = serde_json::to_vec(value).map_err(machine_fault)?;
    let mut bytes = Vec::with_capacity(domain.len() + 1 + body.len());
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&body);
    Ok(sha256_bytes(&bytes))
}
fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: "0".repeat(64),
    }
}
fn count_u32(value: usize) -> Result<u32, SjsRcxFault> {
    u32::try_from(value).map_err(|_| {
        fault(
            SjsRcxFaultCode::ArithmeticOverflow,
            "usize to u32 count overflow",
        )
    })
}
fn count_u64(value: usize) -> Result<u64, SjsRcxFault> {
    u64::try_from(value).map_err(|_| {
        fault(
            SjsRcxFaultCode::ArithmeticOverflow,
            "usize to u64 count overflow",
        )
    })
}
fn id(value: &str) -> Result<SemanticId, SjsRcxFault> {
    SemanticId::new(value)
        .map_err(|error| fault(SjsRcxFaultCode::InvalidIdentity, error.to_string()))
}
fn validate_uuid_id(id: &SemanticId, label: &str) -> Result<(), SjsRcxFault> {
    let suffix = id.as_str().rsplit(':').next().unwrap_or_default();
    let bytes = suffix.as_bytes();
    let valid = bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                *byte == b'-'
            } else {
                byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
            }
        })
        && suffix != "00000000-0000-0000-0000-000000000000";
    if valid {
        Ok(())
    } else {
        Err(fault(
            SjsRcxFaultCode::InvalidIdentity,
            format!("{label} is not lowercase nonnil UUID-bearing"),
        ))
    }
}
fn validate_text(value: &str, label: &str) -> Result<(), SjsRcxFault> {
    if !value.is_empty()
        && value.len() <= MAX_TEXT_BYTES
        && value.trim() == value
        && value
            .chars()
            .all(|character| !character.is_control() && character != '\u{7f}')
    {
        Ok(())
    } else {
        Err(fault(
            SjsRcxFaultCode::InvalidText,
            format!("{label} differs"),
        ))
    }
}
fn strictly_sorted_by<T, K: Ord>(values: &[T], key: impl Fn(&T) -> &K) -> bool {
    values.windows(2).all(|pair| key(&pair[0]) < key(&pair[1]))
}
fn downstream_fault(error: impl fmt::Display) -> SjsRcxFault {
    fault(SjsRcxFaultCode::DownstreamRefusal, error.to_string())
}
fn to_machine_form<T: Serialize>(value: &T) -> Result<String, SjsRcxFault> {
    serde_json::to_string(value).map_err(machine_fault)
}
fn canonical_file(value: String) -> String {
    format!("{value}\n")
}
fn canonical_file_body<'a>(value: &'a str, label: &str) -> Result<&'a str, SjsRcxFault> {
    value.strip_suffix('\n').ok_or_else(|| {
        fault(
            SjsRcxFaultCode::InvalidMachineForm,
            format!("{label} lacks one LF"),
        )
    })
}
fn parse_bounded<T: DeserializeOwned + Serialize>(value: &str) -> Result<T, SjsRcxFault> {
    parse_bounded_with_limit(value, SJS_RCX_MAX_MACHINE_FORM_BYTES)
}
fn parse_bounded_with_limit<T: DeserializeOwned + Serialize>(
    value: &str,
    limit: usize,
) -> Result<T, SjsRcxFault> {
    if value.len() > limit {
        return Err(fault(
            SjsRcxFaultCode::InvalidBound,
            "machine form too large",
        ));
    }
    let mut deserializer = serde_json::Deserializer::from_str(value);
    NoDuplicateJson::deserialize(&mut deserializer).map_err(machine_fault)?;
    deserializer.end().map_err(machine_fault)?;
    let shape: Value = serde_json::from_str(value).map_err(machine_fault)?;
    let mut fields = 0;
    validate_json_shape(&shape, 1, &mut fields, None)?;
    let parsed: T = serde_json::from_str(value).map_err(machine_fault)?;
    if to_machine_form(&parsed)? != value {
        return Err(fault(
            SjsRcxFaultCode::InvalidMachineForm,
            "machine form is not compact canonical JSON",
        ));
    }
    Ok(parsed)
}

struct NoDuplicateJson;
impl<'de> Deserialize<'de> for NoDuplicateJson {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(NoDuplicateVisitor)?;
        Ok(Self)
    }
}
struct NoDuplicateVisitor;
impl<'de> Visitor<'de> for NoDuplicateVisitor {
    type Value = ();
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("strict JSON")
    }
    fn visit_bool<E>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_string<E>(self, _: String) -> Result<(), E> {
        Ok(())
    }
    fn visit_none<E>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<(), A::Error> {
        while sequence.next_element::<NoDuplicateJson>()?.is_some() {}
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(serde::de::Error::custom(format!("duplicate key {key}")));
            }
            map.next_value::<NoDuplicateJson>()?;
        }
        Ok(())
    }
}
fn validate_json_shape(
    value: &Value,
    depth: usize,
    fields: &mut usize,
    parent_key: Option<&str>,
) -> Result<(), SjsRcxFault> {
    if depth > MAX_DEPTH {
        return Err(fault(
            SjsRcxFaultCode::InvalidMachineForm,
            "depth exceeds 40",
        ));
    }
    match value {
        Value::Object(map) => {
            *fields = fields
                .checked_add(map.len())
                .ok_or_else(|| fault(SjsRcxFaultCode::ArithmeticOverflow, "field count"))?;
            if *fields > MAX_FIELDS {
                return Err(fault(
                    SjsRcxFaultCode::InvalidMachineForm,
                    "fields exceed 16384",
                ));
            }
            for (key, nested) in map {
                validate_text(key, "field")?;
                validate_json_shape(nested, depth + 1, fields, Some(key))?;
            }
        }
        Value::Array(array) => {
            for nested in array {
                validate_json_shape(nested, depth + 1, fields, None)?;
            }
        }
        Value::String(text) => {
            let evidence_file = matches!(
                parent_key,
                Some("request_file" | "envelope_file" | "verification_file" | "manifest_file")
            );
            if evidence_file {
                if text.len() > SJS_RCX_MAX_EVIDENCE_BYTES {
                    return Err(fault(
                        SjsRcxFaultCode::InvalidBound,
                        "embedded evidence file exceeds bound",
                    ));
                }
            } else {
                validate_text(text, "machine text")?;
            }
        }
        _ => {}
    }
    Ok(())
}
fn machine_fault(error: impl fmt::Display) -> SjsRcxFault {
    fault(SjsRcxFaultCode::InvalidMachineForm, error.to_string())
}
fn fault(code: SjsRcxFaultCode, detail: impl Into<String>) -> SjsRcxFault {
    SjsRcxFault {
        code,
        detail: detail.into(),
    }
}
