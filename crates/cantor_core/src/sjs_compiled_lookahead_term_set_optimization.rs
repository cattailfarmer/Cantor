//! Provider-free exact-pool term-set selection for compiled lookahead stitches.
//!
//! This module consumes supplied public typed data. It does not inspect a
//! repository, generate semantics, call a provider or model, mutate a prompt
//! or stitch, or perform any external effect.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::de::{DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    ContentDigest, SemanticId, SjsLasPredicate, SjsLasSemanticTurn, SjsLasSemanticTurnKind,
    SjsLasSourceBinding, SjsLasSourceBindingClass, sha256_bytes,
};

pub const SJS_LTO_REQUEST_PROFILE: &str = "cantor-sjs-lookahead-term-set-request/0.1";
pub const SJS_LTO_ENVELOPE_PROFILE: &str = "cantor-sjs-lookahead-term-set-envelope/0.1";
pub const SJS_LTO_VERIFICATION_PROFILE: &str = "cantor-sjs-lookahead-term-set-verification/0.1";
pub const SJS_LTO_EVIDENCE_PROFILE: &str = "cantor-sjs-lookahead-term-set-evidence/0.1";
pub const SJS_LTO_CANONICAL_UUID: &str = "5bb132b9-8250-4f6d-a7e6-6977edad8162";
pub const SJS_LTO_SIGNATURE_UUID: &str = "65b049b8-7af6-463a-9c03-9e0714f068b0";
pub const SJS_LTO_SOURCE_UUID: &str = "24c3902d-634f-40b5-93bc-ffec40db2f84";
pub const SJS_LTO_STITCH_SOURCE_UUID: &str = "9a3eb07f-b5f3-4d4b-83ec-32c410deb7ec";
pub const SJS_LTO_STITCH_CANONICAL_UUID: &str = "5b57d004-0a43-4d89-9c5a-6dc671a2a05a";
pub const SJS_LTO_NON_AUTHORITY: &str = "Exact supplied-pool provider-free selection only. A candidate, edge, score, selected set, receipt, digest, or verifier result grants no generated-semantic truth, global optimality, tokenizer accuracy, prompt or stitch mutation, provider or model use, performance truth, autonomous work, host authority, remote-hardware state, or external-effect authority.";
pub const SJS_LTO_MAX_MACHINE_FORM_BYTES: usize = 1_048_576;
pub const SJS_LTO_MAX_EVIDENCE_BYTES: usize = 8_388_608;

const MAX_DEPTH: usize = 40;
const MAX_FIELDS: usize = 16_384;
const MAX_TEXT_BYTES: usize = 4_096;
const MAX_CANDIDATES: usize = 16;
const MAX_OBLIGATIONS: usize = 64;
const MAX_EDGES: usize = 256;
const MAX_SELECTED: usize = 8;
const MAX_PROJECTED_BYTES: u64 = 8_192;
const MAX_TOKEN_ESTIMATE: u64 = 4_096;
const MAX_BASIS_POINTS: u32 = 10_000;
const MAX_REFERENCES: usize = 64;

const SCOPE_DOMAIN: &str = "cantor.sjs-lto.scope.v1";
const CANDIDATE_DOMAIN: &str = "cantor.sjs-lto.candidate.v1";
const POLICY_DOMAIN: &str = "cantor.sjs-lto.policy.v1";
const REQUEST_DOMAIN: &str = "cantor.sjs-lto.request.v1";
const RECEIPT_DOMAIN: &str = "cantor.sjs-lto.receipt.v1";
const ENVELOPE_DOMAIN: &str = "cantor.sjs-lto.envelope.v1";
const REQUEST_FILE: &str = "request.json";
const ENVELOPE_FILE: &str = "envelope.json";
const VERIFICATION_FILE: &str = "verification.json";

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SjsLtoInputClass {
    SyntheticProviderFreeFixture,
    SuppliedUnobservedCandidatePool,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SjsLtoObligationKind {
    GoverningRequirement,
    CurrentDecision,
    ActionCoordinate,
    EvidenceGate,
    KnownFault,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SjsLtoResultStatus {
    SelectedExact,
    InsufficientBudget,
    UncoverableMandatory,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SjsLtoCandidateDisposition {
    Selected,
    Dominated,
    FeasibleNotSelected,
    Ineligible,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SjsLtoAuthority {
    SuppliedPublicExactPoolSelectionOnly,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsLtoSelectionScope {
    pub scope_id: SemanticId,
    pub source_identities: BTreeSet<SemanticId>,
    pub subject: String,
    pub objective: String,
    pub phase: String,
    pub feature: String,
    pub requirement: String,
    pub artifact: String,
    pub task_class: String,
    pub model_profile: String,
    pub horizon: String,
    pub context_assembly: String,
    pub tool_policy: String,
    pub authority_ceiling: String,
    pub compiled_stitch_profile: String,
    pub scope_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsLtoObligation {
    pub obligation_id: SemanticId,
    pub kind: SjsLtoObligationKind,
    pub description: String,
    pub weight: u32,
    pub mandatory: bool,
    pub source_id: SemanticId,
    pub scope_id: SemanticId,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsLtoCandidateMetrics {
    pub decision_relevance: u32,
    pub ambiguity_reduction: u32,
    pub action_relevance: u32,
    pub evidence_relevance: u32,
    pub fault_avoidance: u32,
    pub anchoring_risk: u32,
    pub unsupported_inference_risk: u32,
    pub stale_distance: u32,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsLtoTermCandidate {
    pub candidate_id: SemanticId,
    pub semantic_identity: String,
    pub subject_anchor: String,
    pub semantic_turn: SjsLasSemanticTurn,
    pub transform: String,
    pub scope_id: SemanticId,
    pub source_binding: SjsLasSourceBinding,
    pub completion_cue: SjsLasPredicate,
    pub invalidators: Vec<SjsLasPredicate>,
    pub placement_role: String,
    pub dependency_rank: u32,
    pub projected_surface: String,
    pub projected_bytes: u64,
    pub token_estimate: u64,
    pub metrics: SjsLtoCandidateMetrics,
    pub candidate_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsLtoCoverageEdge {
    pub relation_id: SemanticId,
    pub candidate_id: SemanticId,
    pub obligation_id: SemanticId,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsLtoSelectionPolicy {
    pub policy_id: SemanticId,
    pub maximum_selected_count: u32,
    pub maximum_projected_bytes: u64,
    pub maximum_token_estimate: u64,
    pub required_coverage_basis_points: u32,
    pub metric_precedence: Vec<String>,
    pub source_precedence: Vec<SjsLasSourceBindingClass>,
    pub placement_precedence: Vec<String>,
    pub policy_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsLtoRequest {
    pub profile: String,
    pub request_id: SemanticId,
    pub run_id: SemanticId,
    pub receipt_id: SemanticId,
    pub input_class: SjsLtoInputClass,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub source_snapshot_uuid: String,
    pub stitch_source_uuid: String,
    pub stitch_canonical_uuid: String,
    pub scope: SjsLtoSelectionScope,
    pub policy: SjsLtoSelectionPolicy,
    pub obligations: Vec<SjsLtoObligation>,
    pub candidates: Vec<SjsLtoTermCandidate>,
    pub coverage_edges: Vec<SjsLtoCoverageEdge>,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub non_authority: String,
    pub request_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsLtoObjectiveAccount {
    pub selected_count: u32,
    pub coverage_basis_points: u32,
    pub decision_relevance: u64,
    pub ambiguity_reduction: u64,
    pub action_relevance: u64,
    pub evidence_relevance: u64,
    pub fault_avoidance: u64,
    pub anchoring_risk: u64,
    pub unsupported_inference_risk: u64,
    pub stale_distance: u64,
    pub projected_bytes: u64,
    pub token_estimate: u64,
    pub identity_vector: Vec<SemanticId>,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsLtoCandidateAccount {
    pub candidate_id: SemanticId,
    pub disposition: SjsLtoCandidateDisposition,
    pub covered_obligation_ids: Vec<SemanticId>,
    pub comparator_id: Option<SemanticId>,
    pub reason: String,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsLtoUncoveredAccount {
    pub obligation_id: SemanticId,
    pub mandatory: bool,
    pub reason: String,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsLtoBudgetAccount {
    pub maximum_selected_count: u32,
    pub selected_count: u32,
    pub maximum_projected_bytes: u64,
    pub selected_projected_bytes: u64,
    pub maximum_token_estimate: u64,
    pub selected_token_estimate: u64,
    pub required_coverage_basis_points: u32,
    pub selected_coverage_basis_points: u32,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsLtoEffectAccount {
    pub filesystem_effect_count: u32,
    pub environment_effect_count: u32,
    pub clock_effect_count: u32,
    pub process_effect_count: u32,
    pub network_effect_count: u32,
    pub provider_effect_count: u32,
    pub model_effect_count: u32,
    pub inference_effect_count: u32,
    pub mcp_effect_count: u32,
    pub git_workspace_effect_count: u32,
    pub secret_effect_count: u32,
    pub permission_effect_count: u32,
    pub remote_hardware_effect_count: u32,
    pub external_effect_count: u32,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsLtoOptimizationReceipt {
    pub receipt_id: SemanticId,
    pub status: SjsLtoResultStatus,
    pub admitted_subset_count: u32,
    pub feasible_subset_count: u32,
    pub selected_candidate_ids: Vec<SemanticId>,
    pub best_partial_candidate_ids: Vec<SemanticId>,
    pub candidate_accounts: Vec<SjsLtoCandidateAccount>,
    pub uncovered_accounts: Vec<SjsLtoUncoveredAccount>,
    pub budget_account: SjsLtoBudgetAccount,
    pub objective_account: SjsLtoObjectiveAccount,
    pub request_digest: ContentDigest,
    pub receipt_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsLtoEnvelope {
    pub profile: String,
    pub request: SjsLtoRequest,
    pub authority: SjsLtoAuthority,
    pub selected_candidates: Vec<SjsLtoTermCandidate>,
    pub receipt: SjsLtoOptimizationReceipt,
    pub execution_authorized: bool,
    pub effects: SjsLtoEffectAccount,
    pub envelope_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsLtoVerification {
    pub profile: String,
    pub status: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub input_class: SjsLtoInputClass,
    pub result_status: SjsLtoResultStatus,
    pub request_digest: ContentDigest,
    pub envelope_digest: ContentDigest,
    pub candidate_count: u32,
    pub obligation_count: u32,
    pub coverage_edge_count: u32,
    pub admitted_subset_count: u32,
    pub feasible_subset_count: u32,
    pub selected_count: u32,
    pub rejected_count: u32,
    pub dominated_count: u32,
    pub uncovered_count: u32,
    pub execution_authorized: bool,
    pub effects: SjsLtoEffectAccount,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsLtoEvidenceFile {
    pub bytes: u64,
    pub sha256: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsLtoEvidenceManifest {
    pub profile: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub replay_count: u32,
    pub files: BTreeMap<String, SjsLtoEvidenceFile>,
    pub request_digest: ContentDigest,
    pub envelope_digest: ContentDigest,
    pub result_status: SjsLtoResultStatus,
    pub candidate_count: u32,
    pub obligation_count: u32,
    pub coverage_edge_count: u32,
    pub admitted_subset_count: u32,
    pub feasible_subset_count: u32,
    pub selected_count: u32,
    pub rejected_count: u32,
    pub dominated_count: u32,
    pub uncovered_count: u32,
    pub execution_authorized: bool,
    pub effects: SjsLtoEffectAccount,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsLtoEvidenceBundle {
    pub request_file: String,
    pub envelope_file: String,
    pub verification_file: String,
    pub manifest_file: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SjsLtoFaultCode {
    InvalidProfile,
    InvalidInputClass,
    InvalidIdentity,
    InvalidText,
    InvalidDigest,
    InvalidBound,
    InvalidScope,
    InvalidObligation,
    InvalidCandidate,
    InvalidCoverage,
    InvalidPolicy,
    InvalidAuthority,
    InvalidAccount,
    InvalidMachineForm,
    ArithmeticOverflow,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SjsLtoFault {
    pub code: SjsLtoFaultCode,
    pub detail: String,
}

impl fmt::Display for SjsLtoFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.detail)
    }
}
impl std::error::Error for SjsLtoFault {}

struct EvaluatedSubset {
    indices: Vec<usize>,
    objective: SjsLtoObjectiveAccount,
    mandatory_covered: usize,
    budget_admitted: bool,
    feasible: bool,
}

pub fn seal_sjs_lto_request(mut request: SjsLtoRequest) -> Result<SjsLtoRequest, SjsLtoFault> {
    request
        .obligations
        .sort_by(|a, b| a.obligation_id.cmp(&b.obligation_id));
    request
        .candidates
        .sort_by(|a, b| a.candidate_id.cmp(&b.candidate_id));
    request.coverage_edges.sort();
    request.scope.scope_digest = empty_digest();
    request.scope.scope_digest = sha256_form(SCOPE_DOMAIN, &request.scope)?;
    request.policy.policy_digest = empty_digest();
    request.policy.policy_digest = sha256_form(POLICY_DOMAIN, &request.policy)?;
    for candidate in &mut request.candidates {
        candidate
            .invalidators
            .sort_by(|a, b| (&a.field, &a.equals).cmp(&(&b.field, &b.equals)));
        candidate.candidate_digest = empty_digest();
        candidate.candidate_digest = sha256_form(CANDIDATE_DOMAIN, candidate)?;
    }
    request.request_digest = empty_digest();
    validate_request_body(&request)?;
    request.request_digest = sha256_form(REQUEST_DOMAIN, &request)?;
    validate_sjs_lto_request(&request)?;
    Ok(request)
}

pub fn validate_sjs_lto_request(request: &SjsLtoRequest) -> Result<(), SjsLtoFault> {
    validate_request_body(request)?;
    if request.scope.scope_digest
        != digest_without(&request.scope, SCOPE_DOMAIN, |v| &mut v.scope_digest)?
        || request.policy.policy_digest
            != digest_without(&request.policy, POLICY_DOMAIN, |v| &mut v.policy_digest)?
    {
        return Err(fault(
            SjsLtoFaultCode::InvalidDigest,
            "scope or policy digest differs",
        ));
    }
    for candidate in &request.candidates {
        if candidate.candidate_digest
            != digest_without(candidate, CANDIDATE_DOMAIN, |v| &mut v.candidate_digest)?
        {
            return Err(fault(
                SjsLtoFaultCode::InvalidDigest,
                "candidate digest differs",
            ));
        }
    }
    if request.request_digest != digest_without(request, REQUEST_DOMAIN, |v| &mut v.request_digest)?
    {
        return Err(fault(
            SjsLtoFaultCode::InvalidDigest,
            "request digest differs",
        ));
    }
    Ok(())
}

pub fn optimize_sjs_lto(request: &SjsLtoRequest) -> Result<SjsLtoEnvelope, SjsLtoFault> {
    validate_sjs_lto_request(request)?;
    let envelope = compile_internal(request)?;
    validate_sjs_lto_envelope(&envelope)?;
    Ok(envelope)
}

pub fn validate_sjs_lto_envelope(envelope: &SjsLtoEnvelope) -> Result<(), SjsLtoFault> {
    if envelope.profile != SJS_LTO_ENVELOPE_PROFILE
        || envelope.execution_authorized
        || envelope.effects != SjsLtoEffectAccount::default()
    {
        return Err(fault(
            SjsLtoFaultCode::InvalidAuthority,
            "envelope profile authority or effects differ",
        ));
    }
    validate_sjs_lto_request(&envelope.request)?;
    if envelope.receipt.request_digest != envelope.request.request_digest
        || envelope.receipt.receipt_digest
            != digest_without(&envelope.receipt, RECEIPT_DOMAIN, |v| &mut v.receipt_digest)?
        || envelope.envelope_digest
            != digest_without(envelope, ENVELOPE_DOMAIN, |v| &mut v.envelope_digest)?
    {
        return Err(fault(
            SjsLtoFaultCode::InvalidDigest,
            "receipt or envelope digest differs",
        ));
    }
    let rebuilt = optimize_without_envelope_validation(&envelope.request)?;
    if rebuilt.selected_candidates != envelope.selected_candidates
        || rebuilt.receipt != envelope.receipt
    {
        return Err(fault(
            SjsLtoFaultCode::InvalidAccount,
            "selection or account replay differs",
        ));
    }
    Ok(())
}

fn optimize_without_envelope_validation(
    request: &SjsLtoRequest,
) -> Result<SjsLtoEnvelope, SjsLtoFault> {
    // Avoid recursion by using the same compiler with a validation skip flag.
    compile_internal(request)
}

fn compile_internal(request: &SjsLtoRequest) -> Result<SjsLtoEnvelope, SjsLtoFault> {
    let coverage = coverage_map(request);
    let mandatory_total = request.obligations.iter().filter(|o| o.mandatory).count();
    let mut admitted = 0_u32;
    let mut feasible = 0_u32;
    let mut best: Option<EvaluatedSubset> = None;
    let mut partial: Option<EvaluatedSubset> = None;
    let limit = 1_u32 << request.candidates.len();
    for mask in 1_u32..limit {
        if mask.count_ones() > request.policy.maximum_selected_count {
            continue;
        }
        admitted += 1;
        let indices = (0..request.candidates.len())
            .filter(|i| mask & (1_u32 << i) != 0)
            .collect::<Vec<_>>();
        let e = evaluate_subset(request, &coverage, indices, mandatory_total)?;
        if e.budget_admitted && partial.as_ref().is_none_or(|o| partial_better(&e, o)) {
            partial = Some(clone_evaluated(&e));
        }
        if e.feasible {
            feasible += 1;
            if best
                .as_ref()
                .is_none_or(|o| objective_better(&e.objective, &o.objective))
            {
                best = Some(e);
            }
        }
    }
    let mandatory_uncoverable = request.obligations.iter().filter(|o| o.mandatory).any(|o| {
        !request
            .coverage_edges
            .iter()
            .any(|e| e.obligation_id == o.obligation_id)
    });
    let status = if best.is_some() {
        SjsLtoResultStatus::SelectedExact
    } else if mandatory_uncoverable {
        SjsLtoResultStatus::UncoverableMandatory
    } else {
        SjsLtoResultStatus::InsufficientBudget
    };
    let indices = best.as_ref().map(|v| v.indices.clone()).unwrap_or_default();
    let ids = indices
        .iter()
        .map(|i| request.candidates[*i].candidate_id.clone())
        .collect::<Vec<_>>();
    let partial_ids = partial
        .as_ref()
        .map(|v| {
            v.indices
                .iter()
                .map(|i| request.candidates[*i].candidate_id.clone())
                .collect()
        })
        .unwrap_or_default();
    let covered = covered_for_indices(request, &coverage, &indices);
    let objective = best
        .as_ref()
        .map(|v| v.objective.clone())
        .unwrap_or_default();
    let mut receipt = SjsLtoOptimizationReceipt {
        receipt_id: request.receipt_id.clone(),
        status,
        admitted_subset_count: admitted,
        feasible_subset_count: feasible,
        selected_candidate_ids: ids,
        best_partial_candidate_ids: partial_ids,
        candidate_accounts: candidate_accounts(request, &coverage, &indices)?,
        uncovered_accounts: request
            .obligations
            .iter()
            .filter(|o| !covered.contains(&o.obligation_id))
            .map(|o| SjsLtoUncoveredAccount {
                obligation_id: o.obligation_id.clone(),
                mandatory: o.mandatory,
                reason: "obligation is not covered by an authorized selected exact set".to_owned(),
            })
            .collect(),
        budget_account: SjsLtoBudgetAccount {
            maximum_selected_count: request.policy.maximum_selected_count,
            selected_count: objective.selected_count,
            maximum_projected_bytes: request.policy.maximum_projected_bytes,
            selected_projected_bytes: objective.projected_bytes,
            maximum_token_estimate: request.policy.maximum_token_estimate,
            selected_token_estimate: objective.token_estimate,
            required_coverage_basis_points: request.policy.required_coverage_basis_points,
            selected_coverage_basis_points: objective.coverage_basis_points,
        },
        objective_account: objective,
        request_digest: request.request_digest.clone(),
        receipt_digest: empty_digest(),
    };
    receipt.receipt_digest = sha256_form(RECEIPT_DOMAIN, &receipt)?;
    let mut selected = indices
        .iter()
        .map(|i| request.candidates[*i].clone())
        .collect::<Vec<_>>();
    selected.sort_by_key(|candidate| placement_key(request, candidate));
    let mut envelope = SjsLtoEnvelope {
        profile: SJS_LTO_ENVELOPE_PROFILE.to_owned(),
        request: request.clone(),
        authority: SjsLtoAuthority::SuppliedPublicExactPoolSelectionOnly,
        selected_candidates: selected,
        receipt,
        execution_authorized: false,
        effects: SjsLtoEffectAccount::default(),
        envelope_digest: empty_digest(),
    };
    envelope.envelope_digest = sha256_form(ENVELOPE_DOMAIN, &envelope)?;
    Ok(envelope)
}

pub fn verify_sjs_lto(envelope: &SjsLtoEnvelope) -> Result<SjsLtoVerification, SjsLtoFault> {
    validate_sjs_lto_envelope(envelope)?;
    let first = compile_internal(&envelope.request)?;
    let second = compile_internal(&envelope.request)?;
    if to_sjs_lto_envelope_machine_form(&first)? != to_sjs_lto_envelope_machine_form(&second)?
        || first != *envelope
    {
        return Err(fault(
            SjsLtoFaultCode::InvalidAccount,
            "independent double replay differs",
        ));
    }
    Ok(SjsLtoVerification {
        profile: SJS_LTO_VERIFICATION_PROFILE.to_owned(),
        status: "verified_provider_free_exact_pool".to_owned(),
        canonical_uuid: SJS_LTO_CANONICAL_UUID.to_owned(),
        signature_uuid: SJS_LTO_SIGNATURE_UUID.to_owned(),
        input_class: envelope.request.input_class,
        result_status: envelope.receipt.status,
        request_digest: envelope.request.request_digest.clone(),
        envelope_digest: envelope.envelope_digest.clone(),
        candidate_count: count_u32(envelope.request.candidates.len())?,
        obligation_count: count_u32(envelope.request.obligations.len())?,
        coverage_edge_count: count_u32(envelope.request.coverage_edges.len())?,
        admitted_subset_count: envelope.receipt.admitted_subset_count,
        feasible_subset_count: envelope.receipt.feasible_subset_count,
        selected_count: count_u32(envelope.selected_candidates.len())?,
        rejected_count: count_u32(
            envelope.request.candidates.len() - envelope.selected_candidates.len(),
        )?,
        dominated_count: count_u32(
            envelope
                .receipt
                .candidate_accounts
                .iter()
                .filter(|a| a.disposition == SjsLtoCandidateDisposition::Dominated)
                .count(),
        )?,
        uncovered_count: count_u32(envelope.receipt.uncovered_accounts.len())?,
        execution_authorized: false,
        effects: SjsLtoEffectAccount::default(),
    })
}

pub fn to_sjs_lto_request_machine_form(value: &SjsLtoRequest) -> Result<String, SjsLtoFault> {
    to_machine_form(value)
}
pub fn from_sjs_lto_request_machine_form(value: &str) -> Result<SjsLtoRequest, SjsLtoFault> {
    parse_bounded(value)
}
pub fn to_sjs_lto_envelope_machine_form(value: &SjsLtoEnvelope) -> Result<String, SjsLtoFault> {
    to_machine_form(value)
}
pub fn from_sjs_lto_envelope_machine_form(value: &str) -> Result<SjsLtoEnvelope, SjsLtoFault> {
    parse_bounded(value)
}
pub fn to_sjs_lto_verification_machine_form(
    value: &SjsLtoVerification,
) -> Result<String, SjsLtoFault> {
    to_machine_form(value)
}

pub fn build_sjs_lto_evidence_bundle(
    request: &SjsLtoRequest,
) -> Result<SjsLtoEvidenceBundle, SjsLtoFault> {
    validate_sjs_lto_request(request)?;
    let envelope = optimize_sjs_lto(request)?;
    let verification = verify_sjs_lto(&envelope)?;
    let request_file = canonical_file(to_sjs_lto_request_machine_form(request)?);
    let envelope_file = canonical_file(to_sjs_lto_envelope_machine_form(&envelope)?);
    let verification_file = canonical_file(to_sjs_lto_verification_machine_form(&verification)?);
    let manifest = evidence_manifest(
        &request_file,
        &envelope_file,
        &verification_file,
        &verification,
    )?;
    let manifest_file = canonical_file(to_machine_form(&manifest)?);
    Ok(SjsLtoEvidenceBundle {
        request_file,
        envelope_file,
        verification_file,
        manifest_file,
    })
}

pub fn verify_sjs_lto_evidence_bundle(
    bundle: &SjsLtoEvidenceBundle,
) -> Result<SjsLtoVerification, SjsLtoFault> {
    ensure_bundle_bound(bundle)?;
    let request: SjsLtoRequest =
        parse_bounded(canonical_file_body(&bundle.request_file, REQUEST_FILE)?)?;
    validate_sjs_lto_request(&request)?;
    let envelope: SjsLtoEnvelope =
        parse_bounded(canonical_file_body(&bundle.envelope_file, ENVELOPE_FILE)?)?;
    if envelope.request != request {
        return Err(fault(
            SjsLtoFaultCode::InvalidAccount,
            "retained request and envelope request differ",
        ));
    }
    let expected_envelope = optimize_sjs_lto(&request)?;
    if expected_envelope != envelope {
        return Err(fault(
            SjsLtoFaultCode::InvalidAccount,
            "retained envelope differs from independent replay",
        ));
    }
    let retained_verification: SjsLtoVerification = parse_bounded(canonical_file_body(
        &bundle.verification_file,
        VERIFICATION_FILE,
    )?)?;
    let verification = verify_sjs_lto(&envelope)?;
    if retained_verification != verification {
        return Err(fault(
            SjsLtoFaultCode::InvalidAccount,
            "retained verification differs",
        ));
    }
    let retained_manifest: SjsLtoEvidenceManifest =
        parse_bounded(canonical_file_body(&bundle.manifest_file, "manifest.json")?)?;
    let rebuilt = evidence_manifest(
        &bundle.request_file,
        &bundle.envelope_file,
        &bundle.verification_file,
        &verification,
    )?;
    if retained_manifest != rebuilt {
        return Err(fault(
            SjsLtoFaultCode::InvalidAccount,
            "retained evidence manifest differs",
        ));
    }
    Ok(verification)
}

pub fn to_sjs_lto_evidence_bundle_machine_form(
    value: &SjsLtoEvidenceBundle,
) -> Result<String, SjsLtoFault> {
    to_machine_form(value)
}

pub fn from_sjs_lto_evidence_bundle_machine_form(
    value: &str,
) -> Result<SjsLtoEvidenceBundle, SjsLtoFault> {
    parse_bounded_with_limit(value, SJS_LTO_MAX_EVIDENCE_BYTES)
}

fn evidence_manifest(
    request_file: &str,
    envelope_file: &str,
    verification_file: &str,
    verification: &SjsLtoVerification,
) -> Result<SjsLtoEvidenceManifest, SjsLtoFault> {
    let mut files = BTreeMap::new();
    for (path, body) in [
        (REQUEST_FILE, request_file),
        (ENVELOPE_FILE, envelope_file),
        (VERIFICATION_FILE, verification_file),
    ] {
        files.insert(
            path.to_owned(),
            SjsLtoEvidenceFile {
                bytes: count_u64(body.len())?,
                sha256: sha256_bytes(body.as_bytes()),
            },
        );
    }
    Ok(SjsLtoEvidenceManifest {
        profile: SJS_LTO_EVIDENCE_PROFILE.to_owned(),
        canonical_uuid: SJS_LTO_CANONICAL_UUID.to_owned(),
        signature_uuid: SJS_LTO_SIGNATURE_UUID.to_owned(),
        replay_count: 2,
        files,
        request_digest: verification.request_digest.clone(),
        envelope_digest: verification.envelope_digest.clone(),
        result_status: verification.result_status,
        candidate_count: verification.candidate_count,
        obligation_count: verification.obligation_count,
        coverage_edge_count: verification.coverage_edge_count,
        admitted_subset_count: verification.admitted_subset_count,
        feasible_subset_count: verification.feasible_subset_count,
        selected_count: verification.selected_count,
        rejected_count: verification.rejected_count,
        dominated_count: verification.dominated_count,
        uncovered_count: verification.uncovered_count,
        execution_authorized: false,
        effects: SjsLtoEffectAccount::default(),
    })
}

fn ensure_bundle_bound(bundle: &SjsLtoEvidenceBundle) -> Result<(), SjsLtoFault> {
    for (name, value) in [
        (REQUEST_FILE, &bundle.request_file),
        (ENVELOPE_FILE, &bundle.envelope_file),
        (VERIFICATION_FILE, &bundle.verification_file),
        ("manifest.json", &bundle.manifest_file),
    ] {
        if value.len() > SJS_LTO_MAX_EVIDENCE_BYTES
            || !value.ends_with('\n')
            || value[..value.len() - 1].contains('\n')
            || value.contains('\r')
        {
            return Err(fault(
                SjsLtoFaultCode::InvalidMachineForm,
                format!("{name} framing differs"),
            ));
        }
    }
    let manifest: SjsLtoEvidenceManifest =
        parse_bounded(canonical_file_body(&bundle.manifest_file, "manifest.json")?)?;
    for (name, value) in [
        (REQUEST_FILE, &bundle.request_file),
        (ENVELOPE_FILE, &bundle.envelope_file),
        (VERIFICATION_FILE, &bundle.verification_file),
    ] {
        let retained = manifest.files.get(name).ok_or_else(|| {
            fault(
                SjsLtoFaultCode::InvalidAccount,
                format!("manifest omits {name}"),
            )
        })?;
        if retained.bytes != count_u64(value.len())?
            || retained.sha256 != sha256_bytes(value.as_bytes())
        {
            return Err(fault(
                SjsLtoFaultCode::InvalidAccount,
                format!("manifest identity differs for {name}"),
            ));
        }
    }
    Ok(())
}

fn validate_request_body(request: &SjsLtoRequest) -> Result<(), SjsLtoFault> {
    if request.profile != SJS_LTO_REQUEST_PROFILE {
        return Err(fault(
            SjsLtoFaultCode::InvalidProfile,
            "request profile differs",
        ));
    }
    if request.canonical_uuid != SJS_LTO_CANONICAL_UUID
        || request.signature_uuid != SJS_LTO_SIGNATURE_UUID
        || request.source_snapshot_uuid != SJS_LTO_SOURCE_UUID
        || request.stitch_source_uuid != SJS_LTO_STITCH_SOURCE_UUID
        || request.stitch_canonical_uuid != SJS_LTO_STITCH_CANONICAL_UUID
        || request.non_authority != SJS_LTO_NON_AUTHORITY
    {
        return Err(fault(
            SjsLtoFaultCode::InvalidAuthority,
            "authority identity differs",
        ));
    }
    for (id, label) in [
        (&request.request_id, "request"),
        (&request.run_id, "run"),
        (&request.receipt_id, "receipt"),
        (&request.scope.scope_id, "scope"),
        (&request.policy.policy_id, "policy"),
    ] {
        validate_uuid_id(id, label)?;
    }
    if request.candidates.is_empty()
        || request.candidates.len() > MAX_CANDIDATES
        || request.obligations.is_empty()
        || request.obligations.len() > MAX_OBLIGATIONS
        || request.coverage_edges.is_empty()
        || request.coverage_edges.len() > MAX_EDGES
        || request.evidence_refs.len() > MAX_REFERENCES
    {
        return Err(fault(
            SjsLtoFaultCode::InvalidBound,
            "request collection bound differs",
        ));
    }
    if !strictly_sorted_by(&request.obligations, |v| &v.obligation_id)
        || !strictly_sorted_by(&request.candidates, |v| &v.candidate_id)
        || !request.coverage_edges.windows(2).all(|p| p[0] < p[1])
    {
        return Err(fault(
            SjsLtoFaultCode::InvalidMachineForm,
            "request collections are not canonical sets",
        ));
    }
    validate_scope(&request.scope)?;
    validate_policy(&request.policy)?;
    let source_ids = &request.scope.source_identities;
    let obligation_ids = request
        .obligations
        .iter()
        .map(|o| o.obligation_id.clone())
        .collect::<BTreeSet<_>>();
    let candidate_ids = request
        .candidates
        .iter()
        .map(|c| c.candidate_id.clone())
        .collect::<BTreeSet<_>>();
    let semantic_identities = request
        .candidates
        .iter()
        .map(|c| c.semantic_identity.as_str())
        .collect::<BTreeSet<_>>();
    if obligation_ids.len() != request.obligations.len()
        || candidate_ids.len() != request.candidates.len()
        || semantic_identities.len() != request.candidates.len()
    {
        return Err(fault(
            SjsLtoFaultCode::InvalidIdentity,
            "duplicate obligation candidate or semantic identity",
        ));
    }
    for o in &request.obligations {
        validate_uuid_id(&o.obligation_id, "obligation")?;
        validate_uuid_id(&o.source_id, "obligation source")?;
        validate_text(&o.description, "obligation description")?;
        if o.scope_id != request.scope.scope_id
            || !source_ids.contains(&o.source_id)
            || o.weight == 0
            || o.weight > MAX_BASIS_POINTS
        {
            return Err(fault(
                SjsLtoFaultCode::InvalidObligation,
                "obligation correspondence differs",
            ));
        }
        if o.mandatory && o.kind != SjsLtoObligationKind::GoverningRequirement {
            return Err(fault(
                SjsLtoFaultCode::InvalidObligation,
                "mandatory obligation is not governing",
            ));
        }
    }
    for c in &request.candidates {
        validate_candidate(c, &request.scope)?;
    }
    let mut pairs = BTreeSet::new();
    for e in &request.coverage_edges {
        validate_uuid_id(&e.relation_id, "coverage relation")?;
        if !candidate_ids.contains(&e.candidate_id)
            || !obligation_ids.contains(&e.obligation_id)
            || !pairs.insert((e.candidate_id.clone(), e.obligation_id.clone()))
        {
            return Err(fault(
                SjsLtoFaultCode::InvalidCoverage,
                "coverage edge differs",
            ));
        }
        let o = request
            .obligations
            .iter()
            .find(|o| o.obligation_id == e.obligation_id)
            .expect("set checked");
        let c = request
            .candidates
            .iter()
            .find(|c| c.candidate_id == e.candidate_id)
            .expect("set checked");
        if o.mandatory && c.source_binding.class != SjsLasSourceBindingClass::GoverningAnchor {
            return Err(fault(
                SjsLtoFaultCode::InvalidAuthority,
                "nonauthority candidate covers mandatory obligation",
            ));
        }
    }
    if request.input_class == SjsLtoInputClass::SyntheticProviderFreeFixture
        && (request.candidates.len() != 8
            || request.obligations.len() != 6
            || request.coverage_edges.len() != 12
            || request.policy.maximum_selected_count != 3)
    {
        return Err(fault(
            SjsLtoFaultCode::InvalidInputClass,
            "synthetic fixture shape differs",
        ));
    }
    Ok(())
}

fn validate_scope(scope: &SjsLtoSelectionScope) -> Result<(), SjsLtoFault> {
    if scope.source_identities.is_empty() || scope.source_identities.len() > MAX_REFERENCES {
        return Err(fault(
            SjsLtoFaultCode::InvalidScope,
            "scope source bound differs",
        ));
    }
    for id in &scope.source_identities {
        validate_uuid_id(id, "scope source")?;
    }
    for (v, l) in [
        (&scope.subject, "subject"),
        (&scope.objective, "objective"),
        (&scope.phase, "phase"),
        (&scope.feature, "feature"),
        (&scope.requirement, "requirement"),
        (&scope.artifact, "artifact"),
        (&scope.task_class, "task class"),
        (&scope.model_profile, "model profile"),
        (&scope.horizon, "horizon"),
        (&scope.context_assembly, "context assembly"),
        (&scope.tool_policy, "tool policy"),
        (&scope.authority_ceiling, "authority ceiling"),
        (&scope.compiled_stitch_profile, "compiled stitch profile"),
    ] {
        validate_text(v, l)?;
    }
    Ok(())
}

fn validate_policy(p: &SjsLtoSelectionPolicy) -> Result<(), SjsLtoFault> {
    if p.maximum_selected_count == 0
        || p.maximum_selected_count as usize > MAX_SELECTED
        || p.maximum_projected_bytes == 0
        || p.maximum_projected_bytes > MAX_PROJECTED_BYTES
        || p.maximum_token_estimate == 0
        || p.maximum_token_estimate > MAX_TOKEN_ESTIMATE
        || p.required_coverage_basis_points == 0
        || p.required_coverage_basis_points > MAX_BASIS_POINTS
    {
        return Err(fault(
            SjsLtoFaultCode::InvalidPolicy,
            "policy bound differs",
        ));
    }
    let expected_metrics = [
        "decision_relevance",
        "ambiguity_reduction",
        "action_relevance",
        "evidence_relevance",
        "fault_avoidance",
        "anchoring_risk",
        "unsupported_inference_risk",
        "stale_distance",
    ];
    if p.metric_precedence
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        != expected_metrics
        || p.source_precedence
            != [
                SjsLasSourceBindingClass::GoverningAnchor,
                SjsLasSourceBindingClass::PlanHint,
                SjsLasSourceBindingClass::ObservedCoordinate,
                SjsLasSourceBindingClass::NonauthorityEvidence,
            ]
        || p.placement_precedence.is_empty()
        || p.placement_precedence.iter().collect::<BTreeSet<_>>().len()
            != p.placement_precedence.len()
    {
        return Err(fault(
            SjsLtoFaultCode::InvalidPolicy,
            "policy ordering differs",
        ));
    }
    for v in &p.placement_precedence {
        validate_text(v, "placement precedence")?;
    }
    Ok(())
}

fn validate_candidate(
    c: &SjsLtoTermCandidate,
    scope: &SjsLtoSelectionScope,
) -> Result<(), SjsLtoFault> {
    validate_uuid_id(&c.candidate_id, "candidate")?;
    validate_uuid_id(&c.source_binding.source_id, "candidate source")?;
    for (v, l) in [
        (&c.semantic_identity, "semantic identity"),
        (&c.subject_anchor, "subject anchor"),
        (&c.semantic_turn.description, "semantic turn"),
        (&c.transform, "transform"),
        (&c.source_binding.locator, "source locator"),
        (&c.completion_cue.field, "completion field"),
        (&c.completion_cue.equals, "completion value"),
        (&c.placement_role, "placement role"),
        (&c.projected_surface, "projected surface"),
    ] {
        validate_text(v, l)?;
    }
    if c.scope_id != scope.scope_id
        || !scope
            .source_identities
            .contains(&c.source_binding.source_id)
        || c.projected_bytes != count_u64(c.projected_surface.len())?
        || c.projected_bytes == 0
        || c.projected_bytes > MAX_PROJECTED_BYTES
        || c.token_estimate == 0
        || c.token_estimate > MAX_TOKEN_ESTIMATE
        || c.invalidators.is_empty()
        || !c
            .invalidators
            .windows(2)
            .all(|p| (&p[0].field, &p[0].equals) < (&p[1].field, &p[1].equals))
    {
        return Err(fault(
            SjsLtoFaultCode::InvalidCandidate,
            "candidate correspondence or bound differs",
        ));
    }
    match c.source_binding.class {
        SjsLasSourceBindingClass::GoverningAnchor => {
            if c.source_binding
                .authority_identity
                .as_ref()
                .is_none_or(|v| v.is_empty())
            {
                return Err(fault(
                    SjsLtoFaultCode::InvalidAuthority,
                    "governing authority absent",
                ));
            }
        }
        _ => {
            if c.source_binding.authority_identity.is_some() {
                return Err(fault(
                    SjsLtoFaultCode::InvalidAuthority,
                    "nonauthority promoted",
                ));
            }
        }
    }
    for p in &c.invalidators {
        validate_text(&p.field, "invalidator field")?;
        validate_text(&p.equals, "invalidator value")?;
    }
    for v in [
        c.metrics.decision_relevance,
        c.metrics.ambiguity_reduction,
        c.metrics.action_relevance,
        c.metrics.evidence_relevance,
        c.metrics.fault_avoidance,
        c.metrics.anchoring_risk,
        c.metrics.unsupported_inference_risk,
        c.metrics.stale_distance,
    ] {
        if v > MAX_BASIS_POINTS {
            return Err(fault(
                SjsLtoFaultCode::InvalidBound,
                "candidate metric differs",
            ));
        }
    }
    Ok(())
}

fn coverage_map(request: &SjsLtoRequest) -> BTreeMap<SemanticId, BTreeSet<SemanticId>> {
    let mut m = BTreeMap::new();
    for c in &request.candidates {
        m.insert(c.candidate_id.clone(), BTreeSet::new());
    }
    for e in &request.coverage_edges {
        m.get_mut(&e.candidate_id)
            .expect("validated candidate")
            .insert(e.obligation_id.clone());
    }
    m
}
fn covered_for_indices(
    request: &SjsLtoRequest,
    coverage: &BTreeMap<SemanticId, BTreeSet<SemanticId>>,
    indices: &[usize],
) -> BTreeSet<SemanticId> {
    let mut s = BTreeSet::new();
    for i in indices {
        s.extend(
            coverage[&request.candidates[*i].candidate_id]
                .iter()
                .cloned(),
        );
    }
    s
}

fn evaluate_subset(
    request: &SjsLtoRequest,
    coverage: &BTreeMap<SemanticId, BTreeSet<SemanticId>>,
    indices: Vec<usize>,
    mandatory_total: usize,
) -> Result<EvaluatedSubset, SjsLtoFault> {
    let covered = covered_for_indices(request, coverage, &indices);
    let total_weight = request.obligations.iter().try_fold(0_u64, |a, o| {
        a.checked_add(u64::from(o.weight))
            .ok_or_else(|| fault(SjsLtoFaultCode::ArithmeticOverflow, "weight overflow"))
    })?;
    let covered_weight = request
        .obligations
        .iter()
        .filter(|o| covered.contains(&o.obligation_id))
        .try_fold(0_u64, |a, o| {
            a.checked_add(u64::from(o.weight)).ok_or_else(|| {
                fault(
                    SjsLtoFaultCode::ArithmeticOverflow,
                    "covered weight overflow",
                )
            })
        })?;
    let coverage_bp = u32::try_from(
        covered_weight.checked_mul(10_000).ok_or_else(|| {
            fault(
                SjsLtoFaultCode::ArithmeticOverflow,
                "coverage multiply overflow",
            )
        })? / total_weight,
    )
    .map_err(|_| fault(SjsLtoFaultCode::ArithmeticOverflow, "coverage conversion"))?;
    let mut o = SjsLtoObjectiveAccount {
        selected_count: count_u32(indices.len())?,
        coverage_basis_points: coverage_bp,
        identity_vector: indices
            .iter()
            .map(|i| request.candidates[*i].candidate_id.clone())
            .collect(),
        ..Default::default()
    };
    for i in &indices {
        let c = &request.candidates[*i];
        o.decision_relevance = add(o.decision_relevance, c.metrics.decision_relevance)?;
        o.ambiguity_reduction = add(o.ambiguity_reduction, c.metrics.ambiguity_reduction)?;
        o.action_relevance = add(o.action_relevance, c.metrics.action_relevance)?;
        o.evidence_relevance = add(o.evidence_relevance, c.metrics.evidence_relevance)?;
        o.fault_avoidance = add(o.fault_avoidance, c.metrics.fault_avoidance)?;
        o.anchoring_risk = add(o.anchoring_risk, c.metrics.anchoring_risk)?;
        o.unsupported_inference_risk = add(
            o.unsupported_inference_risk,
            c.metrics.unsupported_inference_risk,
        )?;
        o.stale_distance = add(o.stale_distance, c.metrics.stale_distance)?;
        o.projected_bytes = o
            .projected_bytes
            .checked_add(c.projected_bytes)
            .ok_or_else(|| fault(SjsLtoFaultCode::ArithmeticOverflow, "byte sum overflow"))?;
        o.token_estimate = o
            .token_estimate
            .checked_add(c.token_estimate)
            .ok_or_else(|| fault(SjsLtoFaultCode::ArithmeticOverflow, "token sum overflow"))?;
    }
    let mandatory_covered = request
        .obligations
        .iter()
        .filter(|x| x.mandatory && covered.contains(&x.obligation_id))
        .count();
    let budget = o.projected_bytes <= request.policy.maximum_projected_bytes
        && o.token_estimate <= request.policy.maximum_token_estimate;
    let feasible = budget
        && mandatory_covered == mandatory_total
        && o.coverage_basis_points >= request.policy.required_coverage_basis_points;
    Ok(EvaluatedSubset {
        indices,
        objective: o,
        mandatory_covered,
        budget_admitted: budget,
        feasible,
    })
}

fn objective_better(a: &SjsLtoObjectiveAccount, b: &SjsLtoObjectiveAccount) -> bool {
    use std::cmp::Ordering;
    let comparisons = [
        a.selected_count.cmp(&b.selected_count),
        b.coverage_basis_points.cmp(&a.coverage_basis_points),
        b.decision_relevance.cmp(&a.decision_relevance),
        b.ambiguity_reduction.cmp(&a.ambiguity_reduction),
        b.action_relevance.cmp(&a.action_relevance),
        b.evidence_relevance.cmp(&a.evidence_relevance),
        b.fault_avoidance.cmp(&a.fault_avoidance),
        a.anchoring_risk.cmp(&b.anchoring_risk),
        a.unsupported_inference_risk
            .cmp(&b.unsupported_inference_risk),
        a.stale_distance.cmp(&b.stale_distance),
        a.projected_bytes.cmp(&b.projected_bytes),
        a.token_estimate.cmp(&b.token_estimate),
        a.identity_vector.cmp(&b.identity_vector),
    ];
    comparisons.into_iter().find(|v| *v != Ordering::Equal) == Some(Ordering::Less)
}
fn partial_better(a: &EvaluatedSubset, b: &EvaluatedSubset) -> bool {
    (
        std::cmp::Reverse(a.mandatory_covered),
        std::cmp::Reverse(a.objective.coverage_basis_points),
        a.objective.selected_count,
        &a.objective.identity_vector,
    ) < (
        std::cmp::Reverse(b.mandatory_covered),
        std::cmp::Reverse(b.objective.coverage_basis_points),
        b.objective.selected_count,
        &b.objective.identity_vector,
    )
}
fn clone_evaluated(v: &EvaluatedSubset) -> EvaluatedSubset {
    EvaluatedSubset {
        indices: v.indices.clone(),
        objective: v.objective.clone(),
        mandatory_covered: v.mandatory_covered,
        budget_admitted: v.budget_admitted,
        feasible: v.feasible,
    }
}

fn candidate_accounts(
    request: &SjsLtoRequest,
    coverage: &BTreeMap<SemanticId, BTreeSet<SemanticId>>,
    selected: &[usize],
) -> Result<Vec<SjsLtoCandidateAccount>, SjsLtoFault> {
    let selected_ids = selected
        .iter()
        .map(|i| request.candidates[*i].candidate_id.clone())
        .collect::<BTreeSet<_>>();
    let mut out = Vec::new();
    for c in &request.candidates {
        let comparator = request
            .candidates
            .iter()
            .find(|other| other.candidate_id != c.candidate_id && dominates(other, c, coverage));
        let (disposition, reason, comparator_id) = if selected_ids.contains(&c.candidate_id) {
            (
                SjsLtoCandidateDisposition::Selected,
                "member of unique best feasible exact-pool set".to_owned(),
                None,
            )
        } else if c.projected_bytes > request.policy.maximum_projected_bytes
            || c.token_estimate > request.policy.maximum_token_estimate
        {
            (
                SjsLtoCandidateDisposition::Ineligible,
                "candidate alone exceeds a declared budget".to_owned(),
                None,
            )
        } else if let Some(d) = comparator {
            (SjsLtoCandidateDisposition::Dominated,"same-scope candidate has supplied superset coverage and no-worse objective dimensions".to_owned(),Some(d.candidate_id.clone()))
        } else {
            (
                SjsLtoCandidateDisposition::FeasibleNotSelected,
                "admitted candidate is not in the unique best feasible set".to_owned(),
                None,
            )
        };
        out.push(SjsLtoCandidateAccount {
            candidate_id: c.candidate_id.clone(),
            disposition,
            covered_obligation_ids: coverage[&c.candidate_id].iter().cloned().collect(),
            comparator_id,
            reason,
        });
    }
    Ok(out)
}
fn dominates(
    a: &SjsLtoTermCandidate,
    b: &SjsLtoTermCandidate,
    coverage: &BTreeMap<SemanticId, BTreeSet<SemanticId>>,
) -> bool {
    if a.scope_id != b.scope_id || a.source_binding.class != b.source_binding.class {
        return false;
    }
    let ac = &coverage[&a.candidate_id];
    let bc = &coverage[&b.candidate_id];
    let no_worse = ac.is_superset(bc)
        && a.projected_bytes <= b.projected_bytes
        && a.token_estimate <= b.token_estimate
        && a.metrics.decision_relevance >= b.metrics.decision_relevance
        && a.metrics.ambiguity_reduction >= b.metrics.ambiguity_reduction
        && a.metrics.action_relevance >= b.metrics.action_relevance
        && a.metrics.evidence_relevance >= b.metrics.evidence_relevance
        && a.metrics.fault_avoidance >= b.metrics.fault_avoidance
        && a.metrics.anchoring_risk <= b.metrics.anchoring_risk
        && a.metrics.unsupported_inference_risk <= b.metrics.unsupported_inference_risk
        && a.metrics.stale_distance <= b.metrics.stale_distance;
    no_worse
        && (ac != bc
            || a.projected_bytes < b.projected_bytes
            || a.token_estimate < b.token_estimate
            || a.metrics != b.metrics)
}
fn placement_key(
    request: &SjsLtoRequest,
    c: &SjsLtoTermCandidate,
) -> (usize, u32, usize, SemanticId) {
    let source = request
        .policy
        .source_precedence
        .iter()
        .position(|v| *v == c.source_binding.class)
        .unwrap_or(usize::MAX);
    let place = request
        .policy
        .placement_precedence
        .iter()
        .position(|v| v == &c.placement_role)
        .unwrap_or(usize::MAX);
    (source, c.dependency_rank, place, c.candidate_id.clone())
}

pub fn synthetic_sjs_lto_request() -> Result<SjsLtoRequest, SjsLtoFault> {
    let scope_id = id("scope:83000000-0000-4000-8000-000000000001")?;
    let gov = id("source:83000000-0000-4000-8000-000000000010")?;
    let plan = id("source:83000000-0000-4000-8000-000000000011")?;
    let observed = id("source:83000000-0000-4000-8000-000000000012")?;
    let evidence = id("source:83000000-0000-4000-8000-000000000013")?;
    let mut scope = SjsLtoSelectionScope {
        scope_id: scope_id.clone(),
        source_identities: [
            gov.clone(),
            plan.clone(),
            observed.clone(),
            evidence.clone(),
        ]
        .into_iter()
        .collect(),
        subject: "compiled lookahead selection".to_owned(),
        objective: "select the smallest exact governed term set".to_owned(),
        phase: "implementation".to_owned(),
        feature: "term_set_optimization_p0".to_owned(),
        requirement: "LTO-001..032".to_owned(),
        artifact: "synthetic fixture".to_owned(),
        task_class: "code_change".to_owned(),
        model_profile: "needle2-pinned-unobserved".to_owned(),
        horizon: "one governed work scope".to_owned(),
        context_assembly: "compiled stitch".to_owned(),
        tool_policy: "provider-free".to_owned(),
        authority_ceiling: "supplied public exact pool only".to_owned(),
        compiled_stitch_profile: "cantor-sjs-compiled-lookahead-stitch-request/0.1".to_owned(),
        scope_digest: empty_digest(),
    };
    scope.scope_digest = sha256_form(SCOPE_DOMAIN, &scope)?;
    let obligation_specs = [
        (
            1,
            SjsLtoObligationKind::GoverningRequirement,
            3000,
            true,
            &gov,
        ),
        (
            2,
            SjsLtoObligationKind::GoverningRequirement,
            2500,
            true,
            &gov,
        ),
        (3, SjsLtoObligationKind::CurrentDecision, 1500, false, &plan),
        (
            4,
            SjsLtoObligationKind::ActionCoordinate,
            1000,
            false,
            &observed,
        ),
        (
            5,
            SjsLtoObligationKind::EvidenceGate,
            1000,
            false,
            &evidence,
        ),
        (6, SjsLtoObligationKind::KnownFault, 1000, false, &evidence),
    ];
    let obligations = obligation_specs
        .into_iter()
        .map(|(n, kind, weight, mandatory, source)| SjsLtoObligation {
            obligation_id: id(&format!("obligation:83000000-0000-4000-8000-{n:012}"))
                .expect("fixed id"),
            kind,
            description: format!("fixture obligation {n}"),
            weight,
            mandatory,
            source_id: source.clone(),
            scope_id: scope_id.clone(),
        })
        .collect::<Vec<_>>();
    let classes = [
        SjsLasSourceBindingClass::GoverningAnchor,
        SjsLasSourceBindingClass::GoverningAnchor,
        SjsLasSourceBindingClass::PlanHint,
        SjsLasSourceBindingClass::GoverningAnchor,
        SjsLasSourceBindingClass::PlanHint,
        SjsLasSourceBindingClass::NonauthorityEvidence,
        SjsLasSourceBindingClass::ObservedCoordinate,
        SjsLasSourceBindingClass::PlanHint,
    ];
    let source_ids = [
        gov.clone(),
        gov.clone(),
        plan.clone(),
        gov,
        plan,
        evidence.clone(),
        observed,
        evidence,
    ];
    let surfaces = [
        "a",
        "govern",
        "route gates and fault",
        "long dominated governing anchor",
        "coordinate",
        "evidence",
        "fault",
        "decision route",
    ];
    let mut candidates = Vec::new();
    for n in 1..=8 {
        let class = classes[n - 1];
        let authority = if class == SjsLasSourceBindingClass::GoverningAnchor {
            Some("governing-sjs".to_owned())
        } else {
            None
        };
        let mut c = SjsLtoTermCandidate {
            candidate_id: id(&format!("candidate:83000000-0000-4000-8001-{n:012}"))?,
            semantic_identity: format!("fixture semantic {n}"),
            subject_anchor: "term-set selector".to_owned(),
            semantic_turn: SjsLasSemanticTurn {
                kind: if n <= 2 {
                    SjsLasSemanticTurnKind::ConserveInvariant
                } else {
                    SjsLasSemanticTurnKind::RouteEvidenceGate
                },
                description: format!("fixture turn {n}"),
            },
            transform: format!("fixture transform {n}"),
            scope_id: scope_id.clone(),
            source_binding: SjsLasSourceBinding {
                source_id: source_ids[n - 1].clone(),
                class,
                locator: format!("fixture/source/{n}"),
                authority_identity: authority,
            },
            completion_cue: SjsLasPredicate {
                field: "state".to_owned(),
                equals: "complete".to_owned(),
            },
            invalidators: vec![SjsLasPredicate {
                field: "scope".to_owned(),
                equals: "changed".to_owned(),
            }],
            placement_role: if n <= 2 {
                "prefix".to_owned()
            } else {
                "body".to_owned()
            },
            dependency_rank: n as u32,
            projected_surface: surfaces[n - 1].to_owned(),
            projected_bytes: surfaces[n - 1].len() as u64,
            token_estimate: 1 + surfaces[n - 1].split_whitespace().count() as u64,
            metrics: SjsLtoCandidateMetrics {
                decision_relevance: 9000 - (n as u32 * 100),
                ambiguity_reduction: 8000 - (n as u32 * 100),
                action_relevance: 7000 - (n as u32 * 100),
                evidence_relevance: 6000 - (n as u32 * 100),
                fault_avoidance: 5000 - (n as u32 * 100),
                anchoring_risk: n as u32 * 10,
                unsupported_inference_risk: n as u32 * 10,
                stale_distance: n as u32 * 10,
            },
            candidate_digest: empty_digest(),
        };
        c.candidate_digest = sha256_form(CANDIDATE_DOMAIN, &c)?;
        candidates.push(c);
    }
    let edge_specs = [
        (1, 1),
        (1, 3),
        (2, 2),
        (3, 4),
        (3, 5),
        (3, 6),
        (4, 1),
        (5, 4),
        (6, 5),
        (7, 6),
        (8, 3),
        (8, 4),
    ];
    let edges = edge_specs
        .into_iter()
        .enumerate()
        .map(|(i, (c, o))| SjsLtoCoverageEdge {
            relation_id: id(&format!("relation:83000000-0000-4000-8002-{:012}", i + 1))
                .expect("fixed id"),
            candidate_id: candidates[c - 1].candidate_id.clone(),
            obligation_id: obligations[o - 1].obligation_id.clone(),
        })
        .collect();
    let mut policy = SjsLtoSelectionPolicy {
        policy_id: id("policy:83000000-0000-4000-8000-000000000020")?,
        maximum_selected_count: 3,
        maximum_projected_bytes: 128,
        maximum_token_estimate: 64,
        required_coverage_basis_points: 10_000,
        metric_precedence: [
            "decision_relevance",
            "ambiguity_reduction",
            "action_relevance",
            "evidence_relevance",
            "fault_avoidance",
            "anchoring_risk",
            "unsupported_inference_risk",
            "stale_distance",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        source_precedence: vec![
            SjsLasSourceBindingClass::GoverningAnchor,
            SjsLasSourceBindingClass::PlanHint,
            SjsLasSourceBindingClass::ObservedCoordinate,
            SjsLasSourceBindingClass::NonauthorityEvidence,
        ],
        placement_precedence: vec!["prefix".to_owned(), "body".to_owned(), "suffix".to_owned()],
        policy_digest: empty_digest(),
    };
    policy.policy_digest = sha256_form(POLICY_DOMAIN, &policy)?;
    seal_sjs_lto_request(SjsLtoRequest {
        profile: SJS_LTO_REQUEST_PROFILE.to_owned(),
        request_id: id("request:83000000-0000-4000-8000-000000000021")?,
        run_id: id("run:83000000-0000-4000-8000-000000000022")?,
        receipt_id: id("receipt:83000000-0000-4000-8000-000000000023")?,
        input_class: SjsLtoInputClass::SyntheticProviderFreeFixture,
        canonical_uuid: SJS_LTO_CANONICAL_UUID.to_owned(),
        signature_uuid: SJS_LTO_SIGNATURE_UUID.to_owned(),
        source_snapshot_uuid: SJS_LTO_SOURCE_UUID.to_owned(),
        stitch_source_uuid: SJS_LTO_STITCH_SOURCE_UUID.to_owned(),
        stitch_canonical_uuid: SJS_LTO_STITCH_CANONICAL_UUID.to_owned(),
        scope,
        policy,
        obligations,
        candidates,
        coverage_edges: edges,
        evidence_refs: BTreeSet::new(),
        non_authority: SJS_LTO_NON_AUTHORITY.to_owned(),
        request_digest: empty_digest(),
    })
}

fn digest_without<T: Clone + Serialize>(
    value: &T,
    domain: &str,
    field: impl Fn(&mut T) -> &mut ContentDigest,
) -> Result<ContentDigest, SjsLtoFault> {
    let mut v = value.clone();
    *field(&mut v) = empty_digest();
    sha256_form(domain, &v)
}
fn sha256_form<T: Serialize>(domain: &str, value: &T) -> Result<ContentDigest, SjsLtoFault> {
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
fn add(a: u64, b: u32) -> Result<u64, SjsLtoFault> {
    a.checked_add(u64::from(b))
        .ok_or_else(|| fault(SjsLtoFaultCode::ArithmeticOverflow, "metric sum overflow"))
}
fn count_u32(v: usize) -> Result<u32, SjsLtoFault> {
    u32::try_from(v).map_err(|_| fault(SjsLtoFaultCode::ArithmeticOverflow, "usize to u32"))
}
fn count_u64(v: usize) -> Result<u64, SjsLtoFault> {
    u64::try_from(v).map_err(|_| fault(SjsLtoFaultCode::ArithmeticOverflow, "usize to u64"))
}
fn id(v: &str) -> Result<SemanticId, SjsLtoFault> {
    SemanticId::new(v).map_err(|e| fault(SjsLtoFaultCode::InvalidIdentity, e.to_string()))
}
fn validate_uuid_id(id: &SemanticId, label: &str) -> Result<(), SjsLtoFault> {
    let suffix = id.as_str().rsplit(':').next().unwrap_or_default();
    let b = suffix.as_bytes();
    let ok = b.len() == 36
        && b.iter().enumerate().all(|(i, c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                *c == b'-'
            } else {
                c.is_ascii_digit() || matches!(c, b'a'..=b'f')
            }
        })
        && suffix != "00000000-0000-0000-0000-000000000000";
    if ok {
        Ok(())
    } else {
        Err(fault(
            SjsLtoFaultCode::InvalidIdentity,
            format!("{label} is not lowercase nonnil UUID-bearing"),
        ))
    }
}
fn validate_text(v: &str, label: &str) -> Result<(), SjsLtoFault> {
    if !v.is_empty()
        && v.len() <= MAX_TEXT_BYTES
        && v.trim() == v
        && v.chars().all(|c| !c.is_control() && c != '\u{7f}')
    {
        Ok(())
    } else {
        Err(fault(
            SjsLtoFaultCode::InvalidText,
            format!("{label} differs"),
        ))
    }
}
fn strictly_sorted_by<T, K: Ord>(v: &[T], key: impl Fn(&T) -> &K) -> bool {
    v.windows(2).all(|p| key(&p[0]) < key(&p[1]))
}
fn to_machine_form<T: Serialize>(v: &T) -> Result<String, SjsLtoFault> {
    serde_json::to_string(v).map_err(machine_fault)
}
fn canonical_file(value: String) -> String {
    format!("{value}\n")
}
fn canonical_file_body<'a>(value: &'a str, label: &str) -> Result<&'a str, SjsLtoFault> {
    value.strip_suffix('\n').ok_or_else(|| {
        fault(
            SjsLtoFaultCode::InvalidMachineForm,
            format!("{label} lacks one LF"),
        )
    })
}
fn parse_bounded<T: DeserializeOwned + Serialize>(value: &str) -> Result<T, SjsLtoFault> {
    parse_bounded_with_limit(value, SJS_LTO_MAX_MACHINE_FORM_BYTES)
}
fn parse_bounded_with_limit<T: DeserializeOwned + Serialize>(
    value: &str,
    limit: usize,
) -> Result<T, SjsLtoFault> {
    if value.len() > limit {
        return Err(fault(
            SjsLtoFaultCode::InvalidBound,
            "machine form too large",
        ));
    }
    let mut d = serde_json::Deserializer::from_str(value);
    NoDuplicateJson::deserialize(&mut d).map_err(machine_fault)?;
    d.end().map_err(machine_fault)?;
    let shape: Value = serde_json::from_str(value).map_err(machine_fault)?;
    let mut fields = 0;
    validate_json_shape(&shape, 1, &mut fields, None)?;
    let parsed: T = serde_json::from_str(value).map_err(machine_fault)?;
    if to_machine_form(&parsed)? != value {
        return Err(fault(
            SjsLtoFaultCode::InvalidMachineForm,
            "machine form is not compact canonical JSON",
        ));
    }
    Ok(parsed)
}
struct NoDuplicateJson;
impl<'de> Deserialize<'de> for NoDuplicateJson {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(NoDuplicateVisitor)?;
        Ok(Self)
    }
}
struct NoDuplicateVisitor;
impl<'de> Visitor<'de> for NoDuplicateVisitor {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("strict JSON")
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
    fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<(), A::Error> {
        while s.next_element::<NoDuplicateJson>()?.is_some() {}
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<(), A::Error> {
        let mut keys = BTreeSet::new();
        while let Some(k) = m.next_key::<String>()? {
            if !keys.insert(k.clone()) {
                return Err(serde::de::Error::custom(format!("duplicate key {k}")));
            }
            m.next_value::<NoDuplicateJson>()?;
        }
        Ok(())
    }
}
fn validate_json_shape(
    v: &Value,
    depth: usize,
    fields: &mut usize,
    parent_key: Option<&str>,
) -> Result<(), SjsLtoFault> {
    if depth > MAX_DEPTH {
        return Err(fault(
            SjsLtoFaultCode::InvalidMachineForm,
            "depth exceeds 40",
        ));
    }
    match v {
        Value::Object(m) => {
            *fields = fields
                .checked_add(m.len())
                .ok_or_else(|| fault(SjsLtoFaultCode::ArithmeticOverflow, "field count"))?;
            if *fields > MAX_FIELDS {
                return Err(fault(
                    SjsLtoFaultCode::InvalidMachineForm,
                    "fields exceed 16384",
                ));
            }
            for (k, v) in m {
                validate_text(k, "field")?;
                validate_json_shape(v, depth + 1, fields, Some(k))?;
            }
        }
        Value::Array(a) => {
            for v in a {
                validate_json_shape(v, depth + 1, fields, None)?
            }
        }
        Value::String(s) => {
            let evidence_file = matches!(
                parent_key,
                Some("request_file" | "envelope_file" | "verification_file" | "manifest_file")
            );
            if evidence_file {
                if s.len() > SJS_LTO_MAX_EVIDENCE_BYTES {
                    return Err(fault(
                        SjsLtoFaultCode::InvalidBound,
                        "embedded evidence file exceeds bound",
                    ));
                }
            } else {
                validate_text(s, "machine text")?;
            }
        }
        _ => {}
    }
    Ok(())
}
fn machine_fault(e: impl fmt::Display) -> SjsLtoFault {
    fault(SjsLtoFaultCode::InvalidMachineForm, e.to_string())
}
fn fault(code: SjsLtoFaultCode, detail: impl Into<String>) -> SjsLtoFault {
    SjsLtoFault {
        code,
        detail: detail.into(),
    }
}
