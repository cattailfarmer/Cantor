//! Strict pure forms for the semantic anchor catalogue P0.
//!
//! This slice defines and validates data only. It does not derive a catalogue,
//! scan a fabric, invoke a provider, persist state, or authorize an effect.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    AuthorityContext, BoundaryAccount, ContentDigest, RelationType, RequestedDetailKind,
    SemanticId, SourceAnchor, UnitKind,
};

pub const SEMANTIC_ANCHOR_CATALOGUE_PROFILE: &str = "cantor-semantic-anchor-catalogue/0.1";
pub const ANCHOR_QUERY_PROFILE: &str = "cantor-anchor-query/0.1";
pub const ANCHOR_QUERY_RESULT_PROFILE: &str = "cantor-anchor-query-result/0.1";

const DIGEST_ALGORITHM: &str = "sha256";
const DERIVATION_DOMAIN: &str = "cantor.semantic-anchor-catalogue.derivation.v1";
const CATALOGUE_DOMAIN: &str = "cantor.semantic-anchor-catalogue.root.v1";
const RESULT_DOMAIN: &str = "cantor.semantic-anchor-catalogue.result.v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogueIdentity {
    pub profile: String,
    pub catalogue_id: SemanticId,
    pub catalogue_root: ContentDigest,
    pub fabric_root: ContentDigest,
    pub package_roots: BTreeMap<SemanticId, ContentDigest>,
    pub compiler_id: SemanticId,
    pub compiler_version: String,
    pub derivation_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticAddress {
    pub unit_id: SemanticId,
    pub unit_digest: ContentDigest,
    pub package_id: SemanticId,
    pub package_digest: ContentDigest,
    pub kind: UnitKind,
    pub context_id: SemanticId,
    pub version: String,
    pub source_anchors: Vec<SourceAnchor>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityAnchorEntry {
    pub address: SemanticAddress,
    pub preferred_expression: String,
    pub aliases: BTreeSet<String>,
    pub meaning_ref: SemanticId,
    pub purposes: BTreeSet<String>,
    pub use_cases: BTreeSet<String>,
    pub included_boundaries: BTreeSet<String>,
    pub excluded_boundaries: BTreeSet<String>,
    pub protected_identities: BTreeSet<SemanticId>,
    pub relation_refs: BTreeSet<SemanticId>,
    pub lifecycle: AnchorLifecycle,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AnchorLifecycle {
    Admitted,
    Stale,
    Revoked,
    Superseded,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum OperationClass {
    Relation,
    Observation,
    Query,
    Inference,
    Transformation,
    Validation,
    Control,
    Capability,
    PhysicalEffect,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationRole {
    pub name: String,
    pub required: bool,
    pub accepted_kinds: Vec<UnitKind>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationAnchorEntry {
    pub address: SemanticAddress,
    pub operation_class: OperationClass,
    pub verbs: BTreeSet<String>,
    pub aliases: BTreeSet<String>,
    pub roles: Vec<OperationRole>,
    pub preconditions: BTreeSet<String>,
    pub invariants: BTreeSet<String>,
    pub postconditions: BTreeSet<String>,
    pub failure_conditions: BTreeSet<String>,
    pub authority_requirements: BTreeSet<String>,
    pub effect_class: String,
    pub non_transfer_set: BTreeSet<String>,
    pub applicability_refs: BTreeSet<SemanticId>,
    pub lifecycle: AnchorLifecycle,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ApplicabilityStatus {
    Declared,
    Derived,
    Candidate,
    Contradicted,
    Blocked,
    Stale,
    Unresolved,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicabilityBinding {
    pub binding_id: SemanticId,
    pub operation_ref: SemanticId,
    pub role_ref: String,
    pub identity_ref: Option<SemanticId>,
    pub admitted_kind: Option<UnitKind>,
    pub context: String,
    pub purpose: String,
    pub conditions: BTreeSet<String>,
    pub boundary_refs: BTreeSet<SemanticId>,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub transfer_law: String,
    pub non_transfer_set: BTreeSet<String>,
    pub authority_ref: Option<SemanticId>,
    pub status: ApplicabilityStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticAnchorCatalogue {
    pub identity: CatalogueIdentity,
    pub identity_entries: Vec<IdentityAnchorEntry>,
    pub operation_entries: Vec<OperationAnchorEntry>,
    pub applicability_bindings: Vec<ApplicabilityBinding>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AssociationChannel {
    ExactIdentity,
    ExactLabel,
    DeclaredApplicability,
    TypedRelation,
    Lexical,
    Embedding,
    LearnedRoute,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", deny_unknown_fields)]
pub enum ChannelLocalValue {
    Exact,
    Declared,
    RelationHops(u16),
    RelevanceBasisPoints(u16),
    LearnedBasisPoints {
        basis_points: u16,
        model_digest: ContentDigest,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ContributionStatus {
    Proposed,
    Retained,
    Excluded,
    Contradicted,
    Stale,
    Incompatible,
    Clipped,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssociationContribution {
    pub channel: AssociationChannel,
    pub candidate_address: SemanticAddress,
    pub basis: String,
    pub channel_local_value: ChannelLocalValue,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub conditions: BTreeSet<String>,
    pub unresolved_guards: BTreeSet<String>,
    pub status: ContributionStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PriorityTier {
    ExactIdentity,
    ExactLabel,
    DeclaredApplicability,
    TypedRelation,
    Lexical,
    Embedding,
    LearnedRoute,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CandidateEligibility {
    Eligible,
    Excluded,
    Ambiguous,
    Contradicted,
    Unknown,
    Stale,
    Unauthorized,
    Unresolved,
    Clipped,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorCandidate {
    pub address: SemanticAddress,
    pub contributions: Vec<AssociationContribution>,
    pub priority_tier: PriorityTier,
    pub channel_local_rank: u32,
    pub eligibility: CandidateEligibility,
    pub unresolved_guards: BTreeSet<String>,
    pub exact_resolution_required: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorBudget {
    pub maximum_candidates: u32,
    pub maximum_records: u32,
    pub maximum_paths: u32,
    pub maximum_depth: u16,
    pub maximum_bytes: u64,
    pub maximum_elapsed_milliseconds: u64,
    pub maximum_continuations: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorQuery {
    pub profile: String,
    pub request_id: SemanticId,
    pub term_set: BTreeSet<String>,
    pub subject: Option<String>,
    pub purpose: String,
    pub use_cases: BTreeSet<String>,
    pub include_boundaries: BTreeSet<String>,
    pub exclude_boundaries: BTreeSet<String>,
    pub known_identities: BTreeSet<SemanticId>,
    pub requested_details: BTreeSet<RequestedDetailKind>,
    pub allowed_relations: BTreeSet<RelationType>,
    pub allowed_channels: BTreeSet<AssociationChannel>,
    pub authority_context: AuthorityContext,
    pub budget: AnchorBudget,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorProof {
    pub catalogue_root: ContentDigest,
    pub fabric_root: ContentDigest,
    pub input_digest: ContentDigest,
    pub decisions: Vec<String>,
    pub omissions: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorQueryResult {
    pub profile: String,
    pub request_id: SemanticId,
    pub catalogue_root: ContentDigest,
    pub fabric_root: ContentDigest,
    pub candidates: Vec<AnchorCandidate>,
    pub record_ids: Vec<SemanticId>,
    pub source_anchors: Vec<SourceAnchor>,
    pub boundary_account: BoundaryAccount,
    pub proof: AnchorProof,
    pub continuation: Option<String>,
    pub result_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AnchorFormFaultKind {
    InvalidProfile,
    InvalidDigest,
    InvalidBound,
    InvalidIdentity,
    DuplicateIdentity,
    NonCanonicalOrder,
    ChannelValueMismatch,
    PriorityMismatch,
    ExactResolutionDisabled,
    RootMismatch,
    ResultDigestMismatch,
    ScoreLaundering,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorFormFault {
    pub kind: AnchorFormFaultKind,
    pub field: String,
    pub detail: String,
}

type AnchorValidation<T = ()> = Result<T, AnchorFormFault>;

pub fn validate_semantic_anchor_catalogue(catalogue: &SemanticAnchorCatalogue) -> AnchorValidation {
    if catalogue.identity.profile != SEMANTIC_ANCHOR_CATALOGUE_PROFILE {
        return fault(
            AnchorFormFaultKind::InvalidProfile,
            "identity.profile",
            "wrong catalogue profile",
        );
    }
    validate_digest(&catalogue.identity.fabric_root, "identity.fabric_root")?;
    validate_digest(
        &catalogue.identity.catalogue_root,
        "identity.catalogue_root",
    )?;
    validate_digest(
        &catalogue.identity.derivation_digest,
        "identity.derivation_digest",
    )?;
    if catalogue.identity.package_roots.is_empty() || catalogue.identity.compiler_version.is_empty()
    {
        return fault(
            AnchorFormFaultKind::InvalidIdentity,
            "identity",
            "package roots and compiler version are required",
        );
    }
    for digest in catalogue.identity.package_roots.values() {
        validate_digest(digest, "identity.package_roots")?;
    }
    ensure_sorted_unique_by(
        &catalogue.identity_entries,
        |entry| entry.address.unit_id.as_str(),
        "identity_entries",
    )?;
    ensure_sorted_unique_by(
        &catalogue.operation_entries,
        |entry| entry.address.unit_id.as_str(),
        "operation_entries",
    )?;
    ensure_sorted_unique_by(
        &catalogue.applicability_bindings,
        |binding| binding.binding_id.as_str(),
        "applicability_bindings",
    )?;
    let operation_ids = catalogue
        .operation_entries
        .iter()
        .map(|entry| entry.address.unit_id.clone())
        .collect::<BTreeSet<_>>();
    let identity_ids = catalogue
        .identity_entries
        .iter()
        .map(|entry| entry.address.unit_id.clone())
        .collect::<BTreeSet<_>>();
    let binding_ids = catalogue
        .applicability_bindings
        .iter()
        .map(|binding| binding.binding_id.clone())
        .collect::<BTreeSet<_>>();
    for entry in &catalogue.identity_entries {
        validate_address(&entry.address)?;
        validate_address_package_root(&catalogue.identity, &entry.address)?;
        if entry.preferred_expression.trim().is_empty() {
            return fault(
                AnchorFormFaultKind::InvalidIdentity,
                "preferred_expression",
                "preferred expression is empty",
            );
        }
    }
    for entry in &catalogue.operation_entries {
        validate_address(&entry.address)?;
        validate_address_package_root(&catalogue.identity, &entry.address)?;
        if entry.verbs.is_empty()
            || entry.roles.is_empty()
            || entry.effect_class.trim().is_empty()
            || entry.address.kind != UnitKind::Operation
            || !entry.applicability_refs.is_subset(&binding_ids)
        {
            return fault(
                AnchorFormFaultKind::InvalidIdentity,
                "operation_entry",
                "verbs roles and effect class are required",
            );
        }
        for role in &entry.roles {
            if role.name.trim().is_empty() || role.accepted_kinds.is_empty() {
                return fault(
                    AnchorFormFaultKind::InvalidIdentity,
                    "operation_role",
                    "role name and accepted kinds are required",
                );
            }
        }
    }
    for binding in &catalogue.applicability_bindings {
        if binding.role_ref.trim().is_empty()
            || binding.context.trim().is_empty()
            || binding.purpose.trim().is_empty()
            || (binding.identity_ref.is_some() == binding.admitted_kind.is_some())
            || !operation_ids.contains(&binding.operation_ref)
            || binding
                .identity_ref
                .as_ref()
                .is_some_and(|identity| !identity_ids.contains(identity))
        {
            return fault(
                AnchorFormFaultKind::InvalidIdentity,
                "applicability_binding",
                "exactly one target and nonempty role context purpose are required",
            );
        }
    }
    let expected_derivation = catalogue_derivation_digest(&catalogue.identity)?;
    if catalogue.identity.derivation_digest != expected_derivation {
        return fault(
            AnchorFormFaultKind::InvalidDigest,
            "identity.derivation_digest",
            "derivation digest differs",
        );
    }
    let expected_root = catalogue_root(catalogue)?;
    if catalogue.identity.catalogue_root != expected_root {
        return fault(
            AnchorFormFaultKind::InvalidDigest,
            "identity.catalogue_root",
            "catalogue root differs",
        );
    }
    Ok(())
}

pub fn validate_anchor_query(query: &AnchorQuery) -> AnchorValidation {
    if query.profile != ANCHOR_QUERY_PROFILE {
        return fault(
            AnchorFormFaultKind::InvalidProfile,
            "profile",
            "wrong query profile",
        );
    }
    if query.term_set.is_empty()
        || query.purpose.trim().is_empty()
        || query.allowed_channels.is_empty()
        || query.budget.maximum_candidates == 0
        || query.budget.maximum_candidates > 1024
        || query.budget.maximum_records == 0
        || query.budget.maximum_records > 1024
        || query.budget.maximum_paths > 1024
        || query.budget.maximum_depth > 64
        || query.budget.maximum_bytes == 0
        || query.budget.maximum_bytes > 16 * 1024 * 1024
        || query.budget.maximum_elapsed_milliseconds == 0
        || query.budget.maximum_elapsed_milliseconds > 300_000
        || query.budget.maximum_continuations > 64
    {
        return fault(
            AnchorFormFaultKind::InvalidBound,
            "query",
            "query identity or bounds are invalid",
        );
    }
    if query
        .term_set
        .iter()
        .any(|term| term.trim().is_empty() || term.len() > 1024)
    {
        return fault(
            AnchorFormFaultKind::InvalidBound,
            "term_set",
            "term is empty or oversized",
        );
    }
    Ok(())
}

pub fn validate_anchor_candidate(candidate: &AnchorCandidate) -> AnchorValidation {
    validate_address(&candidate.address)?;
    if !candidate.exact_resolution_required {
        return fault(
            AnchorFormFaultKind::ExactResolutionDisabled,
            "exact_resolution_required",
            "exact resolution is mandatory",
        );
    }
    if candidate.contributions.is_empty() || candidate.channel_local_rank == 0 {
        return fault(
            AnchorFormFaultKind::InvalidBound,
            "candidate",
            "contributions and positive rank are required",
        );
    }
    let mut best: Option<PriorityTier> = None;
    for contribution in &candidate.contributions {
        validate_contribution(contribution)?;
        if contribution.candidate_address != candidate.address {
            return fault(
                AnchorFormFaultKind::InvalidIdentity,
                "candidate_address",
                "contribution address differs",
            );
        }
        if matches!(contribution.status, ContributionStatus::Retained) {
            let tier = tier_for_channel(&contribution.channel);
            if best.as_ref().is_none_or(|current| tier < *current) {
                best = Some(tier);
            }
        }
    }
    if best.as_ref() != Some(&candidate.priority_tier) {
        return fault(
            AnchorFormFaultKind::PriorityMismatch,
            "priority_tier",
            "priority does not equal highest retained channel",
        );
    }
    Ok(())
}

pub fn validate_anchor_query_result(result: &AnchorQueryResult) -> AnchorValidation {
    if result.profile != ANCHOR_QUERY_RESULT_PROFILE {
        return fault(
            AnchorFormFaultKind::InvalidProfile,
            "profile",
            "wrong result profile",
        );
    }
    validate_digest(&result.catalogue_root, "catalogue_root")?;
    validate_digest(&result.fabric_root, "fabric_root")?;
    validate_digest(&result.proof.catalogue_root, "proof.catalogue_root")?;
    validate_digest(&result.proof.fabric_root, "proof.fabric_root")?;
    validate_digest(&result.proof.input_digest, "proof.input_digest")?;
    if result.catalogue_root != result.proof.catalogue_root
        || result.fabric_root != result.proof.fabric_root
    {
        return fault(
            AnchorFormFaultKind::RootMismatch,
            "proof",
            "result and proof roots differ",
        );
    }
    for candidate in &result.candidates {
        validate_anchor_candidate(candidate)?;
        if matches!(candidate.eligibility, CandidateEligibility::Ambiguous)
            && !result
                .boundary_account
                .ambiguous
                .contains(&candidate.address.unit_id)
        {
            return fault(
                AnchorFormFaultKind::InvalidIdentity,
                "boundary_account.ambiguous",
                "ambiguous candidate is not accounted",
            );
        }
    }
    ensure_candidate_order(&result.candidates)?;
    ensure_sorted_unique_by(
        &result.record_ids,
        |record_id| record_id.as_str(),
        "record_ids",
    )?;
    let expected = anchor_query_result_digest(result)?;
    if result.result_digest != expected {
        return fault(
            AnchorFormFaultKind::ResultDigestMismatch,
            "result_digest",
            "result digest differs",
        );
    }
    Ok(())
}

pub fn catalogue_derivation_digest(
    identity: &CatalogueIdentity,
) -> AnchorValidation<ContentDigest> {
    digest_form(
        DERIVATION_DOMAIN,
        &(
            &identity.profile,
            &identity.catalogue_id,
            &identity.fabric_root,
            &identity.package_roots,
            &identity.compiler_id,
            &identity.compiler_version,
        ),
    )
}

pub fn catalogue_root(catalogue: &SemanticAnchorCatalogue) -> AnchorValidation<ContentDigest> {
    digest_form(
        CATALOGUE_DOMAIN,
        &(
            &catalogue.identity.profile,
            &catalogue.identity.catalogue_id,
            &catalogue.identity.fabric_root,
            &catalogue.identity.package_roots,
            &catalogue.identity.compiler_id,
            &catalogue.identity.compiler_version,
            &catalogue.identity.derivation_digest,
            &catalogue.identity_entries,
            &catalogue.operation_entries,
            &catalogue.applicability_bindings,
        ),
    )
}

pub fn anchor_query_result_digest(result: &AnchorQueryResult) -> AnchorValidation<ContentDigest> {
    digest_form(
        RESULT_DOMAIN,
        &(
            &result.profile,
            &result.request_id,
            &result.catalogue_root,
            &result.fabric_root,
            &result.candidates,
            &result.record_ids,
            &result.source_anchors,
            &result.boundary_account,
            &result.proof,
            &result.continuation,
        ),
    )
}

fn validate_contribution(contribution: &AssociationContribution) -> AnchorValidation {
    validate_address(&contribution.candidate_address)?;
    if contribution.basis.trim().is_empty() || contribution.basis.len() > 4096 {
        return fault(
            AnchorFormFaultKind::InvalidBound,
            "basis",
            "basis is empty or oversized",
        );
    }
    let compatible = matches!(
        (&contribution.channel, &contribution.channel_local_value),
        (
            AssociationChannel::ExactIdentity | AssociationChannel::ExactLabel,
            ChannelLocalValue::Exact
        ) | (
            AssociationChannel::DeclaredApplicability,
            ChannelLocalValue::Declared
        ) | (
            AssociationChannel::TypedRelation,
            ChannelLocalValue::RelationHops(1..=64)
        ) | (
            AssociationChannel::Lexical | AssociationChannel::Embedding,
            ChannelLocalValue::RelevanceBasisPoints(0..=10_000)
        ) | (
            AssociationChannel::LearnedRoute,
            ChannelLocalValue::LearnedBasisPoints {
                basis_points: 0..=10_000,
                ..
            }
        )
    );
    if !compatible {
        return fault(
            AnchorFormFaultKind::ChannelValueMismatch,
            "channel_local_value",
            "value shape is incompatible with channel",
        );
    }
    if let ChannelLocalValue::LearnedBasisPoints { model_digest, .. } =
        &contribution.channel_local_value
    {
        validate_digest(model_digest, "model_digest")?;
    }
    Ok(())
}

fn validate_address(address: &SemanticAddress) -> AnchorValidation {
    validate_digest(&address.unit_digest, "unit_digest")?;
    validate_digest(&address.package_digest, "package_digest")?;
    if address.version.trim().is_empty() {
        return fault(
            AnchorFormFaultKind::InvalidIdentity,
            "version",
            "address version is empty",
        );
    }
    for anchor in &address.source_anchors {
        validate_digest(&anchor.span_digest, "source_anchor.span_digest")?;
        if anchor.unit_id != address.unit_id
            || anchor.package_id != address.package_id
            || anchor.byte_start >= anchor.byte_end
            || anchor.display_line_start == 0
            || anchor.display_line_start > anchor.display_line_end
        {
            return fault(
                AnchorFormFaultKind::InvalidIdentity,
                "source_anchor",
                "source anchor differs from address or has invalid span",
            );
        }
    }
    Ok(())
}

fn validate_address_package_root(
    identity: &CatalogueIdentity,
    address: &SemanticAddress,
) -> AnchorValidation {
    if identity.package_roots.get(&address.package_id) != Some(&address.package_digest) {
        return fault(
            AnchorFormFaultKind::RootMismatch,
            "address.package_digest",
            "address package identity and digest are absent from catalogue package roots",
        );
    }
    Ok(())
}

fn validate_digest(digest: &ContentDigest, field: &str) -> AnchorValidation {
    if digest.algorithm != DIGEST_ALGORITHM
        || digest.value.len() != 64
        || !digest
            .value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return fault(
            AnchorFormFaultKind::InvalidDigest,
            field,
            "expected lowercase SHA-256",
        );
    }
    Ok(())
}

fn tier_for_channel(channel: &AssociationChannel) -> PriorityTier {
    match channel {
        AssociationChannel::ExactIdentity => PriorityTier::ExactIdentity,
        AssociationChannel::ExactLabel => PriorityTier::ExactLabel,
        AssociationChannel::DeclaredApplicability => PriorityTier::DeclaredApplicability,
        AssociationChannel::TypedRelation => PriorityTier::TypedRelation,
        AssociationChannel::Lexical => PriorityTier::Lexical,
        AssociationChannel::Embedding => PriorityTier::Embedding,
        AssociationChannel::LearnedRoute => PriorityTier::LearnedRoute,
    }
}

fn ensure_candidate_order(candidates: &[AnchorCandidate]) -> AnchorValidation {
    for pair in candidates.windows(2) {
        let left = (
            &pair[0].priority_tier,
            pair[0].channel_local_rank,
            pair[0].address.unit_id.as_str(),
        );
        let right = (
            &pair[1].priority_tier,
            pair[1].channel_local_rank,
            pair[1].address.unit_id.as_str(),
        );
        if left >= right {
            return fault(
                AnchorFormFaultKind::NonCanonicalOrder,
                "candidates",
                "candidates are not in canonical priority order",
            );
        }
    }
    Ok(())
}

fn ensure_sorted_unique_by<T, F>(values: &[T], mut key: F, field: &str) -> AnchorValidation
where
    F: FnMut(&T) -> &str,
{
    for pair in values.windows(2) {
        if key(&pair[0]) >= key(&pair[1]) {
            return fault(
                AnchorFormFaultKind::NonCanonicalOrder,
                field,
                "values are not strictly sorted and unique",
            );
        }
    }
    Ok(())
}

fn digest_form<T: Serialize>(domain: &str, value: &T) -> AnchorValidation<ContentDigest> {
    let bytes = serde_json::to_vec(value).map_err(|error| AnchorFormFault {
        kind: AnchorFormFaultKind::InvalidIdentity,
        field: "serialization".to_owned(),
        detail: error.to_string(),
    })?;
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(bytes);
    Ok(ContentDigest {
        algorithm: DIGEST_ALGORITHM.to_owned(),
        value: hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    })
}

fn fault<T>(kind: AnchorFormFaultKind, field: &str, detail: &str) -> AnchorValidation<T> {
    Err(AnchorFormFault {
        kind,
        field: field.to_owned(),
        detail: detail.to_owned(),
    })
}
