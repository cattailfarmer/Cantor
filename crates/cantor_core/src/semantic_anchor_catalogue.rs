//! Strict pure forms and admitted-fabric derivation for the semantic anchor
//! catalogue P0.
//!
//! Slice 1 defines and validates the closed machine forms. Slice 2 reads one
//! already admitted immutable semantic fabric and derives a disposable,
//! generation-bound catalogue projection. Slice 4B1 derives a separate,
//! disposable lexical token-posting sidecar from that validated projection and
//! the same fabric. It does not compile or admit source, scan a query, rank a
//! candidate, invoke a provider, persist state, or authorize an effect.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    AuthorityContext, AuthorityScope, BoundaryAccount, ContentDigest, RelationType,
    RequestedDetailKind, SemanticFabric, SemanticId, SourceAnchor, UnitKind, UnitStatus,
};

pub const SEMANTIC_ANCHOR_CATALOGUE_PROFILE: &str = "cantor-semantic-anchor-catalogue/0.1";
pub const ANCHOR_QUERY_PROFILE: &str = "cantor-anchor-query/0.1";
pub const ANCHOR_QUERY_RESULT_PROFILE: &str = "cantor-anchor-query-result/0.1";
pub const DERIVED_SEMANTIC_ANCHOR_CATALOGUE_PROFILE: &str =
    "cantor-derived-semantic-anchor-catalogue/0.1";
pub const DERIVED_LEXICAL_ASSOCIATION_INDEX_PROFILE: &str =
    "cantor-derived-lexical-association-index/0.1";
pub const LEXICAL_TOKENIZER_PROFILE: &str = "cantor-lexical-tokenizer/0.1";
pub const SEMANTIC_ANCHOR_CATALOGUE_COMPILER_ID: &str = "compiler:cantor_semantic_anchor_catalogue";
pub const SEMANTIC_ANCHOR_CATALOGUE_COMPILER_VERSION: &str = "0.1.0";
pub const LEXICAL_ASSOCIATION_INDEX_COMPILER_ID: &str = "compiler:cantor_lexical_association_index";
pub const LEXICAL_ASSOCIATION_INDEX_COMPILER_VERSION: &str = "0.1.0";
pub const LEXICAL_ANCHOR_LOOKUP_PROFILE: &str = "cantor-lexical-anchor-lookup/0.1";
pub const LEXICAL_ANCHOR_LOOKUP_RESULT_PROFILE: &str = "cantor-lexical-anchor-lookup-result/0.1";
pub const LEXICAL_ANCHOR_LOOKUP_NON_AUTHORITY: &str = "Lexical correspondence evidence only. Semantic purpose, truth, permission, authority, safety, applicability, lifecycle, and boundary gates did not run.";
pub const LEXICAL_ANCHOR_SOURCE_PROJECTION_RESULT_PROFILE: &str =
    "cantor-lexical-anchor-source-projection-result/0.1";
pub const LEXICAL_ANCHOR_SOURCE_PROJECTION_BOUNDARY: &str = "Quoted text and path correspond to the admitted signed package snapshot only. They do not assert current live-file state, semantic purpose, truth, permission, authority, safety, applicability, lifecycle, or boundary satisfaction.";
pub const MAX_LEXICAL_LOGICAL_REVISION_BYTES: usize = 256;
pub const MAX_LEXICAL_SURFACE_BYTES: usize = 16 * 1024;
pub const MAX_LEXICAL_TOKEN_BYTES: usize = 256;
pub const MAX_LEXICAL_TOKENS_PER_SURFACE: usize = 4096;
pub const MAX_LEXICAL_POSTINGS_PER_TOKEN: usize = 4096;
pub const MAX_LEXICAL_TOTAL_POSTINGS: usize = 262_144;
pub const MAX_LEXICAL_EVIDENCE_REFS: usize = 64;
pub const MAX_LEXICAL_INDEX_SERIALIZED_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_LEXICAL_LOOKUP_TERMS: u32 = 128;
pub const MAX_LEXICAL_LOOKUP_QUERY_BYTES: u64 = 65_536;
pub const MAX_LEXICAL_LOOKUP_UNIQUE_TOKENS: u32 = 4_096;
pub const MAX_LEXICAL_LOOKUP_POSTINGS: u32 = 131_072;
pub const MAX_LEXICAL_LOOKUP_MATCHES: u32 = 4_096;
pub const MAX_LEXICAL_LOOKUP_RESULT_BYTES: u64 = 67_108_864;
pub const MAX_LEXICAL_SOURCE_PROJECTIONS: u32 = 4_096;
pub const MAX_LEXICAL_SOURCE_QUOTE_BYTES: u64 = 16_777_216;
pub const MAX_LEXICAL_SOURCE_PROJECTION_RESULT_BYTES: u64 = 67_108_864;

const DIGEST_ALGORITHM: &str = "sha256";
const DERIVATION_DOMAIN: &str = "cantor.semantic-anchor-catalogue.derivation.v1";
const CATALOGUE_DOMAIN: &str = "cantor.semantic-anchor-catalogue.root.v1";
const RESULT_DOMAIN: &str = "cantor.semantic-anchor-catalogue.result.v1";
const FABRIC_GENERATION_DOMAIN: &str = "cantor.semantic-anchor-catalogue.fabric-generation.v1";
const DERIVED_ARTIFACT_DOMAIN: &str = "cantor.semantic-anchor-catalogue.derived-artifact.v1";
const UNIT_DOMAIN: &str = "cantor.semantic-anchor-catalogue.unit.v1";
const MEANING_DOMAIN: &str = "cantor.semantic-anchor-catalogue.meaning.v1";
const CONTEXT_DOMAIN: &str = "cantor.semantic-anchor-catalogue.context.v1";
const LEXICAL_TOKENIZER_FIXTURE_DOMAIN: &str =
    "cantor.semantic-anchor-catalogue.lexical-tokenizer-fixtures.v1";
const LEXICAL_SURFACE_DOMAIN: &str = "cantor.semantic-anchor-catalogue.lexical-surface.v1";
const LEXICAL_INDEX_ROOT_DOMAIN: &str = "cantor.semantic-anchor-catalogue.lexical-index-root.v1";
const LEXICAL_INDEX_PROOF_DOMAIN: &str = "cantor.semantic-anchor-catalogue.lexical-index-proof.v1";
const LEXICAL_DERIVATION_DECISION_PROFILE: &str = "cantor.lexical-index-derivation-decisions/0.1";
const LEXICAL_LOOKUP_PROOF_DOMAIN: &str =
    "cantor.semantic-anchor-catalogue.lexical-lookup-proof.v1";
const LEXICAL_LOOKUP_DECISION_PROFILE: &str = "cantor.lexical-anchor-lookup-decisions/0.1";
const LEXICAL_SOURCE_PROJECTION_DOMAIN: &str =
    "cantor.semantic-anchor-catalogue.lexical-source-projection.v1";
const LEXICAL_SOURCE_PROJECTION_RESULT_DOMAIN: &str =
    "cantor.semantic-anchor-catalogue.lexical-source-projection-result.v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogueIdentity {
    pub profile: String,
    pub catalogue_id: SemanticId,
    pub logical_revision: String,
    pub catalogue_root: ContentDigest,
    pub fabric_root: ContentDigest,
    pub package_roots: BTreeMap<SemanticId, ContentDigest>,
    pub compiler_id: SemanticId,
    pub compiler_version: String,
    pub derivation_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogueDerivationRequest {
    pub catalogue_id: SemanticId,
    pub logical_revision: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FabricPackageIdentity {
    pub package_id: SemanticId,
    pub package_digest: ContentDigest,
    pub certificate_id: SemanticId,
    pub semantic_root_digest: ContentDigest,
    pub source_root_digest: ContentDigest,
    pub compiler_id: SemanticId,
    pub compiler_version: String,
    pub authority_scope: AuthorityScope,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FabricGenerationIdentity {
    pub packages: Vec<FabricPackageIdentity>,
    pub fabric_root: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogueDerivationOmission {
    pub unit_id: SemanticId,
    pub omitted_fields: BTreeSet<String>,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedSemanticAnchorCatalogue {
    pub profile: String,
    pub logical_revision: String,
    pub generation: FabricGenerationIdentity,
    pub catalogue: SemanticAnchorCatalogue,
    pub exact_label_index: BTreeMap<String, BTreeSet<SemanticId>>,
    pub relation_adjacency: BTreeMap<SemanticId, BTreeSet<SemanticId>>,
    pub omissions: Vec<CatalogueDerivationOmission>,
    pub proof_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LexicalTokenizerIdentity {
    pub profile: String,
    pub compiler_id: SemanticId,
    pub compiler_version: String,
    pub adversarial_fixture_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LexicalSurfaceKind {
    PreferredExpression,
    Alias,
    Meaning,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LexicalPosting {
    pub token: String,
    pub address: SemanticAddress,
    pub surface_kind: LexicalSurfaceKind,
    pub surface_digest: ContentDigest,
    pub occurrence_count: u32,
    pub evidence_refs: BTreeSet<SemanticId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedLexicalAssociationIndex {
    pub profile: String,
    pub index_id: SemanticId,
    pub logical_revision: String,
    pub catalogue_root: ContentDigest,
    pub fabric_root: ContentDigest,
    pub compiler_id: SemanticId,
    pub compiler_version: String,
    pub tokenizer: LexicalTokenizerIdentity,
    pub postings: BTreeMap<String, Vec<LexicalPosting>>,
    pub index_root: ContentDigest,
    pub proof_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LexicalIndexDerivationRequest {
    pub index_id: SemanticId,
    pub logical_revision: String,
    pub tokenizer_profile: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LexicalAnchorLookupBudget {
    pub maximum_terms: u32,
    pub maximum_query_bytes: u64,
    pub maximum_unique_tokens: u32,
    pub maximum_postings: u32,
    pub maximum_matches: u32,
    pub maximum_serialized_result_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LexicalAnchorLookupRequest {
    pub profile: String,
    pub request_id: SemanticId,
    pub terms: Vec<String>,
    pub budget: LexicalAnchorLookupBudget,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LexicalTermAccount {
    pub original_term: String,
    pub token_occurrences: BTreeMap<String, u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchedLexicalEvidence {
    pub token: String,
    pub surface_kind: LexicalSurfaceKind,
    pub surface_digest: ContentDigest,
    pub occurrence_count: u32,
    pub evidence_refs: BTreeSet<SemanticId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LexicalAnchorMatch {
    pub address: SemanticAddress,
    pub matched_tokens: BTreeSet<String>,
    pub evidence: Vec<MatchedLexicalEvidence>,
    pub coverage_basis_points: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LexicalAnchorLookupResult {
    pub profile: String,
    pub request_id: SemanticId,
    pub catalogue_root: ContentDigest,
    pub fabric_root: ContentDigest,
    pub index_root: ContentDigest,
    pub tokenizer: LexicalTokenizerIdentity,
    pub term_accounts: Vec<LexicalTermAccount>,
    pub eligible_tokens: BTreeSet<String>,
    pub unmatched_tokens: BTreeSet<String>,
    pub complete_posting_count: u32,
    pub matches: Vec<LexicalAnchorMatch>,
    pub non_authority_statement: String,
    pub proof_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LexicalAnchorSourceProjectionBudget {
    pub maximum_projections: u32,
    pub maximum_quote_bytes: u64,
    pub maximum_serialized_result_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedAnchorSourceProjection {
    pub address: SemanticAddress,
    pub source_path: String,
    pub source_anchor: SourceAnchor,
    pub text: String,
    pub document_digest: ContentDigest,
    pub certificate_id: SemanticId,
    pub projection_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LexicalAnchorSourceProjectionResult {
    pub profile: String,
    pub lookup_proof_digest: ContentDigest,
    pub projections: Vec<VerifiedAnchorSourceProjection>,
    pub snapshot_boundary_statement: String,
    pub proof_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LexicalSourceProjectionFaultKind {
    InvalidProfile,
    InvalidBound,
    LookupRejected,
    SourceProofMissing,
    IdentityMismatch,
    InvalidUtf8,
    BudgetExceeded,
    ProjectionMismatch,
    ProofMismatch,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LexicalSourceProjectionFault {
    pub kind: LexicalSourceProjectionFaultKind,
    pub field: String,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LexicalLookupFaultKind {
    InvalidProfile,
    InvalidBound,
    IndexRejected,
    BudgetExceeded,
    RootMismatch,
    NonCanonicalOrder,
    ProjectionMismatch,
    ProofMismatch,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LexicalLookupFault {
    pub kind: LexicalLookupFaultKind,
    pub field: String,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LexicalIndexFaultKind {
    InvalidProfile,
    InvalidBound,
    InvalidIdentity,
    InvalidDigest,
    NonCanonicalOrder,
    DuplicatePosting,
    RootMismatch,
    ProjectionMismatch,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LexicalIndexFault {
    pub kind: LexicalIndexFaultKind,
    pub field: String,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AnchorDerivationFaultKind {
    InvalidRequest,
    MissingCertificate,
    MissingPackage,
    MissingSourceAnchor,
    InvalidGeneratedIdentity,
    SourceCorrespondence,
    InvalidCatalogue,
    ProjectionMismatch,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorDerivationFault {
    pub kind: AnchorDerivationFaultKind,
    pub stage: String,
    pub detail: String,
    pub related_ids: Vec<SemanticId>,
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

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RelationshipDirection {
    Forward,
    Reverse,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorRelationshipStep {
    pub relation_id: SemanticId,
    pub relation_type: RelationType,
    pub relation_source: SemanticId,
    pub relation_target: SemanticId,
    pub direction: RelationshipDirection,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorRelationshipPath {
    pub seed_id: SemanticId,
    pub target_id: SemanticId,
    pub steps: Vec<AnchorRelationshipStep>,
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
    pub relationship_path: Option<AnchorRelationshipPath>,
    pub status: ContributionStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssociationChannelAccount {
    pub channel: AssociationChannel,
    pub candidate_ids: Vec<SemanticId>,
    pub contribution_count: u32,
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
    pub relationship_paths: Vec<AnchorRelationshipPath>,
    pub association_account: Vec<AssociationChannelAccount>,
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
    RelationshipPathMismatch,
    AssociationAccountMismatch,
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
type AnchorDerivationResult<T = ()> = Result<T, AnchorDerivationFault>;
type LexicalIndexValidation<T = ()> = Result<T, LexicalIndexFault>;
type LexicalLookupValidation<T = ()> = Result<T, LexicalLookupFault>;
type LexicalSourceProjectionValidation<T = ()> = Result<T, LexicalSourceProjectionFault>;

pub fn derive_semantic_anchor_catalogue(
    fabric: &SemanticFabric,
    request: CatalogueDerivationRequest,
) -> AnchorDerivationResult<DerivedSemanticAnchorCatalogue> {
    if request.logical_revision.trim().is_empty() {
        return derivation_fault(
            AnchorDerivationFaultKind::InvalidRequest,
            "request",
            "logical revision is empty",
            Vec::new(),
        );
    }
    let derived = build_derived_semantic_anchor_catalogue(fabric, &request)?;
    validate_semantic_anchor_catalogue(&derived.catalogue).map_err(|fault| {
        AnchorDerivationFault {
            kind: AnchorDerivationFaultKind::InvalidCatalogue,
            stage: fault.field,
            detail: fault.detail,
            related_ids: Vec::new(),
        }
    })?;
    Ok(derived)
}

pub fn validate_derived_semantic_anchor_catalogue(
    derived: &DerivedSemanticAnchorCatalogue,
    fabric: &SemanticFabric,
) -> AnchorDerivationResult {
    if derived.profile != DERIVED_SEMANTIC_ANCHOR_CATALOGUE_PROFILE {
        return derivation_fault(
            AnchorDerivationFaultKind::ProjectionMismatch,
            "profile",
            "wrong derived catalogue profile",
            Vec::new(),
        );
    }
    validate_semantic_anchor_catalogue(&derived.catalogue).map_err(|fault| {
        AnchorDerivationFault {
            kind: AnchorDerivationFaultKind::InvalidCatalogue,
            stage: fault.field,
            detail: fault.detail,
            related_ids: Vec::new(),
        }
    })?;
    let expected = build_derived_semantic_anchor_catalogue(
        fabric,
        &CatalogueDerivationRequest {
            catalogue_id: derived.catalogue.identity.catalogue_id.clone(),
            logical_revision: derived.logical_revision.clone(),
        },
    )?;
    if &expected != derived {
        return derivation_fault(
            AnchorDerivationFaultKind::ProjectionMismatch,
            "derived_catalogue",
            "derived catalogue differs from a canonical rebuild of the admitted fabric",
            Vec::new(),
        );
    }
    Ok(())
}

pub fn validate_lexical_index_derivation_request(
    request: &LexicalIndexDerivationRequest,
) -> LexicalIndexValidation {
    if request.tokenizer_profile != LEXICAL_TOKENIZER_PROFILE {
        return lexical_fault(
            LexicalIndexFaultKind::InvalidProfile,
            "tokenizer_profile",
            "unsupported lexical tokenizer profile",
        );
    }
    if request.logical_revision.trim().is_empty()
        || request.logical_revision.len() > MAX_LEXICAL_LOGICAL_REVISION_BYTES
    {
        return lexical_fault(
            LexicalIndexFaultKind::InvalidBound,
            "logical_revision",
            "lexical logical revision is empty or oversized",
        );
    }
    Ok(())
}

pub fn tokenize_lexical_surface(surface: &str) -> LexicalIndexValidation<BTreeMap<String, u32>> {
    if surface.len() > MAX_LEXICAL_SURFACE_BYTES {
        return lexical_fault(
            LexicalIndexFaultKind::InvalidBound,
            "surface",
            "lexical surface byte bound exceeded",
        );
    }
    let mut tokens = BTreeMap::<String, u32>::new();
    let mut current = String::new();
    let mut occurrences = 0usize;
    for character in surface.trim().chars() {
        for lowercase in character.to_lowercase() {
            if lowercase.is_alphanumeric() {
                current.push(lowercase);
                if current.len() > MAX_LEXICAL_TOKEN_BYTES {
                    return lexical_fault(
                        LexicalIndexFaultKind::InvalidBound,
                        "token",
                        "lexical token byte bound exceeded",
                    );
                }
            } else {
                commit_lexical_token(&mut current, &mut tokens, &mut occurrences)?;
            }
        }
    }
    commit_lexical_token(&mut current, &mut tokens, &mut occurrences)?;
    Ok(tokens)
}

pub fn lexical_tokenizer_adversarial_fixture_digest() -> LexicalIndexValidation<ContentDigest> {
    let surfaces = [
        " Anchor,ANCHOR ",
        "R2D2 v1.0",
        "ÉLAN 東京 ١٢٣",
        "İ",
        "e\u{301} é",
        "---",
        "A_B",
        "x",
    ];
    let fixtures = surfaces
        .into_iter()
        .map(|surface| tokenize_lexical_surface(surface).map(|tokens| (surface.to_owned(), tokens)))
        .collect::<LexicalIndexValidation<Vec<_>>>()?;
    lexical_digest_form(LEXICAL_TOKENIZER_FIXTURE_DOMAIN, &fixtures)
}

pub fn validate_lexical_tokenizer_identity(
    tokenizer: &LexicalTokenizerIdentity,
) -> LexicalIndexValidation {
    if tokenizer.profile != LEXICAL_TOKENIZER_PROFILE {
        return lexical_fault(
            LexicalIndexFaultKind::InvalidProfile,
            "tokenizer.profile",
            "unsupported lexical tokenizer profile",
        );
    }
    if tokenizer.compiler_id.as_str() != LEXICAL_ASSOCIATION_INDEX_COMPILER_ID
        || tokenizer.compiler_version != LEXICAL_ASSOCIATION_INDEX_COMPILER_VERSION
    {
        return lexical_fault(
            LexicalIndexFaultKind::InvalidIdentity,
            "tokenizer.compiler",
            "lexical tokenizer compiler identity differs",
        );
    }
    validate_lexical_digest(
        &tokenizer.adversarial_fixture_digest,
        "tokenizer.adversarial_fixture_digest",
    )?;
    if tokenizer.adversarial_fixture_digest != lexical_tokenizer_adversarial_fixture_digest()? {
        return lexical_fault(
            LexicalIndexFaultKind::ProjectionMismatch,
            "tokenizer.adversarial_fixture_digest",
            "lexical tokenizer fixture digest differs from canonical behavior",
        );
    }
    Ok(())
}

pub fn derive_lexical_association_index(
    fabric: &SemanticFabric,
    catalogue: &DerivedSemanticAnchorCatalogue,
    request: LexicalIndexDerivationRequest,
) -> LexicalIndexValidation<DerivedLexicalAssociationIndex> {
    validate_lexical_index_derivation_request(&request)?;
    validate_derived_semantic_anchor_catalogue(catalogue, fabric)
        .map_err(anchor_derivation_to_lexical_fault)?;
    let index = build_derived_lexical_association_index(fabric, catalogue, &request)?;
    validate_derived_lexical_association_index_form(&index)?;
    Ok(index)
}

pub fn validate_derived_lexical_association_index(
    index: &DerivedLexicalAssociationIndex,
    catalogue: &DerivedSemanticAnchorCatalogue,
    fabric: &SemanticFabric,
) -> LexicalIndexValidation {
    validate_derived_lexical_association_index_form(index)?;
    validate_derived_semantic_anchor_catalogue(catalogue, fabric)
        .map_err(anchor_derivation_to_lexical_fault)?;
    if index.catalogue_root != catalogue.catalogue.identity.catalogue_root
        || index.fabric_root != catalogue.catalogue.identity.fabric_root
    {
        return lexical_fault(
            LexicalIndexFaultKind::RootMismatch,
            "index_roots",
            "lexical index roots differ from the validated catalogue and admitted fabric",
        );
    }
    let expected = build_derived_lexical_association_index(
        fabric,
        catalogue,
        &LexicalIndexDerivationRequest {
            index_id: index.index_id.clone(),
            logical_revision: index.logical_revision.clone(),
            tokenizer_profile: index.tokenizer.profile.clone(),
        },
    )?;
    if &expected != index {
        return lexical_fault(
            LexicalIndexFaultKind::ProjectionMismatch,
            "derived_lexical_index",
            "lexical index differs from a canonical rebuild of the admitted surfaces",
        );
    }
    Ok(())
}

pub fn validate_lexical_anchor_lookup_request(
    request: &LexicalAnchorLookupRequest,
) -> LexicalLookupValidation {
    if request.profile != LEXICAL_ANCHOR_LOOKUP_PROFILE {
        return lexical_lookup_fault(
            LexicalLookupFaultKind::InvalidProfile,
            "request.profile",
            "unsupported lexical anchor lookup profile",
        );
    }
    let budget = &request.budget;
    if budget.maximum_terms == 0
        || budget.maximum_terms > MAX_LEXICAL_LOOKUP_TERMS
        || budget.maximum_query_bytes == 0
        || budget.maximum_query_bytes > MAX_LEXICAL_LOOKUP_QUERY_BYTES
        || budget.maximum_unique_tokens == 0
        || budget.maximum_unique_tokens > MAX_LEXICAL_LOOKUP_UNIQUE_TOKENS
        || budget.maximum_postings == 0
        || budget.maximum_postings > MAX_LEXICAL_LOOKUP_POSTINGS
        || budget.maximum_matches == 0
        || budget.maximum_matches > MAX_LEXICAL_LOOKUP_MATCHES
        || budget.maximum_serialized_result_bytes == 0
        || budget.maximum_serialized_result_bytes > MAX_LEXICAL_LOOKUP_RESULT_BYTES
    {
        return lexical_lookup_fault(
            LexicalLookupFaultKind::InvalidBound,
            "request.budget",
            "lexical lookup budget is zero or exceeds a hard cap",
        );
    }
    if request.terms.is_empty() || request.terms.len() > budget.maximum_terms as usize {
        return lexical_lookup_fault(
            LexicalLookupFaultKind::InvalidBound,
            "request.terms",
            "lexical lookup term count is empty or exceeds its budget",
        );
    }
    let mut query_bytes = 0_u64;
    for term in &request.terms {
        if term.trim().is_empty() || term.len() > MAX_LEXICAL_SURFACE_BYTES {
            return lexical_lookup_fault(
                LexicalLookupFaultKind::InvalidBound,
                "request.term",
                "lexical lookup term is blank or exceeds the lexical surface bound",
            );
        }
        query_bytes =
            query_bytes
                .checked_add(term.len() as u64)
                .ok_or_else(|| LexicalLookupFault {
                    kind: LexicalLookupFaultKind::InvalidBound,
                    field: "request.terms".to_owned(),
                    detail: "lexical lookup query byte count overflow".to_owned(),
                })?;
    }
    if query_bytes > budget.maximum_query_bytes {
        return lexical_lookup_fault(
            LexicalLookupFaultKind::BudgetExceeded,
            "request.budget.maximum_query_bytes",
            "complete lexical lookup query bytes exceed budget",
        );
    }
    Ok(())
}

pub fn lookup_lexical_anchors(
    fabric: &SemanticFabric,
    catalogue: &DerivedSemanticAnchorCatalogue,
    index: &DerivedLexicalAssociationIndex,
    request: LexicalAnchorLookupRequest,
) -> LexicalLookupValidation<LexicalAnchorLookupResult> {
    validate_lexical_anchor_lookup_request(&request)?;
    validate_derived_lexical_association_index(index, catalogue, fabric)
        .map_err(lexical_index_to_lookup_fault)?;
    let result = build_lexical_anchor_lookup_result(index, &request, catalogue)?;
    validate_lexical_anchor_lookup_result_form(&result, &request, index, catalogue)?;
    Ok(result)
}

pub fn validate_lexical_anchor_lookup_result_form(
    result: &LexicalAnchorLookupResult,
    request: &LexicalAnchorLookupRequest,
    index: &DerivedLexicalAssociationIndex,
    catalogue: &DerivedSemanticAnchorCatalogue,
) -> LexicalLookupValidation {
    validate_lexical_anchor_lookup_request(request)?;
    validate_derived_lexical_association_index_form(index)
        .map_err(lexical_index_to_lookup_fault)?;
    validate_semantic_anchor_catalogue(&catalogue.catalogue)
        .map_err(anchor_form_to_lookup_fault)?;
    if result.profile != LEXICAL_ANCHOR_LOOKUP_RESULT_PROFILE {
        return lexical_lookup_fault(
            LexicalLookupFaultKind::InvalidProfile,
            "result.profile",
            "unsupported lexical anchor lookup result profile",
        );
    }
    if result.request_id != request.request_id
        || result.catalogue_root != catalogue.catalogue.identity.catalogue_root
        || result.fabric_root != catalogue.catalogue.identity.fabric_root
        || result.index_root != index.index_root
        || result.tokenizer != index.tokenizer
    {
        return lexical_lookup_fault(
            LexicalLookupFaultKind::RootMismatch,
            "result.identity",
            "lookup result identity differs from request catalogue fabric or lexical index",
        );
    }
    if result.non_authority_statement != LEXICAL_ANCHOR_LOOKUP_NON_AUTHORITY {
        return lexical_lookup_fault(
            LexicalLookupFaultKind::ProjectionMismatch,
            "result.non_authority_statement",
            "lookup result must retain the exact lexical-only non-authority statement",
        );
    }
    validate_lexical_digest(&result.proof_digest, "result.proof_digest")
        .map_err(lexical_index_to_lookup_fault)?;
    let serialized_bytes = serde_json::to_vec(result).map_err(|error| LexicalLookupFault {
        kind: LexicalLookupFaultKind::ProjectionMismatch,
        field: "result.serialization".to_owned(),
        detail: error.to_string(),
    })?;
    if serialized_bytes.len() as u64 > request.budget.maximum_serialized_result_bytes
        || serialized_bytes.len() as u64 > MAX_LEXICAL_LOOKUP_RESULT_BYTES
    {
        return lexical_lookup_fault(
            LexicalLookupFaultKind::BudgetExceeded,
            "result.serialized_bytes",
            "complete lexical lookup result exceeds its byte budget",
        );
    }
    if result.proof_digest != lexical_anchor_lookup_proof_digest(result, request, index, catalogue)?
    {
        return lexical_lookup_fault(
            LexicalLookupFaultKind::ProofMismatch,
            "result.proof_digest",
            "lexical lookup proof digest differs from the result body",
        );
    }
    let expected = build_lexical_anchor_lookup_result(index, request, catalogue)?;
    if &expected != result {
        return lexical_lookup_fault(
            LexicalLookupFaultKind::ProjectionMismatch,
            "lookup_result",
            "lexical lookup result differs from canonical replay over the supplied index",
        );
    }
    Ok(())
}

pub fn validate_lexical_anchor_lookup_result(
    result: &LexicalAnchorLookupResult,
    request: &LexicalAnchorLookupRequest,
    index: &DerivedLexicalAssociationIndex,
    catalogue: &DerivedSemanticAnchorCatalogue,
    fabric: &SemanticFabric,
) -> LexicalLookupValidation {
    validate_derived_lexical_association_index(index, catalogue, fabric)
        .map_err(lexical_index_to_lookup_fault)?;
    validate_lexical_anchor_lookup_result_form(result, request, index, catalogue)
}

pub fn lexical_anchor_lookup_proof_digest(
    result: &LexicalAnchorLookupResult,
    request: &LexicalAnchorLookupRequest,
    index: &DerivedLexicalAssociationIndex,
    catalogue: &DerivedSemanticAnchorCatalogue,
) -> LexicalLookupValidation<ContentDigest> {
    lexical_lookup_digest_form(
        LEXICAL_LOOKUP_PROOF_DOMAIN,
        &(
            (
                request,
                &catalogue.generation,
                &catalogue.proof_digest,
                LEXICAL_LOOKUP_DECISION_PROFILE,
                &index.profile,
                &index.compiler_id,
                &index.compiler_version,
            ),
            (
                &result.profile,
                &result.request_id,
                &result.catalogue_root,
                &result.fabric_root,
                &result.index_root,
                &result.tokenizer,
            ),
            (
                &result.term_accounts,
                &result.eligible_tokens,
                &result.unmatched_tokens,
                result.complete_posting_count,
                &result.matches,
                &result.non_authority_statement,
            ),
        ),
    )
}

pub fn validate_lexical_anchor_source_projection_budget(
    budget: &LexicalAnchorSourceProjectionBudget,
) -> LexicalSourceProjectionValidation {
    if budget.maximum_projections == 0
        || budget.maximum_projections > MAX_LEXICAL_SOURCE_PROJECTIONS
        || budget.maximum_quote_bytes == 0
        || budget.maximum_quote_bytes > MAX_LEXICAL_SOURCE_QUOTE_BYTES
        || budget.maximum_serialized_result_bytes == 0
        || budget.maximum_serialized_result_bytes > MAX_LEXICAL_SOURCE_PROJECTION_RESULT_BYTES
    {
        return lexical_source_projection_fault(
            LexicalSourceProjectionFaultKind::InvalidBound,
            "source_projection.budget",
            "source projection budget is zero or exceeds a hard cap",
        );
    }
    Ok(())
}

pub fn project_lexical_anchor_sources(
    fabric: &SemanticFabric,
    catalogue: &DerivedSemanticAnchorCatalogue,
    index: &DerivedLexicalAssociationIndex,
    lookup_request: &LexicalAnchorLookupRequest,
    lookup_result: &LexicalAnchorLookupResult,
    budget: LexicalAnchorSourceProjectionBudget,
) -> LexicalSourceProjectionValidation<LexicalAnchorSourceProjectionResult> {
    validate_lexical_anchor_source_projection_budget(&budget)?;
    validate_lexical_anchor_lookup_result(lookup_result, lookup_request, index, catalogue, fabric)
        .map_err(lexical_lookup_to_source_projection_fault)?;
    let result = build_lexical_anchor_source_projection_result(fabric, lookup_result, &budget)?;
    validate_lexical_anchor_source_projection_result_form(&result, lookup_result, &budget)?;
    Ok(result)
}

pub fn validate_lexical_anchor_source_projection_result_form(
    result: &LexicalAnchorSourceProjectionResult,
    lookup_result: &LexicalAnchorLookupResult,
    budget: &LexicalAnchorSourceProjectionBudget,
) -> LexicalSourceProjectionValidation {
    validate_lexical_anchor_source_projection_budget(budget)?;
    if result.profile != LEXICAL_ANCHOR_SOURCE_PROJECTION_RESULT_PROFILE {
        return lexical_source_projection_fault(
            LexicalSourceProjectionFaultKind::InvalidProfile,
            "source_projection.profile",
            "unsupported lexical source projection result profile",
        );
    }
    if result.lookup_proof_digest != lookup_result.proof_digest {
        return lexical_source_projection_fault(
            LexicalSourceProjectionFaultKind::IdentityMismatch,
            "source_projection.lookup_proof_digest",
            "source projection does not bind the supplied lexical lookup proof",
        );
    }
    if result.snapshot_boundary_statement != LEXICAL_ANCHOR_SOURCE_PROJECTION_BOUNDARY {
        return lexical_source_projection_fault(
            LexicalSourceProjectionFaultKind::ProjectionMismatch,
            "source_projection.snapshot_boundary_statement",
            "source projection must retain the exact admitted-snapshot boundary statement",
        );
    }
    if result.projections.len() != lookup_result.matches.len()
        || result.projections.len() > budget.maximum_projections as usize
    {
        return lexical_source_projection_fault(
            LexicalSourceProjectionFaultKind::ProjectionMismatch,
            "source_projection.projections",
            "source projection must contain exactly one bounded entry per lexical match",
        );
    }
    let mut quote_bytes = 0_u64;
    for (projection, matched) in result.projections.iter().zip(&lookup_result.matches) {
        if projection.address != matched.address
            || !projection
                .address
                .source_anchors
                .contains(&projection.source_anchor)
        {
            return lexical_source_projection_fault(
                LexicalSourceProjectionFaultKind::IdentityMismatch,
                "source_projection.address",
                "source projection order address or source anchor differs from its lexical match",
            );
        }
        if projection.source_path.trim().is_empty() {
            return lexical_source_projection_fault(
                LexicalSourceProjectionFaultKind::ProjectionMismatch,
                "source_projection.source_path",
                "admitted source projection requires a human-readable snapshot path",
            );
        }
        validate_lexical_digest(
            &projection.document_digest,
            "source_projection.document_digest",
        )
        .map_err(lexical_index_to_source_projection_fault)?;
        validate_lexical_digest(
            &projection.projection_digest,
            "source_projection.projection_digest",
        )
        .map_err(lexical_index_to_source_projection_fault)?;
        quote_bytes = quote_bytes
            .checked_add(projection.text.len() as u64)
            .ok_or_else(|| LexicalSourceProjectionFault {
                kind: LexicalSourceProjectionFaultKind::InvalidBound,
                field: "source_projection.text".to_owned(),
                detail: "source projection quote byte count overflow".to_owned(),
            })?;
        if projection.projection_digest != lexical_anchor_source_projection_digest(projection)? {
            return lexical_source_projection_fault(
                LexicalSourceProjectionFaultKind::ProofMismatch,
                "source_projection.projection_digest",
                "source projection digest differs from its exact body",
            );
        }
    }
    if quote_bytes > budget.maximum_quote_bytes {
        return lexical_source_projection_fault(
            LexicalSourceProjectionFaultKind::BudgetExceeded,
            "source_projection.budget.maximum_quote_bytes",
            "complete admitted quote bytes exceed source projection budget",
        );
    }
    validate_lexical_digest(&result.proof_digest, "source_projection.proof_digest")
        .map_err(lexical_index_to_source_projection_fault)?;
    if result.proof_digest
        != lexical_anchor_source_projection_result_digest(result, lookup_result, budget)?
    {
        return lexical_source_projection_fault(
            LexicalSourceProjectionFaultKind::ProofMismatch,
            "source_projection.proof_digest",
            "source projection result proof differs from its exact body",
        );
    }
    let serialized_bytes =
        serde_json::to_vec(result).map_err(|error| LexicalSourceProjectionFault {
            kind: LexicalSourceProjectionFaultKind::ProjectionMismatch,
            field: "source_projection.serialization".to_owned(),
            detail: error.to_string(),
        })?;
    if serialized_bytes.len() as u64 > budget.maximum_serialized_result_bytes
        || serialized_bytes.len() as u64 > MAX_LEXICAL_SOURCE_PROJECTION_RESULT_BYTES
    {
        return lexical_source_projection_fault(
            LexicalSourceProjectionFaultKind::BudgetExceeded,
            "source_projection.budget.maximum_serialized_result_bytes",
            "complete source projection result exceeds its serialized byte budget",
        );
    }
    Ok(())
}

pub fn validate_lexical_anchor_source_projection_result(
    result: &LexicalAnchorSourceProjectionResult,
    fabric: &SemanticFabric,
    catalogue: &DerivedSemanticAnchorCatalogue,
    index: &DerivedLexicalAssociationIndex,
    lookup_request: &LexicalAnchorLookupRequest,
    lookup_result: &LexicalAnchorLookupResult,
    budget: &LexicalAnchorSourceProjectionBudget,
) -> LexicalSourceProjectionValidation {
    validate_lexical_anchor_lookup_result(lookup_result, lookup_request, index, catalogue, fabric)
        .map_err(lexical_lookup_to_source_projection_fault)?;
    validate_lexical_anchor_source_projection_result_form(result, lookup_result, budget)?;
    let expected = build_lexical_anchor_source_projection_result(fabric, lookup_result, budget)?;
    if &expected != result {
        return lexical_source_projection_fault(
            LexicalSourceProjectionFaultKind::ProjectionMismatch,
            "source_projection",
            "source projection result differs from canonical replay over admitted packages",
        );
    }
    Ok(())
}

pub fn lexical_anchor_source_projection_digest(
    projection: &VerifiedAnchorSourceProjection,
) -> LexicalSourceProjectionValidation<ContentDigest> {
    lexical_source_projection_digest_form(
        LEXICAL_SOURCE_PROJECTION_DOMAIN,
        &(
            &projection.address,
            &projection.source_path,
            &projection.source_anchor,
            &projection.text,
            &projection.document_digest,
            &projection.certificate_id,
        ),
    )
}

pub fn lexical_anchor_source_projection_result_digest(
    result: &LexicalAnchorSourceProjectionResult,
    lookup_result: &LexicalAnchorLookupResult,
    budget: &LexicalAnchorSourceProjectionBudget,
) -> LexicalSourceProjectionValidation<ContentDigest> {
    lexical_source_projection_digest_form(
        LEXICAL_SOURCE_PROJECTION_RESULT_DOMAIN,
        &(
            budget,
            &lookup_result.proof_digest,
            &result.profile,
            &result.lookup_proof_digest,
            &result.projections,
            &result.snapshot_boundary_statement,
        ),
    )
}

pub fn lexical_association_index_root(
    index: &DerivedLexicalAssociationIndex,
) -> LexicalIndexValidation<ContentDigest> {
    lexical_digest_form(
        LEXICAL_INDEX_ROOT_DOMAIN,
        &(
            &index.profile,
            &index.index_id,
            &index.logical_revision,
            &index.catalogue_root,
            &index.fabric_root,
            &index.compiler_id,
            &index.compiler_version,
            &index.tokenizer,
            &index.postings,
        ),
    )
}

pub fn lexical_association_index_proof_digest(
    index: &DerivedLexicalAssociationIndex,
    request: &LexicalIndexDerivationRequest,
    catalogue: &DerivedSemanticAnchorCatalogue,
) -> LexicalIndexValidation<ContentDigest> {
    lexical_digest_form(
        LEXICAL_INDEX_PROOF_DOMAIN,
        &(
            request,
            &catalogue.generation,
            &catalogue.proof_digest,
            LEXICAL_DERIVATION_DECISION_PROFILE,
            &index.profile,
            &index.compiler_id,
            &index.compiler_version,
            &index.tokenizer,
            &index.index_root,
        ),
    )
}

pub fn validate_derived_lexical_association_index_form(
    index: &DerivedLexicalAssociationIndex,
) -> LexicalIndexValidation {
    if index.profile != DERIVED_LEXICAL_ASSOCIATION_INDEX_PROFILE {
        return lexical_fault(
            LexicalIndexFaultKind::InvalidProfile,
            "profile",
            "wrong derived lexical association index profile",
        );
    }
    if index.logical_revision.trim().is_empty()
        || index.logical_revision.len() > MAX_LEXICAL_LOGICAL_REVISION_BYTES
    {
        return lexical_fault(
            LexicalIndexFaultKind::InvalidBound,
            "logical_revision",
            "lexical logical revision is empty or oversized",
        );
    }
    if index.compiler_id.as_str() != LEXICAL_ASSOCIATION_INDEX_COMPILER_ID
        || index.compiler_version != LEXICAL_ASSOCIATION_INDEX_COMPILER_VERSION
    {
        return lexical_fault(
            LexicalIndexFaultKind::InvalidIdentity,
            "compiler",
            "lexical index compiler identity differs",
        );
    }
    validate_lexical_tokenizer_identity(&index.tokenizer)?;
    validate_lexical_digest(&index.catalogue_root, "catalogue_root")?;
    validate_lexical_digest(&index.fabric_root, "fabric_root")?;
    validate_lexical_digest(&index.index_root, "index_root")?;
    validate_lexical_digest(&index.proof_digest, "proof_digest")?;

    let mut total_postings = 0usize;
    for (token, postings) in &index.postings {
        if token.is_empty()
            || token.len() > MAX_LEXICAL_TOKEN_BYTES
            || token
                .chars()
                .any(|character| !character.is_alphanumeric() || character.is_uppercase())
        {
            return lexical_fault(
                LexicalIndexFaultKind::InvalidBound,
                "postings.token",
                "lexical token is empty oversized uppercase or non-alphanumeric",
            );
        }
        if postings.is_empty() || postings.len() > MAX_LEXICAL_POSTINGS_PER_TOKEN {
            return lexical_fault(
                LexicalIndexFaultKind::InvalidBound,
                "postings",
                "posting set is empty or oversized",
            );
        }
        total_postings =
            total_postings
                .checked_add(postings.len())
                .ok_or_else(|| LexicalIndexFault {
                    kind: LexicalIndexFaultKind::InvalidBound,
                    field: "postings".to_owned(),
                    detail: "total lexical posting count overflow".to_owned(),
                })?;
        if total_postings > MAX_LEXICAL_TOTAL_POSTINGS {
            return lexical_fault(
                LexicalIndexFaultKind::InvalidBound,
                "postings",
                "total lexical posting bound exceeded",
            );
        }
        for posting in postings {
            if posting.token != *token {
                return lexical_fault(
                    LexicalIndexFaultKind::InvalidIdentity,
                    "posting.token",
                    "posting token differs from its map key",
                );
            }
            validate_address(&posting.address).map_err(anchor_form_to_lexical_fault)?;
            validate_lexical_digest(&posting.surface_digest, "posting.surface_digest")?;
            if posting.occurrence_count == 0
                || posting.evidence_refs.is_empty()
                || posting.evidence_refs.len() > MAX_LEXICAL_EVIDENCE_REFS
            {
                return lexical_fault(
                    LexicalIndexFaultKind::InvalidBound,
                    "posting",
                    "positive occurrence count and bounded evidence are required",
                );
            }
        }
        for pair in postings.windows(2) {
            let left = (
                &pair[0].address.unit_id,
                &pair[0].address.package_id,
                &pair[0].surface_kind,
                &pair[0].surface_digest.value,
            );
            let right = (
                &pair[1].address.unit_id,
                &pair[1].address.package_id,
                &pair[1].surface_kind,
                &pair[1].surface_digest.value,
            );
            if left >= right {
                return lexical_fault(
                    if left == right {
                        LexicalIndexFaultKind::DuplicatePosting
                    } else {
                        LexicalIndexFaultKind::NonCanonicalOrder
                    },
                    "postings",
                    "lexical postings are not strictly canonical and unique",
                );
            }
        }
    }
    let serialized_bytes = serde_json::to_vec(index).map_err(|error| LexicalIndexFault {
        kind: LexicalIndexFaultKind::InvalidIdentity,
        field: "serialization".to_owned(),
        detail: error.to_string(),
    })?;
    if serialized_bytes.len() > MAX_LEXICAL_INDEX_SERIALIZED_BYTES {
        return lexical_fault(
            LexicalIndexFaultKind::InvalidBound,
            "serialized_index",
            "serialized lexical index bound exceeded",
        );
    }
    if index.index_root != lexical_association_index_root(index)? {
        return lexical_fault(
            LexicalIndexFaultKind::RootMismatch,
            "index_root",
            "lexical index root differs from its canonical posting projection",
        );
    }
    Ok(())
}

fn build_derived_lexical_association_index(
    fabric: &SemanticFabric,
    catalogue: &DerivedSemanticAnchorCatalogue,
    request: &LexicalIndexDerivationRequest,
) -> LexicalIndexValidation<DerivedLexicalAssociationIndex> {
    validate_lexical_index_derivation_request(request)?;
    let compiler_id = SemanticId::new(LEXICAL_ASSOCIATION_INDEX_COMPILER_ID).map_err(|error| {
        LexicalIndexFault {
            kind: LexicalIndexFaultKind::InvalidIdentity,
            field: "compiler_id".to_owned(),
            detail: error.to_string(),
        }
    })?;
    let tokenizer = LexicalTokenizerIdentity {
        profile: request.tokenizer_profile.clone(),
        compiler_id: compiler_id.clone(),
        compiler_version: LEXICAL_ASSOCIATION_INDEX_COMPILER_VERSION.to_owned(),
        adversarial_fixture_digest: lexical_tokenizer_adversarial_fixture_digest()?,
    };
    let mut postings = BTreeMap::<String, Vec<LexicalPosting>>::new();
    let mut total_postings = 0usize;

    for entry in &catalogue.catalogue.identity_entries {
        let unit = fabric
            .unit(&entry.address.unit_id)
            .ok_or_else(|| LexicalIndexFault {
                kind: LexicalIndexFaultKind::ProjectionMismatch,
                field: "surface.unit".to_owned(),
                detail: format!(
                    "catalogue identity {} has no admitted semantic unit",
                    entry.address.unit_id
                ),
            })?;
        let admitted = fabric
            .package_for_unit(&entry.address.unit_id)
            .ok_or_else(|| LexicalIndexFault {
                kind: LexicalIndexFaultKind::ProjectionMismatch,
                field: "surface.package".to_owned(),
                detail: format!(
                    "catalogue identity {} has no admitted package owner",
                    entry.address.unit_id
                ),
            })?;
        if admitted.package().package_id != entry.address.package_id {
            return lexical_fault(
                LexicalIndexFaultKind::ProjectionMismatch,
                "surface.package",
                "catalogue address and admitted package owner differ",
            );
        }
        let meaning_ref = content_identity("meaning", MEANING_DOMAIN, &unit.meaning)
            .map_err(anchor_derivation_to_lexical_fault)?;
        if meaning_ref != entry.meaning_ref {
            return lexical_fault(
                LexicalIndexFaultKind::ProjectionMismatch,
                "surface.meaning_ref",
                "catalogue meaning reference differs from admitted meaning bytes",
            );
        }
        let evidence_refs = lexical_surface_evidence_refs(entry)?;
        append_lexical_surface_postings(
            &mut postings,
            &mut total_postings,
            entry,
            LexicalSurfaceKind::PreferredExpression,
            &entry.preferred_expression,
            &evidence_refs,
        )?;
        for alias in &entry.aliases {
            append_lexical_surface_postings(
                &mut postings,
                &mut total_postings,
                entry,
                LexicalSurfaceKind::Alias,
                alias,
                &evidence_refs,
            )?;
        }
        append_lexical_surface_postings(
            &mut postings,
            &mut total_postings,
            entry,
            LexicalSurfaceKind::Meaning,
            &unit.meaning,
            &evidence_refs,
        )?;
    }

    for token_postings in postings.values_mut() {
        token_postings.sort_by(lexical_posting_canonical_cmp);
        for pair in token_postings.windows(2) {
            if lexical_posting_canonical_key(&pair[0]) == lexical_posting_canonical_key(&pair[1]) {
                return lexical_fault(
                    LexicalIndexFaultKind::DuplicatePosting,
                    "postings",
                    "canonical surface projection produced a duplicate lexical posting",
                );
            }
        }
    }

    let mut index = DerivedLexicalAssociationIndex {
        profile: DERIVED_LEXICAL_ASSOCIATION_INDEX_PROFILE.to_owned(),
        index_id: request.index_id.clone(),
        logical_revision: request.logical_revision.clone(),
        catalogue_root: catalogue.catalogue.identity.catalogue_root.clone(),
        fabric_root: catalogue.catalogue.identity.fabric_root.clone(),
        compiler_id,
        compiler_version: LEXICAL_ASSOCIATION_INDEX_COMPILER_VERSION.to_owned(),
        tokenizer,
        postings,
        index_root: zero_sha256(),
        proof_digest: zero_sha256(),
    };
    index.index_root = lexical_association_index_root(&index)?;
    index.proof_digest = lexical_association_index_proof_digest(&index, request, catalogue)?;
    Ok(index)
}

#[derive(Clone)]
struct LexicalMatchAccumulator {
    address: SemanticAddress,
    matched_tokens: BTreeSet<String>,
    evidence: Vec<MatchedLexicalEvidence>,
}

fn build_lexical_anchor_lookup_result(
    index: &DerivedLexicalAssociationIndex,
    request: &LexicalAnchorLookupRequest,
    catalogue: &DerivedSemanticAnchorCatalogue,
) -> LexicalLookupValidation<LexicalAnchorLookupResult> {
    validate_lexical_anchor_lookup_request(request)?;
    let mut term_accounts = Vec::with_capacity(request.terms.len());
    let mut eligible_tokens = BTreeSet::new();
    for term in &request.terms {
        let token_occurrences =
            tokenize_lexical_surface(term).map_err(lexical_index_to_lookup_fault)?;
        eligible_tokens.extend(token_occurrences.keys().cloned());
        term_accounts.push(LexicalTermAccount {
            original_term: term.clone(),
            token_occurrences,
        });
    }
    if eligible_tokens.len() > request.budget.maximum_unique_tokens as usize {
        return lexical_lookup_fault(
            LexicalLookupFaultKind::BudgetExceeded,
            "request.budget.maximum_unique_tokens",
            "complete lexical lookup token union exceeds budget",
        );
    }

    let mut complete_posting_count = 0_u32;
    for token in &eligible_tokens {
        let posting_count = index.postings.get(token).map_or(0, Vec::len);
        complete_posting_count = complete_posting_count
            .checked_add(posting_count.try_into().map_err(|_| LexicalLookupFault {
                kind: LexicalLookupFaultKind::InvalidBound,
                field: "lookup.postings".to_owned(),
                detail: "posting count cannot be represented as u32".to_owned(),
            })?)
            .ok_or_else(|| LexicalLookupFault {
                kind: LexicalLookupFaultKind::InvalidBound,
                field: "lookup.postings".to_owned(),
                detail: "complete posting count overflow".to_owned(),
            })?;
    }
    if complete_posting_count > request.budget.maximum_postings {
        return lexical_lookup_fault(
            LexicalLookupFaultKind::BudgetExceeded,
            "request.budget.maximum_postings",
            "complete lexical posting union exceeds budget",
        );
    }

    let catalogue_addresses = catalogue
        .catalogue
        .identity_entries
        .iter()
        .map(|entry| (entry.address.unit_id.clone(), entry.address.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut accumulators = BTreeMap::<SemanticId, LexicalMatchAccumulator>::new();
    for token in &eligible_tokens {
        let Some(postings) = index.postings.get(token) else {
            continue;
        };
        for posting in postings {
            let catalogue_address = catalogue_addresses
                .get(&posting.address.unit_id)
                .ok_or_else(|| LexicalLookupFault {
                    kind: LexicalLookupFaultKind::ProjectionMismatch,
                    field: "posting.address".to_owned(),
                    detail: format!(
                        "lexical posting target {} is absent from the catalogue",
                        posting.address.unit_id
                    ),
                })?;
            if catalogue_address != &posting.address {
                return lexical_lookup_fault(
                    LexicalLookupFaultKind::ProjectionMismatch,
                    "posting.address",
                    "lexical posting address differs from the exact catalogue address",
                );
            }
            let accumulator = accumulators
                .entry(posting.address.unit_id.clone())
                .or_insert_with(|| LexicalMatchAccumulator {
                    address: posting.address.clone(),
                    matched_tokens: BTreeSet::new(),
                    evidence: Vec::new(),
                });
            if accumulator.address != posting.address {
                return lexical_lookup_fault(
                    LexicalLookupFaultKind::ProjectionMismatch,
                    "posting.address",
                    "one lexical unit identity resolved to more than one address",
                );
            }
            accumulator.matched_tokens.insert(token.clone());
            accumulator.evidence.push(MatchedLexicalEvidence {
                token: token.clone(),
                surface_kind: posting.surface_kind.clone(),
                surface_digest: posting.surface_digest.clone(),
                occurrence_count: posting.occurrence_count,
                evidence_refs: posting.evidence_refs.clone(),
            });
        }
    }

    let eligible_count = eligible_tokens.len() as u64;
    let mut keyed_matches = Vec::with_capacity(accumulators.len());
    let mut all_matched_tokens = BTreeSet::new();
    for (_, mut accumulator) in accumulators {
        accumulator.evidence.sort_by(lexical_matched_evidence_cmp);
        for pair in accumulator.evidence.windows(2) {
            if lexical_matched_evidence_key(&pair[0]) == lexical_matched_evidence_key(&pair[1]) {
                return lexical_lookup_fault(
                    LexicalLookupFaultKind::NonCanonicalOrder,
                    "match.evidence",
                    "lookup aggregation produced duplicate lexical evidence",
                );
            }
        }
        let matched_count = accumulator.matched_tokens.len() as u64;
        if matched_count == 0 || eligible_count == 0 {
            return lexical_lookup_fault(
                LexicalLookupFaultKind::ProjectionMismatch,
                "match.matched_tokens",
                "an emitted match requires positive matched and eligible token counts",
            );
        }
        let coverage = matched_count
            .checked_mul(10_000)
            .ok_or_else(|| LexicalLookupFault {
                kind: LexicalLookupFaultKind::InvalidBound,
                field: "match.coverage_basis_points".to_owned(),
                detail: "lexical coverage multiplication overflow".to_owned(),
            })?
            / eligible_count;
        let coverage_basis_points = u16::try_from(coverage).map_err(|_| LexicalLookupFault {
            kind: LexicalLookupFaultKind::ProjectionMismatch,
            field: "match.coverage_basis_points".to_owned(),
            detail: "lexical coverage is outside the basis-point range".to_owned(),
        })?;
        if coverage_basis_points == 0 || coverage_basis_points > 10_000 {
            return lexical_lookup_fault(
                LexicalLookupFaultKind::ProjectionMismatch,
                "match.coverage_basis_points",
                "lexical coverage must be from one through ten-thousand basis points",
            );
        }
        all_matched_tokens.extend(accumulator.matched_tokens.iter().cloned());
        let address_order =
            serde_json::to_vec(&accumulator.address).map_err(|error| LexicalLookupFault {
                kind: LexicalLookupFaultKind::ProjectionMismatch,
                field: "match.address".to_owned(),
                detail: error.to_string(),
            })?;
        keyed_matches.push((
            address_order,
            LexicalAnchorMatch {
                address: accumulator.address,
                matched_tokens: accumulator.matched_tokens,
                evidence: accumulator.evidence,
                coverage_basis_points,
            },
        ));
    }
    if keyed_matches.len() > request.budget.maximum_matches as usize {
        return lexical_lookup_fault(
            LexicalLookupFaultKind::BudgetExceeded,
            "request.budget.maximum_matches",
            "complete lexical match set exceeds budget",
        );
    }
    keyed_matches.sort_by(|left, right| {
        right
            .1
            .coverage_basis_points
            .cmp(&left.1.coverage_basis_points)
            .then_with(|| left.0.cmp(&right.0))
    });
    let matches = keyed_matches
        .into_iter()
        .map(|(_, candidate)| candidate)
        .collect::<Vec<_>>();
    let unmatched_tokens = eligible_tokens
        .difference(&all_matched_tokens)
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut result = LexicalAnchorLookupResult {
        profile: LEXICAL_ANCHOR_LOOKUP_RESULT_PROFILE.to_owned(),
        request_id: request.request_id.clone(),
        catalogue_root: catalogue.catalogue.identity.catalogue_root.clone(),
        fabric_root: catalogue.catalogue.identity.fabric_root.clone(),
        index_root: index.index_root.clone(),
        tokenizer: index.tokenizer.clone(),
        term_accounts,
        eligible_tokens,
        unmatched_tokens,
        complete_posting_count,
        matches,
        non_authority_statement: LEXICAL_ANCHOR_LOOKUP_NON_AUTHORITY.to_owned(),
        proof_digest: zero_sha256(),
    };
    result.proof_digest = lexical_anchor_lookup_proof_digest(&result, request, index, catalogue)?;
    let serialized_bytes = serde_json::to_vec(&result).map_err(|error| LexicalLookupFault {
        kind: LexicalLookupFaultKind::ProjectionMismatch,
        field: "result.serialization".to_owned(),
        detail: error.to_string(),
    })?;
    if serialized_bytes.len() as u64 > request.budget.maximum_serialized_result_bytes
        || serialized_bytes.len() as u64 > MAX_LEXICAL_LOOKUP_RESULT_BYTES
    {
        return lexical_lookup_fault(
            LexicalLookupFaultKind::BudgetExceeded,
            "request.budget.maximum_serialized_result_bytes",
            "complete lexical lookup result exceeds its serialized byte budget",
        );
    }
    Ok(result)
}

fn build_lexical_anchor_source_projection_result(
    fabric: &SemanticFabric,
    lookup_result: &LexicalAnchorLookupResult,
    budget: &LexicalAnchorSourceProjectionBudget,
) -> LexicalSourceProjectionValidation<LexicalAnchorSourceProjectionResult> {
    validate_lexical_anchor_source_projection_budget(budget)?;
    if lookup_result.matches.len() > budget.maximum_projections as usize {
        return lexical_source_projection_fault(
            LexicalSourceProjectionFaultKind::BudgetExceeded,
            "source_projection.budget.maximum_projections",
            "complete lexical match set exceeds source projection budget",
        );
    }
    let mut projections = Vec::with_capacity(lookup_result.matches.len());
    let mut quote_bytes = 0_u64;
    for matched in &lookup_result.matches {
        let address = &matched.address;
        let package = fabric.package_for_unit(&address.unit_id).ok_or_else(|| {
            LexicalSourceProjectionFault {
                kind: LexicalSourceProjectionFaultKind::SourceProofMissing,
                field: "source_projection.package".to_owned(),
                detail: format!("lexical match {} has no admitted package", address.unit_id),
            }
        })?;
        let compiled = package.package();
        let certificate =
            compiled
                .certificate
                .as_ref()
                .ok_or_else(|| LexicalSourceProjectionFault {
                    kind: LexicalSourceProjectionFaultKind::SourceProofMissing,
                    field: "source_projection.certificate".to_owned(),
                    detail: format!(
                        "admitted package {} has no retained recognition certificate",
                        compiled.package_id
                    ),
                })?;
        if compiled.package_id != address.package_id
            || certificate.package_digest != address.package_digest
            || package.certificate_id() != &certificate.certificate_id
        {
            return lexical_source_projection_fault(
                LexicalSourceProjectionFaultKind::IdentityMismatch,
                "source_projection.package_identity",
                "admitted package or certificate identity differs from the lexical address",
            );
        }
        let quote =
            package
                .quote(&address.unit_id)
                .ok_or_else(|| LexicalSourceProjectionFault {
                    kind: LexicalSourceProjectionFaultKind::SourceProofMissing,
                    field: "source_projection.quote".to_owned(),
                    detail: format!(
                        "lexical match {} has no admitted quote record",
                        address.unit_id
                    ),
                })?;
        if !address.source_anchors.contains(&quote.anchor) {
            return lexical_source_projection_fault(
                LexicalSourceProjectionFaultKind::IdentityMismatch,
                "source_projection.source_anchor",
                "admitted quote anchor is absent from the lexical address",
            );
        }
        let source = package
            .content()
            .sources
            .iter()
            .find(|source| source.file_id == quote.anchor.file_id)
            .ok_or_else(|| LexicalSourceProjectionFault {
                kind: LexicalSourceProjectionFaultKind::SourceProofMissing,
                field: "source_projection.source_snapshot".to_owned(),
                detail: format!(
                    "admitted quote file {} has no signed source snapshot",
                    quote.anchor.file_id
                ),
            })?;
        let text = String::from_utf8(quote.bytes.clone()).map_err(|error| {
            LexicalSourceProjectionFault {
                kind: LexicalSourceProjectionFaultKind::InvalidUtf8,
                field: "source_projection.text".to_owned(),
                detail: format!("admitted quote is not valid UTF-8: {error}"),
            }
        })?;
        quote_bytes = quote_bytes.checked_add(text.len() as u64).ok_or_else(|| {
            LexicalSourceProjectionFault {
                kind: LexicalSourceProjectionFaultKind::InvalidBound,
                field: "source_projection.text".to_owned(),
                detail: "source projection quote byte count overflow".to_owned(),
            }
        })?;
        if quote_bytes > budget.maximum_quote_bytes {
            return lexical_source_projection_fault(
                LexicalSourceProjectionFaultKind::BudgetExceeded,
                "source_projection.budget.maximum_quote_bytes",
                "complete admitted quote bytes exceed source projection budget",
            );
        }
        let mut projection = VerifiedAnchorSourceProjection {
            address: address.clone(),
            source_path: source.path.clone(),
            source_anchor: quote.anchor.clone(),
            text,
            document_digest: source.document_digest.clone(),
            certificate_id: package.certificate_id().clone(),
            projection_digest: zero_sha256(),
        };
        projection.projection_digest = lexical_anchor_source_projection_digest(&projection)?;
        projections.push(projection);
    }
    let mut result = LexicalAnchorSourceProjectionResult {
        profile: LEXICAL_ANCHOR_SOURCE_PROJECTION_RESULT_PROFILE.to_owned(),
        lookup_proof_digest: lookup_result.proof_digest.clone(),
        projections,
        snapshot_boundary_statement: LEXICAL_ANCHOR_SOURCE_PROJECTION_BOUNDARY.to_owned(),
        proof_digest: zero_sha256(),
    };
    result.proof_digest =
        lexical_anchor_source_projection_result_digest(&result, lookup_result, budget)?;
    let serialized_bytes =
        serde_json::to_vec(&result).map_err(|error| LexicalSourceProjectionFault {
            kind: LexicalSourceProjectionFaultKind::ProjectionMismatch,
            field: "source_projection.serialization".to_owned(),
            detail: error.to_string(),
        })?;
    if serialized_bytes.len() as u64 > budget.maximum_serialized_result_bytes
        || serialized_bytes.len() as u64 > MAX_LEXICAL_SOURCE_PROJECTION_RESULT_BYTES
    {
        return lexical_source_projection_fault(
            LexicalSourceProjectionFaultKind::BudgetExceeded,
            "source_projection.budget.maximum_serialized_result_bytes",
            "complete source projection result exceeds its serialized byte budget",
        );
    }
    Ok(result)
}

fn lexical_matched_evidence_key(
    evidence: &MatchedLexicalEvidence,
) -> (&str, &LexicalSurfaceKind, &str) {
    (
        &evidence.token,
        &evidence.surface_kind,
        &evidence.surface_digest.value,
    )
}

fn lexical_matched_evidence_cmp(
    left: &MatchedLexicalEvidence,
    right: &MatchedLexicalEvidence,
) -> std::cmp::Ordering {
    lexical_matched_evidence_key(left).cmp(&lexical_matched_evidence_key(right))
}

fn lexical_surface_evidence_refs(
    entry: &IdentityAnchorEntry,
) -> LexicalIndexValidation<BTreeSet<SemanticId>> {
    let mut refs = BTreeSet::from([
        entry.address.unit_id.clone(),
        entry.address.package_id.clone(),
        entry.address.context_id.clone(),
        entry.meaning_ref.clone(),
    ]);
    for anchor in &entry.address.source_anchors {
        refs.insert(anchor.file_id.clone());
        refs.insert(anchor.clause_id.clone());
    }
    if refs.is_empty() || refs.len() > MAX_LEXICAL_EVIDENCE_REFS {
        return lexical_fault(
            LexicalIndexFaultKind::InvalidBound,
            "posting.evidence_refs",
            "surface evidence reference bound exceeded",
        );
    }
    Ok(refs)
}

fn append_lexical_surface_postings(
    postings: &mut BTreeMap<String, Vec<LexicalPosting>>,
    total_postings: &mut usize,
    entry: &IdentityAnchorEntry,
    surface_kind: LexicalSurfaceKind,
    surface: &str,
    evidence_refs: &BTreeSet<SemanticId>,
) -> LexicalIndexValidation {
    let surface_digest = lexical_surface_digest(&entry.address, &surface_kind, surface)?;
    for (token, occurrence_count) in tokenize_lexical_surface(surface)? {
        *total_postings = total_postings
            .checked_add(1)
            .ok_or_else(|| LexicalIndexFault {
                kind: LexicalIndexFaultKind::InvalidBound,
                field: "postings".to_owned(),
                detail: "total lexical posting count overflow".to_owned(),
            })?;
        if *total_postings > MAX_LEXICAL_TOTAL_POSTINGS {
            return lexical_fault(
                LexicalIndexFaultKind::InvalidBound,
                "postings",
                "total lexical posting bound exceeded",
            );
        }
        let token_postings = postings.entry(token.clone()).or_default();
        if token_postings.len() >= MAX_LEXICAL_POSTINGS_PER_TOKEN {
            return lexical_fault(
                LexicalIndexFaultKind::InvalidBound,
                "postings",
                "lexical postings-per-token bound exceeded",
            );
        }
        token_postings.push(LexicalPosting {
            token,
            address: entry.address.clone(),
            surface_kind: surface_kind.clone(),
            surface_digest: surface_digest.clone(),
            occurrence_count,
            evidence_refs: evidence_refs.clone(),
        });
    }
    Ok(())
}

fn lexical_surface_digest(
    address: &SemanticAddress,
    surface_kind: &LexicalSurfaceKind,
    surface: &str,
) -> LexicalIndexValidation<ContentDigest> {
    lexical_digest_form(LEXICAL_SURFACE_DOMAIN, &(surface_kind, address, surface))
}

fn lexical_posting_canonical_key(
    posting: &LexicalPosting,
) -> (&SemanticId, &SemanticId, &LexicalSurfaceKind, &str) {
    (
        &posting.address.unit_id,
        &posting.address.package_id,
        &posting.surface_kind,
        &posting.surface_digest.value,
    )
}

fn lexical_posting_canonical_cmp(
    left: &LexicalPosting,
    right: &LexicalPosting,
) -> std::cmp::Ordering {
    lexical_posting_canonical_key(left).cmp(&lexical_posting_canonical_key(right))
}

pub fn derived_semantic_anchor_catalogue_digest(
    derived: &DerivedSemanticAnchorCatalogue,
) -> AnchorValidation<ContentDigest> {
    digest_form(
        DERIVED_ARTIFACT_DOMAIN,
        &(
            &derived.profile,
            &derived.logical_revision,
            &derived.generation,
            &derived.catalogue,
            &derived.exact_label_index,
            &derived.relation_adjacency,
            &derived.omissions,
        ),
    )
}

fn build_derived_semantic_anchor_catalogue(
    fabric: &SemanticFabric,
    request: &CatalogueDerivationRequest,
) -> AnchorDerivationResult<DerivedSemanticAnchorCatalogue> {
    let generation = derive_fabric_generation(fabric)?;
    let package_roots = generation
        .packages
        .iter()
        .map(|package| (package.package_id.clone(), package.package_digest.clone()))
        .collect::<BTreeMap<_, _>>();
    let relation_adjacency = derive_relation_adjacency(fabric);
    let mut identity_entries = Vec::new();
    let mut exact_label_index: BTreeMap<String, BTreeSet<SemanticId>> = BTreeMap::new();
    let mut omissions = Vec::new();

    for unit in fabric.units() {
        let admitted =
            fabric
                .package_for_unit(&unit.unit_id)
                .ok_or_else(|| AnchorDerivationFault {
                    kind: AnchorDerivationFaultKind::MissingPackage,
                    stage: "unit_package".to_owned(),
                    detail: format!("unit {} has no admitted package owner", unit.unit_id),
                    related_ids: vec![unit.unit_id.clone()],
                })?;
        let certificate =
            admitted
                .package()
                .certificate
                .as_ref()
                .ok_or_else(|| AnchorDerivationFault {
                    kind: AnchorDerivationFaultKind::MissingCertificate,
                    stage: "unit_package".to_owned(),
                    detail: format!("unit {} owner has no recognition certificate", unit.unit_id),
                    related_ids: vec![unit.unit_id.clone()],
                })?;
        let mut source_anchors = admitted
            .content()
            .source_anchors
            .iter()
            .filter(|anchor| anchor.unit_id == unit.unit_id)
            .cloned()
            .collect::<Vec<_>>();
        source_anchors.sort_by(|left, right| {
            (
                &left.file_id,
                &left.clause_id,
                left.byte_start,
                left.byte_end,
                left.display_line_start,
                left.display_line_end,
            )
                .cmp(&(
                    &right.file_id,
                    &right.clause_id,
                    right.byte_start,
                    right.byte_end,
                    right.display_line_start,
                    right.display_line_end,
                ))
        });
        if source_anchors.is_empty() {
            return derivation_fault(
                AnchorDerivationFaultKind::MissingSourceAnchor,
                "source_anchor",
                &format!("unit {} has no exact source anchor", unit.unit_id),
                vec![unit.unit_id.clone()],
            );
        }
        let unit_digest = content_commitment(UNIT_DOMAIN, unit)?;
        let meaning_ref = content_identity("meaning", MEANING_DOMAIN, &unit.meaning)?;
        let context_id = content_identity("context", CONTEXT_DOMAIN, &unit.context)?;
        let package = admitted.package();
        let version = format!(
            "{}:{}@{}#{}",
            admitted.content().format_version,
            admitted.content().compiler_id,
            admitted.content().compiler_version,
            admitted.certificate_id()
        );
        let address = SemanticAddress {
            unit_id: unit.unit_id.clone(),
            unit_digest,
            package_id: package.package_id.clone(),
            package_digest: certificate.package_digest.clone(),
            kind: unit.kind.clone(),
            context_id,
            version,
            source_anchors,
        };
        let purposes = (!unit.context.purpose.trim().is_empty())
            .then(|| unit.context.purpose.clone())
            .into_iter()
            .collect();
        let relation_refs = relation_adjacency
            .get(&unit.unit_id)
            .cloned()
            .unwrap_or_default();
        identity_entries.push(IdentityAnchorEntry {
            address,
            preferred_expression: unit.expression.clone(),
            aliases: unit.aliases.clone(),
            meaning_ref,
            purposes,
            use_cases: BTreeSet::new(),
            included_boundaries: BTreeSet::new(),
            excluded_boundaries: BTreeSet::new(),
            protected_identities: BTreeSet::new(),
            relation_refs,
            lifecycle: if unit.status == UnitStatus::Superseded {
                AnchorLifecycle::Superseded
            } else {
                AnchorLifecycle::Admitted
            },
        });
        exact_label_index
            .entry(normalize_catalogue_label(&unit.expression))
            .or_default()
            .insert(unit.unit_id.clone());
        for alias in &unit.aliases {
            exact_label_index
                .entry(normalize_catalogue_label(alias))
                .or_default()
                .insert(unit.unit_id.clone());
        }
        if unit.kind == UnitKind::Operation {
            omissions.push(CatalogueDerivationOmission {
                unit_id: unit.unit_id.clone(),
                omitted_fields: [
                    "applicability_bindings",
                    "authority_requirements",
                    "effect_class",
                    "failure_conditions",
                    "invariants",
                    "non_transfer_set",
                    "operation_class",
                    "postconditions",
                    "preconditions",
                    "roles",
                    "verbs",
                ]
                .into_iter()
                .map(str::to_owned)
                .collect(),
                reason: "SemanticFabric has no admitted structured operation contract; natural-language inference is prohibited"
                    .to_owned(),
            });
        }
    }
    identity_entries.sort_by(|left, right| left.address.unit_id.cmp(&right.address.unit_id));
    omissions.sort_by(|left, right| left.unit_id.cmp(&right.unit_id));
    validate_label_source_correspondence(fabric, &exact_label_index)?;

    let compiler_id = SemanticId::new(SEMANTIC_ANCHOR_CATALOGUE_COMPILER_ID).map_err(|error| {
        AnchorDerivationFault {
            kind: AnchorDerivationFaultKind::InvalidGeneratedIdentity,
            stage: "catalogue_compiler".to_owned(),
            detail: error.to_string(),
            related_ids: Vec::new(),
        }
    })?;
    let mut catalogue = SemanticAnchorCatalogue {
        identity: CatalogueIdentity {
            profile: SEMANTIC_ANCHOR_CATALOGUE_PROFILE.to_owned(),
            catalogue_id: request.catalogue_id.clone(),
            logical_revision: request.logical_revision.clone(),
            catalogue_root: zero_sha256(),
            fabric_root: generation.fabric_root.clone(),
            package_roots,
            compiler_id,
            compiler_version: SEMANTIC_ANCHOR_CATALOGUE_COMPILER_VERSION.to_owned(),
            derivation_digest: zero_sha256(),
        },
        identity_entries,
        operation_entries: Vec::new(),
        applicability_bindings: Vec::new(),
    };
    catalogue.identity.derivation_digest =
        catalogue_derivation_digest(&catalogue.identity).map_err(anchor_form_to_derivation)?;
    catalogue.identity.catalogue_root =
        catalogue_root(&catalogue).map_err(anchor_form_to_derivation)?;
    let mut derived = DerivedSemanticAnchorCatalogue {
        profile: DERIVED_SEMANTIC_ANCHOR_CATALOGUE_PROFILE.to_owned(),
        logical_revision: request.logical_revision.clone(),
        generation,
        catalogue,
        exact_label_index,
        relation_adjacency,
        omissions,
        proof_digest: zero_sha256(),
    };
    derived.proof_digest =
        derived_semantic_anchor_catalogue_digest(&derived).map_err(anchor_form_to_derivation)?;
    Ok(derived)
}

fn derive_fabric_generation(
    fabric: &SemanticFabric,
) -> AnchorDerivationResult<FabricGenerationIdentity> {
    let mut packages = Vec::new();
    for package_id in fabric.package_ids() {
        let admitted = fabric
            .package(package_id)
            .ok_or_else(|| AnchorDerivationFault {
                kind: AnchorDerivationFaultKind::MissingPackage,
                stage: "fabric_generation".to_owned(),
                detail: format!("fabric package {package_id} cannot be resolved"),
                related_ids: vec![package_id.clone()],
            })?;
        let certificate =
            admitted
                .package()
                .certificate
                .as_ref()
                .ok_or_else(|| AnchorDerivationFault {
                    kind: AnchorDerivationFaultKind::MissingCertificate,
                    stage: "fabric_generation".to_owned(),
                    detail: format!("admitted package {package_id} has no certificate"),
                    related_ids: vec![package_id.clone()],
                })?;
        let actual_package_digest =
            crate::package_content_digest(admitted.content()).map_err(|error| {
                trust_to_derivation("package_digest", error.to_string(), package_id)
            })?;
        let actual_semantic_root = crate::semantic_root_digest(admitted.content())
            .map_err(|error| trust_to_derivation("semantic_root", error.to_string(), package_id))?;
        let actual_source_root = crate::source_root_digest(admitted.content())
            .map_err(|error| trust_to_derivation("source_root", error.to_string(), package_id))?;
        let derived_package_id =
            crate::derive_package_id(&actual_package_digest).map_err(|error| {
                trust_to_derivation("package_identity", error.to_string(), package_id)
            })?;
        if actual_package_digest != certificate.package_digest
            || actual_semantic_root != certificate.semantic_root_digest
            || actual_source_root != certificate.source_root_digest
            || derived_package_id != *package_id
            || certificate.certificate_id != *admitted.certificate_id()
        {
            return derivation_fault(
                AnchorDerivationFaultKind::SourceCorrespondence,
                "fabric_generation",
                &format!("admitted package {package_id} no longer matches certificate roots"),
                vec![package_id.clone()],
            );
        }
        packages.push(FabricPackageIdentity {
            package_id: package_id.clone(),
            package_digest: certificate.package_digest.clone(),
            certificate_id: certificate.certificate_id.clone(),
            semantic_root_digest: certificate.semantic_root_digest.clone(),
            source_root_digest: certificate.source_root_digest.clone(),
            compiler_id: admitted.content().compiler_id.clone(),
            compiler_version: admitted.content().compiler_version.clone(),
            authority_scope: certificate.authority_scope.clone(),
        });
    }
    packages.sort_by(|left, right| left.package_id.cmp(&right.package_id));
    let fabric_root = content_commitment(FABRIC_GENERATION_DOMAIN, &packages)?;
    Ok(FabricGenerationIdentity {
        packages,
        fabric_root,
    })
}

fn derive_relation_adjacency(
    fabric: &SemanticFabric,
) -> BTreeMap<SemanticId, BTreeSet<SemanticId>> {
    let mut adjacency = BTreeMap::<SemanticId, BTreeSet<SemanticId>>::new();
    for (_, relation) in fabric.relations() {
        adjacency
            .entry(relation.source.clone())
            .or_default()
            .insert(relation.relation_id.clone());
        adjacency
            .entry(relation.target.clone())
            .or_default()
            .insert(relation.relation_id.clone());
    }
    adjacency
}

fn validate_label_source_correspondence(
    fabric: &SemanticFabric,
    derived_labels: &BTreeMap<String, BTreeSet<SemanticId>>,
) -> AnchorDerivationResult {
    let mut admitted_labels: BTreeMap<String, BTreeSet<SemanticId>> = BTreeMap::new();
    for package_id in fabric.package_ids() {
        let package = fabric
            .package(package_id)
            .ok_or_else(|| AnchorDerivationFault {
                kind: AnchorDerivationFaultKind::MissingPackage,
                stage: "label_index".to_owned(),
                detail: format!("fabric package {package_id} cannot be resolved"),
                related_ids: vec![package_id.clone()],
            })?;
        for (label, units) in &package.content().exact_indexes.labels {
            admitted_labels
                .entry(label.clone())
                .or_default()
                .extend(units.iter().cloned());
        }
    }
    if &admitted_labels != derived_labels {
        return derivation_fault(
            AnchorDerivationFaultKind::SourceCorrespondence,
            "label_index",
            "derived labels differ from admitted package exact indexes",
            Vec::new(),
        );
    }
    Ok(())
}

fn content_commitment<T: Serialize>(
    domain: &str,
    value: &T,
) -> AnchorDerivationResult<ContentDigest> {
    digest_form(domain, value).map_err(anchor_form_to_derivation)
}

fn content_identity<T: Serialize>(
    prefix: &str,
    domain: &str,
    value: &T,
) -> AnchorDerivationResult<SemanticId> {
    let digest = content_commitment(domain, value)?;
    SemanticId::new(format!("{prefix}:{}:{}", digest.algorithm, digest.value)).map_err(|error| {
        AnchorDerivationFault {
            kind: AnchorDerivationFaultKind::InvalidGeneratedIdentity,
            stage: prefix.to_owned(),
            detail: error.to_string(),
            related_ids: Vec::new(),
        }
    })
}

fn normalize_catalogue_label(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn zero_sha256() -> ContentDigest {
    ContentDigest {
        algorithm: DIGEST_ALGORITHM.to_owned(),
        value: "0".repeat(64),
    }
}

fn anchor_form_to_derivation(fault: AnchorFormFault) -> AnchorDerivationFault {
    AnchorDerivationFault {
        kind: AnchorDerivationFaultKind::InvalidCatalogue,
        stage: fault.field,
        detail: fault.detail,
        related_ids: Vec::new(),
    }
}

fn trust_to_derivation(
    stage: &str,
    detail: String,
    package_id: &SemanticId,
) -> AnchorDerivationFault {
    AnchorDerivationFault {
        kind: AnchorDerivationFaultKind::SourceCorrespondence,
        stage: stage.to_owned(),
        detail,
        related_ids: vec![package_id.clone()],
    }
}

fn derivation_fault<T>(
    kind: AnchorDerivationFaultKind,
    stage: &str,
    detail: &str,
    related_ids: Vec<SemanticId>,
) -> AnchorDerivationResult<T> {
    Err(AnchorDerivationFault {
        kind,
        stage: stage.to_owned(),
        detail: detail.to_owned(),
        related_ids,
    })
}

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
    if catalogue.identity.package_roots.is_empty()
        || catalogue.identity.logical_revision.trim().is_empty()
        || catalogue.identity.compiler_version.is_empty()
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
    let expected_paths = candidate_relationship_paths(&result.candidates)?;
    if result.relationship_paths != expected_paths {
        return fault(
            AnchorFormFaultKind::RelationshipPathMismatch,
            "relationship_paths",
            "result relationship paths differ from canonical candidate contributions",
        );
    }
    let expected_account = candidate_association_account(&result.candidates)?;
    if result.association_account != expected_account {
        return fault(
            AnchorFormFaultKind::AssociationAccountMismatch,
            "association_account",
            "result association account differs from canonical candidate contributions",
        );
    }
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

pub fn candidate_relationship_paths(
    candidates: &[AnchorCandidate],
) -> AnchorValidation<Vec<AnchorRelationshipPath>> {
    let mut paths = Vec::new();
    for candidate in candidates {
        for contribution in &candidate.contributions {
            if let Some(path) = &contribution.relationship_path {
                validate_relationship_path(contribution, path)?;
                paths.push(path.clone());
            }
        }
    }
    paths.sort();
    if paths.windows(2).any(|pair| pair[0] == pair[1]) {
        return fault(
            AnchorFormFaultKind::RelationshipPathMismatch,
            "relationship_paths",
            "duplicate relationship path",
        );
    }
    Ok(paths)
}

pub fn candidate_association_account(
    candidates: &[AnchorCandidate],
) -> AnchorValidation<Vec<AssociationChannelAccount>> {
    let mut grouped = BTreeMap::<AssociationChannel, (BTreeSet<SemanticId>, u32)>::new();
    for candidate in candidates {
        for contribution in &candidate.contributions {
            let account = grouped.entry(contribution.channel.clone()).or_default();
            account.0.insert(candidate.address.unit_id.clone());
            account.1 = account.1.checked_add(1).ok_or_else(|| AnchorFormFault {
                kind: AnchorFormFaultKind::InvalidBound,
                field: "association_account.contribution_count".to_owned(),
                detail: "contribution count overflow".to_owned(),
            })?;
        }
    }
    Ok(grouped
        .into_iter()
        .map(
            |(channel, (candidate_ids, contribution_count))| AssociationChannelAccount {
                channel,
                candidate_ids: candidate_ids.into_iter().collect(),
                contribution_count,
            },
        )
        .collect())
}

pub fn catalogue_derivation_digest(
    identity: &CatalogueIdentity,
) -> AnchorValidation<ContentDigest> {
    digest_form(
        DERIVATION_DOMAIN,
        &(
            &identity.profile,
            &identity.catalogue_id,
            &identity.logical_revision,
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
            &catalogue.identity.logical_revision,
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
            &result.relationship_paths,
            &result.association_account,
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
    match (
        &contribution.channel,
        &contribution.channel_local_value,
        &contribution.relationship_path,
    ) {
        (AssociationChannel::TypedRelation, ChannelLocalValue::RelationHops(_), Some(path)) => {
            validate_relationship_path(contribution, path)?
        }
        (AssociationChannel::TypedRelation, _, None) => {
            return fault(
                AnchorFormFaultKind::RelationshipPathMismatch,
                "relationship_path",
                "typed relation contribution requires one relationship path",
            );
        }
        (_, _, Some(_)) => {
            return fault(
                AnchorFormFaultKind::RelationshipPathMismatch,
                "relationship_path",
                "only typed relation contributions may carry a relationship path",
            );
        }
        _ => {}
    }
    Ok(())
}

fn validate_relationship_path(
    contribution: &AssociationContribution,
    path: &AnchorRelationshipPath,
) -> AnchorValidation {
    let hops = match contribution.channel_local_value {
        ChannelLocalValue::RelationHops(hops) => usize::from(hops),
        _ => {
            return fault(
                AnchorFormFaultKind::RelationshipPathMismatch,
                "relationship_path",
                "relationship path requires relation-hop channel value",
            );
        }
    };
    if path.steps.is_empty()
        || path.steps.len() != hops
        || path.target_id != contribution.candidate_address.unit_id
    {
        return fault(
            AnchorFormFaultKind::RelationshipPathMismatch,
            "relationship_path",
            "path steps hops or target differ from the contribution",
        );
    }
    let mut cursor = path.seed_id.clone();
    let mut visited = BTreeSet::from([cursor.clone()]);
    for step in &path.steps {
        let (from, to) = match step.direction {
            RelationshipDirection::Forward => (&step.relation_source, &step.relation_target),
            RelationshipDirection::Reverse => (&step.relation_target, &step.relation_source),
        };
        if from != &cursor
            || !contribution.evidence_refs.contains(&step.relation_id)
            || !visited.insert(to.clone())
        {
            return fault(
                AnchorFormFaultKind::RelationshipPathMismatch,
                "relationship_path.steps",
                "path is discontinuous cyclic or lacks exact relation evidence",
            );
        }
        cursor = to.clone();
    }
    if cursor != path.target_id {
        return fault(
            AnchorFormFaultKind::RelationshipPathMismatch,
            "relationship_path.target_id",
            "path does not terminate at its target",
        );
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

fn commit_lexical_token(
    current: &mut String,
    tokens: &mut BTreeMap<String, u32>,
    occurrences: &mut usize,
) -> LexicalIndexValidation {
    if current.is_empty() {
        return Ok(());
    }
    *occurrences = occurrences
        .checked_add(1)
        .ok_or_else(|| LexicalIndexFault {
            kind: LexicalIndexFaultKind::InvalidBound,
            field: "surface.tokens".to_owned(),
            detail: "lexical token occurrence count overflow".to_owned(),
        })?;
    if *occurrences > MAX_LEXICAL_TOKENS_PER_SURFACE {
        return lexical_fault(
            LexicalIndexFaultKind::InvalidBound,
            "surface.tokens",
            "lexical tokens-per-surface bound exceeded",
        );
    }
    let token = std::mem::take(current);
    let count = tokens.entry(token).or_default();
    *count = count.checked_add(1).ok_or_else(|| LexicalIndexFault {
        kind: LexicalIndexFaultKind::InvalidBound,
        field: "surface.token_occurrence".to_owned(),
        detail: "lexical token occurrence count overflow".to_owned(),
    })?;
    Ok(())
}

fn lexical_digest_form<T: Serialize>(
    domain: &str,
    value: &T,
) -> LexicalIndexValidation<ContentDigest> {
    let bytes = serde_json::to_vec(value).map_err(|error| LexicalIndexFault {
        kind: LexicalIndexFaultKind::InvalidIdentity,
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

fn validate_lexical_digest(digest: &ContentDigest, field: &str) -> LexicalIndexValidation {
    if digest.algorithm != DIGEST_ALGORITHM
        || digest.value.len() != 64
        || !digest
            .value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return lexical_fault(
            LexicalIndexFaultKind::InvalidDigest,
            field,
            "expected lowercase SHA-256",
        );
    }
    Ok(())
}

fn anchor_form_to_lexical_fault(fault: AnchorFormFault) -> LexicalIndexFault {
    LexicalIndexFault {
        kind: LexicalIndexFaultKind::InvalidIdentity,
        field: fault.field,
        detail: fault.detail,
    }
}

fn anchor_form_to_lookup_fault(fault: AnchorFormFault) -> LexicalLookupFault {
    LexicalLookupFault {
        kind: match fault.kind {
            AnchorFormFaultKind::RootMismatch => LexicalLookupFaultKind::RootMismatch,
            AnchorFormFaultKind::NonCanonicalOrder | AnchorFormFaultKind::DuplicateIdentity => {
                LexicalLookupFaultKind::NonCanonicalOrder
            }
            AnchorFormFaultKind::InvalidProfile => LexicalLookupFaultKind::InvalidProfile,
            AnchorFormFaultKind::InvalidBound => LexicalLookupFaultKind::InvalidBound,
            _ => LexicalLookupFaultKind::ProjectionMismatch,
        },
        field: fault.field,
        detail: fault.detail,
    }
}

fn lexical_index_to_lookup_fault(fault: LexicalIndexFault) -> LexicalLookupFault {
    LexicalLookupFault {
        kind: match fault.kind {
            LexicalIndexFaultKind::InvalidProfile => LexicalLookupFaultKind::InvalidProfile,
            LexicalIndexFaultKind::InvalidBound => LexicalLookupFaultKind::InvalidBound,
            LexicalIndexFaultKind::RootMismatch => LexicalLookupFaultKind::RootMismatch,
            LexicalIndexFaultKind::NonCanonicalOrder | LexicalIndexFaultKind::DuplicatePosting => {
                LexicalLookupFaultKind::NonCanonicalOrder
            }
            LexicalIndexFaultKind::InvalidIdentity
            | LexicalIndexFaultKind::InvalidDigest
            | LexicalIndexFaultKind::ProjectionMismatch => LexicalLookupFaultKind::IndexRejected,
        },
        field: fault.field,
        detail: fault.detail,
    }
}

fn lexical_lookup_to_source_projection_fault(
    fault: LexicalLookupFault,
) -> LexicalSourceProjectionFault {
    LexicalSourceProjectionFault {
        kind: match fault.kind {
            LexicalLookupFaultKind::InvalidProfile => {
                LexicalSourceProjectionFaultKind::InvalidProfile
            }
            LexicalLookupFaultKind::InvalidBound => LexicalSourceProjectionFaultKind::InvalidBound,
            LexicalLookupFaultKind::BudgetExceeded => {
                LexicalSourceProjectionFaultKind::BudgetExceeded
            }
            LexicalLookupFaultKind::RootMismatch => {
                LexicalSourceProjectionFaultKind::IdentityMismatch
            }
            LexicalLookupFaultKind::IndexRejected
            | LexicalLookupFaultKind::NonCanonicalOrder
            | LexicalLookupFaultKind::ProjectionMismatch
            | LexicalLookupFaultKind::ProofMismatch => {
                LexicalSourceProjectionFaultKind::LookupRejected
            }
        },
        field: fault.field,
        detail: fault.detail,
    }
}

fn lexical_index_to_source_projection_fault(
    fault: LexicalIndexFault,
) -> LexicalSourceProjectionFault {
    LexicalSourceProjectionFault {
        kind: match fault.kind {
            LexicalIndexFaultKind::InvalidProfile => {
                LexicalSourceProjectionFaultKind::InvalidProfile
            }
            LexicalIndexFaultKind::InvalidBound => LexicalSourceProjectionFaultKind::InvalidBound,
            LexicalIndexFaultKind::RootMismatch => {
                LexicalSourceProjectionFaultKind::IdentityMismatch
            }
            LexicalIndexFaultKind::InvalidIdentity
            | LexicalIndexFaultKind::InvalidDigest
            | LexicalIndexFaultKind::NonCanonicalOrder
            | LexicalIndexFaultKind::DuplicatePosting
            | LexicalIndexFaultKind::ProjectionMismatch => {
                LexicalSourceProjectionFaultKind::ProjectionMismatch
            }
        },
        field: fault.field,
        detail: fault.detail,
    }
}

fn anchor_derivation_to_lexical_fault(fault: AnchorDerivationFault) -> LexicalIndexFault {
    LexicalIndexFault {
        kind: match fault.kind {
            AnchorDerivationFaultKind::InvalidRequest
            | AnchorDerivationFaultKind::InvalidGeneratedIdentity => {
                LexicalIndexFaultKind::InvalidIdentity
            }
            AnchorDerivationFaultKind::MissingCertificate
            | AnchorDerivationFaultKind::MissingPackage
            | AnchorDerivationFaultKind::MissingSourceAnchor
            | AnchorDerivationFaultKind::SourceCorrespondence
            | AnchorDerivationFaultKind::InvalidCatalogue
            | AnchorDerivationFaultKind::ProjectionMismatch => {
                LexicalIndexFaultKind::ProjectionMismatch
            }
        },
        field: fault.stage,
        detail: fault.detail,
    }
}

fn lexical_fault<T>(
    kind: LexicalIndexFaultKind,
    field: &str,
    detail: &str,
) -> LexicalIndexValidation<T> {
    Err(LexicalIndexFault {
        kind,
        field: field.to_owned(),
        detail: detail.to_owned(),
    })
}

fn lexical_lookup_digest_form<T: Serialize>(
    domain: &str,
    value: &T,
) -> LexicalLookupValidation<ContentDigest> {
    lexical_digest_form(domain, value).map_err(lexical_index_to_lookup_fault)
}

fn lexical_source_projection_digest_form<T: Serialize>(
    domain: &str,
    value: &T,
) -> LexicalSourceProjectionValidation<ContentDigest> {
    lexical_digest_form(domain, value).map_err(lexical_index_to_source_projection_fault)
}

fn lexical_lookup_fault<T>(
    kind: LexicalLookupFaultKind,
    field: &str,
    detail: &str,
) -> LexicalLookupValidation<T> {
    Err(LexicalLookupFault {
        kind,
        field: field.to_owned(),
        detail: detail.to_owned(),
    })
}

fn lexical_source_projection_fault<T>(
    kind: LexicalSourceProjectionFaultKind,
    field: &str,
    detail: &str,
) -> LexicalSourceProjectionValidation<T> {
    Err(LexicalSourceProjectionFault {
        kind,
        field: field.to_owned(),
        detail: detail.to_owned(),
    })
}

fn fault<T>(kind: AnchorFormFaultKind, field: &str, detail: &str) -> AnchorValidation<T> {
    Err(AnchorFormFault {
        kind,
        field: field.to_owned(),
        detail: detail.to_owned(),
    })
}
