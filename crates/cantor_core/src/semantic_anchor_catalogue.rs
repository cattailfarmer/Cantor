//! Strict pure forms and admitted-fabric derivation for the semantic anchor
//! catalogue P0.
//!
//! Slice 1 defines and validates the closed machine forms. Slice 2 reads one
//! already admitted immutable semantic fabric and derives a disposable,
//! generation-bound catalogue projection. It does not compile or admit source,
//! scan a query, invoke a provider, persist state, or authorize an effect.

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
pub const SEMANTIC_ANCHOR_CATALOGUE_COMPILER_ID: &str = "compiler:cantor_semantic_anchor_catalogue";
pub const SEMANTIC_ANCHOR_CATALOGUE_COMPILER_VERSION: &str = "0.1.0";

const DIGEST_ALGORITHM: &str = "sha256";
const DERIVATION_DOMAIN: &str = "cantor.semantic-anchor-catalogue.derivation.v1";
const CATALOGUE_DOMAIN: &str = "cantor.semantic-anchor-catalogue.root.v1";
const RESULT_DOMAIN: &str = "cantor.semantic-anchor-catalogue.result.v1";
const FABRIC_GENERATION_DOMAIN: &str = "cantor.semantic-anchor-catalogue.fabric-generation.v1";
const DERIVED_ARTIFACT_DOMAIN: &str = "cantor.semantic-anchor-catalogue.derived-artifact.v1";
const UNIT_DOMAIN: &str = "cantor.semantic-anchor-catalogue.unit.v1";
const MEANING_DOMAIN: &str = "cantor.semantic-anchor-catalogue.meaning.v1";
const CONTEXT_DOMAIN: &str = "cantor.semantic-anchor-catalogue.context.v1";

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

fn fault<T>(kind: AnchorFormFaultKind, field: &str, detail: &str) -> AnchorValidation<T> {
    Err(AnchorFormFault {
        kind,
        field: field.to_owned(),
        detail: detail.to_owned(),
    })
}
