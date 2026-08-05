use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::IR_VERSION;

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "json-schema", schemars(extend("minLength" = 1, "maxLength" = 512, "pattern" = "^[A-Za-z0-9_.:/-]+$")))]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct SemanticId(String);

impl SemanticId {
    pub fn new(value: impl Into<String>) -> Result<Self, EvaluationFault> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= 512
            && value
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | ':' | '/'));
        if valid {
            Ok(Self(value))
        } else {
            let preview = value.chars().take(80).collect::<String>();
            let suffix = if preview.len() < value.len() {
                "…"
            } else {
                ""
            };
            Err(EvaluationFault::new(
                FaultKind::InvalidIdentity,
                format!(
                    "invalid semantic identity (empty, over 512 bytes, or invalid character): byte_length={}, preview={preview:?}{suffix}",
                    value.len()
                ),
            ))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SemanticId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SemanticId {
    fn deserialize<Deserializer>(deserializer: Deserializer) -> Result<Self, Deserializer::Error>
    where
        Deserializer: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentDigest {
    pub algorithm: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceAnchor {
    pub package_id: SemanticId,
    pub file_id: SemanticId,
    pub unit_id: SemanticId,
    pub clause_id: SemanticId,
    pub byte_start: u64,
    pub byte_end: u64,
    pub span_digest: ContentDigest,
    pub display_line_start: u32,
    pub display_line_end: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PackageLifecycle {
    SchemaOnly,
    Compiled,
    Admitted,
    Stale,
    Revoked,
}

/// Slice-01 machine form only. Recognition and admission behavior belongs to
/// CEB Slice 02.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledPackageManifest {
    pub manifest_version: String,
    pub package_id: SemanticId,
    pub semantic_unit_ids: Vec<SemanticId>,
    pub relation_ids: Vec<SemanticId>,
    pub source_files: Vec<String>,
    pub package_digest: ContentDigest,
    pub recognition_certificate: Option<String>,
    pub lifecycle: PackageLifecycle,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RequestedDetailKind {
    Term,
    Clause,
    Definition,
    Description,
    UseCase,
    Boundary,
    Condition,
    Relation,
    Instruction,
    Authority,
    Evidence,
    Fault,
    SourceSpan,
    Derivation,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SearchMode {
    Exact,
    Contextual,
    Relational,
    Lexical,
    Routed,
    Composed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityContext {
    pub caller_id: SemanticId,
    pub allowed_package_scopes: BTreeSet<String>,
    pub operation: String,
    pub effect_boundary: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryBudget {
    pub maximum_records: u32,
    pub maximum_paths: u32,
    pub maximum_depth: u32,
    pub maximum_bytes: u64,
    pub maximum_elapsed_milliseconds: u64,
}

/// Slice-01 machine form only. Query behavior belongs to CEB Slice 03.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CantorQueryRequest {
    pub protocol_version: String,
    pub request_id: SemanticId,
    pub term_set: BTreeSet<String>,
    pub subject: Option<String>,
    pub purpose: String,
    pub use_case_set: BTreeSet<String>,
    pub include_boundary_set: BTreeSet<String>,
    pub exclude_boundary_set: BTreeSet<String>,
    pub description_need: Option<String>,
    pub requested_detail_kinds: BTreeSet<RequestedDetailKind>,
    pub search_modes: BTreeSet<SearchMode>,
    pub relation_types: BTreeSet<RelationType>,
    pub criteria: BTreeSet<String>,
    pub source_scopes: BTreeSet<String>,
    pub perspectives: BTreeSet<String>,
    pub known_units: BTreeSet<SemanticId>,
    pub authority_context: AuthorityContext,
    pub budget: QueryBudget,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedQuote {
    pub text: String,
    pub source_anchor: SourceAnchor,
    pub document_digest: ContentDigest,
    pub certificate_id: SemanticId,
    pub verified: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationshipStep {
    pub package_id: SemanticId,
    pub relation_id: SemanticId,
    pub relation_type: RelationType,
    pub source: SemanticId,
    pub target: SemanticId,
    pub source_ref: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationshipPath {
    pub unit_path: Vec<SemanticId>,
    pub steps: Vec<RelationshipStep>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageProofRecord {
    pub package_id: SemanticId,
    pub certificate_id: SemanticId,
    pub package_digest: ContentDigest,
    pub semantic_root_digest: ContentDigest,
    pub source_root_digest: ContentDigest,
    pub authority_signer_id: SemanticId,
    pub compiler_signer_id: SemanticId,
    pub admitted_at_epoch_seconds: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundaryAccount {
    pub admitted: Vec<SemanticId>,
    pub excluded: Vec<SemanticId>,
    pub ambiguous: Vec<SemanticId>,
    pub contradictory: Vec<SemanticId>,
    pub unknown: Vec<String>,
    pub stale: Vec<SemanticId>,
    pub unauthorized: Vec<SemanticId>,
    pub budget_clipped: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofBundle {
    pub package_proofs: Vec<PackageProofRecord>,
    pub package_checks: Vec<String>,
    pub source_checks: Vec<String>,
    pub query_decisions: Vec<String>,
    pub relation_paths: Vec<RelationshipPath>,
    pub exclusions: Vec<String>,
    pub omissions: Vec<String>,
    pub result_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetailStatus {
    Returned,
    AlreadyResident,
    ExplicitlyAbsent,
    BudgetClipped,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetailAccount {
    pub kind: RequestedDetailKind,
    pub status: DetailStatus,
    pub record_ids: Vec<SemanticId>,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum QueryFaultKind {
    InvalidRequest,
    UnknownIdentity,
    Ambiguous,
    Unauthorized,
    UnsupportedSearchMode,
    MissingDetail,
    BudgetExhausted,
    Contradiction,
    ProofGap,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryFault {
    pub kind: QueryFaultKind,
    pub stage: String,
    pub message: String,
    pub related_ids: Vec<SemanticId>,
}

impl QueryFault {
    pub fn new(
        kind: QueryFaultKind,
        stage: impl Into<String>,
        message: impl Into<String>,
        related_ids: Vec<SemanticId>,
    ) -> Self {
        Self {
            kind,
            stage: stage.into(),
            message: message.into(),
            related_ids,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CantorQueryResult {
    pub protocol_version: String,
    pub request_id: SemanticId,
    pub resolved_subjects: Vec<SemanticId>,
    pub records: Vec<SemanticUnit>,
    pub verified_quotes: Vec<VerifiedQuote>,
    pub relationship_paths: Vec<RelationshipPath>,
    pub boundary_account: BoundaryAccount,
    pub deterministic_contributions: Vec<String>,
    pub routed_contributions: Vec<String>,
    pub proof: ProofBundle,
    pub detail_accounts: Vec<DetailAccount>,
    pub faults: Vec<QueryFault>,
    pub continuation: Option<String>,
    pub result_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoreMachineSchema {
    pub semantic_unit: SemanticUnit,
    pub relation: SemanticRelation,
    pub context: SemanticContext,
    pub anchor: SourceAnchor,
    pub package: CompiledPackageManifest,
    pub query: CantorQueryRequest,
    pub result: CantorQueryResult,
    pub proof: ProofBundle,
    pub trace: TransitionTrace,
    pub fault: EvaluationFault,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum UnitKind {
    Term,
    Value,
    Relation,
    Declaration,
    Judgment,
    Contract,
    Operation,
    Program,
    Result,
    Fault,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnitStatus {
    Asserted,
    Assumed,
    Inferred,
    Disputed,
    Validated,
    Superseded,
    Unresolved,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticContext {
    pub scope: String,
    pub purpose: String,
    pub assumptions: Vec<String>,
    pub perspective: String,
    pub world: String,
}

impl SemanticContext {
    pub fn fixture(scope: &str, purpose: &str) -> Self {
        Self {
            scope: scope.to_owned(),
            purpose: purpose.to_owned(),
            assumptions: Vec::new(),
            perspective: "fixture".to_owned(),
            world: "core-v0.1".to_owned(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticUnit {
    pub unit_id: SemanticId,
    pub kind: UnitKind,
    pub expression: String,
    pub aliases: BTreeSet<String>,
    pub meaning: String,
    pub context: SemanticContext,
    pub source_set: Vec<String>,
    pub status: UnitStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RelationType {
    Alias,
    Broader,
    Narrower,
    DependsOn,
    DistinctFrom,
    Supports,
    Contradicts,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticRelation {
    pub relation_id: SemanticId,
    pub source: SemanticId,
    pub relation_type: RelationType,
    pub target: SemanticId,
    pub source_ref: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct SemanticEnvironment {
    pub units: BTreeMap<SemanticId, SemanticUnit>,
    pub labels: BTreeMap<String, BTreeSet<SemanticId>>,
    pub relations: Vec<SemanticRelation>,
}

impl SemanticEnvironment {
    pub fn resolve_label_in_scope(&self, label: &str, scope: &str) -> Vec<&SemanticUnit> {
        self.labels
            .get(&label.to_ascii_lowercase())
            .into_iter()
            .flatten()
            .filter_map(|id| self.units.get(id))
            .filter(|unit| unit.context.scope == scope)
            .collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StateStatus {
    Ready,
    Running,
    Yielded,
    Blocked,
    Faulted,
    Stopped,
    Complete,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttentionBudget {
    pub transitions_remaining: u32,
    pub effects_remaining: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticState {
    pub ir_version: String,
    pub state_id: SemanticId,
    pub purpose: String,
    pub environment: SemanticEnvironment,
    pub focus: Option<SemanticId>,
    pub inside: BTreeSet<SemanticId>,
    pub boundary: BTreeSet<String>,
    pub outside: BTreeSet<SemanticId>,
    pub frontier: BTreeSet<SemanticId>,
    pub evidence: Vec<String>,
    pub uncertainty: Vec<String>,
    pub values: BTreeMap<String, i64>,
    pub budget: AttentionBudget,
    pub pending_effects: Vec<EffectEvent>,
    pub status: StateStatus,
}

impl SemanticState {
    pub fn fixture(state_id: SemanticId, purpose: &str) -> Self {
        Self {
            ir_version: IR_VERSION.to_owned(),
            state_id,
            purpose: purpose.to_owned(),
            environment: SemanticEnvironment::default(),
            focus: None,
            inside: BTreeSet::new(),
            boundary: BTreeSet::new(),
            outside: BTreeSet::new(),
            frontier: BTreeSet::new(),
            evidence: Vec::new(),
            uncertainty: Vec::new(),
            values: BTreeMap::new(),
            budget: AttentionBudget {
                transitions_remaining: 32,
                effects_remaining: 2,
            },
            pending_effects: Vec::new(),
            status: StateStatus::Ready,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConstraintRequirement {
    Present,
    NonEmpty,
    Equals(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConstraintOutcome {
    Valid,
    Unknown,
    Invalid,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum EffectAuthority {
    Denied { reason: String },
    Authorized { grant: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EffectStatus {
    Denied,
    Proposed,
    Authorized,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectEvent {
    pub effect_id: SemanticId,
    pub description: String,
    pub status: EffectStatus,
    pub authority: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OntologyStandard {
    Skos,
    Rdfs,
    Shacl,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ImportFidelity {
    Exact,
    Partial { loss_notes: Vec<String> },
    Rejected { reason: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OntologyImport {
    pub standard: OntologyStandard,
    pub source_construct: String,
    pub relation: SemanticRelation,
    pub fidelity: ImportFidelity,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Instruction {
    Declare {
        unit: SemanticUnit,
    },
    Infer {
        conclusion: SemanticUnit,
        premises: Vec<String>,
        rule: String,
    },
    ValidateConstraint {
        name: String,
        observed: Option<String>,
        requirement: ConstraintRequirement,
    },
    TransformAdd {
        target: String,
        left: i64,
        right: i64,
    },
    ProposeEffect {
        effect_id: SemanticId,
        description: String,
        authority: EffectAuthority,
    },
    Yield,
    Reenter {
        restored_state: Box<SemanticState>,
    },
    ImportOntology {
        import: OntologyImport,
    },
}

impl Instruction {
    pub fn family(&self) -> &'static str {
        match self {
            Self::Declare { .. } => "DECLARE",
            Self::Infer { .. } => "INFER",
            Self::ValidateConstraint { .. } => "CONSTRAIN",
            Self::TransformAdd { .. } => "TRANSFORM",
            Self::ProposeEffect { .. } => "EFFECT",
            Self::Yield | Self::Reenter { .. } => "CONTROL",
            Self::ImportOntology { .. } => "RELATE",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticProgram {
    pub ir_version: String,
    pub program_id: SemanticId,
    pub purpose: String,
    pub instructions: Vec<Instruction>,
    pub source_forms: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum JudgmentStatus {
    Asserted,
    Assumed,
    Inferred,
    Validated,
    Unknown,
    Invalid,
    Denied,
    Authorized,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Judgment {
    pub status: JudgmentStatus,
    pub claim: String,
    pub grounds: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransitionTrace {
    pub source: String,
    pub rule: String,
    pub reason: String,
    pub evidence: Vec<String>,
    pub authority: Vec<String>,
    pub uncertainty: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HistoryDecision {
    Continue,
    Revise,
    Redirect,
    Block,
    Escalate,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryReviewEvent {
    pub review_id: SemanticId,
    pub current_subject: String,
    pub current_purpose: String,
    pub current_operation: String,
    pub candidate_count: usize,
    pub selected_records: Vec<String>,
    pub counterevidence_records: Vec<String>,
    pub excluded_summary: Vec<String>,
    pub coverage_statement: String,
    pub projection_digest: ContentDigest,
    pub reconciliation: String,
    pub transition_decision: HistoryDecision,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticTransition {
    pub transition_id: SemanticId,
    pub before_state: SemanticState,
    pub history_review: HistoryReviewEvent,
    pub instruction: Instruction,
    pub judgments: Vec<Judgment>,
    pub after_state: SemanticState,
    pub effect_events: Vec<EffectEvent>,
    pub faults: Vec<EvaluationFault>,
    pub trace: TransitionTrace,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FaultKind {
    InvalidIdentity,
    BudgetExhausted,
    UnknownKnowledge,
    ConstraintViolation,
    UnauthorizedEffect,
    InvalidReentry,
    SemanticLoss,
    MachineForm,
    UnsupportedSurface,
    ReviewFailure,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationFault {
    pub kind: FaultKind,
    pub message: String,
}

impl EvaluationFault {
    pub fn new(kind: FaultKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

impl fmt::Display for EvaluationFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.kind, self.message)
    }
}

impl std::error::Error for EvaluationFault {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofAssertion {
    pub claim: String,
    pub support: Vec<String>,
    pub passed: bool,
}
