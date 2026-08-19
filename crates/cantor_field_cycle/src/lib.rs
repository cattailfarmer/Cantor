use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::Write;

pub const FIELD_PROFILE: &str = "cantor-semantic-field/0.1";
pub const CYCLE_PROFILE: &str = "cantor-field-attention-cycle/0.1";
pub const REQUEST_PROFILE_V1: &str = "cantor-field-attention-requests/0.1";
pub const REQUEST_PROFILE_V2: &str = "cantor-field-attention-requests/0.2";
pub const REQUEST_PROFILE_V3: &str = "cantor-field-attention-requests/0.3";
pub const REQUEST_PROFILE_V4: &str = "cantor-field-attention-requests/0.4";
pub const REQUEST_PROFILE_V5: &str = "cantor-field-attention-requests/0.5";
pub const CURRENT_REQUEST_PROFILE: &str = REQUEST_PROFILE_V5;
pub const PROBE_COUNT: usize = 4;
pub const MINIMUM_SUPPORT: usize = 3;
pub const MINIMUM_ELEMENTS: usize = 4;
pub const MAXIMUM_ELEMENTS: usize = 16;
pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_SUBJECT_BYTES: usize = 4096;
pub const MAX_PURPOSE_BYTES: usize = 4096;
pub const MAX_ELEMENT_CONTENT_BYTES: usize = 16_384;
pub const MAX_SOURCE_REF_BYTES: usize = 2048;
pub const MAX_BOUNDARY_REASON_BYTES: usize = 4096;
pub const MAX_PROVIDER_MODEL_BYTES: usize = 4096;
pub const MAX_PROVIDER_BASE_URL_BYTES: usize = 2048;
pub const MAX_FIELD_FILE_BYTES: u64 = 524_288;
pub const MAX_REPORT_FILE_BYTES: u64 = 16_777_216;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ElementKind {
    Term,
    Clause,
    Contract,
    Observation,
    Purpose,
    Constraint,
    Artifact,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FieldElement {
    pub element_id: String,
    pub kind: ElementKind,
    pub content: String,
    pub content_sha256: String,
    pub source_ref: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryKind {
    ForbidCoMembership,
    ForbidRelation,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RelationKind {
    Supports,
    Complements,
    Contrasts,
    Constrains,
    DependsOn,
    Contextualizes,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HardBoundary {
    pub boundary_id: String,
    pub kind: BoundaryKind,
    pub left_id: String,
    pub right_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relation_kind: Option<RelationKind>,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProbePolicy {
    pub probe_count: usize,
    pub minimum_support: usize,
}

impl Default for ProbePolicy {
    fn default() -> Self {
        Self {
            probe_count: PROBE_COUNT,
            minimum_support: MINIMUM_SUPPORT,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SemanticField {
    pub profile: String,
    pub field_id: String,
    pub subject: String,
    pub purpose: String,
    pub elements: Vec<FieldElement>,
    #[serde(default)]
    pub boundaries: Vec<HardBoundary>,
    pub probe_policy: ProbePolicy,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProbeProposal {
    pub candidate_member_ids: Vec<String>,
    pub pattern: String,
    #[serde(default)]
    pub tensions: Vec<String>,
    #[serde(default)]
    pub exclusions: Vec<String>,
    #[serde(default)]
    pub uncertainty: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum FieldAssessment {
    Coherent,
    Uncertain,
    Conflicted,
    Excludes,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct TypedProbeProposal {
    candidate_member_ids: Vec<String>,
    assessment: FieldAssessment,
    flagged_member_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FieldProbe {
    pub probe_id: String,
    pub order: Vec<String>,
    pub candidate_member_ids: Vec<String>,
    pub pattern: String,
    pub tensions: Vec<String>,
    pub exclusions: Vec<String>,
    pub uncertainty: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CandidateStatus {
    Provisional,
    InsufficientSupport,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GestaltCandidate {
    pub candidate_id: String,
    pub field_digest: String,
    pub member_ids: Vec<String>,
    pub supporting_probe_ids: Vec<String>,
    pub support_count: usize,
    pub probe_count: usize,
    pub status: CandidateStatus,
    pub representative_pattern: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DelineationStatus {
    Supported,
    Rejected,
    Unresolved,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentityBinding {
    pub input_id: String,
    pub output_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct RelationEdge {
    pub source_id: String,
    pub kind: RelationKind,
    pub target_id: String,
    pub account: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DelineationProposal {
    pub candidate_id: String,
    pub status: DelineationStatus,
    pub identity_bindings: Vec<IdentityBinding>,
    pub relations: Vec<RelationEdge>,
    #[serde(default)]
    pub contradictions: Vec<String>,
    #[serde(default)]
    pub excluded_member_ids: Vec<String>,
    #[serde(default)]
    pub uncertainty: Vec<String>,
    pub account: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct TypedDelineationProposal {
    candidate_id: String,
    status: DelineationStatus,
    ordered_member_ids: Vec<String>,
    relation_kinds: Vec<RelationKind>,
    contradiction_member_ids: Vec<String>,
    excluded_member_ids: Vec<String>,
    uncertain_member_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum GateFault {
    CandidateIdMismatch,
    CandidateNotProvisional,
    InsufficientProbeSupport,
    UnknownIdentity,
    IncompleteIdentityBindings,
    DuplicateIdentityBinding,
    IdentityRemap,
    UnknownRelationEndpoint,
    SelfRelation,
    DuplicateRelation,
    MissingAccount,
    BoundaryConflict,
    IncompleteRelationCoverage,
    DisconnectedSupport,
    ProposalRejected,
    ProposalUnresolved,
    ContradictionPresent,
    ExcludedCandidateMember,
    UncertaintyPresent,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DelineationResult {
    pub status: DelineationStatus,
    pub identity_preserved: bool,
    pub boundary_preserved: bool,
    pub support_connected: bool,
    pub contradiction_free: bool,
    pub uncertainty_free: bool,
    pub failed_gates: Vec<GateFault>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LatchStatus {
    AdmittedForAttention,
    Rejected,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LatchDecision {
    pub profile: String,
    pub field_id: String,
    pub field_digest: String,
    pub candidate_id: String,
    pub status: LatchStatus,
    pub failed_gates: Vec<GateFault>,
    pub proof_refs: Vec<String>,
    pub semantic_scope: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CycleState {
    Created,
    FieldValidated,
    ProbesRequested,
    ProbesCollected,
    CandidateAggregated,
    DelineationRequested,
    DelineationCollected,
    LatchEvaluated,
    Completed,
    Rejected,
    Faulted,
    ControlCompleted,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CycleEvent {
    pub ordinal: usize,
    pub state: CycleState,
    pub evidence_ref: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ControlObservation {
    pub probe: FieldProbe,
    pub latch_eligible: bool,
    pub terminal_state: CycleState,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderIdentity {
    pub base_url: String,
    pub model: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProviderExchange {
    pub stage: String,
    pub request_sha256: String,
    pub response_sha256: String,
    pub request: Value,
    pub response: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CycleReport {
    pub profile: String,
    #[serde(
        default = "default_request_profile",
        skip_serializing_if = "is_request_profile_v1"
    )]
    pub request_profile: String,
    pub run_id: String,
    pub provider: ProviderIdentity,
    pub field: SemanticField,
    pub field_digest: String,
    pub events: Vec<CycleEvent>,
    pub exchanges: Vec<ProviderExchange>,
    pub probes: Vec<FieldProbe>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate: Option<GestaltCandidate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delineation_proposal: Option<DelineationProposal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delineation_result: Option<DelineationResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latch_decision: Option<LatchDecision>,
    pub terminal_state: CycleState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fault: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReportVerification {
    pub valid: bool,
    pub terminal_state: CycleState,
    pub latch_status: Option<LatchStatus>,
    pub exchange_count: usize,
    pub report_sha256: String,
}

pub fn sha256_hex(bytes: impl AsRef<[u8]>) -> String {
    let digest = Sha256::digest(bytes.as_ref());
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

pub fn canonical_digest<T: Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(sha256_hex)
        .map_err(|error| format!("canonical JSON serialization failed: {error}"))
}

pub fn normalize_loopback_base_url(candidate: &str) -> Result<String, String> {
    require_bounded_nonempty("provider base URL", candidate, MAX_PROVIDER_BASE_URL_BYTES)?;
    let trimmed = candidate.trim_end_matches('/');
    if trimmed.contains('@') || trimmed.contains('?') || trimmed.contains('#') {
        return Err("base URL must not contain userinfo, query, or fragment".to_owned());
    }
    let authority = trimmed
        .strip_prefix("http://")
        .ok_or("base URL must use ordinary loopback HTTP")?;
    if authority.contains('/') {
        return Err("base URL must not contain a path".to_owned());
    }
    let valid = authority == "127.0.0.1"
        || authority == "localhost"
        || authority.strip_prefix("127.0.0.1:").is_some_and(valid_port)
        || authority.strip_prefix("localhost:").is_some_and(valid_port);
    if !valid {
        return Err("base URL must identify 127.0.0.1 or localhost".to_owned());
    }
    Ok(trimmed.to_owned())
}

fn valid_port(value: &str) -> bool {
    value.parse::<u16>().is_ok_and(|port| port != 0)
}

fn default_request_profile() -> String {
    REQUEST_PROFILE_V1.to_owned()
}

fn is_request_profile_v1(value: &String) -> bool {
    value == REQUEST_PROFILE_V1
}

pub fn validate_field(field: &SemanticField) -> Result<(), String> {
    if field.profile != FIELD_PROFILE {
        return Err(format!("unsupported field profile: {}", field.profile));
    }
    require_bounded_nonempty("field_id", &field.field_id, MAX_IDENTIFIER_BYTES)?;
    require_bounded_nonempty("subject", &field.subject, MAX_SUBJECT_BYTES)?;
    require_bounded_nonempty("purpose", &field.purpose, MAX_PURPOSE_BYTES)?;
    if !(MINIMUM_ELEMENTS..=MAXIMUM_ELEMENTS).contains(&field.elements.len()) {
        return Err(format!(
            "field must contain {MINIMUM_ELEMENTS} through {MAXIMUM_ELEMENTS} elements"
        ));
    }
    if field.probe_policy.probe_count != PROBE_COUNT
        || field.probe_policy.minimum_support != MINIMUM_SUPPORT
    {
        return Err(format!(
            "probe policy must be exactly {PROBE_COUNT} probes with support {MINIMUM_SUPPORT}"
        ));
    }

    let mut ids = BTreeSet::new();
    for element in &field.elements {
        require_bounded_nonempty("element_id", &element.element_id, MAX_IDENTIFIER_BYTES)?;
        require_bounded_nonempty("content", &element.content, MAX_ELEMENT_CONTENT_BYTES)?;
        require_bounded_nonempty("source_ref", &element.source_ref, MAX_SOURCE_REF_BYTES)?;
        if !ids.insert(element.element_id.as_str()) {
            return Err(format!("duplicate element_id: {}", element.element_id));
        }
        let observed = sha256_hex(element.content.as_bytes());
        if element.content_sha256 != observed {
            return Err(format!(
                "content digest mismatch for {}: expected {observed}",
                element.element_id
            ));
        }
    }

    let mut boundary_ids = BTreeSet::new();
    for boundary in &field.boundaries {
        require_bounded_nonempty("boundary_id", &boundary.boundary_id, MAX_IDENTIFIER_BYTES)?;
        require_bounded_nonempty(
            "boundary reason",
            &boundary.reason,
            MAX_BOUNDARY_REASON_BYTES,
        )?;
        if !boundary_ids.insert(boundary.boundary_id.as_str()) {
            return Err(format!("duplicate boundary_id: {}", boundary.boundary_id));
        }
        if boundary.left_id == boundary.right_id {
            return Err(format!(
                "boundary {} must bind two distinct identities",
                boundary.boundary_id
            ));
        }
        for endpoint in [&boundary.left_id, &boundary.right_id] {
            if !ids.contains(endpoint.as_str()) {
                return Err(format!(
                    "boundary {} references unknown identity {endpoint}",
                    boundary.boundary_id
                ));
            }
        }
        match (boundary.kind, boundary.relation_kind) {
            (BoundaryKind::ForbidCoMembership, None) | (BoundaryKind::ForbidRelation, Some(_)) => {}
            (BoundaryKind::ForbidCoMembership, Some(_)) => {
                return Err(format!(
                    "boundary {} cannot name relation_kind for forbid_co_membership",
                    boundary.boundary_id
                ));
            }
            (BoundaryKind::ForbidRelation, None) => {
                return Err(format!(
                    "boundary {} requires relation_kind for forbid_relation",
                    boundary.boundary_id
                ));
            }
        }
    }

    let orders = probe_orders(field)?;
    let unique_orders: BTreeSet<_> = orders.iter().cloned().collect();
    if unique_orders.len() != PROBE_COUNT {
        return Err("probe order generator did not produce four unique orders".to_owned());
    }
    Ok(())
}

pub fn probe_orders(field: &SemanticField) -> Result<Vec<Vec<String>>, String> {
    if field.elements.len() < MINIMUM_ELEMENTS {
        return Err(format!("at least {MINIMUM_ELEMENTS} elements are required"));
    }
    let base: Vec<String> = field
        .elements
        .iter()
        .map(|element| element.element_id.clone())
        .collect();
    let mut reverse = base.clone();
    reverse.reverse();
    let mut rotate = base.clone();
    rotate.rotate_left(1);
    let mut interleave = Vec::with_capacity(base.len());
    interleave.extend(base.iter().step_by(2).cloned());
    interleave.extend(base.iter().skip(1).step_by(2).cloned());
    Ok(vec![base, reverse, rotate, interleave])
}

pub fn admit_probe(
    field: &SemanticField,
    probe_index: usize,
    proposal: ProbeProposal,
) -> Result<FieldProbe, String> {
    validate_field(field)?;
    let orders = probe_orders(field)?;
    let order = orders
        .get(probe_index)
        .ok_or_else(|| format!("probe index {probe_index} is outside 0..{PROBE_COUNT}"))?
        .clone();
    require_nonempty("pattern", &proposal.pattern)?;
    if proposal.candidate_member_ids.len() < 2 {
        return Err("probe candidate must contain at least two identities".to_owned());
    }
    let admitted = field_ids(field);
    let mut candidate_ids = BTreeSet::new();
    for member in &proposal.candidate_member_ids {
        if !admitted.contains(member) {
            return Err(format!("probe references unknown identity {member}"));
        }
        if !candidate_ids.insert(member.clone()) {
            return Err(format!("probe repeats candidate identity {member}"));
        }
    }
    Ok(FieldProbe {
        probe_id: format!("probe-{}", probe_index + 1),
        order,
        candidate_member_ids: proposal.candidate_member_ids,
        pattern: proposal.pattern,
        tensions: proposal.tensions,
        exclusions: proposal.exclusions,
        uncertainty: proposal.uncertainty,
    })
}

pub fn validate_probe_set(field: &SemanticField, probes: &[FieldProbe]) -> Result<(), String> {
    validate_field(field)?;
    if probes.len() != PROBE_COUNT {
        return Err(format!("expected exactly {PROBE_COUNT} probes"));
    }
    let orders = probe_orders(field)?;
    let mut probe_ids = BTreeSet::new();
    for (index, probe) in probes.iter().enumerate() {
        if !probe_ids.insert(probe.probe_id.as_str()) {
            return Err(format!("duplicate probe_id: {}", probe.probe_id));
        }
        if probe.order != orders[index] {
            return Err(format!("{} does not use declared order", probe.probe_id));
        }
        let readmitted = admit_probe(
            field,
            index,
            ProbeProposal {
                candidate_member_ids: probe.candidate_member_ids.clone(),
                pattern: probe.pattern.clone(),
                tensions: probe.tensions.clone(),
                exclusions: probe.exclusions.clone(),
                uncertainty: probe.uncertainty.clone(),
            },
        )?;
        if readmitted != *probe {
            return Err(format!("{} is not canonical", probe.probe_id));
        }
    }
    Ok(())
}

pub fn aggregate_candidate(
    field: &SemanticField,
    probes: &[FieldProbe],
) -> Result<GestaltCandidate, String> {
    validate_probe_set(field, probes)?;
    let mut groups: BTreeMap<Vec<String>, Vec<&FieldProbe>> = BTreeMap::new();
    for probe in probes {
        let mut key = probe.candidate_member_ids.clone();
        key.sort();
        groups.entry(key).or_default().push(probe);
    }
    let (member_ids, supporters) = groups
        .into_iter()
        .filter(|(_, supporting)| supporting.len() >= MINIMUM_SUPPORT)
        .max_by(|(left_ids, left), (right_ids, right)| {
            left.len()
                .cmp(&right.len())
                .then_with(|| right_ids.cmp(left_ids))
        })
        .ok_or_else(|| {
            format!("no exact member set reached {MINIMUM_SUPPORT}-of-{PROBE_COUNT} support")
        })?;

    if violates_co_membership(field, &member_ids) {
        return Err("candidate violates forbid_co_membership boundary".to_owned());
    }

    let field_digest = canonical_digest(field)?;
    let purpose_digest = sha256_hex(field.purpose.as_bytes());
    let candidate_id = sha256_hex(
        [
            CYCLE_PROFILE.to_owned(),
            field_digest.clone(),
            purpose_digest,
            member_ids.join("\u{1f}"),
        ]
        .join("\0")
        .as_bytes(),
    );
    let mut supporting_probe_ids: Vec<String> = supporters
        .iter()
        .map(|probe| probe.probe_id.clone())
        .collect();
    supporting_probe_ids.sort();
    let representative_pattern = supporters
        .iter()
        .map(|probe| probe.pattern.as_str())
        .min()
        .unwrap_or_default()
        .to_owned();

    Ok(GestaltCandidate {
        candidate_id,
        field_digest,
        member_ids,
        support_count: supporters.len(),
        probe_count: probes.len(),
        supporting_probe_ids,
        status: CandidateStatus::Provisional,
        representative_pattern,
    })
}

pub fn validate_delineation(
    field: &SemanticField,
    candidate: &GestaltCandidate,
    proposal: &DelineationProposal,
) -> DelineationResult {
    let candidate_ids: BTreeSet<String> = candidate.member_ids.iter().cloned().collect();
    let mut faults = BTreeSet::new();

    if proposal.account.trim().is_empty() {
        faults.insert(GateFault::MissingAccount);
    }

    if proposal.candidate_id != candidate.candidate_id {
        faults.insert(GateFault::CandidateIdMismatch);
    }
    match proposal.status {
        DelineationStatus::Supported => {}
        DelineationStatus::Rejected => {
            faults.insert(GateFault::ProposalRejected);
        }
        DelineationStatus::Unresolved => {
            faults.insert(GateFault::ProposalUnresolved);
        }
    }

    let admitted = field_ids(field);
    let mut binding_inputs = BTreeSet::new();
    for binding in &proposal.identity_bindings {
        if !admitted.contains(&binding.input_id) || !admitted.contains(&binding.output_id) {
            faults.insert(GateFault::UnknownIdentity);
        }
        if !binding_inputs.insert(binding.input_id.clone()) {
            faults.insert(GateFault::DuplicateIdentityBinding);
        }
        if binding.input_id != binding.output_id {
            faults.insert(GateFault::IdentityRemap);
        }
    }
    if binding_inputs != candidate_ids {
        faults.insert(GateFault::IncompleteIdentityBindings);
    }

    let mut unique_relations = BTreeSet::new();
    let mut covered = BTreeSet::new();
    let mut adjacency: BTreeMap<String, BTreeSet<String>> = candidate_ids
        .iter()
        .cloned()
        .map(|id| (id, BTreeSet::new()))
        .collect();
    for relation in &proposal.relations {
        if relation.account.trim().is_empty() {
            faults.insert(GateFault::MissingAccount);
        }
        if !candidate_ids.contains(&relation.source_id)
            || !candidate_ids.contains(&relation.target_id)
        {
            faults.insert(GateFault::UnknownRelationEndpoint);
            continue;
        }
        if relation.source_id == relation.target_id {
            faults.insert(GateFault::SelfRelation);
            continue;
        }
        let key = (
            relation.source_id.clone(),
            relation.kind,
            relation.target_id.clone(),
        );
        if !unique_relations.insert(key) {
            faults.insert(GateFault::DuplicateRelation);
        }
        if violates_relation_boundary(field, relation) {
            faults.insert(GateFault::BoundaryConflict);
        }
        covered.insert(relation.source_id.clone());
        covered.insert(relation.target_id.clone());
        adjacency
            .get_mut(&relation.source_id)
            .expect("candidate endpoint was checked")
            .insert(relation.target_id.clone());
        adjacency
            .get_mut(&relation.target_id)
            .expect("candidate endpoint was checked")
            .insert(relation.source_id.clone());
    }
    if covered != candidate_ids {
        faults.insert(GateFault::IncompleteRelationCoverage);
    }
    if !is_connected(&candidate_ids, &adjacency) {
        faults.insert(GateFault::DisconnectedSupport);
    }
    if violates_co_membership(field, &candidate.member_ids) {
        faults.insert(GateFault::BoundaryConflict);
    }
    if !proposal.contradictions.is_empty() {
        faults.insert(GateFault::ContradictionPresent);
    }
    for excluded in &proposal.excluded_member_ids {
        if candidate_ids.contains(excluded) {
            faults.insert(GateFault::ExcludedCandidateMember);
        } else {
            faults.insert(GateFault::UnknownIdentity);
        }
    }
    if !proposal.uncertainty.is_empty() {
        faults.insert(GateFault::UncertaintyPresent);
    }

    let identity_preserved = !faults.contains(&GateFault::UnknownIdentity)
        && !faults.contains(&GateFault::IncompleteIdentityBindings)
        && !faults.contains(&GateFault::DuplicateIdentityBinding)
        && !faults.contains(&GateFault::IdentityRemap);
    let boundary_preserved = !faults.contains(&GateFault::BoundaryConflict);
    let support_connected = !faults.contains(&GateFault::UnknownRelationEndpoint)
        && !faults.contains(&GateFault::SelfRelation)
        && !faults.contains(&GateFault::DuplicateRelation)
        && !faults.contains(&GateFault::IncompleteRelationCoverage)
        && !faults.contains(&GateFault::DisconnectedSupport);
    let contradiction_free = !faults.contains(&GateFault::ContradictionPresent);
    let uncertainty_free = !faults.contains(&GateFault::ProposalUnresolved)
        && !faults.contains(&GateFault::UncertaintyPresent);
    let status = if faults.is_empty() {
        DelineationStatus::Supported
    } else if matches!(proposal.status, DelineationStatus::Unresolved)
        || faults.contains(&GateFault::UncertaintyPresent)
    {
        DelineationStatus::Unresolved
    } else {
        DelineationStatus::Rejected
    };

    DelineationResult {
        status,
        identity_preserved,
        boundary_preserved,
        support_connected,
        contradiction_free,
        uncertainty_free,
        failed_gates: faults.into_iter().collect(),
    }
}

pub fn latch(
    field: &SemanticField,
    candidate: &GestaltCandidate,
    delineation: &DelineationResult,
) -> LatchDecision {
    let mut failed: BTreeSet<GateFault> = delineation.failed_gates.iter().cloned().collect();
    if candidate.status != CandidateStatus::Provisional {
        failed.insert(GateFault::CandidateNotProvisional);
    }
    if candidate.support_count < MINIMUM_SUPPORT || candidate.probe_count != PROBE_COUNT {
        failed.insert(GateFault::InsufficientProbeSupport);
    }
    let admitted = failed.is_empty() && delineation.status == DelineationStatus::Supported;
    LatchDecision {
        profile: CYCLE_PROFILE.to_owned(),
        field_id: field.field_id.clone(),
        field_digest: candidate.field_digest.clone(),
        candidate_id: candidate.candidate_id.clone(),
        status: if admitted {
            LatchStatus::AdmittedForAttention
        } else {
            LatchStatus::Rejected
        },
        failed_gates: failed.into_iter().collect(),
        proof_refs: candidate.supporting_probe_ids.clone(),
        semantic_scope: field.purpose.clone(),
    }
}

pub fn control_observation(probe: FieldProbe) -> ControlObservation {
    ControlObservation {
        probe,
        latch_eligible: false,
        terminal_state: CycleState::ControlCompleted,
    }
}

pub fn sanitize(value: &Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .iter()
                .filter(|(key, _)| {
                    !matches!(
                        key.as_str(),
                        "reasoning" | "reasoning_content" | "thinking" | "chain_of_thought"
                    )
                })
                .map(|(key, value)| (key.clone(), sanitize(value)))
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.iter().map(sanitize).collect()),
        scalar => scalar.clone(),
    }
}

pub fn field_request(
    model: &str,
    field: &SemanticField,
    probe_index: usize,
) -> Result<Value, String> {
    field_request_for_profile(CURRENT_REQUEST_PROFILE, model, field, probe_index)
}

fn field_request_for_profile(
    request_profile: &str,
    model: &str,
    field: &SemanticField,
    probe_index: usize,
) -> Result<Value, String> {
    require_bounded_nonempty("provider model", model, MAX_PROVIDER_MODEL_BYTES)?;
    validate_field(field)?;
    let order = probe_orders(field)?
        .get(probe_index)
        .cloned()
        .ok_or_else(|| format!("probe index {probe_index} is outside 0..{PROBE_COUNT}"))?;
    let by_id: BTreeMap<&str, &FieldElement> = field
        .elements
        .iter()
        .map(|element| (element.element_id.as_str(), element))
        .collect();
    let elements: Vec<Value> = order
        .iter()
        .map(|id| {
            let element = by_id
                .get(id.as_str())
                .expect("order is derived from admitted elements");
            serde_json::json!({
                "element_id": element.element_id,
                "kind": element.kind,
                "content": element.content,
                "source_ref": element.source_ref
            })
        })
        .collect();
    let input = serde_json::json!({
        "field_id": field.field_id,
        "subject": field.subject,
        "purpose": field.purpose,
        "presentation_order": order,
        "elements": elements,
        "hard_boundaries": field.boundaries
    });
    let (instruction, schema) = match request_profile {
        REQUEST_PROFILE_V1 => (
            "Run one FIELD_ATTEND proposal over the complete supplied field. Treat every element_id as immutable. Do not decide truth, authorization, or admission. Select the smallest member set whose whole-field relation appears useful for the stated purpose. Return only the required JSON object. Use only supplied IDs. State tensions, exclusions, and uncertainty rather than repairing them silently.",
            probe_schema_v1(field),
        ),
        REQUEST_PROFILE_V2 => (
            "Run one FIELD_ATTEND proposal over the complete supplied field. Treat every element_id as immutable. Do not decide truth, authorization, or admission. Select the smallest member set whose whole-field relation appears useful for the stated purpose. Return only the required JSON object. Use only supplied IDs. State a tension, exclusion, or uncertainty only when the supplied field gives a concrete reason for it; otherwise return an empty array. Never invent or repeat filler tokens, labels, or placeholders.",
            probe_schema(field),
        ),
        REQUEST_PROFILE_V3 => (
            "Run one typed FIELD_ATTEND selection over the complete supplied field. Treat every element_id as immutable. Select the smallest member set whose whole-field relation appears useful for the stated purpose. Classify the selection as coherent, uncertain, conflicted, or excludes. For coherent, flagged_member_ids must be empty. For every other assessment, flagged_member_ids must contain the supplied IDs that cause that assessment. Use supplied IDs only. Return only the required JSON object. Do not decide truth, authorization, or admission; the host compiles and validates the proposal.",
            typed_probe_schema_v3(field),
        ),
        REQUEST_PROFILE_V4 => (
            "Run one typed FIELD_ATTEND selection over the complete supplied field. Treat every element_id as immutable. Select the smallest member set whose whole-field relation appears useful for the stated purpose, listing each selected ID at most once. Classify the selection as coherent, uncertain, conflicted, or excludes. For coherent, flagged_member_ids must be empty. For every other assessment, flagged_member_ids must contain each supplied ID causing that assessment at most once. Use supplied IDs only. Return only the required JSON object. Do not decide truth, authorization, or admission; the host compiles and validates the proposal.",
            typed_probe_schema(field),
        ),
        REQUEST_PROFILE_V5 => (
            "Run one typed FIELD_ATTEND selection over the complete supplied field. Treat every element_id as immutable. Select the smallest member set whose whole-field relation appears useful for the stated purpose, listing each selected ID at most once. Classify the selection as coherent, uncertain, conflicted, or excludes. flagged_member_ids may identify specific supplied IDs causing a non-coherent assessment; leave it empty when the assessment applies only to the selection as a whole. For coherent it must be empty. Use supplied IDs only. Return only the required JSON object. Do not decide truth, authorization, or admission; the host compiles and validates the proposal.",
            typed_probe_schema(field),
        ),
        other => return Err(format!("unsupported request profile: {other}")),
    };
    Ok(serde_json::json!({
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": instruction
            },
            {
                "role": "user",
                "content": serde_json::to_string(&input).expect("JSON value serializes")
            }
        ],
        "response_format": {
            "type": "json_object",
            "schema": schema
        },
        "chat_template_kwargs": {"enable_thinking": false},
        "temperature": 0,
        "seed": 7000 + probe_index,
        "max_tokens": 512
    }))
}

pub fn delineation_request(
    model: &str,
    field: &SemanticField,
    candidate: &GestaltCandidate,
) -> Result<Value, String> {
    delineation_request_for_profile(CURRENT_REQUEST_PROFILE, model, field, candidate)
}

fn delineation_request_for_profile(
    request_profile: &str,
    model: &str,
    field: &SemanticField,
    candidate: &GestaltCandidate,
) -> Result<Value, String> {
    validate_field(field)?;
    let admitted = field_ids(field);
    if candidate.member_ids.iter().any(|id| !admitted.contains(id)) {
        return Err("candidate contains identity outside field".to_owned());
    }
    let by_id: BTreeMap<&str, &FieldElement> = field
        .elements
        .iter()
        .map(|element| (element.element_id.as_str(), element))
        .collect();
    let elements: Vec<Value> = candidate
        .member_ids
        .iter()
        .map(|id| {
            let element = by_id
                .get(id.as_str())
                .expect("candidate identity was checked");
            serde_json::json!({
                "element_id": element.element_id,
                "kind": element.kind,
                "content": element.content,
                "source_ref": element.source_ref
            })
        })
        .collect();
    let input = serde_json::json!({
        "field_id": field.field_id,
        "subject": field.subject,
        "purpose": field.purpose,
        "candidate": candidate,
        "candidate_elements": elements,
        "hard_boundaries": field.boundaries
    });
    let (instruction, schema) = match request_profile {
        REQUEST_PROFILE_V1 => (
            "Run a separate DELINEATE pass over the supplied provisional candidate. Preserve every identity by mapping each input_id to the identical output_id exactly once. Express support as explicit typed directed relations using only the candidate IDs and the allowed relation kinds. A supported result must connect every member. Report contradictions, exclusions, and uncertainty honestly. Return only the required JSON object. This is not a truth or authorization decision; the host will validate it.",
            delineation_schema_v1(candidate),
        ),
        REQUEST_PROFILE_V2 => (
            "Run a separate DELINEATE pass over the supplied provisional candidate. Preserve every identity by mapping each input_id to the identical output_id exactly once. Express support as explicit typed directed relations using only the candidate IDs and allowed relation kinds. Each account must explain that specific relation from supplied content. A supported result must connect every member. State a contradiction, exclusion, or uncertainty only when the supplied material gives a concrete reason for it; otherwise return an empty array. Never invent or repeat filler tokens, labels, or placeholders. Return only the required JSON object. This is not a truth or authorization decision; the host will validate it.",
            delineation_schema(candidate),
        ),
        REQUEST_PROFILE_V3 => (
            "Run a separate typed DELINEATE pass over the supplied provisional candidate. Return every candidate ID exactly once in ordered_member_ids. The host will compile adjacent IDs into a connected directed chain, so return exactly one fewer relation_kinds than ordered IDs and choose each kind for the corresponding adjacent pair. Mark supported only when the supplied content supports that typed chain. Put only supplied candidate IDs in contradiction_member_ids, excluded_member_ids, or uncertain_member_ids; use empty arrays when none. Return only the required JSON object. This is not a truth or authorization decision; the host compiles identity bindings and validates every boundary and latch gate.",
            typed_delineation_schema(candidate),
        ),
        REQUEST_PROFILE_V4 => (
            "Run a separate typed DELINEATE pass over the supplied provisional candidate. Return every candidate ID exactly once in ordered_member_ids. The host will compile adjacent IDs into a connected directed chain, so return exactly one fewer relation_kinds than ordered IDs and choose each kind for the corresponding adjacent pair. Mark supported only when the supplied content supports that typed chain. Put only supplied candidate IDs in contradiction_member_ids, excluded_member_ids, or uncertain_member_ids; use empty arrays when none. Return only the required JSON object. This is not a truth or authorization decision; the host compiles identity bindings and validates every boundary and latch gate.",
            typed_delineation_schema(candidate),
        ),
        REQUEST_PROFILE_V5 => (
            "Run a separate typed DELINEATE pass over the supplied provisional candidate. Return every candidate ID exactly once in ordered_member_ids. The host will compile adjacent IDs into a connected directed chain, so return exactly one fewer relation_kinds than ordered IDs and choose each kind for the corresponding adjacent pair. Mark supported only when the supplied content supports that typed chain. Put only supplied candidate IDs in contradiction_member_ids, excluded_member_ids, or uncertain_member_ids; use empty arrays when none. Return only the required JSON object. This is not a truth or authorization decision; the host compiles identity bindings and validates every boundary and latch gate.",
            typed_delineation_schema(candidate),
        ),
        other => return Err(format!("unsupported request profile: {other}")),
    };
    Ok(serde_json::json!({
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": instruction
            },
            {
                "role": "user",
                "content": serde_json::to_string(&input).expect("JSON value serializes")
            }
        ],
        "response_format": {
            "type": "json_object",
            "schema": schema
        },
        "chat_template_kwargs": {"enable_thinking": false},
        "temperature": 0,
        "seed": 8000,
        "max_tokens": 1024
    }))
}

pub fn parse_provider_content<T: for<'de> Deserialize<'de>>(response: &Value) -> Result<T, String> {
    let choices = response
        .get("choices")
        .and_then(Value::as_array)
        .ok_or("provider response omitted choices array")?;
    if choices.len() != 1 {
        return Err(format!(
            "provider response must contain exactly one choice, observed {}",
            choices.len()
        ));
    }
    let choice = &choices[0];
    if choice.get("finish_reason").and_then(Value::as_str) != Some("stop") {
        return Err("provider response did not finish with stop".to_owned());
    }
    let content = choice
        .pointer("/message/content")
        .ok_or("provider response omitted choices[0].message.content")?;
    let value = match content {
        Value::String(encoded) => serde_json::from_str(encoded)
            .map_err(|error| format!("provider content is not JSON: {error}"))?,
        Value::Object(_) => content.clone(),
        _ => return Err("provider content is neither encoded JSON nor an object".to_owned()),
    };
    serde_json::from_value(value)
        .map_err(|error| format!("provider content violates closed schema: {error}"))
}

pub fn parse_probe_response(
    request_profile: &str,
    field: &SemanticField,
    response: &Value,
) -> Result<ProbeProposal, String> {
    match request_profile {
        REQUEST_PROFILE_V1 | REQUEST_PROFILE_V2 => parse_provider_content(response),
        REQUEST_PROFILE_V3 | REQUEST_PROFILE_V4 => {
            let typed: TypedProbeProposal = parse_provider_content(response)?;
            compile_typed_probe(field, typed, true)
        }
        REQUEST_PROFILE_V5 => {
            let typed: TypedProbeProposal = parse_provider_content(response)?;
            compile_typed_probe(field, typed, false)
        }
        other => Err(format!("unsupported request profile: {other}")),
    }
}

pub fn parse_delineation_response(
    request_profile: &str,
    candidate: &GestaltCandidate,
    response: &Value,
) -> Result<DelineationProposal, String> {
    match request_profile {
        REQUEST_PROFILE_V1 | REQUEST_PROFILE_V2 => parse_provider_content(response),
        REQUEST_PROFILE_V3 | REQUEST_PROFILE_V4 | REQUEST_PROFILE_V5 => {
            let typed: TypedDelineationProposal = parse_provider_content(response)?;
            compile_typed_delineation(candidate, typed)
        }
        other => Err(format!("unsupported request profile: {other}")),
    }
}

fn compile_typed_probe(
    field: &SemanticField,
    typed: TypedProbeProposal,
    require_attributed_noncoherence: bool,
) -> Result<ProbeProposal, String> {
    let admitted = field_ids(field);
    if typed
        .candidate_member_ids
        .iter()
        .chain(typed.flagged_member_ids.iter())
        .any(|id| !admitted.contains(id))
    {
        return Err("typed probe references identity outside supplied field".to_owned());
    }
    let flags: BTreeSet<&str> = typed
        .flagged_member_ids
        .iter()
        .map(String::as_str)
        .collect();
    if flags.len() != typed.flagged_member_ids.len() {
        return Err("typed probe repeats a flagged identity".to_owned());
    }
    match typed.assessment {
        FieldAssessment::Coherent if !typed.flagged_member_ids.is_empty() => {
            return Err("coherent typed probe must not flag identities".to_owned());
        }
        FieldAssessment::Coherent => {}
        _ if require_attributed_noncoherence && typed.flagged_member_ids.is_empty() => {
            return Err("non-coherent typed probe must flag at least one identity".to_owned());
        }
        _ => {}
    }
    let assessment = match typed.assessment {
        FieldAssessment::Coherent => "coherent",
        FieldAssessment::Uncertain => "uncertain",
        FieldAssessment::Conflicted => "conflicted",
        FieldAssessment::Excludes => "excludes",
    };
    let flagged: Vec<String> =
        if typed.flagged_member_ids.is_empty() && typed.assessment != FieldAssessment::Coherent {
            vec![format!(
                "typed assessment marks the whole proposal {assessment} without member attribution"
            )]
        } else {
            typed
                .flagged_member_ids
                .iter()
                .map(|id| format!("typed assessment flagged candidate identity {id}"))
                .collect()
        };
    Ok(ProbeProposal {
        pattern: format!(
            "{assessment} typed field proposal over [{}]",
            typed.candidate_member_ids.join(",")
        ),
        candidate_member_ids: typed.candidate_member_ids,
        tensions: if typed.assessment == FieldAssessment::Conflicted {
            flagged.clone()
        } else {
            Vec::new()
        },
        exclusions: if typed.assessment == FieldAssessment::Excludes {
            flagged.clone()
        } else {
            Vec::new()
        },
        uncertainty: if typed.assessment == FieldAssessment::Uncertain {
            flagged
        } else {
            Vec::new()
        },
    })
}

fn compile_typed_delineation(
    candidate: &GestaltCandidate,
    typed: TypedDelineationProposal,
) -> Result<DelineationProposal, String> {
    if typed.candidate_id != candidate.candidate_id {
        return Err("typed delineation candidate_id mismatch".to_owned());
    }
    let expected: BTreeSet<&str> = candidate.member_ids.iter().map(String::as_str).collect();
    let ordered: BTreeSet<&str> = typed
        .ordered_member_ids
        .iter()
        .map(String::as_str)
        .collect();
    if typed.ordered_member_ids.len() != candidate.member_ids.len() || ordered != expected {
        return Err(
            "typed delineation must order every candidate identity exactly once".to_owned(),
        );
    }
    if typed.relation_kinds.len() + 1 != typed.ordered_member_ids.len() {
        return Err(
            "typed delineation requires exactly one relation kind per adjacent pair".to_owned(),
        );
    }
    for (label, ids) in [
        ("contradiction", &typed.contradiction_member_ids),
        ("excluded", &typed.excluded_member_ids),
        ("uncertain", &typed.uncertain_member_ids),
    ] {
        let unique: BTreeSet<&str> = ids.iter().map(String::as_str).collect();
        if unique.len() != ids.len() || unique.iter().any(|id| !expected.contains(*id)) {
            return Err(format!(
                "typed delineation {label} identities must be unique candidate IDs"
            ));
        }
    }
    let relations: Vec<RelationEdge> = typed
        .ordered_member_ids
        .windows(2)
        .zip(typed.relation_kinds.iter())
        .map(|(pair, kind)| RelationEdge {
            source_id: pair[0].clone(),
            kind: *kind,
            target_id: pair[1].clone(),
            account: format!(
                "typed {} edge binds supplied identities {} and {}",
                relation_kind_label(*kind),
                pair[0],
                pair[1]
            ),
        })
        .collect();
    Ok(DelineationProposal {
        candidate_id: typed.candidate_id,
        status: typed.status,
        identity_bindings: candidate
            .member_ids
            .iter()
            .map(|id| IdentityBinding {
                input_id: id.clone(),
                output_id: id.clone(),
            })
            .collect(),
        relations,
        contradictions: typed
            .contradiction_member_ids
            .iter()
            .map(|id| format!("typed delineation marks candidate identity {id} contradictory"))
            .collect(),
        excluded_member_ids: typed.excluded_member_ids,
        uncertainty: typed
            .uncertain_member_ids
            .iter()
            .map(|id| format!("typed delineation marks candidate identity {id} uncertain"))
            .collect(),
        account: format!(
            "typed delineation compiled {} supplied identities into {} connected edges",
            typed.ordered_member_ids.len(),
            typed.relation_kinds.len()
        ),
    })
}

fn relation_kind_label(kind: RelationKind) -> &'static str {
    match kind {
        RelationKind::Supports => "supports",
        RelationKind::Complements => "complements",
        RelationKind::Contrasts => "contrasts",
        RelationKind::Constrains => "constrains",
        RelationKind::DependsOn => "depends_on",
        RelationKind::Contextualizes => "contextualizes",
    }
}

pub fn provider_exchange(
    stage: impl Into<String>,
    request: Value,
    response: Value,
) -> Result<ProviderExchange, String> {
    let request = sanitize(&request);
    let response = sanitize(&response);
    Ok(ProviderExchange {
        stage: stage.into(),
        request_sha256: canonical_digest(&request)?,
        response_sha256: canonical_digest(&response)?,
        request,
        response,
    })
}

pub fn verify_report(report: &CycleReport) -> Result<ReportVerification, String> {
    if report.profile != CYCLE_PROFILE {
        return Err(format!("unsupported report profile: {}", report.profile));
    }
    validate_report_identity(report)?;
    validate_field(&report.field)?;
    let field_digest = canonical_digest(&report.field)?;
    if report.field_digest != field_digest {
        return Err("report field_digest does not match field".to_owned());
    }
    let deterministic_fixture = report.provider.base_url == "fixture://local"
        && report.provider.model == "deterministic-contract-fixture";
    verify_events(&report.events, report.terminal_state, deterministic_fixture)?;
    for exchange in &report.exchanges {
        if canonical_digest(&exchange.request)? != exchange.request_sha256 {
            return Err(format!("{} request digest mismatch", exchange.stage));
        }
        if canonical_digest(&exchange.response)? != exchange.response_sha256 {
            return Err(format!("{} response digest mismatch", exchange.stage));
        }
        if sanitize(&exchange.request) != exchange.request
            || sanitize(&exchange.response) != exchange.response
        {
            return Err(format!(
                "{} contains private reasoning fields",
                exchange.stage
            ));
        }
        if exchange.request.get("model").and_then(Value::as_str)
            != Some(report.provider.model.as_str())
        {
            return Err(format!(
                "{} request model does not match provider identity",
                exchange.stage
            ));
        }
        if exchange.response.get("model").is_some()
            && exchange.response.get("model").and_then(Value::as_str)
                != Some(report.provider.model.as_str())
        {
            return Err(format!(
                "{} response model does not match provider identity",
                exchange.stage
            ));
        }
    }

    if report.terminal_state == CycleState::Faulted {
        if deterministic_fixture {
            return Err("fault report cannot claim deterministic fixture provider".to_owned());
        }
        verify_fault_report(report)?;
        let encoded = serde_json::to_vec(report)
            .map_err(|error| format!("report serialization failed: {error}"))?;
        return Ok(ReportVerification {
            valid: true,
            terminal_state: CycleState::Faulted,
            latch_status: None,
            exchange_count: report.exchanges.len(),
            report_sha256: sha256_hex(encoded),
        });
    }
    if report.terminal_state == CycleState::ControlCompleted {
        if deterministic_fixture {
            return Err("control report cannot claim deterministic fixture provider".to_owned());
        }
        verify_control_report(report)?;
        let encoded = serde_json::to_vec(report)
            .map_err(|error| format!("report serialization failed: {error}"))?;
        return Ok(ReportVerification {
            valid: true,
            terminal_state: CycleState::ControlCompleted,
            latch_status: None,
            exchange_count: report.exchanges.len(),
            report_sha256: sha256_hex(encoded),
        });
    }
    if deterministic_fixture {
        if !report.exchanges.is_empty() {
            return Err("deterministic fixture must not contain provider exchanges".to_owned());
        }
        let expected_fixture = fixture_report(report.field.clone())?;
        if *report != expected_fixture {
            return Err(
                "deterministic fixture does not match its canonical construction".to_owned(),
            );
        }
    } else {
        verify_probe_exchange_lineage(report)?;
    }

    let expected_candidate = aggregate_candidate(&report.field, &report.probes);
    match (&report.candidate, expected_candidate) {
        (Some(candidate), Ok(expected)) if *candidate == expected => {
            let proposal = report
                .delineation_proposal
                .as_ref()
                .ok_or("report with candidate omitted delineation_proposal")?;
            if !deterministic_fixture {
                verify_delineation_exchange_lineage(report, candidate, proposal)?;
            }
            let expected_result = validate_delineation(&report.field, candidate, proposal);
            if report.delineation_result.as_ref() != Some(&expected_result) {
                return Err("report delineation_result does not recompute".to_owned());
            }
            let expected_latch = latch(&report.field, candidate, &expected_result);
            if report.latch_decision.as_ref() != Some(&expected_latch) {
                return Err("report latch_decision does not recompute".to_owned());
            }
            let expected_terminal = if expected_latch.status == LatchStatus::AdmittedForAttention {
                CycleState::Completed
            } else {
                CycleState::Rejected
            };
            if report.terminal_state != expected_terminal {
                return Err("terminal state disagrees with latch decision".to_owned());
            }
            if report.fault.is_some() {
                return Err("completed or rejected report must not contain fault".to_owned());
            }
        }
        (Some(_), Ok(_)) => return Err("report candidate does not recompute".to_owned()),
        (None, Err(expected_fault)) => {
            if !deterministic_fixture && report.exchanges.len() != PROBE_COUNT {
                return Err(format!(
                    "non-convergent live report must contain exactly {PROBE_COUNT} probe exchanges"
                ));
            }
            if report.terminal_state != CycleState::Rejected {
                return Err("non-convergent report must terminate rejected".to_owned());
            }
            if report.fault.as_deref() != Some(expected_fault.as_str()) {
                return Err("non-convergent report fault does not recompute".to_owned());
            }
            if report.delineation_proposal.is_some()
                || report.delineation_result.is_some()
                || report.latch_decision.is_some()
            {
                return Err("non-convergent report contains post-aggregation records".to_owned());
            }
        }
        (None, Ok(_)) => return Err("report omitted a recomputable candidate".to_owned()),
        (Some(_), Err(_)) => return Err("report contains candidate for rejected probes".to_owned()),
    }
    let encoded = serde_json::to_vec(report)
        .map_err(|error| format!("report serialization failed: {error}"))?;
    Ok(ReportVerification {
        valid: true,
        terminal_state: report.terminal_state,
        latch_status: report
            .latch_decision
            .as_ref()
            .map(|decision| decision.status),
        exchange_count: report.exchanges.len(),
        report_sha256: sha256_hex(encoded),
    })
}

fn validate_report_identity(report: &CycleReport) -> Result<(), String> {
    require_bounded_nonempty("run_id", &report.run_id, MAX_IDENTIFIER_BYTES)?;
    require_bounded_nonempty(
        "provider model",
        &report.provider.model,
        MAX_PROVIDER_MODEL_BYTES,
    )?;
    if !matches!(
        report.request_profile.as_str(),
        REQUEST_PROFILE_V1
            | REQUEST_PROFILE_V2
            | REQUEST_PROFILE_V3
            | REQUEST_PROFILE_V4
            | REQUEST_PROFILE_V5
    ) {
        return Err(format!(
            "unsupported request profile: {}",
            report.request_profile
        ));
    }
    let deterministic_fixture = report.provider.base_url == "fixture://local"
        && report.provider.model == "deterministic-contract-fixture";
    if !deterministic_fixture {
        let normalized = normalize_loopback_base_url(&report.provider.base_url)?;
        if normalized != report.provider.base_url {
            return Err("provider base_url is not in canonical form".to_owned());
        }
    }
    Ok(())
}

pub fn fixture_report(field: SemanticField) -> Result<CycleReport, String> {
    validate_field(&field)?;
    let field_digest = canonical_digest(&field)?;
    let all_ids: Vec<String> = field
        .elements
        .iter()
        .map(|element| element.element_id.clone())
        .collect();
    if violates_co_membership(&field, &all_ids) {
        return Err("fixture field forbids full candidate membership".to_owned());
    }
    let probes: Vec<FieldProbe> = (0..PROBE_COUNT)
        .map(|probe_index| {
            admit_probe(
                &field,
                probe_index,
                ProbeProposal {
                    candidate_member_ids: all_ids.clone(),
                    pattern: "Field proposal, explicit delineation, and host latch form one attention-local cycle."
                        .to_owned(),
                    tensions: vec![
                        "Model agreement remains correlated evidence rather than truth.".to_owned(),
                    ],
                    exclusions: Vec::new(),
                    uncertainty: Vec::new(),
                },
            )
        })
        .collect::<Result<_, _>>()?;
    let candidate = aggregate_candidate(&field, &probes)?;
    let proposal = DelineationProposal {
        candidate_id: candidate.candidate_id.clone(),
        status: DelineationStatus::Supported,
        identity_bindings: candidate
            .member_ids
            .iter()
            .map(|id| IdentityBinding {
                input_id: id.clone(),
                output_id: id.clone(),
            })
            .collect(),
        relations: candidate
            .member_ids
            .windows(2)
            .map(|pair| RelationEdge {
                source_id: pair[0].clone(),
                kind: RelationKind::Supports,
                target_id: pair[1].clone(),
                account: "Deterministic fixture edge preserves identity and connected coverage."
                    .to_owned(),
            })
            .collect(),
        contradictions: Vec::new(),
        excluded_member_ids: Vec::new(),
        uncertainty: Vec::new(),
        account: "Every candidate identity is preserved and the explicit support projection is connected."
            .to_owned(),
    };
    let result = validate_delineation(&field, &candidate, &proposal);
    let decision = latch(&field, &candidate, &result);
    if decision.status != LatchStatus::AdmittedForAttention {
        return Err(format!(
            "deterministic fixture failed latch gates: {:?}",
            decision.failed_gates
        ));
    }
    let states = [
        CycleState::Created,
        CycleState::FieldValidated,
        CycleState::ProbesRequested,
        CycleState::ProbesCollected,
        CycleState::CandidateAggregated,
        CycleState::DelineationRequested,
        CycleState::DelineationCollected,
        CycleState::LatchEvaluated,
        CycleState::Completed,
    ];
    let events = states
        .into_iter()
        .enumerate()
        .map(|(index, state)| CycleEvent {
            ordinal: index + 1,
            state,
            evidence_ref: format!("fixture-event-{}", index + 1),
        })
        .collect();
    Ok(CycleReport {
        profile: CYCLE_PROFILE.to_owned(),
        request_profile: REQUEST_PROFILE_V1.to_owned(),
        run_id: format!("fixture-{field_digest}"),
        provider: ProviderIdentity {
            base_url: "fixture://local".to_owned(),
            model: "deterministic-contract-fixture".to_owned(),
        },
        field,
        field_digest,
        events,
        exchanges: Vec::new(),
        probes,
        candidate: Some(candidate),
        delineation_proposal: Some(proposal),
        delineation_result: Some(result),
        latch_decision: Some(decision),
        terminal_state: CycleState::Completed,
        fault: None,
    })
}

fn probe_schema(field: &SemanticField) -> Value {
    let ids: Vec<&str> = field
        .elements
        .iter()
        .map(|element| element.element_id.as_str())
        .collect();
    serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["candidate_member_ids", "pattern", "tensions", "exclusions", "uncertainty"],
        "properties": {
            "candidate_member_ids": {
                "type": "array", "minItems": 2, "uniqueItems": true,
                "description": "Smallest useful whole-field member set, using supplied immutable IDs only.",
                "items": {"type": "string", "enum": ids}
            },
            "pattern": {"type": "string", "minLength": 1, "maxLength": 512, "description": "Concise account grounded in supplied content."},
            "tensions": {"type": "array", "uniqueItems": true, "items": {"type": "string", "minLength": 1}, "maxItems": 8, "description": "Concrete supplied tensions, or [] when none."},
            "exclusions": {"type": "array", "uniqueItems": true, "items": {"type": "string", "minLength": 1}, "maxItems": 8, "description": "Concrete supplied exclusions, or [] when none."},
            "uncertainty": {"type": "array", "uniqueItems": true, "items": {"type": "string", "minLength": 1}, "maxItems": 8, "description": "Concrete unresolved questions grounded in supplied material, or [] when none."}
        }
    })
}

fn probe_schema_v1(field: &SemanticField) -> Value {
    let ids: Vec<&str> = field
        .elements
        .iter()
        .map(|element| element.element_id.as_str())
        .collect();
    serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["candidate_member_ids", "pattern", "tensions", "exclusions", "uncertainty"],
        "properties": {
            "candidate_member_ids": {
                "type": "array", "minItems": 2, "uniqueItems": true,
                "items": {"type": "string", "enum": ids}
            },
            "pattern": {"type": "string", "minLength": 1, "maxLength": 512},
            "tensions": {"type": "array", "items": {"type": "string"}, "maxItems": 8},
            "exclusions": {"type": "array", "items": {"type": "string"}, "maxItems": 8},
            "uncertainty": {"type": "array", "items": {"type": "string"}, "maxItems": 8}
        }
    })
}

fn typed_probe_schema_v3(field: &SemanticField) -> Value {
    let ids: Vec<&str> = field
        .elements
        .iter()
        .map(|element| element.element_id.as_str())
        .collect();
    serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["candidate_member_ids", "assessment", "flagged_member_ids"],
        "properties": {
            "candidate_member_ids": {
                "type": "array", "minItems": 2, "uniqueItems": true,
                "items": {"type": "string", "enum": ids}
            },
            "assessment": {
                "type": "string", "enum": ["coherent", "uncertain", "conflicted", "excludes"]
            },
            "flagged_member_ids": {
                "type": "array", "uniqueItems": true,
                "items": {"type": "string", "enum": ids}
            }
        }
    })
}

fn typed_probe_schema(field: &SemanticField) -> Value {
    let ids: Vec<&str> = field
        .elements
        .iter()
        .map(|element| element.element_id.as_str())
        .collect();
    serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["candidate_member_ids", "assessment", "flagged_member_ids"],
        "properties": {
            "candidate_member_ids": {
                "type": "array", "minItems": 2, "maxItems": field.elements.len(),
                "uniqueItems": true, "items": {"type": "string", "enum": ids}
            },
            "assessment": {
                "type": "string", "enum": ["coherent", "uncertain", "conflicted", "excludes"]
            },
            "flagged_member_ids": {
                "type": "array", "maxItems": field.elements.len(), "uniqueItems": true,
                "items": {"type": "string", "enum": ids}
            }
        }
    })
}

fn delineation_schema(candidate: &GestaltCandidate) -> Value {
    let ids: Vec<&str> = candidate.member_ids.iter().map(String::as_str).collect();
    serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["candidate_id", "status", "identity_bindings", "relations", "contradictions", "excluded_member_ids", "uncertainty", "account"],
        "properties": {
            "candidate_id": {"type": "string", "const": candidate.candidate_id},
            "status": {"type": "string", "enum": ["supported", "rejected", "unresolved"], "description": "Use supported only when identities remain exact and explicit relations connect all candidate members."},
            "identity_bindings": {
                "type": "array", "minItems": candidate.member_ids.len(), "maxItems": candidate.member_ids.len(),
                "items": {
                    "type": "object", "additionalProperties": false,
                    "required": ["input_id", "output_id"],
                    "properties": {
                        "input_id": {"type": "string", "enum": ids},
                        "output_id": {"type": "string", "enum": ids}
                    }
                }
            },
            "relations": {
                "type": "array", "minItems": 1, "maxItems": 24,
                "items": {
                    "type": "object", "additionalProperties": false,
                    "required": ["source_id", "kind", "target_id", "account"],
                    "properties": {
                        "source_id": {"type": "string", "enum": ids},
                        "kind": {"type": "string", "enum": ["supports", "complements", "contrasts", "constrains", "depends_on", "contextualizes"]},
                        "target_id": {"type": "string", "enum": ids},
                        "account": {"type": "string", "minLength": 1, "maxLength": 512, "description": "Specific relation account grounded in the supplied element content."}
                    }
                }
            },
            "contradictions": {"type": "array", "uniqueItems": true, "items": {"type": "string", "minLength": 1}, "maxItems": 8, "description": "Concrete supplied contradictions, or [] when none."},
            "excluded_member_ids": {"type": "array", "uniqueItems": true, "items": {"type": "string", "enum": ids}},
            "uncertainty": {"type": "array", "uniqueItems": true, "items": {"type": "string", "minLength": 1}, "maxItems": 8, "description": "Concrete unresolved questions grounded in supplied material, or [] when none."},
            "account": {"type": "string", "minLength": 1, "maxLength": 1024, "description": "Concise whole-candidate delineation grounded in supplied content."}
        }
    })
}

fn delineation_schema_v1(candidate: &GestaltCandidate) -> Value {
    let ids: Vec<&str> = candidate.member_ids.iter().map(String::as_str).collect();
    serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["candidate_id", "status", "identity_bindings", "relations", "contradictions", "excluded_member_ids", "uncertainty", "account"],
        "properties": {
            "candidate_id": {"type": "string", "const": candidate.candidate_id},
            "status": {"type": "string", "enum": ["supported", "rejected", "unresolved"]},
            "identity_bindings": {
                "type": "array", "minItems": candidate.member_ids.len(), "maxItems": candidate.member_ids.len(),
                "items": {
                    "type": "object", "additionalProperties": false,
                    "required": ["input_id", "output_id"],
                    "properties": {
                        "input_id": {"type": "string", "enum": ids},
                        "output_id": {"type": "string", "enum": ids}
                    }
                }
            },
            "relations": {
                "type": "array", "minItems": 1, "maxItems": 24,
                "items": {
                    "type": "object", "additionalProperties": false,
                    "required": ["source_id", "kind", "target_id", "account"],
                    "properties": {
                        "source_id": {"type": "string", "enum": ids},
                        "kind": {"type": "string", "enum": ["supports", "complements", "contrasts", "constrains", "depends_on", "contextualizes"]},
                        "target_id": {"type": "string", "enum": ids},
                        "account": {"type": "string", "minLength": 1, "maxLength": 512}
                    }
                }
            },
            "contradictions": {"type": "array", "items": {"type": "string"}, "maxItems": 8},
            "excluded_member_ids": {"type": "array", "uniqueItems": true, "items": {"type": "string", "enum": ids}},
            "uncertainty": {"type": "array", "items": {"type": "string"}, "maxItems": 8},
            "account": {"type": "string", "minLength": 1, "maxLength": 1024}
        }
    })
}

fn typed_delineation_schema(candidate: &GestaltCandidate) -> Value {
    let ids: Vec<&str> = candidate.member_ids.iter().map(String::as_str).collect();
    let relation_count = candidate.member_ids.len().saturating_sub(1);
    serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "candidate_id", "status", "ordered_member_ids", "relation_kinds",
            "contradiction_member_ids", "excluded_member_ids", "uncertain_member_ids"
        ],
        "properties": {
            "candidate_id": {"type": "string", "const": candidate.candidate_id},
            "status": {"type": "string", "enum": ["supported", "rejected", "unresolved"]},
            "ordered_member_ids": {
                "type": "array", "minItems": candidate.member_ids.len(),
                "maxItems": candidate.member_ids.len(), "uniqueItems": true,
                "items": {"type": "string", "enum": ids}
            },
            "relation_kinds": {
                "type": "array", "minItems": relation_count, "maxItems": relation_count,
                "items": {"type": "string", "enum": ["supports", "complements", "contrasts", "constrains", "depends_on", "contextualizes"]}
            },
            "contradiction_member_ids": {
                "type": "array", "uniqueItems": true,
                "items": {"type": "string", "enum": ids}
            },
            "excluded_member_ids": {
                "type": "array", "uniqueItems": true,
                "items": {"type": "string", "enum": ids}
            },
            "uncertain_member_ids": {
                "type": "array", "uniqueItems": true,
                "items": {"type": "string", "enum": ids}
            }
        }
    })
}

fn verify_probe_exchange_lineage(report: &CycleReport) -> Result<(), String> {
    if report.exchanges.len() < PROBE_COUNT {
        return Err(format!(
            "live report contains {} exchanges but requires {PROBE_COUNT} probe exchanges",
            report.exchanges.len()
        ));
    }
    if report.probes.len() != PROBE_COUNT {
        return Err(format!(
            "live report must contain exactly {PROBE_COUNT} probes"
        ));
    }
    for probe_index in 0..PROBE_COUNT {
        verify_completed_probe_exchange(report, probe_index)?;
    }
    Ok(())
}

fn verify_completed_probe_exchange(report: &CycleReport, probe_index: usize) -> Result<(), String> {
    let exchange = report
        .exchanges
        .get(probe_index)
        .ok_or_else(|| format!("report omitted field probe exchange {}", probe_index + 1))?;
    let probe = report
        .probes
        .get(probe_index)
        .ok_or_else(|| format!("report omitted stored probe {}", probe_index + 1))?;
    let expected_stage = format!("field_probe_{}", probe_index + 1);
    if exchange.stage != expected_stage {
        return Err(format!(
            "exchange {} has stage {:?}, expected {:?}",
            probe_index + 1,
            exchange.stage,
            expected_stage
        ));
    }
    let expected_request = field_request_for_profile(
        &report.request_profile,
        &report.provider.model,
        &report.field,
        probe_index,
    )?;
    if exchange.request != expected_request {
        return Err(format!("{expected_stage} request does not recompute"));
    }
    let proposal = parse_probe_response(&report.request_profile, &report.field, &exchange.response)
        .map_err(|error| format!("{expected_stage} response cannot replay: {error}"))?;
    let expected_probe = admit_probe(&report.field, probe_index, proposal)
        .map_err(|error| format!("{expected_stage} proposal cannot be admitted: {error}"))?;
    if *probe != expected_probe {
        return Err(format!(
            "{expected_stage} stored probe does not match response"
        ));
    }
    Ok(())
}

fn verify_fault_report(report: &CycleReport) -> Result<(), String> {
    let fault = report
        .fault
        .as_deref()
        .filter(|fault| !fault.trim().is_empty())
        .ok_or("faulted report must contain a nonempty fault")?;
    if report.delineation_result.is_some() || report.latch_decision.is_some() {
        return Err(
            "faulted report cannot contain delineation result or latch decision".to_owned(),
        );
    }
    let states: Vec<CycleState> = report.events.iter().map(|event| event.state).collect();
    let control_prefix = vec![
        CycleState::Created,
        CycleState::FieldValidated,
        CycleState::Faulted,
    ];
    let probe_prefix = vec![
        CycleState::Created,
        CycleState::FieldValidated,
        CycleState::ProbesRequested,
        CycleState::Faulted,
    ];
    let delineation_prefix = vec![
        CycleState::Created,
        CycleState::FieldValidated,
        CycleState::ProbesRequested,
        CycleState::ProbesCollected,
        CycleState::CandidateAggregated,
        CycleState::DelineationRequested,
        CycleState::Faulted,
    ];
    if states == control_prefix {
        verify_control_fault(report, fault)
    } else if states == probe_prefix {
        verify_probe_fault(report, fault)
    } else if states == delineation_prefix {
        verify_delineation_fault(report, fault)
    } else {
        Err("fault report has an unsupported state prefix".to_owned())
    }
}

fn verify_control_fault(report: &CycleReport, fault: &str) -> Result<(), String> {
    if !report.probes.is_empty()
        || report.exchanges.len() > 1
        || report.candidate.is_some()
        || report.delineation_proposal.is_some()
    {
        return Err("control fault contains impossible post-control state".to_owned());
    }
    let Some(exchange) = report.exchanges.first() else {
        return Ok(());
    };
    if exchange.stage != "control_probe_1" {
        return Err("control fault exchange stage must be control_probe_1".to_owned());
    }
    let expected_request = field_request_for_profile(
        &report.request_profile,
        &report.provider.model,
        &report.field,
        0,
    )?;
    if exchange.request != expected_request {
        return Err("control fault request does not recompute".to_owned());
    }
    verify_failed_probe_response(report, 0, fault, exchange)
}

fn verify_probe_fault(report: &CycleReport, fault: &str) -> Result<(), String> {
    if report.candidate.is_some() || report.delineation_proposal.is_some() {
        return Err("probe fault contains candidate or delineation proposal".to_owned());
    }
    if report.probes.len() > PROBE_COUNT
        || report.exchanges.len() > PROBE_COUNT
        || report.exchanges.len() < report.probes.len()
        || report.exchanges.len() > report.probes.len() + 1
    {
        return Err("probe fault has impossible probe/exchange cardinality".to_owned());
    }
    for probe_index in 0..report.probes.len() {
        verify_completed_probe_exchange(report, probe_index)?;
    }
    if report.exchanges.len() == report.probes.len() {
        return Ok(());
    }
    let probe_index = report.probes.len();
    let exchange = &report.exchanges[probe_index];
    let expected_stage = format!("field_probe_{}", probe_index + 1);
    if exchange.stage != expected_stage {
        return Err(format!(
            "failed probe exchange stage must be {expected_stage}"
        ));
    }
    let expected_request = field_request_for_profile(
        &report.request_profile,
        &report.provider.model,
        &report.field,
        probe_index,
    )?;
    if exchange.request != expected_request {
        return Err(format!(
            "{expected_stage} failed request does not recompute"
        ));
    }
    verify_failed_probe_response(report, probe_index, fault, exchange)
}

fn verify_failed_probe_response(
    report: &CycleReport,
    probe_index: usize,
    fault: &str,
    exchange: &ProviderExchange,
) -> Result<(), String> {
    let recomputed_fault =
        match parse_probe_response(&report.request_profile, &report.field, &exchange.response) {
            Err(error) => error,
            Ok(proposal) => match admit_probe(&report.field, probe_index, proposal) {
                Err(error) => error,
                Ok(_) => return Err("failed probe exchange replays as a valid probe".to_owned()),
            },
        };
    if fault != recomputed_fault {
        return Err("recorded probe fault does not match failed response".to_owned());
    }
    Ok(())
}

fn verify_delineation_fault(report: &CycleReport, fault: &str) -> Result<(), String> {
    if report.probes.len() != PROBE_COUNT
        || !(report.exchanges.len() == PROBE_COUNT || report.exchanges.len() == PROBE_COUNT + 1)
        || report.delineation_proposal.is_some()
    {
        return Err("delineation fault has impossible record cardinality".to_owned());
    }
    verify_probe_exchange_lineage(report)?;
    let expected_candidate = aggregate_candidate(&report.field, &report.probes)?;
    if report.candidate.as_ref() != Some(&expected_candidate) {
        return Err("delineation fault candidate does not recompute".to_owned());
    }
    let Some(exchange) = report.exchanges.get(PROBE_COUNT) else {
        return Ok(());
    };
    if exchange.stage != "delineation" {
        return Err("failed fifth exchange must be delineation".to_owned());
    }
    let expected_request = delineation_request_for_profile(
        &report.request_profile,
        &report.provider.model,
        &report.field,
        &expected_candidate,
    )?;
    if exchange.request != expected_request {
        return Err("failed delineation request does not recompute".to_owned());
    }
    let recomputed_fault = parse_delineation_response(
        &report.request_profile,
        &expected_candidate,
        &exchange.response,
    )
    .err()
    .ok_or("failed delineation exchange replays as a valid proposal")?;
    if fault != recomputed_fault {
        return Err("recorded delineation fault does not match failed response".to_owned());
    }
    Ok(())
}

fn verify_control_report(report: &CycleReport) -> Result<(), String> {
    if report.exchanges.len() != 1 || report.probes.len() != 1 {
        return Err("control report must contain exactly one exchange and one probe".to_owned());
    }
    if report.candidate.is_some()
        || report.delineation_proposal.is_some()
        || report.delineation_result.is_some()
        || report.latch_decision.is_some()
        || report.fault.is_some()
    {
        return Err(
            "control report contains forbidden candidate, latch, or fault state".to_owned(),
        );
    }
    let exchange = &report.exchanges[0];
    if exchange.stage != "control_probe_1" {
        return Err("control exchange stage must be control_probe_1".to_owned());
    }
    let expected_request = field_request_for_profile(
        &report.request_profile,
        &report.provider.model,
        &report.field,
        0,
    )?;
    if exchange.request != expected_request {
        return Err("control request does not recompute".to_owned());
    }
    let proposal = parse_probe_response(&report.request_profile, &report.field, &exchange.response)
        .map_err(|error| format!("control response cannot replay: {error}"))?;
    let expected_probe = admit_probe(&report.field, 0, proposal)
        .map_err(|error| format!("control proposal cannot be admitted: {error}"))?;
    if report.probes[0] != expected_probe {
        return Err("control stored probe does not match response".to_owned());
    }
    Ok(())
}

fn verify_delineation_exchange_lineage(
    report: &CycleReport,
    candidate: &GestaltCandidate,
    proposal: &DelineationProposal,
) -> Result<(), String> {
    if report.exchanges.len() != PROBE_COUNT + 1 {
        return Err(format!(
            "live report with a candidate must contain exactly {} exchanges",
            PROBE_COUNT + 1
        ));
    }
    let exchange = &report.exchanges[PROBE_COUNT];
    if exchange.stage != "delineation" {
        return Err("fifth exchange must be the delineation stage".to_owned());
    }
    let expected_request = delineation_request_for_profile(
        &report.request_profile,
        &report.provider.model,
        &report.field,
        candidate,
    )?;
    if exchange.request != expected_request {
        return Err("delineation request does not recompute".to_owned());
    }
    let expected_proposal =
        parse_delineation_response(&report.request_profile, candidate, &exchange.response)
            .map_err(|error| format!("delineation response cannot replay: {error}"))?;
    if *proposal != expected_proposal {
        return Err("stored delineation proposal does not match response".to_owned());
    }
    Ok(())
}

fn verify_events(
    events: &[CycleEvent],
    terminal: CycleState,
    deterministic_fixture: bool,
) -> Result<(), String> {
    if events.is_empty() {
        return Err("report contains no events".to_owned());
    }
    if events
        .iter()
        .enumerate()
        .any(|(index, event)| event.ordinal != index + 1 || event.evidence_ref.trim().is_empty())
    {
        return Err("events have invalid ordinal or evidence reference".to_owned());
    }
    if events.last().map(|event| event.state) != Some(terminal) {
        return Err("last event does not match terminal state".to_owned());
    }
    let states: Vec<CycleState> = events.iter().map(|event| event.state).collect();
    let expected = match terminal {
        CycleState::Completed => vec![
            CycleState::Created,
            CycleState::FieldValidated,
            CycleState::ProbesRequested,
            CycleState::ProbesCollected,
            CycleState::CandidateAggregated,
            CycleState::DelineationRequested,
            CycleState::DelineationCollected,
            CycleState::LatchEvaluated,
            CycleState::Completed,
        ],
        CycleState::Rejected if states.len() == 5 => vec![
            CycleState::Created,
            CycleState::FieldValidated,
            CycleState::ProbesRequested,
            CycleState::ProbesCollected,
            CycleState::Rejected,
        ],
        CycleState::Rejected => vec![
            CycleState::Created,
            CycleState::FieldValidated,
            CycleState::ProbesRequested,
            CycleState::ProbesCollected,
            CycleState::CandidateAggregated,
            CycleState::DelineationRequested,
            CycleState::DelineationCollected,
            CycleState::LatchEvaluated,
            CycleState::Rejected,
        ],
        CycleState::ControlCompleted => vec![
            CycleState::Created,
            CycleState::FieldValidated,
            CycleState::ControlCompleted,
        ],
        CycleState::Faulted
            if states
                == [
                    CycleState::Created,
                    CycleState::FieldValidated,
                    CycleState::Faulted,
                ] =>
        {
            states.clone()
        }
        CycleState::Faulted
            if states
                == [
                    CycleState::Created,
                    CycleState::FieldValidated,
                    CycleState::ProbesRequested,
                    CycleState::Faulted,
                ] =>
        {
            states.clone()
        }
        CycleState::Faulted
            if states
                == [
                    CycleState::Created,
                    CycleState::FieldValidated,
                    CycleState::ProbesRequested,
                    CycleState::ProbesCollected,
                    CycleState::CandidateAggregated,
                    CycleState::DelineationRequested,
                    CycleState::Faulted,
                ] =>
        {
            states.clone()
        }
        _ => return Err("terminal state is not replay-verifiable".to_owned()),
    };
    if states != expected {
        return Err("event state path is not canonical".to_owned());
    }
    let control_path = terminal == CycleState::ControlCompleted
        || states
            == [
                CycleState::Created,
                CycleState::FieldValidated,
                CycleState::Faulted,
            ];
    for (index, event) in events.iter().enumerate() {
        let expected_ref = if deterministic_fixture {
            format!("fixture-event-{}", index + 1)
        } else {
            let label = match event.state {
                CycleState::Created if control_path => "control-field-input",
                CycleState::Created => "field-input",
                CycleState::FieldValidated if control_path => "control-field-digest",
                CycleState::FieldValidated => "field-digest",
                CycleState::ProbesRequested => "probe-orders",
                CycleState::ProbesCollected => "field-probes",
                CycleState::CandidateAggregated => "gestalt-candidate",
                CycleState::DelineationRequested => "delineation-request",
                CycleState::DelineationCollected => "delineation-result",
                CycleState::LatchEvaluated => "latch-decision",
                CycleState::Completed => "terminal-decision",
                CycleState::Rejected if states.len() == 5 => "aggregation-rejection",
                CycleState::Rejected => "terminal-decision",
                CycleState::Faulted => "typed-fault",
                CycleState::ControlCompleted => "control-probe-only-no-latch",
            };
            label.to_owned()
        };
        if event.evidence_ref != expected_ref {
            return Err(format!(
                "event {} evidence reference does not match canonical trajectory",
                index + 1
            ));
        }
    }
    Ok(())
}

fn require_nonempty(label: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{label} must not be empty"))
    } else {
        Ok(())
    }
}

fn require_bounded_nonempty(label: &str, value: &str, maximum_bytes: usize) -> Result<(), String> {
    require_nonempty(label, value)?;
    if value.len() > maximum_bytes {
        return Err(format!("{label} exceeds {maximum_bytes} UTF-8 byte limit"));
    }
    Ok(())
}

fn field_ids(field: &SemanticField) -> BTreeSet<String> {
    field
        .elements
        .iter()
        .map(|element| element.element_id.clone())
        .collect()
}

fn violates_co_membership(field: &SemanticField, members: &[String]) -> bool {
    let members: BTreeSet<&str> = members.iter().map(String::as_str).collect();
    field.boundaries.iter().any(|boundary| {
        boundary.kind == BoundaryKind::ForbidCoMembership
            && members.contains(boundary.left_id.as_str())
            && members.contains(boundary.right_id.as_str())
    })
}

fn violates_relation_boundary(field: &SemanticField, relation: &RelationEdge) -> bool {
    field.boundaries.iter().any(|boundary| {
        if boundary.kind != BoundaryKind::ForbidRelation
            || boundary.relation_kind != Some(relation.kind)
        {
            return false;
        }
        (boundary.left_id == relation.source_id && boundary.right_id == relation.target_id)
            || (boundary.left_id == relation.target_id && boundary.right_id == relation.source_id)
    })
}

fn is_connected(
    candidate_ids: &BTreeSet<String>,
    adjacency: &BTreeMap<String, BTreeSet<String>>,
) -> bool {
    let Some(first) = candidate_ids.first() else {
        return false;
    };
    let mut seen = BTreeSet::new();
    let mut queue = VecDeque::from([first.clone()]);
    while let Some(id) = queue.pop_front() {
        if !seen.insert(id.clone()) {
            continue;
        }
        if let Some(neighbors) = adjacency.get(&id) {
            queue.extend(
                neighbors
                    .iter()
                    .filter(|next| !seen.contains(*next))
                    .cloned(),
            );
        }
    }
    seen == *candidate_ids
}

#[cfg(test)]
mod tests {
    use super::*;

    fn element(id: &str, content: &str) -> FieldElement {
        FieldElement {
            element_id: id.to_owned(),
            kind: ElementKind::Term,
            content: content.to_owned(),
            content_sha256: sha256_hex(content.as_bytes()),
            source_ref: format!("fixture:{id}"),
        }
    }

    fn field() -> SemanticField {
        SemanticField {
            profile: FIELD_PROFILE.to_owned(),
            field_id: "field-attention".to_owned(),
            subject: "attention cycle".to_owned(),
            purpose: "discover a coherent implementation seam".to_owned(),
            elements: vec![
                element("observer", "preserve subject continuity"),
                element("field", "propose a whole-field pattern"),
                element("delineation", "make relations explicit"),
                element("latch", "admit only after gates pass"),
            ],
            boundaries: Vec::new(),
            probe_policy: ProbePolicy::default(),
        }
    }

    fn probes(field: &SemanticField, sets: &[&[&str]]) -> Vec<FieldProbe> {
        sets.iter()
            .enumerate()
            .map(|(index, ids)| {
                admit_probe(
                    field,
                    index,
                    ProbeProposal {
                        candidate_member_ids: ids.iter().map(|id| (*id).to_owned()).collect(),
                        pattern: format!("pattern-{index}"),
                        tensions: Vec::new(),
                        exclusions: Vec::new(),
                        uncertainty: Vec::new(),
                    },
                )
                .unwrap()
            })
            .collect()
    }

    fn supported_proposal(candidate: &GestaltCandidate) -> DelineationProposal {
        DelineationProposal {
            candidate_id: candidate.candidate_id.clone(),
            status: DelineationStatus::Supported,
            identity_bindings: candidate
                .member_ids
                .iter()
                .map(|id| IdentityBinding {
                    input_id: id.clone(),
                    output_id: id.clone(),
                })
                .collect(),
            relations: candidate
                .member_ids
                .windows(2)
                .map(|pair| RelationEdge {
                    source_id: pair[0].clone(),
                    kind: RelationKind::Supports,
                    target_id: pair[1].clone(),
                    account: "explicit fixture support".to_owned(),
                })
                .collect(),
            contradictions: Vec::new(),
            excluded_member_ids: Vec::new(),
            uncertainty: Vec::new(),
            account: "the support chain covers the candidate".to_owned(),
        }
    }

    fn stopped_response(content: Value) -> Value {
        serde_json::json!({
            "choices": [{
                "finish_reason": "stop",
                "message": {"content": serde_json::to_string(&content).unwrap()}
            }]
        })
    }

    fn typed_probe_value(field: &SemanticField, assessment: &str) -> Value {
        serde_json::json!({
            "candidate_member_ids": field.elements.iter().map(|element| element.element_id.clone()).collect::<Vec<_>>(),
            "assessment": assessment,
            "flagged_member_ids": []
        })
    }

    fn live_report() -> CycleReport {
        let field = field();
        let model = "typed-fixture-model";
        let mut probes = Vec::new();
        let mut exchanges = Vec::new();
        for probe_index in 0..PROBE_COUNT {
            let request =
                field_request_for_profile(REQUEST_PROFILE_V5, model, &field, probe_index).unwrap();
            let response = stopped_response(typed_probe_value(&field, "coherent"));
            let proposal = parse_probe_response(REQUEST_PROFILE_V5, &field, &response).unwrap();
            probes.push(admit_probe(&field, probe_index, proposal).unwrap());
            exchanges.push(
                provider_exchange(
                    format!("field_probe_{}", probe_index + 1),
                    request,
                    response,
                )
                .unwrap(),
            );
        }
        let candidate = aggregate_candidate(&field, &probes).unwrap();
        let typed_delineation = serde_json::json!({
            "candidate_id": candidate.candidate_id,
            "status": "supported",
            "ordered_member_ids": candidate.member_ids,
            "relation_kinds": vec!["supports"; candidate.member_ids.len() - 1],
            "contradiction_member_ids": [],
            "excluded_member_ids": [],
            "uncertain_member_ids": []
        });
        let request =
            delineation_request_for_profile(REQUEST_PROFILE_V5, model, &field, &candidate).unwrap();
        let response = stopped_response(typed_delineation);
        let proposal =
            parse_delineation_response(REQUEST_PROFILE_V5, &candidate, &response).unwrap();
        exchanges.push(provider_exchange("delineation", request, response).unwrap());
        let result = validate_delineation(&field, &candidate, &proposal);
        let decision = latch(&field, &candidate, &result);
        let events = [
            (CycleState::Created, "field-input"),
            (CycleState::FieldValidated, "field-digest"),
            (CycleState::ProbesRequested, "probe-orders"),
            (CycleState::ProbesCollected, "field-probes"),
            (CycleState::CandidateAggregated, "gestalt-candidate"),
            (CycleState::DelineationRequested, "delineation-request"),
            (CycleState::DelineationCollected, "delineation-result"),
            (CycleState::LatchEvaluated, "latch-decision"),
            (CycleState::Completed, "terminal-decision"),
        ];
        CycleReport {
            profile: CYCLE_PROFILE.to_owned(),
            request_profile: REQUEST_PROFILE_V5.to_owned(),
            run_id: "typed-live-fixture".to_owned(),
            provider: ProviderIdentity {
                base_url: "http://127.0.0.1:8081".to_owned(),
                model: model.to_owned(),
            },
            field_digest: canonical_digest(&field).unwrap(),
            field,
            events: events
                .into_iter()
                .enumerate()
                .map(|(index, (state, evidence_ref))| CycleEvent {
                    ordinal: index + 1,
                    state,
                    evidence_ref: evidence_ref.to_owned(),
                })
                .collect(),
            exchanges,
            probes,
            candidate: Some(candidate),
            delineation_proposal: Some(proposal),
            delineation_result: Some(result),
            latch_decision: Some(decision),
            terminal_state: CycleState::Completed,
            fault: None,
        }
    }

    fn control_report() -> CycleReport {
        let field = field();
        let model = "typed-fixture-model";
        let request = field_request_for_profile(REQUEST_PROFILE_V5, model, &field, 0).unwrap();
        let response = stopped_response(typed_probe_value(&field, "coherent"));
        let proposal = parse_probe_response(REQUEST_PROFILE_V5, &field, &response).unwrap();
        let probe = admit_probe(&field, 0, proposal).unwrap();
        CycleReport {
            profile: CYCLE_PROFILE.to_owned(),
            request_profile: REQUEST_PROFILE_V5.to_owned(),
            run_id: "typed-control-fixture".to_owned(),
            provider: ProviderIdentity {
                base_url: "http://127.0.0.1:8081".to_owned(),
                model: model.to_owned(),
            },
            field_digest: canonical_digest(&field).unwrap(),
            field,
            events: [
                (CycleState::Created, "control-field-input"),
                (CycleState::FieldValidated, "control-field-digest"),
                (CycleState::ControlCompleted, "control-probe-only-no-latch"),
            ]
            .into_iter()
            .enumerate()
            .map(|(index, (state, evidence_ref))| CycleEvent {
                ordinal: index + 1,
                state,
                evidence_ref: evidence_ref.to_owned(),
            })
            .collect(),
            exchanges: vec![provider_exchange("control_probe_1", request, response).unwrap()],
            probes: vec![probe],
            candidate: None,
            delineation_proposal: None,
            delineation_result: None,
            latch_decision: None,
            terminal_state: CycleState::ControlCompleted,
            fault: None,
        }
    }

    #[test]
    fn field_and_orders_are_exact() {
        let field = field();
        validate_field(&field).unwrap();
        let orders = probe_orders(&field).unwrap();
        assert_eq!(orders.len(), PROBE_COUNT);
        assert_eq!(orders.iter().cloned().collect::<BTreeSet<_>>().len(), 4);
        let expected = field_ids(&field);
        assert!(
            orders
                .iter()
                .all(|order| order.iter().cloned().collect::<BTreeSet<_>>() == expected)
        );
    }

    #[test]
    fn field_order_generator_is_unique_at_every_supported_cardinality() {
        for cardinality in MINIMUM_ELEMENTS..=MAXIMUM_ELEMENTS {
            let mut field = field();
            field.elements = (0..cardinality)
                .map(|index| {
                    element(
                        &format!("element-{index:02}"),
                        &format!("content-{index:02}"),
                    )
                })
                .collect();
            field.boundaries.clear();
            validate_field(&field).unwrap();
            let expected = field_ids(&field);
            let orders = probe_orders(&field).unwrap();
            assert_eq!(
                orders.iter().cloned().collect::<BTreeSet<_>>().len(),
                PROBE_COUNT
            );
            assert!(
                orders
                    .iter()
                    .all(|order| order.iter().cloned().collect::<BTreeSet<_>>() == expected)
            );
        }
    }

    #[test]
    fn field_rejects_digest_and_unknown_boundary_identity() {
        let mut field = field();
        field.elements[0].content_sha256 = "00".repeat(32);
        assert!(
            validate_field(&field)
                .unwrap_err()
                .contains("digest mismatch")
        );
        field.elements[0].content_sha256 = sha256_hex(field.elements[0].content.as_bytes());
        field.boundaries.push(HardBoundary {
            boundary_id: "unknown".to_owned(),
            kind: BoundaryKind::ForbidCoMembership,
            left_id: "observer".to_owned(),
            right_id: "not-admitted".to_owned(),
            relation_kind: None,
            reason: "fixture".to_owned(),
        });
        assert!(
            validate_field(&field)
                .unwrap_err()
                .contains("unknown identity")
        );
    }

    #[test]
    fn field_text_budgets_count_utf8_bytes_and_never_truncate() {
        let mut oversized_content = field();
        oversized_content.elements[0].content =
            "é".repeat((MAX_ELEMENT_CONTENT_BYTES / "é".len()) + 1);
        oversized_content.elements[0].content_sha256 =
            sha256_hex(oversized_content.elements[0].content.as_bytes());
        let error = validate_field(&oversized_content).unwrap_err();
        assert!(error.contains("content exceeds"));
        assert_eq!(
            oversized_content.elements[0].content.len(),
            MAX_ELEMENT_CONTENT_BYTES + "é".len()
        );

        let mut oversized_identity = field();
        oversized_identity.field_id = "i".repeat(MAX_IDENTIFIER_BYTES + 1);
        assert!(
            validate_field(&oversized_identity)
                .unwrap_err()
                .contains("field_id exceeds")
        );

        let oversized_model = "m".repeat(MAX_PROVIDER_MODEL_BYTES + 1);
        assert!(
            field_request(&oversized_model, &field(), 0)
                .unwrap_err()
                .contains("provider model exceeds")
        );
    }

    #[test]
    fn proposal_schema_rejects_unknown_fields() {
        let json = r#"{
            "candidate_member_ids":["observer","field"],
            "pattern":"x",
            "tensions":[],"exclusions":[],"uncertainty":[],
            "truth":true
        }"#;
        assert!(serde_json::from_str::<ProbeProposal>(json).is_err());
    }

    #[test]
    fn exact_three_of_four_aggregation_is_deterministic() {
        let field = field();
        let probes = probes(
            &field,
            &[
                &["observer", "field", "delineation"],
                &["delineation", "observer", "field"],
                &["field", "delineation", "observer"],
                &["latch", "observer"],
            ],
        );
        let candidate = aggregate_candidate(&field, &probes).unwrap();
        assert_eq!(candidate.support_count, 3);
        assert_eq!(
            candidate.member_ids,
            vec!["delineation", "field", "observer"]
        );
        assert_eq!(candidate.representative_pattern, "pattern-0");
        assert_eq!(
            candidate.candidate_id,
            aggregate_candidate(&field, &probes).unwrap().candidate_id
        );
    }

    #[test]
    fn order_unstable_field_cannot_aggregate() {
        let field = field();
        let probes = probes(
            &field,
            &[
                &["observer", "field"],
                &["observer", "delineation"],
                &["observer", "latch"],
                &["field", "latch"],
            ],
        );
        assert!(
            aggregate_candidate(&field, &probes)
                .unwrap_err()
                .contains("3-of-4")
        );
    }

    #[test]
    fn misleading_boundary_crossing_agreement_cannot_aggregate() {
        let mut field = field();
        field.boundaries.push(HardBoundary {
            boundary_id: "separate-observer-field".to_owned(),
            kind: BoundaryKind::ForbidCoMembership,
            left_id: "observer".to_owned(),
            right_id: "field".to_owned(),
            relation_kind: None,
            reason: "fixture forbids composition".to_owned(),
        });
        let probes = probes(
            &field,
            &[
                &["observer", "field"],
                &["field", "observer"],
                &["observer", "field"],
                &["observer", "latch"],
            ],
        );
        assert!(
            aggregate_candidate(&field, &probes)
                .unwrap_err()
                .contains("forbid_co_membership")
        );
    }

    #[test]
    fn connected_supported_delineation_latches() {
        let field = field();
        let probes = probes(
            &field,
            &[
                &["observer", "field", "delineation"],
                &["delineation", "observer", "field"],
                &["field", "delineation", "observer"],
                &["observer", "field", "delineation"],
            ],
        );
        let candidate = aggregate_candidate(&field, &probes).unwrap();
        let proposal = supported_proposal(&candidate);
        let result = validate_delineation(&field, &candidate, &proposal);
        assert_eq!(result.status, DelineationStatus::Supported);
        let decision = latch(&field, &candidate, &result);
        assert_eq!(decision.status, LatchStatus::AdmittedForAttention);
        assert!(decision.failed_gates.is_empty());
    }

    #[test]
    fn identity_remap_rejects_latch() {
        let field = field();
        let probes = probes(
            &field,
            &[
                &["observer", "field"],
                &["field", "observer"],
                &["observer", "field"],
                &["observer", "field"],
            ],
        );
        let candidate = aggregate_candidate(&field, &probes).unwrap();
        let mut proposal = supported_proposal(&candidate);
        proposal.identity_bindings[0].output_id = candidate.member_ids[1].clone();
        let result = validate_delineation(&field, &candidate, &proposal);
        assert!(result.failed_gates.contains(&GateFault::IdentityRemap));
        assert_eq!(
            latch(&field, &candidate, &result).status,
            LatchStatus::Rejected
        );
    }

    #[test]
    fn disconnected_contradictory_or_uncertain_support_rejects() {
        let field = field();
        let probes = probes(
            &field,
            &[
                &["observer", "field", "delineation", "latch"],
                &["latch", "delineation", "field", "observer"],
                &["field", "observer", "latch", "delineation"],
                &["observer", "field", "delineation", "latch"],
            ],
        );
        let candidate = aggregate_candidate(&field, &probes).unwrap();
        let mut proposal = supported_proposal(&candidate);
        proposal.relations.truncate(1);
        proposal.contradictions.push("fixture conflict".to_owned());
        proposal.uncertainty.push("fixture uncertainty".to_owned());
        let result = validate_delineation(&field, &candidate, &proposal);
        assert!(
            result
                .failed_gates
                .contains(&GateFault::DisconnectedSupport)
        );
        assert!(
            result
                .failed_gates
                .contains(&GateFault::ContradictionPresent)
        );
        assert!(result.failed_gates.contains(&GateFault::UncertaintyPresent));
        assert_eq!(
            latch(&field, &candidate, &result).status,
            LatchStatus::Rejected
        );
    }

    #[test]
    fn forbidden_relation_rejects() {
        let mut field = field();
        field.boundaries.push(HardBoundary {
            boundary_id: "no-support-edge".to_owned(),
            kind: BoundaryKind::ForbidRelation,
            left_id: "field".to_owned(),
            right_id: "observer".to_owned(),
            relation_kind: Some(RelationKind::Supports),
            reason: "fixture".to_owned(),
        });
        let probes = probes(
            &field,
            &[
                &["observer", "field"],
                &["field", "observer"],
                &["observer", "field"],
                &["observer", "field"],
            ],
        );
        let candidate = aggregate_candidate(&field, &probes).unwrap();
        let proposal = supported_proposal(&candidate);
        let result = validate_delineation(&field, &candidate, &proposal);
        assert!(result.failed_gates.contains(&GateFault::BoundaryConflict));
    }

    #[test]
    fn delineation_rejects_unknown_exclusion_missing_accounts_and_blank_model() {
        let field = field();
        let probes = probes(
            &field,
            &[
                &["observer", "field", "delineation", "latch"],
                &["observer", "field", "delineation", "latch"],
                &["observer", "field", "delineation", "latch"],
                &["observer", "field", "delineation", "latch"],
            ],
        );
        let candidate = aggregate_candidate(&field, &probes).unwrap();

        let mut unknown_exclusion = supported_proposal(&candidate);
        unknown_exclusion.excluded_member_ids = vec!["outside-candidate".to_owned()];
        let result = validate_delineation(&field, &candidate, &unknown_exclusion);
        assert_eq!(result.status, DelineationStatus::Rejected);
        assert!(result.failed_gates.contains(&GateFault::UnknownIdentity));

        let mut missing_proposal_account = supported_proposal(&candidate);
        missing_proposal_account.account = "  ".to_owned();
        assert!(
            validate_delineation(&field, &candidate, &missing_proposal_account)
                .failed_gates
                .contains(&GateFault::MissingAccount)
        );

        let mut missing_relation_account = supported_proposal(&candidate);
        missing_relation_account.relations[0].account.clear();
        assert!(
            validate_delineation(&field, &candidate, &missing_relation_account)
                .failed_gates
                .contains(&GateFault::MissingAccount)
        );

        assert!(
            field_request("  ", &field, 0)
                .unwrap_err()
                .contains("provider model")
        );
    }

    #[test]
    fn control_is_never_latch_eligible() {
        let field = field();
        let probe = probes(&field, &[&["observer", "field"]]).remove(0);
        let control = control_observation(probe);
        assert!(!control.latch_eligible);
        assert_eq!(control.terminal_state, CycleState::ControlCompleted);
    }

    #[test]
    fn sanitizer_removes_private_reasoning_recursively() {
        let value = serde_json::json!({
            "answer": {"reasoning_content": "private", "content": "visible"},
            "thinking": ["private"]
        });
        assert_eq!(
            sanitize(&value),
            serde_json::json!({"answer":{"content":"visible"}})
        );
    }

    #[test]
    fn requests_bind_orders_candidate_and_closed_schemas() {
        let field = field();
        let request = field_request("fixture-model", &field, 2).unwrap();
        assert_eq!(request.pointer("/temperature"), Some(&serde_json::json!(0)));
        assert_eq!(
            request.pointer("/response_format/schema/additionalProperties"),
            Some(&serde_json::json!(false))
        );
        let content = request
            .pointer("/messages/1/content")
            .unwrap()
            .as_str()
            .unwrap();
        let input: Value = serde_json::from_str(content).unwrap();
        assert_eq!(
            input.pointer("/presentation_order/0"),
            Some(&serde_json::json!("field"))
        );

        let probes = probes(
            &field,
            &[
                &["observer", "field"],
                &["field", "observer"],
                &["observer", "field"],
                &["observer", "field"],
            ],
        );
        let candidate = aggregate_candidate(&field, &probes).unwrap();
        let request = delineation_request("fixture-model", &field, &candidate).unwrap();
        assert_eq!(
            request.pointer("/response_format/schema/properties/candidate_id/const"),
            Some(&serde_json::json!(candidate.candidate_id))
        );
    }

    #[test]
    fn provider_content_requires_one_clean_stopped_choice() {
        let response = serde_json::json!({
            "choices": [{
                "finish_reason": "stop",
                "message": {"content": "{\"candidate_member_ids\":[\"observer\",\"field\"],\"pattern\":\"x\",\"tensions\":[],\"exclusions\":[],\"uncertainty\":[]}"}
            }]
        });
        let proposal: ProbeProposal = parse_provider_content(&response).unwrap();
        assert_eq!(proposal.pattern, "x");
        let mut malformed = response;
        malformed["choices"][0]["finish_reason"] = serde_json::json!("length");
        assert!(parse_provider_content::<ProbeProposal>(&malformed).is_err());
    }

    #[test]
    fn deterministic_fixture_report_replays_and_detects_tampering() {
        let report = fixture_report(field()).unwrap();
        let verified = verify_report(&report).unwrap();
        assert!(verified.valid);
        assert_eq!(
            verified.latch_status,
            Some(LatchStatus::AdmittedForAttention)
        );
        let mut tampered = report;
        tampered
            .candidate
            .as_mut()
            .unwrap()
            .supporting_probe_ids
            .pop();
        assert!(verify_report(&tampered).is_err());
    }

    #[test]
    fn typed_probe_profiles_preserve_strict_and_whole_proposal_semantics() {
        let field = field();
        let response = stopped_response(typed_probe_value(&field, "conflicted"));
        assert!(
            parse_probe_response(REQUEST_PROFILE_V4, &field, &response)
                .unwrap_err()
                .contains("flag at least one")
        );
        let compiled = parse_probe_response(REQUEST_PROFILE_V5, &field, &response).unwrap();
        assert_eq!(compiled.candidate_member_ids.len(), field.elements.len());
        assert_eq!(compiled.tensions.len(), 1);
        assert!(compiled.tensions[0].contains("whole proposal conflicted"));
        assert!(compiled.exclusions.is_empty());
        assert!(compiled.uncertainty.is_empty());
    }

    #[test]
    fn typed_delineation_compiles_exact_identity_chain_and_rejects_bad_permutation() {
        let field = field();
        let probes = probes(
            &field,
            &[
                &["observer", "field", "delineation", "latch"],
                &["latch", "delineation", "field", "observer"],
                &["field", "observer", "latch", "delineation"],
                &["observer", "field", "delineation", "latch"],
            ],
        );
        let candidate = aggregate_candidate(&field, &probes).unwrap();
        let value = serde_json::json!({
            "candidate_id": candidate.candidate_id,
            "status": "supported",
            "ordered_member_ids": candidate.member_ids,
            "relation_kinds": ["supports", "constrains", "depends_on"],
            "contradiction_member_ids": [],
            "excluded_member_ids": [],
            "uncertain_member_ids": []
        });
        let proposal = parse_delineation_response(
            REQUEST_PROFILE_V5,
            &candidate,
            &stopped_response(value.clone()),
        )
        .unwrap();
        assert_eq!(proposal.identity_bindings.len(), candidate.member_ids.len());
        assert_eq!(proposal.relations.len(), candidate.member_ids.len() - 1);
        assert_eq!(
            validate_delineation(&field, &candidate, &proposal).status,
            DelineationStatus::Supported
        );

        let mut bad = value;
        bad["ordered_member_ids"][0] = bad["ordered_member_ids"][1].clone();
        assert!(
            parse_delineation_response(REQUEST_PROFILE_V5, &candidate, &stopped_response(bad))
                .is_err()
        );
    }

    #[test]
    fn live_lineage_replays_and_rejects_redigested_request_or_response_tampering() {
        let report = live_report();
        assert_eq!(
            verify_report(&report).unwrap().latch_status,
            Some(LatchStatus::AdmittedForAttention)
        );

        let mut request_tampered = report.clone();
        request_tampered.exchanges[0].request["seed"] = serde_json::json!(9999);
        request_tampered.exchanges[0].request_sha256 =
            canonical_digest(&request_tampered.exchanges[0].request).unwrap();
        assert!(
            verify_report(&request_tampered)
                .unwrap_err()
                .contains("request does not recompute")
        );

        let mut response_tampered = report;
        response_tampered.exchanges[0].response = stopped_response(serde_json::json!({
            "candidate_member_ids": ["observer", "field"],
            "assessment": "coherent",
            "flagged_member_ids": []
        }));
        response_tampered.exchanges[0].response_sha256 =
            canonical_digest(&response_tampered.exchanges[0].response).unwrap();
        assert!(
            verify_report(&response_tampered)
                .unwrap_err()
                .contains("stored probe does not match response")
        );

        let mut model_tampered = live_report();
        model_tampered.exchanges[0].response["model"] =
            Value::String("substituted-model".to_owned());
        model_tampered.exchanges[0].response_sha256 =
            canonical_digest(&model_tampered.exchanges[0].response).unwrap();
        assert!(
            verify_report(&model_tampered)
                .unwrap_err()
                .contains("response model does not match provider identity")
        );
    }

    #[test]
    fn live_control_and_fault_event_evidence_references_are_exact() {
        let mut live = live_report();
        live.events[3].evidence_ref = "substituted-but-nonempty".to_owned();
        assert!(
            verify_report(&live)
                .unwrap_err()
                .contains("evidence reference does not match canonical trajectory")
        );

        let mut control = control_report();
        control.events[0].evidence_ref = "field-input".to_owned();
        assert!(
            verify_report(&control)
                .unwrap_err()
                .contains("evidence reference does not match canonical trajectory")
        );

        let mut fault = live_report();
        fault.events.truncate(4);
        fault.events[3] = CycleEvent {
            ordinal: 4,
            state: CycleState::Faulted,
            evidence_ref: "wrong-fault-label".to_owned(),
        };
        fault.exchanges.truncate(1);
        fault.probes.clear();
        fault.candidate = None;
        fault.delineation_proposal = None;
        fault.delineation_result = None;
        fault.latch_decision = None;
        fault.terminal_state = CycleState::Faulted;
        fault.fault = Some("synthetic fault".to_owned());
        assert!(
            verify_report(&fault)
                .unwrap_err()
                .contains("evidence reference does not match canonical trajectory")
        );
    }

    #[test]
    fn control_report_replays_but_cannot_carry_candidate_or_latch() {
        let report = control_report();
        let verified = verify_report(&report).unwrap();
        assert_eq!(verified.terminal_state, CycleState::ControlCompleted);
        assert_eq!(verified.latch_status, None);
        assert_eq!(verified.exchange_count, 1);

        let mut tampered = report;
        tampered.candidate = live_report().candidate;
        assert!(
            verify_report(&tampered)
                .unwrap_err()
                .contains("forbidden candidate")
        );
    }

    #[test]
    fn request_profiles_are_versioned_and_v5_bounds_typed_arrays() {
        let field = field();
        let v1 = field_request_for_profile(REQUEST_PROFILE_V1, "model", &field, 0).unwrap();
        let v5 = field_request_for_profile(REQUEST_PROFILE_V5, "model", &field, 0).unwrap();
        assert_ne!(v1, v5);
        assert_eq!(
            v5.pointer("/response_format/schema/properties/candidate_member_ids/maxItems"),
            Some(&serde_json::json!(field.elements.len()))
        );
        assert_eq!(
            v5.pointer("/response_format/schema/properties/flagged_member_ids/maxItems"),
            Some(&serde_json::json!(field.elements.len()))
        );
    }

    #[test]
    fn response_backed_fault_replays_and_fault_text_cannot_be_rewritten() {
        let field = field();
        let model = "typed-fixture-model";
        let request = field_request_for_profile(REQUEST_PROFILE_V4, model, &field, 0).unwrap();
        let response = stopped_response(typed_probe_value(&field, "conflicted"));
        let fault = parse_probe_response(REQUEST_PROFILE_V4, &field, &response).unwrap_err();
        let report = CycleReport {
            profile: CYCLE_PROFILE.to_owned(),
            request_profile: REQUEST_PROFILE_V4.to_owned(),
            run_id: "typed-fault-fixture".to_owned(),
            provider: ProviderIdentity {
                base_url: "http://127.0.0.1:8081".to_owned(),
                model: model.to_owned(),
            },
            field_digest: canonical_digest(&field).unwrap(),
            field,
            events: [
                (CycleState::Created, "field-input"),
                (CycleState::FieldValidated, "field-digest"),
                (CycleState::ProbesRequested, "probe-orders"),
                (CycleState::Faulted, "typed-fault"),
            ]
            .into_iter()
            .enumerate()
            .map(|(index, (state, evidence_ref))| CycleEvent {
                ordinal: index + 1,
                state,
                evidence_ref: evidence_ref.to_owned(),
            })
            .collect(),
            exchanges: vec![provider_exchange("field_probe_1", request, response).unwrap()],
            probes: Vec::new(),
            candidate: None,
            delineation_proposal: None,
            delineation_result: None,
            latch_decision: None,
            terminal_state: CycleState::Faulted,
            fault: Some(fault),
        };
        assert_eq!(
            verify_report(&report).unwrap().terminal_state,
            CycleState::Faulted
        );
        let mut rewritten = report;
        rewritten.fault = Some("different explanation".to_owned());
        assert!(
            verify_report(&rewritten)
                .unwrap_err()
                .contains("does not match failed response")
        );
    }

    #[test]
    fn report_identity_rejects_blank_remote_noncanonical_and_unknown_profiles() {
        let report = live_report();

        let mut blank_run = report.clone();
        blank_run.run_id = "  ".to_owned();
        assert!(verify_report(&blank_run).unwrap_err().contains("run_id"));

        let mut blank_model = report.clone();
        blank_model.provider.model.clear();
        assert!(
            verify_report(&blank_model)
                .unwrap_err()
                .contains("provider model")
        );

        let mut remote = report.clone();
        remote.provider.base_url = "http://192.168.1.19:8081".to_owned();
        assert!(
            verify_report(&remote)
                .unwrap_err()
                .contains("127.0.0.1 or localhost")
        );

        let mut noncanonical = report.clone();
        noncanonical.provider.base_url.push('/');
        assert!(
            verify_report(&noncanonical)
                .unwrap_err()
                .contains("canonical form")
        );

        let mut unknown_profile = report;
        unknown_profile.request_profile = "cantor-field-attention-requests/999".to_owned();
        assert!(
            verify_report(&unknown_profile)
                .unwrap_err()
                .contains("unsupported request profile")
        );
    }
}
