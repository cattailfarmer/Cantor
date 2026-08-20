//! Strict inert forms for the seeded multi-backend semantic compiler.
//!
//! This module identifies source, target, capability, proof, and self-assembly
//! boundaries. It does not parse SOP, lower meaning, emit artifacts, invoke a
//! compiler, modify an inference host, install a candidate, or execute work.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{ContentDigest, SemanticAddress, SemanticId};

mod self_ordering;
pub use self_ordering::*;

pub const SOP_SEED_PROFILE: &str = "cantor-sop-seed/0.1";
pub const COMPILER_CAPABILITY_CEILING_PROFILE: &str = "cantor-compiler-capability-ceiling/0.1";
pub const TYPED_SOP_IR_PROFILE: &str = "cantor-typed-sop-ir/0.1";
pub const CANDIDATE_COMPILATION_PLAN_PROFILE: &str = "cantor-candidate-compilation-plan/0.1";
pub const COMPILER_CAPABILITY_RECEIPT_PROFILE: &str = "cantor-compiler-capability-receipt/0.1";
pub const SELF_ASSEMBLY_LEDGER_PROFILE: &str = "cantor-self-assembly-ledger/0.1";
pub const COMPILER_NON_AUTHORITY: &str = "Candidate compilation metadata only. Parsing, semantic validity, artifact emission, signing, admission, installation, execution, effect authority, and successor recognition are not granted.";

const DIGEST_ALGORITHM: &str = "sha256";
const CEILING_DOMAIN: &str = "cantor.semantic-compiler.capability-ceiling.v1";
const SEED_DOMAIN: &str = "cantor.semantic-compiler.seed.v1";
const IR_DOMAIN: &str = "cantor.semantic-compiler.ir.v1";
const PLAN_DOMAIN: &str = "cantor.semantic-compiler.plan.v1";
const RECEIPT_DOMAIN: &str = "cantor.semantic-compiler.capability-receipt.v1";
const LEDGER_DOMAIN: &str = "cantor.semantic-compiler.self-assembly-ledger.v1";
const MAX_TEXT_BYTES: usize = 4096;
const MAX_COLLECTION_ITEMS: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompilerBackendKind {
    AttentionProcedure,
    InferenceHostIntegration,
    NativeArtifact,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompilerCapability {
    SemanticRead,
    SourceRead,
    Build,
    FileWrite,
    ProcessExecute,
    Install,
    Network,
    ExternalEffect,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompilerCapabilityCeiling {
    pub profile: String,
    pub ceiling_id: SemanticId,
    pub capabilities: BTreeSet<CompilerCapability>,
    pub resource_scopes: BTreeSet<String>,
    pub maximum_artifacts: u32,
    pub maximum_serialized_bytes: u64,
    pub ceiling_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SopSeed {
    pub profile: String,
    pub seed_id: SemanticId,
    pub generation_id: SemanticId,
    pub purpose: String,
    pub honesty_trust_root_ref: SemanticId,
    pub security_trust_root_ref: SemanticId,
    pub authority_trust_root_ref: SemanticId,
    pub compiler_trust_root_ref: SemanticId,
    pub dependency_roots: BTreeMap<SemanticId, ContentDigest>,
    pub discovery_contract_ref: SemanticId,
    pub semantic_frontend_profile: String,
    pub backend_profiles: BTreeMap<CompilerBackendKind, String>,
    pub capability_ceiling: CompilerCapabilityCeiling,
    pub predecessor_generation_ref: Option<SemanticId>,
    pub successor_policy_ref: SemanticId,
    pub seed_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticIrNodeKind {
    Identity,
    Type,
    Role,
    Input,
    Output,
    Precondition,
    Invariant,
    Transform,
    Postcondition,
    Fault,
    Evidence,
    NonTransferRule,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticIrNode {
    pub node_id: SemanticId,
    pub kind: SemanticIrNodeKind,
    pub semantic_address: SemanticAddress,
    pub type_ref: Option<SemanticId>,
    pub dependency_refs: BTreeSet<SemanticId>,
    pub generated_derivation_refs: BTreeSet<SemanticId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompilerSourceMapEntry {
    pub node_ref: SemanticId,
    pub semantic_address: SemanticAddress,
    pub derivation_refs: BTreeSet<SemanticId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypedSopIr {
    pub profile: String,
    pub ir_id: SemanticId,
    pub source_manifest_digest: ContentDigest,
    pub canonical_specification_ref: SemanticId,
    pub canonical_specification_digest: ContentDigest,
    pub nodes: BTreeMap<SemanticId, SemanticIrNode>,
    pub source_map: BTreeMap<SemanticId, CompilerSourceMapEntry>,
    pub unresolved_account: BTreeSet<String>,
    pub non_authority: String,
    pub ir_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateCompilationPlan {
    pub profile: String,
    pub plan_id: SemanticId,
    pub seed_ref: SemanticId,
    pub seed_digest: ContentDigest,
    pub ir_ref: SemanticId,
    pub ir_digest: ContentDigest,
    pub backend: CompilerBackendKind,
    pub backend_profile: String,
    pub purpose: String,
    pub requested_capabilities: BTreeSet<CompilerCapability>,
    pub input_refs: BTreeSet<SemanticId>,
    pub expected_output_refs: BTreeSet<SemanticId>,
    pub verifier_refs: BTreeSet<SemanticId>,
    pub rollback_ref: SemanticId,
    pub unresolved_account: BTreeSet<String>,
    pub non_authority: String,
    pub plan_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityDisposition {
    WithinCeiling,
    ExceedsCeiling,
    Unresolved,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompilerCapabilityReceipt {
    pub profile: String,
    pub receipt_id: SemanticId,
    pub plan_ref: SemanticId,
    pub plan_digest: ContentDigest,
    pub backend: CompilerBackendKind,
    pub ceiling_ref: SemanticId,
    pub ceiling_digest: ContentDigest,
    pub requested_capabilities: BTreeSet<CompilerCapability>,
    pub admitted_capabilities: BTreeSet<CompilerCapability>,
    pub denied_capabilities: BTreeSet<CompilerCapability>,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub disposition: CapabilityDisposition,
    pub non_authority: String,
    pub receipt_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelfAssemblyStage {
    SelfDescription,
    SelfOrdering,
    SelfHosting,
    SelfRevision,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelfAssemblyDisposition {
    Observed,
    Candidate,
    VerifiedCandidate,
    RecognizedSuccessor,
    Refused,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfAssemblyEntry {
    pub entry_id: SemanticId,
    pub stage: SelfAssemblyStage,
    pub plan_ref: Option<SemanticId>,
    pub candidate_artifact_ref: Option<SemanticId>,
    pub honesty_receipt_ref: Option<SemanticId>,
    pub security_receipt_ref: Option<SemanticId>,
    pub external_recognition_ref: Option<SemanticId>,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub disposition: SelfAssemblyDisposition,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfAssemblyLedger {
    pub profile: String,
    pub ledger_id: SemanticId,
    pub seed_ref: SemanticId,
    pub seed_digest: ContentDigest,
    pub predecessor_generation_ref: SemanticId,
    pub successor_generation_ref: Option<SemanticId>,
    pub rollback_ref: SemanticId,
    pub entries: Vec<SelfAssemblyEntry>,
    pub non_authority: String,
    pub ledger_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticCompilerFormFaultKind {
    InvalidProfile,
    InvalidDigest,
    InvalidBound,
    InvalidReference,
    MissingSourceMap,
    DependencyCycle,
    BackendMismatch,
    CapabilityExceeded,
    AccountingMismatch,
    StageOrder,
    RecognitionBoundary,
    NonAuthorityMismatch,
    DigestMismatch,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticCompilerFormFault {
    pub kind: SemanticCompilerFormFaultKind,
    pub field: String,
    pub detail: String,
}

pub type SemanticCompilerValidation<T = ()> = Result<T, SemanticCompilerFormFault>;

pub fn compiler_capability_ceiling_digest(
    ceiling: &CompilerCapabilityCeiling,
) -> SemanticCompilerValidation<ContentDigest> {
    digest_form(
        CEILING_DOMAIN,
        &(
            &ceiling.profile,
            &ceiling.ceiling_id,
            &ceiling.capabilities,
            &ceiling.resource_scopes,
            ceiling.maximum_artifacts,
            ceiling.maximum_serialized_bytes,
        ),
    )
}

pub fn sop_seed_digest(seed: &SopSeed) -> SemanticCompilerValidation<ContentDigest> {
    digest_form(
        SEED_DOMAIN,
        &(
            &seed.profile,
            &seed.seed_id,
            &seed.generation_id,
            &seed.purpose,
            &seed.honesty_trust_root_ref,
            &seed.security_trust_root_ref,
            &seed.authority_trust_root_ref,
            &seed.compiler_trust_root_ref,
            &seed.dependency_roots,
            &seed.discovery_contract_ref,
            &seed.semantic_frontend_profile,
            &seed.backend_profiles,
            &seed.capability_ceiling,
            &seed.predecessor_generation_ref,
            &seed.successor_policy_ref,
        ),
    )
}

pub fn typed_sop_ir_digest(ir: &TypedSopIr) -> SemanticCompilerValidation<ContentDigest> {
    digest_form(
        IR_DOMAIN,
        &(
            &ir.profile,
            &ir.ir_id,
            &ir.source_manifest_digest,
            &ir.canonical_specification_ref,
            &ir.canonical_specification_digest,
            &ir.nodes,
            &ir.source_map,
            &ir.unresolved_account,
            &ir.non_authority,
        ),
    )
}

pub fn candidate_compilation_plan_digest(
    plan: &CandidateCompilationPlan,
) -> SemanticCompilerValidation<ContentDigest> {
    digest_form(
        PLAN_DOMAIN,
        &(
            &plan.profile,
            &plan.plan_id,
            &plan.seed_ref,
            &plan.seed_digest,
            &plan.ir_ref,
            &plan.ir_digest,
            &plan.backend,
            &plan.backend_profile,
            &plan.purpose,
            &plan.requested_capabilities,
            &plan.input_refs,
            &plan.expected_output_refs,
            &plan.verifier_refs,
            &plan.rollback_ref,
            &plan.unresolved_account,
            &plan.non_authority,
        ),
    )
}

pub fn compiler_capability_receipt_digest(
    receipt: &CompilerCapabilityReceipt,
) -> SemanticCompilerValidation<ContentDigest> {
    digest_form(
        RECEIPT_DOMAIN,
        &(
            &receipt.profile,
            &receipt.receipt_id,
            &receipt.plan_ref,
            &receipt.plan_digest,
            &receipt.backend,
            &receipt.ceiling_ref,
            &receipt.ceiling_digest,
            &receipt.requested_capabilities,
            &receipt.admitted_capabilities,
            &receipt.denied_capabilities,
            &receipt.evidence_refs,
            &receipt.disposition,
            &receipt.non_authority,
        ),
    )
}

pub fn self_assembly_ledger_digest(
    ledger: &SelfAssemblyLedger,
) -> SemanticCompilerValidation<ContentDigest> {
    digest_form(
        LEDGER_DOMAIN,
        &(
            &ledger.profile,
            &ledger.ledger_id,
            &ledger.seed_ref,
            &ledger.seed_digest,
            &ledger.predecessor_generation_ref,
            &ledger.successor_generation_ref,
            &ledger.rollback_ref,
            &ledger.entries,
            &ledger.non_authority,
        ),
    )
}

pub fn validate_compiler_capability_ceiling(
    ceiling: &CompilerCapabilityCeiling,
) -> SemanticCompilerValidation {
    exact_profile(
        &ceiling.profile,
        COMPILER_CAPABILITY_CEILING_PROFILE,
        "ceiling.profile",
    )?;
    bounded_set(&ceiling.resource_scopes, "ceiling.resource_scopes")?;
    if ceiling.capabilities.len() > CompilerCapability::variant_count()
        || ceiling.resource_scopes.is_empty()
        || ceiling.maximum_artifacts == 0
        || ceiling.maximum_serialized_bytes == 0
    {
        return form_fault(
            SemanticCompilerFormFaultKind::InvalidBound,
            "capability_ceiling",
            "capability count and artifact byte bounds must be finite and positive",
        );
    }
    validate_digest(&ceiling.ceiling_digest, "ceiling.ceiling_digest")?;
    require_digest(
        &ceiling.ceiling_digest,
        compiler_capability_ceiling_digest(ceiling)?,
        "ceiling.ceiling_digest",
    )
}

pub fn validate_sop_seed(seed: &SopSeed) -> SemanticCompilerValidation {
    exact_profile(&seed.profile, SOP_SEED_PROFILE, "seed.profile")?;
    bounded_text(&seed.purpose, "seed.purpose")?;
    bounded_text(
        &seed.semantic_frontend_profile,
        "seed.semantic_frontend_profile",
    )?;
    if seed.dependency_roots.is_empty() || seed.dependency_roots.len() > MAX_COLLECTION_ITEMS {
        return form_fault(
            SemanticCompilerFormFaultKind::InvalidBound,
            "seed.dependency_roots",
            "dependency roots must be nonempty and bounded",
        );
    }
    for digest in seed.dependency_roots.values() {
        validate_digest(digest, "seed.dependency_roots")?;
    }
    let required = BTreeSet::from([
        CompilerBackendKind::AttentionProcedure,
        CompilerBackendKind::InferenceHostIntegration,
        CompilerBackendKind::NativeArtifact,
    ]);
    if seed
        .backend_profiles
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>()
        != required
    {
        return form_fault(
            SemanticCompilerFormFaultKind::BackendMismatch,
            "seed.backend_profiles",
            "seed must register exactly the three compiler backend kinds",
        );
    }
    for profile in seed.backend_profiles.values() {
        bounded_text(profile, "seed.backend_profiles")?;
    }
    let trust_roots = BTreeSet::from([
        &seed.honesty_trust_root_ref,
        &seed.security_trust_root_ref,
        &seed.authority_trust_root_ref,
        &seed.compiler_trust_root_ref,
    ]);
    if trust_roots.len() != 4 {
        return form_fault(
            SemanticCompilerFormFaultKind::InvalidReference,
            "seed.trust_roots",
            "Honesty Security authority and compiler trust roots must be distinct",
        );
    }
    validate_compiler_capability_ceiling(&seed.capability_ceiling)?;
    validate_digest(&seed.seed_digest, "seed.seed_digest")?;
    require_digest(
        &seed.seed_digest,
        sop_seed_digest(seed)?,
        "seed.seed_digest",
    )
}

pub fn validate_typed_sop_ir(ir: &TypedSopIr) -> SemanticCompilerValidation {
    exact_profile(&ir.profile, TYPED_SOP_IR_PROFILE, "ir.profile")?;
    validate_digest(&ir.source_manifest_digest, "ir.source_manifest_digest")?;
    validate_digest(
        &ir.canonical_specification_digest,
        "ir.canonical_specification_digest",
    )?;
    exact_non_authority(&ir.non_authority, "ir.non_authority")?;
    if ir.nodes.is_empty()
        || ir.nodes.len() > MAX_COLLECTION_ITEMS
        || ir.source_map.len() != ir.nodes.len()
    {
        return form_fault(
            SemanticCompilerFormFaultKind::MissingSourceMap,
            "ir.nodes",
            "IR nodes must be nonempty bounded and have one source-map entry each",
        );
    }
    bounded_set(&ir.unresolved_account, "ir.unresolved_account")?;
    for (node_id, node) in &ir.nodes {
        if node_id != &node.node_id {
            return form_fault(
                SemanticCompilerFormFaultKind::InvalidReference,
                "ir.nodes",
                "node map key differs from node identity",
            );
        }
        validate_address(&node.semantic_address, "ir.nodes.semantic_address")?;
        if matches!(
            node.kind,
            SemanticIrNodeKind::Input | SemanticIrNodeKind::Output
        ) && node.type_ref.is_none()
        {
            return form_fault(
                SemanticCompilerFormFaultKind::InvalidReference,
                "ir.nodes.type_ref",
                "input and output nodes require an exact type reference",
            );
        }
        if node.type_ref.as_ref().is_some_and(|type_ref| {
            ir.nodes
                .get(type_ref)
                .is_none_or(|type_node| type_node.kind != SemanticIrNodeKind::Type)
        }) {
            return form_fault(
                SemanticCompilerFormFaultKind::InvalidReference,
                "ir.nodes.type_ref",
                "type reference must resolve to one exact type node",
            );
        }
        if node.dependency_refs.contains(node_id)
            || !node
                .dependency_refs
                .iter()
                .all(|dependency| ir.nodes.contains_key(dependency))
        {
            return form_fault(
                SemanticCompilerFormFaultKind::InvalidReference,
                "ir.nodes.dependency_refs",
                "node dependencies must resolve and cannot contain self",
            );
        }
        let Some(source_map) = ir.source_map.get(node_id) else {
            return form_fault(
                SemanticCompilerFormFaultKind::MissingSourceMap,
                "ir.source_map",
                "node lacks an exact source-map entry",
            );
        };
        if source_map.node_ref != *node_id
            || source_map.semantic_address != node.semantic_address
            || source_map.derivation_refs != node.generated_derivation_refs
        {
            return form_fault(
                SemanticCompilerFormFaultKind::MissingSourceMap,
                "ir.source_map",
                "source-map identity address or derivation differs from its node",
            );
        }
    }
    validate_dependency_dag(&ir.nodes)?;
    validate_digest(&ir.ir_digest, "ir.ir_digest")?;
    require_digest(&ir.ir_digest, typed_sop_ir_digest(ir)?, "ir.ir_digest")
}

pub fn validate_candidate_compilation_plan(
    seed: &SopSeed,
    ir: &TypedSopIr,
    plan: &CandidateCompilationPlan,
) -> SemanticCompilerValidation {
    validate_sop_seed(seed)?;
    validate_typed_sop_ir(ir)?;
    exact_profile(
        &plan.profile,
        CANDIDATE_COMPILATION_PLAN_PROFILE,
        "plan.profile",
    )?;
    if plan.seed_ref != seed.seed_id
        || plan.seed_digest != seed.seed_digest
        || plan.ir_ref != ir.ir_id
        || plan.ir_digest != ir.ir_digest
    {
        return form_fault(
            SemanticCompilerFormFaultKind::InvalidReference,
            "plan.lineage",
            "plan seed or IR lineage differs from the validated inputs",
        );
    }
    if seed.backend_profiles.get(&plan.backend) != Some(&plan.backend_profile) {
        return form_fault(
            SemanticCompilerFormFaultKind::BackendMismatch,
            "plan.backend_profile",
            "plan backend profile differs from the exact seed registration",
        );
    }
    if !plan
        .requested_capabilities
        .is_subset(&seed.capability_ceiling.capabilities)
    {
        return form_fault(
            SemanticCompilerFormFaultKind::CapabilityExceeded,
            "plan.requested_capabilities",
            "plan requests a capability outside the seed ceiling",
        );
    }
    bounded_text(&plan.purpose, "plan.purpose")?;
    if normalize(&plan.purpose) != normalize(&seed.purpose)
        || plan.input_refs.is_empty()
        || plan.expected_output_refs.is_empty()
        || plan.verifier_refs.is_empty()
        || !plan.input_refs.iter().all(|id| ir.nodes.contains_key(id))
        || !plan.expected_output_refs.iter().all(|id| {
            ir.nodes
                .get(id)
                .is_some_and(|node| node.kind == SemanticIrNodeKind::Output)
        })
    {
        return form_fault(
            SemanticCompilerFormFaultKind::InvalidReference,
            "plan.contract",
            "purpose inputs outputs or verifier contract is incomplete or unresolved",
        );
    }
    bounded_set(&plan.unresolved_account, "plan.unresolved_account")?;
    exact_non_authority(&plan.non_authority, "plan.non_authority")?;
    validate_digest(&plan.plan_digest, "plan.plan_digest")?;
    require_digest(
        &plan.plan_digest,
        candidate_compilation_plan_digest(plan)?,
        "plan.plan_digest",
    )
}

pub fn validate_compiler_capability_receipt(
    seed: &SopSeed,
    plan: &CandidateCompilationPlan,
    receipt: &CompilerCapabilityReceipt,
) -> SemanticCompilerValidation {
    validate_sop_seed(seed)?;
    exact_profile(
        &receipt.profile,
        COMPILER_CAPABILITY_RECEIPT_PROFILE,
        "receipt.profile",
    )?;
    validate_digest(&plan.plan_digest, "receipt.plan_digest")?;
    require_digest(
        &plan.plan_digest,
        candidate_compilation_plan_digest(plan)?,
        "receipt.plan_digest",
    )?;
    if receipt.plan_ref != plan.plan_id
        || receipt.plan_digest != plan.plan_digest
        || receipt.backend != plan.backend
        || receipt.ceiling_ref != seed.capability_ceiling.ceiling_id
        || receipt.ceiling_digest != seed.capability_ceiling.ceiling_digest
        || receipt.requested_capabilities != plan.requested_capabilities
    {
        return form_fault(
            SemanticCompilerFormFaultKind::InvalidReference,
            "receipt.lineage",
            "receipt plan backend ceiling or request differs",
        );
    }
    if !receipt
        .admitted_capabilities
        .is_subset(&seed.capability_ceiling.capabilities)
        || !receipt
            .admitted_capabilities
            .is_disjoint(&receipt.denied_capabilities)
        || receipt
            .admitted_capabilities
            .union(&receipt.denied_capabilities)
            .cloned()
            .collect::<BTreeSet<_>>()
            != receipt.requested_capabilities
    {
        return form_fault(
            SemanticCompilerFormFaultKind::AccountingMismatch,
            "receipt.capabilities",
            "admitted and denied capabilities must partition the exact request within ceiling",
        );
    }
    let expected_disposition =
        if !receipt.evidence_refs.is_empty() && receipt.denied_capabilities.is_empty() {
            CapabilityDisposition::WithinCeiling
        } else if receipt.denied_capabilities.is_empty() {
            CapabilityDisposition::Unresolved
        } else {
            CapabilityDisposition::ExceedsCeiling
        };
    if receipt.disposition != expected_disposition {
        return form_fault(
            SemanticCompilerFormFaultKind::AccountingMismatch,
            "receipt.disposition",
            "receipt disposition differs from capability and evidence account",
        );
    }
    exact_non_authority(&receipt.non_authority, "receipt.non_authority")?;
    validate_digest(&receipt.receipt_digest, "receipt.receipt_digest")?;
    require_digest(
        &receipt.receipt_digest,
        compiler_capability_receipt_digest(receipt)?,
        "receipt.receipt_digest",
    )
}

pub fn validate_self_assembly_ledger(
    seed: &SopSeed,
    ledger: &SelfAssemblyLedger,
) -> SemanticCompilerValidation {
    validate_sop_seed(seed)?;
    exact_profile(
        &ledger.profile,
        SELF_ASSEMBLY_LEDGER_PROFILE,
        "ledger.profile",
    )?;
    if ledger.seed_ref != seed.seed_id
        || ledger.seed_digest != seed.seed_digest
        || ledger.predecessor_generation_ref != seed.generation_id
        || ledger.entries.is_empty()
        || ledger.entries.len() > 4
    {
        return form_fault(
            SemanticCompilerFormFaultKind::InvalidReference,
            "ledger.lineage",
            "ledger must bind the seed generation and contain one to four stages",
        );
    }
    exact_non_authority(&ledger.non_authority, "ledger.non_authority")?;
    let mut entry_ids = BTreeSet::new();
    for (index, entry) in ledger.entries.iter().enumerate() {
        if !entry_ids.insert(entry.entry_id.clone()) || stage_order(&entry.stage) != index {
            return form_fault(
                SemanticCompilerFormFaultKind::StageOrder,
                "ledger.entries",
                "entries must be unique and form a contiguous stage prefix",
            );
        }
        validate_self_assembly_entry(entry)?;
    }
    let recognized = ledger
        .entries
        .last()
        .is_some_and(|entry| entry.disposition == SelfAssemblyDisposition::RecognizedSuccessor);
    if recognized != ledger.successor_generation_ref.is_some() {
        return form_fault(
            SemanticCompilerFormFaultKind::RecognitionBoundary,
            "ledger.successor_generation_ref",
            "successor identity exists exactly when the final entry is externally recognized",
        );
    }
    validate_digest(&ledger.ledger_digest, "ledger.ledger_digest")?;
    require_digest(
        &ledger.ledger_digest,
        self_assembly_ledger_digest(ledger)?,
        "ledger.ledger_digest",
    )
}

fn validate_self_assembly_entry(entry: &SelfAssemblyEntry) -> SemanticCompilerValidation {
    match entry.stage {
        SelfAssemblyStage::SelfDescription => {
            if entry.plan_ref.is_some()
                || entry.candidate_artifact_ref.is_some()
                || entry.honesty_receipt_ref.is_some()
                || entry.security_receipt_ref.is_some()
                || entry.external_recognition_ref.is_some()
                || entry.disposition != SelfAssemblyDisposition::Observed
            {
                return form_fault(
                    SemanticCompilerFormFaultKind::StageOrder,
                    "ledger.self_description",
                    "self-description is observation-only",
                );
            }
        }
        SelfAssemblyStage::SelfOrdering => {
            if entry.plan_ref.is_none()
                || entry.candidate_artifact_ref.is_some()
                || entry.external_recognition_ref.is_some()
                || !matches!(
                    entry.disposition,
                    SelfAssemblyDisposition::Candidate | SelfAssemblyDisposition::Refused
                )
            {
                return form_fault(
                    SemanticCompilerFormFaultKind::StageOrder,
                    "ledger.self_ordering",
                    "self-ordering requires a plan and no artifact or recognition",
                );
            }
        }
        SelfAssemblyStage::SelfHosting => {
            if entry.plan_ref.is_none()
                || entry.candidate_artifact_ref.is_none()
                || entry.external_recognition_ref.is_some()
                || !matches!(
                    entry.disposition,
                    SelfAssemblyDisposition::VerifiedCandidate | SelfAssemblyDisposition::Refused
                )
            {
                return form_fault(
                    SemanticCompilerFormFaultKind::StageOrder,
                    "ledger.self_hosting",
                    "self-hosting requires candidate metadata and grants no recognition",
                );
            }
        }
        SelfAssemblyStage::SelfRevision => {
            if entry.plan_ref.is_none()
                || entry.candidate_artifact_ref.is_none()
                || entry.disposition == SelfAssemblyDisposition::Observed
            {
                return form_fault(
                    SemanticCompilerFormFaultKind::StageOrder,
                    "ledger.self_revision",
                    "self-revision requires plan and candidate identities",
                );
            }
            let recognition_complete = entry.plan_ref.is_some()
                && entry.candidate_artifact_ref.is_some()
                && entry.honesty_receipt_ref.is_some()
                && entry.security_receipt_ref.is_some()
                && entry.external_recognition_ref.is_some()
                && !entry.evidence_refs.is_empty();
            if entry.disposition == SelfAssemblyDisposition::RecognizedSuccessor
                && !recognition_complete
            {
                return form_fault(
                    SemanticCompilerFormFaultKind::RecognitionBoundary,
                    "ledger.self_revision",
                    "recognized successor requires candidate Honesty Security external recognition and evidence",
                );
            }
            if entry.disposition != SelfAssemblyDisposition::RecognizedSuccessor
                && entry.external_recognition_ref.is_some()
            {
                return form_fault(
                    SemanticCompilerFormFaultKind::RecognitionBoundary,
                    "ledger.self_revision",
                    "external recognition cannot be retained under a non-recognized disposition",
                );
            }
        }
    }
    Ok(())
}

fn validate_dependency_dag(
    nodes: &BTreeMap<SemanticId, SemanticIrNode>,
) -> SemanticCompilerValidation {
    fn visit(
        node_id: &SemanticId,
        nodes: &BTreeMap<SemanticId, SemanticIrNode>,
        visiting: &mut BTreeSet<SemanticId>,
        visited: &mut BTreeSet<SemanticId>,
    ) -> SemanticCompilerValidation {
        if visited.contains(node_id) {
            return Ok(());
        }
        if !visiting.insert(node_id.clone()) {
            return form_fault(
                SemanticCompilerFormFaultKind::DependencyCycle,
                "ir.nodes.dependency_refs",
                "semantic IR dependency graph contains a cycle",
            );
        }
        for dependency in &nodes[node_id].dependency_refs {
            visit(dependency, nodes, visiting, visited)?;
        }
        visiting.remove(node_id);
        visited.insert(node_id.clone());
        Ok(())
    }

    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for node_id in nodes.keys() {
        visit(node_id, nodes, &mut visiting, &mut visited)?;
    }
    Ok(())
}

fn validate_address(address: &SemanticAddress, field: &str) -> SemanticCompilerValidation {
    validate_digest(&address.unit_digest, field)?;
    validate_digest(&address.package_digest, field)?;
    bounded_text(&address.version, field)?;
    if address.source_anchors.is_empty() || address.source_anchors.len() > MAX_COLLECTION_ITEMS {
        return form_fault(
            SemanticCompilerFormFaultKind::InvalidBound,
            field,
            "semantic address requires bounded source anchors",
        );
    }
    for anchor in &address.source_anchors {
        validate_digest(&anchor.span_digest, field)?;
        if anchor.unit_id != address.unit_id
            || anchor.package_id != address.package_id
            || anchor.byte_start >= anchor.byte_end
            || anchor.display_line_start == 0
            || anchor.display_line_start > anchor.display_line_end
        {
            return form_fault(
                SemanticCompilerFormFaultKind::InvalidReference,
                field,
                "source anchor differs from address or has an invalid span",
            );
        }
    }
    Ok(())
}

fn exact_profile(actual: &str, expected: &str, field: &str) -> SemanticCompilerValidation {
    if actual == expected {
        Ok(())
    } else {
        form_fault(
            SemanticCompilerFormFaultKind::InvalidProfile,
            field,
            "profile differs from the exact supported version",
        )
    }
}

fn exact_non_authority(value: &str, field: &str) -> SemanticCompilerValidation {
    if value == COMPILER_NON_AUTHORITY {
        Ok(())
    } else {
        form_fault(
            SemanticCompilerFormFaultKind::NonAuthorityMismatch,
            field,
            "fixed compiler non-authority statement differs",
        )
    }
}

fn bounded_text(value: &str, field: &str) -> SemanticCompilerValidation {
    if !value.trim().is_empty() && value.len() <= MAX_TEXT_BYTES {
        Ok(())
    } else {
        form_fault(
            SemanticCompilerFormFaultKind::InvalidBound,
            field,
            "text is empty or exceeds the bounded form limit",
        )
    }
}

fn bounded_set(values: &BTreeSet<String>, field: &str) -> SemanticCompilerValidation {
    if values.len() > MAX_COLLECTION_ITEMS {
        return form_fault(
            SemanticCompilerFormFaultKind::InvalidBound,
            field,
            "set exceeds the bounded form limit",
        );
    }
    for value in values {
        bounded_text(value, field)?;
    }
    Ok(())
}

fn normalize(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn validate_digest(digest: &ContentDigest, field: &str) -> SemanticCompilerValidation {
    if digest.algorithm == DIGEST_ALGORITHM
        && digest.value.len() == 64
        && digest
            .value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Ok(())
    } else {
        form_fault(
            SemanticCompilerFormFaultKind::InvalidDigest,
            field,
            "expected lowercase SHA-256",
        )
    }
}

fn require_digest(
    actual: &ContentDigest,
    expected: ContentDigest,
    field: &str,
) -> SemanticCompilerValidation {
    if actual == &expected {
        Ok(())
    } else {
        form_fault(
            SemanticCompilerFormFaultKind::DigestMismatch,
            field,
            "digest differs from canonical form",
        )
    }
}

fn digest_form<T: Serialize>(domain: &str, value: &T) -> SemanticCompilerValidation<ContentDigest> {
    let bytes = serde_json::to_vec(value).map_err(|error| SemanticCompilerFormFault {
        kind: SemanticCompilerFormFaultKind::InvalidReference,
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

fn stage_order(stage: &SelfAssemblyStage) -> usize {
    match stage {
        SelfAssemblyStage::SelfDescription => 0,
        SelfAssemblyStage::SelfOrdering => 1,
        SelfAssemblyStage::SelfHosting => 2,
        SelfAssemblyStage::SelfRevision => 3,
    }
}

fn form_fault<T>(
    kind: SemanticCompilerFormFaultKind,
    field: &str,
    detail: &str,
) -> SemanticCompilerValidation<T> {
    Err(SemanticCompilerFormFault {
        kind,
        field: field.to_owned(),
        detail: detail.to_owned(),
    })
}

impl CompilerCapability {
    const fn variant_count() -> usize {
        8
    }
}
