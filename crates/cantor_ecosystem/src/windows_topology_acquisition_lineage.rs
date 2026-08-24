//! Pure binding of strict acquisition metadata to complete supplied inventory carriers.
//!
//! Success proves only that caller-declared metadata is internally coherent,
//! exact carrier-exposed joins match, both supplied carriers rederive under the
//! current profile, and current reconciliation is `Equal`. It does not prove
//! physical acquisition, event occurrence, causal truth, producer provenance,
//! quiescence, atomicity, snapshot semantics, freshness, issuance, receipt
//! authority, consumption, or present world state.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    InventoryConsistencyEvidence, PHASE3_MACHINE_FORMS_PROFILE, StrongFileIdentity,
    TOPOLOGY_FORMS_PROFILE, TOPOLOGY_RECEIPT_PROFILE, TopologyEntryKind, TopologyFormFault,
    TopologyScanLimits, ValidateTopologyForm, WINDOWS_TOPOLOGY_PROFILE,
    topology_forms::validate_volume_guid_path,
    windows_supplied_ordered_topology_inventory_digest::{
        ORDERED_TOPOLOGY_OBSERVATION_ENCODING_PROFILE,
        WINDOWS_SUPPLIED_ORDERED_TOPOLOGY_INVENTORY_DIGEST_PROFILE,
        WindowsSuppliedOrderedTopologyInventoryDigest,
        WindowsSuppliedOrderedTopologyInventoryDigestFault,
        derive_windows_supplied_ordered_topology_inventory_digest,
    },
    windows_supplied_ordered_topology_inventory_digest_reconciliation::{
        WINDOWS_SUPPLIED_ORDERED_TOPOLOGY_INVENTORY_DIGEST_RECONCILIATION_PROFILE,
        WindowsSuppliedOrderedTopologyInventoryDigestReconciliation,
        WindowsSuppliedOrderedTopologyInventoryDigestReconciliationDisposition,
        WindowsSuppliedOrderedTopologyInventoryDigestReconciliationFault,
        WindowsSuppliedOrderedTopologyInventoryDigestReconciliationPlan,
        reconcile_windows_supplied_ordered_topology_inventory_digests,
    },
    windows_supplied_topology_inventory_assembly::WINDOWS_SUPPLIED_TOPOLOGY_INVENTORY_ASSEMBLY_PROFILE,
    workspace_admission::CANDIDATE_WORKSPACE_ADMISSION_PROFILE,
};

/// Exact corrected pure acquisition-lineage profile.
pub const WINDOWS_TOPOLOGY_ACQUISITION_LINEAGE_PROFILE: &str =
    "cantor-phase3-topology-acquisition-lineage-forms/0.2";
/// Maximum accepted strict metadata-plan bytes before decoding.
pub const REPEATED_INVENTORY_EVIDENCE_PLAN_MAX_BYTES: usize = 131_072;

const MAX_PROFILE_BYTES: usize = 128;
const MAX_PATH_BYTES: usize = 32_768;
const DIGEST_HEX_BYTES: usize = 64;

/// Bounded logical correlation syntax. It proves neither uniqueness nor occurrence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcquisitionIdentity {
    value: u64,
}

impl AcquisitionIdentity {
    pub fn value(&self) -> u64 {
        self.value
    }
}

/// Complete caller-declared common scope for two acquisition roles.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcquisitionScopeClaim {
    candidate_root: String,
    root_identity: StrongFileIdentity,
    root_volume_guid_path: String,
    scanner_profile: String,
    machine_forms_profile: String,
    topology_forms_profile: String,
    topology_receipt_profile: String,
    assembly_profile: String,
    digest_profile: String,
    reconciliation_profile: String,
    encoding_profile: String,
    limits: TopologyScanLimits,
    policy_sha256: String,
    predecessor_admission_profile: String,
    predecessor_receipt_sha256: String,
}

impl AcquisitionScopeClaim {
    pub fn candidate_root(&self) -> &str {
        &self.candidate_root
    }

    pub fn root_identity(&self) -> &StrongFileIdentity {
        &self.root_identity
    }

    pub fn root_volume_guid_path(&self) -> &str {
        &self.root_volume_guid_path
    }

    pub fn scanner_profile(&self) -> &str {
        &self.scanner_profile
    }

    pub fn machine_forms_profile(&self) -> &str {
        &self.machine_forms_profile
    }

    pub fn topology_forms_profile(&self) -> &str {
        &self.topology_forms_profile
    }

    pub fn topology_receipt_profile(&self) -> &str {
        &self.topology_receipt_profile
    }

    pub fn assembly_profile(&self) -> &str {
        &self.assembly_profile
    }

    pub fn digest_profile(&self) -> &str {
        &self.digest_profile
    }

    pub fn reconciliation_profile(&self) -> &str {
        &self.reconciliation_profile
    }

    pub fn encoding_profile(&self) -> &str {
        &self.encoding_profile
    }

    pub fn limits(&self) -> &TopologyScanLimits {
        &self.limits
    }

    pub fn policy_sha256(&self) -> &str {
        &self.policy_sha256
    }

    pub fn predecessor_admission_profile(&self) -> &str {
        &self.predecessor_admission_profile
    }

    pub fn predecessor_receipt_sha256(&self) -> &str {
        &self.predecessor_receipt_sha256
    }
}

/// Closed caller declaration. It is not an observation of completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompletionDisposition {
    CompleteClaimed,
}

/// Strict metadata for one claimed acquisition role, without a carrier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcquisitionLineageMetadataClaim {
    identity: AcquisitionIdentity,
    scope: AcquisitionScopeClaim,
    completion: CompletionDisposition,
}

impl AcquisitionLineageMetadataClaim {
    pub fn identity(&self) -> &AcquisitionIdentity {
        &self.identity
    }

    pub fn scope(&self) -> &AcquisitionScopeClaim {
        &self.scope
    }

    pub fn completion(&self) -> CompletionDisposition {
        self.completion
    }
}

/// Closed direction for the caller-declared causal relation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CausalOrderKind {
    FirstCompletionStrictlyPrecedesSecondStart,
}

/// Caller-declared identity-bound causal edge without a clock witness.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CausalOrderClaim {
    first_acquisition_identity: AcquisitionIdentity,
    second_acquisition_identity: AcquisitionIdentity,
    kind: CausalOrderKind,
}

impl CausalOrderClaim {
    pub fn first_acquisition_identity(&self) -> &AcquisitionIdentity {
        &self.first_acquisition_identity
    }

    pub fn second_acquisition_identity(&self) -> &AcquisitionIdentity {
        &self.second_acquisition_identity
    }

    pub fn kind(&self) -> CausalOrderKind {
        self.kind
    }
}

/// Exact First and Second metadata roles plus one explicit causal claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrderedAcquisitionPairMetadataClaim {
    first: AcquisitionLineageMetadataClaim,
    second: AcquisitionLineageMetadataClaim,
    causal_order: CausalOrderClaim,
}

impl OrderedAcquisitionPairMetadataClaim {
    pub fn first(&self) -> &AcquisitionLineageMetadataClaim {
        &self.first
    }

    pub fn second(&self) -> &AcquisitionLineageMetadataClaim {
        &self.second
    }

    pub fn causal_order(&self) -> &CausalOrderClaim {
        &self.causal_order
    }
}

/// Strict metadata plan. Complete carriers are supplied as separate typed arguments.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepeatedInventoryEvidencePlan {
    profile: String,
    pair: OrderedAcquisitionPairMetadataClaim,
    reconciliation_plan: WindowsSuppliedOrderedTopologyInventoryDigestReconciliationPlan,
    requested_evidence: InventoryConsistencyEvidence,
}

impl RepeatedInventoryEvidencePlan {
    pub fn profile(&self) -> &str {
        &self.profile
    }

    pub fn pair(&self) -> &OrderedAcquisitionPairMetadataClaim {
        &self.pair
    }

    pub fn reconciliation_plan(
        &self,
    ) -> &WindowsSuppliedOrderedTopologyInventoryDigestReconciliationPlan {
        &self.reconciliation_plan
    }

    pub fn requested_evidence(&self) -> InventoryConsistencyEvidence {
        self.requested_evidence
    }
}

/// Output-only validated association between one metadata role and one carrier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AcquisitionLineageBinding {
    metadata: AcquisitionLineageMetadataClaim,
    carrier: WindowsSuppliedOrderedTopologyInventoryDigest,
}

impl AcquisitionLineageBinding {
    pub fn metadata(&self) -> &AcquisitionLineageMetadataClaim {
        &self.metadata
    }

    pub fn carrier(&self) -> &WindowsSuppliedOrderedTopologyInventoryDigest {
        &self.carrier
    }
}

/// Output-only exact pair of role-bound complete carrier lineages.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OrderedAcquisitionPairBinding {
    first: AcquisitionLineageBinding,
    second: AcquisitionLineageBinding,
    causal_order: CausalOrderClaim,
}

impl OrderedAcquisitionPairBinding {
    pub fn first(&self) -> &AcquisitionLineageBinding {
        &self.first
    }

    pub fn second(&self) -> &AcquisitionLineageBinding {
        &self.second
    }

    pub fn causal_order(&self) -> &CausalOrderClaim {
        &self.causal_order
    }
}

/// Closed non-authoritative provenance grade for this pure profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AcquisitionEvidenceProvenanceGrade {
    ClaimOnly,
}

/// Output-only pure result retaining complete bindings and reconciliation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RepeatedInventoryEvidenceClaim {
    profile: String,
    pair: OrderedAcquisitionPairBinding,
    reconciliation: WindowsSuppliedOrderedTopologyInventoryDigestReconciliation,
    requested_evidence: InventoryConsistencyEvidence,
    provenance: AcquisitionEvidenceProvenanceGrade,
}

impl RepeatedInventoryEvidenceClaim {
    pub fn profile(&self) -> &str {
        &self.profile
    }

    pub fn pair(&self) -> &OrderedAcquisitionPairBinding {
        &self.pair
    }

    pub fn reconciliation(&self) -> &WindowsSuppliedOrderedTopologyInventoryDigestReconciliation {
        &self.reconciliation
    }

    pub fn requested_evidence(&self) -> InventoryConsistencyEvidence {
        self.requested_evidence
    }

    pub fn provenance(&self) -> AcquisitionEvidenceProvenanceGrade {
        self.provenance
    }
}

/// Closed pure acquisition-lineage refusal vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcquisitionLineageFaultCode {
    InvalidRequest,
    Profile,
    Identity,
    Scope,
    Lineage,
    Order,
    Reconciliation,
    Different,
    Evidence,
    Resource,
}

/// One bounded atomic denial without a partial binding or result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcquisitionLineageFault {
    pub code: AcquisitionLineageFaultCode,
    pub nested_digest_fault: Option<Box<WindowsSuppliedOrderedTopologyInventoryDigestFault>>,
    pub nested_reconciliation_fault:
        Option<Box<WindowsSuppliedOrderedTopologyInventoryDigestReconciliationFault>>,
    pub field: String,
    pub message: String,
}

impl AcquisitionLineageFault {
    fn simple(code: AcquisitionLineageFaultCode, field: &str, message: &str) -> Self {
        Self {
            code,
            nested_digest_fault: None,
            nested_reconciliation_fault: None,
            field: bounded(field, 64),
            message: bounded(message, 256),
        }
    }

    fn digest(role: &str, fault: WindowsSuppliedOrderedTopologyInventoryDigestFault) -> Self {
        let message = format!("current {role} carrier rederivation rejected: {fault}");
        Self {
            code: AcquisitionLineageFaultCode::Lineage,
            nested_digest_fault: Some(Box::new(fault)),
            nested_reconciliation_fault: None,
            field: bounded(role, 64),
            message: bounded(&message, 256),
        }
    }

    fn reconciliation(
        fault: WindowsSuppliedOrderedTopologyInventoryDigestReconciliationFault,
    ) -> Self {
        let message = format!("current reconciliation rejected: {fault}");
        Self {
            code: AcquisitionLineageFaultCode::Reconciliation,
            nested_digest_fault: None,
            nested_reconciliation_fault: Some(Box::new(fault)),
            field: "reconciliation".to_owned(),
            message: bounded(&message, 256),
        }
    }
}

impl fmt::Display for AcquisitionLineageFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl std::error::Error for AcquisitionLineageFault {}

/// Strictly decodes and validates one bounded metadata-only plan.
pub fn decode_repeated_inventory_evidence_plan(
    bytes: &[u8],
) -> Result<RepeatedInventoryEvidencePlan, AcquisitionLineageFault> {
    if bytes.len() > REPEATED_INVENTORY_EVIDENCE_PLAN_MAX_BYTES {
        return Err(AcquisitionLineageFault::simple(
            AcquisitionLineageFaultCode::Resource,
            "json",
            "encoded repeated inventory evidence plan exceeds 131072 bytes",
        ));
    }
    let plan = serde_json::from_slice(bytes).map_err(|error| {
        AcquisitionLineageFault::simple(
            AcquisitionLineageFaultCode::InvalidRequest,
            "json",
            &error.to_string(),
        )
    })?;
    validate_plan(&plan)?;
    Ok(plan)
}

/// Binds exact First and Second metadata to two complete supplied carriers.
pub fn derive_repeated_inventory_evidence_claim(
    plan: RepeatedInventoryEvidencePlan,
    first_carrier: WindowsSuppliedOrderedTopologyInventoryDigest,
    second_carrier: WindowsSuppliedOrderedTopologyInventoryDigest,
) -> Result<RepeatedInventoryEvidenceClaim, AcquisitionLineageFault> {
    validate_plan(&plan)?;
    validate_carrier("first", plan.pair.first.scope(), &first_carrier)?;
    validate_carrier("second", plan.pair.second.scope(), &second_carrier)?;

    let first_rederived = rederive_carrier("first", &first_carrier)?;
    let second_rederived = rederive_carrier("second", &second_carrier)?;
    let reconciliation = reconcile_windows_supplied_ordered_topology_inventory_digests(
        plan.reconciliation_plan.clone(),
        first_rederived.clone(),
        second_rederived.clone(),
    )
    .map_err(AcquisitionLineageFault::reconciliation)?;
    validate_reconciliation_scope(plan.pair.first.scope(), &reconciliation)?;
    if reconciliation.disposition()
        != WindowsSuppliedOrderedTopologyInventoryDigestReconciliationDisposition::Equal
    {
        return Err(AcquisitionLineageFault::simple(
            AcquisitionLineageFaultCode::Different,
            "reconciliation.disposition",
            "current supplied inventories are valid but different",
        ));
    }

    let RepeatedInventoryEvidencePlan {
        pair,
        requested_evidence,
        ..
    } = plan;
    let OrderedAcquisitionPairMetadataClaim {
        first,
        second,
        causal_order,
    } = pair;
    Ok(RepeatedInventoryEvidenceClaim {
        profile: WINDOWS_TOPOLOGY_ACQUISITION_LINEAGE_PROFILE.to_owned(),
        pair: OrderedAcquisitionPairBinding {
            first: AcquisitionLineageBinding {
                metadata: first,
                carrier: first_rederived,
            },
            second: AcquisitionLineageBinding {
                metadata: second,
                carrier: second_rederived,
            },
            causal_order,
        },
        reconciliation,
        requested_evidence,
        provenance: AcquisitionEvidenceProvenanceGrade::ClaimOnly,
    })
}

fn validate_plan(plan: &RepeatedInventoryEvidencePlan) -> Result<(), AcquisitionLineageFault> {
    validate_exact_profile(
        "profile",
        &plan.profile,
        WINDOWS_TOPOLOGY_ACQUISITION_LINEAGE_PROFILE,
    )?;
    if plan.requested_evidence != InventoryConsistencyEvidence::NonAtomicRepeatedInventoryEqual {
        return Err(AcquisitionLineageFault::simple(
            AcquisitionLineageFaultCode::Evidence,
            "requested_evidence",
            "only non_atomic_repeated_inventory_equal is supported",
        ));
    }
    validate_metadata("first", &plan.pair.first)?;
    validate_metadata("second", &plan.pair.second)?;
    if plan.pair.first.identity == plan.pair.second.identity {
        return Err(AcquisitionLineageFault::simple(
            AcquisitionLineageFaultCode::Identity,
            "pair.identity",
            "First and Second acquisition identities must differ",
        ));
    }
    if plan.pair.first.scope != plan.pair.second.scope {
        return Err(AcquisitionLineageFault::simple(
            AcquisitionLineageFaultCode::Scope,
            "pair.scope",
            "First and Second complete metadata scopes must be exactly equal",
        ));
    }
    validate_order(&plan.pair)?;
    if plan.reconciliation_plan.profile()
        != WINDOWS_SUPPLIED_ORDERED_TOPOLOGY_INVENTORY_DIGEST_RECONCILIATION_PROFILE
    {
        return Err(AcquisitionLineageFault::simple(
            AcquisitionLineageFaultCode::Profile,
            "reconciliation_plan.profile",
            "reconciliation plan profile is not exact current profile",
        ));
    }
    if plan.reconciliation_plan.reconciliation_identity() == 0 {
        return Err(AcquisitionLineageFault::simple(
            AcquisitionLineageFaultCode::InvalidRequest,
            "reconciliation_plan.reconciliation_identity",
            "reconciliation identity must be nonzero",
        ));
    }
    Ok(())
}

fn validate_metadata(
    role: &str,
    metadata: &AcquisitionLineageMetadataClaim,
) -> Result<(), AcquisitionLineageFault> {
    if metadata.identity.value == 0 {
        return Err(AcquisitionLineageFault::simple(
            AcquisitionLineageFaultCode::Identity,
            &format!("{role}.identity"),
            "acquisition identity must be nonzero logical correlation syntax",
        ));
    }
    if metadata.completion != CompletionDisposition::CompleteClaimed {
        return Err(AcquisitionLineageFault::simple(
            AcquisitionLineageFaultCode::Lineage,
            &format!("{role}.completion"),
            "completion disposition must be complete_claimed",
        ));
    }
    validate_scope(role, &metadata.scope)
}

fn validate_scope(
    role: &str,
    scope: &AcquisitionScopeClaim,
) -> Result<(), AcquisitionLineageFault> {
    validate_text(
        &format!("{role}.scope.candidate_root"),
        &scope.candidate_root,
        MAX_PATH_BYTES,
    )?;
    scope
        .root_identity
        .validate()
        .map_err(|fault| topology_scope_fault(&format!("{role}.scope.root_identity"), fault))?;
    validate_volume_guid_path(&scope.root_volume_guid_path).map_err(|fault| {
        topology_scope_fault(&format!("{role}.scope.root_volume_guid_path"), fault)
    })?;
    for (field, actual, expected) in [
        (
            "scanner_profile",
            scope.scanner_profile.as_str(),
            WINDOWS_TOPOLOGY_PROFILE,
        ),
        (
            "machine_forms_profile",
            scope.machine_forms_profile.as_str(),
            PHASE3_MACHINE_FORMS_PROFILE,
        ),
        (
            "topology_forms_profile",
            scope.topology_forms_profile.as_str(),
            TOPOLOGY_FORMS_PROFILE,
        ),
        (
            "topology_receipt_profile",
            scope.topology_receipt_profile.as_str(),
            TOPOLOGY_RECEIPT_PROFILE,
        ),
        (
            "assembly_profile",
            scope.assembly_profile.as_str(),
            WINDOWS_SUPPLIED_TOPOLOGY_INVENTORY_ASSEMBLY_PROFILE,
        ),
        (
            "digest_profile",
            scope.digest_profile.as_str(),
            WINDOWS_SUPPLIED_ORDERED_TOPOLOGY_INVENTORY_DIGEST_PROFILE,
        ),
        (
            "reconciliation_profile",
            scope.reconciliation_profile.as_str(),
            WINDOWS_SUPPLIED_ORDERED_TOPOLOGY_INVENTORY_DIGEST_RECONCILIATION_PROFILE,
        ),
        (
            "encoding_profile",
            scope.encoding_profile.as_str(),
            ORDERED_TOPOLOGY_OBSERVATION_ENCODING_PROFILE,
        ),
        (
            "predecessor_admission_profile",
            scope.predecessor_admission_profile.as_str(),
            CANDIDATE_WORKSPACE_ADMISSION_PROFILE,
        ),
    ] {
        validate_exact_profile(&format!("{role}.scope.{field}"), actual, expected)?;
    }
    scope
        .limits
        .validate()
        .map_err(|fault| topology_scope_fault(&format!("{role}.scope.limits"), fault))?;
    validate_digest(&format!("{role}.scope.policy_sha256"), &scope.policy_sha256)?;
    validate_digest(
        &format!("{role}.scope.predecessor_receipt_sha256"),
        &scope.predecessor_receipt_sha256,
    )?;
    Ok(())
}

fn validate_order(
    pair: &OrderedAcquisitionPairMetadataClaim,
) -> Result<(), AcquisitionLineageFault> {
    if pair.causal_order.kind != CausalOrderKind::FirstCompletionStrictlyPrecedesSecondStart {
        return Err(AcquisitionLineageFault::simple(
            AcquisitionLineageFaultCode::Order,
            "pair.causal_order.kind",
            "unsupported causal order kind",
        ));
    }
    if pair.causal_order.first_acquisition_identity != pair.first.identity
        || pair.causal_order.second_acquisition_identity != pair.second.identity
    {
        return Err(AcquisitionLineageFault::simple(
            AcquisitionLineageFaultCode::Order,
            "pair.causal_order",
            "causal endpoints must match exact First and Second acquisition identities",
        ));
    }
    Ok(())
}

fn validate_carrier(
    role: &str,
    scope: &AcquisitionScopeClaim,
    carrier: &WindowsSuppliedOrderedTopologyInventoryDigest,
) -> Result<(), AcquisitionLineageFault> {
    if carrier.profile() != scope.digest_profile
        || carrier.profile() != WINDOWS_SUPPLIED_ORDERED_TOPOLOGY_INVENTORY_DIGEST_PROFILE
    {
        return Err(scope_mismatch(role, "digest_profile"));
    }
    if carrier.encoding_profile() != scope.encoding_profile
        || carrier.encoding_profile() != ORDERED_TOPOLOGY_OBSERVATION_ENCODING_PROFILE
    {
        return Err(scope_mismatch(role, "encoding_profile"));
    }
    if carrier.assembly().profile() != scope.assembly_profile
        || carrier.assembly().profile() != WINDOWS_SUPPLIED_TOPOLOGY_INVENTORY_ASSEMBLY_PROFILE
    {
        return Err(scope_mismatch(role, "assembly_profile"));
    }
    if carrier.assembly().plan().limits != scope.limits {
        return Err(scope_mismatch(role, "limits"));
    }
    let root = carrier
        .assembly()
        .ordered_members()
        .first()
        .ok_or_else(|| scope_mismatch(role, "root"))?
        .topology_observation();
    if root.relative_path.is_some() {
        return Err(scope_mismatch(role, "root.relative_path"));
    }
    if root.kind != TopologyEntryKind::RootDirectory {
        return Err(scope_mismatch(role, "root.kind"));
    }
    if root.identity != scope.root_identity {
        return Err(scope_mismatch(role, "root.identity"));
    }
    Ok(())
}

fn rederive_carrier(
    role: &str,
    carrier: &WindowsSuppliedOrderedTopologyInventoryDigest,
) -> Result<WindowsSuppliedOrderedTopologyInventoryDigest, AcquisitionLineageFault> {
    let rederived = derive_windows_supplied_ordered_topology_inventory_digest(
        carrier.plan().clone(),
        carrier.assembly().clone(),
    )
    .map_err(|fault| AcquisitionLineageFault::digest(role, fault))?;
    if rederived != *carrier {
        return Err(AcquisitionLineageFault::simple(
            AcquisitionLineageFaultCode::Lineage,
            role,
            "current carrier rederivation contradicted the supplied complete carrier",
        ));
    }
    Ok(rederived)
}

fn validate_reconciliation_scope(
    scope: &AcquisitionScopeClaim,
    reconciliation: &WindowsSuppliedOrderedTopologyInventoryDigestReconciliation,
) -> Result<(), AcquisitionLineageFault> {
    if reconciliation.profile() != scope.reconciliation_profile
        || reconciliation.profile()
            != WINDOWS_SUPPLIED_ORDERED_TOPOLOGY_INVENTORY_DIGEST_RECONCILIATION_PROFILE
    {
        return Err(scope_mismatch("reconciliation", "profile"));
    }
    let common = reconciliation.common_scope();
    if common.encoding_profile() != scope.encoding_profile
        || common.limits() != &scope.limits
        || common.root_relative_path().is_some()
        || common.root_kind() != TopologyEntryKind::RootDirectory
        || common.root_volume_serial() != scope.root_identity.volume_serial
        || common.root_file_id() != scope.root_identity.file_id_hex
    {
        return Err(scope_mismatch("reconciliation", "common_scope"));
    }
    Ok(())
}

fn validate_exact_profile(
    field: &str,
    actual: &str,
    expected: &str,
) -> Result<(), AcquisitionLineageFault> {
    validate_text(field, actual, MAX_PROFILE_BYTES)?;
    if actual != expected {
        return Err(AcquisitionLineageFault::simple(
            AcquisitionLineageFaultCode::Profile,
            field,
            "profile is not the exact supported value",
        ));
    }
    Ok(())
}

fn validate_text(
    field: &str,
    value: &str,
    maximum_bytes: usize,
) -> Result<(), AcquisitionLineageFault> {
    if value.is_empty() || value.len() > maximum_bytes || value.contains('\0') {
        return Err(AcquisitionLineageFault::simple(
            AcquisitionLineageFaultCode::Resource,
            field,
            "text is empty, contains NUL, or exceeds its UTF-8 byte bound",
        ));
    }
    Ok(())
}

fn validate_digest(field: &str, value: &str) -> Result<(), AcquisitionLineageFault> {
    if value.len() != DIGEST_HEX_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(AcquisitionLineageFault::simple(
            AcquisitionLineageFaultCode::Scope,
            field,
            "digest must be exact lowercase 64-character hexadecimal",
        ));
    }
    Ok(())
}

fn topology_scope_fault(field: &str, fault: TopologyFormFault) -> AcquisitionLineageFault {
    AcquisitionLineageFault::simple(
        AcquisitionLineageFaultCode::Scope,
        field,
        &format!("current topology form rejected: {fault}"),
    )
}

fn scope_mismatch(role: &str, coordinate: &str) -> AcquisitionLineageFault {
    AcquisitionLineageFault::simple(
        AcquisitionLineageFaultCode::Scope,
        &format!("{role}.{coordinate}"),
        "carrier-exposed coordinate differs from the complete metadata scope",
    )
}

fn bounded(value: &str, maximum_chars: usize) -> String {
    value.chars().take(maximum_chars).collect()
}

#[cfg(test)]
mod tests {
    use serde::de::DeserializeOwned;

    use super::*;
    use crate::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, PlatformPreflightDisposition,
        TopologyModeClass, WINDOWS_PLATFORM_PREFLIGHT_PROFILE, WINDOWS_PLATFORM_PREFLIGHT_TARGET,
        WindowsEntryPolicyKind, WindowsPlatformPreflightRecord, WindowsVolumeInformation,
        windows_supplied_content_digest::{
            WINDOWS_SUPPLIED_CONTENT_DIGEST_PROFILE, WindowsSuppliedContentDigestPlan,
            begin_windows_supplied_content_digest, bind_windows_supplied_content_digest,
        },
        windows_supplied_directory_topology_projection::{
            WINDOWS_SUPPLIED_DIRECTORY_TOPOLOGY_PROJECTION_PROFILE,
            WindowsSuppliedDirectoryTopologyProjectionPlan,
            project_windows_supplied_directory_topology,
        },
        windows_supplied_entry_observation::{
            WINDOWS_SUPPLIED_ENTRY_OBSERVATION_PROFILE, WindowsSuppliedAttributeTagRecord,
            WindowsSuppliedCaseSensitivityRecord, WindowsSuppliedDirectoryCaseFlags,
            WindowsSuppliedEntryAssemblyInput, WindowsSuppliedFileIdentityRecord,
            WindowsSuppliedRecordCorrelation, WindowsSuppliedStandardInformationRecord,
            WindowsSuppliedStreamSet,
        },
        windows_supplied_entry_stability::{
            WINDOWS_SUPPLIED_ENTRY_STABILITY_PROFILE, WindowsSuppliedEntryStabilityInput,
        },
        windows_supplied_ordered_topology_inventory_digest::{
            WindowsSuppliedOrderedTopologyInventoryDigestPlan,
            decode_windows_supplied_ordered_topology_inventory_digest_plan,
        },
        windows_supplied_ordered_topology_inventory_digest_reconciliation::decode_windows_supplied_ordered_topology_inventory_digest_reconciliation_plan,
        windows_supplied_regular_file_topology_projection::{
            WINDOWS_SUPPLIED_REGULAR_FILE_TOPOLOGY_PROJECTION_PROFILE,
            WindowsSuppliedRegularFileTopologyProjectionPlan,
            project_windows_supplied_regular_file_topology,
        },
        windows_supplied_root_topology_projection::{
            WINDOWS_SUPPLIED_ROOT_TOPOLOGY_PROJECTION_PROFILE,
            WindowsSuppliedRootTopologyProjectionPlan, project_windows_supplied_root_topology,
        },
        windows_supplied_topology_inventory_assembly::{
            WindowsSuppliedTopologyInventoryAssembly, WindowsSuppliedTopologyInventoryAssemblyPlan,
            assemble_windows_supplied_topology_inventory,
        },
    };

    const GUID_ROOT: &str = r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\";

    macro_rules! assert_not_deserialize_owned {
        ($ty:ty) => {
            const _: fn() = || {
                struct IfImpl;
                trait AmbiguousIfImpl<A> {
                    fn check() {}
                }
                impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
                impl<T: ?Sized + DeserializeOwned> AmbiguousIfImpl<IfImpl> for T {}
                let _ = <$ty as AmbiguousIfImpl<_>>::check;
            };
        };
    }

    assert_not_deserialize_owned!(WindowsSuppliedOrderedTopologyInventoryDigest);
    assert_not_deserialize_owned!(AcquisitionLineageBinding);
    assert_not_deserialize_owned!(OrderedAcquisitionPairBinding);
    assert_not_deserialize_owned!(WindowsSuppliedOrderedTopologyInventoryDigestReconciliation);
    assert_not_deserialize_owned!(RepeatedInventoryEvidenceClaim);

    fn assert_metadata<T: Serialize + DeserializeOwned>() {}

    fn limits() -> TopologyScanLimits {
        TopologyScanLimits {
            maximum_entries: 64,
            maximum_depth: 16,
            maximum_path_bytes: 1_024,
            maximum_file_bytes: 1_024,
            maximum_total_bytes: 4_096,
            maximum_streams_per_entry: 16,
            deadline_tick: 1,
        }
    }

    fn identity(volume: u64, seed: u8) -> StrongFileIdentity {
        StrongFileIdentity {
            volume_serial: volume,
            file_id_hex: (seed..seed + 16)
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        }
    }

    fn scope() -> AcquisitionScopeClaim {
        AcquisitionScopeClaim {
            candidate_root: r"C:\Cantor".to_owned(),
            root_identity: identity(19, 0),
            root_volume_guid_path: format!("{GUID_ROOT}Cantor"),
            scanner_profile: WINDOWS_TOPOLOGY_PROFILE.to_owned(),
            machine_forms_profile: PHASE3_MACHINE_FORMS_PROFILE.to_owned(),
            topology_forms_profile: TOPOLOGY_FORMS_PROFILE.to_owned(),
            topology_receipt_profile: TOPOLOGY_RECEIPT_PROFILE.to_owned(),
            assembly_profile: WINDOWS_SUPPLIED_TOPOLOGY_INVENTORY_ASSEMBLY_PROFILE.to_owned(),
            digest_profile: WINDOWS_SUPPLIED_ORDERED_TOPOLOGY_INVENTORY_DIGEST_PROFILE.to_owned(),
            reconciliation_profile:
                WINDOWS_SUPPLIED_ORDERED_TOPOLOGY_INVENTORY_DIGEST_RECONCILIATION_PROFILE.to_owned(),
            encoding_profile: ORDERED_TOPOLOGY_OBSERVATION_ENCODING_PROFILE.to_owned(),
            limits: limits(),
            policy_sha256: "a".repeat(64),
            predecessor_admission_profile: CANDIDATE_WORKSPACE_ADMISSION_PROFILE.to_owned(),
            predecessor_receipt_sha256: "b".repeat(64),
        }
    }

    fn reconciliation_plan(
        identity: u64,
    ) -> WindowsSuppliedOrderedTopologyInventoryDigestReconciliationPlan {
        let bytes = serde_json::to_vec(&serde_json::json!({
            "profile": WINDOWS_SUPPLIED_ORDERED_TOPOLOGY_INVENTORY_DIGEST_RECONCILIATION_PROFILE,
            "reconciliation_identity": identity,
        }))
        .unwrap();
        decode_windows_supplied_ordered_topology_inventory_digest_reconciliation_plan(&bytes)
            .unwrap()
    }

    fn plan(first: u64, second: u64) -> RepeatedInventoryEvidencePlan {
        let first_metadata = AcquisitionLineageMetadataClaim {
            identity: AcquisitionIdentity { value: first },
            scope: scope(),
            completion: CompletionDisposition::CompleteClaimed,
        };
        let second_metadata = AcquisitionLineageMetadataClaim {
            identity: AcquisitionIdentity { value: second },
            scope: scope(),
            completion: CompletionDisposition::CompleteClaimed,
        };
        RepeatedInventoryEvidencePlan {
            profile: WINDOWS_TOPOLOGY_ACQUISITION_LINEAGE_PROFILE.to_owned(),
            pair: OrderedAcquisitionPairMetadataClaim {
                first: first_metadata,
                second: second_metadata,
                causal_order: CausalOrderClaim {
                    first_acquisition_identity: AcquisitionIdentity { value: first },
                    second_acquisition_identity: AcquisitionIdentity { value: second },
                    kind: CausalOrderKind::FirstCompletionStrictlyPrecedesSecondStart,
                },
            },
            reconciliation_plan: reconciliation_plan(900),
            requested_evidence: InventoryConsistencyEvidence::NonAtomicRepeatedInventoryEqual,
        }
    }

    fn digest_plan(identity: u64) -> WindowsSuppliedOrderedTopologyInventoryDigestPlan {
        let bytes = serde_json::to_vec(&serde_json::json!({
            "profile": WINDOWS_SUPPLIED_ORDERED_TOPOLOGY_INVENTORY_DIGEST_PROFILE,
            "commitment_identity": identity,
            "encoding_profile": ORDERED_TOPOLOGY_OBSERVATION_ENCODING_PROFILE,
        }))
        .unwrap();
        decode_windows_supplied_ordered_topology_inventory_digest_plan(&bytes).unwrap()
    }

    fn correlation(batch: u64, entry: u64) -> WindowsSuppliedRecordCorrelation {
        WindowsSuppliedRecordCorrelation {
            batch_identity: batch,
            entry_reference_identity: entry,
        }
    }

    fn assembly_input(
        batch: u64,
        entry: u64,
        component: &str,
        kind: WindowsEntryPolicyKind,
        volume: u64,
        seed: u8,
        length: u64,
    ) -> WindowsSuppliedEntryAssemblyInput {
        let correlation = correlation(batch, entry);
        let directory = kind == WindowsEntryPolicyKind::Directory;
        WindowsSuppliedEntryAssemblyInput {
            profile: WINDOWS_SUPPLIED_ENTRY_OBSERVATION_PROFILE.to_owned(),
            kind,
            component: component.to_owned(),
            maximum_component_utf16_units: 32_767,
            attribute_tag: WindowsSuppliedAttributeTagRecord {
                correlation,
                attributes: if directory {
                    FILE_ATTRIBUTE_DIRECTORY
                } else {
                    FILE_ATTRIBUTE_NORMAL
                },
                reparse_tag: 0,
            },
            file_identity: WindowsSuppliedFileIdentityRecord {
                correlation,
                volume_serial: volume,
                file_id_bytes: (seed..seed + 16).collect(),
            },
            standard: WindowsSuppliedStandardInformationRecord {
                correlation,
                allocation_size: i64::try_from(length).unwrap(),
                end_of_file: i64::try_from(length).unwrap(),
                number_of_links: 1,
                delete_pending: false,
                directory,
            },
            case_sensitivity: if directory {
                WindowsSuppliedCaseSensitivityRecord::DirectoryFlags(
                    WindowsSuppliedDirectoryCaseFlags {
                        correlation,
                        flags: 0,
                    },
                )
            } else {
                WindowsSuppliedCaseSensitivityRecord::NotApplicable(correlation)
            },
            streams: WindowsSuppliedStreamSet::ExplicitEmpty(correlation),
        }
    }

    fn stability_input(
        entry: u64,
        component: &str,
        kind: WindowsEntryPolicyKind,
        volume: u64,
        seed: u8,
        length: u64,
    ) -> WindowsSuppliedEntryStabilityInput {
        WindowsSuppliedEntryStabilityInput {
            profile: WINDOWS_SUPPLIED_ENTRY_STABILITY_PROFILE.to_owned(),
            reconciliation_identity: entry + 1_000,
            pre_read: assembly_input(entry + 100, entry, component, kind, volume, seed, length),
            post_read: assembly_input(entry + 200, entry, component, kind, volume, seed, length),
        }
    }

    fn root(
        projection: u64,
        entry: u64,
        volume: u64,
        seed: u8,
    ) -> crate::windows_supplied_root_topology_projection::WindowsSuppliedRootTopologyProjection
    {
        project_windows_supplied_root_topology(
            WindowsSuppliedRootTopologyProjectionPlan {
                profile: WINDOWS_SUPPLIED_ROOT_TOPOLOGY_PROJECTION_PROFILE.to_owned(),
                projection_identity: projection,
                entry_reference_identity: entry,
            },
            WindowsPlatformPreflightRecord::CompleteLocal {
                profile: WINDOWS_PLATFORM_PREFLIGHT_PROFILE.to_owned(),
                target_triple: WINDOWS_PLATFORM_PREFLIGHT_TARGET.to_owned(),
                input_root: r"\\?\C:\Cantor".to_owned(),
                root_identity: identity(volume, seed),
                root_volume_guid_path: format!("{GUID_ROOT}Cantor"),
                volume: WindowsVolumeInformation {
                    volume_name: "Work".to_owned(),
                    volume_serial_number: 42,
                    maximum_component_length: 255,
                    file_system_flags: 0,
                    file_system_name: "NTFS".to_owned(),
                },
                disposition: PlatformPreflightDisposition::EligibleLocalNtfs,
            },
            stability_input(
                entry,
                "Cantor",
                WindowsEntryPolicyKind::Directory,
                volume,
                seed,
                0,
            ),
        )
        .unwrap()
    }

    fn directory(
        projection: u64,
        entry: u64,
    ) -> crate::windows_supplied_directory_topology_projection::WindowsSuppliedDirectoryTopologyProjection{
        project_windows_supplied_directory_topology(
            WindowsSuppliedDirectoryTopologyProjectionPlan {
                profile: WINDOWS_SUPPLIED_DIRECTORY_TOPOLOGY_PROJECTION_PROFILE.to_owned(),
                projection_identity: projection,
                entry_reference_identity: entry,
                relative_path: "src".to_owned(),
                observation_ordinal: 2,
            },
            stability_input(entry, "src", WindowsEntryPolicyKind::Directory, 19, 16, 0),
        )
        .unwrap()
    }

    fn regular_file(
        projection: u64,
        entry: u64,
        bytes: &[u8],
    ) -> crate::windows_supplied_regular_file_topology_projection::WindowsSuppliedRegularFileTopologyProjection{
        let digest_plan = WindowsSuppliedContentDigestPlan {
            profile: WINDOWS_SUPPLIED_CONTENT_DIGEST_PROFILE.to_owned(),
            content_read_identity: entry + 2_000,
            entry_reference_identity: entry,
            expected_content_length: u64::try_from(bytes.len()).unwrap(),
            maximum_content_bytes: u64::try_from(bytes.len()).unwrap().max(1),
            maximum_chunks: 8,
        };
        let accumulator = begin_windows_supplied_content_digest(digest_plan).unwrap();
        let digest = if bytes.is_empty() {
            accumulator.finish().unwrap()
        } else {
            accumulator.push_chunk(bytes).unwrap().finish().unwrap()
        };
        let binding = bind_windows_supplied_content_digest(
            digest,
            stability_input(
                entry,
                "a.txt",
                WindowsEntryPolicyKind::RegularFile,
                19,
                32,
                u64::try_from(bytes.len()).unwrap(),
            ),
        )
        .unwrap();
        project_windows_supplied_regular_file_topology(
            WindowsSuppliedRegularFileTopologyProjectionPlan {
                profile: WINDOWS_SUPPLIED_REGULAR_FILE_TOPOLOGY_PROJECTION_PROFILE.to_owned(),
                projection_identity: projection,
                entry_reference_identity: entry,
                relative_path: "src/a.txt".to_owned(),
                mode_class: TopologyModeClass::RegularNonExecutable,
                observation_ordinal: 3,
            },
            binding,
        )
        .unwrap()
    }

    fn assembly(
        lineage: u64,
        scan_limits: TopologyScanLimits,
        root_volume: u64,
        root_seed: u8,
        content: Option<&[u8]>,
    ) -> WindowsSuppliedTopologyInventoryAssembly {
        let base = lineage * 100;
        let (directories, files) = match content {
            Some(bytes) => (
                vec![directory(base + 2, base + 12)],
                vec![regular_file(base + 3, base + 13, bytes)],
            ),
            None => (vec![], vec![]),
        };
        assemble_windows_supplied_topology_inventory(
            WindowsSuppliedTopologyInventoryAssemblyPlan {
                profile: WINDOWS_SUPPLIED_TOPOLOGY_INVENTORY_ASSEMBLY_PROFILE.to_owned(),
                assembly_identity: base + 91,
                limits: scan_limits,
            },
            root(base + 1, base + 11, root_volume, root_seed),
            directories,
            files,
        )
        .unwrap()
    }

    fn carrier(
        commitment: u64,
        lineage: u64,
        root_volume: u64,
        root_seed: u8,
        content: Option<&[u8]>,
    ) -> WindowsSuppliedOrderedTopologyInventoryDigest {
        derive_windows_supplied_ordered_topology_inventory_digest(
            digest_plan(commitment),
            assembly(lineage, limits(), root_volume, root_seed, content),
        )
        .unwrap()
    }

    fn assert_round_trip<T>(value: &T)
    where
        T: Serialize + DeserializeOwned + PartialEq + fmt::Debug,
    {
        let bytes = serde_json::to_vec(value).unwrap();
        let decoded: T = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(&decoded, value);
    }

    #[test]
    fn metadata_types_round_trip_and_trait_boundary_compiles() {
        assert_metadata::<AcquisitionIdentity>();
        assert_metadata::<AcquisitionScopeClaim>();
        assert_metadata::<CompletionDisposition>();
        assert_metadata::<AcquisitionLineageMetadataClaim>();
        assert_metadata::<CausalOrderKind>();
        assert_metadata::<CausalOrderClaim>();
        assert_metadata::<OrderedAcquisitionPairMetadataClaim>();
        assert_metadata::<RepeatedInventoryEvidencePlan>();

        let value = plan(1, 2);
        assert_round_trip(value.pair.first.identity());
        assert_round_trip(value.pair.first.scope());
        assert_round_trip(&value.pair.first.completion());
        assert_round_trip(value.pair.first());
        assert_round_trip(&value.pair.causal_order.kind());
        assert_round_trip(value.pair.causal_order());
        assert_round_trip(value.pair());
        assert_round_trip(&value);
    }

    #[test]
    fn plan_decode_is_strict_bounded_and_validated() {
        let valid = plan(1, 2);
        let bytes = serde_json::to_vec(&valid).unwrap();
        assert_eq!(
            decode_repeated_inventory_evidence_plan(&bytes).unwrap(),
            valid
        );

        let unknown = String::from_utf8(bytes)
            .unwrap()
            .replacen('{', "{\"unknown\":true,", 1);
        assert_eq!(
            decode_repeated_inventory_evidence_plan(unknown.as_bytes())
                .unwrap_err()
                .code,
            AcquisitionLineageFaultCode::InvalidRequest
        );
        let oversized = vec![b' '; REPEATED_INVENTORY_EVIDENCE_PLAN_MAX_BYTES + 1];
        assert_eq!(
            decode_repeated_inventory_evidence_plan(&oversized)
                .unwrap_err()
                .code,
            AcquisitionLineageFaultCode::Resource
        );
    }

    #[test]
    fn equal_carriers_release_complete_claim_only_binding() {
        let first = carrier(701, 1, 19, 0, Some(b"abc"));
        let second = carrier(702, 2, 19, 0, Some(b"abc"));
        let result =
            derive_repeated_inventory_evidence_claim(plan(1, 2), first.clone(), second.clone())
                .unwrap();
        assert_eq!(
            result.profile(),
            WINDOWS_TOPOLOGY_ACQUISITION_LINEAGE_PROFILE
        );
        assert_eq!(result.pair().first().metadata().identity().value(), 1);
        assert_eq!(result.pair().second().metadata().identity().value(), 2);
        assert_eq!(result.pair().first().carrier(), &first);
        assert_eq!(result.pair().second().carrier(), &second);
        assert_eq!(
            result.reconciliation().disposition(),
            WindowsSuppliedOrderedTopologyInventoryDigestReconciliationDisposition::Equal
        );
        assert_eq!(
            result.requested_evidence(),
            InventoryConsistencyEvidence::NonAtomicRepeatedInventoryEqual
        );
        assert_eq!(
            result.provenance(),
            AcquisitionEvidenceProvenanceGrade::ClaimOnly
        );
    }

    #[test]
    fn different_is_a_distinct_atomic_denial() {
        let fault = derive_repeated_inventory_evidence_claim(
            plan(1, 2),
            carrier(701, 1, 19, 0, Some(b"abc")),
            carrier(702, 2, 19, 0, Some(b"abd")),
        )
        .unwrap_err();
        assert_eq!(fault.code, AcquisitionLineageFaultCode::Different);
        assert!(fault.nested_digest_fault.is_none());
        assert!(fault.nested_reconciliation_fault.is_none());
    }

    #[test]
    fn identity_scope_order_and_grade_fail_closed() {
        let mut value = plan(1, 2);
        value.pair.first.identity.value = 0;
        assert_eq!(
            validate_plan(&value).unwrap_err().code,
            AcquisitionLineageFaultCode::Identity
        );

        let mut value = plan(1, 1);
        value.pair.causal_order.second_acquisition_identity.value = 1;
        assert_eq!(
            validate_plan(&value).unwrap_err().code,
            AcquisitionLineageFaultCode::Identity
        );

        let mut value = plan(1, 2);
        value.pair.causal_order.first_acquisition_identity.value = 2;
        assert_eq!(
            validate_plan(&value).unwrap_err().code,
            AcquisitionLineageFaultCode::Order
        );

        let mut value = plan(1, 2);
        value.pair.second.scope.policy_sha256 = "c".repeat(64);
        assert_eq!(
            validate_plan(&value).unwrap_err().code,
            AcquisitionLineageFaultCode::Scope
        );

        let mut value = plan(1, 2);
        value.requested_evidence = InventoryConsistencyEvidence::OsSnapshotProven;
        assert_eq!(
            validate_plan(&value).unwrap_err().code,
            AcquisitionLineageFaultCode::Evidence
        );
    }

    #[test]
    fn every_metadata_only_coordinate_participates_in_scope_equality() {
        let mutations: [fn(&mut AcquisitionScopeClaim); 6] = [
            |value| value.candidate_root.push_str("-other"),
            |value| value.root_volume_guid_path = format!("{GUID_ROOT}Other"),
            |value| value.policy_sha256 = "c".repeat(64),
            |value| value.predecessor_receipt_sha256 = "d".repeat(64),
            |value| value.scanner_profile = "wrong".to_owned(),
            |value| value.predecessor_admission_profile = "wrong".to_owned(),
        ];
        for mutate in mutations {
            let mut value = plan(1, 2);
            mutate(&mut value.pair.second.scope);
            assert!(matches!(
                validate_plan(&value).unwrap_err().code,
                AcquisitionLineageFaultCode::Profile | AcquisitionLineageFaultCode::Scope
            ));
        }
    }

    #[test]
    fn all_complete_limit_coordinates_join_each_carrier() {
        let mutations: [fn(&mut TopologyScanLimits); 7] = [
            |value| value.maximum_entries += 1,
            |value| value.maximum_depth += 1,
            |value| value.maximum_path_bytes += 1,
            |value| value.maximum_file_bytes += 1,
            |value| value.maximum_total_bytes += 1,
            |value| value.maximum_streams_per_entry += 1,
            |value| value.deadline_tick += 1,
        ];
        for mutate in mutations {
            let mut value = plan(1, 2);
            mutate(&mut value.pair.first.scope.limits);
            value.pair.second.scope.limits = value.pair.first.scope.limits.clone();
            let fault = derive_repeated_inventory_evidence_claim(
                value,
                carrier(701, 1, 19, 0, None),
                carrier(702, 2, 19, 0, None),
            )
            .unwrap_err();
            assert_eq!(fault.code, AcquisitionLineageFaultCode::Scope);
            assert_eq!(fault.field, "first.limits");
        }
    }

    #[test]
    fn carrier_role_swap_with_exposed_scope_mismatch_refuses() {
        let fault = derive_repeated_inventory_evidence_claim(
            plan(1, 2),
            carrier(702, 2, 20, 1, None),
            carrier(701, 1, 19, 0, None),
        )
        .unwrap_err();
        assert_eq!(fault.code, AcquisitionLineageFaultCode::Scope);
        assert_eq!(fault.field, "first.root.identity");
    }

    #[test]
    fn carrier_profile_and_root_identity_joins_are_exact() {
        let mut value = plan(1, 2);
        value.pair.first.scope.encoding_profile = "wrong".to_owned();
        value.pair.second.scope.encoding_profile = "wrong".to_owned();
        assert_eq!(
            validate_plan(&value).unwrap_err().code,
            AcquisitionLineageFaultCode::Profile
        );

        let fault = derive_repeated_inventory_evidence_claim(
            plan(1, 2),
            carrier(701, 1, 19, 1, None),
            carrier(702, 2, 19, 1, None),
        )
        .unwrap_err();
        assert_eq!(fault.code, AcquisitionLineageFaultCode::Scope);
        assert_eq!(fault.field, "first.root.identity");
    }

    #[test]
    fn metadata_bounds_and_digest_grammar_refuse() {
        let mut value = plan(1, 2);
        value.pair.first.scope.candidate_root = "x".repeat(MAX_PATH_BYTES + 1);
        assert_eq!(
            validate_plan(&value).unwrap_err().code,
            AcquisitionLineageFaultCode::Resource
        );

        let mut value = plan(1, 2);
        value.pair.first.scope.policy_sha256 = "A".repeat(64);
        assert_eq!(
            validate_plan(&value).unwrap_err().code,
            AcquisitionLineageFaultCode::Scope
        );
    }

    #[test]
    fn output_serialization_is_deterministic_and_complete() {
        let result = derive_repeated_inventory_evidence_claim(
            plan(1, 2),
            carrier(701, 1, 19, 0, None),
            carrier(702, 2, 19, 0, None),
        )
        .unwrap();
        let first = serde_json::to_vec(&result).unwrap();
        let second = serde_json::to_vec(&result).unwrap();
        assert_eq!(first, second);
        let value: serde_json::Value = serde_json::from_slice(&first).unwrap();
        assert_eq!(
            value["profile"],
            WINDOWS_TOPOLOGY_ACQUISITION_LINEAGE_PROFILE
        );
        assert_eq!(value["pair"]["first"]["metadata"]["identity"]["value"], 1);
        assert_eq!(value["pair"]["second"]["metadata"]["identity"]["value"], 2);
        assert_eq!(value["reconciliation"]["disposition"], "equal");
        assert_eq!(value["provenance"], "claim_only");
    }

    #[test]
    fn faults_are_bounded_and_atomic() {
        let fault = AcquisitionLineageFault::simple(
            AcquisitionLineageFaultCode::InvalidRequest,
            &"f".repeat(100),
            &"m".repeat(300),
        );
        assert_eq!(fault.field.chars().count(), 64);
        assert_eq!(fault.message.chars().count(), 256);
        assert!(fault.nested_digest_fault.is_none());
        assert!(fault.nested_reconciliation_fault.is_none());
    }

    #[test]
    fn module_and_export_remain_pure_and_bounded() {
        let source = include_str!("windows_topology_acquisition_lineage.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production section");
        for forbidden in [
            "unsafe {",
            "cfg(windows)",
            "std::fs",
            "std::process",
            "std::time",
            "std::net",
            "std::env",
            "windows_sys",
            "TopologyReceipt {",
            "impl From<",
            "impl Into<",
        ] {
            assert!(
                !production.contains(forbidden),
                "forbidden surface {forbidden}"
            );
        }
        let lib = include_str!("lib.rs");
        assert_eq!(
            lib.matches("pub mod windows_topology_acquisition_lineage;")
                .count(),
            1
        );
    }
}
