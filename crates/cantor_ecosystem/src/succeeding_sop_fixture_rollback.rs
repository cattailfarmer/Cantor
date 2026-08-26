//! Recovery-owned synthetic-fixture-only SWA-06B2B2 rollback kernel.
//!
//! The kernel consumes one exact successful SWA-06B2B1 receipt, observes the
//! failed successor and preserved source bytes inside its explicitly marked
//! disposable fixture, and restores the predecessor under a new monotonic
//! registry generation. It stops awaiting boot validation and grants no live
//! activation, provider, process, network, cleanup, or boot authority.

use std::{
    collections::BTreeSet,
    fmt, fs,
    fs::OpenOptions,
    io::Write,
    path::{Component, Path, PathBuf},
};

use cantor_core::{
    ContentDigest, SUCCEEDING_SOP_CURRENT_REGISTRY_SNAPSHOT_PROFILE, SemanticId,
    SucceedingSopCurrentRegistrySnapshot, sha256_bytes,
    succeeding_sop_current_registry_snapshot_digest,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::succeeding_sop_fixture_persistence::{
    SUCCEEDING_SOP_FIXTURE_REGISTRY_RECORD_PROFILE, SUCCEEDING_SOP_FIXTURE_ROOT_MARKER_FILE,
    SucceedingSopFixturePersistenceAuthority, SucceedingSopFixturePersistenceReceipt,
    SucceedingSopFixturePersistenceStatus, SucceedingSopFixtureRegistryRecord,
    SucceedingSopFixtureRootMarker, from_succeeding_sop_fixture_registry_record_machine_form,
    from_succeeding_sop_fixture_root_marker_machine_form,
    succeeding_sop_fixture_registry_record_digest,
    to_succeeding_sop_fixture_registry_record_machine_form,
    validate_succeeding_sop_fixture_persistence_receipt,
    validate_succeeding_sop_fixture_registry_record, validate_succeeding_sop_fixture_root_marker,
};

pub const SUCCEEDING_SOP_FIXTURE_ROLLBACK_COMMISSION_PROFILE: &str =
    "cantor-succeeding-sop-fixture-rollback-commission/0.1";
pub const SUCCEEDING_SOP_FIXTURE_ROLLBACK_RECEIPT_PROFILE: &str =
    "cantor-succeeding-sop-fixture-rollback-receipt/0.1";
pub const SUCCEEDING_SOP_FIXTURE_ROLLBACK_TRIGGER: &str = "boot_validation_failed";
pub const SUCCEEDING_SOP_FIXTURE_ROLLBACK_MAX_MACHINE_FORM_BYTES: usize = 16 * 1024 * 1024;

const COMMISSION_DOMAIN: &str = "cantor.succeeding-sop.fixture-rollback.commission.v1";
const RECEIPT_DOMAIN: &str = "cantor.succeeding-sop.fixture-rollback.receipt.v1";
const MAX_EVIDENCE_REFS: usize = 32;

pub const SUCCEEDING_SOP_FIXTURE_ROLLBACK_CHECKS: [&str; 15] = [
    "atomic_replace",
    "authority_boundary",
    "candidate_preservation",
    "deterministic_digests",
    "file_flush",
    "final_reopen",
    "marker_correspondence",
    "monotonic_generation",
    "parent_flush",
    "predecessor_reacquisition",
    "registry_precondition",
    "root_boundary",
    "temp_create_new",
    "trigger_correspondence",
    "upstream_replay",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SucceedingSopFixtureRollbackCommission {
    pub profile: String,
    pub commission_ref: SemanticId,
    pub recovery_owner_ref: SemanticId,
    pub failed_snapshot_ref: SemanticId,
    pub restored_snapshot_ref: SemanticId,
    pub trigger: String,
    pub trigger_evidence_ref: SemanticId,
    pub persistence_receipt: SucceedingSopFixturePersistenceReceipt,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub fixture_only: bool,
    pub live_activation_allowed: bool,
    pub cleanup_authorized: bool,
    pub commission_digest: ContentDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SucceedingSopFixtureRollbackStatus {
    FixtureRegistryRolledBackAwaitingBootValidation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SucceedingSopFixtureRollbackAuthority {
    SyntheticFixtureRecoveryOnly,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SucceedingSopFixtureRollbackReceipt {
    pub profile: String,
    pub commission: SucceedingSopFixtureRollbackCommission,
    pub marker: SucceedingSopFixtureRootMarker,
    pub status: SucceedingSopFixtureRollbackStatus,
    pub authority: SucceedingSopFixtureRollbackAuthority,
    pub trigger: String,
    pub trigger_evidence_ref: SemanticId,
    pub current_failed_record: SucceedingSopFixtureRegistryRecord,
    pub restored_record: SucceedingSopFixtureRegistryRecord,
    pub upstream_receipt_digest: ContentDigest,
    pub predecessor_source_raw_digest: ContentDigest,
    pub failed_candidate_source_raw_digest: ContentDigest,
    pub failed_registry_raw_digest: ContentDigest,
    pub restored_registry_raw_digest: ContentDigest,
    pub verified_checks: BTreeSet<String>,
    pub physical_contact: bool,
    pub current_successor_observed: bool,
    pub predecessor_source_reacquired: bool,
    pub registry_persisted: bool,
    pub predecessor_selected: bool,
    pub rollback_executed: bool,
    pub failed_candidate_preserved: bool,
    pub temp_absent_after: bool,
    pub boot_activation_verified: bool,
    pub live_activation_performed: bool,
    pub provider_contacted: bool,
    pub model_called: bool,
    pub process_launched: bool,
    pub network_contacted: bool,
    pub cleanup_performed: bool,
    pub windows_durability_assumed: bool,
    pub receipt_digest: ContentDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SucceedingSopFixtureRollbackFaultCode {
    InvalidUpstream,
    InvalidMarker,
    InvalidCommission,
    InvalidTrigger,
    InvalidIdentity,
    InvalidRoot,
    InvalidPath,
    LinkOrReparse,
    InvalidSource,
    InvalidRegistry,
    InvalidGeneration,
    InvalidTemporary,
    Persistence,
    Durability,
    PostWriteVerification,
    InvalidDigest,
    InvalidBound,
    InvalidMachineForm,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SucceedingSopFixtureRollbackFault {
    pub code: SucceedingSopFixtureRollbackFaultCode,
    pub message: String,
    pub physical_contact: bool,
    pub replacement_performed: bool,
    pub owned_temp_removed: bool,
    pub failed_candidate_preserved: bool,
}

impl fmt::Display for SucceedingSopFixtureRollbackFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for SucceedingSopFixtureRollbackFault {}

pub fn execute_succeeding_sop_fixture_rollback(
    root: &Path,
    commission: &SucceedingSopFixtureRollbackCommission,
) -> Result<SucceedingSopFixtureRollbackReceipt, SucceedingSopFixtureRollbackFault> {
    validate_succeeding_sop_fixture_rollback_commission(commission)?;

    let root_metadata = fs::symlink_metadata(root).map_err(|error| {
        physical_fault(
            SucceedingSopFixtureRollbackFaultCode::InvalidRoot,
            format!("fixture root metadata failed: {error}"),
            false,
            false,
            false,
        )
    })?;
    if !root_metadata.is_dir() || is_link_or_reparse(&root_metadata) {
        return Err(physical_fault(
            SucceedingSopFixtureRollbackFaultCode::InvalidRoot,
            "fixture root is not one real directory",
            false,
            false,
            false,
        ));
    }
    let root = fs::canonicalize(root).map_err(|error| {
        physical_fault(
            SucceedingSopFixtureRollbackFaultCode::InvalidRoot,
            format!("fixture root canonicalization failed: {error}"),
            false,
            false,
            false,
        )
    })?;
    match fs::symlink_metadata(root.join(".git")) {
        Ok(_) => {
            return Err(physical_fault(
                SucceedingSopFixtureRollbackFaultCode::InvalidRoot,
                "fixture root contains a forbidden .git entry",
                false,
                false,
                false,
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(physical_fault(
                SucceedingSopFixtureRollbackFaultCode::InvalidRoot,
                format!("fixture root .git refusal check failed: {error}"),
                false,
                false,
                false,
            ));
        }
    }

    let marker_path = root.join(SUCCEEDING_SOP_FIXTURE_ROOT_MARKER_FILE);
    reject_link_or_reparse(&marker_path, "fixture marker")?;
    let marker_bytes = read_bounded(&marker_path, "fixture marker")?;
    let marker = from_succeeding_sop_fixture_root_marker_machine_form(
        std::str::from_utf8(&marker_bytes).map_err(|error| {
            physical_fault(
                SucceedingSopFixtureRollbackFaultCode::InvalidMachineForm,
                format!("fixture marker UTF-8 failed: {error}"),
                false,
                false,
                false,
            )
        })?,
    )
    .map_err(|error| {
        physical_fault(
            SucceedingSopFixtureRollbackFaultCode::InvalidMarker,
            error.to_string(),
            false,
            false,
            false,
        )
    })?;
    let upstream = &commission.persistence_receipt;
    if marker.marker_digest != upstream.marker_digest
        || marker.fixture_root_ref != upstream.commission.fixture_root_ref
        || marker.recovery_owner_ref != commission.recovery_owner_ref
    {
        return Err(physical_fault(
            SucceedingSopFixtureRollbackFaultCode::InvalidMarker,
            "physical marker differs from the exact upstream receipt",
            false,
            false,
            false,
        ));
    }

    let transaction = &upstream.commission.activation_transaction.request;
    let registry_path = resolve_existing_relative(
        &root,
        &transaction.transition.registry_final_path,
        "current failed registry",
    )?;
    let failed_registry_bytes = read_bounded(&registry_path, "current failed registry")?;
    if sha256_bytes(&failed_registry_bytes) != upstream.successor_registry_raw_digest {
        return Err(physical_fault(
            SucceedingSopFixtureRollbackFaultCode::InvalidRegistry,
            "current registry raw bytes differ from the exact B2B1 successor",
            false,
            false,
            false,
        ));
    }
    let failed_record = from_succeeding_sop_fixture_registry_record_machine_form(
        std::str::from_utf8(&failed_registry_bytes).map_err(|error| {
            physical_fault(
                SucceedingSopFixtureRollbackFaultCode::InvalidMachineForm,
                format!("current registry UTF-8 failed: {error}"),
                false,
                false,
                false,
            )
        })?,
    )
    .map_err(|error| {
        physical_fault(
            SucceedingSopFixtureRollbackFaultCode::InvalidRegistry,
            error.to_string(),
            false,
            false,
            false,
        )
    })?;
    if failed_record.record_digest != upstream.successor_record_digest
        || failed_record.fixture_root_ref != marker.fixture_root_ref
        || failed_record.activation_authority_ref
            != transaction.activation_policy.activation_authority_ref
        || failed_record.recovery_owner_ref != commission.recovery_owner_ref
        || failed_record.last_transaction_ref.as_ref()
            != Some(&transaction.transition.transaction_ref)
        || failed_record.current.snapshot_ref != commission.failed_snapshot_ref
        || failed_record.current.registry_ref != transaction.current_registry.registry_ref
        || failed_record.current.registry_path != transaction.transition.registry_final_path
        || failed_record.current.generation != transaction.rollback.expected_registry_generation
        || failed_record.current.current_revision_ref != transaction.rollback.failed_candidate_ref
        || failed_record.current.current_revision_digest
            != transaction.rollback.failed_candidate_digest
        || failed_record.current.current_source_path != transaction.transition.candidate_source_path
        || failed_record.current.current_source_bytes
            != transaction.source_reacquisition.source_bytes
    {
        return Err(physical_fault(
            SucceedingSopFixtureRollbackFaultCode::InvalidRegistry,
            "current registry is not the exact failed B2B1 successor",
            false,
            false,
            false,
        ));
    }

    let predecessor_path = resolve_existing_relative(
        &root,
        &transaction.rollback.rollback_source_path,
        "preserved predecessor source",
    )?;
    let predecessor_metadata = fs::metadata(&predecessor_path).map_err(|error| {
        physical_fault(
            SucceedingSopFixtureRollbackFaultCode::InvalidSource,
            format!("preserved predecessor metadata failed: {error}"),
            false,
            false,
            false,
        )
    })?;
    let predecessor_bytes = read_bounded(&predecessor_path, "preserved predecessor source")?;
    if predecessor_metadata.len() != transaction.rollback.rollback_source_bytes
        || predecessor_bytes.len() as u64 != transaction.rollback.rollback_source_bytes
        || sha256_bytes(&predecessor_bytes) != transaction.rollback.rollback_revision_digest
        || transaction.rollback.rollback_revision_ref
            != transaction.current_registry.current_revision_ref
        || transaction.rollback.rollback_revision_digest
            != transaction.current_registry.current_revision_digest
        || transaction.rollback.rollback_source_path
            != transaction.current_registry.current_source_path
    {
        return Err(physical_fault(
            SucceedingSopFixtureRollbackFaultCode::InvalidSource,
            "preserved predecessor raw-byte identity differs",
            false,
            false,
            false,
        ));
    }
    let candidate_path = resolve_existing_relative(
        &root,
        &transaction.transition.candidate_source_path,
        "failed candidate source",
    )?;
    let candidate_metadata = fs::metadata(&candidate_path).map_err(|error| {
        physical_fault(
            SucceedingSopFixtureRollbackFaultCode::InvalidSource,
            format!("failed candidate metadata failed: {error}"),
            false,
            false,
            true,
        )
    })?;
    let candidate_bytes = read_bounded(&candidate_path, "failed candidate source")?;
    if candidate_metadata.len() != transaction.source_reacquisition.source_bytes
        || candidate_bytes.len() as u64 != transaction.source_reacquisition.source_bytes
        || sha256_bytes(&candidate_bytes) != transaction.transition.candidate_source_sha256
        || transaction.transition.candidate_source_sha256
            != transaction.source_reacquisition.source_sha256
    {
        return Err(physical_fault(
            SucceedingSopFixtureRollbackFaultCode::InvalidSource,
            "failed candidate raw-byte identity or byte count differs",
            false,
            false,
            false,
        ));
    }

    let temp_path = resolve_absent_relative(
        &root,
        &transaction.transition.registry_temp_path,
        "rollback registry temporary path",
    )?;
    if registry_path.parent() != temp_path.parent() {
        return Err(physical_fault(
            SucceedingSopFixtureRollbackFaultCode::InvalidPath,
            "registry final and temporary physical parents differ",
            false,
            false,
            true,
        ));
    }
    let restored_record = build_restored_record(&marker, commission, &failed_record)?;
    let restored_form = to_succeeding_sop_fixture_registry_record_machine_form(&restored_record)
        .map_err(|error| {
            fault(
                SucceedingSopFixtureRollbackFaultCode::InvalidRegistry,
                error.to_string(),
            )
        })?;
    let mut restored_bytes = restored_form.into_bytes();
    restored_bytes.push(b'\n');

    let mut temporary = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)
        .map_err(|error| {
            physical_fault(
                SucceedingSopFixtureRollbackFaultCode::InvalidTemporary,
                format!("temporary create_new failed: {error}"),
                false,
                false,
                true,
            )
        })?;
    if let Err(error) = temporary.write_all(&restored_bytes) {
        return Err(pre_replace_fault(
            &temp_path,
            SucceedingSopFixtureRollbackFaultCode::Persistence,
            format!("temporary write failed: {error}"),
        ));
    }
    if let Err(error) = temporary.sync_all() {
        return Err(pre_replace_fault(
            &temp_path,
            SucceedingSopFixtureRollbackFaultCode::Durability,
            format!("temporary file flush failed: {error}"),
        ));
    }
    drop(temporary);
    reject_link_or_reparse(&temp_path, "owned rollback temporary registry").map_err(|error| {
        pre_replace_fault(
            &temp_path,
            SucceedingSopFixtureRollbackFaultCode::LinkOrReparse,
            error.to_string(),
        )
    })?;
    let temp_reopened =
        read_bounded(&temp_path, "owned rollback temporary registry").map_err(|error| {
            pre_replace_fault(
                &temp_path,
                SucceedingSopFixtureRollbackFaultCode::PostWriteVerification,
                error.to_string(),
            )
        })?;
    if temp_reopened != restored_bytes {
        return Err(pre_replace_fault(
            &temp_path,
            SucceedingSopFixtureRollbackFaultCode::PostWriteVerification,
            "temporary reopen bytes differ",
        ));
    }
    if let Err(error) = fs::rename(&temp_path, &registry_path) {
        return Err(pre_replace_fault(
            &temp_path,
            SucceedingSopFixtureRollbackFaultCode::Persistence,
            format!("same-volume registry replacement failed: {error}"),
        ));
    }
    let parent = registry_path.parent().ok_or_else(|| {
        physical_fault(
            SucceedingSopFixtureRollbackFaultCode::InvalidPath,
            "registry parent is absent after replacement",
            true,
            false,
            true,
        )
    })?;
    if let Err(error) = sync_directory(parent) {
        return Err(physical_fault(
            SucceedingSopFixtureRollbackFaultCode::Durability,
            format!("registry parent flush failed after replacement: {error}"),
            true,
            false,
            true,
        ));
    }
    reject_link_or_reparse(&registry_path, "restored registry").map_err(|error| {
        physical_fault(
            SucceedingSopFixtureRollbackFaultCode::LinkOrReparse,
            error.to_string(),
            true,
            false,
            true,
        )
    })?;
    let final_bytes = read_bounded(&registry_path, "restored registry").map_err(|error| {
        physical_fault(
            SucceedingSopFixtureRollbackFaultCode::PostWriteVerification,
            error.to_string(),
            true,
            false,
            true,
        )
    })?;
    let final_record = from_succeeding_sop_fixture_registry_record_machine_form(
        std::str::from_utf8(&final_bytes).map_err(|error| {
            physical_fault(
                SucceedingSopFixtureRollbackFaultCode::InvalidMachineForm,
                format!("restored registry UTF-8 failed: {error}"),
                true,
                false,
                true,
            )
        })?,
    )
    .map_err(|error| {
        physical_fault(
            SucceedingSopFixtureRollbackFaultCode::PostWriteVerification,
            error.to_string(),
            true,
            false,
            true,
        )
    })?;
    if final_bytes != restored_bytes || final_record != restored_record {
        return Err(physical_fault(
            SucceedingSopFixtureRollbackFaultCode::PostWriteVerification,
            "restored final reopen differs",
            true,
            false,
            true,
        ));
    }
    if fs::symlink_metadata(&temp_path).is_ok() {
        return Err(physical_fault(
            SucceedingSopFixtureRollbackFaultCode::PostWriteVerification,
            "temporary registry remains after replacement",
            true,
            false,
            true,
        ));
    }

    let mut receipt = SucceedingSopFixtureRollbackReceipt {
        profile: SUCCEEDING_SOP_FIXTURE_ROLLBACK_RECEIPT_PROFILE.to_owned(),
        commission: commission.clone(),
        marker,
        status: SucceedingSopFixtureRollbackStatus::FixtureRegistryRolledBackAwaitingBootValidation,
        authority: SucceedingSopFixtureRollbackAuthority::SyntheticFixtureRecoveryOnly,
        trigger: commission.trigger.clone(),
        trigger_evidence_ref: commission.trigger_evidence_ref.clone(),
        current_failed_record: failed_record,
        restored_record,
        upstream_receipt_digest: upstream.receipt_digest.clone(),
        predecessor_source_raw_digest: sha256_bytes(&predecessor_bytes),
        failed_candidate_source_raw_digest: sha256_bytes(&candidate_bytes),
        failed_registry_raw_digest: sha256_bytes(&failed_registry_bytes),
        restored_registry_raw_digest: sha256_bytes(&restored_bytes),
        verified_checks: required_checks(),
        physical_contact: true,
        current_successor_observed: true,
        predecessor_source_reacquired: true,
        registry_persisted: true,
        predecessor_selected: true,
        rollback_executed: true,
        failed_candidate_preserved: true,
        temp_absent_after: true,
        boot_activation_verified: false,
        live_activation_performed: false,
        provider_contacted: false,
        model_called: false,
        process_launched: false,
        network_contacted: false,
        cleanup_performed: false,
        windows_durability_assumed: false,
        receipt_digest: empty_digest(),
    };
    receipt.receipt_digest = succeeding_sop_fixture_rollback_receipt_digest(&receipt)?;
    validate_succeeding_sop_fixture_rollback_receipt(&receipt)?;
    Ok(receipt)
}

pub fn validate_succeeding_sop_fixture_rollback_commission(
    commission: &SucceedingSopFixtureRollbackCommission,
) -> Result<(), SucceedingSopFixtureRollbackFault> {
    if commission.profile != SUCCEEDING_SOP_FIXTURE_ROLLBACK_COMMISSION_PROFILE
        || !commission.fixture_only
        || commission.live_activation_allowed
        || commission.cleanup_authorized
    {
        return Err(fault(
            SucceedingSopFixtureRollbackFaultCode::InvalidCommission,
            "rollback commission profile or authority boundary differs",
        ));
    }
    validate_succeeding_sop_fixture_persistence_receipt(&commission.persistence_receipt).map_err(
        |error| {
            fault(
                SucceedingSopFixtureRollbackFaultCode::InvalidUpstream,
                error.to_string(),
            )
        },
    )?;
    let upstream = &commission.persistence_receipt;
    if upstream.status
        != SucceedingSopFixturePersistenceStatus::FixtureRegistryPersistedAwaitingBootValidation
        || upstream.authority
            != SucceedingSopFixturePersistenceAuthority::SyntheticFixturePersistenceOnly
        || !upstream.registry_persisted
        || !upstream.current_sop_selected
        || upstream.boot_activation_verified
        || upstream.rollback_executed
        || upstream.live_activation_performed
        || upstream.provider_contacted
        || upstream.model_called
        || upstream.process_launched
        || upstream.network_contacted
        || upstream.cleanup_performed
    {
        return Err(fault(
            SucceedingSopFixtureRollbackFaultCode::InvalidUpstream,
            "upstream is not exact B2B1 synthetic success awaiting boot validation",
        ));
    }
    let request = &upstream.commission.activation_transaction.request;
    if commission.trigger != SUCCEEDING_SOP_FIXTURE_ROLLBACK_TRIGGER
        || !request
            .rollback
            .triggers
            .contains("boot_validation_failure")
    {
        return Err(fault(
            SucceedingSopFixtureRollbackFaultCode::InvalidTrigger,
            "P0 admits only the supplied boot-validation-failed correspondence",
        ));
    }
    if commission.recovery_owner_ref != upstream.commission.recovery_owner_ref
        || commission.recovery_owner_ref != request.activation_policy.recovery_owner_ref
        || commission.recovery_owner_ref != request.rollback.recovery_owner_ref
        || commission.failed_snapshot_ref != upstream.commission.successor_snapshot_ref
        || !request.rollback.preserve_failed_candidate
    {
        return Err(fault(
            SucceedingSopFixtureRollbackFaultCode::InvalidIdentity,
            "recovery owner, failed snapshot, or preservation identity differs",
        ));
    }
    validate_evidence(&commission.evidence_refs, "rollback commission evidence")?;
    let roles = [
        &commission.commission_ref,
        &commission.recovery_owner_ref,
        &commission.failed_snapshot_ref,
        &commission.restored_snapshot_ref,
        &commission.trigger_evidence_ref,
        &upstream.commission.fixture_root_ref,
        &request.activation_policy.activation_authority_ref,
        &request.rollback.rollback_ref,
        &request.transition.transaction_ref,
        &request.current_registry.snapshot_ref,
    ];
    let mut unique = BTreeSet::new();
    if roles
        .into_iter()
        .any(|identity| !unique.insert(identity.clone()))
        || commission
            .evidence_refs
            .iter()
            .any(|identity| unique.contains(identity))
    {
        return Err(fault(
            SucceedingSopFixtureRollbackFaultCode::InvalidIdentity,
            "rollback duty, snapshot, trigger, or evidence identities collide",
        ));
    }
    validate_digest(&commission.commission_digest, "rollback commission digest")?;
    if commission.commission_digest
        != succeeding_sop_fixture_rollback_commission_digest(commission)?
    {
        return Err(fault(
            SucceedingSopFixtureRollbackFaultCode::InvalidDigest,
            "rollback commission digest differs",
        ));
    }
    Ok(())
}

pub fn validate_succeeding_sop_fixture_rollback_receipt(
    receipt: &SucceedingSopFixtureRollbackReceipt,
) -> Result<(), SucceedingSopFixtureRollbackFault> {
    validate_succeeding_sop_fixture_rollback_commission(&receipt.commission)?;
    validate_succeeding_sop_fixture_root_marker(&receipt.marker).map_err(|error| {
        fault(
            SucceedingSopFixtureRollbackFaultCode::InvalidMarker,
            error.to_string(),
        )
    })?;
    validate_succeeding_sop_fixture_registry_record(&receipt.current_failed_record).map_err(
        |error| {
            fault(
                SucceedingSopFixtureRollbackFaultCode::InvalidRegistry,
                error.to_string(),
            )
        },
    )?;
    validate_succeeding_sop_fixture_registry_record(&receipt.restored_record).map_err(|error| {
        fault(
            SucceedingSopFixtureRollbackFaultCode::InvalidRegistry,
            error.to_string(),
        )
    })?;
    if receipt.profile != SUCCEEDING_SOP_FIXTURE_ROLLBACK_RECEIPT_PROFILE
        || receipt.status
            != SucceedingSopFixtureRollbackStatus::FixtureRegistryRolledBackAwaitingBootValidation
        || receipt.authority != SucceedingSopFixtureRollbackAuthority::SyntheticFixtureRecoveryOnly
        || receipt.trigger != receipt.commission.trigger
        || receipt.trigger_evidence_ref != receipt.commission.trigger_evidence_ref
        || receipt.verified_checks != required_checks()
        || !receipt.physical_contact
        || !receipt.current_successor_observed
        || !receipt.predecessor_source_reacquired
        || !receipt.registry_persisted
        || !receipt.predecessor_selected
        || !receipt.rollback_executed
        || !receipt.failed_candidate_preserved
        || !receipt.temp_absent_after
        || receipt.boot_activation_verified
        || receipt.live_activation_performed
        || receipt.provider_contacted
        || receipt.model_called
        || receipt.process_launched
        || receipt.network_contacted
        || receipt.cleanup_performed
        || receipt.windows_durability_assumed
    {
        return Err(fault(
            SucceedingSopFixtureRollbackFaultCode::InvalidCommission,
            "rollback receipt widens outcome or authority",
        ));
    }
    let upstream = &receipt.commission.persistence_receipt;
    let request = &upstream.commission.activation_transaction.request;
    let expected_generation = receipt
        .current_failed_record
        .current
        .generation
        .checked_add(1)
        .ok_or_else(|| {
            fault(
                SucceedingSopFixtureRollbackFaultCode::InvalidGeneration,
                "restored registry generation overflows",
            )
        })?;
    if receipt.marker.marker_digest != upstream.marker_digest
        || receipt.marker.fixture_root_ref != upstream.commission.fixture_root_ref
        || receipt.marker.recovery_owner_ref != receipt.commission.recovery_owner_ref
        || receipt.upstream_receipt_digest != upstream.receipt_digest
        || receipt.predecessor_source_raw_digest != request.rollback.rollback_revision_digest
        || receipt.failed_candidate_source_raw_digest != request.transition.candidate_source_sha256
        || receipt.failed_registry_raw_digest != upstream.successor_registry_raw_digest
        || receipt.current_failed_record.record_digest != upstream.successor_record_digest
        || receipt.current_failed_record.fixture_root_ref != receipt.marker.fixture_root_ref
        || receipt.current_failed_record.activation_authority_ref
            != request.activation_policy.activation_authority_ref
        || receipt.current_failed_record.recovery_owner_ref != receipt.commission.recovery_owner_ref
        || receipt.current_failed_record.last_transaction_ref.as_ref()
            != Some(&request.transition.transaction_ref)
        || receipt.current_failed_record.current.generation
            != request.rollback.expected_registry_generation
        || receipt.current_failed_record.current.snapshot_ref
            != receipt.commission.failed_snapshot_ref
        || receipt.current_failed_record.current.registry_ref
            != request.current_registry.registry_ref
        || receipt.current_failed_record.current.registry_path
            != request.transition.registry_final_path
        || receipt.current_failed_record.current.current_revision_ref
            != request.rollback.failed_candidate_ref
        || receipt
            .current_failed_record
            .current
            .current_revision_digest
            != request.rollback.failed_candidate_digest
        || receipt.current_failed_record.current.current_source_path
            != request.transition.candidate_source_path
        || receipt.current_failed_record.current.current_source_bytes
            != request.source_reacquisition.source_bytes
        || receipt.current_failed_record.current.evidence_refs != upstream.commission.evidence_refs
        || receipt.restored_record.current.snapshot_ref != receipt.commission.restored_snapshot_ref
        || receipt.restored_record.fixture_root_ref != receipt.marker.fixture_root_ref
        || receipt.restored_record.activation_authority_ref
            != receipt.current_failed_record.activation_authority_ref
        || receipt.restored_record.recovery_owner_ref != receipt.commission.recovery_owner_ref
        || receipt.restored_record.current.registry_ref
            != receipt.current_failed_record.current.registry_ref
        || receipt.restored_record.current.registry_path
            != receipt.current_failed_record.current.registry_path
        || receipt.restored_record.current.evidence_refs != receipt.commission.evidence_refs
        || receipt.restored_record.current.generation != expected_generation
        || receipt.restored_record.current.current_revision_ref
            != request.rollback.rollback_revision_ref
        || receipt.restored_record.current.current_revision_digest
            != request.rollback.rollback_revision_digest
        || receipt.restored_record.current.current_source_path
            != request.rollback.rollback_source_path
        || receipt.restored_record.current.current_source_bytes
            != request.rollback.rollback_source_bytes
        || receipt.restored_record.last_transaction_ref.as_ref()
            != Some(&request.transition.transaction_ref)
    {
        return Err(fault(
            SucceedingSopFixtureRollbackFaultCode::InvalidRegistry,
            "rollback receipt upstream, source, or restored correspondence differs",
        ));
    }
    let mut restored_bytes =
        to_succeeding_sop_fixture_registry_record_machine_form(&receipt.restored_record)
            .map_err(|error| {
                fault(
                    SucceedingSopFixtureRollbackFaultCode::InvalidRegistry,
                    error.to_string(),
                )
            })?
            .into_bytes();
    restored_bytes.push(b'\n');
    if receipt.restored_registry_raw_digest != sha256_bytes(&restored_bytes) {
        return Err(fault(
            SucceedingSopFixtureRollbackFaultCode::InvalidDigest,
            "restored registry raw digest differs",
        ));
    }
    for (digest, label) in [
        (&receipt.upstream_receipt_digest, "upstream receipt digest"),
        (
            &receipt.predecessor_source_raw_digest,
            "predecessor source digest",
        ),
        (
            &receipt.failed_candidate_source_raw_digest,
            "candidate source digest",
        ),
        (
            &receipt.failed_registry_raw_digest,
            "failed registry raw digest",
        ),
        (
            &receipt.restored_registry_raw_digest,
            "restored registry raw digest",
        ),
        (&receipt.receipt_digest, "rollback receipt digest"),
    ] {
        validate_digest(digest, label)?;
    }
    if receipt.receipt_digest != succeeding_sop_fixture_rollback_receipt_digest(receipt)? {
        return Err(fault(
            SucceedingSopFixtureRollbackFaultCode::InvalidDigest,
            "rollback receipt digest differs",
        ));
    }
    Ok(())
}

pub fn succeeding_sop_fixture_rollback_commission_digest(
    commission: &SucceedingSopFixtureRollbackCommission,
) -> Result<ContentDigest, SucceedingSopFixtureRollbackFault> {
    let mut body = commission.clone();
    body.commission_digest = empty_digest();
    sha256_form(COMMISSION_DOMAIN, &body)
}

pub fn succeeding_sop_fixture_rollback_receipt_digest(
    receipt: &SucceedingSopFixtureRollbackReceipt,
) -> Result<ContentDigest, SucceedingSopFixtureRollbackFault> {
    let mut body = receipt.clone();
    body.receipt_digest = empty_digest();
    sha256_form(RECEIPT_DOMAIN, &body)
}

pub fn to_succeeding_sop_fixture_rollback_commission_machine_form(
    commission: &SucceedingSopFixtureRollbackCommission,
) -> Result<String, SucceedingSopFixtureRollbackFault> {
    validate_succeeding_sop_fixture_rollback_commission(commission)?;
    machine_form(commission)
}

pub fn from_succeeding_sop_fixture_rollback_commission_machine_form(
    value: &str,
) -> Result<SucceedingSopFixtureRollbackCommission, SucceedingSopFixtureRollbackFault> {
    let commission = parse_machine_form(value)?;
    validate_succeeding_sop_fixture_rollback_commission(&commission)?;
    Ok(commission)
}

pub fn to_succeeding_sop_fixture_rollback_receipt_machine_form(
    receipt: &SucceedingSopFixtureRollbackReceipt,
) -> Result<String, SucceedingSopFixtureRollbackFault> {
    validate_succeeding_sop_fixture_rollback_receipt(receipt)?;
    machine_form(receipt)
}

pub fn from_succeeding_sop_fixture_rollback_receipt_machine_form(
    value: &str,
) -> Result<SucceedingSopFixtureRollbackReceipt, SucceedingSopFixtureRollbackFault> {
    let receipt = parse_machine_form(value)?;
    validate_succeeding_sop_fixture_rollback_receipt(&receipt)?;
    Ok(receipt)
}

fn build_restored_record(
    marker: &SucceedingSopFixtureRootMarker,
    commission: &SucceedingSopFixtureRollbackCommission,
    failed_record: &SucceedingSopFixtureRegistryRecord,
) -> Result<SucceedingSopFixtureRegistryRecord, SucceedingSopFixtureRollbackFault> {
    let request = &commission
        .persistence_receipt
        .commission
        .activation_transaction
        .request;
    let generation = failed_record
        .current
        .generation
        .checked_add(1)
        .ok_or_else(|| {
            fault(
                SucceedingSopFixtureRollbackFaultCode::InvalidGeneration,
                "restored registry generation overflows",
            )
        })?;
    let mut current = SucceedingSopCurrentRegistrySnapshot {
        profile: SUCCEEDING_SOP_CURRENT_REGISTRY_SNAPSHOT_PROFILE.to_owned(),
        snapshot_ref: commission.restored_snapshot_ref.clone(),
        registry_ref: failed_record.current.registry_ref.clone(),
        registry_path: failed_record.current.registry_path.clone(),
        generation,
        current_revision_ref: request.rollback.rollback_revision_ref.clone(),
        current_revision_digest: request.rollback.rollback_revision_digest.clone(),
        current_source_path: request.rollback.rollback_source_path.clone(),
        current_source_bytes: request.rollback.rollback_source_bytes,
        evidence_refs: commission.evidence_refs.clone(),
        snapshot_digest: empty_digest(),
    };
    current.snapshot_digest =
        succeeding_sop_current_registry_snapshot_digest(&current).map_err(|error| {
            fault(
                SucceedingSopFixtureRollbackFaultCode::InvalidRegistry,
                error.to_string(),
            )
        })?;
    let mut record = SucceedingSopFixtureRegistryRecord {
        profile: SUCCEEDING_SOP_FIXTURE_REGISTRY_RECORD_PROFILE.to_owned(),
        fixture_root_ref: marker.fixture_root_ref.clone(),
        activation_authority_ref: failed_record.activation_authority_ref.clone(),
        recovery_owner_ref: commission.recovery_owner_ref.clone(),
        last_transaction_ref: Some(request.transition.transaction_ref.clone()),
        current,
        record_digest: empty_digest(),
    };
    record.record_digest =
        succeeding_sop_fixture_registry_record_digest(&record).map_err(|error| {
            fault(
                SucceedingSopFixtureRollbackFaultCode::InvalidRegistry,
                error.to_string(),
            )
        })?;
    validate_succeeding_sop_fixture_registry_record(&record).map_err(|error| {
        fault(
            SucceedingSopFixtureRollbackFaultCode::InvalidRegistry,
            error.to_string(),
        )
    })?;
    Ok(record)
}

fn resolve_existing_relative(
    root: &Path,
    relative: &str,
    label: &str,
) -> Result<PathBuf, SucceedingSopFixtureRollbackFault> {
    let path = join_relative(root, relative, label)?;
    let mut cursor = root.to_path_buf();
    for component in Path::new(relative).components() {
        let Component::Normal(segment) = component else {
            return Err(physical_fault(
                SucceedingSopFixtureRollbackFaultCode::InvalidPath,
                format!("{label} has a non-normal component"),
                false,
                false,
                false,
            ));
        };
        cursor.push(segment);
        reject_link_or_reparse(&cursor, label)?;
    }
    let canonical = fs::canonicalize(&path).map_err(|error| {
        physical_fault(
            SucceedingSopFixtureRollbackFaultCode::InvalidPath,
            format!("{label} canonicalization failed: {error}"),
            false,
            false,
            false,
        )
    })?;
    if !canonical.starts_with(root) {
        return Err(physical_fault(
            SucceedingSopFixtureRollbackFaultCode::InvalidPath,
            format!("{label} escapes the fixture root"),
            false,
            false,
            false,
        ));
    }
    Ok(canonical)
}

fn resolve_absent_relative(
    root: &Path,
    relative: &str,
    label: &str,
) -> Result<PathBuf, SucceedingSopFixtureRollbackFault> {
    let path = join_relative(root, relative, label)?;
    let parent_relative = Path::new(relative).parent().ok_or_else(|| {
        physical_fault(
            SucceedingSopFixtureRollbackFaultCode::InvalidPath,
            format!("{label} parent is absent"),
            false,
            false,
            false,
        )
    })?;
    let parent = resolve_existing_relative(
        root,
        parent_relative.to_str().ok_or_else(|| {
            physical_fault(
                SucceedingSopFixtureRollbackFaultCode::InvalidPath,
                format!("{label} parent is not UTF-8"),
                false,
                false,
                false,
            )
        })?,
        label,
    )?;
    let leaf = path.file_name().ok_or_else(|| {
        physical_fault(
            SucceedingSopFixtureRollbackFaultCode::InvalidPath,
            format!("{label} leaf is absent"),
            false,
            false,
            false,
        )
    })?;
    let path = parent.join(leaf);
    match fs::symlink_metadata(&path) {
        Ok(_) => Err(physical_fault(
            SucceedingSopFixtureRollbackFaultCode::InvalidTemporary,
            format!("{label} already exists"),
            false,
            false,
            true,
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(path),
        Err(error) => Err(physical_fault(
            SucceedingSopFixtureRollbackFaultCode::InvalidTemporary,
            format!("{label} absence check failed: {error}"),
            false,
            false,
            true,
        )),
    }
}

fn join_relative(
    root: &Path,
    relative: &str,
    label: &str,
) -> Result<PathBuf, SucceedingSopFixtureRollbackFault> {
    if relative.is_empty()
        || relative.len() > 1024
        || Path::new(relative)
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(physical_fault(
            SucceedingSopFixtureRollbackFaultCode::InvalidPath,
            format!("{label} is not one bounded relative path"),
            false,
            false,
            false,
        ));
    }
    Ok(root.join(Path::new(relative)))
}

fn reject_link_or_reparse(
    path: &Path,
    label: &str,
) -> Result<(), SucceedingSopFixtureRollbackFault> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        physical_fault(
            SucceedingSopFixtureRollbackFaultCode::InvalidPath,
            format!("{label} metadata failed: {error}"),
            false,
            false,
            false,
        )
    })?;
    if is_link_or_reparse(&metadata) {
        return Err(physical_fault(
            SucceedingSopFixtureRollbackFaultCode::LinkOrReparse,
            format!("{label} is a link or reparse point"),
            false,
            false,
            false,
        ));
    }
    Ok(())
}

fn is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

#[cfg(windows)]
fn sync_directory(path: &Path) -> std::io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;
    OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?
        .sync_all()
}

#[cfg(not(windows))]
fn sync_directory(path: &Path) -> std::io::Result<()> {
    fs::File::open(path)?.sync_all()
}

fn read_bounded(path: &Path, label: &str) -> Result<Vec<u8>, SucceedingSopFixtureRollbackFault> {
    let metadata = fs::metadata(path).map_err(|error| {
        physical_fault(
            SucceedingSopFixtureRollbackFaultCode::InvalidPath,
            format!("{label} metadata failed: {error}"),
            false,
            false,
            false,
        )
    })?;
    if !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > SUCCEEDING_SOP_FIXTURE_ROLLBACK_MAX_MACHINE_FORM_BYTES as u64
    {
        return Err(physical_fault(
            SucceedingSopFixtureRollbackFaultCode::InvalidBound,
            format!("{label} file type or bound differs"),
            false,
            false,
            false,
        ));
    }
    fs::read(path).map_err(|error| {
        physical_fault(
            SucceedingSopFixtureRollbackFaultCode::InvalidPath,
            format!("{label} read failed: {error}"),
            false,
            false,
            false,
        )
    })
}

fn pre_replace_fault(
    temp_path: &Path,
    code: SucceedingSopFixtureRollbackFaultCode,
    message: impl Into<String>,
) -> SucceedingSopFixtureRollbackFault {
    match fs::remove_file(temp_path) {
        Ok(()) => physical_fault(code, message, false, true, true),
        Err(error) => physical_fault(
            code,
            format!(
                "{}; exact owned temporary removal failed: {error}",
                message.into()
            ),
            false,
            false,
            true,
        ),
    }
}

fn required_checks() -> BTreeSet<String> {
    SUCCEEDING_SOP_FIXTURE_ROLLBACK_CHECKS
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn validate_evidence(
    evidence: &BTreeSet<SemanticId>,
    label: &str,
) -> Result<(), SucceedingSopFixtureRollbackFault> {
    if evidence.is_empty() || evidence.len() > MAX_EVIDENCE_REFS {
        return Err(fault(
            SucceedingSopFixtureRollbackFaultCode::InvalidBound,
            format!("{label} count differs"),
        ));
    }
    Ok(())
}

fn validate_digest(
    digest: &ContentDigest,
    label: &str,
) -> Result<(), SucceedingSopFixtureRollbackFault> {
    let valid = digest.algorithm == "sha256"
        && digest.value.len() == 64
        && digest
            .value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !valid {
        return Err(fault(
            SucceedingSopFixtureRollbackFaultCode::InvalidDigest,
            format!("{label} must be lower-case SHA256"),
        ));
    }
    Ok(())
}

fn sha256_form<T: Serialize>(
    domain: &str,
    value: &T,
) -> Result<ContentDigest, SucceedingSopFixtureRollbackFault> {
    let body = serde_json::to_vec(value).map_err(machine_fault)?;
    let mut bytes = Vec::with_capacity(domain.len() + 1 + body.len());
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&body);
    Ok(sha256_bytes(&bytes))
}

fn machine_form<T: Serialize>(value: &T) -> Result<String, SucceedingSopFixtureRollbackFault> {
    let output = serde_json::to_string(value).map_err(machine_fault)?;
    validate_machine_bound(&output)?;
    Ok(output)
}

fn parse_machine_form<T: DeserializeOwned>(
    value: &str,
) -> Result<T, SucceedingSopFixtureRollbackFault> {
    validate_machine_bound(value)?;
    serde_json::from_str(value).map_err(machine_fault)
}

fn validate_machine_bound(value: &str) -> Result<(), SucceedingSopFixtureRollbackFault> {
    if value.is_empty() || value.len() > SUCCEEDING_SOP_FIXTURE_ROLLBACK_MAX_MACHINE_FORM_BYTES {
        return Err(fault(
            SucceedingSopFixtureRollbackFaultCode::InvalidBound,
            "machine-form bound differs",
        ));
    }
    Ok(())
}

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: "0".repeat(64),
    }
}

fn machine_fault(error: serde_json::Error) -> SucceedingSopFixtureRollbackFault {
    fault(
        SucceedingSopFixtureRollbackFaultCode::InvalidMachineForm,
        format!("fixture rollback machine form failed: {error}"),
    )
}

fn fault(
    code: SucceedingSopFixtureRollbackFaultCode,
    message: impl Into<String>,
) -> SucceedingSopFixtureRollbackFault {
    SucceedingSopFixtureRollbackFault {
        code,
        message: message.into(),
        physical_contact: false,
        replacement_performed: false,
        owned_temp_removed: false,
        failed_candidate_preserved: false,
    }
}

fn physical_fault(
    code: SucceedingSopFixtureRollbackFaultCode,
    message: impl Into<String>,
    replacement_performed: bool,
    owned_temp_removed: bool,
    failed_candidate_preserved: bool,
) -> SucceedingSopFixtureRollbackFault {
    SucceedingSopFixtureRollbackFault {
        code,
        message: message.into(),
        physical_contact: true,
        replacement_performed,
        owned_temp_removed,
        failed_candidate_preserved,
    }
}
