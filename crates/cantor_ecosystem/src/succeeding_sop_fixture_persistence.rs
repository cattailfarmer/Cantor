//! Synthetic-fixture-only SWA-06B2B1 persistence kernel.
//!
//! The kernel replays one exact SWA-06B2A receipt, reacquires its source bytes,
//! verifies its predecessor registry, and persists one successor registry in an
//! explicitly marked disposable fixture. It never targets a Git root, boots an
//! SOP, executes rollback, invokes a process, or contacts a provider.

use std::{
    collections::BTreeSet,
    fmt, fs,
    fs::OpenOptions,
    io::Write,
    path::{Component, Path, PathBuf},
};

use cantor_core::{
    ContentDigest, SUCCEEDING_SOP_CURRENT_REGISTRY_SNAPSHOT_PROFILE, SemanticId,
    SucceedingSopActivationPolicyUseStatus, SucceedingSopActivationTransactionReceipt,
    SucceedingSopCurrentRegistrySnapshot, sha256_bytes,
    succeeding_sop_activation_transaction_receipt_digest,
    succeeding_sop_current_registry_snapshot_digest,
    validate_succeeding_sop_activation_transaction_receipt,
};
use serde::Deserialize;
use serde::{Serialize, de::DeserializeOwned};

pub const SUCCEEDING_SOP_FIXTURE_ROOT_MARKER_PROFILE: &str =
    "cantor-succeeding-sop-fixture-root-marker/0.1";
pub const SUCCEEDING_SOP_FIXTURE_PERSISTENCE_COMMISSION_PROFILE: &str =
    "cantor-succeeding-sop-fixture-persistence-commission/0.1";
pub const SUCCEEDING_SOP_FIXTURE_REGISTRY_RECORD_PROFILE: &str =
    "cantor-succeeding-sop-fixture-registry-record/0.1";
pub const SUCCEEDING_SOP_FIXTURE_PERSISTENCE_RECEIPT_PROFILE: &str =
    "cantor-succeeding-sop-fixture-persistence-receipt/0.1";
pub const SUCCEEDING_SOP_FIXTURE_ROOT_MARKER_FILE: &str = ".cantor-swa-06b2b1-fixture.json";
pub const SUCCEEDING_SOP_FIXTURE_PERSISTENCE_MAX_MACHINE_FORM_BYTES: usize = 16 * 1024 * 1024;

const MARKER_DOMAIN: &str = "cantor.succeeding-sop.fixture-persistence.marker.v1";
const COMMISSION_DOMAIN: &str = "cantor.succeeding-sop.fixture-persistence.commission.v1";
const REGISTRY_DOMAIN: &str = "cantor.succeeding-sop.fixture-persistence.registry.v1";
const RECEIPT_DOMAIN: &str = "cantor.succeeding-sop.fixture-persistence.receipt.v1";
const MAX_EVIDENCE_REFS: usize = 32;

pub const SUCCEEDING_SOP_FIXTURE_PERSISTENCE_CHECKS: [&str; 13] = [
    "atomic_replace",
    "authority_boundary",
    "deterministic_digests",
    "file_flush",
    "final_reopen",
    "marker_correspondence",
    "parent_flush",
    "registry_precondition",
    "root_boundary",
    "source_reacquisition",
    "temp_create_new",
    "temp_reopen",
    "upstream_replay",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SucceedingSopFixtureRootMarker {
    pub profile: String,
    pub marker_ref: SemanticId,
    pub fixture_root_ref: SemanticId,
    pub recovery_owner_ref: SemanticId,
    pub disposable_fixture: bool,
    pub live_repository: bool,
    pub live_activation_allowed: bool,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub marker_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SucceedingSopFixturePersistenceCommission {
    pub profile: String,
    pub commission_ref: SemanticId,
    pub fixture_root_ref: SemanticId,
    pub recovery_owner_ref: SemanticId,
    pub successor_snapshot_ref: SemanticId,
    pub activation_transaction: SucceedingSopActivationTransactionReceipt,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub fixture_only: bool,
    pub live_activation_allowed: bool,
    pub cleanup_authorized: bool,
    pub commission_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SucceedingSopFixtureRegistryRecord {
    pub profile: String,
    pub fixture_root_ref: SemanticId,
    pub activation_authority_ref: SemanticId,
    pub recovery_owner_ref: SemanticId,
    pub last_transaction_ref: Option<SemanticId>,
    pub current: SucceedingSopCurrentRegistrySnapshot,
    pub record_digest: ContentDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SucceedingSopFixturePersistenceStatus {
    FixtureRegistryPersistedAwaitingBootValidation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SucceedingSopFixturePersistenceAuthority {
    SyntheticFixturePersistenceOnly,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SucceedingSopFixturePersistenceReceipt {
    pub profile: String,
    pub commission: SucceedingSopFixturePersistenceCommission,
    pub status: SucceedingSopFixturePersistenceStatus,
    pub authority: SucceedingSopFixturePersistenceAuthority,
    pub marker_digest: ContentDigest,
    pub activation_transaction_receipt_digest: ContentDigest,
    pub source_raw_digest: ContentDigest,
    pub predecessor_registry_raw_digest: ContentDigest,
    pub successor_registry_raw_digest: ContentDigest,
    pub predecessor_record_digest: ContentDigest,
    pub successor_record_digest: ContentDigest,
    pub verified_checks: BTreeSet<String>,
    pub physical_contact: bool,
    pub source_reacquired: bool,
    pub registry_observed: bool,
    pub registry_persisted: bool,
    pub current_sop_selected: bool,
    pub temp_absent_after: bool,
    pub boot_activation_verified: bool,
    pub rollback_executed: bool,
    pub live_activation_performed: bool,
    pub provider_contacted: bool,
    pub model_called: bool,
    pub process_launched: bool,
    pub network_contacted: bool,
    pub cleanup_performed: bool,
    pub receipt_digest: ContentDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SucceedingSopFixturePersistenceFaultCode {
    InvalidUpstream,
    InvalidMarker,
    InvalidCommission,
    InvalidIdentity,
    InvalidRoot,
    InvalidPath,
    LinkOrReparse,
    InvalidSource,
    InvalidRegistry,
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
pub struct SucceedingSopFixturePersistenceFault {
    pub code: SucceedingSopFixturePersistenceFaultCode,
    pub message: String,
    pub physical_contact: bool,
    pub replacement_performed: bool,
    pub owned_temp_removed: bool,
}

impl fmt::Display for SucceedingSopFixturePersistenceFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for SucceedingSopFixturePersistenceFault {}

pub fn execute_succeeding_sop_fixture_persistence(
    root: &Path,
    commission: &SucceedingSopFixturePersistenceCommission,
) -> Result<SucceedingSopFixturePersistenceReceipt, SucceedingSopFixturePersistenceFault> {
    validate_succeeding_sop_fixture_persistence_commission(commission)?;

    let root_metadata = fs::symlink_metadata(root).map_err(|error| {
        physical_fault(
            SucceedingSopFixturePersistenceFaultCode::InvalidRoot,
            format!("fixture root metadata failed: {error}"),
            false,
            false,
        )
    })?;
    if !root_metadata.is_dir() || is_link_or_reparse(&root_metadata) {
        return Err(physical_fault(
            SucceedingSopFixturePersistenceFaultCode::InvalidRoot,
            "fixture root is not one real directory",
            false,
            false,
        ));
    }
    let root = fs::canonicalize(root).map_err(|error| {
        physical_fault(
            SucceedingSopFixturePersistenceFaultCode::InvalidRoot,
            format!("fixture root canonicalization failed: {error}"),
            false,
            false,
        )
    })?;
    match fs::symlink_metadata(root.join(".git")) {
        Ok(_) => {
            return Err(physical_fault(
                SucceedingSopFixturePersistenceFaultCode::InvalidRoot,
                "fixture root contains a forbidden .git entry",
                false,
                false,
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(physical_fault(
                SucceedingSopFixturePersistenceFaultCode::InvalidRoot,
                format!("fixture root .git refusal check failed: {error}"),
                false,
                false,
            ));
        }
    }

    let marker_path = root.join(SUCCEEDING_SOP_FIXTURE_ROOT_MARKER_FILE);
    reject_link_or_reparse(&marker_path, "fixture marker")?;
    let marker_bytes = read_bounded(&marker_path, "fixture marker")?;
    let marker: SucceedingSopFixtureRootMarker = parse_machine_bytes(&marker_bytes)
        .map_err(|error| physical_fault(error.code, error.message, false, false))?;
    validate_succeeding_sop_fixture_root_marker(&marker)
        .map_err(|error| physical_fault(error.code, error.message, false, false))?;
    if marker.fixture_root_ref != commission.fixture_root_ref
        || marker.recovery_owner_ref != commission.recovery_owner_ref
    {
        return Err(physical_fault(
            SucceedingSopFixturePersistenceFaultCode::InvalidIdentity,
            "marker and commission root or recovery-owner identity differs",
            false,
            false,
        ));
    }

    let transaction = &commission.activation_transaction.request;
    let source_path = resolve_existing_relative(
        &root,
        &transaction.source_reacquisition.source_path,
        "succeeding SOP source",
    )?;
    let source_metadata = fs::metadata(&source_path).map_err(|error| {
        physical_fault(
            SucceedingSopFixturePersistenceFaultCode::InvalidSource,
            format!("source metadata failed: {error}"),
            false,
            false,
        )
    })?;
    if !source_metadata.is_file()
        || source_metadata.len() != transaction.source_reacquisition.source_bytes
        || source_metadata.len() > usize::MAX as u64
    {
        return Err(physical_fault(
            SucceedingSopFixturePersistenceFaultCode::InvalidSource,
            "source file type or byte count differs",
            false,
            false,
        ));
    }
    let source_bytes = fs::read(&source_path).map_err(|error| {
        physical_fault(
            SucceedingSopFixturePersistenceFaultCode::InvalidSource,
            format!("source read failed: {error}"),
            false,
            false,
        )
    })?;
    if source_bytes.len() as u64 != transaction.source_reacquisition.source_bytes
        || sha256_bytes(&source_bytes) != transaction.source_reacquisition.source_sha256
    {
        return Err(physical_fault(
            SucceedingSopFixturePersistenceFaultCode::InvalidSource,
            "source raw-byte identity differs",
            false,
            false,
        ));
    }

    let registry_path = resolve_existing_relative(
        &root,
        &transaction.current_registry.registry_path,
        "current registry",
    )?;
    let predecessor_bytes = read_bounded(&registry_path, "current registry")?;
    let predecessor: SucceedingSopFixtureRegistryRecord =
        parse_machine_bytes(&predecessor_bytes)
            .map_err(|error| physical_fault(error.code, error.message, false, false))?;
    validate_succeeding_sop_fixture_registry_record(&predecessor)
        .map_err(|error| physical_fault(error.code, error.message, false, false))?;
    if predecessor.fixture_root_ref != marker.fixture_root_ref
        || predecessor.activation_authority_ref
            != transaction.activation_policy.activation_authority_ref
        || predecessor.recovery_owner_ref != transaction.activation_policy.recovery_owner_ref
        || predecessor.last_transaction_ref.is_some()
        || predecessor.current != transaction.current_registry
    {
        return Err(physical_fault(
            SucceedingSopFixturePersistenceFaultCode::InvalidRegistry,
            "predecessor registry differs from the exact transaction snapshot",
            false,
            false,
        ));
    }

    let temp_path = resolve_absent_relative(
        &root,
        &transaction.transition.registry_temp_path,
        "registry temporary path",
    )?;
    if registry_path.parent() != temp_path.parent() {
        return Err(physical_fault(
            SucceedingSopFixturePersistenceFaultCode::InvalidPath,
            "registry final and temporary physical parents differ",
            false,
            false,
        ));
    }

    let successor = build_successor_registry_record(&marker, commission)?;
    let successor_form = to_succeeding_sop_fixture_registry_record_machine_form(&successor)?;
    let mut successor_bytes = successor_form.into_bytes();
    successor_bytes.push(b'\n');

    let mut temporary = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)
    {
        Ok(file) => file,
        Err(error) => {
            return Err(physical_fault(
                SucceedingSopFixturePersistenceFaultCode::InvalidTemporary,
                format!("temporary create_new failed: {error}"),
                false,
                false,
            ));
        }
    };
    if let Err(error) = temporary.write_all(&successor_bytes) {
        return Err(pre_replace_fault(
            &temp_path,
            SucceedingSopFixturePersistenceFaultCode::Persistence,
            format!("temporary write failed: {error}"),
        ));
    }
    if let Err(error) = temporary.sync_all() {
        return Err(pre_replace_fault(
            &temp_path,
            SucceedingSopFixturePersistenceFaultCode::Durability,
            format!("temporary file flush failed: {error}"),
        ));
    }
    drop(temporary);
    if let Err(error) = reject_link_or_reparse(&temp_path, "owned temporary registry") {
        let mut fault = pre_replace_fault(
            &temp_path,
            SucceedingSopFixturePersistenceFaultCode::LinkOrReparse,
            "owned temporary registry became a link or reparse point",
        );
        fault.message.push_str(&format!(": {error}"));
        return Err(fault);
    }
    let temp_reopened = match read_bounded(&temp_path, "owned temporary registry") {
        Ok(bytes) => bytes,
        Err(error) => {
            return Err(pre_replace_fault(
                &temp_path,
                SucceedingSopFixturePersistenceFaultCode::PostWriteVerification,
                error.to_string(),
            ));
        }
    };
    if temp_reopened != successor_bytes {
        return Err(pre_replace_fault(
            &temp_path,
            SucceedingSopFixturePersistenceFaultCode::PostWriteVerification,
            "temporary reopen bytes differ",
        ));
    }

    if let Err(error) = fs::rename(&temp_path, &registry_path) {
        return Err(pre_replace_fault(
            &temp_path,
            SucceedingSopFixturePersistenceFaultCode::Persistence,
            format!("same-volume registry replacement failed: {error}"),
        ));
    }
    let parent = registry_path.parent().ok_or_else(|| {
        physical_fault(
            SucceedingSopFixturePersistenceFaultCode::InvalidPath,
            "registry parent is absent after replacement",
            true,
            false,
        )
    })?;
    if let Err(error) = sync_directory(parent) {
        return Err(physical_fault(
            SucceedingSopFixturePersistenceFaultCode::Durability,
            format!("registry parent flush failed after replacement: {error}"),
            true,
            false,
        ));
    }
    reject_link_or_reparse(&registry_path, "successor registry").map_err(|error| {
        physical_fault(
            SucceedingSopFixturePersistenceFaultCode::LinkOrReparse,
            format!("successor registry link check failed: {error}"),
            true,
            false,
        )
    })?;
    let final_bytes = read_bounded(&registry_path, "successor registry").map_err(|error| {
        physical_fault(
            SucceedingSopFixturePersistenceFaultCode::PostWriteVerification,
            error.to_string(),
            true,
            false,
        )
    })?;
    let final_record: SucceedingSopFixtureRegistryRecord = parse_machine_bytes(&final_bytes)
        .map_err(|error| {
            physical_fault(
                SucceedingSopFixturePersistenceFaultCode::PostWriteVerification,
                error.to_string(),
                true,
                false,
            )
        })?;
    validate_succeeding_sop_fixture_registry_record(&final_record).map_err(|error| {
        physical_fault(
            SucceedingSopFixturePersistenceFaultCode::PostWriteVerification,
            error.to_string(),
            true,
            false,
        )
    })?;
    if final_bytes != successor_bytes || final_record != successor {
        return Err(physical_fault(
            SucceedingSopFixturePersistenceFaultCode::PostWriteVerification,
            "successor final reopen differs",
            true,
            false,
        ));
    }
    if fs::symlink_metadata(&temp_path).is_ok() {
        return Err(physical_fault(
            SucceedingSopFixturePersistenceFaultCode::PostWriteVerification,
            "temporary registry remains after replacement",
            true,
            false,
        ));
    }

    let mut receipt = SucceedingSopFixturePersistenceReceipt {
        profile: SUCCEEDING_SOP_FIXTURE_PERSISTENCE_RECEIPT_PROFILE.to_owned(),
        commission: commission.clone(),
        status:
            SucceedingSopFixturePersistenceStatus::FixtureRegistryPersistedAwaitingBootValidation,
        authority: SucceedingSopFixturePersistenceAuthority::SyntheticFixturePersistenceOnly,
        marker_digest: marker.marker_digest.clone(),
        activation_transaction_receipt_digest: commission
            .activation_transaction
            .receipt_digest
            .clone(),
        source_raw_digest: sha256_bytes(&source_bytes),
        predecessor_registry_raw_digest: sha256_bytes(&predecessor_bytes),
        successor_registry_raw_digest: sha256_bytes(&successor_bytes),
        predecessor_record_digest: predecessor.record_digest,
        successor_record_digest: successor.record_digest,
        verified_checks: required_checks(),
        physical_contact: true,
        source_reacquired: true,
        registry_observed: true,
        registry_persisted: true,
        current_sop_selected: true,
        temp_absent_after: true,
        boot_activation_verified: false,
        rollback_executed: false,
        live_activation_performed: false,
        provider_contacted: false,
        model_called: false,
        process_launched: false,
        network_contacted: false,
        cleanup_performed: false,
        receipt_digest: empty_digest(),
    };
    receipt.receipt_digest = succeeding_sop_fixture_persistence_receipt_digest(&receipt)?;
    validate_succeeding_sop_fixture_persistence_receipt(&receipt)?;
    Ok(receipt)
}

pub fn predecessor_succeeding_sop_fixture_registry_record(
    marker: &SucceedingSopFixtureRootMarker,
    commission: &SucceedingSopFixturePersistenceCommission,
) -> Result<SucceedingSopFixtureRegistryRecord, SucceedingSopFixturePersistenceFault> {
    validate_succeeding_sop_fixture_root_marker(marker)?;
    validate_succeeding_sop_fixture_persistence_commission(commission)?;
    if marker.fixture_root_ref != commission.fixture_root_ref
        || marker.recovery_owner_ref != commission.recovery_owner_ref
    {
        return Err(fault(
            SucceedingSopFixturePersistenceFaultCode::InvalidIdentity,
            "predecessor marker and commission identities differ",
        ));
    }
    let request = &commission.activation_transaction.request;
    let mut record = SucceedingSopFixtureRegistryRecord {
        profile: SUCCEEDING_SOP_FIXTURE_REGISTRY_RECORD_PROFILE.to_owned(),
        fixture_root_ref: marker.fixture_root_ref.clone(),
        activation_authority_ref: request.activation_policy.activation_authority_ref.clone(),
        recovery_owner_ref: request.activation_policy.recovery_owner_ref.clone(),
        last_transaction_ref: None,
        current: request.current_registry.clone(),
        record_digest: empty_digest(),
    };
    record.record_digest = succeeding_sop_fixture_registry_record_digest(&record)?;
    validate_succeeding_sop_fixture_registry_record(&record)?;
    Ok(record)
}

pub fn validate_succeeding_sop_fixture_root_marker(
    marker: &SucceedingSopFixtureRootMarker,
) -> Result<(), SucceedingSopFixturePersistenceFault> {
    if marker.profile != SUCCEEDING_SOP_FIXTURE_ROOT_MARKER_PROFILE
        || !marker.disposable_fixture
        || marker.live_repository
        || marker.live_activation_allowed
    {
        return Err(fault(
            SucceedingSopFixturePersistenceFaultCode::InvalidMarker,
            "fixture marker profile or authority boundary differs",
        ));
    }
    validate_evidence(&marker.evidence_refs, "marker evidence")?;
    validate_digest(&marker.marker_digest, "marker digest")?;
    if marker.marker_digest != succeeding_sop_fixture_root_marker_digest(marker)? {
        return Err(fault(
            SucceedingSopFixturePersistenceFaultCode::InvalidDigest,
            "fixture marker digest differs",
        ));
    }
    Ok(())
}

pub fn validate_succeeding_sop_fixture_persistence_commission(
    commission: &SucceedingSopFixturePersistenceCommission,
) -> Result<(), SucceedingSopFixturePersistenceFault> {
    if commission.profile != SUCCEEDING_SOP_FIXTURE_PERSISTENCE_COMMISSION_PROFILE
        || !commission.fixture_only
        || commission.live_activation_allowed
        || commission.cleanup_authorized
    {
        return Err(fault(
            SucceedingSopFixturePersistenceFaultCode::InvalidCommission,
            "fixture commission profile or authority boundary differs",
        ));
    }
    validate_succeeding_sop_activation_transaction_receipt(&commission.activation_transaction)
        .map_err(|error| {
            fault(
                SucceedingSopFixturePersistenceFaultCode::InvalidUpstream,
                error.to_string(),
            )
        })?;
    if commission.activation_transaction.policy_use_status
        != SucceedingSopActivationPolicyUseStatus::SyntheticFixtureOnly
        || commission.recovery_owner_ref
            != commission
                .activation_transaction
                .request
                .activation_policy
                .recovery_owner_ref
    {
        return Err(fault(
            SucceedingSopFixturePersistenceFaultCode::InvalidCommission,
            "commission is not the exact synthetic fixture transaction",
        ));
    }
    validate_evidence(&commission.evidence_refs, "commission evidence")?;
    let roles = [
        &commission.commission_ref,
        &commission.fixture_root_ref,
        &commission.recovery_owner_ref,
        &commission.successor_snapshot_ref,
        &commission
            .activation_transaction
            .request
            .transition
            .transaction_ref,
        &commission
            .activation_transaction
            .request
            .current_registry
            .snapshot_ref,
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
            SucceedingSopFixturePersistenceFaultCode::InvalidIdentity,
            "commission duty or evidence identities collide",
        ));
    }
    validate_digest(&commission.commission_digest, "commission digest")?;
    if commission.commission_digest
        != succeeding_sop_fixture_persistence_commission_digest(commission)?
    {
        return Err(fault(
            SucceedingSopFixturePersistenceFaultCode::InvalidDigest,
            "fixture commission digest differs",
        ));
    }
    Ok(())
}

pub fn validate_succeeding_sop_fixture_registry_record(
    record: &SucceedingSopFixtureRegistryRecord,
) -> Result<(), SucceedingSopFixturePersistenceFault> {
    if record.profile != SUCCEEDING_SOP_FIXTURE_REGISTRY_RECORD_PROFILE
        || record.current.profile != SUCCEEDING_SOP_CURRENT_REGISTRY_SNAPSHOT_PROFILE
    {
        return Err(fault(
            SucceedingSopFixturePersistenceFaultCode::InvalidRegistry,
            "fixture registry profile differs",
        ));
    }
    validate_evidence(&record.current.evidence_refs, "registry snapshot evidence")?;
    if record.current.snapshot_digest
        != succeeding_sop_current_registry_snapshot_digest(&record.current).map_err(|error| {
            fault(
                SucceedingSopFixturePersistenceFaultCode::InvalidRegistry,
                error.to_string(),
            )
        })?
    {
        return Err(fault(
            SucceedingSopFixturePersistenceFaultCode::InvalidDigest,
            "registry snapshot digest differs",
        ));
    }
    validate_digest(&record.record_digest, "registry record digest")?;
    if record.record_digest != succeeding_sop_fixture_registry_record_digest(record)? {
        return Err(fault(
            SucceedingSopFixturePersistenceFaultCode::InvalidDigest,
            "fixture registry record digest differs",
        ));
    }
    Ok(())
}

pub fn validate_succeeding_sop_fixture_persistence_receipt(
    receipt: &SucceedingSopFixturePersistenceReceipt,
) -> Result<(), SucceedingSopFixturePersistenceFault> {
    validate_succeeding_sop_fixture_persistence_commission(&receipt.commission)?;
    if receipt.profile != SUCCEEDING_SOP_FIXTURE_PERSISTENCE_RECEIPT_PROFILE
        || receipt.status
            != SucceedingSopFixturePersistenceStatus::FixtureRegistryPersistedAwaitingBootValidation
        || receipt.authority
            != SucceedingSopFixturePersistenceAuthority::SyntheticFixturePersistenceOnly
        || receipt.verified_checks != required_checks()
        || !receipt.physical_contact
        || !receipt.source_reacquired
        || !receipt.registry_observed
        || !receipt.registry_persisted
        || !receipt.current_sop_selected
        || !receipt.temp_absent_after
        || receipt.boot_activation_verified
        || receipt.rollback_executed
        || receipt.live_activation_performed
        || receipt.provider_contacted
        || receipt.model_called
        || receipt.process_launched
        || receipt.network_contacted
        || receipt.cleanup_performed
    {
        return Err(fault(
            SucceedingSopFixturePersistenceFaultCode::InvalidCommission,
            "fixture persistence receipt widens outcome or authority",
        ));
    }
    let expected_upstream = succeeding_sop_activation_transaction_receipt_digest(
        &receipt.commission.activation_transaction,
    )
    .map_err(|error| {
        fault(
            SucceedingSopFixturePersistenceFaultCode::InvalidUpstream,
            error.to_string(),
        )
    })?;
    if receipt.activation_transaction_receipt_digest != expected_upstream
        || receipt.source_raw_digest
            != receipt
                .commission
                .activation_transaction
                .request
                .source_reacquisition
                .source_sha256
    {
        return Err(fault(
            SucceedingSopFixturePersistenceFaultCode::InvalidDigest,
            "receipt upstream or source digest differs",
        ));
    }
    for (digest, label) in [
        (&receipt.marker_digest, "receipt marker digest"),
        (
            &receipt.activation_transaction_receipt_digest,
            "receipt upstream digest",
        ),
        (&receipt.source_raw_digest, "receipt source digest"),
        (
            &receipt.predecessor_registry_raw_digest,
            "receipt predecessor raw digest",
        ),
        (
            &receipt.successor_registry_raw_digest,
            "receipt successor raw digest",
        ),
        (
            &receipt.predecessor_record_digest,
            "receipt predecessor record digest",
        ),
        (
            &receipt.successor_record_digest,
            "receipt successor record digest",
        ),
        (&receipt.receipt_digest, "receipt digest"),
    ] {
        validate_digest(digest, label)?;
    }
    if receipt.receipt_digest != succeeding_sop_fixture_persistence_receipt_digest(receipt)? {
        return Err(fault(
            SucceedingSopFixturePersistenceFaultCode::InvalidDigest,
            "fixture persistence receipt digest differs",
        ));
    }
    Ok(())
}

pub fn succeeding_sop_fixture_root_marker_digest(
    marker: &SucceedingSopFixtureRootMarker,
) -> Result<ContentDigest, SucceedingSopFixturePersistenceFault> {
    let mut body = marker.clone();
    body.marker_digest = empty_digest();
    sha256_form(MARKER_DOMAIN, &body)
}

pub fn succeeding_sop_fixture_persistence_commission_digest(
    commission: &SucceedingSopFixturePersistenceCommission,
) -> Result<ContentDigest, SucceedingSopFixturePersistenceFault> {
    let mut body = commission.clone();
    body.commission_digest = empty_digest();
    sha256_form(COMMISSION_DOMAIN, &body)
}

pub fn succeeding_sop_fixture_registry_record_digest(
    record: &SucceedingSopFixtureRegistryRecord,
) -> Result<ContentDigest, SucceedingSopFixturePersistenceFault> {
    let mut body = record.clone();
    body.record_digest = empty_digest();
    sha256_form(REGISTRY_DOMAIN, &body)
}

pub fn succeeding_sop_fixture_persistence_receipt_digest(
    receipt: &SucceedingSopFixturePersistenceReceipt,
) -> Result<ContentDigest, SucceedingSopFixturePersistenceFault> {
    let mut body = receipt.clone();
    body.receipt_digest = empty_digest();
    sha256_form(RECEIPT_DOMAIN, &body)
}

pub fn to_succeeding_sop_fixture_root_marker_machine_form(
    marker: &SucceedingSopFixtureRootMarker,
) -> Result<String, SucceedingSopFixturePersistenceFault> {
    validate_succeeding_sop_fixture_root_marker(marker)?;
    machine_form(marker)
}

pub fn from_succeeding_sop_fixture_root_marker_machine_form(
    value: &str,
) -> Result<SucceedingSopFixtureRootMarker, SucceedingSopFixturePersistenceFault> {
    let marker = parse_machine_form(value)?;
    validate_succeeding_sop_fixture_root_marker(&marker)?;
    Ok(marker)
}

pub fn to_succeeding_sop_fixture_persistence_commission_machine_form(
    commission: &SucceedingSopFixturePersistenceCommission,
) -> Result<String, SucceedingSopFixturePersistenceFault> {
    validate_succeeding_sop_fixture_persistence_commission(commission)?;
    machine_form(commission)
}

pub fn from_succeeding_sop_fixture_persistence_commission_machine_form(
    value: &str,
) -> Result<SucceedingSopFixturePersistenceCommission, SucceedingSopFixturePersistenceFault> {
    let commission = parse_machine_form(value)?;
    validate_succeeding_sop_fixture_persistence_commission(&commission)?;
    Ok(commission)
}

pub fn to_succeeding_sop_fixture_registry_record_machine_form(
    record: &SucceedingSopFixtureRegistryRecord,
) -> Result<String, SucceedingSopFixturePersistenceFault> {
    validate_succeeding_sop_fixture_registry_record(record)?;
    machine_form(record)
}

pub fn from_succeeding_sop_fixture_registry_record_machine_form(
    value: &str,
) -> Result<SucceedingSopFixtureRegistryRecord, SucceedingSopFixturePersistenceFault> {
    let record = parse_machine_form(value)?;
    validate_succeeding_sop_fixture_registry_record(&record)?;
    Ok(record)
}

pub fn to_succeeding_sop_fixture_persistence_receipt_machine_form(
    receipt: &SucceedingSopFixturePersistenceReceipt,
) -> Result<String, SucceedingSopFixturePersistenceFault> {
    validate_succeeding_sop_fixture_persistence_receipt(receipt)?;
    machine_form(receipt)
}

pub fn from_succeeding_sop_fixture_persistence_receipt_machine_form(
    value: &str,
) -> Result<SucceedingSopFixturePersistenceReceipt, SucceedingSopFixturePersistenceFault> {
    let receipt = parse_machine_form(value)?;
    validate_succeeding_sop_fixture_persistence_receipt(&receipt)?;
    Ok(receipt)
}

fn build_successor_registry_record(
    marker: &SucceedingSopFixtureRootMarker,
    commission: &SucceedingSopFixturePersistenceCommission,
) -> Result<SucceedingSopFixtureRegistryRecord, SucceedingSopFixturePersistenceFault> {
    let request = &commission.activation_transaction.request;
    let transition = &request.transition;
    let mut current = SucceedingSopCurrentRegistrySnapshot {
        profile: SUCCEEDING_SOP_CURRENT_REGISTRY_SNAPSHOT_PROFILE.to_owned(),
        snapshot_ref: commission.successor_snapshot_ref.clone(),
        registry_ref: request.current_registry.registry_ref.clone(),
        registry_path: transition.registry_final_path.clone(),
        generation: transition.after_generation,
        current_revision_ref: transition.candidate_proposal_ref.clone(),
        current_revision_digest: transition.candidate_proposal_digest.clone(),
        current_source_path: transition.candidate_source_path.clone(),
        evidence_refs: commission.evidence_refs.clone(),
        snapshot_digest: empty_digest(),
    };
    current.snapshot_digest =
        succeeding_sop_current_registry_snapshot_digest(&current).map_err(|error| {
            fault(
                SucceedingSopFixturePersistenceFaultCode::InvalidRegistry,
                error.to_string(),
            )
        })?;
    let mut record = SucceedingSopFixtureRegistryRecord {
        profile: SUCCEEDING_SOP_FIXTURE_REGISTRY_RECORD_PROFILE.to_owned(),
        fixture_root_ref: marker.fixture_root_ref.clone(),
        activation_authority_ref: request.activation_policy.activation_authority_ref.clone(),
        recovery_owner_ref: request.activation_policy.recovery_owner_ref.clone(),
        last_transaction_ref: Some(transition.transaction_ref.clone()),
        current,
        record_digest: empty_digest(),
    };
    record.record_digest = succeeding_sop_fixture_registry_record_digest(&record)?;
    validate_succeeding_sop_fixture_registry_record(&record)?;
    Ok(record)
}

fn resolve_existing_relative(
    root: &Path,
    relative: &str,
    label: &str,
) -> Result<PathBuf, SucceedingSopFixturePersistenceFault> {
    let path = join_relative(root, relative, label)?;
    let mut cursor = root.to_path_buf();
    for component in Path::new(relative).components() {
        let Component::Normal(segment) = component else {
            return Err(physical_fault(
                SucceedingSopFixturePersistenceFaultCode::InvalidPath,
                format!("{label} has a non-normal component"),
                false,
                false,
            ));
        };
        cursor.push(segment);
        reject_link_or_reparse(&cursor, label)?;
    }
    let canonical = fs::canonicalize(&path).map_err(|error| {
        physical_fault(
            SucceedingSopFixturePersistenceFaultCode::InvalidPath,
            format!("{label} canonicalization failed: {error}"),
            false,
            false,
        )
    })?;
    if !canonical.starts_with(root) {
        return Err(physical_fault(
            SucceedingSopFixturePersistenceFaultCode::InvalidPath,
            format!("{label} escapes the fixture root"),
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
) -> Result<PathBuf, SucceedingSopFixturePersistenceFault> {
    let path = join_relative(root, relative, label)?;
    let parent_relative = Path::new(relative).parent().ok_or_else(|| {
        physical_fault(
            SucceedingSopFixturePersistenceFaultCode::InvalidPath,
            format!("{label} parent is absent"),
            false,
            false,
        )
    })?;
    let parent = resolve_existing_relative(
        root,
        parent_relative.to_str().ok_or_else(|| {
            physical_fault(
                SucceedingSopFixturePersistenceFaultCode::InvalidPath,
                format!("{label} parent is not UTF-8"),
                false,
                false,
            )
        })?,
        label,
    )?;
    let leaf = path.file_name().ok_or_else(|| {
        physical_fault(
            SucceedingSopFixturePersistenceFaultCode::InvalidPath,
            format!("{label} leaf is absent"),
            false,
            false,
        )
    })?;
    let path = parent.join(leaf);
    match fs::symlink_metadata(&path) {
        Ok(_) => Err(physical_fault(
            SucceedingSopFixturePersistenceFaultCode::InvalidTemporary,
            format!("{label} already exists"),
            false,
            false,
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(path),
        Err(error) => Err(physical_fault(
            SucceedingSopFixturePersistenceFaultCode::InvalidTemporary,
            format!("{label} absence check failed: {error}"),
            false,
            false,
        )),
    }
}

fn join_relative(
    root: &Path,
    relative: &str,
    label: &str,
) -> Result<PathBuf, SucceedingSopFixturePersistenceFault> {
    if relative.is_empty()
        || relative.len() > 1024
        || Path::new(relative)
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(physical_fault(
            SucceedingSopFixturePersistenceFaultCode::InvalidPath,
            format!("{label} is not one bounded relative path"),
            false,
            false,
        ));
    }
    Ok(root.join(Path::new(relative)))
}

fn reject_link_or_reparse(
    path: &Path,
    label: &str,
) -> Result<(), SucceedingSopFixturePersistenceFault> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        physical_fault(
            SucceedingSopFixturePersistenceFaultCode::InvalidPath,
            format!("{label} metadata failed: {error}"),
            false,
            false,
        )
    })?;
    if is_link_or_reparse(&metadata) {
        return Err(physical_fault(
            SucceedingSopFixturePersistenceFaultCode::LinkOrReparse,
            format!("{label} is a link or reparse point"),
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

fn read_bounded(path: &Path, label: &str) -> Result<Vec<u8>, SucceedingSopFixturePersistenceFault> {
    let metadata = fs::metadata(path).map_err(|error| {
        physical_fault(
            SucceedingSopFixturePersistenceFaultCode::InvalidPath,
            format!("{label} metadata failed: {error}"),
            false,
            false,
        )
    })?;
    if !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > SUCCEEDING_SOP_FIXTURE_PERSISTENCE_MAX_MACHINE_FORM_BYTES as u64
    {
        return Err(physical_fault(
            SucceedingSopFixturePersistenceFaultCode::InvalidBound,
            format!("{label} file type or bound differs"),
            false,
            false,
        ));
    }
    fs::read(path).map_err(|error| {
        physical_fault(
            SucceedingSopFixturePersistenceFaultCode::InvalidPath,
            format!("{label} read failed: {error}"),
            false,
            false,
        )
    })
}

fn pre_replace_fault(
    temp_path: &Path,
    code: SucceedingSopFixturePersistenceFaultCode,
    message: impl Into<String>,
) -> SucceedingSopFixturePersistenceFault {
    match fs::remove_file(temp_path) {
        Ok(()) => physical_fault(code, message, false, true),
        Err(error) => physical_fault(
            code,
            format!(
                "{}; exact owned temporary removal failed: {error}",
                message.into()
            ),
            false,
            false,
        ),
    }
}

fn required_checks() -> BTreeSet<String> {
    SUCCEEDING_SOP_FIXTURE_PERSISTENCE_CHECKS
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn validate_evidence(
    evidence: &BTreeSet<SemanticId>,
    label: &str,
) -> Result<(), SucceedingSopFixturePersistenceFault> {
    if evidence.is_empty() || evidence.len() > MAX_EVIDENCE_REFS {
        return Err(fault(
            SucceedingSopFixturePersistenceFaultCode::InvalidBound,
            format!("{label} count differs"),
        ));
    }
    Ok(())
}

fn validate_digest(
    digest: &ContentDigest,
    label: &str,
) -> Result<(), SucceedingSopFixturePersistenceFault> {
    let valid = digest.algorithm == "sha256"
        && digest.value.len() == 64
        && digest
            .value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !valid {
        return Err(fault(
            SucceedingSopFixturePersistenceFaultCode::InvalidDigest,
            format!("{label} must be lower-case SHA256"),
        ));
    }
    Ok(())
}

fn sha256_form<T: Serialize>(
    domain: &str,
    value: &T,
) -> Result<ContentDigest, SucceedingSopFixturePersistenceFault> {
    let body = serde_json::to_vec(value).map_err(machine_fault)?;
    let mut bytes = Vec::with_capacity(domain.len() + 1 + body.len());
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&body);
    Ok(sha256_bytes(&bytes))
}

fn machine_form<T: Serialize>(value: &T) -> Result<String, SucceedingSopFixturePersistenceFault> {
    let output = serde_json::to_string(value).map_err(machine_fault)?;
    validate_machine_bound(&output)?;
    Ok(output)
}

fn parse_machine_form<T: DeserializeOwned>(
    value: &str,
) -> Result<T, SucceedingSopFixturePersistenceFault> {
    validate_machine_bound(value)?;
    serde_json::from_str(value).map_err(machine_fault)
}

fn parse_machine_bytes<T: DeserializeOwned>(
    value: &[u8],
) -> Result<T, SucceedingSopFixturePersistenceFault> {
    if value.is_empty() || value.len() > SUCCEEDING_SOP_FIXTURE_PERSISTENCE_MAX_MACHINE_FORM_BYTES {
        return Err(fault(
            SucceedingSopFixturePersistenceFaultCode::InvalidBound,
            "machine-form byte bound differs",
        ));
    }
    serde_json::from_slice(value).map_err(machine_fault)
}

fn validate_machine_bound(value: &str) -> Result<(), SucceedingSopFixturePersistenceFault> {
    if value.is_empty() || value.len() > SUCCEEDING_SOP_FIXTURE_PERSISTENCE_MAX_MACHINE_FORM_BYTES {
        return Err(fault(
            SucceedingSopFixturePersistenceFaultCode::InvalidBound,
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

fn machine_fault(error: serde_json::Error) -> SucceedingSopFixturePersistenceFault {
    fault(
        SucceedingSopFixturePersistenceFaultCode::InvalidMachineForm,
        format!("fixture persistence machine form failed: {error}"),
    )
}

fn fault(
    code: SucceedingSopFixturePersistenceFaultCode,
    message: impl Into<String>,
) -> SucceedingSopFixturePersistenceFault {
    SucceedingSopFixturePersistenceFault {
        code,
        message: message.into(),
        physical_contact: false,
        replacement_performed: false,
        owned_temp_removed: false,
    }
}

fn physical_fault(
    code: SucceedingSopFixturePersistenceFaultCode,
    message: impl Into<String>,
    replacement_performed: bool,
    owned_temp_removed: bool,
) -> SucceedingSopFixturePersistenceFault {
    SucceedingSopFixturePersistenceFault {
        code,
        message: message.into(),
        physical_contact: true,
        replacement_performed,
        owned_temp_removed,
    }
}
