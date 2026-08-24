//! Pure verification for one-head-lag SJS commit-envelope journals.
//!
//! A manifest cannot be part of the same exact diff inventory whose digest it
//! contains. This module resolves that recursion by verifying an immutable
//! envelope for payload commit N as a record carried by immediate successor
//! commit N+1. Every closed payload has a successor-carried record and exactly
//! one current carrier tip remains explicitly open. Placement observations are
//! supplied data, not physical Git proof, and this module performs no effects.

use std::{collections::HashSet, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::sjs_repository_graph::{
    ChangeSetManifest, DiffInventory, PublicationState, VerificationAuthority, VerificationReceipt,
    validate_verification_receipt,
};

pub const JOURNAL_PROFILE: &str = "cantor-sjs-commit-envelope-journal/0.1";
pub const RECORD_PROFILE: &str = "cantor-sjs-commit-envelope-record/0.1";
pub const PLACEMENT_PROFILE: &str = "cantor-sjs-commit-envelope-placement/0.1";
pub const RECEIPT_PROFILE: &str = "cantor-sjs-commit-envelope-journal-receipt/0.1";
pub const MAX_JOURNAL_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_LINKS: usize = 32;

const MAX_PATH_BYTES: usize = 1_024;
const JOURNAL_DOMAIN: &[u8] = b"cantor:sjs-commit-envelope:journal:0.1";
const RECORD_DOMAIN: &[u8] = b"cantor:sjs-commit-envelope:record:0.1";
const PLACEMENT_DOMAIN: &[u8] = b"cantor:sjs-commit-envelope:placement:0.1";
const RECEIPT_DOMAIN: &[u8] = b"cantor:sjs-commit-envelope:receipt:0.1";
const NONAUTHORITY: &str = "verification proves supplied envelope and one-head-lag chain consistency only; placement is supplied data and no Git observation hook staging commit push publication provider or self-signature authority is granted";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalPolicy {
    ImmediateSuccessor,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlacementAuthority {
    SuppliedData,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitEnvelopeRecord {
    pub profile: String,
    pub record_uuid: String,
    pub change_set_uuid: String,
    pub repository_id: String,
    pub branch_ref: String,
    pub payload_predecessor_commit: String,
    pub payload_resulting_commit: String,
    pub inventory_sha256: String,
    pub candidate_change_set_sha256: String,
    pub candidate_receipt_sha256: String,
    pub published_change_set_sha256: String,
    pub published_receipt_sha256: String,
    pub journal_path: String,
    pub policy: JournalPolicy,
    pub authority: VerificationAuthority,
    pub physical_contact: bool,
    pub record_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlacementObservation {
    pub profile: String,
    pub record_sha256: String,
    pub journal_path: String,
    pub carrier_parent_commit: String,
    pub carrier_commit: String,
    pub authority: PlacementAuthority,
    pub physical_contact: bool,
    pub placement_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalLink {
    pub inventory: DiffInventory,
    pub candidate_manifest: ChangeSetManifest,
    pub candidate_receipt: VerificationReceipt,
    pub published_manifest: ChangeSetManifest,
    pub published_receipt: VerificationReceipt,
    pub record: CommitEnvelopeRecord,
    pub placement: PlacementObservation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitEnvelopeJournal {
    pub profile: String,
    pub repository_id: String,
    pub branch_ref: String,
    pub anchor_commit: String,
    pub open_tip_commit: String,
    pub links: Vec<JournalLink>,
    pub authority: VerificationAuthority,
    pub physical_contact: bool,
    pub journal_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalVerificationReceipt {
    pub profile: String,
    pub journal_sha256: String,
    pub repository_id: String,
    pub anchor_commit: String,
    pub open_tip_commit: String,
    pub link_count: u32,
    pub closed_payload_count: u32,
    pub open_tip_count: u32,
    pub complete_historical_coverage: bool,
    pub authority: VerificationAuthority,
    pub physical_contact: bool,
    pub nonauthority: String,
    pub result_sha256: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalFaultCode {
    Profile,
    Identity,
    Path,
    P0,
    Invariant,
    Chain,
    Digest,
    Authority,
    Resource,
    Serialization,
    Io,
    Cli,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalFault {
    pub code: JournalFaultCode,
    pub message: String,
}

impl fmt::Display for JournalFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for JournalFault {}

pub fn commit_envelope_record_digest(
    record: &CommitEnvelopeRecord,
) -> Result<String, JournalFault> {
    let mut body = record.clone();
    body.record_sha256.clear();
    digest_form(RECORD_DOMAIN, &body)
}

pub fn placement_observation_digest(
    placement: &PlacementObservation,
) -> Result<String, JournalFault> {
    let mut body = placement.clone();
    body.placement_sha256.clear();
    digest_form(PLACEMENT_DOMAIN, &body)
}

pub fn commit_envelope_journal_digest(
    journal: &CommitEnvelopeJournal,
) -> Result<String, JournalFault> {
    let mut body = journal.clone();
    body.journal_sha256.clear();
    digest_form(JOURNAL_DOMAIN, &body)
}

pub fn journal_verification_receipt_digest(
    receipt: &JournalVerificationReceipt,
) -> Result<String, JournalFault> {
    let mut body = receipt.clone();
    body.result_sha256.clear();
    digest_form(RECEIPT_DOMAIN, &body)
}

pub fn compile_commit_envelope_journal_verification(
    journal: &CommitEnvelopeJournal,
) -> Result<JournalVerificationReceipt, JournalFault> {
    validate_journal(journal)?;
    let link_count = u32::try_from(journal.links.len()).map_err(|_| JournalFault {
        code: JournalFaultCode::Resource,
        message: "link count exceeds u32".to_owned(),
    })?;
    let mut receipt = JournalVerificationReceipt {
        profile: RECEIPT_PROFILE.to_owned(),
        journal_sha256: journal.journal_sha256.clone(),
        repository_id: journal.repository_id.clone(),
        anchor_commit: journal.anchor_commit.clone(),
        open_tip_commit: journal.open_tip_commit.clone(),
        link_count,
        closed_payload_count: link_count,
        open_tip_count: 1,
        complete_historical_coverage: true,
        authority: VerificationAuthority::VerificationOnly,
        physical_contact: false,
        nonauthority: NONAUTHORITY.to_owned(),
        result_sha256: String::new(),
    };
    receipt.result_sha256 = journal_verification_receipt_digest(&receipt)?;
    Ok(receipt)
}

pub fn validate_journal_verification_receipt(
    journal: &CommitEnvelopeJournal,
    receipt: &JournalVerificationReceipt,
) -> Result<(), JournalFault> {
    let expected = compile_commit_envelope_journal_verification(journal)?;
    if receipt != &expected {
        return fault(
            JournalFaultCode::Digest,
            "journal verification receipt differs",
        );
    }
    Ok(())
}

pub fn parse_journal_json(bytes: &[u8]) -> Result<CommitEnvelopeJournal, JournalFault> {
    if bytes.is_empty() || bytes.len() > MAX_JOURNAL_BYTES {
        return fault(
            JournalFaultCode::Resource,
            "journal JSON is empty or over bound",
        );
    }
    serde_json::from_slice(bytes).map_err(|error| JournalFault {
        code: JournalFaultCode::Serialization,
        message: format!("journal JSON differs: {error}"),
    })
}

fn validate_journal(journal: &CommitEnvelopeJournal) -> Result<(), JournalFault> {
    if journal.profile != JOURNAL_PROFILE {
        return fault(JournalFaultCode::Profile, "journal profile differs");
    }
    validate_encoded_bound(journal, MAX_JOURNAL_BYTES, "journal")?;
    validate_semantic_id(&journal.repository_id, "repository_id")?;
    validate_branch_ref(&journal.branch_ref)?;
    validate_commit(&journal.anchor_commit, "anchor_commit")?;
    validate_commit(&journal.open_tip_commit, "open_tip_commit")?;
    if journal.links.is_empty() || journal.links.len() > MAX_LINKS {
        return fault(
            JournalFaultCode::Resource,
            "journal link count is empty or over bound",
        );
    }
    if journal.authority != VerificationAuthority::VerificationOnly || journal.physical_contact {
        return fault(JournalFaultCode::Authority, "journal authority widens");
    }

    let mut journal_paths = HashSet::new();
    let mut transition_commits = HashSet::new();
    transition_commits.insert(journal.anchor_commit.as_str());
    let mut previous_result: Option<&str> = None;
    let mut previous_carrier: Option<&str> = None;

    for (index, link) in journal.links.iter().enumerate() {
        validate_link(link)?;
        if link.inventory.repository_id != journal.repository_id
            || link.inventory.branch_ref != journal.branch_ref
        {
            return fault(
                JournalFaultCode::Invariant,
                "link repository or branch differs from journal",
            );
        }
        if !journal_paths.insert(link.record.journal_path.as_str()) {
            return fault(JournalFaultCode::Path, "duplicate journal path");
        }
        let result = link.record.payload_resulting_commit.as_str();
        let carrier = link.placement.carrier_commit.as_str();
        if index == 0 {
            if link.record.payload_predecessor_commit != journal.anchor_commit {
                return fault(
                    JournalFaultCode::Chain,
                    "first payload predecessor differs from anchor",
                );
            }
        } else if link.record.payload_predecessor_commit != previous_result.unwrap_or_default()
            || result != previous_carrier.unwrap_or_default()
        {
            return fault(JournalFaultCode::Chain, "adjacent journal link differs");
        }
        if index == 0 && !transition_commits.insert(result) {
            return fault(JournalFaultCode::Chain, "payload commit cycle");
        }
        if index > 0 && result != previous_carrier.unwrap_or_default() {
            return fault(
                JournalFaultCode::Chain,
                "payload result is not prior carrier",
            );
        }
        if !transition_commits.insert(carrier) {
            return fault(JournalFaultCode::Chain, "carrier commit cycle");
        }
        previous_result = Some(result);
        previous_carrier = Some(carrier);
    }
    if previous_carrier != Some(journal.open_tip_commit.as_str()) {
        return fault(
            JournalFaultCode::Chain,
            "final carrier differs from open tip",
        );
    }
    validate_sha256(&journal.journal_sha256, "journal_sha256")?;
    if journal.journal_sha256 != commit_envelope_journal_digest(journal)? {
        return fault(JournalFaultCode::Digest, "journal digest differs");
    }
    Ok(())
}

fn validate_link(link: &JournalLink) -> Result<(), JournalFault> {
    validate_verification_receipt(
        &link.candidate_manifest,
        &link.inventory,
        &link.candidate_receipt,
    )
    .map_err(|error| JournalFault {
        code: JournalFaultCode::P0,
        message: format!("candidate P0 verification refused: {error}"),
    })?;
    validate_verification_receipt(
        &link.published_manifest,
        &link.inventory,
        &link.published_receipt,
    )
    .map_err(|error| JournalFault {
        code: JournalFaultCode::P0,
        message: format!("published P0 verification refused: {error}"),
    })?;
    if link.candidate_manifest.publication_state != PublicationState::Candidate
        || link.candidate_manifest.resulting_commit.is_some()
        || link.published_manifest.publication_state != PublicationState::Published
    {
        return fault(
            JournalFaultCode::Invariant,
            "candidate or published state differs",
        );
    }
    let resulting_commit = link
        .published_manifest
        .resulting_commit
        .as_deref()
        .ok_or_else(|| JournalFault {
            code: JournalFaultCode::Invariant,
            message: "published resulting commit is absent".to_owned(),
        })?;
    validate_commit(resulting_commit, "published resulting_commit")?;
    if normalized_manifest(&link.candidate_manifest)
        != normalized_manifest(&link.published_manifest)
    {
        return fault(
            JournalFaultCode::Invariant,
            "candidate and published manifest invariant content differs",
        );
    }
    validate_record(&link.record)?;
    validate_placement(&link.placement)?;
    if link.record.change_set_uuid != link.candidate_manifest.change_set_uuid
        || link.record.repository_id != link.inventory.repository_id
        || link.record.branch_ref != link.inventory.branch_ref
        || link.record.payload_predecessor_commit != link.inventory.predecessor_commit
        || link.record.payload_resulting_commit != resulting_commit
        || link.record.inventory_sha256 != link.inventory.inventory_sha256
        || link.record.candidate_change_set_sha256 != link.candidate_manifest.change_set_sha256
        || link.record.candidate_receipt_sha256 != link.candidate_receipt.result_sha256
        || link.record.published_change_set_sha256 != link.published_manifest.change_set_sha256
        || link.record.published_receipt_sha256 != link.published_receipt.result_sha256
    {
        return fault(
            JournalFaultCode::Invariant,
            "record does not bind both P0 forms",
        );
    }
    if inventory_contains_path(&link.inventory, &link.record.journal_path) {
        return fault(
            JournalFaultCode::Path,
            "journal path overlaps described payload inventory",
        );
    }
    if link.placement.record_sha256 != link.record.record_sha256
        || link.placement.journal_path != link.record.journal_path
        || link.placement.carrier_parent_commit != resulting_commit
        || link.placement.carrier_commit == resulting_commit
    {
        return fault(
            JournalFaultCode::Chain,
            "placement does not bind immediate successor",
        );
    }
    Ok(())
}

fn normalized_manifest(manifest: &ChangeSetManifest) -> ChangeSetManifest {
    let mut normalized = manifest.clone();
    normalized.publication_state = PublicationState::Candidate;
    normalized.resulting_commit = None;
    normalized.change_set_sha256.clear();
    normalized
}

fn validate_record(record: &CommitEnvelopeRecord) -> Result<(), JournalFault> {
    if record.profile != RECORD_PROFILE {
        return fault(JournalFaultCode::Profile, "record profile differs");
    }
    validate_uuid(&record.record_uuid, "record_uuid")?;
    validate_uuid(&record.change_set_uuid, "change_set_uuid")?;
    validate_semantic_id(&record.repository_id, "record repository_id")?;
    validate_branch_ref(&record.branch_ref)?;
    validate_commit(
        &record.payload_predecessor_commit,
        "payload_predecessor_commit",
    )?;
    validate_commit(&record.payload_resulting_commit, "payload_resulting_commit")?;
    if record.payload_predecessor_commit == record.payload_resulting_commit {
        return fault(JournalFaultCode::Chain, "payload commit self loop");
    }
    validate_sha256(&record.inventory_sha256, "inventory_sha256")?;
    validate_sha256(
        &record.candidate_change_set_sha256,
        "candidate_change_set_sha256",
    )?;
    validate_sha256(&record.candidate_receipt_sha256, "candidate_receipt_sha256")?;
    validate_sha256(
        &record.published_change_set_sha256,
        "published_change_set_sha256",
    )?;
    validate_sha256(&record.published_receipt_sha256, "published_receipt_sha256")?;
    validate_repository_path(&record.journal_path, "journal_path")?;
    if record.policy != JournalPolicy::ImmediateSuccessor
        || record.authority != VerificationAuthority::VerificationOnly
        || record.physical_contact
    {
        return fault(
            JournalFaultCode::Authority,
            "record authority or policy widens",
        );
    }
    validate_sha256(&record.record_sha256, "record_sha256")?;
    if record.record_sha256 != commit_envelope_record_digest(record)? {
        return fault(JournalFaultCode::Digest, "record digest differs");
    }
    Ok(())
}

fn validate_placement(placement: &PlacementObservation) -> Result<(), JournalFault> {
    if placement.profile != PLACEMENT_PROFILE {
        return fault(JournalFaultCode::Profile, "placement profile differs");
    }
    validate_sha256(&placement.record_sha256, "placement record_sha256")?;
    validate_repository_path(&placement.journal_path, "placement journal_path")?;
    validate_commit(&placement.carrier_parent_commit, "carrier_parent_commit")?;
    validate_commit(&placement.carrier_commit, "carrier_commit")?;
    if placement.authority != PlacementAuthority::SuppliedData || placement.physical_contact {
        return fault(JournalFaultCode::Authority, "placement authority widens");
    }
    validate_sha256(&placement.placement_sha256, "placement_sha256")?;
    if placement.placement_sha256 != placement_observation_digest(placement)? {
        return fault(JournalFaultCode::Digest, "placement digest differs");
    }
    Ok(())
}

fn inventory_contains_path(inventory: &DiffInventory, path: &str) -> bool {
    inventory.entries.iter().any(|entry| {
        entry.old_path.as_deref() == Some(path) || entry.new_path.as_deref() == Some(path)
    })
}

fn digest_form<T: Serialize>(domain: &[u8], value: &T) -> Result<String, JournalFault> {
    let encoded = serde_json::to_vec(value).map_err(|error| JournalFault {
        code: JournalFaultCode::Serialization,
        message: format!("digest serialization failed: {error}"),
    })?;
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update([0]);
    digest.update(encoded);
    let bytes = digest.finalize();
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write;
        write!(&mut encoded, "{byte:02X}").map_err(|error| JournalFault {
            code: JournalFaultCode::Serialization,
            message: format!("digest formatting failed: {error}"),
        })?;
    }
    Ok(encoded)
}

fn validate_encoded_bound<T: Serialize>(
    value: &T,
    maximum: usize,
    label: &str,
) -> Result<(), JournalFault> {
    let bytes = serde_json::to_vec(value).map_err(|error| JournalFault {
        code: JournalFaultCode::Serialization,
        message: format!("{label} serialization failed: {error}"),
    })?;
    if bytes.len() > maximum {
        return fault(JournalFaultCode::Resource, format!("{label} is over bound"));
    }
    Ok(())
}

fn validate_uuid(value: &str, label: &str) -> Result<(), JournalFault> {
    let bytes = value.as_bytes();
    let valid = bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase(),
        });
    if !valid {
        return fault(JournalFaultCode::Identity, format!("{label} differs"));
    }
    Ok(())
}

fn validate_commit(value: &str, label: &str) -> Result<(), JournalFault> {
    if value.len() != 40
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return fault(JournalFaultCode::Identity, format!("{label} differs"));
    }
    Ok(())
}

fn validate_sha256(value: &str, label: &str) -> Result<(), JournalFault> {
    if value.len() != 64
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_lowercase())
    {
        return fault(JournalFaultCode::Identity, format!("{label} differs"));
    }
    Ok(())
}

fn validate_semantic_id(value: &str, label: &str) -> Result<(), JournalFault> {
    if value.is_empty()
        || value.len() > 256
        || !value.as_bytes().iter().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(*byte, b'.' | b'_' | b'-' | b'/')
        })
    {
        return fault(JournalFaultCode::Identity, format!("{label} differs"));
    }
    Ok(())
}

fn validate_branch_ref(value: &str) -> Result<(), JournalFault> {
    if !value.starts_with("refs/heads/") || value.len() > 512 {
        return fault(JournalFaultCode::Identity, "branch_ref differs");
    }
    validate_repository_path(value, "branch_ref")
}

fn validate_repository_path(value: &str, label: &str) -> Result<(), JournalFault> {
    if value.is_empty()
        || value.len() > MAX_PATH_BYTES
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains('\\')
        || value.contains('\0')
        || value.contains(':')
        || value.contains("//")
        || value.split('/').any(|part| {
            part.is_empty() || part == "." || part == ".." || part.chars().any(char::is_control)
        })
    {
        return fault(JournalFaultCode::Path, format!("{label} differs"));
    }
    Ok(())
}

fn fault<T>(code: JournalFaultCode, message: impl Into<String>) -> Result<T, JournalFault> {
    Err(JournalFault {
        code,
        message: message.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sjs_repository_graph::{
        change_set_manifest_digest, compile_sjs_repository_graph_verification,
        diff_inventory_digest,
    };

    const RESULT_A: &str = "1111111111111111111111111111111111111111";
    const RESULT_B: &str = "2222222222222222222222222222222222222222";
    const RESULT_C: &str = "3333333333333333333333333333333333333333";

    fn base_forms() -> (DiffInventory, ChangeSetManifest) {
        let inventory = serde_json::from_str(include_str!(
            "../../../fixtures/sjs_repository_graph_p0/diff_inventory.json"
        ))
        .unwrap();
        let manifest = serde_json::from_str(include_str!(
            "../../../fixtures/sjs_repository_graph_p0/change_set.json"
        ))
        .unwrap();
        (inventory, manifest)
    }

    fn make_link(
        mut inventory: DiffInventory,
        mut candidate: ChangeSetManifest,
        predecessor: &str,
        result: &str,
        carrier: &str,
        record_uuid: &str,
        journal_path: &str,
    ) -> JournalLink {
        inventory.predecessor_commit = predecessor.to_owned();
        inventory.inventory_sha256.clear();
        inventory.inventory_sha256 = diff_inventory_digest(&inventory).unwrap();
        candidate.predecessor_commit = predecessor.to_owned();
        candidate.inventory_sha256 = inventory.inventory_sha256.clone();
        candidate.publication_state = PublicationState::Candidate;
        candidate.resulting_commit = None;
        candidate.change_set_sha256.clear();
        candidate.change_set_sha256 = change_set_manifest_digest(&candidate).unwrap();
        let candidate_receipt =
            compile_sjs_repository_graph_verification(&candidate, &inventory).unwrap();
        let mut published = candidate.clone();
        published.publication_state = PublicationState::Published;
        published.resulting_commit = Some(result.to_owned());
        published.change_set_sha256.clear();
        published.change_set_sha256 = change_set_manifest_digest(&published).unwrap();
        let published_receipt =
            compile_sjs_repository_graph_verification(&published, &inventory).unwrap();
        let mut record = CommitEnvelopeRecord {
            profile: RECORD_PROFILE.to_owned(),
            record_uuid: record_uuid.to_owned(),
            change_set_uuid: candidate.change_set_uuid.clone(),
            repository_id: inventory.repository_id.clone(),
            branch_ref: inventory.branch_ref.clone(),
            payload_predecessor_commit: predecessor.to_owned(),
            payload_resulting_commit: result.to_owned(),
            inventory_sha256: inventory.inventory_sha256.clone(),
            candidate_change_set_sha256: candidate.change_set_sha256.clone(),
            candidate_receipt_sha256: candidate_receipt.result_sha256.clone(),
            published_change_set_sha256: published.change_set_sha256.clone(),
            published_receipt_sha256: published_receipt.result_sha256.clone(),
            journal_path: journal_path.to_owned(),
            policy: JournalPolicy::ImmediateSuccessor,
            authority: VerificationAuthority::VerificationOnly,
            physical_contact: false,
            record_sha256: String::new(),
        };
        record.record_sha256 = commit_envelope_record_digest(&record).unwrap();
        let mut placement = PlacementObservation {
            profile: PLACEMENT_PROFILE.to_owned(),
            record_sha256: record.record_sha256.clone(),
            journal_path: journal_path.to_owned(),
            carrier_parent_commit: result.to_owned(),
            carrier_commit: carrier.to_owned(),
            authority: PlacementAuthority::SuppliedData,
            physical_contact: false,
            placement_sha256: String::new(),
        };
        placement.placement_sha256 = placement_observation_digest(&placement).unwrap();
        JournalLink {
            inventory,
            candidate_manifest: candidate,
            candidate_receipt,
            published_manifest: published,
            published_receipt,
            record,
            placement,
        }
    }

    fn valid_journal(link_count: usize) -> CommitEnvelopeJournal {
        let (inventory, manifest) = base_forms();
        let anchor = inventory.predecessor_commit.clone();
        let first = make_link(
            inventory.clone(),
            manifest.clone(),
            &anchor,
            RESULT_A,
            RESULT_B,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "narrative/commit_envelopes/a.json",
        );
        let mut links = vec![first];
        if link_count == 2 {
            links.push(make_link(
                inventory,
                manifest,
                RESULT_A,
                RESULT_B,
                RESULT_C,
                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                "narrative/commit_envelopes/b.json",
            ));
        }
        let open_tip_commit = links.last().unwrap().placement.carrier_commit.clone();
        let mut journal = CommitEnvelopeJournal {
            profile: JOURNAL_PROFILE.to_owned(),
            repository_id: links[0].inventory.repository_id.clone(),
            branch_ref: links[0].inventory.branch_ref.clone(),
            anchor_commit: anchor,
            open_tip_commit,
            links,
            authority: VerificationAuthority::VerificationOnly,
            physical_contact: false,
            journal_sha256: String::new(),
        };
        journal.journal_sha256 = commit_envelope_journal_digest(&journal).unwrap();
        journal
    }

    fn rehash_journal(journal: &mut CommitEnvelopeJournal) {
        journal.journal_sha256.clear();
        journal.journal_sha256 = commit_envelope_journal_digest(journal).unwrap();
    }

    #[test]
    fn one_link_journal_verifies_with_one_open_tip() {
        let journal = valid_journal(1);
        let receipt = compile_commit_envelope_journal_verification(&journal).unwrap();
        assert_eq!(receipt.link_count, 1);
        assert_eq!(receipt.open_tip_count, 1);
        assert!(receipt.complete_historical_coverage);
        assert!(!receipt.physical_contact);
        validate_journal_verification_receipt(&journal, &receipt).unwrap();
    }

    #[test]
    fn two_link_journal_replays_deterministically() {
        let journal = valid_journal(2);
        let first = compile_commit_envelope_journal_verification(&journal).unwrap();
        let second = compile_commit_envelope_journal_verification(&journal).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.closed_payload_count, 2);
        assert_eq!(first.open_tip_commit, RESULT_C);
    }

    #[test]
    fn published_graph_drift_is_refused_even_when_rehashed() {
        let mut journal = valid_journal(1);
        journal.links[0].published_manifest.events[0]
            .reason_summary
            .push('!');
        let event = &mut journal.links[0].published_manifest.events[0];
        event.event_sha256 =
            crate::sjs_repository_graph::element_history_event_digest(event).unwrap();
        let inventory = journal.links[0].inventory.clone();
        let (manifest_sha256, receipt) = {
            let manifest = &mut journal.links[0].published_manifest;
            manifest.change_set_sha256.clear();
            manifest.change_set_sha256 = change_set_manifest_digest(manifest).unwrap();
            let receipt = compile_sjs_repository_graph_verification(manifest, &inventory).unwrap();
            (manifest.change_set_sha256.clone(), receipt)
        };
        journal.links[0].published_receipt = receipt;
        journal.links[0].record.published_change_set_sha256 = manifest_sha256;
        journal.links[0].record.published_receipt_sha256 =
            journal.links[0].published_receipt.result_sha256.clone();
        journal.links[0].record.record_sha256.clear();
        journal.links[0].record.record_sha256 =
            commit_envelope_record_digest(&journal.links[0].record).unwrap();
        journal.links[0].placement.record_sha256 = journal.links[0].record.record_sha256.clone();
        journal.links[0].placement.placement_sha256.clear();
        journal.links[0].placement.placement_sha256 =
            placement_observation_digest(&journal.links[0].placement).unwrap();
        rehash_journal(&mut journal);
        let fault = compile_commit_envelope_journal_verification(&journal).unwrap_err();
        assert_eq!(fault.code, JournalFaultCode::Invariant);
    }

    #[test]
    fn journal_path_in_payload_is_refused() {
        let mut journal = valid_journal(1);
        journal.links[0].record.journal_path = "src/new.rs".to_owned();
        journal.links[0].record.record_sha256.clear();
        journal.links[0].record.record_sha256 =
            commit_envelope_record_digest(&journal.links[0].record).unwrap();
        journal.links[0].placement.journal_path = "src/new.rs".to_owned();
        journal.links[0].placement.record_sha256 = journal.links[0].record.record_sha256.clone();
        journal.links[0].placement.placement_sha256.clear();
        journal.links[0].placement.placement_sha256 =
            placement_observation_digest(&journal.links[0].placement).unwrap();
        rehash_journal(&mut journal);
        assert_eq!(
            compile_commit_envelope_journal_verification(&journal)
                .unwrap_err()
                .code,
            JournalFaultCode::Path
        );
    }

    #[test]
    fn placement_parent_tamper_is_refused() {
        let mut journal = valid_journal(1);
        journal.links[0].placement.carrier_parent_commit = RESULT_C.to_owned();
        journal.links[0].placement.placement_sha256.clear();
        journal.links[0].placement.placement_sha256 =
            placement_observation_digest(&journal.links[0].placement).unwrap();
        rehash_journal(&mut journal);
        assert_eq!(
            compile_commit_envelope_journal_verification(&journal)
                .unwrap_err()
                .code,
            JournalFaultCode::Chain
        );
    }

    #[test]
    fn adjacent_gap_is_refused() {
        let mut journal = valid_journal(2);
        journal.links[1].record.payload_predecessor_commit = RESULT_C.to_owned();
        journal.links[1].record.record_sha256.clear();
        journal.links[1].record.record_sha256 =
            commit_envelope_record_digest(&journal.links[1].record).unwrap();
        rehash_journal(&mut journal);
        assert_eq!(
            compile_commit_envelope_journal_verification(&journal)
                .unwrap_err()
                .code,
            JournalFaultCode::Invariant
        );
    }

    #[test]
    fn false_open_tip_is_refused() {
        let mut journal = valid_journal(1);
        journal.open_tip_commit = RESULT_C.to_owned();
        rehash_journal(&mut journal);
        assert_eq!(
            compile_commit_envelope_journal_verification(&journal)
                .unwrap_err()
                .code,
            JournalFaultCode::Chain
        );
    }

    #[test]
    fn placement_digest_tamper_is_refused() {
        let mut journal = valid_journal(1);
        journal.links[0].placement.placement_sha256 = "A".repeat(64);
        rehash_journal(&mut journal);
        assert_eq!(
            compile_commit_envelope_journal_verification(&journal)
                .unwrap_err()
                .code,
            JournalFaultCode::Digest
        );
    }

    #[test]
    fn physical_contact_is_refused() {
        let mut journal = valid_journal(1);
        journal.physical_contact = true;
        rehash_journal(&mut journal);
        assert_eq!(
            compile_commit_envelope_journal_verification(&journal)
                .unwrap_err()
                .code,
            JournalFaultCode::Authority
        );
    }

    #[test]
    fn duplicate_journal_path_is_refused() {
        let mut journal = valid_journal(2);
        let path = journal.links[0].record.journal_path.clone();
        journal.links[1].record.journal_path = path.clone();
        journal.links[1].record.record_sha256.clear();
        journal.links[1].record.record_sha256 =
            commit_envelope_record_digest(&journal.links[1].record).unwrap();
        journal.links[1].placement.journal_path = path;
        journal.links[1].placement.record_sha256 = journal.links[1].record.record_sha256.clone();
        journal.links[1].placement.placement_sha256.clear();
        journal.links[1].placement.placement_sha256 =
            placement_observation_digest(&journal.links[1].placement).unwrap();
        rehash_journal(&mut journal);
        assert_eq!(
            compile_commit_envelope_journal_verification(&journal)
                .unwrap_err()
                .code,
            JournalFaultCode::Path
        );
    }

    #[test]
    fn unknown_json_field_is_refused() {
        let journal = valid_journal(1);
        let mut value = serde_json::to_value(journal).unwrap();
        value.as_object_mut().unwrap().insert(
            "unexpected_authority".to_owned(),
            serde_json::Value::Bool(true),
        );
        let bytes = serde_json::to_vec(&value).unwrap();
        assert_eq!(
            parse_journal_json(&bytes).unwrap_err().code,
            JournalFaultCode::Serialization
        );
    }

    #[test]
    fn empty_and_overbound_json_are_refused() {
        assert_eq!(
            parse_journal_json(&[]).unwrap_err().code,
            JournalFaultCode::Resource
        );
        let bytes = vec![b' '; MAX_JOURNAL_BYTES + 1];
        assert_eq!(
            parse_journal_json(&bytes).unwrap_err().code,
            JournalFaultCode::Resource
        );
    }
}
