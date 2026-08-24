use std::{env, process};

use cantor_ecosystem::{
    sjs_commit_envelope_journal::{
        CommitEnvelopeJournal, CommitEnvelopeRecord, JOURNAL_PROFILE, JournalLink, JournalPolicy,
        PLACEMENT_PROFILE, PlacementAuthority, PlacementObservation, RECORD_PROFILE,
        commit_envelope_journal_digest, commit_envelope_record_digest,
        placement_observation_digest,
    },
    sjs_repository_graph::{
        ChangeSetManifest, DiffInventory, PublicationState, VerificationAuthority,
        change_set_manifest_digest, compile_sjs_repository_graph_verification,
        diff_inventory_digest,
    },
};

const RESULT_A: &str = "1111111111111111111111111111111111111111";
const RESULT_B: &str = "2222222222222222222222222222222222222222";
const RESULT_C: &str = "3333333333333333333333333333333333333333";

fn main() {
    let argument = env::args().nth(1).unwrap_or_default();
    let link_count = match argument.as_str() {
        "one" => 1,
        "two" => 2,
        _ => {
            eprintln!("expected one or two");
            process::exit(2);
        }
    };
    let journal = build_journal(link_count);
    println!("{}", serde_json::to_string_pretty(&journal).unwrap());
}

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

fn build_link(
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

fn build_journal(link_count: usize) -> CommitEnvelopeJournal {
    let (inventory, manifest) = base_forms();
    let anchor = inventory.predecessor_commit.clone();
    let first = build_link(
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
        links.push(build_link(
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
