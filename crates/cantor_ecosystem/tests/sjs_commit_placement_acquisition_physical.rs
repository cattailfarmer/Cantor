use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};

use cantor_ecosystem::{
    sjs_commit_envelope_journal::{
        CommitEnvelopeJournal, CommitEnvelopeRecord, JOURNAL_PROFILE, JournalLink, JournalPolicy,
        PLACEMENT_PROFILE, PlacementAuthority, PlacementObservation, RECORD_PROFILE,
        commit_envelope_journal_digest, commit_envelope_record_digest,
        placement_observation_digest,
    },
    sjs_commit_placement_acquisition::{
        CommitPlacementAcquisitionReceipt, CommitPlacementAcquisitionRequest,
        PLACEMENT_ACQUISITION_PROFILE, PlacementAcquisitionFault, PlacementAcquisitionFaultCode,
        PlacementAcquisitionLimits, acquire_commit_placements, canonical_record_blob,
        placement_acquisition_receipt_digest, validate_placement_acquisition_receipt,
    },
    sjs_repository_graph::{
        ChangeSetManifest, DiffInventory, PublicationState, VerificationAuthority,
        change_set_manifest_digest, compile_sjs_repository_graph_verification,
        diff_inventory_digest,
    },
};
use sha2::{Digest, Sha256};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

struct TempRoot {
    path: PathBuf,
}

impl TempRoot {
    fn new() -> Self {
        let base = std::env::temp_dir();
        let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = base.join(format!(
            "cantor-p3-physical-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        Self { path }
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let base = fs::canonicalize(std::env::temp_dir()).unwrap();
        if let Ok(path) = fs::canonicalize(&self.path) {
            assert!(path.starts_with(base));
            fs::remove_dir_all(path).unwrap();
        }
    }
}

struct PhysicalFixture {
    temp: TempRoot,
    request: CommitPlacementAcquisitionRequest,
}

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn locate_git() -> PathBuf {
    if let Some(path) = std::env::var_os("CANTOR_TEST_GIT") {
        return fs::canonicalize(path).unwrap();
    }
    let output = if cfg!(windows) {
        Command::new("where.exe").arg("git.exe").output().unwrap()
    } else {
        Command::new("which").arg("git").output().unwrap()
    };
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    fs::canonicalize(text.lines().next().unwrap().trim()).unwrap()
}

fn run_git(git: &Path, repository: &Path, arguments: &[&str]) -> String {
    let output = Command::new(git)
        .current_dir(repository)
        .args(arguments)
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "Git {:?} failed: {}",
        arguments,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    String::from_utf8(output.stdout)
        .unwrap()
        .trim_end_matches(['\r', '\n'])
        .to_owned()
}

fn commit_all(git: &Path, repository: &Path, message: &str) -> String {
    run_git(git, repository, &["add", "--all"]);
    run_git(git, repository, &["commit", "-q", "-m", message]);
    run_git(git, repository, &["rev-parse", "HEAD"])
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

struct LinkParts {
    inventory: DiffInventory,
    candidate: ChangeSetManifest,
    candidate_receipt: cantor_ecosystem::sjs_repository_graph::VerificationReceipt,
    published: ChangeSetManifest,
    published_receipt: cantor_ecosystem::sjs_repository_graph::VerificationReceipt,
    record: CommitEnvelopeRecord,
}

fn build_link_parts(
    predecessor: &str,
    result: &str,
    record_uuid: &str,
    journal_path: &str,
) -> LinkParts {
    let (mut inventory, mut candidate) = base_forms();
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
    LinkParts {
        inventory,
        candidate,
        candidate_receipt,
        published,
        published_receipt,
        record,
    }
}

fn finish_link(parts: LinkParts, carrier: &str) -> JournalLink {
    let mut placement = PlacementObservation {
        profile: PLACEMENT_PROFILE.to_owned(),
        record_sha256: parts.record.record_sha256.clone(),
        journal_path: parts.record.journal_path.clone(),
        carrier_parent_commit: parts.record.payload_resulting_commit.clone(),
        carrier_commit: carrier.to_owned(),
        authority: PlacementAuthority::SuppliedData,
        physical_contact: false,
        placement_sha256: String::new(),
    };
    placement.placement_sha256 = placement_observation_digest(&placement).unwrap();
    JournalLink {
        inventory: parts.inventory,
        candidate_manifest: parts.candidate,
        candidate_receipt: parts.candidate_receipt,
        published_manifest: parts.published,
        published_receipt: parts.published_receipt,
        record: parts.record,
        placement,
    }
}

fn write_record(repository: &Path, record: &CommitEnvelopeRecord, tamper: bool) -> PathBuf {
    let path = repository.join(
        record
            .journal_path
            .replace('/', std::path::MAIN_SEPARATOR_STR),
    );
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut bytes = canonical_record_blob(record).unwrap();
    if tamper {
        bytes.push(b' ');
    }
    fs::write(&path, bytes).unwrap();
    path
}

fn sha256_file(path: &Path) -> String {
    let bytes = fs::read(path).unwrap();
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02X}")).collect()
}

fn build_fixture(link_count: usize, tamper_first: bool, executable_first: bool) -> PhysicalFixture {
    assert!((1..=2).contains(&link_count));
    let temp = TempRoot::new();
    let repository = temp.path.join("repository");
    fs::create_dir(&repository).unwrap();
    let git = locate_git();
    run_git(
        &git,
        &repository,
        &["init", "-q", "-b", "codex/self-hosted-corpus"],
    );
    run_git(&git, &repository, &["config", "user.name", "Cantor P3"]);
    run_git(
        &git,
        &repository,
        &["config", "user.email", "cantor-p3@example.invalid"],
    );
    run_git(&git, &repository, &["config", "core.autocrlf", "false"]);
    fs::write(repository.join("payload.txt"), b"anchor\n").unwrap();
    let anchor = commit_all(&git, &repository, "anchor");
    fs::write(repository.join("payload.txt"), b"payload\n").unwrap();
    let payload = commit_all(&git, &repository, "payload");

    let first_parts = build_link_parts(
        &anchor,
        &payload,
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "narrative/commit_envelopes/a.json",
    );
    let first_record_path = write_record(&repository, &first_parts.record, tamper_first);
    run_git(&git, &repository, &["add", "--all"]);
    if executable_first {
        let relative = first_record_path
            .strip_prefix(&repository)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        run_git(
            &git,
            &repository,
            &["update-index", "--chmod=+x", &relative],
        );
    }
    run_git(&git, &repository, &["commit", "-q", "-m", "carrier one"]);
    let first_carrier = run_git(&git, &repository, &["rev-parse", "HEAD"]);
    let first_link = finish_link(first_parts, &first_carrier);
    let mut links = vec![first_link];

    if link_count == 2 {
        let second_parts = build_link_parts(
            &payload,
            &first_carrier,
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "narrative/commit_envelopes/b.json",
        );
        write_record(&repository, &second_parts.record, false);
        let second_carrier = commit_all(&git, &repository, "carrier two");
        links.push(finish_link(second_parts, &second_carrier));
    }

    let open_tip_commit = links.last().unwrap().placement.carrier_commit.clone();
    let mut journal = CommitEnvelopeJournal {
        profile: JOURNAL_PROFILE.to_owned(),
        repository_id: links[0].inventory.repository_id.clone(),
        branch_ref: links[0].inventory.branch_ref.clone(),
        anchor_commit: anchor,
        open_tip_commit: open_tip_commit.clone(),
        links,
        authority: VerificationAuthority::VerificationOnly,
        physical_contact: false,
        journal_sha256: String::new(),
    };
    journal.journal_sha256 = commit_envelope_journal_digest(&journal).unwrap();
    let request = CommitPlacementAcquisitionRequest {
        profile: PLACEMENT_ACQUISITION_PROFILE.to_owned(),
        repository_id: journal.repository_id.clone(),
        branch_ref: journal.branch_ref.clone(),
        expected_head: open_tip_commit,
        object_format: "sha1".to_owned(),
        repository_root: fs::canonicalize(&repository)
            .unwrap()
            .to_string_lossy()
            .into_owned(),
        git_executable: git.to_string_lossy().into_owned(),
        expected_git_sha256: sha256_file(&git),
        journal,
        limits: PlacementAcquisitionLimits {
            max_command_stdout_bytes: 1_048_576,
            max_command_stderr_bytes: 65_536,
            max_record_blob_bytes: 65_536,
            max_total_record_blob_bytes: 131_072,
            max_git_commands: 64,
        },
    };
    PhysicalFixture { temp, request }
}

#[test]
fn one_and_two_link_physical_acquisition_pass_and_replay() {
    for links in 1..=2 {
        let fixture = build_fixture(links, false, false);
        let index = fixture.temp.path.join("repository/.git/index");
        let before_index = sha256_file(&index);
        let first = acquire_commit_placements(&fixture.request).unwrap();
        let second = acquire_commit_placements(&fixture.request).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.observations.len(), links);
        assert!(first.physical_contact);
        assert_eq!(first.repository_before, first.repository_after);
        assert_eq!(sha256_file(&index), before_index);
        validate_placement_acquisition_receipt(&fixture.request, &first).unwrap();
    }
}

#[test]
fn raw_blob_tamper_and_executable_mode_are_refused() {
    let tampered = build_fixture(1, true, false);
    assert_eq!(
        acquire_commit_placements(&tampered.request)
            .unwrap_err()
            .code,
        PlacementAcquisitionFaultCode::Blob
    );
    let executable = build_fixture(1, false, true);
    assert_eq!(
        acquire_commit_placements(&executable.request)
            .unwrap_err()
            .code,
        PlacementAcquisitionFaultCode::Tree
    );
}

#[test]
fn cli_emits_stdout_receipt_and_refuses_output_path() {
    let fixture = build_fixture(1, false, false);
    let request_path = fixture.temp.path.join("request.json");
    fs::write(&request_path, serde_json::to_vec(&fixture.request).unwrap()).unwrap();
    let binary = env!("CARGO_BIN_EXE_cantor-sjs-commit-placement-acquire");
    let success = Command::new(binary)
        .args(["--request", request_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(success.status.success());
    assert!(success.stderr.is_empty());
    let receipt: CommitPlacementAcquisitionReceipt =
        serde_json::from_slice(&success.stdout).unwrap();
    assert_eq!(receipt.observations.len(), 1);

    let forbidden = fixture.temp.path.join("forbidden.json");
    let refusal = Command::new(binary)
        .args(["--output", forbidden.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(refusal.status.code(), Some(2));
    assert!(refusal.stdout.is_empty());
    let fault: PlacementAcquisitionFault = serde_json::from_slice(&refusal.stderr).unwrap();
    assert_eq!(fault.code, PlacementAcquisitionFaultCode::Cli);
    assert!(!forbidden.exists());
}

#[test]
fn noncanonical_repository_path_and_git_version_replay_are_refused() {
    let mut noncanonical = build_fixture(1, false, false);
    noncanonical
        .request
        .repository_root
        .push(std::path::MAIN_SEPARATOR);
    assert_eq!(
        acquire_commit_placements(&noncanonical.request)
            .unwrap_err()
            .code,
        PlacementAcquisitionFaultCode::Repository
    );

    let fixture = build_fixture(1, false, false);
    let mut receipt = acquire_commit_placements(&fixture.request).unwrap();
    receipt.git_version.clear();
    receipt.result_sha256.clear();
    receipt.result_sha256 = placement_acquisition_receipt_digest(&receipt).unwrap();
    assert_eq!(
        validate_placement_acquisition_receipt(&fixture.request, &receipt)
            .unwrap_err()
            .code,
        PlacementAcquisitionFaultCode::Process
    );
}

#[test]
fn signed_boundary_and_product_effect_absence_are_static() {
    let root = repository_root();
    let module = fs::read_to_string(
        root.join("crates/cantor_ecosystem/src/sjs_commit_placement_acquisition.rs"),
    )
    .unwrap();
    let production = module.split("#[cfg(test)]").next().unwrap();
    let cli = fs::read_to_string(
        root.join("crates/cantor_ecosystem/src/bin/cantor-sjs-commit-placement-acquire.rs"),
    )
    .unwrap();
    let cli_production = cli.split("#[cfg(test)]").next().unwrap();
    let specification = fs::read_to_string(
        root.join("specifications/Cantor_SJS_Commit_Placement_Acquisition_P3.sop"),
    )
    .unwrap();
    let signature = fs::read_to_string(root.join(
        "narrative/registries/Cantor_SJS_Commit_Placement_Acquisition_P3_Satisfaction_Signature.sop",
    ))
    .unwrap();
    let threat_review = fs::read_to_string(root.join(
        "narrative/research/Cantor_SJS_Commit_Placement_Acquisition_P3_Threat_Review_2026-08-24.sop",
    ))
    .unwrap();

    for requirement in 1..=20 {
        assert!(specification.contains(&format!("CPA-{requirement:03}")));
    }
    for threat in 1..=20 {
        assert!(threat_review.contains(&format!("T{threat:02}")));
    }
    assert!(signature.contains("[status] valid"));
    assert!(signature.contains("29c32998-d592-40f7-9481-6cba19634581"));
    for forbidden in [
        "fs::write",
        "File::create",
        "OpenOptions",
        "TcpStream",
        "reqwest",
        "unsafe {",
        "&[\"add\"",
        "&[\"commit\"",
        "&[\"push\"",
        "&[\"reset\"",
        "&[\"fetch\"",
    ] {
        assert!(
            !production.contains(forbidden),
            "module contains {forbidden}"
        );
    }
    for forbidden in ["--output", "fs::write", "File::create", "Command::new"] {
        assert!(
            !cli_production.contains(forbidden),
            "CLI contains {forbidden}"
        );
    }
}
