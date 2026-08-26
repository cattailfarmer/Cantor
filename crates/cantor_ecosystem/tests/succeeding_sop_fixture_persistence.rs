use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use cantor_core::{
    ContentDigest, SemanticId, SucceedingSopActivationTransactionReceipt,
    from_succeeding_sop_activation_transaction_receipt_machine_form,
};
use cantor_ecosystem::*;
#[cfg(not(windows))]
use serde_json::Value;

#[path = "succeeding_sop_fixture_rollback.rs"]
mod succeeding_sop_fixture_rollback;

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);
const SOURCE_TEXT: &str = "Subject: Cantor Fixture Succeeding SOP\n\n& [Purpose]\n  + continue the exact verified frontier\n";
const PREDECESSOR_SOURCE_TEXT: &str = "Subject: Cantor Fixture Current SOP\n\n& [Purpose]\n  + preserve the exact rollback predecessor\n";

fn id(value: &str) -> SemanticId {
    SemanticId::new(value).expect("fixture identity")
}

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: "0".repeat(64),
    }
}

fn activation_transaction() -> SucceedingSopActivationTransactionReceipt {
    from_succeeding_sop_activation_transaction_receipt_machine_form(
        include_str!("fixtures/succeeding_sop_activation_transaction_receipt.json").trim(),
    )
    .expect("checked synthetic activation transaction fixture")
}

fn marker() -> SucceedingSopFixtureRootMarker {
    let mut marker = SucceedingSopFixtureRootMarker {
        profile: SUCCEEDING_SOP_FIXTURE_ROOT_MARKER_PROFILE.to_owned(),
        marker_ref: id("fixture-marker:swa-06b2b1"),
        fixture_root_ref: id("fixture-root:swa-06b2b1"),
        recovery_owner_ref: id("recovery-owner:independent-fixture"),
        disposable_fixture: true,
        live_repository: false,
        live_activation_allowed: false,
        evidence_refs: [id("evidence:fixture-root-authorized")]
            .into_iter()
            .collect(),
        marker_digest: empty_digest(),
    };
    marker.marker_digest =
        succeeding_sop_fixture_root_marker_digest(&marker).expect("marker digest");
    marker
}

fn commission() -> SucceedingSopFixturePersistenceCommission {
    let mut commission = SucceedingSopFixturePersistenceCommission {
        profile: SUCCEEDING_SOP_FIXTURE_PERSISTENCE_COMMISSION_PROFILE.to_owned(),
        commission_ref: id("fixture-persistence-commission:swa-06b2b1"),
        fixture_root_ref: id("fixture-root:swa-06b2b1"),
        recovery_owner_ref: id("recovery-owner:independent-fixture"),
        successor_snapshot_ref: id("registry-snapshot:swa-06b2b1-successor"),
        activation_transaction: activation_transaction(),
        evidence_refs: [id("evidence:fixture-persistence-commission")]
            .into_iter()
            .collect(),
        fixture_only: true,
        live_activation_allowed: false,
        cleanup_authorized: false,
        commission_digest: empty_digest(),
    };
    commission.commission_digest =
        succeeding_sop_fixture_persistence_commission_digest(&commission)
            .expect("commission digest");
    commission
}

struct Fixture {
    root: PathBuf,
    marker: SucceedingSopFixtureRootMarker,
    commission: SucceedingSopFixturePersistenceCommission,
    predecessor_bytes: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "cantor-swa-06b2b1-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("fixture root");
        let marker = marker();
        let commission = commission();
        let request = &commission.activation_transaction.request;
        assert_eq!(
            request
                .review_admission
                .request
                .proposal_verification
                .proposal
                .source_text,
            SOURCE_TEXT
        );

        let marker_form =
            to_succeeding_sop_fixture_root_marker_machine_form(&marker).expect("marker form");
        fs::write(
            root.join(SUCCEEDING_SOP_FIXTURE_ROOT_MARKER_FILE),
            format!("{marker_form}\n"),
        )
        .expect("marker write");

        let source_path = physical(&root, &request.source_reacquisition.source_path);
        fs::create_dir_all(source_path.parent().expect("source parent"))
            .expect("source parent create");
        fs::write(&source_path, SOURCE_TEXT.as_bytes()).expect("source write");

        let predecessor_source_path = physical(&root, &request.rollback.rollback_source_path);
        fs::create_dir_all(
            predecessor_source_path
                .parent()
                .expect("predecessor source parent"),
        )
        .expect("predecessor source parent create");
        fs::write(&predecessor_source_path, PREDECESSOR_SOURCE_TEXT.as_bytes())
            .expect("predecessor source write");
        assert_eq!(
            cantor_core::sha256_bytes(PREDECESSOR_SOURCE_TEXT.as_bytes()),
            request.rollback.rollback_revision_digest
        );

        let registry = predecessor_succeeding_sop_fixture_registry_record(&marker, &commission)
            .expect("predecessor registry");
        let registry_form = to_succeeding_sop_fixture_registry_record_machine_form(&registry)
            .expect("registry form");
        let predecessor_bytes = format!("{registry_form}\n").into_bytes();
        let registry_path = physical(&root, &request.current_registry.registry_path);
        fs::create_dir_all(registry_path.parent().expect("registry parent"))
            .expect("registry parent create");
        fs::write(&registry_path, &predecessor_bytes).expect("registry write");

        Self {
            root,
            marker,
            commission,
            predecessor_bytes,
        }
    }

    fn source_path(&self) -> PathBuf {
        physical(
            &self.root,
            &self
                .commission
                .activation_transaction
                .request
                .source_reacquisition
                .source_path,
        )
    }

    fn registry_path(&self) -> PathBuf {
        physical(
            &self.root,
            &self
                .commission
                .activation_transaction
                .request
                .current_registry
                .registry_path,
        )
    }

    fn temp_path(&self) -> PathBuf {
        physical(
            &self.root,
            &self
                .commission
                .activation_transaction
                .request
                .transition
                .registry_temp_path,
        )
    }

    fn write_marker(&self, marker: &SucceedingSopFixtureRootMarker) {
        let form = to_succeeding_sop_fixture_root_marker_machine_form(marker).expect("marker form");
        fs::write(
            self.root.join(SUCCEEDING_SOP_FIXTURE_ROOT_MARKER_FILE),
            format!("{form}\n"),
        )
        .expect("marker rewrite");
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).expect("fixture cleanup");
    }
}

fn physical(root: &Path, relative: &str) -> PathBuf {
    relative
        .split('/')
        .fold(root.to_path_buf(), |path, segment| path.join(segment))
}

#[test]
#[cfg(not(windows))]
fn exact_fixture_persistence_selects_successor_and_replays_deterministically() {
    let first = Fixture::new();
    let first_receipt = execute_succeeding_sop_fixture_persistence(&first.root, &first.commission)
        .expect("fixture persistence");
    validate_succeeding_sop_fixture_persistence_receipt(&first_receipt)
        .expect("receipt validation");
    assert!(first_receipt.physical_contact);
    assert!(first_receipt.source_reacquired);
    assert!(first_receipt.registry_observed);
    assert!(first_receipt.registry_persisted);
    assert!(first_receipt.current_sop_selected);
    assert!(first_receipt.temp_absent_after);
    assert!(!first_receipt.boot_activation_verified);
    assert!(!first_receipt.rollback_executed);
    assert!(!first_receipt.live_activation_performed);
    assert!(!first_receipt.provider_contacted);
    assert!(!first_receipt.process_launched);
    assert!(!first.temp_path().exists());

    let successor_form = fs::read_to_string(first.registry_path()).expect("successor registry");
    let successor = from_succeeding_sop_fixture_registry_record_machine_form(successor_form.trim())
        .expect("successor form");
    let transition = &first.commission.activation_transaction.request.transition;
    assert_eq!(successor.current.generation, transition.after_generation);
    assert_eq!(
        successor.current.current_revision_ref,
        transition.candidate_proposal_ref
    );
    assert_eq!(
        successor.current.current_revision_digest,
        transition.candidate_proposal_digest
    );
    assert_eq!(
        successor.current.current_source_path,
        transition.candidate_source_path
    );
    assert_eq!(
        successor.last_transaction_ref.as_ref(),
        Some(&transition.transaction_ref)
    );

    let receipt_form = to_succeeding_sop_fixture_persistence_receipt_machine_form(&first_receipt)
        .expect("receipt form");
    assert_eq!(
        first_receipt,
        from_succeeding_sop_fixture_persistence_receipt_machine_form(&receipt_form)
            .expect("receipt round trip")
    );

    let second = Fixture::new();
    let second_receipt =
        execute_succeeding_sop_fixture_persistence(&second.root, &second.commission)
            .expect("second fixture persistence");
    assert_eq!(first_receipt, second_receipt);
}

#[test]
#[cfg(windows)]
fn windows_parent_flush_refuses_with_exact_post_replacement_state() {
    let fixture = Fixture::new();
    let fault = execute_succeeding_sop_fixture_persistence(&fixture.root, &fixture.commission)
        .expect_err("Windows safe parent flush is unavailable");
    assert_eq!(
        fault.code,
        SucceedingSopFixturePersistenceFaultCode::Durability
    );
    assert!(fault.physical_contact);
    assert!(fault.replacement_performed);
    assert!(!fault.owned_temp_removed);
    assert!(!fixture.temp_path().exists());
    assert_ne!(
        fs::read(fixture.registry_path()).expect("post-replacement registry"),
        fixture.predecessor_bytes
    );
}

#[test]
fn upstream_and_commission_authority_laundering_refuse_without_contact() {
    let fixture = Fixture::new();
    let mut upstream = fixture.commission.clone();
    upstream.activation_transaction.physical_execution_eligible = true;
    upstream.commission_digest = empty_digest();
    upstream.commission_digest =
        succeeding_sop_fixture_persistence_commission_digest(&upstream).expect("digest");
    let fault = execute_succeeding_sop_fixture_persistence(&fixture.root, &upstream)
        .expect_err("upstream laundering");
    assert_eq!(
        fault.code,
        SucceedingSopFixturePersistenceFaultCode::InvalidUpstream
    );
    assert!(!fault.physical_contact);
    assert_eq!(
        fs::read(fixture.registry_path()).expect("registry"),
        fixture.predecessor_bytes
    );

    let mut live = fixture.commission.clone();
    live.live_activation_allowed = true;
    live.commission_digest = empty_digest();
    live.commission_digest =
        succeeding_sop_fixture_persistence_commission_digest(&live).expect("digest");
    let fault = execute_succeeding_sop_fixture_persistence(&fixture.root, &live)
        .expect_err("live authority");
    assert_eq!(
        fault.code,
        SucceedingSopFixturePersistenceFaultCode::InvalidCommission
    );
    assert!(!fault.physical_contact);
}

#[test]
fn marker_live_root_and_git_substitutions_refuse_before_source_or_registry_change() {
    let fixture = Fixture::new();
    let mut live = fixture.marker.clone();
    live.live_repository = true;
    live.marker_digest = empty_digest();
    live.marker_digest = succeeding_sop_fixture_root_marker_digest(&live).expect("digest");
    let form = serde_json::to_string(&live).expect("live marker form");
    fs::write(
        fixture.root.join(SUCCEEDING_SOP_FIXTURE_ROOT_MARKER_FILE),
        format!("{form}\n"),
    )
    .expect("live marker write");
    let fault = execute_succeeding_sop_fixture_persistence(&fixture.root, &fixture.commission)
        .expect_err("live marker");
    assert_eq!(
        fault.code,
        SucceedingSopFixturePersistenceFaultCode::InvalidMarker
    );
    assert!(fault.physical_contact);
    assert_eq!(
        fs::read(fixture.registry_path()).expect("registry"),
        fixture.predecessor_bytes
    );

    fixture.write_marker(&fixture.marker);
    fs::create_dir(fixture.root.join(".git")).expect("forbidden git entry");
    let fault = execute_succeeding_sop_fixture_persistence(&fixture.root, &fixture.commission)
        .expect_err("git root");
    assert_eq!(
        fault.code,
        SucceedingSopFixturePersistenceFaultCode::InvalidRoot
    );
    assert!(fault.physical_contact);
}

#[test]
fn source_registry_and_existing_temp_tampering_refuse_without_replacement() {
    let source = Fixture::new();
    fs::write(source.source_path(), b"tampered source").expect("source tamper");
    let fault = execute_succeeding_sop_fixture_persistence(&source.root, &source.commission)
        .expect_err("source tamper");
    assert_eq!(
        fault.code,
        SucceedingSopFixturePersistenceFaultCode::InvalidSource
    );
    assert!(!fault.replacement_performed);
    assert_eq!(
        fs::read(source.registry_path()).expect("registry"),
        source.predecessor_bytes
    );

    let registry = Fixture::new();
    let mut stale =
        predecessor_succeeding_sop_fixture_registry_record(&registry.marker, &registry.commission)
            .expect("predecessor");
    stale.current.generation += 1;
    stale.current.snapshot_digest = empty_digest();
    stale.current.snapshot_digest =
        cantor_core::succeeding_sop_current_registry_snapshot_digest(&stale.current)
            .expect("snapshot digest");
    stale.record_digest = empty_digest();
    stale.record_digest =
        succeeding_sop_fixture_registry_record_digest(&stale).expect("record digest");
    let stale_form =
        to_succeeding_sop_fixture_registry_record_machine_form(&stale).expect("stale form");
    fs::write(registry.registry_path(), format!("{stale_form}\n")).expect("stale write");
    let fault = execute_succeeding_sop_fixture_persistence(&registry.root, &registry.commission)
        .expect_err("stale registry");
    assert_eq!(
        fault.code,
        SucceedingSopFixturePersistenceFaultCode::InvalidRegistry
    );
    assert!(!fault.replacement_performed);

    let temporary = Fixture::new();
    fs::write(temporary.temp_path(), b"foreign temporary").expect("existing temporary");
    let fault = execute_succeeding_sop_fixture_persistence(&temporary.root, &temporary.commission)
        .expect_err("existing temporary");
    assert_eq!(
        fault.code,
        SucceedingSopFixturePersistenceFaultCode::InvalidTemporary
    );
    assert_eq!(
        fs::read(temporary.temp_path()).expect("foreign temp"),
        b"foreign temporary"
    );
    assert_eq!(
        fs::read(temporary.registry_path()).expect("registry"),
        temporary.predecessor_bytes
    );
}

#[test]
fn source_link_or_reparse_substitution_refuses_when_platform_supports_fixture_link() {
    let fixture = Fixture::new();
    let source = fixture.source_path();
    let alternate = fixture.root.join("alternate-source.sop");
    fs::write(&alternate, SOURCE_TEXT).expect("alternate source");
    fs::remove_file(&source).expect("remove source leaf");
    #[cfg(unix)]
    let linked = std::os::unix::fs::symlink(&alternate, &source);
    #[cfg(windows)]
    let linked = std::os::windows::fs::symlink_file(&alternate, &source);
    if linked.is_err() {
        fs::write(&source, SOURCE_TEXT).expect("restore unsupported link fixture");
        return;
    }
    let fault = execute_succeeding_sop_fixture_persistence(&fixture.root, &fixture.commission)
        .expect_err("source link");
    assert_eq!(
        fault.code,
        SucceedingSopFixturePersistenceFaultCode::LinkOrReparse
    );
    assert!(!fault.replacement_performed);
}

#[test]
#[cfg(not(windows))]
fn receipt_and_machine_form_mutations_refuse() {
    let fixture = Fixture::new();
    let receipt = execute_succeeding_sop_fixture_persistence(&fixture.root, &fixture.commission)
        .expect("fixture persistence");
    let mut authority = receipt.clone();
    authority.boot_activation_verified = true;
    authority.receipt_digest = empty_digest();
    authority.receipt_digest =
        succeeding_sop_fixture_persistence_receipt_digest(&authority).expect("digest");
    assert_eq!(
        validate_succeeding_sop_fixture_persistence_receipt(&authority)
            .expect_err("boot laundering")
            .code,
        SucceedingSopFixturePersistenceFaultCode::InvalidCommission
    );

    let form =
        to_succeeding_sop_fixture_persistence_receipt_machine_form(&receipt).expect("receipt form");
    let mut unknown: Value = serde_json::from_str(&form).expect("receipt json");
    unknown["live_authority"] = Value::Bool(true);
    assert_eq!(
        from_succeeding_sop_fixture_persistence_receipt_machine_form(
            &serde_json::to_string(&unknown).expect("unknown form")
        )
        .expect_err("unknown field")
        .code,
        SucceedingSopFixturePersistenceFaultCode::InvalidMachineForm
    );
    let oversized = "x".repeat(SUCCEEDING_SOP_FIXTURE_PERSISTENCE_MAX_MACHINE_FORM_BYTES + 1);
    assert_eq!(
        from_succeeding_sop_fixture_persistence_receipt_machine_form(&oversized)
            .expect_err("oversized")
            .code,
        SucceedingSopFixturePersistenceFaultCode::InvalidBound
    );
}

#[test]
fn production_surface_has_no_ambient_or_live_activation_capability() {
    let module = include_str!("../src/succeeding_sop_fixture_persistence.rs");
    for forbidden in [
        "std::env",
        "std::process",
        "std::net",
        "Command::new",
        "TcpStream",
        "UdpSocket",
        "SystemTime",
        "unsafe {",
        "git commit",
        "git push",
        "remove_dir_all",
    ] {
        assert!(
            !module.contains(forbidden),
            "forbidden production surface: {forbidden}"
        );
    }
    assert!(!module.contains("boot_sop"));
    assert!(!module.contains("execute_rollback"));
}
