use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use cantor_core::{
    ContentDigest, SemanticId, from_succeeding_sop_activation_transaction_receipt_machine_form,
    sha256_bytes,
};
use cantor_ecosystem::*;
#[cfg(test)]
use serde_json::Value;

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);
const CANDIDATE_SOURCE: &str = "Subject: Cantor Fixture Succeeding SOP\n\n& [Purpose]\n  + continue the exact verified frontier\n";
const PREDECESSOR_SOURCE: &str = "Subject: Cantor Fixture Current SOP\n\n& [Purpose]\n  + preserve the exact rollback predecessor\n";

fn id(value: &str) -> SemanticId {
    SemanticId::new(value).expect("fixture identity")
}

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: "0".repeat(64),
    }
}

fn activation_transaction() -> cantor_core::SucceedingSopActivationTransactionReceipt {
    from_succeeding_sop_activation_transaction_receipt_machine_form(
        include_str!("fixtures/succeeding_sop_activation_transaction_receipt.json").trim(),
    )
    .expect("corrected synthetic activation transaction fixture")
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

fn persistence_commission() -> SucceedingSopFixturePersistenceCommission {
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
        succeeding_sop_fixture_persistence_commission_digest(&commission).expect("digest");
    commission
}

struct Fixture {
    root: PathBuf,
    persistence_commission: SucceedingSopFixturePersistenceCommission,
    persistence_receipt: SucceedingSopFixturePersistenceReceipt,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "cantor-swa-06b2b2-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("fixture root");
        let marker = marker();
        let persistence_commission = persistence_commission();
        let request = &persistence_commission.activation_transaction.request;
        assert_eq!(
            request.rollback.rollback_revision_digest,
            sha256_bytes(PREDECESSOR_SOURCE.as_bytes())
        );

        let marker_form =
            to_succeeding_sop_fixture_root_marker_machine_form(&marker).expect("marker form");
        fs::write(
            root.join(SUCCEEDING_SOP_FIXTURE_ROOT_MARKER_FILE),
            format!("{marker_form}\n"),
        )
        .expect("marker write");
        let candidate_path = physical(&root, &request.source_reacquisition.source_path);
        fs::create_dir_all(candidate_path.parent().expect("candidate parent"))
            .expect("candidate parent create");
        fs::write(&candidate_path, CANDIDATE_SOURCE.as_bytes()).expect("candidate write");
        let predecessor_path = physical(&root, &request.rollback.rollback_source_path);
        fs::create_dir_all(predecessor_path.parent().expect("predecessor parent"))
            .expect("predecessor parent create");
        fs::write(&predecessor_path, PREDECESSOR_SOURCE.as_bytes()).expect("predecessor write");

        let predecessor_record =
            predecessor_succeeding_sop_fixture_registry_record(&marker, &persistence_commission)
                .expect("predecessor record");
        let predecessor_form =
            to_succeeding_sop_fixture_registry_record_machine_form(&predecessor_record)
                .expect("predecessor form");
        let predecessor_bytes = format!("{predecessor_form}\n").into_bytes();
        let registry_path = physical(&root, &request.current_registry.registry_path);
        fs::create_dir_all(registry_path.parent().expect("registry parent"))
            .expect("registry parent create");
        fs::write(&registry_path, &predecessor_bytes).expect("registry write");

        let persistence_result =
            execute_succeeding_sop_fixture_persistence(&root, &persistence_commission);
        #[cfg(not(windows))]
        let persistence_receipt = persistence_result.expect("B2B1 fixture success");
        #[cfg(windows)]
        let persistence_receipt = {
            let fault = persistence_result.expect_err("Windows parent durability refusal");
            assert_eq!(
                fault.code,
                SucceedingSopFixturePersistenceFaultCode::Durability
            );
            assert!(fault.replacement_performed);
            let successor_bytes = fs::read(&registry_path).expect("successor bytes");
            let successor = from_succeeding_sop_fixture_registry_record_machine_form(
                std::str::from_utf8(&successor_bytes).expect("successor UTF-8"),
            )
            .expect("successor record");
            let mut receipt = SucceedingSopFixturePersistenceReceipt {
                profile: SUCCEEDING_SOP_FIXTURE_PERSISTENCE_RECEIPT_PROFILE.to_owned(),
                commission: persistence_commission.clone(),
                status: SucceedingSopFixturePersistenceStatus::FixtureRegistryPersistedAwaitingBootValidation,
                authority: SucceedingSopFixturePersistenceAuthority::SyntheticFixturePersistenceOnly,
                marker_digest: marker.marker_digest.clone(),
                activation_transaction_receipt_digest: persistence_commission
                    .activation_transaction
                    .receipt_digest
                    .clone(),
                source_raw_digest: sha256_bytes(CANDIDATE_SOURCE.as_bytes()),
                predecessor_registry_raw_digest: sha256_bytes(&predecessor_bytes),
                successor_registry_raw_digest: sha256_bytes(&successor_bytes),
                predecessor_record_digest: predecessor_record.record_digest,
                successor_record_digest: successor.record_digest,
                verified_checks: SUCCEEDING_SOP_FIXTURE_PERSISTENCE_CHECKS
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
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
            receipt.receipt_digest = succeeding_sop_fixture_persistence_receipt_digest(&receipt)
                .expect("receipt digest");
            validate_succeeding_sop_fixture_persistence_receipt(&receipt)
                .expect("supplied exact B2B1 success receipt");
            receipt
        };

        Self {
            root,
            persistence_commission,
            persistence_receipt,
        }
    }

    fn rollback_commission(&self) -> SucceedingSopFixtureRollbackCommission {
        let mut commission = SucceedingSopFixtureRollbackCommission {
            profile: SUCCEEDING_SOP_FIXTURE_ROLLBACK_COMMISSION_PROFILE.to_owned(),
            commission_ref: id("fixture-rollback-commission:swa-06b2b2"),
            recovery_owner_ref: id("recovery-owner:independent-fixture"),
            failed_snapshot_ref: self.persistence_commission.successor_snapshot_ref.clone(),
            restored_snapshot_ref: id("registry-snapshot:swa-06b2b2-restored"),
            trigger: SUCCEEDING_SOP_FIXTURE_ROLLBACK_TRIGGER.to_owned(),
            trigger_evidence_ref: id("trigger-evidence:boot-validation-failed"),
            persistence_receipt: self.persistence_receipt.clone(),
            evidence_refs: [id("evidence:fixture-rollback-commission")]
                .into_iter()
                .collect(),
            fixture_only: true,
            live_activation_allowed: false,
            cleanup_authorized: false,
            commission_digest: empty_digest(),
        };
        commission.commission_digest =
            succeeding_sop_fixture_rollback_commission_digest(&commission).expect("digest");
        commission
    }

    #[cfg(test)]
    fn registry_path(&self) -> PathBuf {
        physical(
            &self.root,
            &self
                .persistence_commission
                .activation_transaction
                .request
                .transition
                .registry_final_path,
        )
    }

    #[cfg(test)]
    fn temp_path(&self) -> PathBuf {
        physical(
            &self.root,
            &self
                .persistence_commission
                .activation_transaction
                .request
                .transition
                .registry_temp_path,
        )
    }

    #[cfg(test)]
    fn predecessor_path(&self) -> PathBuf {
        physical(
            &self.root,
            &self
                .persistence_commission
                .activation_transaction
                .request
                .rollback
                .rollback_source_path,
        )
    }

    #[cfg(test)]
    fn candidate_path(&self) -> PathBuf {
        physical(
            &self.root,
            &self
                .persistence_commission
                .activation_transaction
                .request
                .transition
                .candidate_source_path,
        )
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

#[cfg(not(windows))]
#[allow(dead_code)]
pub fn development_success_receipt_machine_form() -> String {
    let fixture = Fixture::new();
    let receipt =
        execute_succeeding_sop_fixture_rollback(&fixture.root, &fixture.rollback_commission())
            .expect("development fixture rollback success");
    to_succeeding_sop_fixture_rollback_receipt_machine_form(&receipt)
        .expect("development fixture receipt form")
}

#[test]
#[cfg(not(windows))]
fn exact_fixture_rollback_restores_predecessor_monotonically_and_replays() {
    let first = Fixture::new();
    let commission = first.rollback_commission();
    let receipt = execute_succeeding_sop_fixture_rollback(&first.root, &commission)
        .expect("fixture rollback");
    validate_succeeding_sop_fixture_rollback_receipt(&receipt).expect("receipt");
    assert_eq!(receipt.current_failed_record.current.generation, 42);
    assert_eq!(receipt.restored_record.current.generation, 43);
    assert_eq!(
        receipt.restored_record.current.current_revision_ref,
        commission
            .persistence_receipt
            .commission
            .activation_transaction
            .request
            .rollback
            .rollback_revision_ref
    );
    assert_eq!(
        fs::read(first.predecessor_path()).unwrap(),
        PREDECESSOR_SOURCE.as_bytes()
    );
    assert!(!first.temp_path().exists());
    let form = to_succeeding_sop_fixture_rollback_receipt_machine_form(&receipt).unwrap();
    assert_eq!(
        receipt,
        from_succeeding_sop_fixture_rollback_receipt_machine_form(&form).unwrap()
    );
}

#[test]
#[cfg(not(windows))]
fn receipt_failed_record_path_laundering_refuses_after_full_rehash() {
    let fixture = Fixture::new();
    let mut receipt =
        execute_succeeding_sop_fixture_rollback(&fixture.root, &fixture.rollback_commission())
            .expect("fixture rollback");
    receipt.current_failed_record.current.current_source_path =
        "source_documents/laundered_candidate.sop".to_owned();
    receipt.current_failed_record.current.snapshot_digest = empty_digest();
    receipt.current_failed_record.current.snapshot_digest =
        cantor_core::succeeding_sop_current_registry_snapshot_digest(
            &receipt.current_failed_record.current,
        )
        .expect("snapshot digest");
    receipt.current_failed_record.record_digest = empty_digest();
    receipt.current_failed_record.record_digest =
        succeeding_sop_fixture_registry_record_digest(&receipt.current_failed_record)
            .expect("record digest");
    receipt
        .commission
        .persistence_receipt
        .successor_record_digest = receipt.current_failed_record.record_digest.clone();
    receipt.commission.persistence_receipt.receipt_digest = empty_digest();
    receipt.commission.persistence_receipt.receipt_digest =
        succeeding_sop_fixture_persistence_receipt_digest(&receipt.commission.persistence_receipt)
            .expect("upstream receipt digest");
    receipt.commission.commission_digest = empty_digest();
    receipt.commission.commission_digest =
        succeeding_sop_fixture_rollback_commission_digest(&receipt.commission)
            .expect("commission digest");
    receipt.receipt_digest = empty_digest();
    receipt.receipt_digest =
        succeeding_sop_fixture_rollback_receipt_digest(&receipt).expect("receipt digest");

    assert_eq!(
        validate_succeeding_sop_fixture_rollback_receipt(&receipt)
            .expect_err("failed-record source-path laundering")
            .code,
        SucceedingSopFixtureRollbackFaultCode::InvalidRegistry
    );
}

#[test]
#[cfg(windows)]
fn windows_parent_flush_refuses_after_exact_restored_replacement() {
    let fixture = Fixture::new();
    let commission = fixture.rollback_commission();
    let fault = execute_succeeding_sop_fixture_rollback(&fixture.root, &commission)
        .expect_err("Windows safe parent flush is unavailable");
    assert_eq!(
        fault.code,
        SucceedingSopFixtureRollbackFaultCode::Durability
    );
    assert!(fault.physical_contact);
    assert!(fault.replacement_performed);
    assert!(fault.failed_candidate_preserved);
    assert!(!fixture.temp_path().exists());
    let restored = from_succeeding_sop_fixture_registry_record_machine_form(
        &fs::read_to_string(fixture.registry_path()).expect("restored registry"),
    )
    .expect("restored record");
    assert_eq!(restored.current.generation, 43);
    assert_eq!(
        restored.current.current_revision_digest,
        sha256_bytes(PREDECESSOR_SOURCE.as_bytes())
    );
}

#[test]
fn commission_trigger_owner_and_upstream_laundering_refuse_without_contact() {
    let fixture = Fixture::new();
    let current = fs::read(fixture.registry_path()).expect("current registry");

    let mut trigger = fixture.rollback_commission();
    trigger.trigger = "operator_abort".to_owned();
    trigger.commission_digest = empty_digest();
    trigger.commission_digest =
        succeeding_sop_fixture_rollback_commission_digest(&trigger).expect("digest");
    let fault = execute_succeeding_sop_fixture_rollback(&fixture.root, &trigger)
        .expect_err("trigger laundering");
    assert_eq!(
        fault.code,
        SucceedingSopFixtureRollbackFaultCode::InvalidTrigger
    );
    assert!(!fault.physical_contact);

    let mut owner = fixture.rollback_commission();
    owner.recovery_owner_ref = id("recovery-owner:substituted");
    owner.commission_digest = empty_digest();
    owner.commission_digest =
        succeeding_sop_fixture_rollback_commission_digest(&owner).expect("digest");
    let fault = execute_succeeding_sop_fixture_rollback(&fixture.root, &owner)
        .expect_err("owner laundering");
    assert_eq!(
        fault.code,
        SucceedingSopFixtureRollbackFaultCode::InvalidIdentity
    );
    assert!(!fault.physical_contact);
    assert_eq!(fs::read(fixture.registry_path()).unwrap(), current);
}

#[test]
fn predecessor_tamper_and_existing_temp_refuse_without_replacement() {
    let predecessor = Fixture::new();
    fs::write(predecessor.predecessor_path(), b"tampered predecessor").unwrap();
    let fault = execute_succeeding_sop_fixture_rollback(
        &predecessor.root,
        &predecessor.rollback_commission(),
    )
    .expect_err("predecessor tamper");
    assert_eq!(
        fault.code,
        SucceedingSopFixtureRollbackFaultCode::InvalidSource
    );
    assert!(!fault.replacement_performed);

    let temporary = Fixture::new();
    fs::write(temporary.temp_path(), b"foreign temporary").unwrap();
    let fault =
        execute_succeeding_sop_fixture_rollback(&temporary.root, &temporary.rollback_commission())
            .expect_err("foreign temp");
    assert_eq!(
        fault.code,
        SucceedingSopFixtureRollbackFaultCode::InvalidTemporary
    );
    assert_eq!(
        fs::read(temporary.temp_path()).unwrap(),
        b"foreign temporary"
    );
}

#[test]
fn current_registry_and_candidate_drift_refuse_before_replacement() {
    let registry = Fixture::new();
    let mut drift = from_succeeding_sop_fixture_registry_record_machine_form(
        &fs::read_to_string(registry.registry_path()).unwrap(),
    )
    .unwrap();
    drift.current.generation += 1;
    drift.current.snapshot_digest = empty_digest();
    drift.current.snapshot_digest =
        cantor_core::succeeding_sop_current_registry_snapshot_digest(&drift.current).unwrap();
    drift.record_digest = empty_digest();
    drift.record_digest = succeeding_sop_fixture_registry_record_digest(&drift).unwrap();
    fs::write(
        registry.registry_path(),
        format!(
            "{}\n",
            to_succeeding_sop_fixture_registry_record_machine_form(&drift).unwrap()
        ),
    )
    .unwrap();
    let fault =
        execute_succeeding_sop_fixture_rollback(&registry.root, &registry.rollback_commission())
            .expect_err("registry drift");
    assert_eq!(
        fault.code,
        SucceedingSopFixtureRollbackFaultCode::InvalidRegistry
    );
    assert!(!fault.replacement_performed);

    let candidate = Fixture::new();
    fs::write(candidate.candidate_path(), b"tampered candidate").unwrap();
    let fault =
        execute_succeeding_sop_fixture_rollback(&candidate.root, &candidate.rollback_commission())
            .expect_err("candidate drift");
    assert_eq!(
        fault.code,
        SucceedingSopFixtureRollbackFaultCode::InvalidSource
    );
    assert!(!fault.replacement_performed);
}

#[test]
fn live_evidence_upstream_and_digest_laundering_refuse_without_contact() {
    let fixture = Fixture::new();

    let mut live = fixture.rollback_commission();
    live.live_activation_allowed = true;
    live.commission_digest = empty_digest();
    live.commission_digest = succeeding_sop_fixture_rollback_commission_digest(&live).unwrap();
    let fault =
        execute_succeeding_sop_fixture_rollback(&fixture.root, &live).expect_err("live authority");
    assert_eq!(
        fault.code,
        SucceedingSopFixtureRollbackFaultCode::InvalidCommission
    );
    assert!(!fault.physical_contact);

    let mut evidence = fixture.rollback_commission();
    evidence
        .evidence_refs
        .insert(evidence.recovery_owner_ref.clone());
    evidence.commission_digest = empty_digest();
    evidence.commission_digest =
        succeeding_sop_fixture_rollback_commission_digest(&evidence).unwrap();
    let fault = execute_succeeding_sop_fixture_rollback(&fixture.root, &evidence)
        .expect_err("evidence laundering");
    assert_eq!(
        fault.code,
        SucceedingSopFixtureRollbackFaultCode::InvalidIdentity
    );
    assert!(!fault.physical_contact);

    let mut upstream = fixture.rollback_commission();
    upstream.persistence_receipt.provider_contacted = true;
    upstream.persistence_receipt.receipt_digest = empty_digest();
    upstream.persistence_receipt.receipt_digest =
        succeeding_sop_fixture_persistence_receipt_digest(&upstream.persistence_receipt).unwrap();
    upstream.commission_digest = empty_digest();
    upstream.commission_digest =
        succeeding_sop_fixture_rollback_commission_digest(&upstream).unwrap();
    let fault = execute_succeeding_sop_fixture_rollback(&fixture.root, &upstream)
        .expect_err("upstream laundering");
    assert_eq!(
        fault.code,
        SucceedingSopFixtureRollbackFaultCode::InvalidUpstream
    );
    assert!(!fault.physical_contact);

    let mut digest = fixture.rollback_commission();
    digest.commission_digest.value = "f".repeat(64);
    let fault = execute_succeeding_sop_fixture_rollback(&fixture.root, &digest)
        .expect_err("digest laundering");
    assert_eq!(
        fault.code,
        SucceedingSopFixtureRollbackFaultCode::InvalidDigest
    );
    assert!(!fault.physical_contact);
}

#[test]
fn git_root_and_predecessor_link_substitution_refuse() {
    let git = Fixture::new();
    fs::create_dir(git.root.join(".git")).unwrap();
    let fault = execute_succeeding_sop_fixture_rollback(&git.root, &git.rollback_commission())
        .expect_err("Git root");
    assert_eq!(
        fault.code,
        SucceedingSopFixtureRollbackFaultCode::InvalidRoot
    );
    assert!(fault.physical_contact);

    let link = Fixture::new();
    let predecessor = link.predecessor_path();
    let alternate = link.root.join("alternate-predecessor.sop");
    fs::write(&alternate, PREDECESSOR_SOURCE).unwrap();
    fs::remove_file(&predecessor).unwrap();
    #[cfg(unix)]
    let linked = std::os::unix::fs::symlink(&alternate, &predecessor);
    #[cfg(windows)]
    let linked = std::os::windows::fs::symlink_file(&alternate, &predecessor);
    if linked.is_err() {
        fs::write(&predecessor, PREDECESSOR_SOURCE).unwrap();
        return;
    }
    let fault = execute_succeeding_sop_fixture_rollback(&link.root, &link.rollback_commission())
        .expect_err("predecessor link");
    assert_eq!(
        fault.code,
        SucceedingSopFixtureRollbackFaultCode::LinkOrReparse
    );
    assert!(!fault.replacement_performed);
}

#[test]
fn commission_forms_refuse_unknown_fields_and_oversize() {
    let fixture = Fixture::new();
    let commission = fixture.rollback_commission();
    let form = to_succeeding_sop_fixture_rollback_commission_machine_form(&commission).unwrap();
    assert_eq!(
        commission,
        from_succeeding_sop_fixture_rollback_commission_machine_form(&form).unwrap()
    );
    let mut unknown: Value = serde_json::from_str(&form).unwrap();
    unknown["observed_boot_truth"] = Value::Bool(true);
    assert_eq!(
        from_succeeding_sop_fixture_rollback_commission_machine_form(
            &serde_json::to_string(&unknown).unwrap()
        )
        .expect_err("unknown field")
        .code,
        SucceedingSopFixtureRollbackFaultCode::InvalidMachineForm
    );
    let oversized = "x".repeat(SUCCEEDING_SOP_FIXTURE_ROLLBACK_MAX_MACHINE_FORM_BYTES + 1);
    assert_eq!(
        from_succeeding_sop_fixture_rollback_commission_machine_form(&oversized)
            .expect_err("oversize")
            .code,
        SucceedingSopFixtureRollbackFaultCode::InvalidBound
    );
}

#[test]
fn production_surface_has_no_ambient_live_or_cleanup_capability() {
    let module = include_str!("../src/succeeding_sop_fixture_rollback.rs");
    assert!(
        module
            .contains("candidate_metadata.len() != transaction.source_reacquisition.source_bytes")
    );
    assert!(
        module.contains(
            "candidate_bytes.len() as u64 != transaction.source_reacquisition.source_bytes"
        )
    );
    assert!(module.contains("receipt.current_failed_record.current.current_source_path"));
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
        "boot_sop",
    ] {
        assert!(
            !module.contains(forbidden),
            "forbidden surface: {forbidden}"
        );
    }
}
