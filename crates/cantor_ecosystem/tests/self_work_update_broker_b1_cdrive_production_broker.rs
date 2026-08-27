use std::{env, fs, path::PathBuf};

use cantor_core::{ContentDigest, sha256_bytes};
use cantor_ecosystem::{
    B1_CDRIVE_PRODUCTION_BROKER_CANONICAL_UUID,
    B1_CDRIVE_PRODUCTION_BROKER_EVIDENCE_MANIFEST_PROFILE,
    B1_CDRIVE_PRODUCTION_BROKER_FIXTURE_INPUT_PROFILE,
    B1_CDRIVE_PRODUCTION_BROKER_FORMATION_BOOKEND, B1_CDRIVE_PRODUCTION_BROKER_FORMATION_COMMIT,
    B1_CDRIVE_PRODUCTION_BROKER_IMPLEMENTATION_REQUEST_PROFILE,
    B1_CDRIVE_PRODUCTION_BROKER_SIGNATURE_UUID, B1_CDRIVE_PRODUCTION_BROKER_SOURCE_SNAPSHOT_UUID,
    B1_CDRIVE_PRODUCTION_COMMISSION_PROFILE, B1_CDRIVE_PRODUCTION_OPERATOR_AUTHORIZATION_PROFILE,
    B1_CDRIVE_PRODUCTION_PREPARED_RECEIPT_PROFILE, B1CDrivePreflightProducerChildKind,
    B1CDriveProductionBrokerAuthorityRecord, B1CDriveProductionBrokerChildAccount,
    B1CDriveProductionBrokerEffectAccount, B1CDriveProductionBrokerEvidenceArtifact,
    B1CDriveProductionBrokerEvidenceManifest, B1CDriveProductionBrokerFiveAuthorityJoin,
    B1CDriveProductionBrokerFixtureFaultPoint, B1CDriveProductionBrokerFixtureInput,
    B1CDriveProductionBrokerImplementationRequest, B1CDriveProductionBrokerLedgerFixture,
    B1CDriveProductionBrokerLedgerState, B1CDriveProductionBrokerMutableObservation,
    B1CDriveProductionBrokerPreparedReceipt, B1CDriveProductionBrokerState,
    B1CDriveProductionBrokerTranscriptAccount, B1CDriveProductionBrokerTransition,
    B1CDriveProductionCommission, B1CDriveProductionOperatorAuthorization,
    b1_cdrive_production_broker_authority_join_digest,
    b1_cdrive_production_broker_authority_record_digest,
    b1_cdrive_production_broker_evidence_manifest_digest,
    b1_cdrive_production_broker_fixture_input_digest,
    b1_cdrive_production_broker_implementation_request_digest,
    b1_cdrive_production_commission_digest, b1_cdrive_production_ledger_fixture_digest,
    b1_cdrive_production_observation_digest, b1_cdrive_production_observed_state_digest,
    b1_cdrive_production_operator_authorization_digest,
    b1_cdrive_production_prepared_receipt_digest,
    compile_b1_cdrive_production_broker_implementation_receipt,
    from_b1_cdrive_preflight_producer_plan_machine_form,
    from_b1_cdrive_preflight_producer_plan_request_machine_form,
    from_b1_cdrive_production_broker_fixture_input_machine_form,
    from_b1_cdrive_production_broker_fixture_outcome_machine_form,
    from_b1_cdrive_production_broker_implementation_request_machine_form,
    required_b1_cdrive_production_broker_authority_classes,
    run_b1_cdrive_production_broker_fixture,
    to_b1_cdrive_production_broker_evidence_manifest_machine_form,
    to_b1_cdrive_production_broker_evidence_verification_machine_form,
    to_b1_cdrive_production_broker_fixture_input_machine_form,
    to_b1_cdrive_production_broker_fixture_outcome_machine_form,
    to_b1_cdrive_production_broker_implementation_receipt_machine_form,
    to_b1_cdrive_production_broker_implementation_request_machine_form,
    validate_b1_cdrive_production_broker_fixture_authority_join,
    validate_b1_cdrive_production_broker_fixture_outcome,
    validate_b1_cdrive_production_broker_live_authority_join,
    validate_b1_cdrive_production_broker_transition_trace,
    validate_b1_cdrive_production_child_accounts, validate_b1_cdrive_production_transcript_account,
    verify_b1_cdrive_production_broker_activation_lock,
    verify_b1_cdrive_production_broker_evidence_directory,
};
use serde_json::json;

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: "0".repeat(64),
    }
}

fn evidence_file(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../experiments/self_work_update_broker_b1_cdrive_permission_profile_preflight_p1_revision_0_2/producer_plan_provider_free_evidence")
        .join(name);
    fs::read_to_string(path)
        .expect("published producer evidence")
        .trim_end_matches(['\r', '\n'])
        .to_owned()
}

fn implementation_request() -> B1CDriveProductionBrokerImplementationRequest {
    let mut request = B1CDriveProductionBrokerImplementationRequest {
        profile: B1_CDRIVE_PRODUCTION_BROKER_IMPLEMENTATION_REQUEST_PROFILE.to_owned(),
        source_snapshot_uuid: B1_CDRIVE_PRODUCTION_BROKER_SOURCE_SNAPSHOT_UUID.to_owned(),
        canonical_uuid: B1_CDRIVE_PRODUCTION_BROKER_CANONICAL_UUID.to_owned(),
        signature_uuid: B1_CDRIVE_PRODUCTION_BROKER_SIGNATURE_UUID.to_owned(),
        formation_commit: B1_CDRIVE_PRODUCTION_BROKER_FORMATION_COMMIT.to_owned(),
        formation_bookend: B1_CDRIVE_PRODUCTION_BROKER_FORMATION_BOOKEND.to_owned(),
        producer_plan_request_machine_form: evidence_file("request.json"),
        producer_plan_machine_form: evidence_file("plan.json"),
        physical_activation_digest: None,
        request_sha256: empty_digest(),
    };
    request.request_sha256 = b1_cdrive_production_broker_implementation_request_digest(&request)
        .expect("request digest");
    request
}

fn fixture() -> B1CDriveProductionBrokerFixtureInput {
    let request = implementation_request();
    let producer_request = from_b1_cdrive_preflight_producer_plan_request_machine_form(
        &request.producer_plan_request_machine_form,
    )
    .expect("producer request");
    let plan = from_b1_cdrive_preflight_producer_plan_machine_form(
        &producer_request,
        &request.producer_plan_machine_form,
    )
    .expect("producer plan");
    let phase3a_sha256 = sha256_bytes(b"fixture-only fresh phase3a replay");

    let mut authorization = B1CDriveProductionOperatorAuthorization {
        profile: B1_CDRIVE_PRODUCTION_OPERATOR_AUTHORIZATION_PROFILE.to_owned(),
        issuer: r"THEBRAIN\enjer".to_owned(),
        subject: "cantor_b1_cdrive_production_broker_p0".to_owned(),
        role: "operator_authorizer".to_owned(),
        attempt_uuid: "00000000-0000-4000-8000-000000000001".to_owned(),
        conversation_uuid: "01a02268-2614-7d80-9737-ea77f4aeacb1".to_owned(),
        purpose: "provider-free production-broker orchestration fixture".to_owned(),
        plan_sha256: plan.plan_sha256.clone(),
        issued_at_unix_millis: 1,
        expires_at_unix_millis: 2,
        broker_authored: false,
        fixture_only: true,
        authorization_sha256: empty_digest(),
    };
    authorization.authorization_sha256 =
        b1_cdrive_production_operator_authorization_digest(&authorization)
            .expect("authorization digest");

    let mut prepared = B1CDriveProductionBrokerPreparedReceipt {
        profile: B1_CDRIVE_PRODUCTION_PREPARED_RECEIPT_PROFILE.to_owned(),
        scratch_root: r"C:\Project\CantorWorktrees\swa05_b1_cdrive_preflight_fixture".to_owned(),
        candidate_root: r"C:\Project\CantorWorktrees\swa05_b1_cdrive_preflight_fixture\candidate"
            .to_owned(),
        evidence_root: r"C:\Project\CantorWorktrees\swa05_b1_cdrive_preflight_fixture\evidence"
            .to_owned(),
        lease_path: r"C:\Project\CantorWorktrees\swa05_b1_cdrive_preflight_fixture\broker.lease"
            .to_owned(),
        ledger_path: r"C:\Project\CantorWorktrees\swa05_b1_cdrive_preflight_fixture\broker.ledger"
            .to_owned(),
        plan_sha256: plan.plan_sha256.clone(),
        phase3a_sha256: phase3a_sha256.clone(),
        unclaimed_ledger_sha256: sha256_bytes(b"fixed Unclaimed fixture bytes"),
        fixed_ledger_bytes: 256,
        lease_preexisting_regular_nonlink: true,
        ledger_preexisting_regular_nonlink: true,
        evidence_preexisting_directory_nonlink: true,
        fixture_only: true,
        prepared_receipt_sha256: empty_digest(),
    };
    prepared.prepared_receipt_sha256 =
        b1_cdrive_production_prepared_receipt_digest(&prepared).expect("prepared digest");

    let mut commission = B1CDriveProductionCommission {
        profile: B1_CDRIVE_PRODUCTION_COMMISSION_PROFILE.to_owned(),
        issuer: r"THEBRAIN\enjer".to_owned(),
        subject: "cantor_b1_cdrive_production_broker_p0".to_owned(),
        recovery_owner: r"THEBRAIN\enjer".to_owned(),
        attempt_uuid: authorization.attempt_uuid.clone(),
        conversation_uuid: authorization.conversation_uuid.clone(),
        purpose: authorization.purpose.clone(),
        implementation_commit: B1_CDRIVE_PRODUCTION_BROKER_FORMATION_COMMIT.to_owned(),
        implementation_bookend: B1_CDRIVE_PRODUCTION_BROKER_FORMATION_BOOKEND.to_owned(),
        expected_current_commit: B1_CDRIVE_PRODUCTION_BROKER_FORMATION_BOOKEND.to_owned(),
        plan_sha256: plan.plan_sha256.clone(),
        prepared_receipt_sha256: prepared.prepared_receipt_sha256.clone(),
        phase3a_sha256: phase3a_sha256.clone(),
        operator_authorization_sha256: authorization.authorization_sha256.clone(),
        issued_at_unix_millis: 1,
        expires_at_unix_millis: 2,
        maximum_attempts: 1,
        retry_count: 0,
        broker_authored: false,
        fixture_only: true,
        commission_sha256: empty_digest(),
    };
    commission.commission_sha256 =
        b1_cdrive_production_commission_digest(&commission).expect("commission digest");

    let artifact_digests = [
        commission.commission_sha256.clone(),
        sha256_bytes(b"fixture-only continuously held lease"),
        sha256_bytes(b"fixture-only durable claim"),
        prepared.prepared_receipt_sha256.clone(),
        phase3a_sha256.clone(),
    ];
    let mut records = Vec::new();
    for (class, artifact_sha256) in required_b1_cdrive_production_broker_authority_classes()
        .into_iter()
        .zip(artifact_digests)
    {
        let mut record = B1CDriveProductionBrokerAuthorityRecord {
            class,
            artifact_profile: format!("fixture/{}", class.as_str()),
            artifact_sha256,
            externally_authenticated: false,
            fixture_only: true,
            record_sha256: empty_digest(),
        };
        record.record_sha256 =
            b1_cdrive_production_broker_authority_record_digest(&record).expect("authority digest");
        records.push(record);
    }
    let mut authorities = B1CDriveProductionBrokerFiveAuthorityJoin {
        records,
        join_sha256: empty_digest(),
    };
    authorities.join_sha256 =
        b1_cdrive_production_broker_authority_join_digest(&authorities).expect("join digest");

    let mut first = B1CDriveProductionBrokerMutableObservation {
        sequence: 1,
        expected_current_commit: commission.expected_current_commit.clone(),
        free_bytes: 16_000_000_000,
        minimum_free_bytes: 15_032_385_536,
        reserved_root_present: true,
        reserved_ref_present: true,
        candidate_clean: true,
        sentinels_exact: true,
        write_canary_absent: true,
        executable_exact: true,
        prepared_receipt_sha256: prepared.prepared_receipt_sha256.clone(),
        phase3a_sha256: phase3a_sha256.clone(),
        plan_sha256: plan.plan_sha256.clone(),
        broker_process_count: 0,
        observed_state_sha256: empty_digest(),
        observation_sha256: empty_digest(),
    };
    first.observed_state_sha256 =
        b1_cdrive_production_observed_state_digest(&first).expect("first state digest");
    first.observation_sha256 =
        b1_cdrive_production_observation_digest(&first).expect("first observation digest");
    let mut second = first.clone();
    second.sequence = 2;
    second.observation_sha256 =
        b1_cdrive_production_observation_digest(&second).expect("second observation digest");

    let mut ledger = B1CDriveProductionBrokerLedgerFixture {
        prior_state: B1CDriveProductionBrokerLedgerState::Unclaimed,
        fixed_ledger_bytes: prepared.fixed_ledger_bytes,
        prior_bytes_sha256: prepared.unclaimed_ledger_sha256.clone(),
        claimed_bytes_sha256: sha256_bytes(b"fixed Claimed fixture bytes"),
        flush_succeeded: true,
        close_reopen_succeeded: true,
        byte_verification_succeeded: true,
        fixture_only: true,
        ledger_sha256: empty_digest(),
    };
    ledger.ledger_sha256 =
        b1_cdrive_production_ledger_fixture_digest(&ledger).expect("ledger digest");

    let mut input = B1CDriveProductionBrokerFixtureInput {
        profile: B1_CDRIVE_PRODUCTION_BROKER_FIXTURE_INPUT_PROFILE.to_owned(),
        implementation_request_machine_form:
            to_b1_cdrive_production_broker_implementation_request_machine_form(&request)
                .expect("request form"),
        authorities,
        commission,
        operator_authorization: authorization,
        prepared_receipt: prepared,
        first_observation: first,
        second_observation: second,
        ledger,
        fault_point: None,
        input_sha256: empty_digest(),
    };
    input.input_sha256 =
        b1_cdrive_production_broker_fixture_input_digest(&input).expect("input digest");
    input
}

fn producer_plan() -> cantor_ecosystem::B1CDrivePreflightProducerPlan {
    let request = implementation_request();
    let producer_request = from_b1_cdrive_preflight_producer_plan_request_machine_form(
        &request.producer_plan_request_machine_form,
    )
    .expect("producer request");
    from_b1_cdrive_preflight_producer_plan_machine_form(
        &producer_request,
        &request.producer_plan_machine_form,
    )
    .expect("producer plan")
}

fn reseal_input(input: &mut B1CDriveProductionBrokerFixtureInput) {
    input.input_sha256 = empty_digest();
    input.input_sha256 =
        b1_cdrive_production_broker_fixture_input_digest(input).expect("input digest");
}

#[test]
fn implementation_receipt_is_deterministic_and_records_no_runtime_authority() {
    let request = implementation_request();
    let left =
        compile_b1_cdrive_production_broker_implementation_receipt(&request).expect("left receipt");
    let right = compile_b1_cdrive_production_broker_implementation_receipt(&request)
        .expect("right receipt");
    assert_eq!(left, right);
    assert_eq!(left.required_authorities.len(), 5);
    assert!(!left.physical_activation_digest_configured);
    assert!(!left.private_execution_permit_constructed);
    assert!(!left.windows_backend_invoked);
    assert!(!left.physical_contact);
    assert_eq!(left.child_process_count, 0);
}

#[test]
fn fake_backend_proves_exact_order_single_consumption_and_zero_effects() {
    let input = fixture();
    let outcome = run_b1_cdrive_production_broker_fixture(&input).expect("fixture outcome");
    assert_eq!(
        outcome.terminal_state,
        B1CDriveProductionBrokerState::Complete
    );
    assert_eq!(outcome.transitions.len(), 9);
    assert_eq!(
        outcome.call_ledger,
        [
            "validate_inputs",
            "acquire_exclusive_lease",
            "reobserve_mutable_state",
            "claim_flush_reopen_verify_ledger",
            "issue_fake_execution_capability",
            "begin_fake_child_sequence",
            "execute_fake_child:version",
            "execute_fake_child:standard_schema",
            "execute_fake_child:experimental_schema",
            "execute_fake_child:app_server",
            "retain_append_only_evidence",
            "mark_commission_consumed",
            "release_exclusive_lease",
            "complete",
        ]
    );
    assert!(outcome.fake_execution_capability_consumed);
    assert!(!outcome.private_execution_permit_constructed);
    assert!(!outcome.windows_backend_invoked);
    assert!(!outcome.lease_held_at_terminal);
    assert_eq!(outcome.effect_account, zero_effect_account());
    validate_b1_cdrive_production_broker_fixture_outcome(&input, &outcome)
        .expect("deterministic replay");
}

#[test]
fn fixture_authorities_cannot_launder_live_authority_or_reorder_the_join() {
    let input = fixture();
    validate_b1_cdrive_production_broker_fixture_authority_join(&input.authorities)
        .expect("fixture join");
    assert!(validate_b1_cdrive_production_broker_live_authority_join(&input.authorities).is_err());

    let mut live = input.authorities.clone();
    for record in &mut live.records {
        record.fixture_only = false;
        record.externally_authenticated = true;
        record.record_sha256 =
            b1_cdrive_production_broker_authority_record_digest(record).expect("record digest");
    }
    live.join_sha256 =
        b1_cdrive_production_broker_authority_join_digest(&live).expect("join digest");
    validate_b1_cdrive_production_broker_live_authority_join(&live).expect("live shape");
    assert!(validate_b1_cdrive_production_broker_fixture_authority_join(&live).is_err());

    let mut reordered = input.authorities;
    reordered.records.swap(0, 1);
    reordered.join_sha256 =
        b1_cdrive_production_broker_authority_join_digest(&reordered).expect("join digest");
    assert!(validate_b1_cdrive_production_broker_fixture_authority_join(&reordered).is_err());
}

#[test]
fn commission_self_authorization_reobserve_drift_and_ledger_replay_refuse() {
    let mut self_authored = fixture();
    self_authored.operator_authorization.broker_authored = true;
    self_authored.operator_authorization.authorization_sha256 =
        b1_cdrive_production_operator_authorization_digest(&self_authored.operator_authorization)
            .expect("authorization digest");
    self_authored.commission.operator_authorization_sha256 = self_authored
        .operator_authorization
        .authorization_sha256
        .clone();
    self_authored.commission.commission_sha256 =
        b1_cdrive_production_commission_digest(&self_authored.commission)
            .expect("commission digest");
    reseal_input(&mut self_authored);
    assert!(run_b1_cdrive_production_broker_fixture(&self_authored).is_err());

    let mut drift = fixture();
    drift.second_observation.free_bytes -= 1;
    drift.second_observation.observed_state_sha256 =
        b1_cdrive_production_observed_state_digest(&drift.second_observation)
            .expect("state digest");
    drift.second_observation.observation_sha256 =
        b1_cdrive_production_observation_digest(&drift.second_observation)
            .expect("observation digest");
    reseal_input(&mut drift);
    assert!(run_b1_cdrive_production_broker_fixture(&drift).is_err());

    let mut replay = fixture();
    replay.ledger.prior_state = B1CDriveProductionBrokerLedgerState::Claimed;
    replay.ledger.ledger_sha256 =
        b1_cdrive_production_ledger_fixture_digest(&replay.ledger).expect("ledger digest");
    reseal_input(&mut replay);
    assert!(run_b1_cdrive_production_broker_fixture(&replay).is_err());
}

#[test]
fn every_fault_point_preserves_preclaim_not_run_or_postclaim_quarantine_truth() {
    use B1CDriveProductionBrokerFixtureFaultPoint as Point;
    for point in [
        Point::BeforeLease,
        Point::AfterLease,
        Point::AfterReobserve,
        Point::AfterClaim,
        Point::AfterTestCapability,
        Point::DuringChildren,
        Point::AfterEvidenceRetention,
        Point::AfterCommissionConsumption,
        Point::AfterLeaseRelease,
    ] {
        let mut input = fixture();
        input.fault_point = Some(point);
        reseal_input(&mut input);
        let outcome = run_b1_cdrive_production_broker_fixture(&input).expect("fault outcome");
        let expected = match point {
            Point::BeforeLease | Point::AfterLease | Point::AfterReobserve => {
                B1CDriveProductionBrokerState::NotRun
            }
            _ => B1CDriveProductionBrokerState::Quarantined,
        };
        assert_eq!(outcome.terminal_state, expected, "{point:?}");
        assert_eq!(
            outcome.may_have_mutated,
            expected == B1CDriveProductionBrokerState::Quarantined
        );
        assert_eq!(
            outcome.ledger_claimed,
            expected == B1CDriveProductionBrokerState::Quarantined
        );
        assert_eq!(outcome.retry_count, 0);
        assert_eq!(outcome.cleanup_count, 0);
        assert_eq!(outcome.effect_account, zero_effect_account());
    }
    let impossible_skip_to_claim = [
        B1CDriveProductionBrokerTransition {
            sequence: 1,
            from: B1CDriveProductionBrokerState::InputsValidated,
            to: B1CDriveProductionBrokerState::ConsumptionClaimed,
            consumption_claimed_after: true,
            process_creation_allowed_after: false,
        },
        B1CDriveProductionBrokerTransition {
            sequence: 2,
            from: B1CDriveProductionBrokerState::ConsumptionClaimed,
            to: B1CDriveProductionBrokerState::Quarantined,
            consumption_claimed_after: true,
            process_creation_allowed_after: false,
        },
    ];
    assert!(
        validate_b1_cdrive_production_broker_transition_trace(&impossible_skip_to_claim).is_err()
    );
}

#[test]
fn machine_forms_are_canonical_duplicate_free_unknown_field_free_and_bounded() {
    let input = fixture();
    let input_form =
        to_b1_cdrive_production_broker_fixture_input_machine_form(&input).expect("input form");
    assert_eq!(
        from_b1_cdrive_production_broker_fixture_input_machine_form(&input_form)
            .expect("input roundtrip"),
        input
    );
    let duplicate = format!("{{\"profile\":\"duplicate\",{}", &input_form[1..]);
    assert!(from_b1_cdrive_production_broker_fixture_input_machine_form(&duplicate).is_err());
    let unknown = input_form.replacen("{", "{\"unknown_production_broker_field\":true,", 1);
    assert!(from_b1_cdrive_production_broker_fixture_input_machine_form(&unknown).is_err());

    let outcome = run_b1_cdrive_production_broker_fixture(&input).expect("outcome");
    let outcome_form =
        to_b1_cdrive_production_broker_fixture_outcome_machine_form(&input, &outcome)
            .expect("outcome form");
    assert_eq!(
        from_b1_cdrive_production_broker_fixture_outcome_machine_form(&input, &outcome_form)
            .expect("outcome roundtrip"),
        outcome
    );

    let request_form = to_b1_cdrive_production_broker_implementation_request_machine_form(
        &implementation_request(),
    )
    .expect("request form");
    assert_eq!(
        from_b1_cdrive_production_broker_implementation_request_machine_form(&request_form)
            .expect("request roundtrip"),
        implementation_request()
    );
    let oversized = "x".repeat(2 * 1024 * 1024 + 1);
    assert!(from_b1_cdrive_production_broker_fixture_input_machine_form(&oversized).is_err());
}

#[test]
fn physical_activation_and_unsafe_surface_remain_statically_locked() {
    assert!(verify_b1_cdrive_production_broker_activation_lock().is_err());
    let source = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src/self_work_update_broker_b1_cdrive_production_broker.rs"),
    )
    .expect("broker source");
    let windows = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src/self_work_update_broker_b1_cdrive_windows_containment.rs"),
    )
    .expect("containment source");
    let verifier = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src/self_work_update_broker_b1_cdrive_production_broker_evidence.rs"),
    )
    .expect("verifier source");
    assert!(source.contains("const PHYSICAL_ACTIVATION_DIGEST: Option<&str> = None;"));
    assert!(source.contains("pub(crate) struct B1CDrivePhysicalExecutionPermit"));
    assert!(
        !source.contains(
            "Serialize, Deserialize)]\npub(crate) struct B1CDrivePhysicalExecutionPermit"
        )
    );
    assert_eq!(windows.matches("#![allow(unsafe_code)]").count(), 1);
    assert!(!source.contains("unsafe {"));
    let job_create = windows.find("let job = create_job").expect("job creation");
    let handle_list = windows
        .find("ProcThreadAttributeList::new(&child_handles)")
        .expect("exact handle list");
    let process_create = windows
        .find("let created = unsafe")
        .expect("suspended process creation");
    let job_assign = windows
        .find("AssignProcessToJobObject(job.raw(), process.raw())")
        .expect("job assignment");
    let resume = windows
        .find("ResumeThread(thread_handle.raw())")
        .expect("primary-thread resume");
    assert!(job_create < handle_list);
    assert!(handle_list < process_create);
    assert!(process_create < job_assign);
    assert!(job_assign < resume);
    assert!(windows.contains("CREATE_SUSPENDED"));
    assert!(windows.contains("PROC_THREAD_ATTRIBUTE_HANDLE_LIST"));
    assert!(windows.contains("JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE"));
    assert!(windows.contains("impl Drop for OwnedHandle"));
    assert!(!windows.contains("BREAKAWAY"));
    for forbidden in [
        "fs::write",
        "OpenOptions",
        "create_dir",
        "remove_file",
        "remove_dir",
        "std::process",
        "Command::",
        "std::env",
        "SystemTime",
        "TcpStream",
    ] {
        assert!(
            !verifier.contains(forbidden),
            "verifier effect surface: {forbidden}"
        );
    }
}

#[test]
fn retained_provider_free_evidence_double_replays_without_runtime_effects() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "../../experiments/self_work_update_broker_b1_cdrive_production_broker_p0/implementation_provider_free_evidence",
    );
    let left = verify_b1_cdrive_production_broker_evidence_directory(&root)
        .expect("left independent replay");
    let right = verify_b1_cdrive_production_broker_evidence_directory(&root)
        .expect("right independent replay");
    assert_eq!(left, right);
    assert_eq!(left.independent_replay_count, 2);
    assert!(left.byte_identical_replays);
    assert!(!left.physical_execution_authorized);
    assert!(!left.private_execution_permit_constructed);
    assert!(!left.windows_backend_invoked);
    assert_eq!(left.effect_account, zero_effect_account());
    assert_eq!(
        to_b1_cdrive_production_broker_evidence_verification_machine_form(&left)
            .expect("verification form"),
        fs::read_to_string(root.join("verification.json")).expect("retained verification")
    );
}

#[test]
fn child_and_transcript_accounts_enforce_containment_counts_and_closed_methods() {
    use B1CDrivePreflightProducerChildKind as Kind;
    let mut children: Vec<_> = [
        (Kind::Version, 1, 1),
        (Kind::StandardSchema, 1, 1),
        (Kind::ExperimentalSchema, 1, 1),
        (Kind::AppServer, 2, 4),
    ]
    .into_iter()
    .enumerate()
    .map(
        |(index, (kind, maximum_active_processes, total_processes))| {
            B1CDriveProductionBrokerChildAccount {
                sequence: (index + 1) as u8,
                kind,
                job_created_before_process: true,
                kill_on_close: true,
                breakaway_enabled: false,
                inherited_handle_count: 3,
                process_created_suspended: true,
                assigned_before_resume: true,
                resume_previous_count: 1,
                maximum_active_processes,
                total_processes,
                active_processes_at_terminal: 0,
                late_output: false,
                stdout_over_bound: false,
                stderr_over_bound: false,
                timed_out: false,
                forced_termination: false,
                exit_code: 0,
            }
        },
    )
    .collect();
    validate_b1_cdrive_production_child_accounts(&children).expect("child accounts");
    children[0].resume_previous_count = 0;
    assert!(validate_b1_cdrive_production_child_accounts(&children).is_err());
    children[0].resume_previous_count = 1;
    children[3].total_processes = 5;
    assert!(validate_b1_cdrive_production_child_accounts(&children).is_err());

    let plan = producer_plan();
    let response = |id| json!({"id": id, "result": {}});
    let frames = vec![
        plan.outbound_frames[0].clone(),
        response(0),
        plan.outbound_frames[1].clone(),
        json!({"method":"remoteControl/status/changed","params":{}}),
        plan.outbound_frames[2].clone(),
        response(1),
        plan.outbound_frames[3].clone(),
        response(2),
        plan.outbound_frames[4].clone(),
        response(3),
        plan.outbound_frames[5].clone(),
        response(4),
    ];
    let mut transcript = B1CDriveProductionBrokerTranscriptAccount {
        frames,
        allowed_read_exit_code: 0,
        allowed_read_stdout: "SWA05_B1_ALLOWED_READ_SENTINEL\n".to_owned(),
        allowed_read_stderr: String::new(),
        denied_read_exit_code: 1,
        denied_read_stdout: String::new(),
        denied_read_stderr: "Access is denied.\r\n".to_owned(),
        denied_write_exit_code: 1,
        denied_write_stdout: String::new(),
        denied_write_stderr: "Access is denied.\r\n".to_owned(),
        denied_sentinel_disclosed: false,
        write_sentinel_disclosed: false,
        write_canary_present: false,
    };
    validate_b1_cdrive_production_transcript_account(&plan, &transcript)
        .expect("closed transcript");
    transcript.frames.swap(1, 5);
    assert!(validate_b1_cdrive_production_transcript_account(&plan, &transcript).is_err());
    transcript.frames.swap(1, 5);
    transcript.frames[3] = json!({"method":"thread/start","params":{}});
    assert!(validate_b1_cdrive_production_transcript_account(&plan, &transcript).is_err());
    transcript.frames[3] = json!({"method":"remoteControl/status/changed","params":{}});
    transcript.write_canary_present = true;
    assert!(validate_b1_cdrive_production_transcript_account(&plan, &transcript).is_err());
}

#[test]
#[ignore = "writes only the explicitly supplied owned evidence root"]
fn write_owned_provider_free_production_broker_evidence() {
    let root = env::var("CANTOR_B1_PRODUCTION_BROKER_EVIDENCE_ROOT")
        .expect("explicit evidence root is required");
    let root = PathBuf::from(root);
    if root.exists() {
        assert!(root.is_dir());
        assert_eq!(fs::read_dir(&root).expect("evidence entries").count(), 0);
    } else {
        fs::create_dir_all(&root).expect("create evidence root");
    }

    let request = implementation_request();
    let request_bytes =
        to_b1_cdrive_production_broker_implementation_request_machine_form(&request)
            .expect("request form")
            .into_bytes();
    let receipt = compile_b1_cdrive_production_broker_implementation_receipt(&request)
        .expect("implementation receipt");
    let receipt_bytes =
        to_b1_cdrive_production_broker_implementation_receipt_machine_form(&request, &receipt)
            .expect("receipt form")
            .into_bytes();
    let input = fixture();
    assert_eq!(
        input.implementation_request_machine_form.as_bytes(),
        request_bytes
    );
    let input_bytes = to_b1_cdrive_production_broker_fixture_input_machine_form(&input)
        .expect("fixture input form")
        .into_bytes();
    let outcome = run_b1_cdrive_production_broker_fixture(&input).expect("fixture outcome");
    let outcome_bytes =
        to_b1_cdrive_production_broker_fixture_outcome_machine_form(&input, &outcome)
            .expect("fixture outcome form")
            .into_bytes();
    let artifacts = [
        ("fixture_input.json", input_bytes),
        ("fixture_outcome.json", outcome_bytes),
        ("implementation_receipt.json", receipt_bytes),
        ("implementation_request.json", request_bytes),
    ];
    for (name, bytes) in &artifacts {
        fs::write(root.join(name), bytes).expect("write evidence artifact");
    }
    let mut manifest = B1CDriveProductionBrokerEvidenceManifest {
        profile: B1_CDRIVE_PRODUCTION_BROKER_EVIDENCE_MANIFEST_PROFILE.to_owned(),
        source_snapshot_uuid: B1_CDRIVE_PRODUCTION_BROKER_SOURCE_SNAPSHOT_UUID.to_owned(),
        canonical_uuid: B1_CDRIVE_PRODUCTION_BROKER_CANONICAL_UUID.to_owned(),
        signature_uuid: B1_CDRIVE_PRODUCTION_BROKER_SIGNATURE_UUID.to_owned(),
        formation_commit: B1_CDRIVE_PRODUCTION_BROKER_FORMATION_COMMIT.to_owned(),
        formation_bookend: B1_CDRIVE_PRODUCTION_BROKER_FORMATION_BOOKEND.to_owned(),
        artifacts: artifacts
            .iter()
            .map(|(name, bytes)| B1CDriveProductionBrokerEvidenceArtifact {
                path: (*name).to_owned(),
                bytes: bytes.len() as u64,
                sha256: sha256_bytes(bytes),
            })
            .collect(),
        fixture_only: true,
        physical_execution_authorized: false,
        non_authority_statement: "Synthetic provider-free production-broker evidence only; no authentic commission, lease, ledger, child process, App Server, provider, model, MCP, network, writer, Git mutation, publication, persistence, activation, D-drive, remote, FPGA, Minecraft, WSL compile, cleanup, or physical authority."
            .to_owned(),
        manifest_sha256: empty_digest(),
    };
    manifest.manifest_sha256 =
        b1_cdrive_production_broker_evidence_manifest_digest(&manifest).expect("manifest digest");
    fs::write(
        root.join("evidence_manifest.json"),
        to_b1_cdrive_production_broker_evidence_manifest_machine_form(&manifest)
            .expect("manifest form"),
    )
    .expect("write evidence manifest");

    let verification = verify_b1_cdrive_production_broker_evidence_directory(&root)
        .expect("independent verification");
    let verification_form =
        to_b1_cdrive_production_broker_evidence_verification_machine_form(&verification)
            .expect("verification form");
    fs::write(root.join("verification.json"), verification_form)
        .expect("write verification receipt");
    assert_eq!(
        verify_b1_cdrive_production_broker_evidence_directory(&root)
            .expect("retained independent verification"),
        verification
    );
}

fn zero_effect_account() -> B1CDriveProductionBrokerEffectAccount {
    B1CDriveProductionBrokerEffectAccount {
        physical_contact: false,
        process_creation_count: 0,
        provider_trial_count: 0,
        model_turn_count: 0,
        mcp_call_count: 0,
        network_contact_count: 0,
        writer_run_count: 0,
        git_mutation_count: 0,
        publication_count: 0,
        persistence_count: 0,
        activation_count: 0,
        d_drive_contact_count: 0,
        remote_contact_count: 0,
        fpga_contact_count: 0,
        minecraft_contact_count: 0,
        wsl_compile_count: 0,
        cleanup_count: 0,
        foreign_effect_count: 0,
    }
}
