use cantor_core::*;
use sha2::{Digest, Sha256};
use std::fs;
use std::process::Command;

const RUN_UUID: &str = "61927fc8-5c08-4a78-9993-df1dc975db56";
const IMPLEMENTATION: &str = "1111111111111111111111111111111111111111";
const BOOKEND: &str = "2222222222222222222222222222222222222222";

struct Fixture {
    request: Evox2ScratchBuildControllerRequest,
    plan: Evox2ScratchBuildControllerPlan,
    program: Evox2ScratchBuildEffectProgram,
}

fn fixture() -> Fixture {
    let request =
        fixed_evox2_scratch_build_controller_request(RUN_UUID, IMPLEMENTATION, BOOKEND).unwrap();
    let plan = compile_evox2_scratch_build_controller_plan(&request).unwrap();
    let program = compile_evox2_scratch_build_effect_program(&request, &plan).unwrap();
    Fixture {
        request,
        plan,
        program,
    }
}

fn refused_receipt(commission: &Evox2ScratchBuildCommission) -> Evox2ScratchBuildReceipt {
    seal_evox2_scratch_build_receipt(
        Evox2ScratchBuildReceipt {
            profile: EVOX2_SCRATCH_BUILD_RECEIPT_PROFILE.to_owned(),
            receipt_uuid: "5e1d8786-2e91-421a-966d-1e7c2de3652d".to_owned(),
            canonical_uuid: commission.canonical_uuid.clone(),
            commission_uuid: commission.commission_uuid.clone(),
            commission_sha256: commission.commission_sha256.clone(),
            source_archive_sha256: commission.source_archive_sha256.clone(),
            source_commit: commission.source_commit.clone(),
            target_host: commission.target_host.clone(),
            workspace_root: commission.workspace_root.clone(),
            target_root: commission.target_root.clone(),
            toolchain_observation: unobserved_evox2_scratch_build_toolchain(),
            operation_records: Vec::new(),
            protected_before: "a".repeat(64),
            protected_after: "a".repeat(64),
            provider_before: "b".repeat(64),
            provider_after: "b".repeat(64),
            persistent_executor_process_count: 0,
            physical_build_performed: false,
            disposition: "refused".to_owned(),
            receipt_sha256: String::new(),
        },
        commission,
    )
    .unwrap()
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn observation(
    program: &Evox2ScratchBuildEffectProgram,
    ordinal: u32,
    status: &str,
) -> Evox2ScratchBuildEffectObservation {
    seal_evox2_scratch_build_effect_observation(
        program,
        Evox2ScratchBuildEffectObservation {
            profile: EVOX2_SCRATCH_BUILD_EFFECT_OBSERVATION_PROFILE.to_owned(),
            program_sha256: program.program_sha256.clone(),
            ordinal,
            kind: program.stages[(ordinal - 1) as usize].kind.clone(),
            status: status.to_owned(),
            observation_source: "supplied_provider_free_fixture".to_owned(),
            effect_performed: false,
            remote_calls: 0,
            effects: 0,
            evidence_sha256: format!("{ordinal:064x}"),
            observation_sha256: String::new(),
        },
    )
    .unwrap()
}

fn retrieved_fixture(
    value: &Fixture,
) -> (
    Evox2ScratchBuildRemotePreflight,
    Evox2ScratchBuildRetrievalInventory,
    Vec<(String, Vec<u8>)>,
) {
    let preflight = fixed_evox2_scratch_build_preflight_fixture(
        &value.request,
        &value.plan,
        &value.program,
        true,
    )
    .unwrap();
    let commission = synthetic_evox2_scratch_build_commission();
    let receipt = refused_receipt(&commission);
    let receipt_verification =
        build_evox2_scratch_build_receipt_verification(&commission, &receipt).unwrap();
    let receipt_raw = to_evox2_scratch_build_receipt_machine_form(&commission, &receipt).unwrap();
    let remote_run = format!(
        "{{\"profile\":\"cantor-evox2-scratch-build-host-run/0.1\",\"status\":\"refused\",\"target_host\":\"EVO-X2\",\"operation_record_count\":0,\"physical_build_performed\":false,\"receipt\":{receipt_raw},\"total_duration_ms\":1,\"persistent_processes\":0}}"
    );
    let artifacts = vec![
        (
            "commission.json".to_owned(),
            to_evox2_scratch_build_commission_machine_form(&commission)
                .unwrap()
                .into_bytes(),
        ),
        (
            "controller_preflight.json".to_owned(),
            to_evox2_scratch_build_remote_preflight_machine_form(
                &value.request,
                &value.plan,
                &value.program,
                &preflight,
            )
            .unwrap()
            .into_bytes(),
        ),
        ("receipt.json".to_owned(), receipt_raw.into_bytes()),
        (
            "receipt_verification.json".to_owned(),
            to_evox2_scratch_build_receipt_verification_machine_form(&receipt_verification)
                .unwrap()
                .into_bytes(),
        ),
        ("remote_run.json".to_owned(), remote_run.into_bytes()),
    ];
    let identities = artifacts
        .iter()
        .map(
            |(relative_path, bytes)| Evox2ScratchBuildRetrievedArtifact {
                relative_path: relative_path.clone(),
                bytes: bytes.len() as u64,
                sha256: sha256(bytes),
            },
        )
        .collect();
    let inventory = seal_evox2_scratch_build_retrieval_inventory(
        &value.request,
        &value.plan,
        &value.program,
        &preflight,
        "refused",
        identities,
    )
    .unwrap();
    (preflight, inventory, artifacts)
}

#[test]
fn effect_program_is_exact_deterministic_and_nonauthorizing() {
    let value = fixture();
    assert_eq!(
        value.program,
        compile_evox2_scratch_build_effect_program(&value.request, &value.plan).unwrap()
    );
    assert_eq!(value.program.stage_count, 10);
    assert_eq!(value.program.stages.len(), 10);
    assert_eq!(
        value.program.stages[2].executor_role,
        "bounded_remote_preflight"
    );
    assert_eq!(
        value.program.stages[8].executor_role,
        "independent_live_evidence_verifier"
    );
    assert!(
        value
            .program
            .stages
            .iter()
            .all(|stage| stage.stop_on_failure)
    );
    assert!(!value.program.execution_authorized);
    assert!(!value.program.remote_contact_authorized);
    assert_eq!(value.program.provider_requests, 0);
    assert_eq!(value.program.remote_calls, 0);
    assert_eq!(value.program.effects, 0);
}

#[test]
fn effect_program_machine_form_refuses_raw_duplicate_unknown_and_promotion() {
    let value = fixture();
    let raw = to_evox2_scratch_build_effect_program_machine_form(
        &value.request,
        &value.plan,
        &value.program,
    )
    .unwrap();
    assert_eq!(
        from_evox2_scratch_build_effect_program_machine_form(&value.request, &value.plan, &raw)
            .unwrap(),
        value.program
    );
    assert!(
        from_evox2_scratch_build_effect_program_machine_form(
            &value.request,
            &value.plan,
            &format!("{raw}\n")
        )
        .is_err()
    );
    let duplicate = raw.replacen("\"profile\":", "\"profile\":\"duplicate\",\"profile\":", 1);
    assert!(
        from_evox2_scratch_build_effect_program_machine_form(
            &value.request,
            &value.plan,
            &duplicate
        )
        .is_err()
    );
    let unknown = raw.replacen('{', "{\"unknown\":false,", 1);
    assert!(
        from_evox2_scratch_build_effect_program_machine_form(&value.request, &value.plan, &unknown)
            .is_err()
    );
    let promoted = raw.replace(
        "\"execution_authorized\":false",
        "\"execution_authorized\":true",
    );
    assert!(
        from_evox2_scratch_build_effect_program_machine_form(
            &value.request,
            &value.plan,
            &promoted
        )
        .is_err()
    );
}

#[test]
fn preflight_fixture_keeps_admission_and_refusal_non_equivalent() {
    let value = fixture();
    let admitted = fixed_evox2_scratch_build_preflight_fixture(
        &value.request,
        &value.plan,
        &value.program,
        true,
    )
    .unwrap();
    assert_eq!(admitted.status, "admitted");
    assert!(admitted.commission_admitted);
    assert!(admitted.receipt_expected);
    assert_eq!(admitted.effects, 0);

    let refused = fixed_evox2_scratch_build_preflight_fixture(
        &value.request,
        &value.plan,
        &value.program,
        false,
    )
    .unwrap();
    assert_eq!(refused.status, "refused");
    assert!(!refused.commission_admitted);
    assert!(!refused.receipt_expected);
    assert_eq!(refused.reason, "provider_unavailable_before_commission");
    assert_ne!(refused.preflight_sha256, admitted.preflight_sha256);
}

#[test]
fn operational_refusal_verifies_without_commission_receipt_or_artifacts() {
    let value = fixture();
    let preflight = fixed_evox2_scratch_build_preflight_fixture(
        &value.request,
        &value.plan,
        &value.program,
        false,
    )
    .unwrap();
    let refusal = fixed_evox2_scratch_build_operational_refusal(
        &value.request,
        &value.plan,
        &value.program,
        &preflight,
    )
    .unwrap();
    let verified = verify_evox2_scratch_build_operational_refusal_evidence(
        &value.request,
        &value.plan,
        &value.program,
        &preflight,
        &refusal,
    )
    .unwrap();
    assert_eq!(
        verified.branch,
        "operational_refusal_before_commission_no_receipt"
    );
    assert!(verified.evidence_is_fixture);
    assert_eq!(verified.retrieved_artifact_count, 0);
    assert_eq!(verified.remote_calls, 0);
    assert_eq!(verified.effects, 0);
    to_evox2_scratch_build_live_evidence_verification_machine_form(&verified).unwrap();
}

#[test]
fn operational_refusal_refuses_receipt_promotion_and_counter_drift() {
    let value = fixture();
    let preflight = fixed_evox2_scratch_build_preflight_fixture(
        &value.request,
        &value.plan,
        &value.program,
        false,
    )
    .unwrap();
    let refusal = fixed_evox2_scratch_build_operational_refusal(
        &value.request,
        &value.plan,
        &value.program,
        &preflight,
    )
    .unwrap();
    let raw = to_evox2_scratch_build_operational_refusal_machine_form(
        &value.request,
        &value.plan,
        &value.program,
        &preflight,
        &refusal,
    )
    .unwrap();
    for changed in [
        raw.replace("\"receipt_present\":false", "\"receipt_present\":true"),
        raw.replace("\"remote_calls\":0", "\"remote_calls\":1"),
        format!("{raw}\n"),
    ] {
        assert!(
            from_evox2_scratch_build_operational_refusal_machine_form(
                &value.request,
                &value.plan,
                &value.program,
                &preflight,
                &changed
            )
            .is_err()
        );
    }
}

#[test]
fn retrieval_inventory_and_independent_receipt_replay_pass() {
    let value = fixture();
    let (preflight, inventory, artifacts) = retrieved_fixture(&value);
    let supplied = artifacts
        .iter()
        .map(|(path, bytes)| (path.as_str(), bytes.as_slice()))
        .collect::<Vec<_>>();
    let verified = verify_evox2_scratch_build_retrieved_receipt_evidence(
        &value.request,
        &value.plan,
        &value.program,
        &preflight,
        &inventory,
        &supplied,
    )
    .unwrap();
    assert_eq!(verified.branch, "commissioned_receipt_verified");
    assert_eq!(verified.disposition, "refused");
    assert_eq!(verified.operation_record_count, 0);
    assert!(!verified.physical_build_performed);
    assert_eq!(verified.retrieved_artifact_count, 5);
    assert!(verified.evidence_is_fixture);
    to_evox2_scratch_build_live_evidence_verification_machine_form(&verified).unwrap();
}

#[test]
fn retrieval_replay_refuses_missing_extra_raw_tamper_and_substitution() {
    let value = fixture();
    let (preflight, inventory, artifacts) = retrieved_fixture(&value);

    let missing = artifacts[..4]
        .iter()
        .map(|(path, bytes)| (path.as_str(), bytes.as_slice()))
        .collect::<Vec<_>>();
    assert!(
        verify_evox2_scratch_build_retrieved_receipt_evidence(
            &value.request,
            &value.plan,
            &value.program,
            &preflight,
            &inventory,
            &missing,
        )
        .is_err()
    );

    let mut tampered = artifacts.clone();
    tampered[2].1.push(b'\n');
    let supplied = tampered
        .iter()
        .map(|(path, bytes)| (path.as_str(), bytes.as_slice()))
        .collect::<Vec<_>>();
    assert!(
        verify_evox2_scratch_build_retrieved_receipt_evidence(
            &value.request,
            &value.plan,
            &value.program,
            &preflight,
            &inventory,
            &supplied,
        )
        .is_err()
    );

    let mut substituted = artifacts;
    substituted[4].0 = "unexpected.json".to_owned();
    let supplied = substituted
        .iter()
        .map(|(path, bytes)| (path.as_str(), bytes.as_slice()))
        .collect::<Vec<_>>();
    assert!(
        verify_evox2_scratch_build_retrieved_receipt_evidence(
            &value.request,
            &value.plan,
            &value.program,
            &preflight,
            &inventory,
            &supplied,
        )
        .is_err()
    );
}

#[test]
fn retrieval_inventory_refuses_reorder_duplicate_path_and_outcome_promotion() {
    let value = fixture();
    let (preflight, inventory, artifacts) = retrieved_fixture(&value);

    let mut changed = inventory.clone();
    changed.artifacts.swap(0, 1);
    changed.inventory_sha256.clear();
    assert!(
        validate_evox2_scratch_build_retrieval_inventory(
            &value.request,
            &value.plan,
            &value.program,
            &preflight,
            &changed,
        )
        .is_err()
    );

    let mut changed = inventory.clone();
    changed.artifacts[1].relative_path = changed.artifacts[0].relative_path.clone();
    changed.inventory_sha256.clear();
    assert!(
        validate_evox2_scratch_build_retrieval_inventory(
            &value.request,
            &value.plan,
            &value.program,
            &preflight,
            &changed,
        )
        .is_err()
    );

    let mut changed = inventory;
    changed.outcome = "succeeded".to_owned();
    changed.inventory_sha256.clear();
    let resealed = seal_evox2_scratch_build_retrieval_inventory(
        &value.request,
        &value.plan,
        &value.program,
        &preflight,
        &changed.outcome,
        changed.artifacts,
    )
    .unwrap();
    let supplied = artifacts
        .iter()
        .map(|(path, bytes)| (path.as_str(), bytes.as_slice()))
        .collect::<Vec<_>>();
    assert!(
        verify_evox2_scratch_build_retrieved_receipt_evidence(
            &value.request,
            &value.plan,
            &value.program,
            &preflight,
            &resealed,
            &supplied,
        )
        .is_err()
    );
}

#[test]
fn live_preflight_form_distinguishes_observed_contact_from_fixture() {
    let value = fixture();
    let mut live = fixed_evox2_scratch_build_preflight_fixture(
        &value.request,
        &value.plan,
        &value.program,
        false,
    )
    .unwrap();
    live.observation_source = "live_remote_preflight".to_owned();
    live.remote_contact_made = true;
    live.remote_calls = 1;
    live.effects = 1;
    live.preflight_sha256.clear();
    let live = seal_evox2_scratch_build_remote_preflight(
        &value.request,
        &value.plan,
        &value.program,
        live,
    )
    .unwrap();
    let refusal = fixed_evox2_scratch_build_operational_refusal(
        &value.request,
        &value.plan,
        &value.program,
        &live,
    )
    .unwrap();
    let verified = verify_evox2_scratch_build_operational_refusal_evidence(
        &value.request,
        &value.plan,
        &value.program,
        &live,
        &refusal,
    )
    .unwrap();
    assert!(!verified.evidence_is_fixture);
    assert_eq!(verified.remote_calls, 1);
    assert_eq!(verified.effects, 1);
}

#[test]
fn provider_free_core_has_no_effect_api_surface() {
    let source = include_str!("../src/evox2_scratch_build_deployment_effect.rs");
    for forbidden in [
        "std::process",
        "std::fs",
        "std::env",
        "TcpStream",
        "Command::new",
        "powershell.exe",
        "ssh.exe",
        "scp.exe",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden effect API surface: {forbidden}"
        );
    }
}

#[test]
fn effect_state_machine_runs_exact_sequence_and_admits_cleanup_last() {
    let value = fixture();
    let mut state = initial_evox2_scratch_build_effect_state(&value.program).unwrap();
    for ordinal in 1..=10 {
        assert_eq!(state.next_stage_ordinal, ordinal);
        state = advance_evox2_scratch_build_effect_state(
            &value.program,
            &state,
            &observation(&value.program, ordinal, "passed"),
        )
        .unwrap();
    }
    assert_eq!(state.status, "completed");
    assert_eq!(state.disposition, "all_stages_passed");
    assert_eq!(state.completed_stage_count, 10);
    assert_eq!(state.next_stage_ordinal, 0);
    assert!(state.evidence_is_fixture);
    assert_eq!(state.remote_calls, 0);
    assert_eq!(state.effects, 0);
    let raw = to_evox2_scratch_build_effect_state_machine_form(&value.program, &state).unwrap();
    assert_eq!(
        from_evox2_scratch_build_effect_state_machine_form(&value.program, &raw).unwrap(),
        state
    );
}

#[test]
fn effect_state_machine_refuses_skip_restart_and_later_stage_after_stop() {
    let value = fixture();
    let initial = initial_evox2_scratch_build_effect_state(&value.program).unwrap();
    assert!(
        advance_evox2_scratch_build_effect_state(
            &value.program,
            &initial,
            &observation(&value.program, 2, "passed"),
        )
        .is_err()
    );
    let first = advance_evox2_scratch_build_effect_state(
        &value.program,
        &initial,
        &observation(&value.program, 1, "passed"),
    )
    .unwrap();
    let second = advance_evox2_scratch_build_effect_state(
        &value.program,
        &first,
        &observation(&value.program, 2, "passed"),
    )
    .unwrap();
    let stopped = advance_evox2_scratch_build_effect_state(
        &value.program,
        &second,
        &observation(&value.program, 3, "refused"),
    )
    .unwrap();
    assert_eq!(stopped.status, "stopped");
    assert_eq!(stopped.disposition, "stage_3_refused");
    assert_eq!(stopped.completed_stage_count, 2);
    assert!(
        advance_evox2_scratch_build_effect_state(
            &value.program,
            &stopped,
            &observation(&value.program, 4, "passed"),
        )
        .is_err()
    );
    assert!(
        advance_evox2_scratch_build_effect_state(
            &value.program,
            &second,
            &observation(&value.program, 10, "passed"),
        )
        .is_err()
    );
    let raw = to_evox2_scratch_build_effect_state_machine_form(&value.program, &stopped).unwrap();
    let promoted = raw.replace("\"status\":\"stopped\"", "\"status\":\"completed\"");
    assert!(from_evox2_scratch_build_effect_state_machine_form(&value.program, &promoted).is_err());
}

#[test]
fn effect_observation_refuses_kind_source_and_effect_count_drift() {
    let value = fixture();
    let exact = observation(&value.program, 3, "passed");
    let raw =
        to_evox2_scratch_build_effect_observation_machine_form(&value.program, &exact).unwrap();
    assert_eq!(
        from_evox2_scratch_build_effect_observation_machine_form(&value.program, &raw).unwrap(),
        exact
    );

    let mut changed = exact.clone();
    changed.kind = "transfer_package".to_owned();
    changed.observation_sha256.clear();
    assert!(seal_evox2_scratch_build_effect_observation(&value.program, changed).is_err());

    let mut changed = exact.clone();
    changed.observation_source = "live_wrapper_observation".to_owned();
    changed.effect_performed = true;
    changed.remote_calls = 2;
    changed.effects = 1;
    changed.observation_sha256.clear();
    assert!(seal_evox2_scratch_build_effect_observation(&value.program, changed).is_err());

    let mut changed = exact;
    changed.observation_source = "ambient_claim".to_owned();
    changed.observation_sha256.clear();
    assert!(seal_evox2_scratch_build_effect_observation(&value.program, changed).is_err());
}

#[test]
fn fresh_cli_compiles_and_verifies_operational_refusal_fixture() {
    let value = fixture();
    let parent = std::path::Path::new("D:/CantorBuilds");
    let root = parent.join(format!("evox2-effect-cli-test-{}", std::process::id()));
    if root.exists() {
        fs::remove_dir_all(&root).unwrap();
    }
    fs::create_dir(&root).unwrap();
    let result = (|| {
        let request =
            to_evox2_scratch_build_controller_request_machine_form(&value.request).unwrap();
        let plan = to_evox2_scratch_build_controller_plan_machine_form(&value.request, &value.plan)
            .unwrap();
        fs::write(root.join("request.json"), format!("{request}\n"))?;
        fs::write(root.join("plan.json"), format!("{plan}\n"))?;
        let binary = env!("CARGO_BIN_EXE_cantor-evox2-scratch-build-live-evidence-verify");
        let output = Command::new(binary)
            .current_dir(&root)
            .args(["program", "request.json", "plan.json"])
            .output()?;
        assert!(output.status.success());
        let program = String::from_utf8(output.stdout).unwrap();
        let program = program.trim_end_matches(['\r', '\n']);
        assert_eq!(
            from_evox2_scratch_build_effect_program_machine_form(
                &value.request,
                &value.plan,
                program,
            )
            .unwrap(),
            value.program
        );
        fs::write(root.join("program.json"), format!("{program}\n"))?;

        let output = Command::new(binary)
            .current_dir(&root)
            .args([
                "preflight-fixture",
                "request.json",
                "plan.json",
                "program.json",
                "refused",
            ])
            .output()?;
        assert!(output.status.success());
        let preflight = String::from_utf8(output.stdout).unwrap();
        let preflight = preflight.trim_end_matches(['\r', '\n']);
        fs::write(root.join("preflight.json"), format!("{preflight}\n"))?;

        let output = Command::new(binary)
            .current_dir(&root)
            .args([
                "refusal",
                "request.json",
                "plan.json",
                "program.json",
                "preflight.json",
            ])
            .output()?;
        assert!(output.status.success());
        let refusal = String::from_utf8(output.stdout).unwrap();
        let refusal = refusal.trim_end_matches(['\r', '\n']);
        fs::write(root.join("refusal.json"), format!("{refusal}\n"))?;

        let output = Command::new(binary)
            .current_dir(&root)
            .args([
                "verify-refusal",
                "request.json",
                "plan.json",
                "program.json",
                "preflight.json",
                "refusal.json",
            ])
            .output()?;
        assert!(output.status.success());
        let verification: Evox2ScratchBuildLiveEvidenceVerification =
            serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            verification.branch,
            "operational_refusal_before_commission_no_receipt"
        );
        assert_eq!(verification.remote_calls, 0);
        assert_eq!(verification.effects, 0);

        fs::write(root.join("program.json"), format!("{program}\n\n"))?;
        let refused = Command::new(binary)
            .current_dir(&root)
            .args([
                "verify-refusal",
                "request.json",
                "plan.json",
                "program.json",
                "preflight.json",
                "refusal.json",
            ])
            .output()?;
        assert!(!refused.status.success());
        Ok::<(), std::io::Error>(())
    })();
    fs::remove_dir_all(&root).unwrap();
    result.unwrap();
}

#[test]
fn checked_in_effect_wrapper_fixture_recomputes_exactly() {
    let value = fixture();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../experiments/evox2_scratch_build_executor_p0/effect_wrapper_fixture");
    let one_line = |name: &str| {
        let raw = fs::read_to_string(root.join(name)).unwrap();
        assert!(raw.ends_with('\n'));
        assert!(!raw.ends_with("\n\n"));
        raw.strip_suffix('\n').unwrap().to_owned()
    };
    let program_raw = one_line("program.json");
    let program = from_evox2_scratch_build_effect_program_machine_form(
        &value.request,
        &value.plan,
        &program_raw,
    )
    .unwrap();
    assert_eq!(program, value.program);
    let preflight_raw = one_line("preflight_refusal.json");
    let preflight = from_evox2_scratch_build_remote_preflight_machine_form(
        &value.request,
        &value.plan,
        &program,
        &preflight_raw,
    )
    .unwrap();
    let refusal_raw = one_line("operational_refusal.json");
    let refusal = from_evox2_scratch_build_operational_refusal_machine_form(
        &value.request,
        &value.plan,
        &program,
        &preflight,
        &refusal_raw,
    )
    .unwrap();
    let verified = verify_evox2_scratch_build_operational_refusal_evidence(
        &value.request,
        &value.plan,
        &program,
        &preflight,
        &refusal,
    )
    .unwrap();
    assert_eq!(
        to_evox2_scratch_build_live_evidence_verification_machine_form(&verified).unwrap(),
        one_line("refusal_verification.json")
    );
    let initial = initial_evox2_scratch_build_effect_state(&program).unwrap();
    assert_eq!(
        to_evox2_scratch_build_effect_state_machine_form(&program, &initial).unwrap(),
        one_line("initial_state.json")
    );
}
