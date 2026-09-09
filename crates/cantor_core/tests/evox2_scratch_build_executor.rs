use cantor_core::*;
use std::fs;
use std::process::Command;

fn args(ordinal: u32) -> Vec<String> {
    let values: &[&str] = match ordinal {
        1 => &["verify", "--sha256"],
        2 => &["materialize", "--absent-root"],
        3 => &[
            "test",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--locked",
            "--offline",
        ],
        4 => &[
            "test",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--release",
            "--locked",
            "--offline",
        ],
        5 => &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--locked",
            "--offline",
            "--",
            "-D",
            "warnings",
        ],
        6 => &["fmt", "--all", "--", "--check"],
        7 => &["seal", "--effect-account", "exact"],
        _ => panic!("fixture ordinal"),
    };
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn observation() -> Evox2ScratchBuildToolchainObservation {
    seal_evox2_scratch_build_toolchain_observation(Evox2ScratchBuildToolchainObservation {
        architecture: "x86_64-pc-windows-msvc".to_owned(),
        cargo_path: "C:/Users/cantor/.cargo/bin/cargo.exe".to_owned(),
        cargo_sha256: "1".repeat(64),
        cargo_version: "cargo 1.96.0".to_owned(),
        rustc_path: "C:/Users/cantor/.cargo/bin/rustc.exe".to_owned(),
        rustc_sha256: "2".repeat(64),
        rustc_version: "rustc 1.96.0".to_owned(),
        linker_path: "C:/BuildTools/link.exe".to_owned(),
        linker_sha256: "3".repeat(64),
        offline_probe_status: "available_without_mutation".to_owned(),
        observation_sha256: String::new(),
    })
    .unwrap()
}

fn record(
    commission: &Evox2ScratchBuildCommission,
    ordinal: u32,
    exit_code: i32,
) -> Evox2ScratchBuildOperationRecord {
    seal_evox2_scratch_build_operation_record(
        Evox2ScratchBuildOperationRecord {
            ordinal,
            kind: evox2_scratch_build_operation_ordinals()[(ordinal - 1) as usize].clone(),
            admitted: true,
            started_at: format!("2026-09-09T00:00:0{ordinal}Z"),
            ended_at: format!("2026-09-09T00:00:1{ordinal}Z"),
            duration_ms: 10,
            executable_path: if (3..=6).contains(&ordinal) {
                observation().cargo_path
            } else {
                "C:/AI/services/cantor-scratch-build/executor.exe".to_owned()
            },
            executable_sha256: if (3..=6).contains(&ordinal) {
                observation().cargo_sha256
            } else {
                "4".repeat(64)
            },
            arguments: args(ordinal),
            working_directory: if ordinal == 7 {
                commission.target_root.clone()
            } else {
                commission.workspace_root.clone()
            },
            environment: commission.cargo_environment.clone(),
            exit_code,
            stdout_bytes: 0,
            stdout_sha256: "5".repeat(64),
            stdout_truncated: false,
            stderr_bytes: 0,
            stderr_sha256: "6".repeat(64),
            stderr_truncated: false,
            target_bytes_after: u64::from(ordinal) * 1_024,
            evidence_sha256: String::new(),
        },
        commission,
    )
    .unwrap()
}

fn receipt_with(
    commission: &Evox2ScratchBuildCommission,
    records: Vec<Evox2ScratchBuildOperationRecord>,
    disposition: &str,
    physical_build_performed: bool,
) -> Evox2ScratchBuildReceipt {
    seal_evox2_scratch_build_receipt(
        Evox2ScratchBuildReceipt {
            profile: EVOX2_SCRATCH_BUILD_RECEIPT_PROFILE.to_owned(),
            receipt_uuid: "470bb601-d647-40c9-b851-8b214d477a0a".to_owned(),
            canonical_uuid: commission.canonical_uuid.clone(),
            commission_uuid: commission.commission_uuid.clone(),
            commission_sha256: commission.commission_sha256.clone(),
            source_archive_sha256: commission.source_archive_sha256.clone(),
            source_commit: commission.source_commit.clone(),
            target_host: commission.target_host.clone(),
            workspace_root: commission.workspace_root.clone(),
            target_root: commission.target_root.clone(),
            toolchain_observation: observation(),
            operation_records: records,
            protected_before: "7".repeat(64),
            protected_after: "7".repeat(64),
            provider_before: "8".repeat(64),
            provider_after: "8".repeat(64),
            persistent_executor_process_count: 0,
            physical_build_performed,
            disposition: disposition.to_owned(),
            receipt_sha256: String::new(),
        },
        commission,
    )
    .unwrap()
}

#[test]
fn commission_has_exact_one_run_shape_and_roundtrips() {
    let commission = synthetic_evox2_scratch_build_commission();
    assert_eq!(commission.operation_ordinals.len(), 7);
    assert_eq!(commission.authority_grants.len(), 5);
    assert_eq!(commission.authority_denials.len(), 14);
    assert_eq!(commission.requested_checks.len(), 4);
    assert_eq!(commission.bounds, fixed_evox2_scratch_build_bounds());
    assert_eq!(
        commission.cargo_environment,
        fixed_evox2_scratch_build_environment()
    );
    let form = to_evox2_scratch_build_commission_machine_form(&commission).unwrap();
    assert_eq!(
        from_evox2_scratch_build_commission_machine_form(&form).unwrap(),
        commission
    );
}

#[test]
fn commission_noncanonical_duplicate_unknown_and_trailing_forms_refuse() {
    let commission = synthetic_evox2_scratch_build_commission();
    let canonical = to_evox2_scratch_build_commission_machine_form(&commission).unwrap();
    assert!(from_evox2_scratch_build_commission_machine_form(&format!(" {canonical}")).is_err());
    assert!(from_evox2_scratch_build_commission_machine_form(&format!("{canonical}\n")).is_err());
    let duplicate = canonical.replacen(
        "{\"profile\":",
        "{\"profile\":\"cantor-evox2-scratch-build-executor/0.1\",\"profile\":",
        1,
    );
    assert!(from_evox2_scratch_build_commission_machine_form(&duplicate).is_err());
    let unknown = canonical.replacen('{', "{\"unknown\":false,", 1);
    assert!(from_evox2_scratch_build_commission_machine_form(&unknown).is_err());
    let reordered = canonical.replacen(
        "{\"profile\":\"cantor-evox2-scratch-build-executor/0.1\",\"commission_uuid\":",
        "{\"commission_uuid\":",
        1,
    );
    assert!(from_evox2_scratch_build_commission_machine_form(&reordered).is_err());
}

#[test]
fn identity_authority_bound_and_digest_mutation_refuse() {
    let mut changed = synthetic_evox2_scratch_build_commission();
    changed.source_commit = "0".repeat(40);
    assert!(seal_evox2_scratch_build_commission(changed).is_err());

    let mut changed = synthetic_evox2_scratch_build_commission();
    changed.authority_grants.push("cleanup".to_owned());
    assert!(seal_evox2_scratch_build_commission(changed).is_err());

    let mut changed = synthetic_evox2_scratch_build_commission();
    changed.bounds.maximum_target_bytes += 1;
    assert!(seal_evox2_scratch_build_commission(changed).is_err());

    let mut changed = synthetic_evox2_scratch_build_commission();
    changed.commission_sha256.replace_range(0..1, "f");
    assert!(validate_evox2_scratch_build_commission(&changed).is_err());
}

#[test]
fn successful_receipt_requires_all_seven_successful_records() {
    let commission = synthetic_evox2_scratch_build_commission();
    let records = (1..=7)
        .map(|ordinal| record(&commission, ordinal, 0))
        .collect();
    let receipt = receipt_with(&commission, records, "succeeded", true);
    verify_evox2_scratch_build_receipt(&commission, &receipt).unwrap();
    let form = to_evox2_scratch_build_receipt_machine_form(&commission, &receipt).unwrap();
    assert_eq!(
        from_evox2_scratch_build_receipt_machine_form(&commission, &form).unwrap(),
        receipt
    );
}

#[test]
fn stopped_failure_and_pre_admission_refusal_are_honest() {
    let commission = synthetic_evox2_scratch_build_commission();
    let failed = receipt_with(
        &commission,
        vec![record(&commission, 1, 0), record(&commission, 2, 2)],
        "failed",
        false,
    );
    verify_evox2_scratch_build_receipt(&commission, &failed).unwrap();

    let refused = receipt_with(
        &commission,
        vec![record(&commission, 1, 0)],
        "refused",
        false,
    );
    verify_evox2_scratch_build_receipt(&commission, &refused).unwrap();
}

#[test]
fn later_operation_after_failure_and_physical_build_promotion_refuse() {
    let commission = synthetic_evox2_scratch_build_commission();
    let records = vec![record(&commission, 1, 1), record(&commission, 2, 0)];
    let candidate = Evox2ScratchBuildReceipt {
        operation_records: records,
        disposition: "failed".to_owned(),
        physical_build_performed: false,
        ..receipt_with(&commission, Vec::new(), "refused", false)
    };
    assert!(seal_evox2_scratch_build_receipt(candidate, &commission).is_err());

    let mut promoted = receipt_with(&commission, Vec::new(), "refused", false);
    promoted.physical_build_performed = true;
    promoted.receipt_sha256 = evox2_scratch_build_receipt_digest(&promoted).unwrap();
    assert!(verify_evox2_scratch_build_receipt(&commission, &promoted).is_err());
}

#[test]
fn command_environment_and_nested_digest_mutation_refuse() {
    let commission = synthetic_evox2_scratch_build_commission();
    let mut changed = record(&commission, 3, 0);
    changed.arguments[0] = "bench".to_owned();
    assert!(seal_evox2_scratch_build_operation_record(changed, &commission).is_err());

    let mut changed = record(&commission, 3, 0);
    changed.environment.CARGO_NET_OFFLINE = false;
    assert!(seal_evox2_scratch_build_operation_record(changed, &commission).is_err());

    let records = (1..=7)
        .map(|ordinal| record(&commission, ordinal, 0))
        .collect();
    let mut receipt = receipt_with(&commission, records, "succeeded", true);
    receipt.operation_records[0].evidence_sha256 = "9".repeat(64);
    receipt.receipt_sha256 = evox2_scratch_build_receipt_digest(&receipt).unwrap();
    assert!(verify_evox2_scratch_build_receipt(&commission, &receipt).is_err());
}

#[test]
fn receipt_cross_binds_cargo_and_executor_executable_identities() {
    let commission = synthetic_evox2_scratch_build_commission();
    let records = (1..=7)
        .map(|ordinal| record(&commission, ordinal, 0))
        .collect();
    let receipt = receipt_with(&commission, records, "succeeded", true);

    let mut cargo_drift = receipt.clone();
    cargo_drift.operation_records[2].executable_sha256 = "9".repeat(64);
    cargo_drift.operation_records[2] = seal_evox2_scratch_build_operation_record(
        cargo_drift.operation_records[2].clone(),
        &commission,
    )
    .unwrap();
    cargo_drift.receipt_sha256 = evox2_scratch_build_receipt_digest(&cargo_drift).unwrap();
    assert!(verify_evox2_scratch_build_receipt(&commission, &cargo_drift).is_err());

    let mut executor_drift = receipt;
    executor_drift.operation_records[1].executable_path =
        "C:/AI/services/cantor-scratch-build/other-executor.exe".to_owned();
    executor_drift.operation_records[1] = seal_evox2_scratch_build_operation_record(
        executor_drift.operation_records[1].clone(),
        &commission,
    )
    .unwrap();
    executor_drift.receipt_sha256 = evox2_scratch_build_receipt_digest(&executor_drift).unwrap();
    assert!(verify_evox2_scratch_build_receipt(&commission, &executor_drift).is_err());
}

#[test]
fn cumulative_operation_duration_bound_refuses() {
    let commission = synthetic_evox2_scratch_build_commission();
    let records = (1..=7)
        .map(|ordinal| {
            let mut changed = record(&commission, ordinal, 0);
            changed.duration_ms = 6_000_000;
            seal_evox2_scratch_build_operation_record(changed, &commission).unwrap()
        })
        .collect();
    let candidate = Evox2ScratchBuildReceipt {
        operation_records: records,
        disposition: "succeeded".to_owned(),
        physical_build_performed: true,
        ..receipt_with(&commission, Vec::new(), "refused", false)
    };
    assert!(seal_evox2_scratch_build_receipt(candidate, &commission).is_err());
}

#[test]
fn conservation_drift_and_persistent_process_refuse() {
    let commission = synthetic_evox2_scratch_build_commission();
    let mut receipt = receipt_with(&commission, Vec::new(), "refused", false);
    receipt.provider_after = "a".repeat(64);
    receipt.receipt_sha256 = evox2_scratch_build_receipt_digest(&receipt).unwrap();
    assert!(verify_evox2_scratch_build_receipt(&commission, &receipt).is_err());

    let mut receipt = receipt_with(&commission, Vec::new(), "refused", false);
    receipt.persistent_executor_process_count = 1;
    receipt.receipt_sha256 = evox2_scratch_build_receipt_digest(&receipt).unwrap();
    assert!(verify_evox2_scratch_build_receipt(&commission, &receipt).is_err());
}

#[test]
fn fresh_verifier_processes_pass_and_refuse_tamper() {
    let root = std::env::temp_dir().join(format!(
        "cantor-evox2-scratch-build-verifiers-{}",
        std::process::id()
    ));
    fs::create_dir(&root).expect("create exact verifier root");
    let result = (|| {
        let commission = synthetic_evox2_scratch_build_commission();
        let records = (1..=7)
            .map(|ordinal| record(&commission, ordinal, 0))
            .collect();
        let receipt = receipt_with(&commission, records, "succeeded", true);
        fs::write(
            root.join("commission.json"),
            to_evox2_scratch_build_commission_machine_form(&commission).unwrap(),
        )?;
        fs::write(
            root.join("receipt.json"),
            to_evox2_scratch_build_receipt_machine_form(&commission, &receipt).unwrap(),
        )?;

        let commission_verifier =
            env!("CARGO_BIN_EXE_cantor-evox2-scratch-build-commission-verify");
        let receipt_verifier = env!("CARGO_BIN_EXE_cantor-evox2-scratch-build-receipt-verify");
        let verified = Command::new(commission_verifier)
            .current_dir(&root)
            .arg("commission.json")
            .output()?;
        assert!(verified.status.success());
        let record: Evox2ScratchBuildCommissionVerification =
            serde_json::from_slice(&verified.stdout).unwrap();
        assert_eq!(record.status, "passed");
        assert_eq!(record.effects, 0);

        let verified = Command::new(receipt_verifier)
            .current_dir(&root)
            .args(["commission.json", "receipt.json"])
            .output()?;
        assert!(verified.status.success());
        let record: Evox2ScratchBuildReceiptVerification =
            serde_json::from_slice(&verified.stdout).unwrap();
        assert_eq!(record.disposition, "succeeded");
        assert!(record.physical_build_performed);

        fs::write(
            root.join("commission.json"),
            format!(
                "{}\n",
                to_evox2_scratch_build_commission_machine_form(&commission).unwrap()
            ),
        )?;
        assert!(
            !Command::new(commission_verifier)
                .current_dir(&root)
                .arg("commission.json")
                .output()?
                .status
                .success()
        );
        fs::write(
            root.join("commission.json"),
            to_evox2_scratch_build_commission_machine_form(&commission).unwrap(),
        )?;
        let mut tampered = receipt;
        tampered.provider_after = "9".repeat(64);
        tampered.receipt_sha256 = evox2_scratch_build_receipt_digest(&tampered).unwrap();
        fs::write(
            root.join("receipt.json"),
            serde_json::to_string(&tampered).unwrap(),
        )?;
        assert!(
            !Command::new(receipt_verifier)
                .current_dir(&root)
                .args(["commission.json", "receipt.json"])
                .output()?
                .status
                .success()
        );
        Ok::<(), std::io::Error>(())
    })();
    fs::remove_dir_all(&root).expect("remove exact verifier root");
    result.expect("fresh verifier processes");
}
