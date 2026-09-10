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
                EVOX2_SCRATCH_BUILD_EXECUTOR_PATH.to_owned()
            },
            executable_sha256: if (3..=6).contains(&ordinal) {
                observation().cargo_sha256
            } else {
                "4".repeat(64)
            },
            arguments: args(ordinal),
            working_directory: match ordinal {
                1 => EVOX2_SCRATCH_BUILD_SERVICE_ROOT.to_owned(),
                2 => "C:/AI/workspaces".to_owned(),
                7 => commission.target_root.clone(),
                _ => commission.workspace_root.clone(),
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

fn implementation_manifest() -> Evox2ScratchBuildImplementationManifest {
    let artifacts = evox2_scratch_build_package_artifacts()
        .into_iter()
        .enumerate()
        .map(|(index, (relative_path, role))| {
            let source_archive = relative_path == "source.tar";
            Evox2ScratchBuildPackageArtifact {
                relative_path,
                role,
                bytes: (index + 1) as u64,
                sha256: if source_archive {
                    EVOX2_SCRATCH_BUILD_SOURCE_ARCHIVE_SHA256.to_owned()
                } else {
                    format!("{:064x}", index + 1)
                },
            }
        })
        .collect::<Vec<_>>();
    let aggregate_bytes = artifacts.iter().map(|artifact| artifact.bytes).sum();
    seal_evox2_scratch_build_implementation_manifest(Evox2ScratchBuildImplementationManifest {
        profile: EVOX2_SCRATCH_BUILD_IMPLEMENTATION_MANIFEST_PROFILE.to_owned(),
        manifest_uuid: "973d579c-157d-4550-bad9-8c5e2e79c569".to_owned(),
        canonical_uuid: EVOX2_SCRATCH_BUILD_CANONICAL_UUID.to_owned(),
        local_core_bookend_commit: EVOX2_SCRATCH_BUILD_LOCAL_CORE_BOOKEND_COMMIT.to_owned(),
        implementation_commit: "a".repeat(40),
        source_commit: EVOX2_SCRATCH_BUILD_SOURCE_COMMIT.to_owned(),
        source_archive_sha256: EVOX2_SCRATCH_BUILD_SOURCE_ARCHIVE_SHA256.to_owned(),
        target_host: EVOX2_SCRATCH_BUILD_TARGET_HOST.to_owned(),
        workspace_root: EVOX2_SCRATCH_BUILD_WORKSPACE_ROOT.to_owned(),
        target_root: EVOX2_SCRATCH_BUILD_TARGET_ROOT.to_owned(),
        artifact_count: artifacts.len() as u32,
        aggregate_bytes,
        artifacts,
        allowed_executions: evox2_scratch_build_package_executions(),
        authority_grants: Vec::new(),
        effects: 0,
        manifest_sha256: String::new(),
    })
    .unwrap()
}

fn package_forms() -> (
    Evox2ScratchBuildImplementationManifest,
    Evox2ScratchBuildCommandSet,
    Evox2ScratchBuildCommission,
    Evox2ScratchBuildDeploymentEnvelope,
) {
    let manifest = implementation_manifest();
    let command_set = fixed_evox2_scratch_build_command_set();
    let commission = commissioned_evox2_scratch_build(
        &manifest.manifest_sha256,
        &command_set.command_set_sha256,
    )
    .unwrap();
    let envelope =
        seal_evox2_scratch_build_deployment_envelope(Evox2ScratchBuildDeploymentEnvelope {
            profile: EVOX2_SCRATCH_BUILD_DEPLOYMENT_ENVELOPE_PROFILE.to_owned(),
            envelope_uuid: "864229f1-f3b6-45ad-9ab3-02f52e7795b7".to_owned(),
            canonical_uuid: EVOX2_SCRATCH_BUILD_CANONICAL_UUID.to_owned(),
            implementation_manifest_sha256: manifest.manifest_sha256.clone(),
            commission_uuid: commission.commission_uuid.clone(),
            commission_sha256: commission.commission_sha256.clone(),
            command_set_sha256: command_set.command_set_sha256.clone(),
            package_file_count: manifest.artifact_count + 3,
            package_aggregate_bytes: manifest.aggregate_bytes + 4_096,
            disposition: "sealed_for_single_commission".to_owned(),
            envelope_sha256: String::new(),
        })
        .unwrap();
    (manifest, command_set, commission, envelope)
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

    let preflight_refused = seal_evox2_scratch_build_receipt(
        Evox2ScratchBuildReceipt {
            toolchain_observation: unobserved_evox2_scratch_build_toolchain(),
            ..receipt_with(&commission, Vec::new(), "refused", false)
        },
        &commission,
    )
    .unwrap();
    verify_evox2_scratch_build_receipt(&commission, &preflight_refused).unwrap();
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
        "C:/AI/services/cantor-scratch-build-4fdd29cb/bin/other-executor.exe".to_owned();
    assert!(
        seal_evox2_scratch_build_operation_record(
            executor_drift.operation_records[1].clone(),
            &commission,
        )
        .is_err()
    );
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

#[test]
fn commission_compiler_process_is_deterministic_and_manifest_bound() {
    let root = std::env::temp_dir().join(format!(
        "cantor-evox2-scratch-build-compiler-{}",
        std::process::id()
    ));
    fs::create_dir(&root).unwrap();
    let result = (|| {
        let manifest = implementation_manifest();
        let command_set = fixed_evox2_scratch_build_command_set();
        fs::write(
            root.join("implementation_manifest.json"),
            to_evox2_scratch_build_implementation_manifest_machine_form(&manifest).unwrap(),
        )?;
        fs::write(
            root.join("command_set.json"),
            to_evox2_scratch_build_command_set_machine_form(&command_set).unwrap(),
        )?;
        let compiler = env!("CARGO_BIN_EXE_cantor-evox2-scratch-build-commission");
        let first = Command::new(compiler)
            .current_dir(&root)
            .args(["implementation_manifest.json", "command_set.json"])
            .output()?;
        let second = Command::new(compiler)
            .current_dir(&root)
            .args(["implementation_manifest.json", "command_set.json"])
            .output()?;
        assert!(first.status.success());
        assert_eq!(first.stdout, second.stdout);
        let raw = std::str::from_utf8(&first.stdout).unwrap().trim_end();
        let commission = from_evox2_scratch_build_commission_machine_form(raw).unwrap();
        assert_eq!(commission.package_manifest_sha256, manifest.manifest_sha256);
        assert_eq!(
            commission.command_set_sha256,
            command_set.command_set_sha256
        );

        let emitted = Command::new(compiler).arg("command-set").output()?;
        assert!(emitted.status.success());
        let emitted = std::str::from_utf8(&emitted.stdout).unwrap().trim_end();
        assert_eq!(
            from_evox2_scratch_build_command_set_machine_form(emitted).unwrap(),
            command_set
        );
        Ok::<(), std::io::Error>(())
    })();
    fs::remove_dir_all(&root).unwrap();
    result.unwrap();
}

#[test]
fn pinned_git_archive_passes_strict_ustar_pax_admission() {
    let root = std::env::temp_dir().join(format!(
        "cantor-evox2-scratch-build-real-archive-{}",
        std::process::id()
    ));
    fs::create_dir(&root).unwrap();
    let archive = root.join("source.tar");
    let repository = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let status = Command::new("git")
        .args(["-C"])
        .arg(repository)
        .args(["archive", "--format=tar", "--output"])
        .arg(&archive)
        .arg(EVOX2_SCRATCH_BUILD_SOURCE_COMMIT)
        .status()
        .unwrap();
    assert!(status.success());
    let verification = verify_evox2_scratch_build_source_archive(&archive).unwrap();
    assert_eq!(
        verification.archive_sha256,
        EVOX2_SCRATCH_BUILD_SOURCE_ARCHIVE_SHA256
    );
    assert!(verification.member_count > 0);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn acyclic_package_graph_roundtrips_and_corresponds() {
    let (manifest, command_set, commission, envelope) = package_forms();
    let manifest_form =
        to_evox2_scratch_build_implementation_manifest_machine_form(&manifest).unwrap();
    let command_form = to_evox2_scratch_build_command_set_machine_form(&command_set).unwrap();
    let envelope_form = to_evox2_scratch_build_deployment_envelope_machine_form(&envelope).unwrap();
    assert_eq!(
        from_evox2_scratch_build_implementation_manifest_machine_form(&manifest_form).unwrap(),
        manifest
    );
    assert_eq!(
        from_evox2_scratch_build_command_set_machine_form(&command_form).unwrap(),
        command_set
    );
    assert_eq!(
        from_evox2_scratch_build_deployment_envelope_machine_form(&envelope_form).unwrap(),
        envelope
    );
    let verified = verify_evox2_scratch_build_package_correspondence(
        &manifest,
        &command_set,
        &commission,
        &envelope,
    )
    .unwrap();
    assert_eq!(verified.artifact_count, 21);
    assert_eq!(verified.package_file_count, 24);
    assert_eq!(verified.effects, 0);
}

#[test]
fn package_graph_refuses_cycles_membership_and_digest_drift() {
    let (manifest, command_set, commission, envelope) = package_forms();

    let mut inside_manifest = manifest.clone();
    inside_manifest.artifacts[0].relative_path = "commission.json".to_owned();
    assert!(seal_evox2_scratch_build_implementation_manifest(inside_manifest).is_err());

    let mut extra_authority = manifest.clone();
    extra_authority
        .authority_grants
        .push("process_execute".to_owned());
    assert!(seal_evox2_scratch_build_implementation_manifest(extra_authority).is_err());

    let mut command_drift = command_set.clone();
    command_drift.commands[0].arguments[0] = "bench".to_owned();
    assert!(seal_evox2_scratch_build_command_set(command_drift).is_err());

    let mut correspondence_drift = envelope;
    correspondence_drift.commission_sha256 = "f".repeat(64);
    correspondence_drift =
        seal_evox2_scratch_build_deployment_envelope(correspondence_drift).unwrap();
    assert!(
        verify_evox2_scratch_build_package_correspondence(
            &manifest,
            &command_set,
            &commission,
            &correspondence_drift,
        )
        .is_err()
    );
}

#[test]
fn package_machine_forms_refuse_raw_duplicate_and_unknown_tamper() {
    let (manifest, command_set, _, envelope) = package_forms();
    let command = to_evox2_scratch_build_command_set_machine_form(&command_set).unwrap();
    assert!(from_evox2_scratch_build_command_set_machine_form(&format!("{command}\n")).is_err());
    let duplicate = command.replacen(
        "{\"profile\":",
        "{\"profile\":\"cantor-evox2-scratch-build-command-set/0.1\",\"profile\":",
        1,
    );
    assert!(from_evox2_scratch_build_command_set_machine_form(&duplicate).is_err());

    let manifest_form =
        to_evox2_scratch_build_implementation_manifest_machine_form(&manifest).unwrap();
    assert!(
        from_evox2_scratch_build_implementation_manifest_machine_form(&manifest_form.replacen(
            '{',
            "{\"unknown\":false,",
            1,
        ))
        .is_err()
    );

    let envelope_form = to_evox2_scratch_build_deployment_envelope_machine_form(&envelope).unwrap();
    assert!(
        from_evox2_scratch_build_deployment_envelope_machine_form(&format!(" {envelope_form}"))
            .is_err()
    );
}

#[test]
fn package_composer_process_closes_real_archive_manifest_and_envelope() {
    let root = std::env::temp_dir().join(format!(
        "cantor-evox2-scratch-build-package-compose-{}",
        std::process::id()
    ));
    fs::create_dir(&root).unwrap();
    let result = (|| {
        let repository = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let command_set = fixed_evox2_scratch_build_command_set();
        let command_set_raw =
            to_evox2_scratch_build_command_set_machine_form(&command_set).unwrap();
        for (relative_path, _) in evox2_scratch_build_package_artifacts() {
            let path = root.join(relative_path.replace('/', "\\"));
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            match relative_path.as_str() {
                "source.tar" => {
                    let status = Command::new("git")
                        .args(["-C"])
                        .arg(&repository)
                        .args(["archive", "--format=tar", "--output"])
                        .arg(&path)
                        .arg(EVOX2_SCRATCH_BUILD_SOURCE_COMMIT)
                        .status()?;
                    assert!(status.success());
                }
                "command_set.json" => fs::write(path, &command_set_raw)?,
                _ => fs::write(path, format!("fixture:{relative_path}"))?,
            }
        }

        let composer = env!("CARGO_BIN_EXE_cantor-evox2-scratch-build-package-compose");
        let compiler = env!("CARGO_BIN_EXE_cantor-evox2-scratch-build-commission");
        let manifest_first = Command::new(composer)
            .current_dir(&root)
            .args(["manifest", "--implementation-commit", &"a".repeat(40)])
            .output()?;
        let manifest_second = Command::new(composer)
            .current_dir(&root)
            .args(["manifest", "--implementation-commit", &"a".repeat(40)])
            .output()?;
        assert!(manifest_first.status.success());
        assert_eq!(manifest_first.stdout, manifest_second.stdout);
        let manifest_raw = std::str::from_utf8(&manifest_first.stdout)
            .unwrap()
            .trim_end();
        let manifest =
            from_evox2_scratch_build_implementation_manifest_machine_form(manifest_raw).unwrap();
        assert_eq!(manifest.artifact_count, 21);
        let source_archive = manifest
            .artifacts
            .iter()
            .find(|artifact| artifact.relative_path == "source.tar")
            .unwrap();
        assert_eq!(
            source_archive.sha256,
            EVOX2_SCRATCH_BUILD_SOURCE_ARCHIVE_SHA256
        );
        fs::write(root.join("implementation_manifest.json"), manifest_raw)?;

        let commission = Command::new(compiler)
            .current_dir(&root)
            .args(["implementation_manifest.json", "command_set.json"])
            .output()?;
        assert!(commission.status.success());
        let commission_raw = std::str::from_utf8(&commission.stdout).unwrap().trim_end();
        fs::write(root.join("commission.json"), commission_raw)?;

        let envelope_first = Command::new(composer)
            .current_dir(&root)
            .args([
                "envelope",
                "implementation_manifest.json",
                "command_set.json",
                "commission.json",
            ])
            .output()?;
        let envelope_second = Command::new(composer)
            .current_dir(&root)
            .args([
                "envelope",
                "implementation_manifest.json",
                "command_set.json",
                "commission.json",
            ])
            .output()?;
        assert!(envelope_first.status.success());
        assert_eq!(envelope_first.stdout, envelope_second.stdout);
        let envelope_raw = std::str::from_utf8(&envelope_first.stdout)
            .unwrap()
            .trim_end();
        let envelope =
            from_evox2_scratch_build_deployment_envelope_machine_form(envelope_raw).unwrap();
        assert_eq!(envelope.package_file_count, 24);
        assert_eq!(
            envelope.package_aggregate_bytes,
            manifest.aggregate_bytes
                + manifest_raw.len() as u64
                + commission_raw.len() as u64
                + envelope_raw.len() as u64
        );

        let source_archive = root.join("source.tar");
        let mut tampered = fs::read(&source_archive)?;
        tampered.push(0);
        fs::write(&source_archive, tampered)?;
        let refused = Command::new(composer)
            .current_dir(&root)
            .args(["manifest", "--implementation-commit", &"a".repeat(40)])
            .output()?;
        assert!(!refused.status.success());
        Ok::<(), std::io::Error>(())
    })();
    fs::remove_dir_all(&root).unwrap();
    result.unwrap();
}
