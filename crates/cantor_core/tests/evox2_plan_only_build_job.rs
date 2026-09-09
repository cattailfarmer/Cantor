use std::fs;
use std::process::Command;

use cantor_core::*;

fn fixture() -> Evox2BuildPlanRequest {
    synthetic_evox2_build_plan_request()
}

fn compiled() -> (Evox2BuildPlanRequest, Evox2BuildPlan) {
    let request = fixture();
    let plan = compile_evox2_build_plan(&request).expect("compile build plan");
    (request, plan)
}

#[test]
fn deterministic_plan_has_exact_effectless_shape() {
    let request = fixture();
    let first = compile_evox2_build_plan(&request).unwrap();
    let second = compile_evox2_build_plan(&request).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.operations.len(), 7);
    assert_eq!(first.operation_count, 7);
    assert_eq!(first.authority_denials.len(), 15);
    assert!(first.authority_grants.is_empty());
    assert_eq!(first.unresolved.len(), 5);
    assert_eq!(first.disposition, "planned_effectless");
    assert_eq!(first.cargo_environment.CARGO_BUILD_JOBS, 1);
    assert!(first.cargo_environment.CARGO_NET_OFFLINE);
    assert_eq!(first.cargo_environment.RUST_MIN_STACK, 33_554_432);
    for (index, operation) in first.operations.iter().enumerate() {
        assert_eq!(operation.ordinal as usize, index + 1);
        assert_eq!(operation.authority_required, "not_granted");
        assert!(!operation.authority_denials.is_empty());
        assert_eq!(
            operation.dependencies,
            if index == 0 {
                Vec::new()
            } else {
                vec![index as u32]
            }
        );
    }
}

#[test]
fn canonical_roundtrip_and_independent_verification_pass() {
    let (request, plan) = compiled();
    let request_form = to_evox2_build_plan_request_machine_form(&request).unwrap();
    let plan_form = to_evox2_build_plan_machine_form(&plan).unwrap();
    assert_eq!(
        from_evox2_build_plan_request_machine_form(&request_form).unwrap(),
        request
    );
    assert_eq!(
        from_evox2_build_plan_machine_form(&plan_form).unwrap(),
        plan
    );
    let verification = verify_evox2_build_plan(&request, &plan).unwrap();
    assert_eq!(verification.status, "passed");
    assert!(verification.byte_identical_recompilation);
    assert_eq!(verification.authority_grant_count, 0);
    assert_eq!(verification.effects, 0);
    assert!(
        to_evox2_build_plan_verification_machine_form(&verification)
            .unwrap()
            .starts_with('{')
    );
}

#[test]
fn noncanonical_duplicate_unknown_and_trailing_request_forms_refuse() {
    let request = fixture();
    let canonical = to_evox2_build_plan_request_machine_form(&request).unwrap();
    assert!(from_evox2_build_plan_request_machine_form(&format!(" {canonical}")).is_err());
    assert!(from_evox2_build_plan_request_machine_form(&format!("{canonical}\n")).is_err());
    let duplicate = canonical.replacen(
        "{\"profile\":",
        "{\"profile\":\"cantor-evox2-plan-only-build-job/0.1\",\"profile\":",
        1,
    );
    assert!(from_evox2_build_plan_request_machine_form(&duplicate).is_err());
    let unknown = canonical.replacen("{", "{\"unknown\":false,", 1);
    assert!(from_evox2_build_plan_request_machine_form(&unknown).is_err());
    let reordered = canonical.replacen(
        "{\"profile\":\"cantor-evox2-plan-only-build-job/0.1\",\"request_uuid\":",
        "{\"request_uuid\":",
        1,
    );
    assert!(from_evox2_build_plan_request_machine_form(&reordered).is_err());
}

#[test]
fn request_identity_check_order_and_digest_tamper_refuse() {
    let request = fixture();
    let mut changed = request.clone();
    changed.request_uuid = "b1f2596f-2db8-40ea-8cb1-7bb85ba7f002".to_owned();
    assert!(validate_evox2_build_plan_request(&changed).is_err());
    let mut changed = request.clone();
    changed.source_archive_sha256.replace_range(0..1, "3");
    assert!(validate_evox2_build_plan_request(&changed).is_err());
    let mut changed = request.clone();
    changed.requested_checks.swap(0, 1);
    assert!(seal_evox2_build_plan_request(changed).is_err());
    let mut changed = request;
    let replacement = if changed.request_sha256.starts_with('0') {
        "1"
    } else {
        "0"
    };
    changed.request_sha256.replace_range(0..1, replacement);
    assert!(validate_evox2_build_plan_request(&changed).is_err());
}

#[test]
fn widened_bounds_and_unsafe_roots_refuse_even_when_resealed() {
    let mut changed = fixture();
    changed.bounds.maximum_archive_bytes = EVOX2_BUILD_PLAN_MAX_ARCHIVE_BYTES + 1;
    assert!(seal_evox2_build_plan_request(changed).is_err());
    let mut changed = fixture();
    changed.bounds.maximum_operation_count = 8;
    assert!(seal_evox2_build_plan_request(changed).is_err());
    let mut changed = fixture();
    changed.future_workspace_root = "C:/AI/workspaces/../services/sop-agent".to_owned();
    assert!(seal_evox2_build_plan_request(changed).is_err());
    let mut changed = fixture();
    changed.future_workspace_root = "C:/AI/services/cantor-needle-runtime".to_owned();
    assert!(seal_evox2_build_plan_request(changed).is_err());
}

#[test]
fn request_stdout_ceiling_and_shell_like_argument_refuse() {
    let mut request = fixture();
    request.bounds.maximum_stdout_bytes = 1;
    let request = seal_evox2_build_plan_request(request).unwrap();
    let error = compile_evox2_build_plan(&request).unwrap_err();
    assert_eq!(error.code, Evox2BuildPlanFaultCode::InvalidBound);

    let (request, mut plan) = compiled();
    plan.operations[2].arguments[0] = "test;invoke".to_owned();
    plan.plan_sha256 = evox2_build_plan_digest(&plan).unwrap();
    let error = verify_evox2_build_plan(&request, &plan).unwrap_err();
    assert_eq!(error.code, Evox2BuildPlanFaultCode::InvalidOperation);
}

#[test]
fn operation_and_argument_mutation_refuse_after_digest_repair() {
    let (request, mut plan) = compiled();
    plan.operations[2].kind = "workspace_other".to_owned();
    plan.plan_sha256 = evox2_build_plan_digest(&plan).unwrap();
    assert!(verify_evox2_build_plan(&request, &plan).is_err());

    let (request, mut plan) = compiled();
    plan.operations[2].arguments[0] = "bench".to_owned();
    plan.plan_sha256 = evox2_build_plan_digest(&plan).unwrap();
    assert!(verify_evox2_build_plan(&request, &plan).is_err());
}

#[test]
fn dependency_cycle_refuses_after_digest_repair() {
    let (request, mut plan) = compiled();
    plan.operations[1].dependencies = vec![2];
    plan.plan_sha256 = evox2_build_plan_digest(&plan).unwrap();
    let error = verify_evox2_build_plan(&request, &plan).unwrap_err();
    assert_eq!(error.code, Evox2BuildPlanFaultCode::InvalidDependency);
}

#[test]
fn authority_grant_and_unresolved_removal_refuse_after_digest_repair() {
    let (request, mut plan) = compiled();
    plan.authority_grants.push("process_execute".to_owned());
    plan.plan_sha256 = evox2_build_plan_digest(&plan).unwrap();
    assert!(verify_evox2_build_plan(&request, &plan).is_err());

    let (request, mut plan) = compiled();
    plan.unresolved.pop();
    plan.plan_sha256 = evox2_build_plan_digest(&plan).unwrap();
    assert!(verify_evox2_build_plan(&request, &plan).is_err());
}

#[test]
fn plan_digest_and_plan_uuid_tamper_refuse() {
    let (request, mut plan) = compiled();
    plan.plan_sha256.replace_range(0..1, "f");
    assert!(verify_evox2_build_plan(&request, &plan).is_err());

    let (request, mut plan) = compiled();
    plan.plan_uuid = "b1f2596f-2db8-80ea-8cb1-7bb85ba7f003".to_owned();
    plan.plan_sha256 = evox2_build_plan_digest(&plan).unwrap();
    assert!(verify_evox2_build_plan(&request, &plan).is_err());
}

#[test]
fn fresh_cli_processes_compile_verify_and_refuse_tamper() {
    let root = std::env::temp_dir().join(format!(
        "cantor-evox2-plan-only-build-job-{}",
        std::process::id()
    ));
    fs::create_dir(&root).expect("create exact fresh CLI test root");
    let result = (|| {
        let request = fixture();
        fs::write(
            root.join("request.json"),
            to_evox2_build_plan_request_machine_form(&request).unwrap(),
        )?;
        let compiler = env!("CARGO_BIN_EXE_cantor-evox2-plan-only-build-job");
        let verifier = env!("CARGO_BIN_EXE_cantor-evox2-plan-only-build-job-verify");

        let first = Command::new(compiler)
            .current_dir(&root)
            .arg("request.json")
            .output()?;
        assert!(
            first.status.success(),
            "compiler stderr must remain bounded"
        );
        let second = Command::new(compiler)
            .current_dir(&root)
            .arg("request.json")
            .output()?;
        assert!(second.status.success(), "second compiler process must pass");
        assert_eq!(first.stdout, second.stdout);
        let plan = String::from_utf8(first.stdout).expect("compiler UTF-8");
        let plan = plan.strip_suffix('\n').expect("one stdout terminator");
        assert!(!plan.ends_with('\r'));
        fs::write(root.join("plan-1.json"), plan)?;
        fs::write(root.join("plan-2.json"), plan)?;

        for name in ["plan-1.json", "plan-2.json"] {
            let verified = Command::new(verifier)
                .current_dir(&root)
                .args(["request.json", name])
                .output()?;
            assert!(verified.status.success(), "verifier process must pass");
            let record: Evox2BuildPlanVerification = serde_json::from_slice(&verified.stdout)
                .expect("verification JSON plus whitespace");
            assert_eq!(record.status, "passed");
            assert_eq!(record.effects, 0);
            assert_eq!(record.authority_grant_count, 0);
        }

        assert!(
            !Command::new(compiler)
                .current_dir(&root)
                .arg("other.json")
                .output()?
                .status
                .success()
        );
        let mut tampered: Evox2BuildPlan =
            from_evox2_build_plan_machine_form(plan).expect("plan parse");
        tampered.operations[0].expected_evidence = "other".to_owned();
        tampered.plan_sha256 = evox2_build_plan_digest(&tampered).unwrap();
        fs::write(
            root.join("plan-2.json"),
            to_evox2_build_plan_machine_form(&tampered).unwrap(),
        )?;
        assert!(
            !Command::new(verifier)
                .current_dir(&root)
                .args(["request.json", "plan-2.json"])
                .output()?
                .status
                .success()
        );
        fs::write(
            root.join("request.json"),
            vec![b'x'; EVOX2_BUILD_PLAN_MAX_REQUEST_BYTES + 1],
        )?;
        assert!(
            !Command::new(compiler)
                .current_dir(&root)
                .arg("request.json")
                .output()?
                .status
                .success()
        );
        Ok::<(), std::io::Error>(())
    })();
    fs::remove_dir_all(&root).expect("remove exact CLI test root");
    result.expect("CLI process exercise");
}
