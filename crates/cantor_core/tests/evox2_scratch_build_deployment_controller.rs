use cantor_core::*;
use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};

const RUN_UUID: &str = "61927fc8-5c08-4a78-9993-df1dc975db56";
const IMPLEMENTATION: &str = "1111111111111111111111111111111111111111";
const BOOKEND: &str = "2222222222222222222222222222222222222222";

fn request() -> Evox2ScratchBuildControllerRequest {
    fixed_evox2_scratch_build_controller_request(RUN_UUID, IMPLEMENTATION, BOOKEND).unwrap()
}

#[test]
fn fixed_request_and_plan_are_deterministic_closed_and_nonauthorizing() {
    let request = request();
    assert_eq!(
        request.package_evidence_bookend_commit,
        EVOX2_SCRATCH_BUILD_CONTROLLER_PACKAGE_EVIDENCE_BOOKEND_COMMIT
    );
    assert_eq!(
        request.package_set_sha256,
        EVOX2_SCRATCH_BUILD_CONTROLLER_PACKAGE_SET_SHA256
    );
    let first = compile_evox2_scratch_build_controller_plan(&request).unwrap();
    let second = compile_evox2_scratch_build_controller_plan(&request).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.stage_count, 10);
    assert_eq!(
        first.stages.iter().filter(|stage| stage.effectful).count(),
        7
    );
    assert!(first.stages.iter().all(|stage| stage.stop_on_failure));
    assert_eq!(
        first.provider_unavailable_disposition,
        "operational_refusal_before_commission_no_receipt"
    );
    assert_eq!(
        first.cleanup_condition,
        "transient_transport_only_after_local_evidence_verification"
    );
    assert_eq!(first.authority_disposition, "descriptive_not_authorizing");
    assert!(!first.remote_contact_authorized);
    assert_eq!(first.effects, 0);
}

#[test]
fn machine_forms_are_strict_canonical_and_round_trip() {
    let request = request();
    let request_raw = to_evox2_scratch_build_controller_request_machine_form(&request).unwrap();
    assert_eq!(
        from_evox2_scratch_build_controller_request_machine_form(&request_raw).unwrap(),
        request
    );
    assert!(
        from_evox2_scratch_build_controller_request_machine_form(&format!("{request_raw}\n"))
            .is_err()
    );
    let duplicate =
        request_raw.replacen("\"profile\":", "\"profile\":\"duplicate\",\"profile\":", 1);
    assert!(from_evox2_scratch_build_controller_request_machine_form(&duplicate).is_err());
    let unknown = request_raw.replacen("{", "{\"unknown\":0,", 1);
    assert!(from_evox2_scratch_build_controller_request_machine_form(&unknown).is_err());

    let plan = compile_evox2_scratch_build_controller_plan(&request).unwrap();
    let plan_raw = to_evox2_scratch_build_controller_plan_machine_form(&request, &plan).unwrap();
    assert_eq!(
        from_evox2_scratch_build_controller_plan_machine_form(&request, &plan_raw).unwrap(),
        plan
    );
}

#[test]
fn run_derived_coordinates_and_publication_lineage_refuse_substitution() {
    let mut changed = request();
    changed.local_evidence_root.push_str("/escape");
    assert!(seal_evox2_scratch_build_controller_request(changed).is_err());

    let mut changed = request();
    changed.remote_stage_root = "C:/AI/services/other".to_owned();
    assert!(seal_evox2_scratch_build_controller_request(changed).is_err());

    let mut changed = request();
    changed.package_evidence_bookend_commit = "3333333333333333333333333333333333333333".to_owned();
    assert!(seal_evox2_scratch_build_controller_request(changed).is_err());

    let mut changed = request();
    changed.package_set_sha256 = "0".repeat(64);
    assert!(seal_evox2_scratch_build_controller_request(changed).is_err());

    let mut changed = request();
    changed.controller_publication_bookend_commit = IMPLEMENTATION.to_owned();
    assert!(seal_evox2_scratch_build_controller_request(changed).is_err());

    let mut changed = request();
    changed.ssh_host = "host;whoami".to_owned();
    assert!(seal_evox2_scratch_build_controller_request(changed).is_err());
}

#[test]
fn plan_stage_refusal_and_cleanup_boundaries_are_exact() {
    let request = request();
    let plan = compile_evox2_scratch_build_controller_plan(&request).unwrap();
    let expected = [
        "local_package_verify",
        "publication_lineage_verify",
        "remote_preflight",
        "transfer_package",
        "remote_package_verify",
        "atomic_service_install",
        "execute_commission_once",
        "retrieve_evidence",
        "independent_local_verify",
        "cleanup_transient_transport",
    ];
    assert_eq!(
        plan.stages
            .iter()
            .map(|stage| stage.kind.as_str())
            .collect::<Vec<_>>(),
        expected
    );

    let mut changed = plan.clone();
    changed.stages.swap(7, 8);
    changed.plan_sha256.clear();
    assert!(verify_evox2_scratch_build_controller_plan(&request, &changed).is_err());

    let mut changed = plan.clone();
    changed.provider_unavailable_disposition = "receipt_fabricated".to_owned();
    assert!(verify_evox2_scratch_build_controller_plan(&request, &changed).is_err());

    let mut changed = plan;
    changed.cleanup_condition = "cleanup_before_verification".to_owned();
    assert!(verify_evox2_scratch_build_controller_plan(&request, &changed).is_err());
}

#[test]
fn verification_reports_plan_shape_without_authority_or_effects() {
    let request = request();
    let plan = compile_evox2_scratch_build_controller_plan(&request).unwrap();
    let verification = verify_evox2_scratch_build_controller_plan(&request, &plan).unwrap();
    assert_eq!(verification.status, "passed");
    assert_eq!(verification.stage_count, 10);
    assert_eq!(verification.effectful_stage_count, 7);
    assert!(!verification.remote_contact_authorized);
    assert_eq!(verification.effects, 0);
    to_evox2_scratch_build_controller_verification_machine_form(&verification).unwrap();
}

#[test]
fn cli_compiles_and_independently_verifies_the_exact_plan() {
    let request = request();
    let request_raw = to_evox2_scratch_build_controller_request_machine_form(&request).unwrap();
    let binary = env!("CARGO_BIN_EXE_cantor-evox2-scratch-build-deployment-plan");
    let request_output = Command::new(binary)
        .args(["request", RUN_UUID, IMPLEMENTATION, BOOKEND])
        .output()
        .unwrap();
    assert!(request_output.status.success());
    assert_eq!(
        String::from_utf8(request_output.stdout)
            .unwrap()
            .trim_end_matches(['\r', '\n']),
        request_raw
    );
    let mut child = Command::new(binary)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(request_raw.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let plan_raw = String::from_utf8(output.stdout).unwrap();
    let plan_raw = plan_raw.trim_end_matches(['\r', '\n']);
    let plan = from_evox2_scratch_build_controller_plan_machine_form(&request, plan_raw).unwrap();

    let root = std::env::temp_dir().join(format!("cantor-controller-test-{RUN_UUID}"));
    if root.exists() {
        fs::remove_dir_all(&root).unwrap();
    }
    fs::create_dir(&root).unwrap();
    let request_path = root.join("request.json");
    let plan_path = root.join("plan.json");
    fs::write(&request_path, format!("{request_raw}\n")).unwrap();
    fs::write(
        &plan_path,
        format!(
            "{}\n",
            to_evox2_scratch_build_controller_plan_machine_form(&request, &plan).unwrap()
        ),
    )
    .unwrap();
    let compile_output = Command::new(binary)
        .arg("compile")
        .arg(&request_path)
        .output()
        .unwrap();
    assert!(compile_output.status.success());
    assert_eq!(
        String::from_utf8(compile_output.stdout)
            .unwrap()
            .trim_end_matches(['\r', '\n']),
        to_evox2_scratch_build_controller_plan_machine_form(&request, &plan).unwrap()
    );
    let output = Command::new(binary)
        .args(["verify"])
        .arg(&request_path)
        .arg(&plan_path)
        .output()
        .unwrap();
    fs::remove_dir_all(&root).unwrap();
    assert!(output.status.success());
    let verification: Evox2ScratchBuildControllerVerification =
        serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(verification.status, "passed");
    assert_eq!(verification.effects, 0);
}

#[test]
fn pure_controller_core_has_no_process_network_or_filesystem_effect_surface() {
    let source = include_str!("../src/evox2_scratch_build_deployment_controller.rs");
    for forbidden in [
        "std::process",
        "std::fs",
        "TcpStream",
        "ssh.exe",
        "scp.exe",
        "Command::new",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden effect surface: {forbidden}"
        );
    }
}

#[test]
fn checked_in_controller_fixture_recomputes_without_remote_authority() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let fixture = root.join("experiments/evox2_scratch_build_executor_p0/controller_fixture");
    let request_raw = fs::read_to_string(fixture.join("request.json")).unwrap();
    let plan_raw = fs::read_to_string(fixture.join("plan.json")).unwrap();
    let verification_raw = fs::read_to_string(fixture.join("verification.json")).unwrap();
    let request_raw = request_raw.trim_end_matches(['\r', '\n']);
    let plan_raw = plan_raw.trim_end_matches(['\r', '\n']);
    let request = from_evox2_scratch_build_controller_request_machine_form(request_raw).unwrap();
    let plan = from_evox2_scratch_build_controller_plan_machine_form(&request, plan_raw).unwrap();
    assert_eq!(
        compile_evox2_scratch_build_controller_plan(&request).unwrap(),
        plan
    );
    let verification = verify_evox2_scratch_build_controller_plan(&request, &plan).unwrap();
    assert_eq!(
        to_evox2_scratch_build_controller_verification_machine_form(&verification).unwrap(),
        verification_raw.trim_end_matches(['\r', '\n'])
    );
    assert!(!verification.remote_contact_authorized);
    assert_eq!(verification.effects, 0);
}
