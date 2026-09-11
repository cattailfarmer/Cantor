use cantor_core::*;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::process::Command;

const RUN_UUID: &str = "be7bbaed-4b3f-4d54-8d7b-8f060f96630d";
const IMPLEMENTATION: &str = "1111111111111111111111111111111111111111";
const BOOKEND: &str = "2222222222222222222222222222222222222222";
const EXECUTABLE_SHA256: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

struct Fixture {
    request: Evox2ScratchBuildControllerRequest,
    plan: Evox2ScratchBuildControllerPlan,
    program: Evox2ScratchBuildEffectProgram,
    producer_plan: Evox2ScratchBuildRemotePreflightProducerPlan,
}

fn fixture() -> Fixture {
    let request =
        fixed_evox2_scratch_build_controller_request(RUN_UUID, IMPLEMENTATION, BOOKEND).unwrap();
    let plan = compile_evox2_scratch_build_controller_plan(&request).unwrap();
    let program = compile_evox2_scratch_build_effect_program(&request, &plan).unwrap();
    let producer_plan = compile_evox2_scratch_build_remote_preflight_producer_plan(
        &request,
        &plan,
        &program,
        EXECUTABLE_SHA256,
    )
    .unwrap();
    Fixture {
        request,
        plan,
        program,
        producer_plan,
    }
}

fn probe(value: &Fixture, available: bool) -> Evox2ScratchBuildRemoteProbeResult {
    seal_evox2_scratch_build_remote_probe_result(
        &value.request,
        Evox2ScratchBuildRemoteProbeResult {
            profile: EVOX2_SCRATCH_BUILD_REMOTE_PROBE_RESULT_PROFILE.to_owned(),
            run_uuid: value.request.run_uuid.clone(),
            request_sha256: value.request.request_sha256.clone(),
            target_host: value.request.target_host.clone(),
            provider_listener: "127.0.0.1:8081".to_owned(),
            provider_model_path: "C:/AI/models/validation/Qwen3.5-0.8B-GGUF/Qwen3.5-0.8B-Q4_0.gguf"
                .to_owned(),
            listener_observed: available,
            model_observed: available,
            provider_status: if available {
                "available"
            } else {
                "unavailable"
            }
            .to_owned(),
            reason: if available {
                "preflight_satisfied"
            } else {
                "provider_unavailable_before_commission"
            }
            .to_owned(),
            probe_sha256: String::new(),
        },
    )
    .unwrap()
}

fn process_record(
    value: &Fixture,
    available: bool,
) -> Evox2ScratchBuildRemotePreflightProcessRecord {
    let probe = probe(value, available);
    let stdout =
        to_evox2_scratch_build_remote_probe_result_machine_form(&value.request, &probe).unwrap();
    seal_evox2_scratch_build_remote_preflight_process_record(
        &value.request,
        &value.plan,
        &value.program,
        &value.producer_plan,
        Evox2ScratchBuildRemotePreflightProcessRecord {
            profile: EVOX2_SCRATCH_BUILD_REMOTE_PREFLIGHT_PROCESS_RECORD_PROFILE.to_owned(),
            producer_plan_sha256: value.producer_plan.producer_plan_sha256.clone(),
            executable_path: value.producer_plan.executable_path.clone(),
            executable_sha256: value.producer_plan.executable_sha256.clone(),
            argument_atoms: value.producer_plan.argument_atoms.clone(),
            argument_count: value.producer_plan.argument_count,
            evidence_class: "live_process_observation".to_owned(),
            started: true,
            completed: true,
            exit_code: 0,
            duration_ms: 17,
            timed_out: false,
            stdout_bytes: u32::try_from(stdout.len()).unwrap(),
            stdout_sha256: sha256(stdout.as_bytes()),
            stdout,
            stdout_truncated: false,
            stderr: String::new(),
            stderr_bytes: 0,
            stderr_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .to_owned(),
            stderr_truncated: false,
            probe,
            remote_contact_made: true,
            provider_requests: 0,
            remote_calls: 1,
            effects: 1,
            process_record_sha256: String::new(),
        },
    )
    .unwrap()
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn decode_base64(value: &str) -> Vec<u8> {
    fn sextet(byte: u8) -> u8 {
        match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => panic!("invalid Base64 fixture"),
        }
    }
    let mut decoded = Vec::new();
    for chunk in value.as_bytes().chunks_exact(4) {
        let first = sextet(chunk[0]);
        let second = sextet(chunk[1]);
        decoded.push((first << 2) | (second >> 4));
        if chunk[2] != b'=' {
            let third = sextet(chunk[2]);
            decoded.push((second << 4) | (third >> 2));
            if chunk[3] != b'=' {
                decoded.push((third << 6) | sextet(chunk[3]));
            }
        }
    }
    decoded
}

#[test]
fn producer_plan_is_deterministic_bounded_and_nonauthorizing() {
    let value = fixture();
    let repeated = compile_evox2_scratch_build_remote_preflight_producer_plan(
        &value.request,
        &value.plan,
        &value.program,
        EXECUTABLE_SHA256,
    )
    .unwrap();
    assert_eq!(value.producer_plan, repeated);
    assert_eq!(value.producer_plan.argument_count, 19);
    assert_eq!(
        value.producer_plan.executable_path,
        "C:/Windows/System32/OpenSSH/ssh.exe"
    );
    assert_eq!(value.producer_plan.argument_atoms[0], "-o");
    assert_eq!(value.producer_plan.argument_atoms[1], "BatchMode=yes");
    assert_eq!(value.producer_plan.argument_atoms[3], "ConnectTimeout=15");
    assert_eq!(value.producer_plan.argument_atoms[10], "evo-x2");
    assert_eq!(value.producer_plan.argument_atoms[17], "-EncodedCommand");
    assert_eq!(value.producer_plan.timeout_ms, 30_000);
    assert_eq!(value.producer_plan.stdout_limit_bytes, 65_536);
    assert_eq!(value.producer_plan.stderr_limit_bytes, 65_536);
    assert!(!value.producer_plan.remote_contact_authorized);
    assert_eq!(value.producer_plan.provider_request_limit, 0);
    assert_eq!(value.producer_plan.remote_call_limit, 1);
    assert_eq!(value.producer_plan.effect_limit, 1);

    let payload_bytes = decode_base64(&value.producer_plan.argument_atoms[18]);
    let words = payload_bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    let payload = String::from_utf16(&words).unwrap();
    assert!(payload.contains(RUN_UUID));
    assert!(payload.contains(&value.request.request_sha256));
    assert!(payload.contains("$env:COMPUTERNAME -ne 'EVO-X2'"));
    assert!(payload.contains("target_host_mismatch"));
    assert!(payload.contains("127.0.0.1"));
    assert!(payload.contains("Qwen3.5-0.8B-Q4_0.gguf"));
    assert!(payload.contains(PROBE_DIGEST_MARKER));
    assert!(!payload.contains("Invoke-WebRequest"));
    assert!(!payload.contains("Start-Process"));
}

const PROBE_DIGEST_MARKER: &str = "cantor-evox2-scratch-build-remote-probe-result-v1";

#[test]
fn producer_plan_machine_form_round_trips_and_refuses_noncanonical_or_unknown_data() {
    let value = fixture();
    let raw = to_evox2_scratch_build_remote_preflight_producer_plan_machine_form(
        &value.request,
        &value.plan,
        &value.program,
        &value.producer_plan,
    )
    .unwrap();
    assert_eq!(
        from_evox2_scratch_build_remote_preflight_producer_plan_machine_form(
            &value.request,
            &value.plan,
            &value.program,
            &raw,
        )
        .unwrap(),
        value.producer_plan
    );
    assert!(
        from_evox2_scratch_build_remote_preflight_producer_plan_machine_form(
            &value.request,
            &value.plan,
            &value.program,
            &format!("{raw}\n"),
        )
        .is_err()
    );
    let unknown = raw.replacen("{", "{\"unknown\":true,", 1);
    assert!(
        from_evox2_scratch_build_remote_preflight_producer_plan_machine_form(
            &value.request,
            &value.plan,
            &value.program,
            &unknown,
        )
        .is_err()
    );
}

#[test]
fn process_record_compiles_exact_published_observation_and_verification() {
    for available in [false, true] {
        let value = fixture();
        let record = process_record(&value, available);
        let observation =
            compile_evox2_scratch_build_remote_preflight_observation_from_process_record(
                &value.request,
                &value.plan,
                &value.program,
                &value.producer_plan,
                &record,
            )
            .unwrap();
        let preflight = compile_evox2_scratch_build_remote_preflight_from_observation(
            &value.request,
            &value.plan,
            &value.program,
            &observation,
        )
        .unwrap();
        assert_eq!(
            preflight.status,
            if available { "admitted" } else { "refused" }
        );
        assert_eq!(preflight.remote_calls, 1);
        assert_eq!(preflight.effects, 1);
        let verification = verify_evox2_scratch_build_remote_preflight_producer(
            &value.request,
            &value.plan,
            &value.program,
            &value.producer_plan,
            &record,
            &observation,
        )
        .unwrap();
        assert_eq!(verification.status, "passed");
        assert!(!verification.remote_contact_authorized);
        assert!(
            to_evox2_scratch_build_remote_preflight_producer_verification_machine_form(
                &verification
            )
            .is_ok()
        );
    }
}

#[test]
fn process_record_machine_form_round_trips() {
    let value = fixture();
    let record = process_record(&value, false);
    let raw = to_evox2_scratch_build_remote_preflight_process_record_machine_form(
        &value.request,
        &value.plan,
        &value.program,
        &value.producer_plan,
        &record,
    )
    .unwrap();
    assert_eq!(
        from_evox2_scratch_build_remote_preflight_process_record_machine_form(
            &value.request,
            &value.plan,
            &value.program,
            &value.producer_plan,
            &raw,
        )
        .unwrap(),
        record
    );
}

#[test]
fn executable_identity_and_each_argument_atom_are_bound() {
    let value = fixture();
    let mut path = value.producer_plan.clone();
    path.executable_path.push_str(".old");
    path.producer_plan_sha256.clear();
    assert!(
        verify_evox2_scratch_build_remote_preflight_producer_plan(
            &value.request,
            &value.plan,
            &value.program,
            &path,
        )
        .is_err()
    );

    let mut digest = value.producer_plan.clone();
    digest.executable_sha256 = "b".repeat(64);
    digest.producer_plan_sha256.clear();
    assert!(
        verify_evox2_scratch_build_remote_preflight_producer_plan(
            &value.request,
            &value.plan,
            &value.program,
            &digest,
        )
        .is_err()
    );

    for index in 0..value.producer_plan.argument_atoms.len() {
        let mut drift = value.producer_plan.clone();
        drift.argument_atoms[index].push('x');
        drift.producer_plan_sha256.clear();
        assert!(
            verify_evox2_scratch_build_remote_preflight_producer_plan(
                &value.request,
                &value.plan,
                &value.program,
                &drift,
            )
            .is_err(),
            "argument atom {index} drift admitted"
        );
    }
}

#[test]
fn timeout_exit_truncation_and_accounting_drift_refuse_before_compilation() {
    let value = fixture();
    let baseline = process_record(&value, false);
    let mut cases = Vec::new();

    let mut restart = baseline.clone();
    restart.started = false;
    cases.push(restart);
    let mut incomplete = baseline.clone();
    incomplete.completed = false;
    cases.push(incomplete);
    let mut exit = baseline.clone();
    exit.exit_code = 1;
    cases.push(exit);
    let mut duration = baseline.clone();
    duration.duration_ms = value.producer_plan.timeout_ms + 1;
    cases.push(duration);
    let mut timed_out = baseline.clone();
    timed_out.timed_out = true;
    cases.push(timed_out);
    let mut stdout_truncated = baseline.clone();
    stdout_truncated.stdout_truncated = true;
    cases.push(stdout_truncated);
    let mut stderr = baseline.clone();
    stderr.stderr = "warning".to_owned();
    stderr.stderr_bytes = 7;
    stderr.stderr_sha256 = sha256(stderr.stderr.as_bytes());
    cases.push(stderr);
    let mut stderr_truncated = baseline.clone();
    stderr_truncated.stderr_truncated = true;
    cases.push(stderr_truncated);
    let mut provider_request = baseline.clone();
    provider_request.provider_requests = 1;
    cases.push(provider_request);
    let mut extra_call = baseline.clone();
    extra_call.remote_calls = 2;
    cases.push(extra_call);
    let mut extra_effect = baseline.clone();
    extra_effect.effects = 2;
    cases.push(extra_effect);

    for mut record in cases {
        record.process_record_sha256.clear();
        assert!(
            seal_evox2_scratch_build_remote_preflight_process_record(
                &value.request,
                &value.plan,
                &value.program,
                &value.producer_plan,
                record,
            )
            .is_err()
        );
    }
}

#[test]
fn raw_stream_argument_and_nested_probe_tamper_refuse() {
    let value = fixture();
    let baseline = process_record(&value, false);

    let mut raw = baseline.clone();
    raw.stdout.push('\n');
    raw.stdout_bytes += 1;
    raw.stdout_sha256 = sha256(raw.stdout.as_bytes());
    raw.process_record_sha256.clear();
    assert!(
        seal_evox2_scratch_build_remote_preflight_process_record(
            &value.request,
            &value.plan,
            &value.program,
            &value.producer_plan,
            raw,
        )
        .is_err()
    );

    let mut argument = baseline.clone();
    argument.argument_atoms[3] = "ConnectTimeout=14".to_owned();
    argument.process_record_sha256.clear();
    assert!(
        seal_evox2_scratch_build_remote_preflight_process_record(
            &value.request,
            &value.plan,
            &value.program,
            &value.producer_plan,
            argument,
        )
        .is_err()
    );

    let mut nested = baseline;
    nested.probe.provider_listener = "127.0.0.1:8082".to_owned();
    nested.probe.probe_sha256.clear();
    nested.process_record_sha256.clear();
    assert!(
        seal_evox2_scratch_build_remote_preflight_process_record(
            &value.request,
            &value.plan,
            &value.program,
            &value.producer_plan,
            nested,
        )
        .is_err()
    );
}

#[test]
fn retained_observation_substitution_refuses_verification() {
    let value = fixture();
    let record = process_record(&value, false);
    let mut observation =
        compile_evox2_scratch_build_remote_preflight_observation_from_process_record(
            &value.request,
            &value.plan,
            &value.program,
            &value.producer_plan,
            &record,
        )
        .unwrap();
    observation.observation_sha256 = "f".repeat(64);
    assert!(
        verify_evox2_scratch_build_remote_preflight_producer(
            &value.request,
            &value.plan,
            &value.program,
            &value.producer_plan,
            &record,
            &observation,
        )
        .is_err()
    );
}

#[test]
fn fresh_process_cli_replays_plan_compile_and_verify() {
    let value = fixture();
    let record = process_record(&value, false);
    let observation = compile_evox2_scratch_build_remote_preflight_observation_from_process_record(
        &value.request,
        &value.plan,
        &value.program,
        &value.producer_plan,
        &record,
    )
    .unwrap();
    let root = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join(format!(
            "evox2-preflight-producer-cli-test-{}",
            std::process::id()
        ));
    if root.exists() {
        fs::remove_dir_all(&root).unwrap();
    }
    fs::create_dir_all(&root).unwrap();
    let request_path = root.join("request.json");
    let plan_path = root.join("plan.json");
    let program_path = root.join("program.json");
    let producer_plan_path = root.join("producer_plan.json");
    let record_path = root.join("process_record.json");
    let observation_path = root.join("observation.json");
    fs::write(
        &request_path,
        to_evox2_scratch_build_controller_request_machine_form(&value.request).unwrap(),
    )
    .unwrap();
    fs::write(
        &plan_path,
        to_evox2_scratch_build_controller_plan_machine_form(&value.request, &value.plan).unwrap(),
    )
    .unwrap();
    fs::write(
        &program_path,
        to_evox2_scratch_build_effect_program_machine_form(
            &value.request,
            &value.plan,
            &value.program,
        )
        .unwrap(),
    )
    .unwrap();
    fs::write(
        &producer_plan_path,
        to_evox2_scratch_build_remote_preflight_producer_plan_machine_form(
            &value.request,
            &value.plan,
            &value.program,
            &value.producer_plan,
        )
        .unwrap(),
    )
    .unwrap();
    fs::write(
        &record_path,
        to_evox2_scratch_build_remote_preflight_process_record_machine_form(
            &value.request,
            &value.plan,
            &value.program,
            &value.producer_plan,
            &record,
        )
        .unwrap(),
    )
    .unwrap();
    fs::write(
        &observation_path,
        to_evox2_scratch_build_remote_preflight_observation_machine_form(
            &value.request,
            &value.plan,
            &value.program,
            &observation,
        )
        .unwrap(),
    )
    .unwrap();

    let executable = env!("CARGO_BIN_EXE_cantor-evox2-scratch-build-preflight-producer-verify");
    let plan_output = Command::new(executable)
        .args([
            "plan",
            request_path.to_str().unwrap(),
            plan_path.to_str().unwrap(),
            program_path.to_str().unwrap(),
            EXECUTABLE_SHA256,
        ])
        .output()
        .unwrap();
    assert!(plan_output.status.success());
    assert_eq!(
        String::from_utf8(plan_output.stdout)
            .unwrap()
            .trim_end_matches(['\r', '\n']),
        fs::read_to_string(&producer_plan_path).unwrap()
    );

    let compile_output = Command::new(executable)
        .args([
            "compile",
            request_path.to_str().unwrap(),
            plan_path.to_str().unwrap(),
            program_path.to_str().unwrap(),
            producer_plan_path.to_str().unwrap(),
            record_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(compile_output.status.success());
    assert_eq!(
        String::from_utf8(compile_output.stdout)
            .unwrap()
            .trim_end_matches(['\r', '\n']),
        fs::read_to_string(&observation_path).unwrap()
    );

    let verify_output = Command::new(executable)
        .args([
            "verify",
            request_path.to_str().unwrap(),
            plan_path.to_str().unwrap(),
            program_path.to_str().unwrap(),
            producer_plan_path.to_str().unwrap(),
            record_path.to_str().unwrap(),
            observation_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(verify_output.status.success());
    let verification: serde_json::Value = serde_json::from_slice(&verify_output.stdout).unwrap();
    assert_eq!(verification["status"], "passed");
    assert_eq!(verification["remote_contact_authorized"], false);
    assert_eq!(verification["provider_requests"], 0);
    assert_eq!(verification["remote_calls"], 1);
    assert_eq!(verification["effects"], 1);

    fs::remove_dir_all(root).unwrap();
}
