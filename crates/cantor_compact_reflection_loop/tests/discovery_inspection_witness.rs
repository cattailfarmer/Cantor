use std::process::Command;

use cantor_compact_reflection_loop::{
    CheckpointCustodyOperation, CheckpointCustodyResult, ScriptedDiscoveryInspectionWitness,
    generate_scripted_discovery_inspection_witness,
    pretty_scripted_discovery_inspection_witness_bytes,
    validate_scripted_discovery_inspection_witness,
};

const ARTIFACT: &[u8] = include_bytes!(
    "../../../experiments/iterative_attention_procedure_loop_p1/artifacts/discovery_inspection_witness_v1.json"
);

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_cantor-compact-reflection-loop")
}

fn change_first_hex(value: &mut String) {
    let replacement = if value.starts_with('0') { "1" } else { "0" };
    value.replace_range(0..1, replacement);
}

#[test]
fn bootstrap_pin_rediscover_and_inspect_preserve_exact_identity() {
    let witness = generate_scripted_discovery_inspection_witness().expect("witness");
    assert!(!witness.bootstrap_response.caller_root_pinned);
    assert!(witness.pinned_response.caller_root_pinned);
    assert_eq!(witness.bootstrap_response.matches.len(), 1);
    assert_eq!(
        witness.bootstrap_response.matches,
        witness.pinned_response.matches
    );
    assert_eq!(
        witness.inspection_query.expected_registry_root,
        witness.pinned_response.registry_root
    );
    match (
        &witness.inspection_query.operation,
        &witness.inspection_response.result,
    ) {
        (
            CheckpointCustodyOperation::Inspect { handle },
            CheckpointCustodyResult::Inspection { inspection },
        ) => {
            assert_eq!(handle, &witness.pinned_response.matches[0].handle);
            assert_eq!(
                inspection.entry_digest,
                witness.pinned_response.matches[0].entry_digest
            );
            assert!(!inspection.full_checkpoint_embedded);
        }
        _ => panic!("wrong workflow operation"),
    }
}

#[test]
fn strict_round_trip_and_cross_stage_mutations_fail_closed() {
    let witness = generate_scripted_discovery_inspection_witness().expect("witness");
    let bytes = pretty_scripted_discovery_inspection_witness_bytes(&witness).expect("bytes");
    let decoded: ScriptedDiscoveryInspectionWitness =
        serde_json::from_slice(&bytes).expect("strict JSON");
    assert_eq!(decoded, witness);

    let mut wrong_digest = witness.clone();
    change_first_hex(&mut wrong_digest.workflow_digest.value);
    assert!(validate_scripted_discovery_inspection_witness(&wrong_digest).is_err());
    let mut wrong_stage = witness.clone();
    wrong_stage.pinned_response.caller_root_pinned = false;
    assert!(validate_scripted_discovery_inspection_witness(&wrong_stage).is_err());
    let mut body = witness;
    body.checkpoint_bodies_embedded = true;
    assert!(validate_scripted_discovery_inspection_witness(&body).is_err());
}

#[test]
fn witness_cli_stdout_is_typed_and_rejects_extra_arguments() {
    let output = Command::new(binary())
        .arg("witness-scripted-discovery-inspection")
        .output()
        .expect("run");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let witness: ScriptedDiscoveryInspectionWitness =
        serde_json::from_slice(&output.stdout).expect("typed witness");
    validate_scripted_discovery_inspection_witness(&witness).expect("valid");
    assert_eq!(
        output.stdout,
        pretty_scripted_discovery_inspection_witness_bytes(&witness).expect("pretty")
    );
    assert_eq!(output.stdout, ARTIFACT);
    let extra = Command::new(binary())
        .args(["witness-scripted-discovery-inspection", "unexpected"])
        .output()
        .expect("extra");
    assert_eq!(extra.status.code(), Some(2));
}
