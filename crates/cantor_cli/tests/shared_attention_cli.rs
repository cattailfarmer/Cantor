use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::process::{Command, Output, Stdio};

use cantor_core::{
    ATTENTION_BYTE_PROXY_PROFILE, ATTENTION_COMPACTION_PROFILE, ATTENTION_DELTA_PROFILE,
    AttentionCapacity, AttentionCompaction, AttentionFrameDelta, AttentionParticipant,
    AttestationDisposition, ContentDigest, EpistemicStatus, FRAME_ATTESTATION_PROFILE, FacultyKind,
    FrameAttestation, FrameDeltaOperation, FramedProposition, SemanticId, SharedAttentionFrame,
    SharedAttentionFrameSeed, SharedAttentionToolRequest, execute_shared_attention_tool_request,
    finalize_attention_compaction, finalize_attention_delta, finalize_frame_attestation,
    new_shared_attention_frame,
};

fn sid(value: &str) -> SemanticId {
    SemanticId::new(value).expect("semantic id")
}

fn frame(headroom: u64) -> SharedAttentionFrame {
    let guard = AttentionParticipant {
        participant_id: sid("participant:guard"),
        faculties: BTreeSet::from([FacultyKind::Honesty, FacultyKind::Security]),
        required: true,
    };
    let server = AttentionParticipant {
        participant_id: sid("participant:server"),
        faculties: BTreeSet::from([FacultyKind::Observer, FacultyKind::Refiner]),
        required: true,
    };
    let projection = AttentionParticipant {
        participant_id: sid("participant:projection"),
        faculties: BTreeSet::from([FacultyKind::Planner, FacultyKind::Weaver]),
        required: true,
    };
    let proposition = FramedProposition {
        proposition_id: sid("proposition:base"),
        text: "Cantor coordinates a semantic frame.".to_owned(),
        epistemic_status: EpistemicStatus::Observed,
        source_refs: BTreeSet::from([sid("source:fixture")]),
        evidence_refs: BTreeSet::new(),
        dream_ref: None,
    };
    new_shared_attention_frame(SharedAttentionFrameSeed {
        frame_id: sid("frame:cli-fixture"),
        purpose: "prove closed JSON transport".to_owned(),
        policy_ref: sid("policy:fixture"),
        participants: BTreeMap::from([
            (guard.participant_id.clone(), guard),
            (projection.participant_id.clone(), projection),
            (server.participant_id.clone(), server),
        ]),
        propositions: BTreeMap::from([(proposition.proposition_id.clone(), proposition)]),
        constraints: BTreeMap::from([(
            sid("constraint:no-hidden-state"),
            "no provider hidden state is shared".to_owned(),
        )]),
        pinned_sop_anchor_refs: BTreeSet::new(),
        evidence_refs: BTreeSet::new(),
        current_focus_refs: BTreeSet::from([sid("proposition:base")]),
        capacity: AttentionCapacity {
            accounting_profile: ATTENTION_BYTE_PROXY_PROFILE.to_owned(),
            context_budget_bytes: 2_000_000,
            pinned_anchor_bytes: 0,
            current_focus_bytes: 100,
            retrieved_association_bytes: 0,
            recent_stream_bytes: 0,
            reserved_headroom_bytes: headroom,
        },
    })
    .expect("frame")
}

fn attestation(
    candidate: &SharedAttentionFrame,
    id: &str,
    participant_ref: &str,
    faculty: FacultyKind,
) -> FrameAttestation {
    finalize_frame_attestation(FrameAttestation {
        profile: FRAME_ATTESTATION_PROFILE.to_owned(),
        attestation_id: sid(id),
        participant_ref: sid(participant_ref),
        faculty,
        candidate_generation: candidate.generation,
        candidate_frame_digest: candidate.frame_digest.clone(),
        disposition: AttestationDisposition::Acknowledge,
        rationale: format!("{faculty:?} accepted exact candidate digest"),
        evidence_refs: BTreeSet::new(),
        attestation_digest: ContentDigest {
            algorithm: "sha256".to_owned(),
            value: String::new(),
        },
    })
    .expect("attestation")
}

fn delta(base: &SharedAttentionFrame) -> AttentionFrameDelta {
    finalize_attention_delta(AttentionFrameDelta {
        profile: ATTENTION_DELTA_PROFILE.to_owned(),
        delta_id: sid("delta:cli-fixture"),
        author_ref: sid("participant:guard"),
        policy_ref: base.policy_ref.clone(),
        base_generation: base.generation,
        base_frame_digest: base.frame_digest.clone(),
        logical_time: 1,
        operations: vec![FrameDeltaOperation::AttachEvidence {
            evidence_ref: sid("evidence:cli-fixture"),
        }],
        causal_predecessor_refs: BTreeSet::new(),
        delta_digest: ContentDigest {
            algorithm: "sha256".to_owned(),
            value: String::new(),
        },
    })
    .expect("delta")
}

fn compaction(base: &SharedAttentionFrame) -> AttentionCompaction {
    finalize_attention_compaction(AttentionCompaction {
        profile: ATTENTION_COMPACTION_PROFILE.to_owned(),
        compaction_id: sid("compaction:cli-fixture"),
        actor_ref: sid("participant:server"),
        policy_ref: base.policy_ref.clone(),
        base_generation: base.generation,
        base_frame_digest: base.frame_digest.clone(),
        retained_focus_refs: BTreeSet::new(),
        current_focus_bytes_after: 0,
        retrieved_association_bytes_after: 0,
        recent_stream_bytes_after: 0,
        rationale: "release completed focus".to_owned(),
        evidence_refs: BTreeSet::from([sid("evidence:cli-compaction")]),
        compaction_digest: ContentDigest {
            algorithm: "sha256".to_owned(),
            value: String::new(),
        },
    })
    .expect("compaction")
}

fn run(value: &serde_json::Value) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_cantor-shared-attention"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn CLI");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(
            serde_json::to_string(value)
                .expect("request JSON")
                .as_bytes(),
        )
        .expect("write request");
    child.wait_with_output().expect("CLI output")
}

fn output_json(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).expect("response JSON")
}

#[test]
fn validate_frame_round_trip_is_successful_and_preserves_nonclaims() {
    let base = frame(1_000_000);
    let output = run(&serde_json::json!({
        "operation": "validate_frame",
        "frame": base,
    }));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response = output_json(&output);
    assert_eq!(response["profile"], "cantor-shared-attention-cli/0.1");
    assert_eq!(response["status"], "succeeded");
    assert_eq!(response["operation"], "validate_frame");
    assert_eq!(response["result"]["frame_id"], "frame:cli-fixture");
    assert_eq!(
        response["nonclaims"].as_array().expect("nonclaims").len(),
        3
    );
}

#[test]
fn reconciliation_and_backpressure_are_distinct_successful_transport_results() {
    let roomy = frame(1_000_000);
    let output = run(&serde_json::json!({
        "operation": "reconcile",
        "base": roomy,
        "deltas": [delta(&roomy)],
    }));
    assert!(output.status.success());
    let response = output_json(&output);
    assert_eq!(response["status"], "succeeded");
    assert_eq!(response["result"]["disposition"], "applied");
    assert_eq!(response["result"]["successor"]["generation"], 1);

    let constrained = frame(1);
    let output = run(&serde_json::json!({
        "operation": "reconcile",
        "base": constrained,
        "deltas": [delta(&constrained)],
    }));
    assert!(output.status.success());
    let response = output_json(&output);
    assert_eq!(response["status"], "buffered");
    assert_eq!(response["result"]["disposition"], "buffered");
    assert!(response["result"]["successor"].is_null());
}

#[test]
fn stale_delta_is_a_domain_refusal_with_no_result() {
    let base = frame(1_000_000);
    let mut incoming = delta(&base);
    incoming.base_generation += 1;
    incoming = finalize_attention_delta(incoming).expect("resign stale delta");
    let output = run(&serde_json::json!({
        "operation": "reconcile",
        "base": base,
        "deltas": [incoming],
    }));
    assert_eq!(output.status.code(), Some(3));
    let response = output_json(&output);
    assert_eq!(response["status"], "refused");
    assert_eq!(response["fault"]["code"], "stale_base");
    assert!(response["result"].is_null());
}

#[test]
fn unknown_request_field_is_rejected_before_runtime_execution() {
    let output = run(&serde_json::json!({
        "operation": "validate_frame",
        "frame": frame(1_000_000),
        "invented_authority": true,
    }));
    assert_eq!(output.status.code(), Some(2));
    let response = output_json(&output);
    assert_eq!(response["status"], "invalid_request");
    assert_eq!(response["fault"]["code"], "malformed_request");
    assert!(response["result"].is_null());
}

#[test]
fn cli_transport_is_exactly_shared_dispatch_equivalent() {
    let roomy = frame(1_000_000);
    let constrained = frame(1);
    let mut stale = delta(&roomy);
    stale.base_generation += 1;
    stale = finalize_attention_delta(stale).expect("resign stale fixture");
    let requests = vec![
        SharedAttentionToolRequest::ValidateFrame {
            frame: roomy.clone(),
        },
        SharedAttentionToolRequest::Reconcile {
            base: roomy.clone(),
            deltas: vec![delta(&roomy)],
        },
        SharedAttentionToolRequest::Reconcile {
            base: constrained.clone(),
            deltas: vec![delta(&constrained)],
        },
        SharedAttentionToolRequest::Reconcile {
            base: roomy,
            deltas: vec![stale],
        },
    ];

    for request in requests {
        let expected = serde_json::to_value(execute_shared_attention_tool_request(request.clone()))
            .expect("direct response JSON");
        let request_json = serde_json::to_value(request).expect("request JSON");
        let actual = output_json(&run(&request_json));
        assert_eq!(actual, expected);
    }
}

#[test]
fn complete_frame_cycle_reenters_each_cli_result_as_the_next_request() {
    let base = frame(1_000_000);
    let incoming = delta(&base);
    let reconcile_output = run(&serde_json::json!({
        "operation": "reconcile",
        "base": base,
        "deltas": [incoming],
    }));
    assert!(reconcile_output.status.success());
    let reconciliation = output_json(&reconcile_output);
    let working: SharedAttentionFrame =
        serde_json::from_value(reconciliation["result"]["successor"].clone())
            .expect("working successor");

    let prepare_output = run(&serde_json::json!({
        "operation": "prepare",
        "working": working,
    }));
    assert!(prepare_output.status.success());
    let preparation = output_json(&prepare_output);
    let candidate: SharedAttentionFrame =
        serde_json::from_value(preparation["result"]["candidate"].clone()).expect("candidate");
    let attestations = vec![
        attestation(
            &candidate,
            "attestation:cli-honesty",
            "participant:guard",
            FacultyKind::Honesty,
        ),
        attestation(
            &candidate,
            "attestation:cli-security",
            "participant:guard",
            FacultyKind::Security,
        ),
        attestation(
            &candidate,
            "attestation:cli-planner",
            "participant:projection",
            FacultyKind::Planner,
        ),
        attestation(
            &candidate,
            "attestation:cli-observer",
            "participant:server",
            FacultyKind::Observer,
        ),
    ];
    let settle_output = run(&serde_json::json!({
        "operation": "settle",
        "candidate": candidate,
        "attestations": attestations,
    }));
    assert!(settle_output.status.success());
    let settlement = output_json(&settle_output);
    assert_eq!(settlement["result"]["disposition"], "sealed");
    assert_eq!(settlement["result"]["sealed_frame"]["status"], "sealed");
    assert_eq!(
        settlement["result"]["sealed_frame"]["settlement_attestation_refs"]
            .as_array()
            .expect("attestation lineage")
            .len(),
        4
    );
}

#[test]
fn buffered_cli_work_can_compact_then_resume_on_the_new_digest() {
    let base = frame(1);
    let original_delta = delta(&base);
    let buffered_output = run(&serde_json::json!({
        "operation": "reconcile",
        "base": base,
        "deltas": [original_delta],
    }));
    let buffered = output_json(&buffered_output);
    assert_eq!(buffered["status"], "buffered");

    let compact_output = run(&serde_json::json!({
        "operation": "compact",
        "base": base,
        "compaction": compaction(&base),
    }));
    assert!(compact_output.status.success());
    let compacted = output_json(&compact_output);
    assert_eq!(compacted["status"], "succeeded");
    let successor: SharedAttentionFrame =
        serde_json::from_value(compacted["result"]["successor"].clone())
            .expect("compacted successor");
    assert!(successor.capacity.reserved_headroom_bytes > 1);

    let rebound = delta(&successor);
    let resumed_output = run(&serde_json::json!({
        "operation": "reconcile",
        "base": successor,
        "deltas": [rebound],
    }));
    assert!(resumed_output.status.success());
    let resumed = output_json(&resumed_output);
    assert_eq!(resumed["status"], "succeeded");
    assert_eq!(resumed["result"]["disposition"], "applied");
}
