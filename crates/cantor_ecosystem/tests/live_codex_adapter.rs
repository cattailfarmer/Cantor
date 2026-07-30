mod common;

use std::collections::BTreeSet;

use cantor_core::{ProtocolRequest, SemanticId, execute_protocol_request, sha256_digest};
use cantor_ecosystem::{
    CantorAdapter, CodexAdapter, CycleIdentityPlan, EcosystemFault, EcosystemFaultCode,
    LIVE_CODEX_PROFILE, LiveCandidatePayload, LiveCodexAdapter, LiveTurnDriver, LiveTurnEvidence,
    LiveTurnResult, run_supervised_mock_cycle,
};

#[derive(Clone)]
struct ScriptedDriver {
    expected_packet: SemanticId,
    environment: cantor_core::EmbeddedRuntimeEnvironment,
    candidate: LiveCandidatePayload,
    calls: u32,
}

impl LiveTurnDriver for ScriptedDriver {
    fn run_turn(
        &mut self,
        work_packet: &cantor_ecosystem::WorkPacket,
        request: &ProtocolRequest,
        _admitted_proof_refs: &BTreeSet<SemanticId>,
    ) -> Result<LiveTurnResult, EcosystemFault> {
        self.calls = self.calls.saturating_add(1);
        if self.calls != 1 || work_packet.work_packet_uuid != self.expected_packet {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::AdapterFault,
                "scripted_live_driver",
                "unexpected scripted invocation",
                vec![work_packet.work_packet_uuid.clone()],
            ));
        }
        let response = execute_protocol_request(&self.environment, request.clone());
        let candidate_message =
            serde_json::to_string(&self.candidate).expect("candidate message encoding");
        Ok(LiveTurnResult {
            request: request.clone(),
            evidence: LiveTurnEvidence {
                profile: LIVE_CODEX_PROFILE.to_owned(),
                codex_executable_sha256: "11".repeat(32),
                codex_version: "codex-cli test".to_owned(),
                cantor_mcp_executable_sha256: "22".repeat(32),
                environment_file_sha256: "33".repeat(32),
                thread_id: "thread-test".to_owned(),
                turn_id: "turn-test".to_owned(),
                event_count: 7,
                received_bytes: 4096,
                mcp_call_id: "call-test".to_owned(),
                mcp_server_name: "cantor".to_owned(),
                mcp_tool_name: "query_sop".to_owned(),
                request_digest: sha256_digest(request).expect("request digest"),
                response_digest: sha256_digest(&response).expect("response digest"),
                candidate_payload_digest: cantor_core::sha256_bytes(candidate_message.as_bytes()),
                advisories: Vec::new(),
            },
            response,
            candidate: self.candidate.clone(),
            candidate_message,
        })
    }
}

fn candidate() -> LiveCandidatePayload {
    LiveCandidatePayload {
        summary: "the pinned live exchange satisfied both criteria".to_owned(),
        satisfied_criterion_ids: [
            common::id("criterion:protocol"),
            common::id("criterion:no_effect"),
        ]
        .into_iter()
        .collect(),
        proof_refs: [common::id("proof:required")].into_iter().collect(),
        requested_effects: BTreeSet::new(),
    }
}

#[test]
fn live_adapter_bridges_one_physical_turn_into_the_supervised_cycle() {
    let environment = common::environment();
    let request = common::protocol_request(&environment);
    let commission = common::commission();
    let packet = common::work_packet(cantor_core::sha256_bytes(b"frame:fixture"));
    let driver = ScriptedDriver {
        expected_packet: packet.work_packet_uuid.clone(),
        environment,
        candidate: candidate(),
        calls: 0,
    };
    let (mut codex, mut cantor) = LiveCodexAdapter::new(
        packet.work_packet_uuid.clone(),
        request,
        commission.proof_obligation.clone(),
        driver,
    );

    let outcome = run_supervised_mock_cycle(
        commission,
        packet,
        &CycleIdentityPlan::new("cycle:live_test").expect("identity"),
        &mut codex,
        &mut cantor,
    )
    .expect("live bridge cycle");

    assert!(outcome.review.all_checks_passed());
    assert!(outcome.candidate.requested_effects.is_empty());
    assert_eq!(codex.call_count(), 2);
    assert_eq!(cantor.call_count(), 1);
    let evidence = codex.evidence().expect("live evidence");
    assert_eq!(evidence.mcp_server_name, "cantor");
    assert_eq!(evidence.mcp_tool_name, "query_sop");
}

#[test]
fn live_adapter_rejects_a_candidate_effect_before_observer_review() {
    let environment = common::environment();
    let request = common::protocol_request(&environment);
    let packet = common::work_packet(cantor_core::sha256_bytes(b"frame:fixture"));
    let mut payload = candidate();
    payload.requested_effects.insert("write_file".to_owned());
    let driver = ScriptedDriver {
        expected_packet: packet.work_packet_uuid.clone(),
        environment,
        candidate: payload,
        calls: 0,
    };
    let (mut codex, _cantor) = LiveCodexAdapter::new(
        packet.work_packet_uuid.clone(),
        request,
        common::commission().proof_obligation,
        driver,
    );

    let fault = codex
        .accept_assignment(&packet)
        .expect_err("effect request must fault");
    assert_eq!(fault.code, EcosystemFaultCode::AdapterFault);
    assert!(fault.message.contains("forbidden effect"));
}

#[test]
fn live_adapter_rejects_model_invented_proof_references() {
    let environment = common::environment();
    let request = common::protocol_request(&environment);
    let packet = common::work_packet(cantor_core::sha256_bytes(b"frame:fixture"));
    let mut payload = candidate();
    payload.proof_refs = [common::id("proof:invented")].into_iter().collect();
    let driver = ScriptedDriver {
        expected_packet: packet.work_packet_uuid.clone(),
        environment,
        candidate: payload,
        calls: 0,
    };
    let (mut codex, _cantor) = LiveCodexAdapter::new(
        packet.work_packet_uuid.clone(),
        request,
        common::commission().proof_obligation,
        driver,
    );

    let fault = codex
        .accept_assignment(&packet)
        .expect_err("invented proof must fault");
    assert_eq!(fault.code, EcosystemFaultCode::AdapterFault);
    assert!(fault.message.contains("supervisor-admitted"));
}

#[test]
fn observed_cantor_response_is_single_release_only() {
    let environment = common::environment();
    let request = common::protocol_request(&environment);
    let packet = common::work_packet(cantor_core::sha256_bytes(b"frame:fixture"));
    let driver = ScriptedDriver {
        expected_packet: packet.work_packet_uuid.clone(),
        environment,
        candidate: candidate(),
        calls: 0,
    };
    let (mut codex, mut cantor) = LiveCodexAdapter::new(
        packet.work_packet_uuid.clone(),
        request.clone(),
        common::commission().proof_obligation,
        driver,
    );

    let emitted = codex.accept_assignment(&packet).expect("assignment");
    assert_eq!(emitted, request);
    cantor.execute(&request).expect("first release");
    let fault = cantor
        .execute(&request)
        .expect_err("second release must fault");
    assert_eq!(fault.code, EcosystemFaultCode::AdapterFault);
}

#[test]
fn live_driver_cannot_substitute_a_different_request() {
    struct SubstitutingDriver(ScriptedDriver);
    impl LiveTurnDriver for SubstitutingDriver {
        fn run_turn(
            &mut self,
            work_packet: &cantor_ecosystem::WorkPacket,
            request: &ProtocolRequest,
            admitted_proof_refs: &BTreeSet<SemanticId>,
        ) -> Result<LiveTurnResult, EcosystemFault> {
            let mut result = self.0.run_turn(work_packet, request, admitted_proof_refs)?;
            result.request.request_id = common::id("request:substituted");
            Ok(result)
        }
    }

    let environment = common::environment();
    let request = common::protocol_request(&environment);
    let packet = common::work_packet(cantor_core::sha256_bytes(b"frame:fixture"));
    let driver = SubstitutingDriver(ScriptedDriver {
        expected_packet: packet.work_packet_uuid.clone(),
        environment,
        candidate: candidate(),
        calls: 0,
    });
    let (mut codex, _cantor) = LiveCodexAdapter::new(
        packet.work_packet_uuid.clone(),
        request,
        common::commission().proof_obligation,
        driver,
    );
    let fault = codex
        .accept_assignment(&packet)
        .expect_err("request substitution must fault");
    assert!(fault.message.contains("different protocol request"));
}
