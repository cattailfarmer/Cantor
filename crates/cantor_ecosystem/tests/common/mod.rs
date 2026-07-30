#![allow(dead_code)]

use std::collections::BTreeSet;

use cantor_core::{
    ContentDigest, EmbeddedRuntimeEnvironment, ExpectedPackage, InspectRequest,
    ProtocolCallerContext, ProtocolOperation, ProtocolRequest, RequestedDetailKind, SemanticId,
    SopCompilerIdentity, SopCorpusContext, SopCorpusManifest, SopDocumentInput,
    SopDocumentManifest, SopQueryTemplate, SopSigningKeys, build_sop_corpus,
    embedded_environment_digest, sha256_bytes,
};
use cantor_ecosystem::{
    AcceptanceCriterion, AuthorityGrant, CandidateArtifact, CommissionContract,
    CommissionLifecycle, CycleIdentityPlan, EcosystemBudget, EcosystemFault,
    EcosystemMessageEnvelope, ExpectedResponse, FunctionCantorAdapter, MESSAGE_PROFILE,
    MessageKind, MessagePayload, MessageTranscript, MockCodexAdapter, ParticipantAddress,
    ParticipantRole, ReviewCheckKind, WorkPacket, mandatory_review_checks,
    run_supervised_mock_cycle,
};

pub fn id(value: &str) -> SemanticId {
    SemanticId::new(value).expect("fixture identity")
}

pub fn address(role: ParticipantRole, value: &str) -> ParticipantAddress {
    ParticipantAddress::new(role, value).expect("fixture participant")
}

pub fn authority() -> AuthorityGrant {
    AuthorityGrant {
        projects: ["Cantor".to_owned()].into_iter().collect(),
        semantic_operations: ["inspect".to_owned()].into_iter().collect(),
        tool_capabilities: ["query_sop".to_owned()].into_iter().collect(),
        data_scopes: ["signed_corpus".to_owned()].into_iter().collect(),
        effect_classes: BTreeSet::new(),
    }
}

pub fn budget() -> EcosystemBudget {
    EcosystemBudget {
        maximum_messages: 16,
        maximum_serialized_bytes: 1_000_000,
        maximum_call_depth: 4,
        maximum_logical_ticks: 32,
    }
}

pub fn commission() -> CommissionContract {
    CommissionContract {
        profile: cantor_ecosystem::COMMISSION_PROFILE.to_owned(),
        commission_uuid: id("commission:fixture"),
        principal: address(ParticipantRole::Principal, "principal:user"),
        manager: address(ParticipantRole::Manager, "manager:shaliach"),
        purpose: "prove one effect-free supervised mock loop".to_owned(),
        requested_result: "one reviewed candidate and complete transcript".to_owned(),
        authority_grant: authority(),
        required_review_checks: mandatory_review_checks(),
        evidence_obligation: [id("evidence:source")].into_iter().collect(),
        proof_obligation: [id("proof:required")].into_iter().collect(),
        budget: budget(),
        activated_at_tick: 100,
        expires_at_tick: 200,
        lifecycle: CommissionLifecycle::Active,
    }
}

pub fn work_packet(frame_digest: ContentDigest) -> WorkPacket {
    WorkPacket {
        profile: cantor_ecosystem::WORK_PACKET_PROFILE.to_owned(),
        work_packet_uuid: id("work:fixture"),
        commission_uuid: id("commission:fixture"),
        worker: address(ParticipantRole::CodexThread, "codex:fixture"),
        cantor_participant: address(ParticipantRole::CantorParticipant, "cantor:fixture"),
        observer: address(ParticipantRole::Observer, "observer:fixture"),
        subject: "Cantor supervised mock loop".to_owned(),
        purpose: "return one proof-backed candidate".to_owned(),
        requested_result: "candidate with all criteria and no requested effects".to_owned(),
        acceptance_criteria: vec![
            AcceptanceCriterion {
                criterion_id: id("criterion:protocol"),
                description: "Cantor protocol response is verified".to_owned(),
            },
            AcceptanceCriterion {
                criterion_id: id("criterion:no_effect"),
                description: "candidate requests no exterior effect".to_owned(),
            },
        ],
        authority_grant: authority(),
        frame_digest,
        budget: budget(),
    }
}

pub fn environment() -> EmbeddedRuntimeEnvironment {
    let path = "fixture.sop";
    let manifest = SopCorpusManifest {
        corpus_version: cantor_core::SOP_CORPUS_PROFILE.to_owned(),
        source_root: ".".to_owned(),
        context: SopCorpusContext {
            project: "Cantor".to_owned(),
            namespace: "ecosystem_fixture".to_owned(),
            source_scope: "fixture".to_owned(),
            purpose: "prove supervised delegation".to_owned(),
            perspective: "test".to_owned(),
            world: "test/0.1".to_owned(),
        },
        compiler: SopCompilerIdentity {
            compiler_id: id("compiler:ecosystem_fixture"),
            compiler_version: "0.1.0".to_owned(),
            authority_signer_id: id("signer:ecosystem_authority"),
            compiler_signer_id: id("signer:ecosystem_compiler"),
        },
        dependency_lock: [("cantor-sop".to_owned(), "0.1".to_owned())]
            .into_iter()
            .collect(),
        proof_ids: vec!["proof:ecosystem_fixture".to_owned()],
        issued_at_epoch_seconds: 120,
        not_before_epoch_seconds: 100,
        not_after_epoch_seconds: 200,
        documents: vec![SopDocumentManifest {
            document_id: "ecosystem_fixture".to_owned(),
            path: path.to_owned(),
        }],
        queries: vec![SopQueryTemplate {
            name: "mock-loop".to_owned(),
            terms: ["SupervisedMockLoop".to_owned()].into_iter().collect(),
            subject: Some("SupervisedMockLoop".to_owned()),
            requested_detail_kinds: [RequestedDetailKind::Clause].into_iter().collect(),
        }],
    };
    let document = SopDocumentInput {
        document_id: "ecosystem_fixture".to_owned(),
        path: path.to_owned(),
        bytes:
            b"Subject: Fixture\n\n& [SupervisedMockLoop] is effect-free\n  = must: preserve proof\n"
                .to_vec(),
    };
    build_sop_corpus(
        &manifest,
        vec![document],
        SopSigningKeys {
            authority: ed25519_dalek::SigningKey::from_bytes(&[7_u8; 32]),
            compiler: ed25519_dalek::SigningKey::from_bytes(&[9_u8; 32]),
        },
    )
    .expect("fixture corpus")
    .environment
}

pub fn protocol_request(environment: &EmbeddedRuntimeEnvironment) -> ProtocolRequest {
    let package = environment.packages.first().expect("fixture package");
    ProtocolRequest {
        protocol_version: cantor_core::PROTOCOL_VERSION.to_owned(),
        request_id: id("request:fixture"),
        caller_context: ProtocolCallerContext {
            caller_id: id("codex:fixture"),
            purpose: "inspect the admitted fabric".to_owned(),
            job_id: Some(id("work:fixture")),
            effect_boundary: "read_only".to_owned(),
        },
        expected_environment_digest: embedded_environment_digest(environment)
            .expect("fixture environment digest"),
        expected_packages: vec![ExpectedPackage {
            package_id: package.package_id.clone(),
            package_digest: package
                .certificate
                .as_ref()
                .expect("fixture package is signed")
                .package_digest
                .clone(),
        }],
        requested_scope: package.content.declared_scope.clone(),
        request: ProtocolOperation::Inspect {
            inspect: InspectRequest::Fabric,
        },
    }
}

pub fn candidate() -> CandidateArtifact {
    CandidateArtifact {
        candidate_uuid: id("candidate:fixture"),
        content_digest: sha256_bytes(b"deterministic candidate"),
        summary: "verified candidate without effects".to_owned(),
        satisfied_criterion_ids: [id("criterion:protocol"), id("criterion:no_effect")]
            .into_iter()
            .collect(),
        proof_refs: [id("proof:required")].into_iter().collect(),
        requested_effects: BTreeSet::new(),
    }
}

pub fn run(
    mut commission: CommissionContract,
    mut packet: WorkPacket,
    candidate: CandidateArtifact,
) -> Result<cantor_ecosystem::CycleOutcome, Box<cantor_ecosystem::CycleFailure>> {
    let environment = environment();
    let request = protocol_request(&environment);
    packet.frame_digest = sha256_bytes(b"frame:fixture");
    commission.authority_grant = authority();
    let mut codex =
        MockCodexAdapter::new(packet.work_packet_uuid.clone(), request.clone(), candidate);
    let mut cantor = FunctionCantorAdapter::new(move |request: &ProtocolRequest| {
        Ok(cantor_core::execute_protocol_request(
            &environment,
            request.clone(),
        ))
    });
    run_supervised_mock_cycle(
        commission,
        packet,
        &CycleIdentityPlan::new("cycle:fixture").expect("fixture cycle identity"),
        &mut codex,
        &mut cantor,
    )
}

pub fn standard_fixture() -> (CommissionContract, WorkPacket, CandidateArtifact) {
    let frame = sha256_bytes(b"frame:fixture");
    (commission(), work_packet(frame), candidate())
}

pub fn root_envelope(
    commission: &CommissionContract,
    packet: &WorkPacket,
) -> EcosystemMessageEnvelope {
    EcosystemMessageEnvelope {
        profile: MESSAGE_PROFILE.to_owned(),
        message_uuid: id("message:root"),
        causation_uuid: None,
        correlation_uuid: commission.commission_uuid.clone(),
        sender: commission.principal.clone(),
        recipient: commission.manager.clone(),
        message_kind: MessageKind::Commission,
        subject: packet.subject.clone(),
        frame_digest: packet.frame_digest.clone(),
        authority_scope: commission.authority_grant.clone(),
        payload: MessagePayload::Commission(Box::new(commission.clone())),
        proof_refs: commission.evidence_obligation.clone(),
        expected_response: Some(ExpectedResponse {
            message_kind: MessageKind::Assignment,
            deadline_tick: 102,
            stop_condition: "stop on fault".to_owned(),
        }),
        idempotency_key: id("idempotency:root"),
        logical_tick: 101,
        call_depth: 0,
    }
}

pub fn assignment_envelope(
    commission: &CommissionContract,
    packet: &WorkPacket,
) -> EcosystemMessageEnvelope {
    EcosystemMessageEnvelope {
        profile: MESSAGE_PROFILE.to_owned(),
        message_uuid: id("message:assignment"),
        causation_uuid: Some(id("message:root")),
        correlation_uuid: commission.commission_uuid.clone(),
        sender: commission.manager.clone(),
        recipient: packet.worker.clone(),
        message_kind: MessageKind::Assignment,
        subject: packet.subject.clone(),
        frame_digest: packet.frame_digest.clone(),
        authority_scope: packet.authority_grant.clone(),
        payload: MessagePayload::Assignment(Box::new(packet.clone())),
        proof_refs: commission.evidence_obligation.clone(),
        expected_response: Some(ExpectedResponse {
            message_kind: MessageKind::CantorQuery,
            deadline_tick: 103,
            stop_condition: "stop on fault".to_owned(),
        }),
        idempotency_key: id("idempotency:assignment"),
        logical_tick: 102,
        call_depth: 1,
    }
}

pub fn transcript(commission: &CommissionContract, packet: &WorkPacket) -> MessageTranscript {
    MessageTranscript::new(commission.clone(), packet.clone(), 100).expect("fixture transcript")
}

pub fn assert_fault(fault: &EcosystemFault, expected: cantor_ecosystem::EcosystemFaultCode) {
    assert_eq!(fault.code, expected, "{fault}");
}

pub fn required_checks() -> BTreeSet<ReviewCheckKind> {
    mandatory_review_checks()
}
