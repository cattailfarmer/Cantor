//! Crate-private affine bridge from a future live admission to the sealed EVO-X2 preflight runner.
//!
//! No production constructor exists for `Evox2RemotePreflightLiveAdmission`, so the production
//! entry remains structurally unreachable. A separately governed nested live-initiation module
//! may add the sole constructor later. This module has no clock, key, environment, filesystem,
//! process, provider, remote, persistence, retry, or public-export surface of its own.

use cantor_core::{
    Evox2ScratchBuildControllerPlan, Evox2ScratchBuildControllerRequest,
    Evox2ScratchBuildEffectProgram, Evox2ScratchBuildRemotePreflightProducerPlan,
};

use crate::evox2_remote_preflight_one_shot_activation_ceremony::{
    Evox2RemotePreflightActivationProposal, Evox2RemotePreflightActivationProposalVerification,
    Evox2RemotePreflightActivationRequest, Evox2RemotePreflightDecisionCorrespondence,
    Evox2RemotePreflightOperatorDecision, Evox2RemotePreflightOperatorDecisionKind,
    verify_evox2_remote_preflight_activation_proposal,
    verify_evox2_remote_preflight_operator_decision_correspondence,
};
use crate::evox2_scratch_build_remote_preflight_runner::{
    Evox2ScratchBuildRemotePreflightRun, Evox2ScratchBuildRemotePreflightRunnerFault,
    Evox2ScratchBuildRemotePreflightRunnerFaultCode,
    Evox2ScratchBuildRemotePreflightSingleUsePermit,
    from_evox2_scratch_build_remote_preflight_run_machine_form,
    issue_evox2_scratch_build_remote_preflight_single_use_permit,
    run_evox2_scratch_build_remote_preflight_once,
    to_evox2_scratch_build_remote_preflight_run_machine_form,
    validate_evox2_scratch_build_remote_preflight_run,
};

const BRIDGE_CANONICAL_UUID: &str = "06d82d16-143a-4abb-9c70-c03163285842";
const BRIDGE_SIGNATURE_UUID: &str = "3f7d776d-e012-4efc-9426-d40cf6af7fcb";
const BRIDGE_FORMATION_COMMIT: &str = "001c75ad761d6890c29db793d6d133bdcca037b8";
const BRIDGE_FORMATION_BOOKEND: &str = "d76d0fe0086c8b7b5fab20fbda444524d071d126";
const ACTIVATION_IMPLEMENTATION_COMMIT: &str = "2726ea188b93e70ab8da48d77ec7c43278b64238";
const ACTIVATION_IMPLEMENTATION_BOOKEND: &str = "80f2ef9f6eed3c797b911ba3c7f45e8d28130841";
const RUNNER_IMPLEMENTATION_COMMIT: &str = "0eb334670d825ea7123beb445df1a47e1bc81349";
const RUNNER_IMPLEMENTATION_BOOKEND: &str = "0674395c78a998ce1c36c714e52bae68d0f83f58";

pub(crate) struct Evox2RemotePreflightLiveAdmission {
    bridge_canonical_uuid: String,
    bridge_signature_uuid: String,
    bridge_formation_commit: String,
    bridge_formation_bookend: String,
    activation_implementation_commit: String,
    activation_implementation_bookend: String,
    runner_implementation_commit: String,
    runner_implementation_bookend: String,
    request_sha256: String,
    proposal_sha256: String,
    proposal_verification_sha256: String,
    decision_sha256: String,
    correspondence_sha256: String,
    producer_plan_sha256: String,
    observed_time_ms: u64,
    decision: Evox2RemotePreflightOperatorDecisionKind,
    maximum_attempts: u8,
    maximum_permits: u8,
    maximum_runner_entries: u8,
    maximum_processes: u8,
    retry_count: u8,
    fixture_only: bool,
}

impl Evox2RemotePreflightLiveAdmission {
    fn validates_against(
        &self,
        request: &Evox2RemotePreflightActivationRequest,
        proposal: &Evox2RemotePreflightActivationProposal,
        proposal_verification: &Evox2RemotePreflightActivationProposalVerification,
        decision: &Evox2RemotePreflightOperatorDecision,
        correspondence: &Evox2RemotePreflightDecisionCorrespondence,
        producer_plan: &Evox2ScratchBuildRemotePreflightProducerPlan,
    ) -> bool {
        self.bridge_canonical_uuid == BRIDGE_CANONICAL_UUID
            && self.bridge_signature_uuid == BRIDGE_SIGNATURE_UUID
            && self.bridge_formation_commit == BRIDGE_FORMATION_COMMIT
            && self.bridge_formation_bookend == BRIDGE_FORMATION_BOOKEND
            && self.activation_implementation_commit == ACTIVATION_IMPLEMENTATION_COMMIT
            && self.activation_implementation_bookend == ACTIVATION_IMPLEMENTATION_BOOKEND
            && self.runner_implementation_commit == RUNNER_IMPLEMENTATION_COMMIT
            && self.runner_implementation_bookend == RUNNER_IMPLEMENTATION_BOOKEND
            && self.request_sha256 == request.request_sha256
            && self.proposal_sha256 == proposal.proposal_sha256
            && self.proposal_verification_sha256
                == proposal_verification.proposal_verification_sha256
            && self.decision_sha256 == decision.decision_sha256
            && self.correspondence_sha256 == correspondence.correspondence_sha256
            && self.producer_plan_sha256 == producer_plan.producer_plan_sha256
            && self.observed_time_ms == correspondence.observed_time_ms
            && self.decision == Evox2RemotePreflightOperatorDecisionKind::Authorize
            && self.decision == decision.decision
            && self.decision == correspondence.decision
            && self.maximum_attempts == 1
            && self.maximum_permits == 1
            && self.maximum_runner_entries == 1
            && self.maximum_processes == 1
            && self.retry_count == 0
            && !self.fixture_only
            && !request.fixture_only
            && !proposal.fixture_only
            && !proposal_verification.fixture_only
            && !decision.fixture_only
            && !correspondence.fixture_only
    }

    pub(crate) fn consume_for_runner_permit(
        self,
        producer_plan: &Evox2ScratchBuildRemotePreflightProducerPlan,
    ) -> Result<(), ()> {
        if self.bridge_canonical_uuid == BRIDGE_CANONICAL_UUID
            && self.bridge_signature_uuid == BRIDGE_SIGNATURE_UUID
            && self.bridge_formation_commit == BRIDGE_FORMATION_COMMIT
            && self.bridge_formation_bookend == BRIDGE_FORMATION_BOOKEND
            && self.activation_implementation_commit == ACTIVATION_IMPLEMENTATION_COMMIT
            && self.activation_implementation_bookend == ACTIVATION_IMPLEMENTATION_BOOKEND
            && self.runner_implementation_commit == RUNNER_IMPLEMENTATION_COMMIT
            && self.runner_implementation_bookend == RUNNER_IMPLEMENTATION_BOOKEND
            && self.producer_plan_sha256 == producer_plan.producer_plan_sha256
            && self.decision == Evox2RemotePreflightOperatorDecisionKind::Authorize
            && self.maximum_attempts == 1
            && self.maximum_permits == 1
            && self.maximum_runner_entries == 1
            && self.maximum_processes == 1
            && self.retry_count == 0
            && !self.fixture_only
        {
            Ok(())
        } else {
            Err(())
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Evox2RemotePreflightPrivatePermitBridgeDisposition {
    CompletedAvailable,
    CompletedProviderUnavailable,
    AbandonedAfterConsumption,
    ReceiptRefused,
}

#[derive(Debug)]
pub(crate) struct Evox2RemotePreflightPrivatePermitBridgeTerminal {
    disposition: Evox2RemotePreflightPrivatePermitBridgeDisposition,
    permit_consumed: bool,
    runner_invocations: u8,
    effect_account_observed: bool,
    provider_requests: Option<u32>,
    remote_calls: Option<u32>,
    effects: Option<u32>,
    validated_run: Option<Evox2ScratchBuildRemotePreflightRun>,
    runner_fault: Option<Evox2ScratchBuildRemotePreflightRunnerFaultCode>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Evox2RemotePreflightPrivatePermitBridgeFaultCode {
    Activation,
    Admission,
    Issuance,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Evox2RemotePreflightPrivatePermitBridgeFault {
    code: Evox2RemotePreflightPrivatePermitBridgeFaultCode,
    detail: &'static str,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_evox2_remote_preflight_private_permit_bridge_once(
    admission: Evox2RemotePreflightLiveAdmission,
    activation_request: &Evox2RemotePreflightActivationRequest,
    proposal: &Evox2RemotePreflightActivationProposal,
    proposal_verification: &Evox2RemotePreflightActivationProposalVerification,
    decision: &Evox2RemotePreflightOperatorDecision,
    correspondence: &Evox2RemotePreflightDecisionCorrespondence,
    controller_request: &Evox2ScratchBuildControllerRequest,
    controller_plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
    producer_plan: &Evox2ScratchBuildRemotePreflightProducerPlan,
) -> Result<
    Evox2RemotePreflightPrivatePermitBridgeTerminal,
    Evox2RemotePreflightPrivatePermitBridgeFault,
> {
    run_private_bridge_with(
        admission,
        activation_request,
        proposal,
        proposal_verification,
        decision,
        correspondence,
        controller_request,
        controller_plan,
        program,
        producer_plan,
        |permit| {
            run_evox2_scratch_build_remote_preflight_once(
                permit,
                controller_request,
                controller_plan,
                program,
                producer_plan,
            )
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn run_private_bridge_with<R>(
    admission: Evox2RemotePreflightLiveAdmission,
    activation_request: &Evox2RemotePreflightActivationRequest,
    proposal: &Evox2RemotePreflightActivationProposal,
    proposal_verification: &Evox2RemotePreflightActivationProposalVerification,
    decision: &Evox2RemotePreflightOperatorDecision,
    correspondence: &Evox2RemotePreflightDecisionCorrespondence,
    controller_request: &Evox2ScratchBuildControllerRequest,
    controller_plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
    producer_plan: &Evox2ScratchBuildRemotePreflightProducerPlan,
    runner: R,
) -> Result<
    Evox2RemotePreflightPrivatePermitBridgeTerminal,
    Evox2RemotePreflightPrivatePermitBridgeFault,
>
where
    R: FnOnce(
        Evox2ScratchBuildRemotePreflightSingleUsePermit,
    ) -> Result<
        Evox2ScratchBuildRemotePreflightRun,
        Evox2ScratchBuildRemotePreflightRunnerFault,
    >,
{
    validate_before_issuance(
        &admission,
        activation_request,
        proposal,
        proposal_verification,
        decision,
        correspondence,
        controller_request,
        controller_plan,
        program,
        producer_plan,
    )?;
    let permit =
        issue_evox2_scratch_build_remote_preflight_single_use_permit(admission, producer_plan)
            .map_err(|_| {
                bridge_fault(
                    Evox2RemotePreflightPrivatePermitBridgeFaultCode::Issuance,
                    "runner permit issuance refused",
                )
            })?;
    let returned = match runner(permit) {
        Ok(run) => run,
        Err(fault) => {
            return Ok(Evox2RemotePreflightPrivatePermitBridgeTerminal {
                disposition:
                    Evox2RemotePreflightPrivatePermitBridgeDisposition::AbandonedAfterConsumption,
                permit_consumed: true,
                runner_invocations: 1,
                effect_account_observed: false,
                provider_requests: None,
                remote_calls: None,
                effects: None,
                validated_run: None,
                runner_fault: Some(fault.code),
            });
        }
    };
    let machine_form = match to_evox2_scratch_build_remote_preflight_run_machine_form(
        controller_request,
        controller_plan,
        program,
        producer_plan,
        &returned,
    ) {
        Ok(value) => value,
        Err(_) => return Ok(receipt_refused()),
    };
    let reparsed = match from_evox2_scratch_build_remote_preflight_run_machine_form(
        controller_request,
        controller_plan,
        program,
        producer_plan,
        &machine_form,
    ) {
        Ok(value) => value,
        Err(_) => return Ok(receipt_refused()),
    };
    if validate_evox2_scratch_build_remote_preflight_run(
        controller_request,
        controller_plan,
        program,
        producer_plan,
        &reparsed,
    )
    .is_err()
        || to_evox2_scratch_build_remote_preflight_run_machine_form(
            controller_request,
            controller_plan,
            program,
            producer_plan,
            &reparsed,
        )
        .ok()
        .as_deref()
            != Some(machine_form.as_str())
    {
        return Ok(receipt_refused());
    }
    let disposition = match reparsed.observation.probe.provider_status.as_str() {
        "available" => Evox2RemotePreflightPrivatePermitBridgeDisposition::CompletedAvailable,
        "unavailable" => {
            Evox2RemotePreflightPrivatePermitBridgeDisposition::CompletedProviderUnavailable
        }
        _ => return Ok(receipt_refused()),
    };
    Ok(Evox2RemotePreflightPrivatePermitBridgeTerminal {
        disposition,
        permit_consumed: true,
        runner_invocations: 1,
        effect_account_observed: true,
        provider_requests: Some(reparsed.provider_requests),
        remote_calls: Some(reparsed.remote_calls),
        effects: Some(reparsed.effects),
        validated_run: Some(reparsed),
        runner_fault: None,
    })
}

#[allow(clippy::too_many_arguments)]
fn validate_before_issuance(
    admission: &Evox2RemotePreflightLiveAdmission,
    activation_request: &Evox2RemotePreflightActivationRequest,
    proposal: &Evox2RemotePreflightActivationProposal,
    proposal_verification: &Evox2RemotePreflightActivationProposalVerification,
    decision: &Evox2RemotePreflightOperatorDecision,
    correspondence: &Evox2RemotePreflightDecisionCorrespondence,
    controller_request: &Evox2ScratchBuildControllerRequest,
    controller_plan: &Evox2ScratchBuildControllerPlan,
    program: &Evox2ScratchBuildEffectProgram,
    producer_plan: &Evox2ScratchBuildRemotePreflightProducerPlan,
) -> Result<(), Evox2RemotePreflightPrivatePermitBridgeFault> {
    let rebuilt_proposal_verification = verify_evox2_remote_preflight_activation_proposal(
        activation_request,
        controller_request,
        controller_plan,
        program,
        producer_plan,
        proposal,
    )
    .map_err(|_| {
        bridge_fault(
            Evox2RemotePreflightPrivatePermitBridgeFaultCode::Activation,
            "activation proposal replay refused",
        )
    })?;
    if &rebuilt_proposal_verification != proposal_verification {
        return Err(bridge_fault(
            Evox2RemotePreflightPrivatePermitBridgeFaultCode::Activation,
            "activation proposal verification differs",
        ));
    }
    let rebuilt_correspondence = verify_evox2_remote_preflight_operator_decision_correspondence(
        proposal,
        decision,
        correspondence.observed_time_ms,
    )
    .map_err(|_| {
        bridge_fault(
            Evox2RemotePreflightPrivatePermitBridgeFaultCode::Activation,
            "decision correspondence replay refused",
        )
    })?;
    if &rebuilt_correspondence != correspondence
        || decision.decision != Evox2RemotePreflightOperatorDecisionKind::Authorize
        || !admission.validates_against(
            activation_request,
            proposal,
            proposal_verification,
            decision,
            correspondence,
            producer_plan,
        )
    {
        return Err(bridge_fault(
            Evox2RemotePreflightPrivatePermitBridgeFaultCode::Admission,
            "live admission scope or authority differs",
        ));
    }
    Ok(())
}

fn receipt_refused() -> Evox2RemotePreflightPrivatePermitBridgeTerminal {
    Evox2RemotePreflightPrivatePermitBridgeTerminal {
        disposition: Evox2RemotePreflightPrivatePermitBridgeDisposition::ReceiptRefused,
        permit_consumed: true,
        runner_invocations: 1,
        effect_account_observed: false,
        provider_requests: None,
        remote_calls: None,
        effects: None,
        validated_run: None,
        runner_fault: None,
    }
}

fn bridge_fault(
    code: Evox2RemotePreflightPrivatePermitBridgeFaultCode,
    detail: &'static str,
) -> Evox2RemotePreflightPrivatePermitBridgeFault {
    Evox2RemotePreflightPrivatePermitBridgeFault { code, detail }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use cantor_core::{
        EVOX2_SCRATCH_BUILD_REMOTE_PROBE_RESULT_PROFILE, Evox2ScratchBuildRemoteProbeResult,
        seal_evox2_scratch_build_remote_probe_result,
        to_evox2_scratch_build_remote_probe_result_machine_form,
    };
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;
    use crate::evox2_remote_preflight_one_shot_activation_ceremony::{
        activation_request_digest, canonical_evox2_remote_preflight_activation_request,
        compile_evox2_remote_preflight_activation_proposal,
        evox2_remote_preflight_operator_decision_signing_bytes,
        seal_evox2_remote_preflight_operator_decision_digest,
    };
    use crate::evox2_scratch_build_remote_preflight_runner::{
        Evox2ScratchBuildRemotePreflightContainedProcessObservation,
        run_evox2_scratch_build_remote_preflight_with_supplied_observation_for_private_bridge_test,
    };

    const REQUEST: &str = include_str!(
        "../../../experiments/evox2_scratch_build_executor_p0/controller_fixture/request.json"
    );
    const PLAN: &str = include_str!(
        "../../../experiments/evox2_scratch_build_executor_p0/controller_fixture/plan.json"
    );
    const PROGRAM: &str = include_str!(
        "../../../experiments/evox2_scratch_build_executor_p0/effect_wrapper_fixture/program.json"
    );
    const PRODUCER_PLAN: &str = include_str!(
        "../../../experiments/evox2_scratch_build_executor_p0/preflight_producer_fixture/producer_plan.json"
    );

    struct Fixture {
        controller_request: Evox2ScratchBuildControllerRequest,
        controller_plan: Evox2ScratchBuildControllerPlan,
        program: Evox2ScratchBuildEffectProgram,
        producer_plan: Evox2ScratchBuildRemotePreflightProducerPlan,
        activation_request: Evox2RemotePreflightActivationRequest,
        proposal: Evox2RemotePreflightActivationProposal,
        proposal_verification: Evox2RemotePreflightActivationProposalVerification,
        decision: Evox2RemotePreflightOperatorDecision,
        correspondence: Evox2RemotePreflightDecisionCorrespondence,
    }

    fn fixture(decision_kind: Evox2RemotePreflightOperatorDecisionKind) -> Fixture {
        let controller_request = serde_json::from_str(REQUEST).unwrap();
        let controller_plan = serde_json::from_str(PLAN).unwrap();
        let program = serde_json::from_str(PROGRAM).unwrap();
        let producer_plan = serde_json::from_str(PRODUCER_PLAN).unwrap();
        let mut activation_request = canonical_evox2_remote_preflight_activation_request().unwrap();
        activation_request.fixture_only = false;
        activation_request.request_sha256.clear();
        activation_request.request_sha256 = activation_request_digest(&activation_request).unwrap();
        let proposal = compile_evox2_remote_preflight_activation_proposal(
            &activation_request,
            &controller_request,
            &controller_plan,
            &program,
            &producer_plan,
        )
        .unwrap();
        let proposal_verification = verify_evox2_remote_preflight_activation_proposal(
            &activation_request,
            &controller_request,
            &controller_plan,
            &program,
            &producer_plan,
            &proposal,
        )
        .unwrap();
        let decision = signed_decision(&proposal, decision_kind);
        let correspondence = verify_evox2_remote_preflight_operator_decision_correspondence(
            &proposal,
            &decision,
            decision.issued_at_ms,
        )
        .unwrap();
        Fixture {
            controller_request,
            controller_plan,
            program,
            producer_plan,
            activation_request,
            proposal,
            proposal_verification,
            decision,
            correspondence,
        }
    }

    fn admission(fixture: &Fixture) -> Evox2RemotePreflightLiveAdmission {
        Evox2RemotePreflightLiveAdmission {
            bridge_canonical_uuid: BRIDGE_CANONICAL_UUID.to_owned(),
            bridge_signature_uuid: BRIDGE_SIGNATURE_UUID.to_owned(),
            bridge_formation_commit: BRIDGE_FORMATION_COMMIT.to_owned(),
            bridge_formation_bookend: BRIDGE_FORMATION_BOOKEND.to_owned(),
            activation_implementation_commit: ACTIVATION_IMPLEMENTATION_COMMIT.to_owned(),
            activation_implementation_bookend: ACTIVATION_IMPLEMENTATION_BOOKEND.to_owned(),
            runner_implementation_commit: RUNNER_IMPLEMENTATION_COMMIT.to_owned(),
            runner_implementation_bookend: RUNNER_IMPLEMENTATION_BOOKEND.to_owned(),
            request_sha256: fixture.activation_request.request_sha256.clone(),
            proposal_sha256: fixture.proposal.proposal_sha256.clone(),
            proposal_verification_sha256: fixture
                .proposal_verification
                .proposal_verification_sha256
                .clone(),
            decision_sha256: fixture.decision.decision_sha256.clone(),
            correspondence_sha256: fixture.correspondence.correspondence_sha256.clone(),
            producer_plan_sha256: fixture.producer_plan.producer_plan_sha256.clone(),
            observed_time_ms: fixture.correspondence.observed_time_ms,
            decision: fixture.decision.decision,
            maximum_attempts: 1,
            maximum_permits: 1,
            maximum_runner_entries: 1,
            maximum_processes: 1,
            retry_count: 0,
            fixture_only: false,
        }
    }

    fn signed_decision(
        proposal: &Evox2RemotePreflightActivationProposal,
        decision_kind: Evox2RemotePreflightOperatorDecisionKind,
    ) -> Evox2RemotePreflightOperatorDecision {
        let signing_key = SigningKey::from_bytes(&[11_u8; 32]);
        let mut decision = Evox2RemotePreflightOperatorDecision {
            profile: "cantor-evox2-remote-preflight-operator-decision/0.1".to_owned(),
            decision_uuid: "2e35685a-9b4c-4d34-a0d0-85528462ab08".to_owned(),
            ceremony_uuid: proposal.ceremony_uuid.clone(),
            proposal_sha256: proposal.proposal_sha256.clone(),
            operator_principal: proposal.operator_principal.clone(),
            operator_role: proposal.operator_role.clone(),
            subject: proposal.subject.clone(),
            decision_nonce: proposal.decision_nonce.clone(),
            decision: decision_kind,
            issued_at_ms: proposal.decision_not_before_ms + 1,
            not_before_ms: proposal.decision_not_before_ms,
            expires_at_ms: proposal.decision_expires_at_ms,
            maximum_attempts: 1,
            maximum_permits: 1,
            maximum_processes: 1,
            retry_count: 0,
            verifying_key_hex: hex(&signing_key.verifying_key().to_bytes()),
            signature_hex: String::new(),
            fixture_only: false,
            decision_sha256: String::new(),
        };
        decision.signature_hex = hex(&signing_key
            .sign(&evox2_remote_preflight_operator_decision_signing_bytes(&decision).unwrap())
            .to_bytes());
        seal_evox2_remote_preflight_operator_decision_digest(decision).unwrap()
    }

    fn observation(
        request: &Evox2ScratchBuildControllerRequest,
        available: bool,
    ) -> Evox2ScratchBuildRemotePreflightContainedProcessObservation {
        let probe = seal_evox2_scratch_build_remote_probe_result(
            request,
            Evox2ScratchBuildRemoteProbeResult {
                profile: EVOX2_SCRATCH_BUILD_REMOTE_PROBE_RESULT_PROFILE.to_owned(),
                run_uuid: request.run_uuid.clone(),
                request_sha256: request.request_sha256.clone(),
                target_host: request.target_host.clone(),
                provider_listener: "127.0.0.1:8081".to_owned(),
                provider_model_path:
                    "C:/AI/models/validation/Qwen3.5-0.8B-GGUF/Qwen3.5-0.8B-Q4_0.gguf".to_owned(),
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
        .unwrap();
        let stdout = to_evox2_scratch_build_remote_probe_result_machine_form(request, &probe)
            .unwrap()
            .into_bytes();
        Evox2ScratchBuildRemotePreflightContainedProcessObservation {
            exit_code: 0,
            stdout_observed_bytes: stdout.len() as u64,
            stderr_observed_bytes: 0,
            stdout,
            stderr: Vec::new(),
            stdout_over_bound: false,
            stderr_over_bound: false,
            forced_termination: false,
            total_processes: 1,
            active_processes_at_terminal: 0,
            resume_previous_count: 1,
            duration_ms: 7,
        }
    }

    fn invoke_with_observation(
        fixture: &Fixture,
        available: bool,
    ) -> Evox2RemotePreflightPrivatePermitBridgeTerminal {
        let calls = Cell::new(0_u8);
        let terminal = run_private_bridge_with(
            admission(fixture),
            &fixture.activation_request,
            &fixture.proposal,
            &fixture.proposal_verification,
            &fixture.decision,
            &fixture.correspondence,
            &fixture.controller_request,
            &fixture.controller_plan,
            &fixture.program,
            &fixture.producer_plan,
            |permit| {
                calls.set(calls.get() + 1);
                run_evox2_scratch_build_remote_preflight_with_supplied_observation_for_private_bridge_test(
                    permit,
                    &fixture.controller_request,
                    &fixture.controller_plan,
                    &fixture.program,
                    &fixture.producer_plan,
                    observation(&fixture.controller_request, available),
                )
            },
        )
        .unwrap();
        assert_eq!(calls.get(), 1);
        terminal
    }

    #[test]
    fn provider_unavailable_and_available_receipts_close_terminally() {
        let unavailable = invoke_with_observation(
            &fixture(Evox2RemotePreflightOperatorDecisionKind::Authorize),
            false,
        );
        assert_eq!(
            unavailable.disposition,
            Evox2RemotePreflightPrivatePermitBridgeDisposition::CompletedProviderUnavailable
        );
        assert_eq!(
            (unavailable.permit_consumed, unavailable.runner_invocations),
            (true, 1)
        );
        assert_eq!(
            (
                unavailable.effect_account_observed,
                unavailable.provider_requests,
                unavailable.remote_calls,
                unavailable.effects
            ),
            (true, Some(0), Some(1), Some(1))
        );
        assert_eq!(
            unavailable
                .validated_run
                .as_ref()
                .unwrap()
                .observation
                .probe
                .provider_status,
            "unavailable"
        );

        let available = invoke_with_observation(
            &fixture(Evox2RemotePreflightOperatorDecisionKind::Authorize),
            true,
        );
        assert_eq!(
            available.disposition,
            Evox2RemotePreflightPrivatePermitBridgeDisposition::CompletedAvailable
        );
    }

    #[test]
    fn reject_or_admission_drift_refuses_before_runner_callback() {
        let rejected = fixture(Evox2RemotePreflightOperatorDecisionKind::Reject);
        let calls = Cell::new(0_u8);
        let result = run_private_bridge_with(
            admission(&rejected),
            &rejected.activation_request,
            &rejected.proposal,
            &rejected.proposal_verification,
            &rejected.decision,
            &rejected.correspondence,
            &rejected.controller_request,
            &rejected.controller_plan,
            &rejected.program,
            &rejected.producer_plan,
            |_| {
                calls.set(calls.get() + 1);
                unreachable!()
            },
        );
        assert_eq!(
            result.unwrap_err().code,
            Evox2RemotePreflightPrivatePermitBridgeFaultCode::Admission
        );
        assert_eq!(calls.get(), 0);

        let authorized = fixture(Evox2RemotePreflightOperatorDecisionKind::Authorize);
        let mut changed = admission(&authorized);
        changed.maximum_permits = 2;
        let result = run_private_bridge_with(
            changed,
            &authorized.activation_request,
            &authorized.proposal,
            &authorized.proposal_verification,
            &authorized.decision,
            &authorized.correspondence,
            &authorized.controller_request,
            &authorized.controller_plan,
            &authorized.program,
            &authorized.producer_plan,
            |_| unreachable!(),
        );
        assert_eq!(
            result.unwrap_err().code,
            Evox2RemotePreflightPrivatePermitBridgeFaultCode::Admission
        );
    }

    #[test]
    fn fixture_or_observed_time_drift_refuses_before_runner_callback() {
        let mut fixture_input = fixture(Evox2RemotePreflightOperatorDecisionKind::Authorize);
        let calls = Cell::new(0_u8);
        fixture_input.activation_request.fixture_only = true;
        fixture_input.activation_request.request_sha256.clear();
        fixture_input.activation_request.request_sha256 =
            activation_request_digest(&fixture_input.activation_request).unwrap();
        let result = run_private_bridge_with(
            admission(&fixture_input),
            &fixture_input.activation_request,
            &fixture_input.proposal,
            &fixture_input.proposal_verification,
            &fixture_input.decision,
            &fixture_input.correspondence,
            &fixture_input.controller_request,
            &fixture_input.controller_plan,
            &fixture_input.program,
            &fixture_input.producer_plan,
            |_| {
                calls.set(calls.get() + 1);
                unreachable!()
            },
        );
        assert_eq!(
            result.unwrap_err().code,
            Evox2RemotePreflightPrivatePermitBridgeFaultCode::Activation
        );
        assert_eq!(calls.get(), 0);

        let mut stale = fixture(Evox2RemotePreflightOperatorDecisionKind::Authorize);
        stale.correspondence.observed_time_ms = stale.decision.not_before_ms.saturating_sub(1);
        let result = run_private_bridge_with(
            admission(&stale),
            &stale.activation_request,
            &stale.proposal,
            &stale.proposal_verification,
            &stale.decision,
            &stale.correspondence,
            &stale.controller_request,
            &stale.controller_plan,
            &stale.program,
            &stale.producer_plan,
            |_| {
                calls.set(calls.get() + 1);
                unreachable!()
            },
        );
        assert_eq!(
            result.unwrap_err().code,
            Evox2RemotePreflightPrivatePermitBridgeFaultCode::Activation
        );
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn runner_failure_and_receipt_tamper_are_spent_terminal_outcomes() {
        let authorized = fixture(Evox2RemotePreflightOperatorDecisionKind::Authorize);
        let calls = Cell::new(0_u8);
        let abandoned = run_private_bridge_with(
            admission(&authorized),
            &authorized.activation_request,
            &authorized.proposal,
            &authorized.proposal_verification,
            &authorized.decision,
            &authorized.correspondence,
            &authorized.controller_request,
            &authorized.controller_plan,
            &authorized.program,
            &authorized.producer_plan,
            |_| {
                calls.set(calls.get() + 1);
                Err(Evox2ScratchBuildRemotePreflightRunnerFault {
                    code: Evox2ScratchBuildRemotePreflightRunnerFaultCode::ProcessFailure,
                    detail: "synthetic provider-free runner failure",
                })
            },
        )
        .unwrap();
        assert_eq!(calls.get(), 1);
        assert_eq!(
            abandoned.disposition,
            Evox2RemotePreflightPrivatePermitBridgeDisposition::AbandonedAfterConsumption
        );
        assert!(abandoned.permit_consumed);
        assert_eq!(abandoned.runner_invocations, 1);
        assert!(!abandoned.effect_account_observed);
        assert_eq!(
            abandoned.runner_fault,
            Some(Evox2ScratchBuildRemotePreflightRunnerFaultCode::ProcessFailure)
        );

        let refused = run_private_bridge_with(
            admission(&authorized),
            &authorized.activation_request,
            &authorized.proposal,
            &authorized.proposal_verification,
            &authorized.decision,
            &authorized.correspondence,
            &authorized.controller_request,
            &authorized.controller_plan,
            &authorized.program,
            &authorized.producer_plan,
            |permit| {
                let mut run = run_evox2_scratch_build_remote_preflight_with_supplied_observation_for_private_bridge_test(
                    permit,
                    &authorized.controller_request,
                    &authorized.controller_plan,
                    &authorized.program,
                    &authorized.producer_plan,
                    observation(&authorized.controller_request, false),
                )?;
                run.runner_receipt_sha256 = "0".repeat(64);
                Ok(run)
            },
        )
        .unwrap();
        assert_eq!(
            refused.disposition,
            Evox2RemotePreflightPrivatePermitBridgeDisposition::ReceiptRefused
        );
        assert!(refused.permit_consumed);
        assert_eq!(refused.runner_invocations, 1);
        assert!(refused.validated_run.is_none());
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
