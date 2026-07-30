use cantor_core::{ProtocolRequest, ProtocolResponse, ProtocolStatus, SemanticId};

use crate::{CandidateArtifact, EcosystemFault, EcosystemFaultCode, WorkPacket};

pub trait CodexAdapter {
    fn accept_assignment(
        &mut self,
        work_packet: &WorkPacket,
    ) -> Result<ProtocolRequest, EcosystemFault>;

    fn accept_cantor_return(
        &mut self,
        request: &ProtocolRequest,
        response: &ProtocolResponse,
    ) -> Result<CandidateArtifact, EcosystemFault>;

    fn call_count(&self) -> u32;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MockCodexState {
    New,
    QueryEmitted,
    CandidateEmitted,
    Faulted,
}

/// Fixture-controlled two-step Codex substitute.
pub struct MockCodexAdapter {
    expected_work_packet_uuid: SemanticId,
    request: ProtocolRequest,
    candidate: CandidateArtifact,
    state: MockCodexState,
    calls: u32,
}

impl MockCodexAdapter {
    pub fn new(
        expected_work_packet_uuid: SemanticId,
        request: ProtocolRequest,
        candidate: CandidateArtifact,
    ) -> Self {
        Self {
            expected_work_packet_uuid,
            request,
            candidate,
            state: MockCodexState::New,
            calls: 0,
        }
    }

    fn fail(&mut self, message: impl AsRef<str>) -> EcosystemFault {
        self.state = MockCodexState::Faulted;
        EcosystemFault::new(
            EcosystemFaultCode::AdapterFault,
            "mock_codex",
            message,
            vec![self.expected_work_packet_uuid.clone()],
        )
    }
}

impl CodexAdapter for MockCodexAdapter {
    fn accept_assignment(
        &mut self,
        work_packet: &WorkPacket,
    ) -> Result<ProtocolRequest, EcosystemFault> {
        self.calls = self.calls.saturating_add(1);
        if self.state != MockCodexState::New {
            return Err(self.fail("assignment was delivered outside the new adapter state"));
        }
        if work_packet.work_packet_uuid != self.expected_work_packet_uuid {
            return Err(self.fail("assignment identity differs from the fixture binding"));
        }
        self.state = MockCodexState::QueryEmitted;
        Ok(self.request.clone())
    }

    fn accept_cantor_return(
        &mut self,
        request: &ProtocolRequest,
        response: &ProtocolResponse,
    ) -> Result<CandidateArtifact, EcosystemFault> {
        self.calls = self.calls.saturating_add(1);
        if self.state != MockCodexState::QueryEmitted {
            return Err(self.fail("Cantor return was delivered before exactly one query"));
        }
        if request != &self.request {
            return Err(self.fail("Cantor return is bound to a different request"));
        }
        if let Err(fault) = cantor_core::verify_protocol_response(request, response) {
            return Err(self.fail(format!(
                "Cantor response failed protocol verification: {}",
                fault.message
            )));
        }
        if response.status != ProtocolStatus::Success {
            return Err(self.fail("Cantor response was not successful"));
        }
        if let Err(fault) = self.candidate.validate() {
            self.state = MockCodexState::Faulted;
            return Err(fault);
        }
        self.state = MockCodexState::CandidateEmitted;
        Ok(self.candidate.clone())
    }

    fn call_count(&self) -> u32 {
        self.calls
    }
}

pub trait CantorAdapter {
    fn execute(&mut self, request: &ProtocolRequest) -> Result<ProtocolResponse, EcosystemFault>;

    fn call_count(&self) -> u32;
}

/// A purpose-scoped seam over caller-supplied `cantor_core` execution.
pub struct FunctionCantorAdapter<Executor> {
    executor: Executor,
    calls: u32,
}

impl<Executor> FunctionCantorAdapter<Executor> {
    pub fn new(executor: Executor) -> Self {
        Self { executor, calls: 0 }
    }
}

impl<Executor> CantorAdapter for FunctionCantorAdapter<Executor>
where
    Executor: FnMut(&ProtocolRequest) -> Result<ProtocolResponse, EcosystemFault>,
{
    fn execute(&mut self, request: &ProtocolRequest) -> Result<ProtocolResponse, EcosystemFault> {
        self.calls = self.calls.saturating_add(1);
        let response = (self.executor)(request)?;
        cantor_core::verify_protocol_response(request, &response).map_err(|fault| {
            EcosystemFault::new(
                EcosystemFaultCode::ProtocolFault,
                "cantor_adapter",
                fault.message,
                vec![request.request_id.clone()],
            )
        })?;
        Ok(response)
    }

    fn call_count(&self) -> u32 {
        self.calls
    }
}
