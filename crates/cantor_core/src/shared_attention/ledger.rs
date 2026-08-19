//! Pure content-addressed custody and compare-and-set reentry for attention frames.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{
    AttentionCompaction, AttentionFrameDelta, FrameAttestation, ReconciliationDisposition,
    SettlementDisposition, SharedAttentionFault, SharedAttentionFaultCode, SharedAttentionFrame,
    SharedAttentionToolRequest, SharedAttentionToolResponse, SharedAttentionToolResult,
    SharedAttentionToolStatus, SharedFrameStatus, execute_shared_attention_tool_request,
    validate_shared_attention_frame,
};
use crate::{ContentDigest, SemanticId};

use super::runtime::{derive, digest, fault, require_text};

pub const ATTENTION_LEDGER_PROFILE: &str = "cantor-attention-reentry-ledger/0.1";
pub const ATTENTION_LEDGER_EVENT_PROFILE: &str = "cantor-attention-ledger-event/0.1";
pub const ATTENTION_CONTINUATION_PROFILE: &str = "cantor-attention-continuation/0.1";
pub const ATTENTION_LEDGER_RESPONSE_PROFILE: &str = "cantor-attention-ledger-response/0.1";

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttentionLedgerCommandName {
    Open,
    Apply,
    Inspect,
    ReadFrame,
    ReadEvent,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttentionLedgerDisposition {
    Opened,
    Advanced,
    Recorded,
    Inspected,
    Read,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum AttentionSessionOperation {
    Reconcile {
        deltas: Vec<AttentionFrameDelta>,
    },
    Compact {
        compaction: Box<AttentionCompaction>,
    },
    Prepare,
    Settle {
        attestations: Vec<FrameAttestation>,
    },
}

impl AttentionSessionOperation {
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Reconcile { .. } => "reconcile",
            Self::Compact { .. } => "compact",
            Self::Prepare => "prepare",
            Self::Settle { .. } => "settle",
        }
    }

    fn into_tool_request(self, base: SharedAttentionFrame) -> SharedAttentionToolRequest {
        match self {
            Self::Reconcile { deltas } => SharedAttentionToolRequest::Reconcile { base, deltas },
            Self::Compact { compaction } => SharedAttentionToolRequest::Compact {
                base,
                compaction: *compaction,
            },
            Self::Prepare => SharedAttentionToolRequest::Prepare { working: base },
            Self::Settle { attestations } => SharedAttentionToolRequest::Settle {
                candidate: base,
                attestations,
            },
        }
    }
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum AttentionLedgerCommand {
    Open {
        expected_ledger_digest: ContentDigest,
        session_id: SemanticId,
        frame: Box<SharedAttentionFrame>,
    },
    Apply {
        expected_ledger_digest: ContentDigest,
        session_id: SemanticId,
        expected_sequence: u64,
        expected_head_frame_digest: ContentDigest,
        session_operation: AttentionSessionOperation,
    },
    Inspect {
        expected_ledger_digest: ContentDigest,
        session_id: SemanticId,
    },
    ReadFrame {
        expected_ledger_digest: ContentDigest,
        frame_digest: ContentDigest,
    },
    ReadEvent {
        expected_ledger_digest: ContentDigest,
        event_id: SemanticId,
    },
}

impl AttentionLedgerCommand {
    pub const fn name(&self) -> AttentionLedgerCommandName {
        match self {
            Self::Open { .. } => AttentionLedgerCommandName::Open,
            Self::Apply { .. } => AttentionLedgerCommandName::Apply,
            Self::Inspect { .. } => AttentionLedgerCommandName::Inspect,
            Self::ReadFrame { .. } => AttentionLedgerCommandName::ReadFrame,
            Self::ReadEvent { .. } => AttentionLedgerCommandName::ReadEvent,
        }
    }

    fn expected_ledger_digest(&self) -> &ContentDigest {
        match self {
            Self::Open {
                expected_ledger_digest,
                ..
            }
            | Self::Apply {
                expected_ledger_digest,
                ..
            }
            | Self::Inspect {
                expected_ledger_digest,
                ..
            }
            | Self::ReadFrame {
                expected_ledger_digest,
                ..
            }
            | Self::ReadEvent {
                expected_ledger_digest,
                ..
            } => expected_ledger_digest,
        }
    }
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttentionLedgerEvent {
    pub profile: String,
    pub event_id: SemanticId,
    pub session_id: SemanticId,
    pub sequence: u64,
    pub operation: String,
    pub command_digest: ContentDigest,
    pub response_digest: ContentDigest,
    pub response_status: SharedAttentionToolStatus,
    pub predecessor_frame_digest: Option<ContentDigest>,
    pub successor_frame_digest: Option<ContentDigest>,
    pub event_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttentionSessionState {
    pub session_id: SemanticId,
    pub sequence: u64,
    pub head_frame_digest: ContentDigest,
    pub head_generation: u64,
    pub head_status: SharedFrameStatus,
    pub event_refs: Vec<SemanticId>,
    pub session_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttentionLedger {
    pub profile: String,
    pub ledger_id: SemanticId,
    pub frames: BTreeMap<String, SharedAttentionFrame>,
    pub sessions: BTreeMap<SemanticId, AttentionSessionState>,
    pub events: BTreeMap<SemanticId, AttentionLedgerEvent>,
    pub ledger_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttentionContinuation {
    pub profile: String,
    pub ledger_id: SemanticId,
    pub ledger_digest: ContentDigest,
    pub session_id: SemanticId,
    pub session_sequence: u64,
    pub head_frame_digest: ContentDigest,
    pub head_generation: u64,
    pub head_status: SharedFrameStatus,
    pub latest_event_ref: SemanticId,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttentionLedgerResponse {
    pub profile: String,
    pub command: AttentionLedgerCommandName,
    pub disposition: AttentionLedgerDisposition,
    pub ledger_id: SemanticId,
    pub ledger_digest: ContentDigest,
    pub continuation: Option<AttentionContinuation>,
    pub core_response: Option<SharedAttentionToolResponse>,
    pub frame: Option<SharedAttentionFrame>,
    pub event: Option<AttentionLedgerEvent>,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttentionLedgerTransition {
    pub successor: Option<AttentionLedger>,
    pub response: AttentionLedgerResponse,
}

pub fn new_attention_ledger(
    ledger_id: SemanticId,
) -> Result<AttentionLedger, SharedAttentionFault> {
    let mut ledger = AttentionLedger {
        profile: ATTENTION_LEDGER_PROFILE.to_owned(),
        ledger_id,
        frames: BTreeMap::new(),
        sessions: BTreeMap::new(),
        events: BTreeMap::new(),
        ledger_digest: empty_sha256(),
    };
    refresh_ledger_digest(&mut ledger)?;
    validate_attention_ledger(&ledger)?;
    Ok(ledger)
}

pub fn validate_attention_ledger(ledger: &AttentionLedger) -> Result<(), SharedAttentionFault> {
    if ledger.profile != ATTENTION_LEDGER_PROFILE {
        return Err(ledger_fault("unsupported attention ledger profile"));
    }
    let expected_root = compute_ledger_digest(ledger)?;
    if ledger.ledger_digest != expected_root {
        return Err(fault(
            SharedAttentionFaultCode::InvalidDigest,
            "attention ledger digest differs from canonical content",
        ));
    }
    for (key, frame) in &ledger.frames {
        validate_shared_attention_frame(frame)?;
        if key != &frame_key(&frame.frame_digest)? {
            return Err(ledger_fault("frame map key differs from frame digest"));
        }
    }

    let mut referenced_events = BTreeSet::new();
    for (session_id, session) in &ledger.sessions {
        if session_id != &session.session_id {
            return Err(ledger_fault(
                "session map key differs from session identity",
            ));
        }
        validate_session_digest(session)?;
        if session.sequence == 0 || session.sequence != session.event_refs.len() as u64 {
            return Err(ledger_fault(
                "session sequence must equal its nonempty event history",
            ));
        }
        let head_key = frame_key(&session.head_frame_digest)?;
        let head = ledger
            .frames
            .get(&head_key)
            .ok_or_else(|| ledger_fault("session head frame is absent from ledger"))?;
        if head.generation != session.head_generation || head.status != session.head_status {
            return Err(ledger_fault(
                "session head metadata differs from stored frame",
            ));
        }

        let mut cursor: Option<ContentDigest> = None;
        for (index, event_ref) in session.event_refs.iter().enumerate() {
            if !referenced_events.insert(event_ref.clone()) {
                return Err(ledger_fault(
                    "one ledger event is referenced more than once",
                ));
            }
            let event = ledger
                .events
                .get(event_ref)
                .ok_or_else(|| ledger_fault("session event is absent from ledger"))?;
            validate_event_digest(event)?;
            if &event.session_id != session_id || event.sequence != index as u64 + 1 {
                return Err(ledger_fault(
                    "session event identity or sequence is discontinuous",
                ));
            }
            if event.predecessor_frame_digest != cursor {
                return Err(ledger_fault(
                    "session event predecessor does not match prior head",
                ));
            }
            if let Some(successor) = &event.successor_frame_digest {
                if !ledger.frames.contains_key(&frame_key(successor)?) {
                    return Err(ledger_fault("event successor frame is absent from ledger"));
                }
                cursor = Some(successor.clone());
            }
        }
        if cursor.as_ref() != Some(&session.head_frame_digest) {
            return Err(ledger_fault(
                "session event history does not resolve to current head",
            ));
        }
    }
    if referenced_events.len() != ledger.events.len() {
        return Err(ledger_fault("ledger contains an orphan event"));
    }
    for (event_id, event) in &ledger.events {
        if event_id != &event.event_id {
            return Err(ledger_fault("event map key differs from event identity"));
        }
    }
    Ok(())
}

pub fn execute_attention_ledger_command(
    ledger: &AttentionLedger,
    command: AttentionLedgerCommand,
) -> Result<AttentionLedgerTransition, SharedAttentionFault> {
    validate_attention_ledger(ledger)?;
    if command.expected_ledger_digest() != &ledger.ledger_digest {
        return Err(fault(
            SharedAttentionFaultCode::StaleLedger,
            "command expected ledger digest does not match current ledger",
        ));
    }
    let command_name = command.name();
    let command_digest = digest(&command, "attention ledger command")?;
    match command {
        AttentionLedgerCommand::Open {
            session_id, frame, ..
        } => open_session(ledger, command_name, command_digest, session_id, *frame),
        AttentionLedgerCommand::Apply {
            session_id,
            expected_sequence,
            expected_head_frame_digest,
            session_operation,
            ..
        } => apply_session_operation(
            ledger,
            command_name,
            command_digest,
            session_id,
            expected_sequence,
            expected_head_frame_digest,
            session_operation,
        ),
        AttentionLedgerCommand::Inspect { session_id, .. } => {
            let session = ledger.sessions.get(&session_id).ok_or_else(|| {
                fault(
                    SharedAttentionFaultCode::UnknownSession,
                    "attention session is not present in ledger",
                )
                .with_subject(session_id.clone())
            })?;
            Ok(read_transition(
                ledger,
                command_name,
                AttentionLedgerDisposition::Inspected,
                Some(continuation(ledger, session)?),
                None,
                None,
            ))
        }
        AttentionLedgerCommand::ReadFrame { frame_digest, .. } => {
            let key = frame_key(&frame_digest)?;
            let frame = ledger.frames.get(&key).cloned().ok_or_else(|| {
                fault(
                    SharedAttentionFaultCode::UnknownReference,
                    "frame digest is not present in ledger",
                )
            })?;
            Ok(read_transition(
                ledger,
                command_name,
                AttentionLedgerDisposition::Read,
                None,
                Some(frame),
                None,
            ))
        }
        AttentionLedgerCommand::ReadEvent { event_id, .. } => {
            let event = ledger.events.get(&event_id).cloned().ok_or_else(|| {
                fault(
                    SharedAttentionFaultCode::UnknownEvent,
                    "event identity is not present in ledger",
                )
                .with_subject(event_id.clone())
            })?;
            Ok(read_transition(
                ledger,
                command_name,
                AttentionLedgerDisposition::Read,
                None,
                None,
                Some(event),
            ))
        }
    }
}

fn open_session(
    ledger: &AttentionLedger,
    command_name: AttentionLedgerCommandName,
    command_digest: ContentDigest,
    session_id: SemanticId,
    frame: SharedAttentionFrame,
) -> Result<AttentionLedgerTransition, SharedAttentionFault> {
    if ledger.sessions.contains_key(&session_id) {
        return Err(fault(
            SharedAttentionFaultCode::DuplicateIdentity,
            "attention session identity is already present",
        )
        .with_subject(session_id));
    }
    validate_shared_attention_frame(&frame)?;
    let response_digest = digest(&frame, "attention ledger open response")?;
    let mut successor = ledger.clone();
    insert_frame(&mut successor, frame.clone())?;
    let event = build_event(
        &successor.ledger_id,
        &session_id,
        1,
        "open",
        command_digest,
        response_digest,
        SharedAttentionToolStatus::Succeeded,
        None,
        Some(frame.frame_digest.clone()),
    )?;
    successor
        .events
        .insert(event.event_id.clone(), event.clone());
    let mut session = AttentionSessionState {
        session_id: session_id.clone(),
        sequence: 1,
        head_frame_digest: frame.frame_digest.clone(),
        head_generation: frame.generation,
        head_status: frame.status,
        event_refs: vec![event.event_id.clone()],
        session_digest: empty_sha256(),
    };
    refresh_session_digest(&mut session)?;
    successor.sessions.insert(session_id, session.clone());
    refresh_ledger_digest(&mut successor)?;
    validate_attention_ledger(&successor)?;
    let handle = continuation(&successor, &session)?;
    Ok(AttentionLedgerTransition {
        response: AttentionLedgerResponse {
            profile: ATTENTION_LEDGER_RESPONSE_PROFILE.to_owned(),
            command: command_name,
            disposition: AttentionLedgerDisposition::Opened,
            ledger_id: successor.ledger_id.clone(),
            ledger_digest: successor.ledger_digest.clone(),
            continuation: Some(handle),
            core_response: None,
            frame: None,
            event: Some(event),
        },
        successor: Some(successor),
    })
}

fn apply_session_operation(
    ledger: &AttentionLedger,
    command_name: AttentionLedgerCommandName,
    command_digest: ContentDigest,
    session_id: SemanticId,
    expected_sequence: u64,
    expected_head_frame_digest: ContentDigest,
    session_operation: AttentionSessionOperation,
) -> Result<AttentionLedgerTransition, SharedAttentionFault> {
    let session = ledger.sessions.get(&session_id).ok_or_else(|| {
        fault(
            SharedAttentionFaultCode::UnknownSession,
            "attention session is not present in ledger",
        )
        .with_subject(session_id.clone())
    })?;
    if session.sequence != expected_sequence
        || session.head_frame_digest != expected_head_frame_digest
    {
        return Err(fault(
            SharedAttentionFaultCode::StaleLedger,
            "session compare-and-set sequence or head digest is stale",
        )
        .with_subject(session_id));
    }
    let head = ledger
        .frames
        .get(&frame_key(&session.head_frame_digest)?)
        .cloned()
        .ok_or_else(|| ledger_fault("session head frame is absent"))?;
    let operation_name = session_operation.name().to_owned();
    let core_response =
        execute_shared_attention_tool_request(session_operation.into_tool_request(head));
    let response_digest = digest(&core_response, "attention ledger core response")?;
    let next_frame = response_successor_frame(&core_response).cloned();

    let mut successor = ledger.clone();
    if let Some(frame) = &next_frame {
        insert_frame(&mut successor, frame.clone())?;
    }
    let next_sequence = session
        .sequence
        .checked_add(1)
        .ok_or_else(|| ledger_fault("attention session sequence overflow"))?;
    let event = build_event(
        &successor.ledger_id,
        &session.session_id,
        next_sequence,
        &operation_name,
        command_digest,
        response_digest,
        core_response.status,
        Some(session.head_frame_digest.clone()),
        next_frame.as_ref().map(|frame| frame.frame_digest.clone()),
    )?;
    if successor.events.contains_key(&event.event_id) {
        return Err(fault(
            SharedAttentionFaultCode::DuplicateIdentity,
            "derived attention event identity is already present",
        ));
    }
    successor
        .events
        .insert(event.event_id.clone(), event.clone());
    let mut next_session = session.clone();
    next_session.sequence = next_sequence;
    next_session.event_refs.push(event.event_id.clone());
    if let Some(frame) = next_frame {
        next_session.head_frame_digest = frame.frame_digest;
        next_session.head_generation = frame.generation;
        next_session.head_status = frame.status;
    }
    refresh_session_digest(&mut next_session)?;
    successor
        .sessions
        .insert(next_session.session_id.clone(), next_session.clone());
    refresh_ledger_digest(&mut successor)?;
    validate_attention_ledger(&successor)?;
    let disposition = if event.successor_frame_digest.is_some() {
        AttentionLedgerDisposition::Advanced
    } else {
        AttentionLedgerDisposition::Recorded
    };
    let handle = continuation(&successor, &next_session)?;
    Ok(AttentionLedgerTransition {
        response: AttentionLedgerResponse {
            profile: ATTENTION_LEDGER_RESPONSE_PROFILE.to_owned(),
            command: command_name,
            disposition,
            ledger_id: successor.ledger_id.clone(),
            ledger_digest: successor.ledger_digest.clone(),
            continuation: Some(handle),
            core_response: Some(core_response),
            frame: None,
            event: Some(event),
        },
        successor: Some(successor),
    })
}

fn response_successor_frame(
    response: &SharedAttentionToolResponse,
) -> Option<&SharedAttentionFrame> {
    match response.result.as_ref()? {
        SharedAttentionToolResult::Reconciliation(outcome)
            if outcome.disposition == ReconciliationDisposition::Applied =>
        {
            outcome.successor.as_ref()
        }
        SharedAttentionToolResult::Compaction(outcome) => Some(&outcome.successor),
        SharedAttentionToolResult::Preparation(outcome) => Some(&outcome.candidate),
        SharedAttentionToolResult::Settlement(outcome)
            if outcome.disposition == SettlementDisposition::Sealed =>
        {
            outcome.sealed_frame.as_ref()
        }
        _ => None,
    }
}

fn read_transition(
    ledger: &AttentionLedger,
    command: AttentionLedgerCommandName,
    disposition: AttentionLedgerDisposition,
    continuation: Option<AttentionContinuation>,
    frame: Option<SharedAttentionFrame>,
    event: Option<AttentionLedgerEvent>,
) -> AttentionLedgerTransition {
    AttentionLedgerTransition {
        successor: None,
        response: AttentionLedgerResponse {
            profile: ATTENTION_LEDGER_RESPONSE_PROFILE.to_owned(),
            command,
            disposition,
            ledger_id: ledger.ledger_id.clone(),
            ledger_digest: ledger.ledger_digest.clone(),
            continuation,
            core_response: None,
            frame,
            event,
        },
    }
}

fn insert_frame(
    ledger: &mut AttentionLedger,
    frame: SharedAttentionFrame,
) -> Result<(), SharedAttentionFault> {
    validate_shared_attention_frame(&frame)?;
    let key = frame_key(&frame.frame_digest)?;
    if let Some(existing) = ledger.frames.get(&key) {
        if existing != &frame {
            return Err(fault(
                SharedAttentionFaultCode::DigestCollision,
                "unequal frames claim one content digest",
            ));
        }
        return Ok(());
    }
    ledger.frames.insert(key, frame);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_event(
    ledger_id: &SemanticId,
    session_id: &SemanticId,
    sequence: u64,
    operation: &str,
    command_digest: ContentDigest,
    response_digest: ContentDigest,
    response_status: SharedAttentionToolStatus,
    predecessor_frame_digest: Option<ContentDigest>,
    successor_frame_digest: Option<ContentDigest>,
) -> Result<AttentionLedgerEvent, SharedAttentionFault> {
    require_text(operation, "attention ledger event operation")?;
    let seed = digest(
        &(
            ledger_id,
            session_id,
            sequence,
            operation,
            &command_digest,
            &response_digest,
            response_status,
            &predecessor_frame_digest,
            &successor_frame_digest,
        ),
        "attention ledger event identity",
    )?;
    let mut event = AttentionLedgerEvent {
        profile: ATTENTION_LEDGER_EVENT_PROFILE.to_owned(),
        event_id: derive("attention:ledger-event", &seed)?,
        session_id: session_id.clone(),
        sequence,
        operation: operation.to_owned(),
        command_digest,
        response_digest,
        response_status,
        predecessor_frame_digest,
        successor_frame_digest,
        event_digest: empty_sha256(),
    };
    refresh_event_digest(&mut event)?;
    Ok(event)
}

fn continuation(
    ledger: &AttentionLedger,
    session: &AttentionSessionState,
) -> Result<AttentionContinuation, SharedAttentionFault> {
    let latest_event_ref = session
        .event_refs
        .last()
        .cloned()
        .ok_or_else(|| ledger_fault("attention session has no latest event"))?;
    Ok(AttentionContinuation {
        profile: ATTENTION_CONTINUATION_PROFILE.to_owned(),
        ledger_id: ledger.ledger_id.clone(),
        ledger_digest: ledger.ledger_digest.clone(),
        session_id: session.session_id.clone(),
        session_sequence: session.sequence,
        head_frame_digest: session.head_frame_digest.clone(),
        head_generation: session.head_generation,
        head_status: session.head_status,
        latest_event_ref,
    })
}

fn frame_key(digest_value: &ContentDigest) -> Result<String, SharedAttentionFault> {
    validate_digest_shape(digest_value)?;
    Ok(digest_value.value.clone())
}

fn validate_digest_shape(digest_value: &ContentDigest) -> Result<(), SharedAttentionFault> {
    if digest_value.algorithm != "sha256"
        || digest_value.value.len() != 64
        || !digest_value
            .value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(fault(
            SharedAttentionFaultCode::InvalidDigest,
            "digest must be lowercase 64-hex sha256",
        ));
    }
    Ok(())
}

fn validate_event_digest(event: &AttentionLedgerEvent) -> Result<(), SharedAttentionFault> {
    if event.profile != ATTENTION_LEDGER_EVENT_PROFILE || event.sequence == 0 {
        return Err(ledger_fault(
            "invalid attention ledger event profile or sequence",
        ));
    }
    require_text(&event.operation, "attention ledger event operation")?;
    validate_digest_shape(&event.command_digest)?;
    validate_digest_shape(&event.response_digest)?;
    if event.event_digest != compute_event_digest(event)? {
        return Err(fault(
            SharedAttentionFaultCode::InvalidDigest,
            "attention ledger event digest differs from canonical content",
        ));
    }
    Ok(())
}

fn validate_session_digest(session: &AttentionSessionState) -> Result<(), SharedAttentionFault> {
    validate_digest_shape(&session.head_frame_digest)?;
    if session.session_digest != compute_session_digest(session)? {
        return Err(fault(
            SharedAttentionFaultCode::InvalidDigest,
            "attention session digest differs from canonical content",
        ));
    }
    Ok(())
}

fn refresh_event_digest(event: &mut AttentionLedgerEvent) -> Result<(), SharedAttentionFault> {
    event.event_digest = compute_event_digest(event)?;
    Ok(())
}

fn compute_event_digest(
    event: &AttentionLedgerEvent,
) -> Result<ContentDigest, SharedAttentionFault> {
    let mut canonical = event.clone();
    canonical.event_digest = empty_sha256();
    digest(&canonical, "attention ledger event")
}

fn refresh_session_digest(session: &mut AttentionSessionState) -> Result<(), SharedAttentionFault> {
    session.session_digest = compute_session_digest(session)?;
    Ok(())
}

fn compute_session_digest(
    session: &AttentionSessionState,
) -> Result<ContentDigest, SharedAttentionFault> {
    let mut canonical = session.clone();
    canonical.session_digest = empty_sha256();
    digest(&canonical, "attention session")
}

fn refresh_ledger_digest(ledger: &mut AttentionLedger) -> Result<(), SharedAttentionFault> {
    ledger.ledger_digest = compute_ledger_digest(ledger)?;
    Ok(())
}

fn compute_ledger_digest(ledger: &AttentionLedger) -> Result<ContentDigest, SharedAttentionFault> {
    let mut canonical = ledger.clone();
    canonical.ledger_digest = empty_sha256();
    digest(&canonical, "attention ledger")
}

fn empty_sha256() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: String::new(),
    }
}

fn ledger_fault(message: impl Into<String>) -> SharedAttentionFault {
    fault(SharedAttentionFaultCode::InvalidLedger, message)
}
