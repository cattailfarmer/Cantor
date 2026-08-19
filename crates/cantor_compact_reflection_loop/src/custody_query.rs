//! Closed request-response protocol over exact in-memory checkpoint custody.

use cantor_core::ContentDigest;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    AttentionTransportRecord, CheckpointCustodyRegistry, DispatchCheckpointHandle,
    DispatchCheckpointNextOperation, DispatchLifecycleCheckpoint, EffectlessDispatchPhase,
    EffectlessDispatchTrace, TerminalReflectionTransport, resolve_checkpoint_custody,
    resume_iteration_from_checkpoint_custody, resume_terminal_from_checkpoint_custody,
    validate_checkpoint_custody_registry,
};

pub const CHECKPOINT_CUSTODY_QUERY_PROFILE: &str = "cantor-checkpoint-custody-query/0.1";
pub const CHECKPOINT_CUSTODY_RESPONSE_PROFILE: &str = "cantor-checkpoint-custody-response/0.1";
pub const CHECKPOINT_CUSTODY_INSPECTION_PROFILE: &str = "cantor-checkpoint-custody-inspection/0.1";
pub const CHECKPOINT_CUSTODY_QUERY_NONCLAIMS: [&str; 5] = [
    "query dispatch is a pure value transform and not a database service",
    "inspection metadata is not complete checkpoint custody",
    "resolution and resume are host-facing deterministic operations and not model inference",
    "content digests are not producer authentication authorization or truth",
    "no filesystem write provider network process persistence hidden-state or external effect",
];

const REQUEST_DIGEST_DOMAIN: &str = "cantor.checkpoint-custody.query.request.v1";
const RESPONSE_DIGEST_DOMAIN: &str = "cantor.checkpoint-custody.query.response.v1";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CheckpointCustodyQuery {
    pub profile: String,
    pub expected_registry_root: ContentDigest,
    pub operation: CheckpointCustodyOperation,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CheckpointCustodyOperation {
    Inspect {
        handle: DispatchCheckpointHandle,
    },
    Resolve {
        handle: DispatchCheckpointHandle,
    },
    ResumeIteration {
        handle: DispatchCheckpointHandle,
        transport: Box<AttentionTransportRecord>,
    },
    ResumeTerminal {
        handle: DispatchCheckpointHandle,
        transport: Box<TerminalReflectionTransport>,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CheckpointCustodyInspection {
    pub profile: String,
    pub checkpoint_digest: ContentDigest,
    pub entry_digest: ContentDigest,
    pub checkpoint_phase: EffectlessDispatchPhase,
    pub next_operation: DispatchCheckpointNextOperation,
    pub transport_position: u32,
    pub terminal_reflection: bool,
    pub exact_checkpoint_available: bool,
    pub full_checkpoint_embedded: bool,
    pub request_body_embedded: bool,
    pub response_body_embedded: bool,
    pub message_body_embedded: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CheckpointCustodyResult {
    Inspection {
        inspection: CheckpointCustodyInspection,
    },
    Resolved {
        checkpoint: DispatchLifecycleCheckpoint,
    },
    IterationResumed {
        trace: EffectlessDispatchTrace,
    },
    TerminalResumed {
        trace: EffectlessDispatchTrace,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CheckpointCustodyResponse {
    pub profile: String,
    pub request_digest: ContentDigest,
    pub registry_root: ContentDigest,
    pub result: CheckpointCustodyResult,
    pub response_digest: ContentDigest,
    pub provider_execution_claimed: bool,
    pub external_effect_claimed: bool,
    pub persistence_claimed: bool,
    pub producer_authentication_claimed: bool,
    pub nonclaims: Vec<String>,
}

pub fn dispatch_checkpoint_custody_query(
    registry: &CheckpointCustodyRegistry,
    query: &CheckpointCustodyQuery,
) -> Result<CheckpointCustodyResponse, String> {
    validate_checkpoint_custody_registry(registry)?;
    validate_checkpoint_custody_query(query)?;
    if query.expected_registry_root != registry.root_digest {
        return Err("checkpoint custody query expected registry root differs".to_owned());
    }
    let result = match &query.operation {
        CheckpointCustodyOperation::Inspect { handle } => {
            let checkpoint = resolve_checkpoint_custody(registry, handle)?;
            let entry = registry
                .entries
                .get(&handle.checkpoint_digest.value)
                .ok_or_else(|| "checkpoint custody inspection entry is missing".to_owned())?;
            if checkpoint != entry.checkpoint {
                return Err(
                    "checkpoint custody inspection resolution differs from entry".to_owned(),
                );
            }
            CheckpointCustodyResult::Inspection {
                inspection: CheckpointCustodyInspection {
                    profile: CHECKPOINT_CUSTODY_INSPECTION_PROFILE.to_owned(),
                    checkpoint_digest: handle.checkpoint_digest.clone(),
                    entry_digest: entry.entry_digest.clone(),
                    checkpoint_phase: handle.checkpoint_phase,
                    next_operation: handle.next_operation,
                    transport_position: handle.transport_position,
                    terminal_reflection: handle.terminal_reflection,
                    exact_checkpoint_available: true,
                    full_checkpoint_embedded: false,
                    request_body_embedded: false,
                    response_body_embedded: false,
                    message_body_embedded: false,
                },
            }
        }
        CheckpointCustodyOperation::Resolve { handle } => CheckpointCustodyResult::Resolved {
            checkpoint: resolve_checkpoint_custody(registry, handle)?,
        },
        CheckpointCustodyOperation::ResumeIteration { handle, transport } => {
            CheckpointCustodyResult::IterationResumed {
                trace: resume_iteration_from_checkpoint_custody(registry, handle, transport)?,
            }
        }
        CheckpointCustodyOperation::ResumeTerminal { handle, transport } => {
            CheckpointCustodyResult::TerminalResumed {
                trace: resume_terminal_from_checkpoint_custody(registry, handle, transport)?,
            }
        }
    };
    let request_digest = digest_json(REQUEST_DIGEST_DOMAIN, query)?;
    let nonclaims = query_nonclaims();
    let response_digest =
        response_digest(&request_digest, &registry.root_digest, &result, &nonclaims)?;
    let response = CheckpointCustodyResponse {
        profile: CHECKPOINT_CUSTODY_RESPONSE_PROFILE.to_owned(),
        request_digest,
        registry_root: registry.root_digest.clone(),
        result,
        response_digest,
        provider_execution_claimed: false,
        external_effect_claimed: false,
        persistence_claimed: false,
        producer_authentication_claimed: false,
        nonclaims,
    };
    validate_checkpoint_custody_response(registry, query, &response)?;
    Ok(response)
}

pub fn validate_checkpoint_custody_query(query: &CheckpointCustodyQuery) -> Result<(), String> {
    if query.profile != CHECKPOINT_CUSTODY_QUERY_PROFILE
        || query.expected_registry_root.algorithm != "sha256"
        || !valid_digest_value(&query.expected_registry_root.value)
    {
        return Err("checkpoint custody query identity or root is invalid".to_owned());
    }
    let handle = match &query.operation {
        CheckpointCustodyOperation::Inspect { handle }
        | CheckpointCustodyOperation::Resolve { handle }
        | CheckpointCustodyOperation::ResumeIteration { handle, .. }
        | CheckpointCustodyOperation::ResumeTerminal { handle, .. } => handle,
    };
    crate::validate_dispatch_checkpoint_handle(handle)?;
    match &query.operation {
        CheckpointCustodyOperation::ResumeIteration { handle, .. }
            if handle.terminal_reflection =>
        {
            Err("iteration resume requires an iteration checkpoint handle".to_owned())
        }
        CheckpointCustodyOperation::ResumeTerminal { handle, .. }
            if !handle.terminal_reflection =>
        {
            Err("terminal resume requires a terminal checkpoint handle".to_owned())
        }
        _ => Ok(()),
    }
}

pub fn validate_checkpoint_custody_response(
    registry: &CheckpointCustodyRegistry,
    query: &CheckpointCustodyQuery,
    response: &CheckpointCustodyResponse,
) -> Result<(), String> {
    validate_checkpoint_custody_registry(registry)?;
    validate_checkpoint_custody_query(query)?;
    if response.profile != CHECKPOINT_CUSTODY_RESPONSE_PROFILE
        || response.registry_root != registry.root_digest
        || query.expected_registry_root != registry.root_digest
        || response.request_digest != digest_json(REQUEST_DIGEST_DOMAIN, query)?
        || response.provider_execution_claimed
        || response.external_effect_claimed
        || response.persistence_claimed
        || response.producer_authentication_claimed
        || response.nonclaims != query_nonclaims()
    {
        return Err(
            "checkpoint custody response identity claims or bindings are invalid".to_owned(),
        );
    }
    let expected = expected_result(registry, query)?;
    if response.result != expected {
        return Err("checkpoint custody response result differs from query".to_owned());
    }
    if response.response_digest
        != response_digest(
            &response.request_digest,
            &response.registry_root,
            &response.result,
            &response.nonclaims,
        )?
    {
        return Err("checkpoint custody response digest differs from values".to_owned());
    }
    Ok(())
}

pub fn pretty_checkpoint_custody_query_bytes(
    query: &CheckpointCustodyQuery,
) -> Result<Vec<u8>, String> {
    validate_checkpoint_custody_query(query)?;
    pretty_bytes(query)
}

pub fn pretty_checkpoint_custody_response_bytes(
    registry: &CheckpointCustodyRegistry,
    query: &CheckpointCustodyQuery,
    response: &CheckpointCustodyResponse,
) -> Result<Vec<u8>, String> {
    validate_checkpoint_custody_response(registry, query, response)?;
    pretty_bytes(response)
}

fn expected_result(
    registry: &CheckpointCustodyRegistry,
    query: &CheckpointCustodyQuery,
) -> Result<CheckpointCustodyResult, String> {
    match &query.operation {
        CheckpointCustodyOperation::Inspect { handle } => {
            resolve_checkpoint_custody(registry, handle)?;
            let entry = registry
                .entries
                .get(&handle.checkpoint_digest.value)
                .ok_or_else(|| "checkpoint custody inspection entry is missing".to_owned())?;
            Ok(CheckpointCustodyResult::Inspection {
                inspection: CheckpointCustodyInspection {
                    profile: CHECKPOINT_CUSTODY_INSPECTION_PROFILE.to_owned(),
                    checkpoint_digest: handle.checkpoint_digest.clone(),
                    entry_digest: entry.entry_digest.clone(),
                    checkpoint_phase: handle.checkpoint_phase,
                    next_operation: handle.next_operation,
                    transport_position: handle.transport_position,
                    terminal_reflection: handle.terminal_reflection,
                    exact_checkpoint_available: true,
                    full_checkpoint_embedded: false,
                    request_body_embedded: false,
                    response_body_embedded: false,
                    message_body_embedded: false,
                },
            })
        }
        CheckpointCustodyOperation::Resolve { handle } => Ok(CheckpointCustodyResult::Resolved {
            checkpoint: resolve_checkpoint_custody(registry, handle)?,
        }),
        CheckpointCustodyOperation::ResumeIteration { handle, transport } => {
            Ok(CheckpointCustodyResult::IterationResumed {
                trace: resume_iteration_from_checkpoint_custody(registry, handle, transport)?,
            })
        }
        CheckpointCustodyOperation::ResumeTerminal { handle, transport } => {
            Ok(CheckpointCustodyResult::TerminalResumed {
                trace: resume_terminal_from_checkpoint_custody(registry, handle, transport)?,
            })
        }
    }
}

fn response_digest(
    request_digest: &ContentDigest,
    registry_root: &ContentDigest,
    result: &CheckpointCustodyResult,
    nonclaims: &[String],
) -> Result<ContentDigest, String> {
    digest_json(
        RESPONSE_DIGEST_DOMAIN,
        &(
            CHECKPOINT_CUSTODY_RESPONSE_PROFILE,
            request_digest,
            registry_root,
            result,
            false,
            false,
            false,
            false,
            nonclaims,
        ),
    )
}

fn digest_json<T: Serialize>(domain: &str, value: &T) -> Result<ContentDigest, String> {
    let bytes = serde_json::to_vec(value).map_err(|error| {
        format!("checkpoint custody query digest serialization failed: {error}")
    })?;
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(bytes);
    Ok(ContentDigest {
        algorithm: "sha256".to_owned(),
        value: hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    })
}

fn pretty_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("checkpoint custody query serialization failed: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn valid_digest_value(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn query_nonclaims() -> Vec<String> {
    CHECKPOINT_CUSTODY_QUERY_NONCLAIMS
        .iter()
        .map(ToString::to_string)
        .collect()
}
