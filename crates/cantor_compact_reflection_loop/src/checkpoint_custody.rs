//! Immutable in-memory custody map resolving compact handles to exact checkpoints.

use std::collections::BTreeMap;

use cantor_core::ContentDigest;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    AttentionTransportRecord, DispatchCheckpointHandle, DispatchLifecycleCheckpoint,
    EffectlessDispatchTrace, TerminalReflectionTransport, compile_dispatch_checkpoint_handle,
    generate_scripted_dispatch_resume_corpus, resume_iteration_fixture_checkpoint,
    resume_terminal_fixture_checkpoint, validate_dispatch_checkpoint_handle,
    validate_dispatch_checkpoint_handle_against, validate_dispatch_lifecycle_checkpoint,
};

pub const CHECKPOINT_CUSTODY_REGISTRY_PROFILE: &str = "cantor-checkpoint-custody-registry/0.1";
pub const CHECKPOINT_CUSTODY_ENTRY_PROFILE: &str = "cantor-checkpoint-custody-entry/0.1";
pub const CHECKPOINT_CUSTODY_REGISTRY_NONCLAIMS: [&str; 6] = [
    "registry is an immutable in-process value and not a physical database",
    "in-memory-only flag is not persistence service or freshness evidence",
    "lookup returns exact retained checkpoint bytes and not semantics reconstructed from hash",
    "internal registry coherence is not canonical corpus provenance",
    "content digests are not authentication authorization or signatures",
    "no filesystem process network hidden-state remote or external-effect operation",
];

const ENTRY_DIGEST_DOMAIN: &str = "cantor.checkpoint-custody.entry.v1";
const ROOT_DIGEST_DOMAIN: &str = "cantor.checkpoint-custody.root.v1";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CheckpointCustodyEntry {
    pub profile: String,
    pub handle: DispatchCheckpointHandle,
    pub checkpoint: DispatchLifecycleCheckpoint,
    pub entry_digest: ContentDigest,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CheckpointCustodyRegistry {
    pub profile: String,
    pub entries: BTreeMap<String, CheckpointCustodyEntry>,
    pub entry_count: usize,
    pub root_digest: ContentDigest,
    pub in_memory_only: bool,
    pub persistence_claimed: bool,
    pub producer_authentication_claimed: bool,
    pub provider_execution_claimed: bool,
    pub external_effect_claimed: bool,
    pub nonclaims: Vec<String>,
}

pub fn new_checkpoint_custody_registry() -> Result<CheckpointCustodyRegistry, String> {
    let entries = BTreeMap::new();
    let registry = CheckpointCustodyRegistry {
        profile: CHECKPOINT_CUSTODY_REGISTRY_PROFILE.to_owned(),
        entry_count: 0,
        root_digest: digest_json(ROOT_DIGEST_DOMAIN, &entries)?,
        entries,
        in_memory_only: true,
        persistence_claimed: false,
        producer_authentication_claimed: false,
        provider_execution_claimed: false,
        external_effect_claimed: false,
        nonclaims: registry_nonclaims(),
    };
    validate_checkpoint_custody_registry(&registry)?;
    Ok(registry)
}

pub fn register_checkpoint_custody(
    registry: &CheckpointCustodyRegistry,
    handle: &DispatchCheckpointHandle,
    checkpoint: &DispatchLifecycleCheckpoint,
) -> Result<CheckpointCustodyRegistry, String> {
    validate_checkpoint_custody_registry(registry)?;
    validate_dispatch_checkpoint_handle_against(
        handle,
        checkpoint,
        handle.transport_position,
        handle.terminal_reflection,
    )?;
    let key = handle.checkpoint_digest.value.clone();
    if registry.entries.contains_key(&key) {
        return Err("checkpoint custody digest is already registered".to_owned());
    }
    let entry = CheckpointCustodyEntry {
        profile: CHECKPOINT_CUSTODY_ENTRY_PROFILE.to_owned(),
        handle: handle.clone(),
        checkpoint: checkpoint.clone(),
        entry_digest: digest_json(ENTRY_DIGEST_DOMAIN, &(handle, checkpoint))?,
    };
    validate_checkpoint_custody_entry(&key, &entry)?;
    let mut successor = registry.clone();
    successor.entries.insert(key, entry);
    successor.entry_count = successor.entries.len();
    successor.root_digest = digest_json(ROOT_DIGEST_DOMAIN, &successor.entries)?;
    validate_checkpoint_custody_registry(&successor)?;
    Ok(successor)
}

pub fn resolve_checkpoint_custody(
    registry: &CheckpointCustodyRegistry,
    handle: &DispatchCheckpointHandle,
) -> Result<DispatchLifecycleCheckpoint, String> {
    validate_checkpoint_custody_registry(registry)?;
    validate_dispatch_checkpoint_handle(handle)?;
    let entry = registry
        .entries
        .get(&handle.checkpoint_digest.value)
        .ok_or_else(|| "checkpoint custody handle is not registered".to_owned())?;
    if &entry.handle != handle {
        return Err("checkpoint custody handle differs from registered identity".to_owned());
    }
    validate_dispatch_checkpoint_handle_against(
        handle,
        &entry.checkpoint,
        handle.transport_position,
        handle.terminal_reflection,
    )?;
    Ok(entry.checkpoint.clone())
}

pub fn resume_iteration_from_checkpoint_custody(
    registry: &CheckpointCustodyRegistry,
    handle: &DispatchCheckpointHandle,
    transport: &AttentionTransportRecord,
) -> Result<EffectlessDispatchTrace, String> {
    let checkpoint = resolve_checkpoint_custody(registry, handle)?;
    resume_iteration_fixture_checkpoint(&checkpoint, transport)
}

pub fn resume_terminal_from_checkpoint_custody(
    registry: &CheckpointCustodyRegistry,
    handle: &DispatchCheckpointHandle,
    transport: &TerminalReflectionTransport,
) -> Result<EffectlessDispatchTrace, String> {
    let checkpoint = resolve_checkpoint_custody(registry, handle)?;
    resume_terminal_fixture_checkpoint(&checkpoint, transport)
}

pub fn validate_checkpoint_custody_registry(
    registry: &CheckpointCustodyRegistry,
) -> Result<(), String> {
    if registry.profile != CHECKPOINT_CUSTODY_REGISTRY_PROFILE
        || !registry.in_memory_only
        || registry.persistence_claimed
        || registry.producer_authentication_claimed
        || registry.provider_execution_claimed
        || registry.external_effect_claimed
        || registry.nonclaims != registry_nonclaims()
    {
        return Err("checkpoint custody registry identity or claims are invalid".to_owned());
    }
    if registry.entry_count != registry.entries.len() {
        return Err("checkpoint custody entry count differs from map".to_owned());
    }
    for (key, entry) in &registry.entries {
        validate_checkpoint_custody_entry(key, entry)?;
    }
    if registry.root_digest != digest_json(ROOT_DIGEST_DOMAIN, &registry.entries)? {
        return Err("checkpoint custody root digest differs from entries".to_owned());
    }
    Ok(())
}

pub fn generate_scripted_checkpoint_custody_registry() -> Result<CheckpointCustodyRegistry, String>
{
    let registry = expected_scripted_registry()?;
    validate_scripted_checkpoint_custody_registry(&registry)?;
    Ok(registry)
}

pub fn validate_scripted_checkpoint_custody_registry(
    registry: &CheckpointCustodyRegistry,
) -> Result<(), String> {
    validate_checkpoint_custody_registry(registry)?;
    let expected = expected_scripted_registry()?;
    if registry != &expected {
        return Err("checkpoint custody registry differs from scripted corpus".to_owned());
    }
    Ok(())
}

pub fn pretty_checkpoint_custody_registry_bytes(
    registry: &CheckpointCustodyRegistry,
) -> Result<Vec<u8>, String> {
    validate_checkpoint_custody_registry(registry)?;
    let mut bytes = serde_json::to_vec_pretty(registry)
        .map_err(|error| format!("checkpoint custody serialization failed: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn expected_scripted_registry() -> Result<CheckpointCustodyRegistry, String> {
    let corpus = generate_scripted_dispatch_resume_corpus()?;
    let mut registry = new_checkpoint_custody_registry()?;
    for case in &corpus.cases {
        let handle = compile_dispatch_checkpoint_handle(
            &case.checkpoint,
            case.transport_position,
            case.terminal_reflection,
        )?;
        registry = register_checkpoint_custody(&registry, &handle, &case.checkpoint)?;
    }
    Ok(registry)
}

fn validate_checkpoint_custody_entry(
    key: &str,
    entry: &CheckpointCustodyEntry,
) -> Result<(), String> {
    if entry.profile != CHECKPOINT_CUSTODY_ENTRY_PROFILE
        || key != entry.handle.checkpoint_digest.value
        || !valid_digest_key(key)
    {
        return Err("checkpoint custody entry identity or key is invalid".to_owned());
    }
    validate_dispatch_lifecycle_checkpoint(&entry.checkpoint)?;
    validate_dispatch_checkpoint_handle_against(
        &entry.handle,
        &entry.checkpoint,
        entry.handle.transport_position,
        entry.handle.terminal_reflection,
    )?;
    if entry.entry_digest != digest_json(ENTRY_DIGEST_DOMAIN, &(&entry.handle, &entry.checkpoint))?
    {
        return Err("checkpoint custody entry digest differs from values".to_owned());
    }
    Ok(())
}

fn valid_digest_key(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn digest_json<T: Serialize>(domain: &str, value: &T) -> Result<ContentDigest, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("checkpoint custody digest serialization failed: {error}"))?;
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

fn registry_nonclaims() -> Vec<String> {
    CHECKPOINT_CUSTODY_REGISTRY_NONCLAIMS
        .iter()
        .map(ToString::to_string)
        .collect()
}
