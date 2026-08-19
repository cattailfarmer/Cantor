//! Bounded metadata-only discovery of handles in an in-memory custody registry.

use cantor_core::ContentDigest;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    CheckpointCustodyRegistry, DispatchCheckpointHandle, DispatchCheckpointNextOperation,
    EffectlessDispatchPhase, validate_checkpoint_custody_registry,
};

pub const CHECKPOINT_HANDLE_DISCOVERY_SELECTOR_PROFILE: &str =
    "cantor-checkpoint-handle-discovery-selector/0.1";
pub const CHECKPOINT_HANDLE_DISCOVERY_RESPONSE_PROFILE: &str =
    "cantor-checkpoint-handle-discovery-response/0.1";
pub const CHECKPOINT_HANDLE_DISCOVERY_NONCLAIMS: [&str; 6] = [
    "bootstrap discovery identifies supplied registry state and not external provenance",
    "structural filtering is not semantic association search or correlation weighting",
    "returned handles are not checkpoints and cannot resume without custody",
    "content digests are not authentication authorization freshness or truth",
    "response embeds no checkpoint request response message or transport bodies",
    "no filesystem provider process network persistence hidden-state or external effect",
];

const SELECTOR_DIGEST_DOMAIN: &str = "cantor.checkpoint-handle-discovery.selector.v1";
const RESPONSE_DIGEST_DOMAIN: &str = "cantor.checkpoint-handle-discovery.response.v1";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CheckpointHandleDiscoverySelector {
    pub profile: String,
    pub expected_registry_root: Option<ContentDigest>,
    pub checkpoint_phase: Option<EffectlessDispatchPhase>,
    pub next_operation: Option<DispatchCheckpointNextOperation>,
    pub transport_position: Option<u32>,
    pub terminal_reflection: Option<bool>,
    pub checkpoint_digest_prefix: Option<String>,
    pub maximum_results: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DiscoveredCheckpointHandle {
    pub handle: DispatchCheckpointHandle,
    pub entry_digest: ContentDigest,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CheckpointHandleDiscoveryResponse {
    pub profile: String,
    pub selector_digest: ContentDigest,
    pub registry_root: ContentDigest,
    pub caller_root_pinned: bool,
    pub matches: Vec<DiscoveredCheckpointHandle>,
    pub available_match_count: usize,
    pub returned_match_count: usize,
    pub truncated: bool,
    pub response_digest: ContentDigest,
    pub checkpoint_bodies_embedded: bool,
    pub request_bodies_embedded: bool,
    pub response_bodies_embedded: bool,
    pub message_bodies_embedded: bool,
    pub transport_bodies_embedded: bool,
    pub persistence_claimed: bool,
    pub provider_execution_claimed: bool,
    pub producer_authentication_claimed: bool,
    pub nonclaims: Vec<String>,
}

pub fn discover_checkpoint_handles(
    registry: &CheckpointCustodyRegistry,
    selector: &CheckpointHandleDiscoverySelector,
) -> Result<CheckpointHandleDiscoveryResponse, String> {
    validate_checkpoint_custody_registry(registry)?;
    validate_checkpoint_handle_discovery_selector(selector)?;
    if let Some(expected) = &selector.expected_registry_root
        && expected != &registry.root_digest
    {
        return Err("checkpoint handle discovery expected registry root differs".to_owned());
    }
    let all_matches: Vec<_> = registry
        .entries
        .values()
        .filter(|entry| matches_selector(&entry.handle, selector))
        .map(|entry| DiscoveredCheckpointHandle {
            handle: entry.handle.clone(),
            entry_digest: entry.entry_digest.clone(),
        })
        .collect();
    let available_match_count = all_matches.len();
    let matches: Vec<_> = all_matches
        .into_iter()
        .take(selector.maximum_results)
        .collect();
    let returned_match_count = matches.len();
    let truncated = returned_match_count < available_match_count;
    let selector_digest = digest_json(SELECTOR_DIGEST_DOMAIN, selector)?;
    let nonclaims = discovery_nonclaims();
    let response_digest = response_digest(
        &selector_digest,
        &registry.root_digest,
        selector.expected_registry_root.is_some(),
        &matches,
        (available_match_count, returned_match_count, truncated),
        &nonclaims,
    )?;
    let response = CheckpointHandleDiscoveryResponse {
        profile: CHECKPOINT_HANDLE_DISCOVERY_RESPONSE_PROFILE.to_owned(),
        selector_digest,
        registry_root: registry.root_digest.clone(),
        caller_root_pinned: selector.expected_registry_root.is_some(),
        matches,
        available_match_count,
        returned_match_count,
        truncated,
        response_digest,
        checkpoint_bodies_embedded: false,
        request_bodies_embedded: false,
        response_bodies_embedded: false,
        message_bodies_embedded: false,
        transport_bodies_embedded: false,
        persistence_claimed: false,
        provider_execution_claimed: false,
        producer_authentication_claimed: false,
        nonclaims,
    };
    validate_checkpoint_handle_discovery_response(registry, selector, &response)?;
    Ok(response)
}

pub fn validate_checkpoint_handle_discovery_selector(
    selector: &CheckpointHandleDiscoverySelector,
) -> Result<(), String> {
    if selector.profile != CHECKPOINT_HANDLE_DISCOVERY_SELECTOR_PROFILE
        || !(1..=12).contains(&selector.maximum_results)
    {
        return Err("checkpoint handle discovery selector identity or bound is invalid".to_owned());
    }
    if let Some(root) = &selector.expected_registry_root
        && (root.algorithm != "sha256" || !valid_hex(&root.value, 64, 64))
    {
        return Err("checkpoint handle discovery expected root is invalid".to_owned());
    }
    if let Some(prefix) = &selector.checkpoint_digest_prefix
        && !valid_hex(prefix, 8, 64)
    {
        return Err("checkpoint handle discovery digest prefix is invalid".to_owned());
    }
    Ok(())
}

pub fn validate_checkpoint_handle_discovery_response(
    registry: &CheckpointCustodyRegistry,
    selector: &CheckpointHandleDiscoverySelector,
    response: &CheckpointHandleDiscoveryResponse,
) -> Result<(), String> {
    validate_checkpoint_custody_registry(registry)?;
    validate_checkpoint_handle_discovery_selector(selector)?;
    if response.profile != CHECKPOINT_HANDLE_DISCOVERY_RESPONSE_PROFILE
        || response.registry_root != registry.root_digest
        || response.caller_root_pinned != selector.expected_registry_root.is_some()
        || response.selector_digest != digest_json(SELECTOR_DIGEST_DOMAIN, selector)?
        || response.returned_match_count != response.matches.len()
        || response.returned_match_count > selector.maximum_results
        || response.truncated != (response.returned_match_count < response.available_match_count)
        || response.checkpoint_bodies_embedded
        || response.request_bodies_embedded
        || response.response_bodies_embedded
        || response.message_bodies_embedded
        || response.transport_bodies_embedded
        || response.persistence_claimed
        || response.provider_execution_claimed
        || response.producer_authentication_claimed
        || response.nonclaims != discovery_nonclaims()
    {
        return Err(
            "checkpoint handle discovery response identity or claims are invalid".to_owned(),
        );
    }
    let expected = discover_without_validation(registry, selector)?;
    if response != &expected {
        return Err("checkpoint handle discovery response differs from reconstruction".to_owned());
    }
    Ok(())
}

pub fn pretty_checkpoint_handle_discovery_response_bytes(
    registry: &CheckpointCustodyRegistry,
    selector: &CheckpointHandleDiscoverySelector,
    response: &CheckpointHandleDiscoveryResponse,
) -> Result<Vec<u8>, String> {
    validate_checkpoint_handle_discovery_response(registry, selector, response)?;
    let mut bytes = serde_json::to_vec_pretty(response)
        .map_err(|error| format!("checkpoint handle discovery serialization failed: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn discover_without_validation(
    registry: &CheckpointCustodyRegistry,
    selector: &CheckpointHandleDiscoverySelector,
) -> Result<CheckpointHandleDiscoveryResponse, String> {
    if let Some(expected) = &selector.expected_registry_root
        && expected != &registry.root_digest
    {
        return Err("checkpoint handle discovery expected registry root differs".to_owned());
    }
    let all_matches: Vec<_> = registry
        .entries
        .values()
        .filter(|entry| matches_selector(&entry.handle, selector))
        .map(|entry| DiscoveredCheckpointHandle {
            handle: entry.handle.clone(),
            entry_digest: entry.entry_digest.clone(),
        })
        .collect();
    let available_match_count = all_matches.len();
    let matches: Vec<_> = all_matches
        .into_iter()
        .take(selector.maximum_results)
        .collect();
    let returned_match_count = matches.len();
    let truncated = returned_match_count < available_match_count;
    let selector_digest = digest_json(SELECTOR_DIGEST_DOMAIN, selector)?;
    let nonclaims = discovery_nonclaims();
    Ok(CheckpointHandleDiscoveryResponse {
        profile: CHECKPOINT_HANDLE_DISCOVERY_RESPONSE_PROFILE.to_owned(),
        registry_root: registry.root_digest.clone(),
        caller_root_pinned: selector.expected_registry_root.is_some(),
        response_digest: response_digest(
            &selector_digest,
            &registry.root_digest,
            selector.expected_registry_root.is_some(),
            &matches,
            (available_match_count, returned_match_count, truncated),
            &nonclaims,
        )?,
        selector_digest,
        matches,
        available_match_count,
        returned_match_count,
        truncated,
        checkpoint_bodies_embedded: false,
        request_bodies_embedded: false,
        response_bodies_embedded: false,
        message_bodies_embedded: false,
        transport_bodies_embedded: false,
        persistence_claimed: false,
        provider_execution_claimed: false,
        producer_authentication_claimed: false,
        nonclaims,
    })
}

fn matches_selector(
    handle: &DispatchCheckpointHandle,
    selector: &CheckpointHandleDiscoverySelector,
) -> bool {
    selector
        .checkpoint_phase
        .is_none_or(|value| handle.checkpoint_phase == value)
        && selector
            .next_operation
            .is_none_or(|value| handle.next_operation == value)
        && selector
            .transport_position
            .is_none_or(|value| handle.transport_position == value)
        && selector
            .terminal_reflection
            .is_none_or(|value| handle.terminal_reflection == value)
        && selector
            .checkpoint_digest_prefix
            .as_ref()
            .is_none_or(|value| handle.checkpoint_digest.value.starts_with(value))
}

fn response_digest(
    selector_digest: &ContentDigest,
    registry_root: &ContentDigest,
    caller_root_pinned: bool,
    matches: &[DiscoveredCheckpointHandle],
    match_state: (usize, usize, bool),
    nonclaims: &[String],
) -> Result<ContentDigest, String> {
    let (available, returned, truncated) = match_state;
    digest_json(
        RESPONSE_DIGEST_DOMAIN,
        &(
            CHECKPOINT_HANDLE_DISCOVERY_RESPONSE_PROFILE,
            selector_digest,
            registry_root,
            caller_root_pinned,
            matches,
            available,
            returned,
            truncated,
            [false; 8],
            nonclaims,
        ),
    )
}

fn valid_hex(value: &str, minimum: usize, maximum: usize) -> bool {
    (minimum..=maximum).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn digest_json<T: Serialize>(domain: &str, value: &T) -> Result<ContentDigest, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("checkpoint handle discovery digest failed: {error}"))?;
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

fn discovery_nonclaims() -> Vec<String> {
    CHECKPOINT_HANDLE_DISCOVERY_NONCLAIMS
        .iter()
        .map(ToString::to_string)
        .collect()
}
