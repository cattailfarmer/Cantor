//! Pure immutable custody for complete native lifecycle validation requests.
//!
//! A compact handle locates retained request bytes; it cannot reconstruct
//! omitted meaning. This module owns no process-global state, persistence,
//! authentication, authorization, model, runner, or external effect.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{
    ContentDigest, NATIVE_LIFECYCLE_MAX_INPUT_BYTES, NativeLifecycleValidationOperation,
    NativeLifecycleValidationRequest, NativeLifecycleValidationResponse, SemanticId,
    validate_native_lifecycle_request,
};

pub const NATIVE_LIFECYCLE_CUSTODY_HANDLE_PROFILE: &str =
    "cantor-native-lifecycle-custody-handle/0.1";
pub const NATIVE_LIFECYCLE_CUSTODY_ENTRY_PROFILE: &str =
    "cantor-native-lifecycle-custody-entry/0.1";
pub const NATIVE_LIFECYCLE_CUSTODY_REGISTRY_PROFILE: &str =
    "cantor-native-lifecycle-custody-registry/0.1";
pub const NATIVE_LIFECYCLE_CUSTODY_MAX_ENTRIES: usize = 8;
pub const NATIVE_LIFECYCLE_CUSTODY_MAX_RETAINED_BYTES: u64 = 64 * 1024 * 1024;
pub const NATIVE_LIFECYCLE_CUSTODY_NONCLAIMS: [&str; 7] = [
    "registry is an immutable in-process value and not a physical database",
    "lookup returns an exact retained request and does not reconstruct meaning from a digest",
    "custody coherence is not lifecycle validity truth correctness or safety",
    "content digests are not authentication authorization or signatures",
    "in-memory-only identity is not persistence freshness recovery or global uniqueness",
    "validation disposition remains owned by the Slice7 lifecycle protocol",
    "no filesystem process network provider model remote or external-effect operation",
];

const ENTRY_DIGEST_DOMAIN: &str = "cantor.native-lifecycle-custody.entry.v1";
const ROOT_DIGEST_DOMAIN: &str = "cantor.native-lifecycle-custody.root.v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeLifecycleCustodyHandle {
    pub profile: String,
    pub request_id: SemanticId,
    pub operation: NativeLifecycleValidationOperation,
    pub request_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeLifecycleCustodyEntry {
    pub profile: String,
    pub handle: NativeLifecycleCustodyHandle,
    pub request: NativeLifecycleValidationRequest,
    pub normalized_request_bytes: u64,
    pub entry_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeLifecycleCustodyRegistry {
    pub profile: String,
    pub entries: BTreeMap<String, NativeLifecycleCustodyEntry>,
    pub entry_count: usize,
    pub retained_request_bytes: u64,
    pub root_digest: ContentDigest,
    pub in_memory_only: bool,
    pub persistence_claimed: bool,
    pub authentication_claimed: bool,
    pub authorization_claimed: bool,
    pub external_effect_claimed: bool,
    pub nonclaims: Vec<String>,
}

pub fn new_native_lifecycle_custody_registry() -> Result<NativeLifecycleCustodyRegistry, String> {
    let entries = BTreeMap::new();
    let registry = NativeLifecycleCustodyRegistry {
        profile: NATIVE_LIFECYCLE_CUSTODY_REGISTRY_PROFILE.to_owned(),
        root_digest: digest_json(ROOT_DIGEST_DOMAIN, &entries)?,
        entries,
        entry_count: 0,
        retained_request_bytes: 0,
        in_memory_only: true,
        persistence_claimed: false,
        authentication_claimed: false,
        authorization_claimed: false,
        external_effect_claimed: false,
        nonclaims: custody_nonclaims(),
    };
    validate_native_lifecycle_custody_registry(&registry)?;
    Ok(registry)
}

pub fn compile_native_lifecycle_custody_handle(
    request: &NativeLifecycleValidationRequest,
) -> Result<NativeLifecycleCustodyHandle, String> {
    let bytes = normalized_request_bytes(request)?;
    let handle = NativeLifecycleCustodyHandle {
        profile: NATIVE_LIFECYCLE_CUSTODY_HANDLE_PROFILE.to_owned(),
        request_id: request.request_id.clone(),
        operation: request.operation.clone(),
        request_digest: sha256_bytes(&bytes),
    };
    validate_native_lifecycle_custody_handle(&handle)?;
    Ok(handle)
}

pub fn register_native_lifecycle_custody(
    registry: &NativeLifecycleCustodyRegistry,
    request: &NativeLifecycleValidationRequest,
) -> Result<(NativeLifecycleCustodyRegistry, NativeLifecycleCustodyHandle), String> {
    validate_native_lifecycle_custody_registry(registry)?;
    if registry.entries.len() >= NATIVE_LIFECYCLE_CUSTODY_MAX_ENTRIES {
        return Err("native lifecycle custody entry limit is exhausted".to_owned());
    }
    let bytes = normalized_request_bytes(request)?;
    let request_bytes = u64::try_from(bytes.len())
        .map_err(|_| "native lifecycle request byte count cannot be represented".to_owned())?;
    let handle = compile_native_lifecycle_custody_handle(request)?;
    let key = handle.request_digest.value.clone();
    if registry.entries.contains_key(&key) {
        return Err("native lifecycle custody digest is already registered".to_owned());
    }
    let retained_request_bytes = registry
        .retained_request_bytes
        .checked_add(request_bytes)
        .ok_or_else(|| "native lifecycle custody retained byte count overflow".to_owned())?;
    if retained_request_bytes > NATIVE_LIFECYCLE_CUSTODY_MAX_RETAINED_BYTES {
        return Err("native lifecycle custody retained byte limit is exceeded".to_owned());
    }
    let entry = NativeLifecycleCustodyEntry {
        profile: NATIVE_LIFECYCLE_CUSTODY_ENTRY_PROFILE.to_owned(),
        entry_digest: digest_json(ENTRY_DIGEST_DOMAIN, &(&handle, request, request_bytes))?,
        handle: handle.clone(),
        request: request.clone(),
        normalized_request_bytes: request_bytes,
    };
    validate_native_lifecycle_custody_entry(&key, &entry)?;
    let mut successor = registry.clone();
    successor.entries.insert(key, entry);
    successor.entry_count = successor.entries.len();
    successor.retained_request_bytes = retained_request_bytes;
    successor.root_digest = digest_json(ROOT_DIGEST_DOMAIN, &successor.entries)?;
    validate_native_lifecycle_custody_registry(&successor)?;
    Ok((successor, handle))
}

pub fn resolve_native_lifecycle_custody(
    registry: &NativeLifecycleCustodyRegistry,
    handle: &NativeLifecycleCustodyHandle,
) -> Result<NativeLifecycleValidationRequest, String> {
    validate_native_lifecycle_custody_registry(registry)?;
    validate_native_lifecycle_custody_handle(handle)?;
    let entry = registry
        .entries
        .get(&handle.request_digest.value)
        .ok_or_else(|| "native lifecycle custody handle is not registered".to_owned())?;
    if &entry.handle != handle {
        return Err("native lifecycle custody handle differs from retained identity".to_owned());
    }
    validate_native_lifecycle_custody_entry(&handle.request_digest.value, entry)?;
    Ok(entry.request.clone())
}

pub fn validate_native_lifecycle_from_custody(
    registry: &NativeLifecycleCustodyRegistry,
    handle: &NativeLifecycleCustodyHandle,
) -> Result<NativeLifecycleValidationResponse, String> {
    let request = resolve_native_lifecycle_custody(registry, handle)?;
    Ok(validate_native_lifecycle_request(&request))
}

pub fn validate_native_lifecycle_custody_handle(
    handle: &NativeLifecycleCustodyHandle,
) -> Result<(), String> {
    if handle.profile != NATIVE_LIFECYCLE_CUSTODY_HANDLE_PROFILE
        || !valid_sha256(&handle.request_digest)
    {
        return Err("native lifecycle custody handle identity is invalid".to_owned());
    }
    Ok(())
}

pub fn validate_native_lifecycle_custody_registry(
    registry: &NativeLifecycleCustodyRegistry,
) -> Result<(), String> {
    if registry.profile != NATIVE_LIFECYCLE_CUSTODY_REGISTRY_PROFILE
        || !registry.in_memory_only
        || registry.persistence_claimed
        || registry.authentication_claimed
        || registry.authorization_claimed
        || registry.external_effect_claimed
        || registry.nonclaims != custody_nonclaims()
    {
        return Err("native lifecycle custody registry identity or claims are invalid".to_owned());
    }
    if registry.entry_count != registry.entries.len()
        || registry.entry_count > NATIVE_LIFECYCLE_CUSTODY_MAX_ENTRIES
    {
        return Err("native lifecycle custody entry count is invalid".to_owned());
    }
    let mut retained_request_bytes = 0_u64;
    for (key, entry) in &registry.entries {
        validate_native_lifecycle_custody_entry(key, entry)?;
        retained_request_bytes = retained_request_bytes
            .checked_add(entry.normalized_request_bytes)
            .ok_or_else(|| "native lifecycle custody retained byte count overflow".to_owned())?;
    }
    if retained_request_bytes != registry.retained_request_bytes
        || retained_request_bytes > NATIVE_LIFECYCLE_CUSTODY_MAX_RETAINED_BYTES
    {
        return Err("native lifecycle custody retained byte account is invalid".to_owned());
    }
    if registry.root_digest != digest_json(ROOT_DIGEST_DOMAIN, &registry.entries)? {
        return Err("native lifecycle custody root digest differs from entries".to_owned());
    }
    Ok(())
}

fn validate_native_lifecycle_custody_entry(
    key: &str,
    entry: &NativeLifecycleCustodyEntry,
) -> Result<(), String> {
    if entry.profile != NATIVE_LIFECYCLE_CUSTODY_ENTRY_PROFILE
        || key != entry.handle.request_digest.value
        || !valid_digest_key(key)
    {
        return Err("native lifecycle custody entry identity or key is invalid".to_owned());
    }
    validate_native_lifecycle_custody_handle(&entry.handle)?;
    let bytes = normalized_request_bytes(&entry.request)?;
    let request_bytes = u64::try_from(bytes.len())
        .map_err(|_| "native lifecycle request byte count cannot be represented".to_owned())?;
    if request_bytes != entry.normalized_request_bytes
        || entry.handle != compile_native_lifecycle_custody_handle(&entry.request)?
    {
        return Err("native lifecycle custody entry differs from retained request".to_owned());
    }
    if entry.entry_digest
        != digest_json(
            ENTRY_DIGEST_DOMAIN,
            &(&entry.handle, &entry.request, request_bytes),
        )?
    {
        return Err("native lifecycle custody entry digest differs from values".to_owned());
    }
    Ok(())
}

fn normalized_request_bytes(request: &NativeLifecycleValidationRequest) -> Result<Vec<u8>, String> {
    let bytes = serde_json::to_vec(request)
        .map_err(|error| format!("native lifecycle custody serialization failed: {error}"))?;
    if bytes.len() > NATIVE_LIFECYCLE_MAX_INPUT_BYTES {
        return Err(format!(
            "native lifecycle custody request contains {} bytes; maximum is {}",
            bytes.len(),
            NATIVE_LIFECYCLE_MAX_INPUT_BYTES
        ));
    }
    Ok(bytes)
}

fn digest_json<T: Serialize>(domain: &str, value: &T) -> Result<ContentDigest, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("native lifecycle custody digest failed: {error}"))?;
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

fn sha256_bytes(bytes: &[u8]) -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    }
}

fn valid_sha256(digest: &ContentDigest) -> bool {
    digest.algorithm == "sha256" && valid_digest_key(&digest.value)
}

fn valid_digest_key(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn custody_nonclaims() -> Vec<String> {
    NATIVE_LIFECYCLE_CUSTODY_NONCLAIMS
        .iter()
        .map(ToString::to_string)
        .collect()
}
