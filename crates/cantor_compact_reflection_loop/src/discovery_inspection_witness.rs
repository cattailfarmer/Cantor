//! Provider-free bootstrap, pin, rediscover, and compact-inspect workflow witness.

use cantor_core::ContentDigest;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    CHECKPOINT_CUSTODY_QUERY_PROFILE, CHECKPOINT_HANDLE_DISCOVERY_SELECTOR_PROFILE,
    CheckpointCustodyOperation, CheckpointCustodyQuery, CheckpointCustodyResponse,
    CheckpointCustodyResult, CheckpointHandleDiscoveryResponse, CheckpointHandleDiscoverySelector,
    discover_checkpoint_handles, dispatch_checkpoint_custody_query,
    generate_scripted_checkpoint_custody_registry, validate_checkpoint_custody_response,
    validate_checkpoint_handle_discovery_response,
};

pub const DISCOVERY_INSPECTION_WITNESS_PROFILE: &str = "cantor-discovery-inspection-witness/0.1";
pub const DISCOVERY_INSPECTION_WITNESS_NONCLAIMS: [&str; 6] = [
    "workflow is deterministic provider-free protocol composition",
    "first digest-ordered handle is fixture policy and not semantic relevance",
    "witness is not live model tool selection reflection or understanding",
    "workflow digest is not authentication authorization provenance or truth",
    "witness embeds no full checkpoint request response message or transport body",
    "no filesystem provider process network persistence hidden-state or external effect",
];

const WORKFLOW_DIGEST_DOMAIN: &str = "cantor.discovery-inspection-witness.workflow.v1";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScriptedDiscoveryInspectionWitness {
    pub profile: String,
    pub bootstrap_selector: CheckpointHandleDiscoverySelector,
    pub bootstrap_response: CheckpointHandleDiscoveryResponse,
    pub pinned_selector: CheckpointHandleDiscoverySelector,
    pub pinned_response: CheckpointHandleDiscoveryResponse,
    pub inspection_query: CheckpointCustodyQuery,
    pub inspection_response: CheckpointCustodyResponse,
    pub workflow_digest: ContentDigest,
    pub checkpoint_bodies_embedded: bool,
    pub request_bodies_embedded: bool,
    pub response_bodies_embedded: bool,
    pub message_bodies_embedded: bool,
    pub transport_bodies_embedded: bool,
    pub provider_execution_claimed: bool,
    pub persistence_claimed: bool,
    pub semantic_relevance_claimed: bool,
    pub nonclaims: Vec<String>,
}

pub fn generate_scripted_discovery_inspection_witness()
-> Result<ScriptedDiscoveryInspectionWitness, String> {
    let registry = generate_scripted_checkpoint_custody_registry()?;
    let bootstrap_selector = CheckpointHandleDiscoverySelector {
        profile: CHECKPOINT_HANDLE_DISCOVERY_SELECTOR_PROFILE.to_owned(),
        expected_registry_root: None,
        checkpoint_phase: None,
        next_operation: None,
        transport_position: None,
        terminal_reflection: None,
        checkpoint_digest_prefix: None,
        maximum_results: 1,
    };
    let bootstrap_response = discover_checkpoint_handles(&registry, &bootstrap_selector)?;
    let selected = bootstrap_response
        .matches
        .first()
        .ok_or_else(|| "discovery inspection bootstrap returned no handle".to_owned())?;
    let pinned_selector = CheckpointHandleDiscoverySelector {
        profile: CHECKPOINT_HANDLE_DISCOVERY_SELECTOR_PROFILE.to_owned(),
        expected_registry_root: Some(bootstrap_response.registry_root.clone()),
        checkpoint_phase: None,
        next_operation: None,
        transport_position: None,
        terminal_reflection: None,
        checkpoint_digest_prefix: Some(selected.handle.checkpoint_digest.value.clone()),
        maximum_results: 1,
    };
    let pinned_response = discover_checkpoint_handles(&registry, &pinned_selector)?;
    let pinned = pinned_response
        .matches
        .first()
        .ok_or_else(|| "discovery inspection pinned query returned no handle".to_owned())?;
    if selected != pinned {
        return Err("discovery inspection pinned identity differs from bootstrap".to_owned());
    }
    let inspection_query = CheckpointCustodyQuery {
        profile: CHECKPOINT_CUSTODY_QUERY_PROFILE.to_owned(),
        expected_registry_root: pinned_response.registry_root.clone(),
        operation: CheckpointCustodyOperation::Inspect {
            handle: pinned.handle.clone(),
        },
    };
    let inspection_response = dispatch_checkpoint_custody_query(&registry, &inspection_query)?;
    let nonclaims = witness_nonclaims();
    let mut witness = ScriptedDiscoveryInspectionWitness {
        profile: DISCOVERY_INSPECTION_WITNESS_PROFILE.to_owned(),
        bootstrap_selector,
        bootstrap_response,
        pinned_selector,
        pinned_response,
        inspection_query,
        inspection_response,
        workflow_digest: ContentDigest {
            algorithm: "sha256".to_owned(),
            value: "0".repeat(64),
        },
        checkpoint_bodies_embedded: false,
        request_bodies_embedded: false,
        response_bodies_embedded: false,
        message_bodies_embedded: false,
        transport_bodies_embedded: false,
        provider_execution_claimed: false,
        persistence_claimed: false,
        semantic_relevance_claimed: false,
        nonclaims,
    };
    witness.workflow_digest = workflow_digest(&witness)?;
    validate_scripted_discovery_inspection_witness(&witness)?;
    Ok(witness)
}

pub fn validate_scripted_discovery_inspection_witness(
    witness: &ScriptedDiscoveryInspectionWitness,
) -> Result<(), String> {
    if witness.profile != DISCOVERY_INSPECTION_WITNESS_PROFILE
        || witness.checkpoint_bodies_embedded
        || witness.request_bodies_embedded
        || witness.response_bodies_embedded
        || witness.message_bodies_embedded
        || witness.transport_bodies_embedded
        || witness.provider_execution_claimed
        || witness.persistence_claimed
        || witness.semantic_relevance_claimed
        || witness.nonclaims != witness_nonclaims()
    {
        return Err("discovery inspection witness identity or claims are invalid".to_owned());
    }
    let registry = generate_scripted_checkpoint_custody_registry()?;
    validate_checkpoint_handle_discovery_response(
        &registry,
        &witness.bootstrap_selector,
        &witness.bootstrap_response,
    )?;
    validate_checkpoint_handle_discovery_response(
        &registry,
        &witness.pinned_selector,
        &witness.pinned_response,
    )?;
    validate_checkpoint_custody_response(
        &registry,
        &witness.inspection_query,
        &witness.inspection_response,
    )?;
    if witness.bootstrap_selector.expected_registry_root.is_some()
        || witness.bootstrap_selector.maximum_results != 1
        || witness.pinned_selector.expected_registry_root
            != Some(witness.bootstrap_response.registry_root.clone())
        || !witness.pinned_response.caller_root_pinned
        || witness.bootstrap_response.matches.len() != 1
        || witness.pinned_response.matches.len() != 1
        || witness.bootstrap_response.matches != witness.pinned_response.matches
        || witness.inspection_query.expected_registry_root != witness.pinned_response.registry_root
    {
        return Err("discovery inspection witness stage identity is invalid".to_owned());
    }
    let selected = &witness.pinned_response.matches[0];
    match (
        &witness.inspection_query.operation,
        &witness.inspection_response.result,
    ) {
        (
            CheckpointCustodyOperation::Inspect { handle },
            CheckpointCustodyResult::Inspection { inspection },
        ) if handle == &selected.handle
            && inspection.checkpoint_digest == handle.checkpoint_digest
            && inspection.entry_digest == selected.entry_digest
            && inspection.checkpoint_phase == handle.checkpoint_phase
            && inspection.next_operation == handle.next_operation
            && inspection.transport_position == handle.transport_position
            && inspection.terminal_reflection == handle.terminal_reflection
            && !inspection.full_checkpoint_embedded => {}
        _ => return Err("discovery inspection witness inspection identity differs".to_owned()),
    }
    if witness.workflow_digest != workflow_digest(witness)? {
        return Err("discovery inspection witness workflow digest differs".to_owned());
    }
    Ok(())
}

pub fn pretty_scripted_discovery_inspection_witness_bytes(
    witness: &ScriptedDiscoveryInspectionWitness,
) -> Result<Vec<u8>, String> {
    validate_scripted_discovery_inspection_witness(witness)?;
    let mut bytes = serde_json::to_vec_pretty(witness)
        .map_err(|error| format!("discovery inspection witness serialization failed: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn workflow_digest(witness: &ScriptedDiscoveryInspectionWitness) -> Result<ContentDigest, String> {
    digest_json(
        WORKFLOW_DIGEST_DOMAIN,
        &(
            &witness.profile,
            &witness.bootstrap_selector,
            &witness.bootstrap_response,
            &witness.pinned_selector,
            &witness.pinned_response,
            &witness.inspection_query,
            &witness.inspection_response,
            [false; 8],
            &witness.nonclaims,
        ),
    )
}

fn digest_json<T: Serialize>(domain: &str, value: &T) -> Result<ContentDigest, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("discovery inspection witness digest failed: {error}"))?;
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

fn witness_nonclaims() -> Vec<String> {
    DISCOVERY_INSPECTION_WITNESS_NONCLAIMS
        .iter()
        .map(ToString::to_string)
        .collect()
}
