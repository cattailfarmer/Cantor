//! Additive digest-only release manifest for the provider-free fixture shell.

use cantor_core::ContentDigest;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    CHECKPOINT_CUSTODY_QUERY_PROFILE, CHECKPOINT_CUSTODY_RESPONSE_PROFILE,
    generate_custody_query_surface_measurement, generate_provider_free_attention_lineage_index,
    generate_scripted_checkpoint_custody_registry, pretty_checkpoint_custody_registry_bytes,
    pretty_custody_query_surface_measurement_bytes,
    pretty_provider_free_attention_lineage_index_bytes,
};

pub const PROVIDER_FREE_SHELL_RELEASE_MANIFEST_PROFILE: &str =
    "cantor-provider-free-shell-release-manifest/0.1";
pub const PROVIDER_FREE_SHELL_RELEASE_KIND: &str = "provider_free_fixture_shell_release_candidate";
pub const PROVIDER_FREE_SHELL_RELEASE_NONCLAIMS: [&str; 7] = [
    "release manifest summarizes evidence and does not embed or replace it",
    "historical lineage root commits artifacts only through Slice6G",
    "proof file digests are repository identity evidence and not producer signatures",
    "provider-free release candidate is not a live model inference runtime",
    "content digests are not authentication authorization semantic truth or provenance",
    "byte measurements are not token latency memory quality or compatibility evidence",
    "no process network persistence remote hidden-state external-effect FPGA or Minecraft operation",
];

const RELEASE_ROOT_DOMAIN: &str = "cantor.provider-free-shell.release-root.v1";

const PROOF_FILES: [(&str, &str, &[u8]); 17] = [
    (
        "slice1",
        "proofs/Cantor_Iterative_Attention_Procedure_Loop_P1_Slice1_Proof.sop",
        include_bytes!(
            "../../../proofs/Cantor_Iterative_Attention_Procedure_Loop_P1_Slice1_Proof.sop"
        ),
    ),
    (
        "slice2",
        "proofs/Cantor_Iterative_Attention_Procedure_Loop_P1_Slice2_Proof.sop",
        include_bytes!(
            "../../../proofs/Cantor_Iterative_Attention_Procedure_Loop_P1_Slice2_Proof.sop"
        ),
    ),
    (
        "slice3",
        "proofs/Cantor_Iterative_Attention_Procedure_Loop_P1_Slice3_Proof.sop",
        include_bytes!(
            "../../../proofs/Cantor_Iterative_Attention_Procedure_Loop_P1_Slice3_Proof.sop"
        ),
    ),
    (
        "slice4a",
        "proofs/Cantor_Iterative_Attention_Procedure_Loop_P1_Slice4A_Proof.sop",
        include_bytes!(
            "../../../proofs/Cantor_Iterative_Attention_Procedure_Loop_P1_Slice4A_Proof.sop"
        ),
    ),
    (
        "slice4b",
        "proofs/Cantor_Iterative_Attention_Procedure_Loop_P1_Slice4B_Proof.sop",
        include_bytes!(
            "../../../proofs/Cantor_Iterative_Attention_Procedure_Loop_P1_Slice4B_Proof.sop"
        ),
    ),
    (
        "slice4c",
        "proofs/Cantor_Iterative_Attention_Procedure_Loop_P1_Slice4C_Proof.sop",
        include_bytes!(
            "../../../proofs/Cantor_Iterative_Attention_Procedure_Loop_P1_Slice4C_Proof.sop"
        ),
    ),
    (
        "slice6a",
        "proofs/Cantor_Iterative_Attention_Procedure_Loop_P1_Slice6A_Proof.sop",
        include_bytes!(
            "../../../proofs/Cantor_Iterative_Attention_Procedure_Loop_P1_Slice6A_Proof.sop"
        ),
    ),
    (
        "slice6b",
        "proofs/Cantor_Iterative_Attention_Procedure_Loop_P1_Slice6B_Proof.sop",
        include_bytes!(
            "../../../proofs/Cantor_Iterative_Attention_Procedure_Loop_P1_Slice6B_Proof.sop"
        ),
    ),
    (
        "slice6c",
        "proofs/Cantor_Iterative_Attention_Procedure_Loop_P1_Slice6C_Proof.sop",
        include_bytes!(
            "../../../proofs/Cantor_Iterative_Attention_Procedure_Loop_P1_Slice6C_Proof.sop"
        ),
    ),
    (
        "slice6d",
        "proofs/Cantor_Iterative_Attention_Procedure_Loop_P1_Slice6D_Proof.sop",
        include_bytes!(
            "../../../proofs/Cantor_Iterative_Attention_Procedure_Loop_P1_Slice6D_Proof.sop"
        ),
    ),
    (
        "slice6e",
        "proofs/Cantor_Iterative_Attention_Procedure_Loop_P1_Slice6E_Proof.sop",
        include_bytes!(
            "../../../proofs/Cantor_Iterative_Attention_Procedure_Loop_P1_Slice6E_Proof.sop"
        ),
    ),
    (
        "slice6f",
        "proofs/Cantor_Iterative_Attention_Procedure_Loop_P1_Slice6F_Proof.sop",
        include_bytes!(
            "../../../proofs/Cantor_Iterative_Attention_Procedure_Loop_P1_Slice6F_Proof.sop"
        ),
    ),
    (
        "slice6g",
        "proofs/Cantor_Iterative_Attention_Procedure_Loop_P1_Slice6G_Proof.sop",
        include_bytes!(
            "../../../proofs/Cantor_Iterative_Attention_Procedure_Loop_P1_Slice6G_Proof.sop"
        ),
    ),
    (
        "slice7a",
        "proofs/Cantor_Iterative_Attention_Procedure_Loop_P1_Slice7A_Proof.sop",
        include_bytes!(
            "../../../proofs/Cantor_Iterative_Attention_Procedure_Loop_P1_Slice7A_Proof.sop"
        ),
    ),
    (
        "slice7b",
        "proofs/Cantor_Iterative_Attention_Procedure_Loop_P1_Slice7B_Proof.sop",
        include_bytes!(
            "../../../proofs/Cantor_Iterative_Attention_Procedure_Loop_P1_Slice7B_Proof.sop"
        ),
    ),
    (
        "slice7c",
        "proofs/Cantor_Iterative_Attention_Procedure_Loop_P1_Slice7C_Proof.sop",
        include_bytes!(
            "../../../proofs/Cantor_Iterative_Attention_Procedure_Loop_P1_Slice7C_Proof.sop"
        ),
    ),
    (
        "slice7d",
        "proofs/Cantor_Iterative_Attention_Procedure_Loop_P1_Slice7D_Proof.sop",
        include_bytes!(
            "../../../proofs/Cantor_Iterative_Attention_Procedure_Loop_P1_Slice7D_Proof.sop"
        ),
    ),
];

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReleaseArtifactIdentity {
    pub profile: String,
    pub root_digest: ContentDigest,
    pub item_count: usize,
    pub normalized_pretty_json_bytes: usize,
    pub normalized_pretty_json_sha256: ContentDigest,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReleaseQueryIdentity {
    pub request_profile: String,
    pub response_profile: String,
    pub operations: Vec<String>,
    pub operation_count: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReleaseMeasurementIdentity {
    pub profile: String,
    pub source_cases_digest: ContentDigest,
    pub case_count: usize,
    pub total_inspect_response_bytes: usize,
    pub total_resolve_response_bytes: usize,
    pub total_resolve_minus_inspect_response_bytes: i64,
    pub minimum_inspect_response_bytes: usize,
    pub maximum_inspect_response_bytes: usize,
    pub inspect_to_resolve_response_basis_points: u64,
    pub all_inspect_responses_smaller: bool,
    pub normalized_pretty_json_bytes: usize,
    pub normalized_pretty_json_sha256: ContentDigest,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReleaseProofCommitment {
    pub ordinal: u32,
    pub slice: String,
    pub repository_path: String,
    pub bytes: usize,
    pub sha256: ContentDigest,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderFreeShellReleaseCapabilities {
    pub deterministic_provider_free_loop: bool,
    pub ready_to_terminal: bool,
    pub stopped_and_terminal_pending_resume: bool,
    pub canonical_replay: bool,
    pub compact_reentry: bool,
    pub effectless_dispatch: bool,
    pub checkpoint_custody: bool,
    pub typed_custody_query: bool,
    pub query_surface_measurement: bool,
    pub live_provider_execution: bool,
    pub physical_persistence: bool,
    pub handle_discovery: bool,
    pub producer_signing: bool,
    pub tokenizer_measurement: bool,
    pub semantic_model_equivalence: bool,
    pub hidden_state_integration: bool,
    pub external_effects: bool,
    pub remote_execution: bool,
    pub fpga_execution: bool,
    pub minecraft_scope: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderFreeShellReleaseManifest {
    pub profile: String,
    pub release_kind: String,
    pub historical_lineage: ReleaseArtifactIdentity,
    pub checkpoint_custody: ReleaseArtifactIdentity,
    pub custody_query: ReleaseQueryIdentity,
    pub query_measurement: ReleaseMeasurementIdentity,
    pub proofs: Vec<ReleaseProofCommitment>,
    pub proof_count: usize,
    pub capabilities: ProviderFreeShellReleaseCapabilities,
    pub request_bodies_embedded: bool,
    pub response_bodies_embedded: bool,
    pub message_bodies_embedded: bool,
    pub checkpoint_bodies_embedded: bool,
    pub registry_bodies_embedded: bool,
    pub proof_bodies_embedded: bool,
    pub release_root_digest: ContentDigest,
    pub nonclaims: Vec<String>,
}

pub fn generate_provider_free_shell_release_manifest()
-> Result<ProviderFreeShellReleaseManifest, String> {
    expected_manifest()
}

pub fn validate_provider_free_shell_release_manifest(
    manifest: &ProviderFreeShellReleaseManifest,
) -> Result<(), String> {
    if manifest.profile != PROVIDER_FREE_SHELL_RELEASE_MANIFEST_PROFILE
        || manifest.release_kind != PROVIDER_FREE_SHELL_RELEASE_KIND
        || manifest.request_bodies_embedded
        || manifest.response_bodies_embedded
        || manifest.message_bodies_embedded
        || manifest.checkpoint_bodies_embedded
        || manifest.registry_bodies_embedded
        || manifest.proof_bodies_embedded
        || manifest.nonclaims != release_nonclaims()
    {
        return Err("provider-free shell release identity or boundaries are invalid".to_owned());
    }
    if manifest.proof_count != manifest.proofs.len()
        || manifest.proofs != proof_commitments()?
        || manifest.custody_query.operation_count != manifest.custody_query.operations.len()
        || manifest.capabilities != expected_capabilities()
    {
        return Err(
            "provider-free shell release counts proofs or capabilities are invalid".to_owned(),
        );
    }
    if manifest.release_root_digest != release_root(manifest)? {
        return Err("provider-free shell release root differs from committed fields".to_owned());
    }
    let expected = expected_manifest()?;
    if manifest != &expected {
        return Err("provider-free shell release manifest differs from reconstruction".to_owned());
    }
    Ok(())
}

pub fn pretty_provider_free_shell_release_manifest_bytes(
    manifest: &ProviderFreeShellReleaseManifest,
) -> Result<Vec<u8>, String> {
    validate_provider_free_shell_release_manifest(manifest)?;
    let mut bytes = serde_json::to_vec_pretty(manifest)
        .map_err(|error| format!("provider-free release serialization failed: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn expected_manifest() -> Result<ProviderFreeShellReleaseManifest, String> {
    let lineage = generate_provider_free_attention_lineage_index()?;
    let lineage_bytes = pretty_provider_free_attention_lineage_index_bytes(&lineage)?;
    let registry = generate_scripted_checkpoint_custody_registry()?;
    let registry_bytes = pretty_checkpoint_custody_registry_bytes(&registry)?;
    let measurement = generate_custody_query_surface_measurement()?;
    let measurement_bytes = pretty_custody_query_surface_measurement_bytes(&measurement)?;
    let historical_lineage = ReleaseArtifactIdentity {
        profile: lineage.profile,
        root_digest: lineage.lineage_root_digest,
        item_count: lineage.artifact_count,
        normalized_pretty_json_bytes: lineage_bytes.len(),
        normalized_pretty_json_sha256: raw_sha256(&lineage_bytes),
    };
    let checkpoint_custody = ReleaseArtifactIdentity {
        profile: registry.profile,
        root_digest: registry.root_digest,
        item_count: registry.entry_count,
        normalized_pretty_json_bytes: registry_bytes.len(),
        normalized_pretty_json_sha256: raw_sha256(&registry_bytes),
    };
    let custody_query = ReleaseQueryIdentity {
        request_profile: CHECKPOINT_CUSTODY_QUERY_PROFILE.to_owned(),
        response_profile: CHECKPOINT_CUSTODY_RESPONSE_PROFILE.to_owned(),
        operations: ["inspect", "resolve", "resume_iteration", "resume_terminal"]
            .iter()
            .map(ToString::to_string)
            .collect(),
        operation_count: 4,
    };
    let query_measurement = ReleaseMeasurementIdentity {
        profile: measurement.profile,
        source_cases_digest: measurement.source_cases_digest,
        case_count: measurement.case_count,
        total_inspect_response_bytes: measurement.total_inspect_response_bytes,
        total_resolve_response_bytes: measurement.total_resolve_response_bytes,
        total_resolve_minus_inspect_response_bytes: measurement
            .total_resolve_minus_inspect_response_bytes,
        minimum_inspect_response_bytes: measurement.minimum_inspect_response_bytes,
        maximum_inspect_response_bytes: measurement.maximum_inspect_response_bytes,
        inspect_to_resolve_response_basis_points: measurement
            .inspect_to_resolve_response_basis_points,
        all_inspect_responses_smaller: measurement.all_inspect_responses_smaller,
        normalized_pretty_json_bytes: measurement_bytes.len(),
        normalized_pretty_json_sha256: raw_sha256(&measurement_bytes),
    };
    let proofs = proof_commitments()?;
    let proof_count = proofs.len();
    let capabilities = expected_capabilities();
    let nonclaims = release_nonclaims();
    let mut manifest = ProviderFreeShellReleaseManifest {
        profile: PROVIDER_FREE_SHELL_RELEASE_MANIFEST_PROFILE.to_owned(),
        release_kind: PROVIDER_FREE_SHELL_RELEASE_KIND.to_owned(),
        historical_lineage,
        checkpoint_custody,
        custody_query,
        query_measurement,
        proofs,
        proof_count,
        capabilities,
        request_bodies_embedded: false,
        response_bodies_embedded: false,
        message_bodies_embedded: false,
        checkpoint_bodies_embedded: false,
        registry_bodies_embedded: false,
        proof_bodies_embedded: false,
        release_root_digest: ContentDigest {
            algorithm: "sha256".to_owned(),
            value: "0".repeat(64),
        },
        nonclaims,
    };
    manifest.release_root_digest = release_root(&manifest)?;
    Ok(manifest)
}

fn release_root(manifest: &ProviderFreeShellReleaseManifest) -> Result<ContentDigest, String> {
    digest_json(
        RELEASE_ROOT_DOMAIN,
        &(
            &manifest.profile,
            &manifest.release_kind,
            &manifest.historical_lineage,
            &manifest.checkpoint_custody,
            &manifest.custody_query,
            &manifest.query_measurement,
            &manifest.proofs,
            manifest.proof_count,
            &manifest.capabilities,
            manifest.request_bodies_embedded,
            manifest.response_bodies_embedded,
            manifest.message_bodies_embedded,
            manifest.checkpoint_bodies_embedded,
            manifest.registry_bodies_embedded,
            manifest.proof_bodies_embedded,
            &manifest.nonclaims,
        ),
    )
}

fn proof_commitments() -> Result<Vec<ReleaseProofCommitment>, String> {
    PROOF_FILES
        .iter()
        .enumerate()
        .map(|(ordinal, (slice, path, bytes))| {
            Ok(ReleaseProofCommitment {
                ordinal: u32::try_from(ordinal)
                    .map_err(|_| "release proof ordinal cannot be represented".to_owned())?,
                slice: (*slice).to_owned(),
                repository_path: (*path).to_owned(),
                bytes: bytes.len(),
                sha256: raw_sha256(bytes),
            })
        })
        .collect()
}

fn expected_capabilities() -> ProviderFreeShellReleaseCapabilities {
    ProviderFreeShellReleaseCapabilities {
        deterministic_provider_free_loop: true,
        ready_to_terminal: true,
        stopped_and_terminal_pending_resume: true,
        canonical_replay: true,
        compact_reentry: true,
        effectless_dispatch: true,
        checkpoint_custody: true,
        typed_custody_query: true,
        query_surface_measurement: true,
        live_provider_execution: false,
        physical_persistence: false,
        handle_discovery: false,
        producer_signing: false,
        tokenizer_measurement: false,
        semantic_model_equivalence: false,
        hidden_state_integration: false,
        external_effects: false,
        remote_execution: false,
        fpga_execution: false,
        minecraft_scope: false,
    }
}

fn raw_sha256(bytes: &[u8]) -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    }
}

fn digest_json<T: Serialize>(domain: &str, value: &T) -> Result<ContentDigest, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("provider-free release root serialization failed: {error}"))?;
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

fn release_nonclaims() -> Vec<String> {
    PROVIDER_FREE_SHELL_RELEASE_NONCLAIMS
        .iter()
        .map(ToString::to_string)
        .collect()
}
