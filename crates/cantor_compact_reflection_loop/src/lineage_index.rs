//! Digest-only table of contents for the complete provider-free attention lineage.

use cantor_core::ContentDigest;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    generate_attention_reentry_measurement, generate_dispatch_checkpoint_handle_measurement,
    generate_fixture_deterministic_drive_measurement, generate_iterative_transcript_measurement,
    generate_scripted_compact_transport_projection, generate_scripted_complete_fixture,
    generate_scripted_dispatch_resume_corpus, generate_scripted_effectless_dispatch_run,
    generate_scripted_terminal_pending_fixture, generate_scripted_tool_cap_fixture,
    generate_scripted_transport_envelope_set,
};

pub const PROVIDER_FREE_ATTENTION_LINEAGE_INDEX_PROFILE: &str =
    "cantor-provider-free-attention-lineage-index/0.1";
pub const PROVIDER_FREE_ATTENTION_LINEAGE_INDEX_NONCLAIMS: [&str; 6] = [
    "artifact commitments identify deterministic generated fixture bytes only",
    "lineage index is not provider execution or physical provenance",
    "content digests are not producer signatures or authorization",
    "capability true is limited to provider-free verified form behavior",
    "capability false remains locked pending separately governed evidence",
    "no process network persistence remote hidden-state external-effect or Minecraft operation",
];

const ARTIFACT_DIGEST_DOMAIN: &str = "cantor.provider-free-lineage.artifact.v1";
const ROOT_DIGEST_DOMAIN: &str = "cantor.provider-free-lineage.root.v1";

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderFreeLineageArtifactKind {
    DeterministicDriveMeasurement,
    ScriptedCompleteRun,
    ScriptedToolCapStoppedRun,
    ScriptedTerminalPendingRun,
    IterativeTranscriptMeasurement,
    AttentionReentryMeasurement,
    DualTranscriptProjection,
    TransportEnvelopeSet,
    EffectlessDispatchRun,
    DispatchResumeCorpus,
    CheckpointHandleMeasurement,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderFreeLineageArtifactCommitment {
    pub ordinal: u32,
    pub kind: ProviderFreeLineageArtifactKind,
    pub artifact_profile: String,
    pub compact_json_bytes: usize,
    pub content_digest: ContentDigest,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderFreeCapabilityLedger {
    pub provider_free_execution: bool,
    pub ready_to_terminal: bool,
    pub stopped_resume: bool,
    pub terminal_pending_admission: bool,
    pub canonical_replay: bool,
    pub compact_transport: bool,
    pub packet_integrity: bool,
    pub dispatch_staging: bool,
    pub checkpoint_resume: bool,
    pub byte_measurement: bool,
    pub live_provider_execution: bool,
    pub physical_persistence: bool,
    pub semantic_model_equivalence: bool,
    pub hidden_state_integration: bool,
    pub external_effects: bool,
    pub remote_execution: bool,
    pub minecraft_scope: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderFreeAttentionLineageIndex {
    pub profile: String,
    pub artifacts: Vec<ProviderFreeLineageArtifactCommitment>,
    pub artifact_count: usize,
    pub lineage_root_digest: ContentDigest,
    pub capabilities: ProviderFreeCapabilityLedger,
    pub remote_hosts: Vec<String>,
    pub external_effect_records: Vec<String>,
    pub private_reasoning_recorded: bool,
    pub nonclaims: Vec<String>,
}

pub fn generate_provider_free_attention_lineage_index()
-> Result<ProviderFreeAttentionLineageIndex, String> {
    let artifacts = expected_artifacts()?;
    let index = ProviderFreeAttentionLineageIndex {
        profile: PROVIDER_FREE_ATTENTION_LINEAGE_INDEX_PROFILE.to_owned(),
        artifact_count: artifacts.len(),
        lineage_root_digest: digest_json(ROOT_DIGEST_DOMAIN, &artifacts)?,
        artifacts,
        capabilities: expected_capabilities(),
        remote_hosts: Vec::new(),
        external_effect_records: Vec::new(),
        private_reasoning_recorded: false,
        nonclaims: index_nonclaims(),
    };
    validate_provider_free_attention_lineage_index(&index)?;
    Ok(index)
}

pub fn validate_provider_free_attention_lineage_index(
    index: &ProviderFreeAttentionLineageIndex,
) -> Result<(), String> {
    if index.profile != PROVIDER_FREE_ATTENTION_LINEAGE_INDEX_PROFILE
        || index.capabilities != expected_capabilities()
        || !index.remote_hosts.is_empty()
        || !index.external_effect_records.is_empty()
        || index.private_reasoning_recorded
        || index.nonclaims != index_nonclaims()
    {
        return Err(
            "provider-free lineage index identity claims or denials are invalid".to_owned(),
        );
    }
    let expected = expected_artifacts()?;
    if index.artifact_count != expected.len() || index.artifacts != expected {
        return Err("provider-free lineage artifacts differ from regeneration".to_owned());
    }
    if index.lineage_root_digest != digest_json(ROOT_DIGEST_DOMAIN, &index.artifacts)? {
        return Err("provider-free lineage root digest differs from artifacts".to_owned());
    }
    Ok(())
}

pub fn pretty_provider_free_attention_lineage_index_bytes(
    index: &ProviderFreeAttentionLineageIndex,
) -> Result<Vec<u8>, String> {
    validate_provider_free_attention_lineage_index(index)?;
    let mut bytes = serde_json::to_vec_pretty(index)
        .map_err(|error| format!("provider-free lineage serialization failed: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn expected_artifacts() -> Result<Vec<ProviderFreeLineageArtifactCommitment>, String> {
    let drive = generate_fixture_deterministic_drive_measurement()?;
    let complete = generate_scripted_complete_fixture()?;
    let stopped = generate_scripted_tool_cap_fixture()?;
    let pending = generate_scripted_terminal_pending_fixture()?;
    let transcript = generate_iterative_transcript_measurement()?;
    let reentry = generate_attention_reentry_measurement()?;
    let dual = generate_scripted_compact_transport_projection()?;
    let envelopes = generate_scripted_transport_envelope_set()?;
    let dispatch = generate_scripted_effectless_dispatch_run()?;
    let resume = generate_scripted_dispatch_resume_corpus()?;
    let handles = generate_dispatch_checkpoint_handle_measurement()?;
    Ok(vec![
        commit_artifact(
            0,
            ProviderFreeLineageArtifactKind::DeterministicDriveMeasurement,
            &drive.profile,
            &drive,
        )?,
        commit_artifact(
            1,
            ProviderFreeLineageArtifactKind::ScriptedCompleteRun,
            &complete.profile,
            &complete,
        )?,
        commit_artifact(
            2,
            ProviderFreeLineageArtifactKind::ScriptedToolCapStoppedRun,
            &stopped.profile,
            &stopped,
        )?,
        commit_artifact(
            3,
            ProviderFreeLineageArtifactKind::ScriptedTerminalPendingRun,
            &pending.profile,
            &pending,
        )?,
        commit_artifact(
            4,
            ProviderFreeLineageArtifactKind::IterativeTranscriptMeasurement,
            &transcript.profile,
            &transcript,
        )?,
        commit_artifact(
            5,
            ProviderFreeLineageArtifactKind::AttentionReentryMeasurement,
            &reentry.profile,
            &reentry,
        )?,
        commit_artifact(
            6,
            ProviderFreeLineageArtifactKind::DualTranscriptProjection,
            &dual.profile,
            &dual,
        )?,
        commit_artifact(
            7,
            ProviderFreeLineageArtifactKind::TransportEnvelopeSet,
            &envelopes.profile,
            &envelopes,
        )?,
        commit_artifact(
            8,
            ProviderFreeLineageArtifactKind::EffectlessDispatchRun,
            &dispatch.profile,
            &dispatch,
        )?,
        commit_artifact(
            9,
            ProviderFreeLineageArtifactKind::DispatchResumeCorpus,
            &resume.profile,
            &resume,
        )?,
        commit_artifact(
            10,
            ProviderFreeLineageArtifactKind::CheckpointHandleMeasurement,
            &handles.profile,
            &handles,
        )?,
    ])
}

fn commit_artifact<T: Serialize>(
    ordinal: usize,
    kind: ProviderFreeLineageArtifactKind,
    profile: &str,
    value: &T,
) -> Result<ProviderFreeLineageArtifactCommitment, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("provider-free artifact serialization failed: {error}"))?;
    Ok(ProviderFreeLineageArtifactCommitment {
        ordinal: u32::try_from(ordinal)
            .map_err(|_| "provider-free lineage ordinal cannot be represented".to_owned())?,
        kind,
        artifact_profile: profile.to_owned(),
        compact_json_bytes: bytes.len(),
        content_digest: digest_bytes(artifact_domain(kind).as_bytes(), &bytes),
    })
}

fn artifact_domain(kind: ProviderFreeLineageArtifactKind) -> String {
    format!("{ARTIFACT_DIGEST_DOMAIN}.{}", kind_label(kind))
}

fn kind_label(kind: ProviderFreeLineageArtifactKind) -> &'static str {
    match kind {
        ProviderFreeLineageArtifactKind::DeterministicDriveMeasurement => "deterministic_drive",
        ProviderFreeLineageArtifactKind::ScriptedCompleteRun => "scripted_complete",
        ProviderFreeLineageArtifactKind::ScriptedToolCapStoppedRun => "tool_cap_stopped",
        ProviderFreeLineageArtifactKind::ScriptedTerminalPendingRun => "terminal_pending",
        ProviderFreeLineageArtifactKind::IterativeTranscriptMeasurement => "transcript_measurement",
        ProviderFreeLineageArtifactKind::AttentionReentryMeasurement => "attention_reentry",
        ProviderFreeLineageArtifactKind::DualTranscriptProjection => "dual_transcript",
        ProviderFreeLineageArtifactKind::TransportEnvelopeSet => "transport_envelopes",
        ProviderFreeLineageArtifactKind::EffectlessDispatchRun => "effectless_dispatch",
        ProviderFreeLineageArtifactKind::DispatchResumeCorpus => "dispatch_resume",
        ProviderFreeLineageArtifactKind::CheckpointHandleMeasurement => "checkpoint_handles",
    }
}

fn expected_capabilities() -> ProviderFreeCapabilityLedger {
    ProviderFreeCapabilityLedger {
        provider_free_execution: true,
        ready_to_terminal: true,
        stopped_resume: true,
        terminal_pending_admission: true,
        canonical_replay: true,
        compact_transport: true,
        packet_integrity: true,
        dispatch_staging: true,
        checkpoint_resume: true,
        byte_measurement: true,
        live_provider_execution: false,
        physical_persistence: false,
        semantic_model_equivalence: false,
        hidden_state_integration: false,
        external_effects: false,
        remote_execution: false,
        minecraft_scope: false,
    }
}

fn digest_json<T: Serialize>(domain: &str, value: &T) -> Result<ContentDigest, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("provider-free lineage digest serialization failed: {error}"))?;
    Ok(digest_bytes(domain.as_bytes(), &bytes))
}

fn digest_bytes(domain: &[u8], bytes: &[u8]) -> ContentDigest {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update([0]);
    hasher.update(bytes);
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    }
}

fn index_nonclaims() -> Vec<String> {
    PROVIDER_FREE_ATTENTION_LINEAGE_INDEX_NONCLAIMS
        .iter()
        .map(ToString::to_string)
        .collect()
}
