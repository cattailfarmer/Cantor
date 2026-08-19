use std::process::Command;

use cantor_compact_reflection_loop::{
    ProviderFreeAttentionLineageIndex, ProviderFreeLineageArtifactKind,
    generate_provider_free_attention_lineage_index,
    pretty_provider_free_attention_lineage_index_bytes,
    validate_provider_free_attention_lineage_index,
};
use serde_json::Value;

#[test]
fn lineage_index_commits_the_complete_provider_free_dependency_path() {
    let index = generate_provider_free_attention_lineage_index().expect("index");
    validate_provider_free_attention_lineage_index(&index).expect("valid index");
    assert_eq!(index.artifact_count, 11);
    assert_eq!(index.artifacts.len(), 11);
    let kinds = index
        .artifacts
        .iter()
        .map(|artifact| artifact.kind)
        .collect::<Vec<_>>();
    assert_eq!(
        kinds,
        vec![
            ProviderFreeLineageArtifactKind::DeterministicDriveMeasurement,
            ProviderFreeLineageArtifactKind::ScriptedCompleteRun,
            ProviderFreeLineageArtifactKind::ScriptedToolCapStoppedRun,
            ProviderFreeLineageArtifactKind::ScriptedTerminalPendingRun,
            ProviderFreeLineageArtifactKind::IterativeTranscriptMeasurement,
            ProviderFreeLineageArtifactKind::AttentionReentryMeasurement,
            ProviderFreeLineageArtifactKind::DualTranscriptProjection,
            ProviderFreeLineageArtifactKind::TransportEnvelopeSet,
            ProviderFreeLineageArtifactKind::EffectlessDispatchRun,
            ProviderFreeLineageArtifactKind::DispatchResumeCorpus,
            ProviderFreeLineageArtifactKind::CheckpointHandleMeasurement,
        ]
    );
    for (ordinal, artifact) in index.artifacts.iter().enumerate() {
        assert_eq!(artifact.ordinal as usize, ordinal);
        assert!(!artifact.artifact_profile.is_empty());
        assert!(artifact.compact_json_bytes > 0);
        assert_eq!(artifact.content_digest.algorithm, "sha256");
        assert_eq!(artifact.content_digest.value.len(), 64);
    }
    let capabilities = &index.capabilities;
    assert!(capabilities.provider_free_execution);
    assert!(capabilities.ready_to_terminal);
    assert!(capabilities.stopped_resume);
    assert!(capabilities.terminal_pending_admission);
    assert!(capabilities.canonical_replay);
    assert!(capabilities.compact_transport);
    assert!(capabilities.packet_integrity);
    assert!(capabilities.dispatch_staging);
    assert!(capabilities.checkpoint_resume);
    assert!(capabilities.byte_measurement);
    assert!(!capabilities.live_provider_execution);
    assert!(!capabilities.physical_persistence);
    assert!(!capabilities.semantic_model_equivalence);
    assert!(!capabilities.hidden_state_integration);
    assert!(!capabilities.external_effects);
    assert!(!capabilities.remote_execution);
    assert!(!capabilities.minecraft_scope);
    assert!(index.remote_hosts.is_empty());
    assert!(index.external_effect_records.is_empty());
}

#[test]
fn lineage_index_and_cli_are_deterministic_strict_compact_and_normalized() {
    let first = generate_provider_free_attention_lineage_index().expect("first");
    let second = generate_provider_free_attention_lineage_index().expect("second");
    assert_eq!(first, second);
    let expected = pretty_provider_free_attention_lineage_index_bytes(&first).expect("pretty");
    assert_eq!(expected.last(), Some(&b'\n'));
    assert!(expected.len() < 8_000);
    let text = String::from_utf8(expected.clone()).expect("UTF-8");
    assert!(!text.contains("\"actual_request\""));
    assert!(!text.contains("\"sanitized_response\""));
    assert!(!text.contains("\"messages\""));
    let decoded: ProviderFreeAttentionLineageIndex =
        serde_json::from_slice(&expected).expect("strict JSON");
    assert_eq!(decoded, first);

    let output = Command::new(env!("CARGO_BIN_EXE_cantor-compact-reflection-loop"))
        .arg("index-provider-free-lineage")
        .output()
        .expect("lineage CLI");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(output.stdout, expected);

    let mut unknown = serde_json::to_value(&first).expect("value");
    unknown["provider"] = Value::Null;
    assert!(serde_json::from_value::<ProviderFreeAttentionLineageIndex>(unknown).is_err());
}

#[test]
fn checked_in_lineage_artifact_regenerates_byte_identically() {
    let index = generate_provider_free_attention_lineage_index().expect("index");
    let regenerated = pretty_provider_free_attention_lineage_index_bytes(&index).expect("pretty");
    let checked_in = include_bytes!(
        "../../../experiments/iterative_attention_procedure_loop_p1/artifacts/provider_free_attention_lineage_index_v1.json"
    );
    assert_eq!(checked_in.as_slice(), regenerated);
    assert_eq!(regenerated.len(), 5_139);
    assert_eq!(
        index.lineage_root_digest.value,
        "fab09310674a26688fa19590a194ade552dc125f314f83693988e8bdac70f420"
    );
    assert_eq!(
        index
            .artifacts
            .iter()
            .map(|artifact| artifact.compact_json_bytes)
            .sum::<usize>(),
        1_396_447
    );
}

#[test]
fn lineage_order_commitments_and_capability_boundaries_fail_closed() {
    let index = generate_provider_free_attention_lineage_index().expect("index");

    let mut order = index.clone();
    order.artifacts.swap(0, 1);
    assert!(validate_provider_free_attention_lineage_index(&order).is_err());

    let mut digest = index.clone();
    digest.artifacts[0].content_digest.value.push('0');
    assert!(validate_provider_free_attention_lineage_index(&digest).is_err());

    let mut root = index.clone();
    root.lineage_root_digest.value.push('0');
    assert!(validate_provider_free_attention_lineage_index(&root).is_err());

    let mut live = index.clone();
    live.capabilities.live_provider_execution = true;
    assert!(validate_provider_free_attention_lineage_index(&live).is_err());

    let mut persistence = index.clone();
    persistence.capabilities.physical_persistence = true;
    assert!(validate_provider_free_attention_lineage_index(&persistence).is_err());

    let mut hidden = index.clone();
    hidden.capabilities.hidden_state_integration = true;
    assert!(validate_provider_free_attention_lineage_index(&hidden).is_err());

    let mut remote = index.clone();
    remote.remote_hosts.push("example.invalid".to_owned());
    assert!(validate_provider_free_attention_lineage_index(&remote).is_err());

    let mut reasoning = index.clone();
    reasoning.private_reasoning_recorded = true;
    assert!(validate_provider_free_attention_lineage_index(&reasoning).is_err());

    let mut nonclaim = index;
    nonclaim.nonclaims.pop();
    assert!(validate_provider_free_attention_lineage_index(&nonclaim).is_err());
}
