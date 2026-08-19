use std::process::Command;

use cantor_compact_reflection_loop::{
    PROVIDER_FREE_SHELL_RELEASE_KIND, ProviderFreeShellReleaseManifest,
    generate_provider_free_shell_release_manifest,
    pretty_provider_free_shell_release_manifest_bytes,
    validate_provider_free_shell_release_manifest,
};

const ARTIFACT: &[u8] = include_bytes!(
    "../../../experiments/iterative_attention_procedure_loop_p1/artifacts/provider_free_shell_release_manifest_v1.json"
);

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_cantor-compact-reflection-loop")
}

fn change_first_hex(value: &mut String) {
    let replacement = if value.starts_with('0') { "1" } else { "0" };
    value.replace_range(0..1, replacement);
}

#[test]
fn release_manifest_commits_complete_provider_free_boundary() {
    let manifest = generate_provider_free_shell_release_manifest().expect("manifest");
    assert_eq!(manifest.release_kind, PROVIDER_FREE_SHELL_RELEASE_KIND);
    assert_eq!(manifest.historical_lineage.item_count, 11);
    assert_eq!(manifest.checkpoint_custody.item_count, 12);
    assert_eq!(manifest.custody_query.operation_count, 4);
    assert_eq!(manifest.query_measurement.case_count, 12);
    assert_eq!(manifest.proof_count, 17);
    assert_eq!(manifest.proofs.len(), 17);
    assert_eq!(
        manifest.historical_lineage.root_digest.value,
        "fab09310674a26688fa19590a194ade552dc125f314f83693988e8bdac70f420"
    );
    assert!(manifest.capabilities.deterministic_provider_free_loop);
    assert!(manifest.capabilities.typed_custody_query);
    assert!(!manifest.capabilities.live_provider_execution);
    assert!(!manifest.capabilities.physical_persistence);
    assert!(!manifest.capabilities.handle_discovery);
    assert!(!manifest.capabilities.external_effects);
    assert!(!manifest.request_bodies_embedded);
    assert!(!manifest.checkpoint_bodies_embedded);
    assert!(!manifest.proof_bodies_embedded);
}

#[test]
fn release_manifest_round_trip_and_mutations_fail_closed() {
    let manifest = generate_provider_free_shell_release_manifest().expect("manifest");
    let bytes = pretty_provider_free_shell_release_manifest_bytes(&manifest).expect("bytes");
    let decoded: ProviderFreeShellReleaseManifest =
        serde_json::from_slice(&bytes).expect("strict JSON");
    assert_eq!(decoded, manifest);

    let mut wrong_root = manifest.clone();
    change_first_hex(&mut wrong_root.release_root_digest.value);
    assert!(validate_provider_free_shell_release_manifest(&wrong_root).is_err());
    let mut wrong_proof = manifest.clone();
    change_first_hex(&mut wrong_proof.proofs[0].sha256.value);
    assert!(validate_provider_free_shell_release_manifest(&wrong_proof).is_err());
    let mut wrong_capability = manifest.clone();
    wrong_capability.capabilities.live_provider_execution = true;
    assert!(validate_provider_free_shell_release_manifest(&wrong_capability).is_err());
    let mut embedded = manifest;
    embedded.proof_bodies_embedded = true;
    assert!(validate_provider_free_shell_release_manifest(&embedded).is_err());
}

#[test]
fn release_cli_stdout_is_typed_and_rejects_extra_arguments() {
    let output = Command::new(binary())
        .arg("describe-provider-free-shell-release")
        .output()
        .expect("run");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let manifest: ProviderFreeShellReleaseManifest =
        serde_json::from_slice(&output.stdout).expect("typed manifest");
    validate_provider_free_shell_release_manifest(&manifest).expect("valid manifest");
    assert_eq!(
        output.stdout,
        pretty_provider_free_shell_release_manifest_bytes(&manifest).expect("pretty")
    );
    assert_eq!(output.stdout, ARTIFACT);

    let extra = Command::new(binary())
        .args(["describe-provider-free-shell-release", "unexpected"])
        .output()
        .expect("run invalid");
    assert_eq!(extra.status.code(), Some(2));
}
