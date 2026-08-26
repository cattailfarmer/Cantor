use std::{
    collections::BTreeSet,
    fs,
    path::{Component, Path, PathBuf},
};

use cantor_core::sha256_bytes;
use serde::Deserialize;
use serde_json::Value;

const CONTROLLED: &[u8] = include_bytes!(
    "../../../experiments/succeeding_sop_fixture_persistence_p0/artifacts/controlled_verification.json"
);
const MANIFEST: &[u8] = include_bytes!(
    "../../../experiments/succeeding_sop_fixture_persistence_p0/artifacts/succeeding_sop_fixture_persistence_evidence_manifest.json"
);

const REQUIRED_PATHS: &[&str] = &[
    "crates/cantor_core/examples/succeeding_sop_activation_fixture.rs",
    "crates/cantor_ecosystem/src/succeeding_sop_fixture_persistence.rs",
    "crates/cantor_ecosystem/tests/fixtures/succeeding_sop_activation_transaction_receipt.json",
    "crates/cantor_ecosystem/tests/succeeding_sop_fixture_persistence.rs",
    "crates/cantor_ecosystem/tests/succeeding_sop_fixture_persistence_evidence.rs",
    "experiments/succeeding_sop_fixture_persistence_p0/artifacts/controlled_verification.json",
    "feature_support/Cantor_Succeeding_SOP_Fixture_Persistence_P0_Requirement_Matrix.sop",
    "scripts/build_cantor_succeeding_sop_activation_fixture.ps1",
    "scripts/build_cantor_succeeding_sop_fixture_persistence_evidence.ps1",
    "source_documents/2026-08-25_cantor_succeeding_sop_fixture_persistence_p0/Cantor_Succeeding_SOP_Fixture_Persistence_P0_Source.sop",
    "specifications/Cantor_Succeeding_SOP_Fixture_Persistence_P0.sop",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlledVerification {
    profile: String,
    evidence_uuid: String,
    source_commit: String,
    working_tree_basis: String,
    status: String,
    upstream_fixture: UpstreamFixture,
    wsl: WslVerification,
    windows: WindowsVerification,
    workspace: ControlledWorkspace,
    verified_behavior: VerifiedBehavior,
    boundaries: Boundaries,
    live_provider: LiveProvider,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpstreamFixture {
    profile: String,
    policy_use_status: String,
    bytes: u64,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WslVerification {
    distribution: String,
    debug_passed: u64,
    overflow_checked_release_passed: u64,
    upstream_activation_transaction_passed: u64,
    failed: u64,
    durable_success_receipt: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsVerification {
    safe_registry_replacement_observed: bool,
    parent_directory_flush_status: String,
    fault_physical_contact: bool,
    fault_replacement_performed: bool,
    fault_owned_temp_removed: bool,
    success_receipt: bool,
    exact_current_tree_test_process_status: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlledWorkspace {
    status: String,
    debug_result_groups: u64,
    debug_passed: u64,
    debug_failed: u64,
    debug_ignored: u64,
    debug_transcript_bytes: u64,
    debug_transcript_sha256: String,
    release_result_groups: u64,
    release_passed: u64,
    release_failed: u64,
    release_ignored: u64,
    release_transcript_bytes: u64,
    release_transcript_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifiedBehavior {
    exact_upstream_replay: bool,
    synthetic_fixture_only: bool,
    explicit_marker_and_root: bool,
    git_root_refused: bool,
    source_raw_bytes_reacquired: bool,
    predecessor_registry_verified: bool,
    same_parent_temp_create_new: bool,
    file_flush_and_temp_reopen: bool,
    same_volume_registry_replacement: bool,
    parent_flush_and_final_reopen_on_wsl: bool,
    successor_current_selected_on_wsl: bool,
    typed_post_replacement_windows_fault: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Boundaries {
    externally_governed_activation: bool,
    live_repository_contacted: bool,
    boot_activation_verified: bool,
    rollback_executed: bool,
    provider_contacted: bool,
    model_called: bool,
    process_surface_in_product_module: bool,
    network_surface_in_product_module: bool,
    unsafe_surface: bool,
    git_or_remote_effect: bool,
    cleanup_authority: bool,
    cantor_tree_mutated_by_kernel: bool,
    pinky_tree_mutated: bool,
    d_cantor_b1_mutated: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LiveProvider {
    status: String,
    trials: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceManifest {
    profile: String,
    evidence_manifest_uuid: String,
    canonical_uuid: String,
    source_snapshot_uuid: String,
    satisfaction_signature_uuid: String,
    source_commit: String,
    working_tree_basis: String,
    generated_at_utc: String,
    artifacts: Vec<Artifact>,
    focused_verification: FocusedVerification,
    workspace_verification: WorkspaceVerification,
    non_authority_statement: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    path: String,
    bytes: u64,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FocusedVerification {
    wsl_debug_passed: u64,
    wsl_overflow_checked_release_passed: u64,
    upstream_activation_transaction_passed: u64,
    new_swa_06b2b1_tests: u64,
    warnings_denied_clippy: String,
    format: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkspaceVerification {
    status: String,
    debug: WorkspaceLane,
    overflow_checked_release: WorkspaceLane,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkspaceLane {
    result_groups: u64,
    passed: u64,
    failed: u64,
    ignored: u64,
    transcript_bytes: u64,
    transcript_sha256: String,
}

#[test]
fn committed_fixture_persistence_evidence_rehashes_and_retains_boundaries() {
    verify(CONTROLLED, MANIFEST).expect("committed B2B1 evidence must verify");
}

#[test]
fn artifact_digest_mutation_refuses() {
    let mut manifest = json(MANIFEST);
    manifest["artifacts"][0]["sha256"] = Value::from("00");
    assert_fault(CONTROLLED, manifest, "artifact_sha256");
}

#[test]
fn missing_required_artifact_refuses() {
    let mut manifest = json(MANIFEST);
    let artifacts = manifest["artifacts"].as_array_mut().expect("artifacts");
    artifacts.retain(|entry| entry["path"] != REQUIRED_PATHS[0]);
    assert_fault(CONTROLLED, manifest, "required_artifact");
}

#[test]
fn windows_success_laundering_refuses() {
    let mut controlled = json(CONTROLLED);
    controlled["windows"]["success_receipt"] = Value::Bool(true);
    assert_controlled_fault(controlled, MANIFEST, "windows_success_receipt");
}

#[test]
fn provider_trial_mutation_refuses() {
    let mut controlled = json(CONTROLLED);
    controlled["live_provider"]["trials"] = Value::from(1);
    assert_controlled_fault(controlled, MANIFEST, "live_provider");
}

#[test]
fn duplicate_artifact_path_refuses() {
    let mut manifest = json(MANIFEST);
    let duplicate = manifest["artifacts"][0].clone();
    manifest["artifacts"]
        .as_array_mut()
        .expect("artifacts")
        .push(duplicate);
    assert_fault(CONTROLLED, manifest, "artifact_path_duplicate");
}

fn verify(controlled_bytes: &[u8], manifest_bytes: &[u8]) -> Result<(), String> {
    let controlled: ControlledVerification = serde_json::from_slice(controlled_bytes)
        .map_err(|error| format!("controlled_json: {error}"))?;
    let manifest: EvidenceManifest = serde_json::from_slice(manifest_bytes)
        .map_err(|error| format!("manifest_json: {error}"))?;
    verify_controlled(&controlled)?;
    verify_manifest(&controlled, &manifest)
}

fn verify_controlled(value: &ControlledVerification) -> Result<(), String> {
    exact(
        &value.profile,
        "cantor-succeeding-sop-fixture-persistence-controlled-verification/0.1",
        "controlled_profile",
    )?;
    exact(
        &value.evidence_uuid,
        "d96a8a0f-521b-4b5e-9299-99aff603ff4f",
        "evidence_uuid",
    )?;
    exact(
        &value.source_commit,
        "8cb80c86f88e5b4cd407a09146f01cabec6766a5",
        "source_commit",
    )?;
    exact(
        &value.working_tree_basis,
        "source_commit_plus_exact_owned_swa_06b2b1_delta",
        "working_tree_basis",
    )?;
    exact(
        &value.status,
        "synthetic_fixture_persistence_verified_with_windows_durability_refusal",
        "status",
    )?;
    exact(
        &value.upstream_fixture.profile,
        "cantor-succeeding-sop-activation-transaction-receipt/0.1",
        "upstream_profile",
    )?;
    exact(
        &value.upstream_fixture.policy_use_status,
        "synthetic_fixture_only",
        "upstream_policy",
    )?;
    require(value.upstream_fixture.bytes == 49_431, "upstream_bytes")?;
    exact(
        &value.upstream_fixture.sha256,
        "27A233C7366063DA04371A137CE4E68AE8F5DD97479BF70BFEFB9B180CAB0004",
        "upstream_sha256",
    )?;
    exact(&value.wsl.distribution, "Ubuntu-24.04", "wsl_distribution")?;
    require(
        value.wsl.debug_passed == 7
            && value.wsl.overflow_checked_release_passed == 7
            && value.wsl.upstream_activation_transaction_passed == 45
            && value.wsl.failed == 0
            && value.wsl.durable_success_receipt,
        "wsl_verification",
    )?;
    require(
        value.windows.safe_registry_replacement_observed
            && value.windows.fault_physical_contact
            && value.windows.fault_replacement_performed
            && !value.windows.fault_owned_temp_removed
            && !value.windows.success_receipt,
        "windows_success_receipt",
    )?;
    exact(
        &value.windows.parent_directory_flush_status,
        "refused_access_denied_os_error_5",
        "windows_durability",
    )?;
    exact(
        &value.windows.exact_current_tree_test_process_status,
        "blocked_by_application_control_4551",
        "windows_process_status",
    )?;
    verify_controlled_workspace(&value.workspace)?;
    let behavior = &value.verified_behavior;
    require(
        behavior.exact_upstream_replay
            && behavior.synthetic_fixture_only
            && behavior.explicit_marker_and_root
            && behavior.git_root_refused
            && behavior.source_raw_bytes_reacquired
            && behavior.predecessor_registry_verified
            && behavior.same_parent_temp_create_new
            && behavior.file_flush_and_temp_reopen
            && behavior.same_volume_registry_replacement
            && behavior.parent_flush_and_final_reopen_on_wsl
            && behavior.successor_current_selected_on_wsl
            && behavior.typed_post_replacement_windows_fault,
        "verified_behavior",
    )?;
    let boundaries = &value.boundaries;
    require(
        !boundaries.externally_governed_activation
            && !boundaries.live_repository_contacted
            && !boundaries.boot_activation_verified
            && !boundaries.rollback_executed
            && !boundaries.provider_contacted
            && !boundaries.model_called
            && !boundaries.process_surface_in_product_module
            && !boundaries.network_surface_in_product_module
            && !boundaries.unsafe_surface
            && !boundaries.git_or_remote_effect
            && !boundaries.cleanup_authority
            && !boundaries.cantor_tree_mutated_by_kernel
            && !boundaries.pinky_tree_mutated
            && !boundaries.d_cantor_b1_mutated,
        "boundaries",
    )?;
    require(
        value.live_provider.status == "not_contacted_not_required"
            && value.live_provider.trials == 0,
        "live_provider",
    )
}

fn verify_manifest(
    controlled: &ControlledVerification,
    value: &EvidenceManifest,
) -> Result<(), String> {
    exact(
        &value.profile,
        "cantor-succeeding-sop-fixture-persistence-evidence-manifest/0.1",
        "manifest_profile",
    )?;
    exact(
        &value.evidence_manifest_uuid,
        "094be7fe-975f-41d8-aec8-e355664a69fc",
        "manifest_uuid",
    )?;
    exact(
        &value.canonical_uuid,
        "b87c0711-1151-438e-a2eb-35375e88b134",
        "canonical_uuid",
    )?;
    exact(
        &value.source_snapshot_uuid,
        "2c60682b-8233-46d0-8dbd-46c7c355b90b",
        "source_snapshot_uuid",
    )?;
    exact(
        &value.satisfaction_signature_uuid,
        "7c3952ad-e4fd-4a99-9f88-96ccf182be25",
        "satisfaction_signature_uuid",
    )?;
    require(
        value.source_commit == controlled.source_commit,
        "manifest_source_commit",
    )?;
    require(
        value.working_tree_basis == controlled.working_tree_basis,
        "manifest_working_tree_basis",
    )?;
    require(
        !value.generated_at_utc.trim().is_empty(),
        "generated_at_utc",
    )?;
    require(
        value.focused_verification.wsl_debug_passed == 7
            && value
                .focused_verification
                .wsl_overflow_checked_release_passed
                == 7
            && value
                .focused_verification
                .upstream_activation_transaction_passed
                == 45
            && value.focused_verification.new_swa_06b2b1_tests == 7
            && value.focused_verification.warnings_denied_clippy == "passed"
            && value.focused_verification.format == "passed",
        "focused_verification",
    )?;
    require(
        value.workspace_verification.status == controlled.workspace.status,
        "workspace_status",
    )?;
    require(
        value.workspace_verification.status == "passed",
        "workspace_status",
    )?;
    verify_lane(&value.workspace_verification.debug, "workspace_debug")?;
    verify_lane(
        &value.workspace_verification.overflow_checked_release,
        "workspace_release",
    )?;
    require(
        value
            .non_authority_statement
            .contains("synthetic-fixture-only")
            && value
                .non_authority_statement
                .contains("no externally governed activation")
            && value
                .non_authority_statement
                .contains("no provider or model contact"),
        "non_authority_statement",
    )?;

    let root = repository_root()?;
    let mut paths = BTreeSet::new();
    for artifact in &value.artifacts {
        validate_relative_path(&artifact.path)?;
        require(
            paths.insert(artifact.path.as_str()),
            "artifact_path_duplicate",
        )?;
        let full = physical_file(&root, &artifact.path)?;
        let bytes = fs::read(&full)
            .map_err(|error| format!("artifact_read: {}: {error}", artifact.path))?;
        require(
            u64::try_from(bytes.len()).ok() == Some(artifact.bytes),
            "artifact_bytes",
        )?;
        require(
            sha256_bytes(&bytes)
                .value
                .eq_ignore_ascii_case(&artifact.sha256),
            "artifact_sha256",
        )?;
    }
    for required in REQUIRED_PATHS {
        require(paths.contains(required), "required_artifact")?;
    }
    let source = fs::read_to_string(
        root.join("crates/cantor_ecosystem/src/succeeding_sop_fixture_persistence.rs"),
    )
    .map_err(|error| format!("module_read: {error}"))?;
    for forbidden in [
        "std::env",
        "std::process",
        "Command::new",
        "TcpStream",
        "reqwest",
        "unsafe {",
    ] {
        require(!source.contains(forbidden), "ambient_or_live_surface")?;
    }
    Ok(())
}

fn verify_lane(lane: &WorkspaceLane, field: &str) -> Result<(), String> {
    require(
        lane.result_groups > 0
            && lane.passed > 0
            && lane.failed == 0
            && lane.ignored == 3
            && lane.transcript_bytes > 0
            && lane.transcript_sha256.len() == 64
            && lane
                .transcript_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit()),
        field,
    )
}

fn verify_controlled_workspace(value: &ControlledWorkspace) -> Result<(), String> {
    require(value.status == "passed", "controlled_workspace_status")?;
    let debug = WorkspaceLane {
        result_groups: value.debug_result_groups,
        passed: value.debug_passed,
        failed: value.debug_failed,
        ignored: value.debug_ignored,
        transcript_bytes: value.debug_transcript_bytes,
        transcript_sha256: value.debug_transcript_sha256.clone(),
    };
    let release = WorkspaceLane {
        result_groups: value.release_result_groups,
        passed: value.release_passed,
        failed: value.release_failed,
        ignored: value.release_ignored,
        transcript_bytes: value.release_transcript_bytes,
        transcript_sha256: value.release_transcript_sha256.clone(),
    };
    verify_lane(&debug, "controlled_workspace_debug")?;
    verify_lane(&release, "controlled_workspace_release")
}

fn repository_root() -> Result<PathBuf, String> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .map_err(|error| format!("repository_root: {error}"))
}

fn validate_relative_path(path: &str) -> Result<(), String> {
    require(!path.is_empty() && !path.contains('\\'), "artifact_path")?;
    let candidate = Path::new(path);
    require(!candidate.is_absolute(), "artifact_path")?;
    for component in candidate.components() {
        require(matches!(component, Component::Normal(_)), "artifact_path")?;
    }
    Ok(())
}

fn physical_file(root: &Path, relative: &str) -> Result<PathBuf, String> {
    let mut current = root.to_path_buf();
    for component in Path::new(relative).components() {
        let Component::Normal(part) = component else {
            return Err("artifact_path".into());
        };
        current.push(part);
        let metadata = fs::symlink_metadata(&current)
            .map_err(|error| format!("artifact_metadata: {relative}: {error}"))?;
        require(!metadata.file_type().is_symlink(), "artifact_symlink")?;
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            require(metadata.file_attributes() & 0x400 == 0, "artifact_reparse")?;
        }
    }
    require(
        fs::metadata(&current)
            .map_err(|error| format!("artifact_metadata: {relative}: {error}"))?
            .is_file(),
        "artifact_file",
    )?;
    Ok(current)
}

fn json(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).expect("committed evidence JSON")
}

fn assert_fault(controlled: &[u8], manifest: Value, expected: &str) {
    let encoded = serde_json::to_vec(&manifest).expect("tampered manifest encodes");
    let fault = verify(controlled, &encoded).expect_err("tampering must refuse");
    assert!(
        fault.starts_with(expected),
        "expected {expected}, got {fault}"
    );
}

fn assert_controlled_fault(controlled: Value, manifest: &[u8], expected: &str) {
    let encoded = serde_json::to_vec(&controlled).expect("tampered controlled evidence encodes");
    let fault = verify(&encoded, manifest).expect_err("tampering must refuse");
    assert!(
        fault.starts_with(expected),
        "expected {expected}, got {fault}"
    );
}

fn exact(actual: &str, expected: &str, field: &str) -> Result<(), String> {
    require(actual == expected, field)
}

fn require(condition: bool, field: &str) -> Result<(), String> {
    condition.then_some(()).ok_or_else(|| field.to_string())
}
