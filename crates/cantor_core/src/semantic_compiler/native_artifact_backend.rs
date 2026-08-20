//! Pure native-artifact build-candidate projection.
//!
//! This module records source and a reproducible conventional build contract.
//! It does not generate source, write files, run Cargo or a compiler, produce
//! an artifact digest, sign, verify, admit, install, deploy, or execute.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{
    COMPILER_NON_AUTHORITY, CandidateCompilationPlan, CompilerBackendKind, CompilerCapability,
    SemanticCompilerFormFaultKind, SemanticCompilerValidation, SopSeed, TypedSopIr, bounded_set,
    bounded_text, digest_form, exact_non_authority, exact_profile, form_fault, normalize,
    require_digest, validate_candidate_compilation_plan, validate_digest,
};
use crate::{ContentDigest, SemanticId};

pub const NATIVE_ARTIFACT_BACKEND_REQUEST_PROFILE: &str =
    "cantor-native-artifact-backend-request/0.1";
pub const NATIVE_ARTIFACT_CANDIDATE_PROFILE: &str = "cantor-native-artifact-candidate/0.1";
pub const NATIVE_ARTIFACT_BACKEND_PROJECTION_PROFILE: &str =
    "cantor-native-artifact-backend-projection/0.1";
pub const CARGO_LOCKED_OFFLINE_BUILD_PROFILE: &str = "cargo-build-locked-offline/0.1";
pub const SANITIZED_BUILD_ENVIRONMENT_POLICY: &str =
    "sanitized-explicit-allowlist-no-inherited-secrets/0.1";

const CANDIDATE_DOMAIN: &str = "cantor.semantic-compiler.native-artifact-candidate.v1";
const PROJECTION_DOMAIN: &str = "cantor.semantic-compiler.native-artifact-projection.v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeArtifactKind {
    CliExecutable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeLanguage {
    Rust,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceInputProvenance {
    SelectedExisting,
    GeneratedCandidate,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyPolicy {
    LockedOffline,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeRuntimeRequirement {
    StandardInput,
    StandardOutput,
    AdmittedEnvironmentRead,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeCandidateLifecycle {
    Proposed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSourceInputPin {
    pub source_id: SemanticId,
    pub relative_path: String,
    pub source_digest: ContentDigest,
    pub provenance: SourceInputProvenance,
    pub semantic_node_refs: BTreeSet<SemanticId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeToolchainPin {
    pub language: NativeLanguage,
    pub edition: String,
    pub channel: String,
    pub compiler_version: String,
    pub cargo_version: String,
    pub target_triple: String,
    pub compiler_digest: ContentDigest,
    pub cargo_digest: ContentDigest,
    pub linker_digest: ContentDigest,
    pub configuration_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeInterfaceBinding {
    pub interface_profile: String,
    pub input_schema_digest: ContentDigest,
    pub output_schema_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBuildContract {
    pub build_profile: String,
    pub command_schema: Vec<String>,
    pub environment_policy: String,
    pub workspace_manifest_digest: ContentDigest,
    pub package_manifest_digest: ContentDigest,
    pub dependency_lock_digest: ContentDigest,
    pub dependency_policy: DependencyPolicy,
    pub package_name: String,
    pub binary_name: String,
    pub cargo_profile: String,
    pub features: BTreeSet<String>,
    pub expected_output_id: SemanticId,
    pub expected_output_relative_path: String,
    pub maximum_seconds: u32,
    pub maximum_processes: u32,
    pub maximum_memory_bytes: u64,
    pub maximum_output_bytes: u64,
    pub maximum_artifacts: u32,
    pub expected_receipt_refs: BTreeSet<SemanticId>,
    pub verifier_refs: BTreeSet<SemanticId>,
    pub cleanup_ref: SemanticId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeArtifactBackendRequest {
    pub profile: String,
    pub request_id: SemanticId,
    pub candidate_id: SemanticId,
    pub plan_ref: SemanticId,
    pub plan_digest: ContentDigest,
    pub ir_ref: SemanticId,
    pub ir_digest: ContentDigest,
    pub purpose: String,
    pub artifact_kind: NativeArtifactKind,
    pub source_inputs: BTreeMap<SemanticId, NativeSourceInputPin>,
    pub toolchain: NativeToolchainPin,
    pub interface: NativeInterfaceBinding,
    pub build: NativeBuildContract,
    pub runtime_requirements: BTreeSet<NativeRuntimeRequirement>,
    pub rollback_ref: SemanticId,
    pub unresolved_account: BTreeSet<String>,
    pub non_authority: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeArtifactCandidate {
    pub profile: String,
    pub candidate_id: SemanticId,
    pub seed_ref: SemanticId,
    pub seed_digest: ContentDigest,
    pub plan_ref: SemanticId,
    pub plan_digest: ContentDigest,
    pub ir_ref: SemanticId,
    pub ir_digest: ContentDigest,
    pub purpose: String,
    pub artifact_kind: NativeArtifactKind,
    pub source_inputs: BTreeMap<SemanticId, NativeSourceInputPin>,
    pub toolchain: NativeToolchainPin,
    pub interface: NativeInterfaceBinding,
    pub build: NativeBuildContract,
    pub runtime_requirements: BTreeSet<NativeRuntimeRequirement>,
    pub rollback_ref: SemanticId,
    pub lifecycle: NativeCandidateLifecycle,
    pub unresolved_account: BTreeSet<String>,
    pub non_authority: String,
    pub candidate_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeArtifactBackendProjection {
    pub profile: String,
    pub request_id: SemanticId,
    pub candidate: NativeArtifactCandidate,
    pub projection_digest: ContentDigest,
}

pub fn native_artifact_candidate_digest(
    candidate: &NativeArtifactCandidate,
) -> SemanticCompilerValidation<ContentDigest> {
    let mut body = candidate.clone();
    body.candidate_digest = empty_digest();
    digest_form(CANDIDATE_DOMAIN, &body)
}

pub fn native_artifact_backend_projection_digest(
    projection: &NativeArtifactBackendProjection,
) -> SemanticCompilerValidation<ContentDigest> {
    let mut body = projection.clone();
    body.projection_digest = empty_digest();
    digest_form(PROJECTION_DOMAIN, &body)
}

pub fn project_native_artifact_backend(
    seed: &SopSeed,
    ir: &TypedSopIr,
    plan: &CandidateCompilationPlan,
    request: &NativeArtifactBackendRequest,
) -> SemanticCompilerValidation<NativeArtifactBackendProjection> {
    validate_native_artifact_backend_request(seed, ir, plan, request)?;
    let candidate = project_candidate(seed, ir, plan, request)?;
    let mut projection = NativeArtifactBackendProjection {
        profile: NATIVE_ARTIFACT_BACKEND_PROJECTION_PROFILE.to_owned(),
        request_id: request.request_id.clone(),
        candidate,
        projection_digest: empty_digest(),
    };
    projection.projection_digest = native_artifact_backend_projection_digest(&projection)?;
    validate_native_artifact_backend_projection(seed, ir, plan, request, &projection)?;
    Ok(projection)
}

pub fn validate_native_artifact_backend_projection(
    seed: &SopSeed,
    ir: &TypedSopIr,
    plan: &CandidateCompilationPlan,
    request: &NativeArtifactBackendRequest,
    projection: &NativeArtifactBackendProjection,
) -> SemanticCompilerValidation {
    validate_native_artifact_backend_request(seed, ir, plan, request)?;
    exact_profile(
        &projection.profile,
        NATIVE_ARTIFACT_BACKEND_PROJECTION_PROFILE,
        "projection.profile",
    )?;
    let expected = project_candidate(seed, ir, plan, request)?;
    if projection.request_id != request.request_id || projection.candidate != expected {
        return form_fault(
            SemanticCompilerFormFaultKind::InvalidReference,
            "projection.lineage",
            "projection candidate differs from exact request and upstream lineage",
        );
    }
    validate_digest(
        &projection.projection_digest,
        "projection.projection_digest",
    )?;
    require_digest(
        &projection.projection_digest,
        native_artifact_backend_projection_digest(projection)?,
        "projection.projection_digest",
    )
}

fn project_candidate(
    seed: &SopSeed,
    ir: &TypedSopIr,
    plan: &CandidateCompilationPlan,
    request: &NativeArtifactBackendRequest,
) -> SemanticCompilerValidation<NativeArtifactCandidate> {
    let mut candidate = NativeArtifactCandidate {
        profile: NATIVE_ARTIFACT_CANDIDATE_PROFILE.to_owned(),
        candidate_id: request.candidate_id.clone(),
        seed_ref: seed.seed_id.clone(),
        seed_digest: seed.seed_digest.clone(),
        plan_ref: plan.plan_id.clone(),
        plan_digest: plan.plan_digest.clone(),
        ir_ref: ir.ir_id.clone(),
        ir_digest: ir.ir_digest.clone(),
        purpose: request.purpose.clone(),
        artifact_kind: request.artifact_kind.clone(),
        source_inputs: request.source_inputs.clone(),
        toolchain: request.toolchain.clone(),
        interface: request.interface.clone(),
        build: request.build.clone(),
        runtime_requirements: request.runtime_requirements.clone(),
        rollback_ref: request.rollback_ref.clone(),
        lifecycle: NativeCandidateLifecycle::Proposed,
        unresolved_account: request.unresolved_account.clone(),
        non_authority: COMPILER_NON_AUTHORITY.to_owned(),
        candidate_digest: empty_digest(),
    };
    candidate.candidate_digest = native_artifact_candidate_digest(&candidate)?;
    Ok(candidate)
}

fn validate_native_artifact_backend_request(
    seed: &SopSeed,
    ir: &TypedSopIr,
    plan: &CandidateCompilationPlan,
    request: &NativeArtifactBackendRequest,
) -> SemanticCompilerValidation {
    validate_candidate_compilation_plan(seed, ir, plan)?;
    exact_profile(
        &request.profile,
        NATIVE_ARTIFACT_BACKEND_REQUEST_PROFILE,
        "request.profile",
    )?;
    if plan.backend != CompilerBackendKind::NativeArtifact {
        return form_fault(
            SemanticCompilerFormFaultKind::BackendMismatch,
            "plan.backend",
            "native artifact adapter requires the exact native_artifact backend",
        );
    }
    if request.plan_ref != plan.plan_id
        || request.plan_digest != plan.plan_digest
        || request.ir_ref != ir.ir_id
        || request.ir_digest != ir.ir_digest
        || normalize(&request.purpose) != normalize(&plan.purpose)
        || request.rollback_ref != plan.rollback_ref
    {
        return form_fault(
            SemanticCompilerFormFaultKind::InvalidReference,
            "request.lineage",
            "request plan IR purpose or rollback differs",
        );
    }
    let pure_capabilities = BTreeSet::from([
        CompilerCapability::SemanticRead,
        CompilerCapability::SourceRead,
    ]);
    if !plan.requested_capabilities.is_subset(&pure_capabilities) {
        return form_fault(
            SemanticCompilerFormFaultKind::CapabilityExceeded,
            "plan.requested_capabilities",
            "native candidate projection permits semantic_read and source_read only",
        );
    }
    bounded_text(&request.purpose, "request.purpose")?;
    validate_sources(ir, &request.source_inputs)?;
    validate_toolchain(&request.toolchain)?;
    validate_interface(&request.interface)?;
    validate_build(plan, &request.build)?;
    let runtime = BTreeSet::from([
        NativeRuntimeRequirement::StandardInput,
        NativeRuntimeRequirement::StandardOutput,
        NativeRuntimeRequirement::AdmittedEnvironmentRead,
    ]);
    if request.runtime_requirements != runtime {
        return form_fault(
            SemanticCompilerFormFaultKind::AccountingMismatch,
            "request.runtime_requirements",
            "runtime requirements must name the complete CLI seam without granting it",
        );
    }
    bounded_set(&request.unresolved_account, "request.unresolved_account")?;
    exact_non_authority(&request.non_authority, "request.non_authority")
}

fn validate_sources(
    ir: &TypedSopIr,
    sources: &BTreeMap<SemanticId, NativeSourceInputPin>,
) -> SemanticCompilerValidation {
    if sources.is_empty() {
        return form_fault(
            SemanticCompilerFormFaultKind::InvalidBound,
            "request.source_inputs",
            "native candidate requires at least one source input",
        );
    }
    let mut covered = BTreeSet::new();
    for (source_id, source) in sources {
        if source_id != &source.source_id
            || source.provenance != SourceInputProvenance::SelectedExisting
            || !is_relative_path(&source.relative_path)
            || source.semantic_node_refs.is_empty()
            || !source
                .semantic_node_refs
                .is_subset(&ir.nodes.keys().cloned().collect())
            || !covered.is_disjoint(&source.semantic_node_refs)
        {
            return form_fault(
                SemanticCompilerFormFaultKind::InvalidReference,
                "request.source_inputs",
                "source identity path provenance or semantic-node ownership is invalid",
            );
        }
        validate_digest(&source.source_digest, "request.source_inputs.source_digest")?;
        covered.extend(source.semantic_node_refs.iter().cloned());
    }
    if covered != ir.nodes.keys().cloned().collect() {
        return form_fault(
            SemanticCompilerFormFaultKind::AccountingMismatch,
            "request.source_inputs.semantic_node_refs",
            "selected source inputs must cover every semantic node exactly once",
        );
    }
    Ok(())
}

fn validate_toolchain(toolchain: &NativeToolchainPin) -> SemanticCompilerValidation {
    if toolchain.language != NativeLanguage::Rust
        || toolchain.edition != "2024"
        || toolchain.channel != "stable"
    {
        return form_fault(
            SemanticCompilerFormFaultKind::InvalidProfile,
            "request.toolchain",
            "Slice5 requires the exact stable Rust 2024 toolchain profile",
        );
    }
    for value in [
        &toolchain.compiler_version,
        &toolchain.cargo_version,
        &toolchain.target_triple,
    ] {
        bounded_text(value, "request.toolchain.version")?;
    }
    for digest in [
        &toolchain.compiler_digest,
        &toolchain.cargo_digest,
        &toolchain.linker_digest,
        &toolchain.configuration_digest,
    ] {
        validate_digest(digest, "request.toolchain.digest")?;
    }
    Ok(())
}

fn validate_interface(interface: &NativeInterfaceBinding) -> SemanticCompilerValidation {
    bounded_text(&interface.interface_profile, "request.interface.profile")?;
    validate_digest(
        &interface.input_schema_digest,
        "request.interface.input_schema_digest",
    )?;
    validate_digest(
        &interface.output_schema_digest,
        "request.interface.output_schema_digest",
    )
}

fn validate_build(
    plan: &CandidateCompilationPlan,
    build: &NativeBuildContract,
) -> SemanticCompilerValidation {
    if build.build_profile != CARGO_LOCKED_OFFLINE_BUILD_PROFILE
        || build.command_schema != expected_command_schema(build)
        || build.environment_policy != SANITIZED_BUILD_ENVIRONMENT_POLICY
        || build.cargo_profile != "release"
        || build.verifier_refs != plan.verifier_refs
        || build.expected_receipt_refs.is_empty()
        || !is_relative_path(&build.expected_output_relative_path)
        || build.maximum_seconds == 0
        || build.maximum_processes == 0
        || build.maximum_memory_bytes == 0
        || build.maximum_output_bytes == 0
        || build.maximum_artifacts != 1
    {
        return form_fault(
            SemanticCompilerFormFaultKind::InvalidBound,
            "request.build",
            "build contract profile output verifiers and finite resource bounds must be exact",
        );
    }
    for value in [&build.package_name, &build.binary_name] {
        bounded_text(value, "request.build.name")?;
    }
    bounded_set(&build.features, "request.build.features")?;
    for digest in [
        &build.workspace_manifest_digest,
        &build.package_manifest_digest,
        &build.dependency_lock_digest,
    ] {
        validate_digest(digest, "request.build.digest")?;
    }
    Ok(())
}

fn expected_command_schema(build: &NativeBuildContract) -> Vec<String> {
    let mut command = vec![
        "cargo".to_owned(),
        "build".to_owned(),
        "--locked".to_owned(),
        "--offline".to_owned(),
        "--release".to_owned(),
        "--package".to_owned(),
        build.package_name.clone(),
        "--bin".to_owned(),
        build.binary_name.clone(),
    ];
    if !build.features.is_empty() {
        command.push("--features".to_owned());
        command.push(build.features.iter().cloned().collect::<Vec<_>>().join(","));
    }
    command
}

fn is_relative_path(value: &str) -> bool {
    !value.trim().is_empty()
        && !value.starts_with(['/', '\\'])
        && !value.contains(':')
        && !value
            .split(['/', '\\'])
            .any(|component| component.is_empty() || component == "." || component == "..")
}

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: String::new(),
    }
}
