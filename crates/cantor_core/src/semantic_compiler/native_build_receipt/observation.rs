//! Supplied native runner observations, single-use accounting, and produced-
//! unverified artifact receipts.
//!
//! This module is intentionally pure. An external adapter may construct an
//! observation after running a build, but this code cannot create a directory,
//! write a source file, spawn a process, read ambient state, or claim physical
//! containment.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{
    NativeArtifactBuildLineage, NativeBuildAuthorizationCertificate, NativeBuildCapabilityReceipt,
    NativeBuildExecutionPlan, NativeBuildTrustStore, NativeSandboxAdmission, empty_digest,
    is_safe_relative_path, native_build_authorization_digest,
    validate_native_build_authorization_certificate,
};
use crate::semantic_compiler::{
    ContentDigest, NativeArtifactKind, SemanticCompilerFormFaultKind, SemanticCompilerValidation,
    SemanticId, bounded_text, digest_form, exact_profile, form_fault, require_digest,
    validate_digest,
};

pub const NATIVE_BUILD_OBSERVATION_PROFILE: &str = "cantor-native-build-observation/0.1";
pub const NATIVE_BUILD_ATTEMPT_LEDGER_PROFILE: &str = "cantor-native-build-attempt-ledger/0.1";
pub const NATIVE_ARTIFACT_RECEIPT_PROFILE: &str = "cantor-native-artifact-receipt/0.1";
pub const NATIVE_BUILD_OBSERVATION_NON_AUTHORITY: &str = "Supplied runner observation and produced-unverified artifact evidence only. This form does not prove physical sandbox containment, semantic correctness, reproducibility, independent verification, signing, admission, installation, deployment, runtime execution, or successor recognition.";
pub const NATIVE_BUILD_ATTEMPT_LEDGER_NON_AUTHORITY: &str = "Deterministic single-use accounting projection only. Persistence, atomic compare-and-swap, physical execution exclusion, signing, admission, installation, deployment, runtime execution, and successor recognition require an external authority adapter.";

const OBSERVATION_DOMAIN: &str = "cantor.native-build.observation.v1";
const COMMAND_DOMAIN: &str = "cantor.native-build.command.v1";
const ATTEMPT_LEDGER_DOMAIN: &str = "cantor.native-build.attempt-ledger.v1";
const ARTIFACT_RECEIPT_DOMAIN: &str = "cantor.native-build.artifact-receipt.v1";
const MAX_OBSERVED_ARTIFACTS: usize = 64;
const MAX_FAULT_CODES: usize = 256;
const EXECUTABLE_MEDIA_TYPE: &str = "application/vnd.cantor.native-executable";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeBuildObservationDisposition {
    Succeeded,
    Failed,
    TimedOut,
    Cancelled,
    InfrastructureFault,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeArtifactReceiptLifecycle {
    ProducedUnverified,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBuildResourceUsage {
    pub process_count: u32,
    pub peak_memory_bytes: u64,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub artifact_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeObservedArtifact {
    pub artifact_id: SemanticId,
    pub relative_path: String,
    pub artifact_digest: ContentDigest,
    pub byte_size: u64,
    pub media_type: String,
    pub artifact_kind: NativeArtifactKind,
    pub target_triple: String,
    pub build_input_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBuildObservation {
    pub profile: String,
    pub attempt_id: SemanticId,
    pub authorization_ref: SemanticId,
    pub authorization_digest: ContentDigest,
    pub build_plan_ref: SemanticId,
    pub build_plan_digest: ContentDigest,
    pub candidate_ref: SemanticId,
    pub candidate_digest: ContentDigest,
    pub runner_id: SemanticId,
    pub runner_executable_digest: ContentDigest,
    pub sandbox_admission_ref: SemanticId,
    pub sandbox_admission_digest: ContentDigest,
    pub command_digest: ContentDigest,
    pub environment_digest: ContentDigest,
    pub logical_started_at: u64,
    pub logical_finished_at: u64,
    pub disposition: NativeBuildObservationDisposition,
    pub exit_code: Option<i32>,
    pub stdout_digest: ContentDigest,
    pub stderr_digest: ContentDigest,
    pub resources: NativeBuildResourceUsage,
    pub artifacts: BTreeMap<SemanticId, NativeObservedArtifact>,
    pub fault_codes: BTreeSet<String>,
    pub non_authority: String,
    pub observation_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBuildAttemptLedger {
    pub profile: String,
    pub ledger_id: SemanticId,
    pub predecessor_ledger_digest: Option<ContentDigest>,
    /// Signed approval identity to its one permitted attempt identity.
    pub consumed_approval_attempts: BTreeMap<SemanticId, SemanticId>,
    pub non_authority: String,
    pub ledger_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeArtifactReceipt {
    pub profile: String,
    pub receipt_id: SemanticId,
    pub observation_ref: SemanticId,
    pub observation_digest: ContentDigest,
    pub attempt_ledger_ref: SemanticId,
    pub attempt_ledger_digest: ContentDigest,
    pub authorization_ref: SemanticId,
    pub authorization_digest: ContentDigest,
    pub seed_ref: SemanticId,
    pub seed_digest: ContentDigest,
    pub candidate_ref: SemanticId,
    pub candidate_digest: ContentDigest,
    pub candidate_projection_digest: ContentDigest,
    pub build_plan_ref: SemanticId,
    pub build_plan_digest: ContentDigest,
    pub sandbox_admission_ref: SemanticId,
    pub sandbox_admission_digest: ContentDigest,
    pub runner_id: SemanticId,
    pub runner_executable_digest: ContentDigest,
    pub artifact: NativeObservedArtifact,
    pub lifecycle: NativeArtifactReceiptLifecycle,
    pub non_authority: String,
    pub receipt_digest: ContentDigest,
}

pub struct NativeArtifactReceiptLineage<'a> {
    pub build: NativeArtifactBuildLineage<'a>,
    pub plan: &'a NativeBuildExecutionPlan,
    pub capability: &'a NativeBuildCapabilityReceipt,
    pub sandbox: &'a NativeSandboxAdmission,
    pub trust_store: &'a NativeBuildTrustStore,
    pub authorization: &'a NativeBuildAuthorizationCertificate,
    pub observation: &'a NativeBuildObservation,
    pub attempt_ledger: &'a NativeBuildAttemptLedger,
    pub receipt: &'a NativeArtifactReceipt,
}

impl NativeArtifactReceiptLineage<'_> {
    pub fn validate(&self) -> SemanticCompilerValidation {
        validate_native_artifact_receipt(
            &self.build,
            self.plan,
            self.capability,
            self.sandbox,
            self.trust_store,
            self.authorization,
            self.observation,
            self.attempt_ledger,
            self.receipt,
        )
    }
}

pub fn native_build_command_digest(
    plan: &NativeBuildExecutionPlan,
) -> SemanticCompilerValidation<ContentDigest> {
    digest_form(
        COMMAND_DOMAIN,
        &(
            &plan.runner,
            &plan.command_schema,
            &plan.environment_digest,
            &plan.root_policy,
        ),
    )
}

pub fn native_build_observation_digest(
    observation: &NativeBuildObservation,
) -> SemanticCompilerValidation<ContentDigest> {
    let mut body = observation.clone();
    body.observation_digest = empty_digest();
    digest_form(OBSERVATION_DOMAIN, &body)
}

pub fn native_build_attempt_ledger_digest(
    ledger: &NativeBuildAttemptLedger,
) -> SemanticCompilerValidation<ContentDigest> {
    let mut body = ledger.clone();
    body.ledger_digest = empty_digest();
    digest_form(ATTEMPT_LEDGER_DOMAIN, &body)
}

pub fn native_artifact_receipt_digest(
    receipt: &NativeArtifactReceipt,
) -> SemanticCompilerValidation<ContentDigest> {
    let mut body = receipt.clone();
    body.receipt_digest = empty_digest();
    digest_form(ARTIFACT_RECEIPT_DOMAIN, &body)
}

#[allow(clippy::too_many_arguments)]
pub fn seal_native_build_observation(
    lineage: &NativeArtifactBuildLineage<'_>,
    plan: &NativeBuildExecutionPlan,
    capability: &NativeBuildCapabilityReceipt,
    sandbox: &NativeSandboxAdmission,
    trust_store: &NativeBuildTrustStore,
    authorization: &NativeBuildAuthorizationCertificate,
    mut observation: NativeBuildObservation,
) -> SemanticCompilerValidation<NativeBuildObservation> {
    observation.observation_digest = native_build_observation_digest(&observation)?;
    validate_native_build_observation(
        lineage,
        plan,
        capability,
        sandbox,
        trust_store,
        authorization,
        &observation,
    )?;
    Ok(observation)
}

#[allow(clippy::too_many_arguments)]
pub fn validate_native_build_observation(
    lineage: &NativeArtifactBuildLineage<'_>,
    plan: &NativeBuildExecutionPlan,
    capability: &NativeBuildCapabilityReceipt,
    sandbox: &NativeSandboxAdmission,
    trust_store: &NativeBuildTrustStore,
    authorization: &NativeBuildAuthorizationCertificate,
    observation: &NativeBuildObservation,
) -> SemanticCompilerValidation {
    validate_native_build_authorization_certificate(
        lineage,
        plan,
        capability,
        sandbox,
        trust_store,
        authorization,
        observation.logical_started_at,
    )?;
    exact_profile(
        &observation.profile,
        NATIVE_BUILD_OBSERVATION_PROFILE,
        "build_observation.profile",
    )?;
    let candidate = lineage.candidate();
    if observation.authorization_ref != authorization.certificate_id
        || observation.authorization_digest != authorization.authorization_digest
        || observation.build_plan_ref != plan.plan_id
        || observation.build_plan_digest != plan.plan_digest
        || observation.candidate_ref != candidate.candidate_id
        || observation.candidate_digest != candidate.candidate_digest
        || observation.runner_id != plan.runner.runner_id
        || observation.runner_executable_digest != plan.runner.executable_digest
        || observation.sandbox_admission_ref != sandbox.admission_id
        || observation.sandbox_admission_digest != sandbox.admission_digest
        || observation.command_digest != native_build_command_digest(plan)?
        || observation.environment_digest != plan.environment_digest
        || observation.logical_started_at < authorization.statement.logical_valid_from
        || observation.logical_finished_at > authorization.statement.logical_valid_until
        || observation.logical_finished_at < observation.logical_started_at
    {
        return form_fault(
            SemanticCompilerFormFaultKind::InvalidReference,
            "build_observation.lineage",
            "observation differs from the exact authorized candidate plan runner sandbox or interval",
        );
    }
    let elapsed = observation
        .logical_finished_at
        .checked_sub(observation.logical_started_at)
        .ok_or_else(|| crate::semantic_compiler::SemanticCompilerFormFault {
            kind: SemanticCompilerFormFaultKind::InvalidBound,
            field: "build_observation.elapsed".to_owned(),
            detail: "observation interval underflow".to_owned(),
        })?;
    if elapsed > u64::from(plan.maximum_seconds)
        || observation.resources.process_count > plan.maximum_processes
        || observation.resources.peak_memory_bytes > plan.maximum_memory_bytes
        || observation.resources.stdout_bytes > plan.maximum_stdout_bytes
        || observation.resources.stderr_bytes > plan.maximum_stderr_bytes
        || observation.resources.artifact_bytes > plan.maximum_output_bytes
        || observation.artifacts.len() > plan.maximum_artifacts as usize
        || observation.artifacts.len() > MAX_OBSERVED_ARTIFACTS
        || observation.fault_codes.len() > MAX_FAULT_CODES
    {
        return form_fault(
            SemanticCompilerFormFaultKind::InvalidBound,
            "build_observation.resources",
            "observed time process memory output artifact or fault count exceeds the authorized bound",
        );
    }
    let stream_bytes = observation
        .resources
        .stdout_bytes
        .checked_add(observation.resources.stderr_bytes)
        .ok_or_else(|| crate::semantic_compiler::SemanticCompilerFormFault {
            kind: SemanticCompilerFormFaultKind::InvalidBound,
            field: "build_observation.stream_bytes".to_owned(),
            detail: "stream byte accounting overflow".to_owned(),
        })?;
    if stream_bytes > plan.maximum_output_bytes {
        return form_fault(
            SemanticCompilerFormFaultKind::InvalidBound,
            "build_observation.stream_bytes",
            "combined stdout and stderr exceed the authorized output bound",
        );
    }
    validate_digest(
        &observation.stdout_digest,
        "build_observation.stdout_digest",
    )?;
    validate_digest(
        &observation.stderr_digest,
        "build_observation.stderr_digest",
    )?;
    for code in &observation.fault_codes {
        bounded_text(code, "build_observation.fault_code")?;
    }
    let mut observed_artifact_bytes = 0_u64;
    for (artifact_id, artifact) in &observation.artifacts {
        validate_observed_artifact(artifact_id, artifact, candidate)?;
        observed_artifact_bytes = observed_artifact_bytes
            .checked_add(artifact.byte_size)
            .ok_or_else(|| crate::semantic_compiler::SemanticCompilerFormFault {
                kind: SemanticCompilerFormFaultKind::InvalidBound,
                field: "build_observation.artifact_bytes".to_owned(),
                detail: "artifact byte accounting overflow".to_owned(),
            })?;
    }
    if observed_artifact_bytes != observation.resources.artifact_bytes {
        return form_fault(
            SemanticCompilerFormFaultKind::AccountingMismatch,
            "build_observation.artifact_bytes",
            "observed artifact byte sum differs from resource accounting",
        );
    }
    validate_observation_disposition(observation, candidate)?;
    exact_observation_non_authority(
        &observation.non_authority,
        "build_observation.non_authority",
    )?;
    validate_digest(
        &observation.observation_digest,
        "build_observation.observation_digest",
    )?;
    require_digest(
        &observation.observation_digest,
        native_build_observation_digest(observation)?,
        "build_observation.observation_digest",
    )
}

pub fn new_native_build_attempt_ledger(
    ledger_id: SemanticId,
) -> SemanticCompilerValidation<NativeBuildAttemptLedger> {
    let mut value = NativeBuildAttemptLedger {
        profile: NATIVE_BUILD_ATTEMPT_LEDGER_PROFILE.to_owned(),
        ledger_id,
        predecessor_ledger_digest: None,
        consumed_approval_attempts: BTreeMap::new(),
        non_authority: NATIVE_BUILD_ATTEMPT_LEDGER_NON_AUTHORITY.to_owned(),
        ledger_digest: empty_digest(),
    };
    value.ledger_digest = native_build_attempt_ledger_digest(&value)?;
    validate_native_build_attempt_ledger(&value)?;
    Ok(value)
}

pub fn validate_native_build_attempt_ledger(
    ledger: &NativeBuildAttemptLedger,
) -> SemanticCompilerValidation {
    exact_profile(
        &ledger.profile,
        NATIVE_BUILD_ATTEMPT_LEDGER_PROFILE,
        "attempt_ledger.profile",
    )?;
    if ledger.consumed_approval_attempts.len() > MAX_OBSERVED_ARTIFACTS * 1024 {
        return form_fault(
            SemanticCompilerFormFaultKind::InvalidBound,
            "attempt_ledger.consumed_approval_attempts",
            "attempt ledger exceeds its bounded in-memory projection",
        );
    }
    if let Some(predecessor) = &ledger.predecessor_ledger_digest {
        validate_digest(predecessor, "attempt_ledger.predecessor_ledger_digest")?;
    }
    let unique_attempts: BTreeSet<&SemanticId> =
        ledger.consumed_approval_attempts.values().collect();
    if unique_attempts.len() != ledger.consumed_approval_attempts.len() {
        return form_fault(
            SemanticCompilerFormFaultKind::AccountingMismatch,
            "attempt_ledger.attempt_identity",
            "one attempt identity cannot consume multiple authorizations",
        );
    }
    if ledger.non_authority != NATIVE_BUILD_ATTEMPT_LEDGER_NON_AUTHORITY {
        return form_fault(
            SemanticCompilerFormFaultKind::NonAuthorityMismatch,
            "attempt_ledger.non_authority",
            "attempt ledger changed or omitted its external persistence boundary",
        );
    }
    validate_digest(&ledger.ledger_digest, "attempt_ledger.ledger_digest")?;
    require_digest(
        &ledger.ledger_digest,
        native_build_attempt_ledger_digest(ledger)?,
        "attempt_ledger.ledger_digest",
    )
}

pub fn record_native_build_attempt(
    ledger: &NativeBuildAttemptLedger,
    authorization: &NativeBuildAuthorizationCertificate,
    observation: &NativeBuildObservation,
) -> SemanticCompilerValidation<NativeBuildAttemptLedger> {
    validate_native_build_attempt_ledger(ledger)?;
    validate_digest(
        &authorization.authorization_digest,
        "attempt_ledger.authorization_digest",
    )?;
    require_digest(
        &authorization.authorization_digest,
        native_build_authorization_digest(authorization)?,
        "attempt_ledger.authorization_digest",
    )?;
    validate_digest(
        &observation.observation_digest,
        "attempt_ledger.observation_digest",
    )?;
    require_digest(
        &observation.observation_digest,
        native_build_observation_digest(observation)?,
        "attempt_ledger.observation_digest",
    )?;
    if observation.authorization_ref != authorization.certificate_id
        || observation.authorization_digest != authorization.authorization_digest
        || ledger
            .consumed_approval_attempts
            .contains_key(&authorization.statement.approval_id)
        || ledger
            .consumed_approval_attempts
            .values()
            .any(|attempt| attempt == &observation.attempt_id)
    {
        return form_fault(
            SemanticCompilerFormFaultKind::StageOrder,
            "attempt_ledger.single_use",
            "authorization or attempt identity has already been consumed or does not match",
        );
    }
    let mut value = ledger.clone();
    value.predecessor_ledger_digest = Some(ledger.ledger_digest.clone());
    value.consumed_approval_attempts.insert(
        authorization.statement.approval_id.clone(),
        observation.attempt_id.clone(),
    );
    value.ledger_digest = native_build_attempt_ledger_digest(&value)?;
    validate_native_build_attempt_ledger(&value)?;
    Ok(value)
}

#[allow(clippy::too_many_arguments)]
pub fn project_native_artifact_receipt(
    lineage: &NativeArtifactBuildLineage<'_>,
    plan: &NativeBuildExecutionPlan,
    capability: &NativeBuildCapabilityReceipt,
    sandbox: &NativeSandboxAdmission,
    trust_store: &NativeBuildTrustStore,
    authorization: &NativeBuildAuthorizationCertificate,
    observation: &NativeBuildObservation,
    ledger: &NativeBuildAttemptLedger,
    receipt_id: SemanticId,
) -> SemanticCompilerValidation<NativeArtifactReceipt> {
    validate_native_build_observation(
        lineage,
        plan,
        capability,
        sandbox,
        trust_store,
        authorization,
        observation,
    )?;
    validate_native_build_attempt_ledger(ledger)?;
    if observation.disposition != NativeBuildObservationDisposition::Succeeded
        || ledger
            .consumed_approval_attempts
            .get(&authorization.statement.approval_id)
            != Some(&observation.attempt_id)
    {
        return form_fault(
            SemanticCompilerFormFaultKind::StageOrder,
            "artifact_receipt.production_gate",
            "only a successful single-use-accounted observation may produce an artifact receipt",
        );
    }
    let candidate = lineage.candidate();
    let artifact = observation
        .artifacts
        .get(&candidate.build.expected_output_id)
        .cloned()
        .ok_or_else(|| crate::semantic_compiler::SemanticCompilerFormFault {
            kind: SemanticCompilerFormFaultKind::MissingSourceMap,
            field: "artifact_receipt.artifact".to_owned(),
            detail: "successful observation omitted the expected artifact".to_owned(),
        })?;
    let mut value = NativeArtifactReceipt {
        profile: NATIVE_ARTIFACT_RECEIPT_PROFILE.to_owned(),
        receipt_id,
        observation_ref: observation.attempt_id.clone(),
        observation_digest: observation.observation_digest.clone(),
        attempt_ledger_ref: ledger.ledger_id.clone(),
        attempt_ledger_digest: ledger.ledger_digest.clone(),
        authorization_ref: authorization.certificate_id.clone(),
        authorization_digest: authorization.authorization_digest.clone(),
        seed_ref: lineage.seed.seed_id.clone(),
        seed_digest: lineage.seed.seed_digest.clone(),
        candidate_ref: candidate.candidate_id.clone(),
        candidate_digest: candidate.candidate_digest.clone(),
        candidate_projection_digest: lineage.projection.projection_digest.clone(),
        build_plan_ref: plan.plan_id.clone(),
        build_plan_digest: plan.plan_digest.clone(),
        sandbox_admission_ref: sandbox.admission_id.clone(),
        sandbox_admission_digest: sandbox.admission_digest.clone(),
        runner_id: plan.runner.runner_id.clone(),
        runner_executable_digest: plan.runner.executable_digest.clone(),
        artifact,
        lifecycle: NativeArtifactReceiptLifecycle::ProducedUnverified,
        non_authority: NATIVE_BUILD_OBSERVATION_NON_AUTHORITY.to_owned(),
        receipt_digest: empty_digest(),
    };
    value.receipt_digest = native_artifact_receipt_digest(&value)?;
    validate_native_artifact_receipt(
        lineage,
        plan,
        capability,
        sandbox,
        trust_store,
        authorization,
        observation,
        ledger,
        &value,
    )?;
    Ok(value)
}

#[allow(clippy::too_many_arguments)]
pub fn validate_native_artifact_receipt(
    lineage: &NativeArtifactBuildLineage<'_>,
    plan: &NativeBuildExecutionPlan,
    capability: &NativeBuildCapabilityReceipt,
    sandbox: &NativeSandboxAdmission,
    trust_store: &NativeBuildTrustStore,
    authorization: &NativeBuildAuthorizationCertificate,
    observation: &NativeBuildObservation,
    ledger: &NativeBuildAttemptLedger,
    receipt: &NativeArtifactReceipt,
) -> SemanticCompilerValidation {
    validate_native_build_observation(
        lineage,
        plan,
        capability,
        sandbox,
        trust_store,
        authorization,
        observation,
    )?;
    validate_native_build_attempt_ledger(ledger)?;
    exact_profile(
        &receipt.profile,
        NATIVE_ARTIFACT_RECEIPT_PROFILE,
        "artifact_receipt.profile",
    )?;
    let candidate = lineage.candidate();
    let expected_artifact = observation
        .artifacts
        .get(&candidate.build.expected_output_id);
    if observation.disposition != NativeBuildObservationDisposition::Succeeded
        || ledger
            .consumed_approval_attempts
            .get(&authorization.statement.approval_id)
            != Some(&observation.attempt_id)
        || receipt.observation_ref != observation.attempt_id
        || receipt.observation_digest != observation.observation_digest
        || receipt.attempt_ledger_ref != ledger.ledger_id
        || receipt.attempt_ledger_digest != ledger.ledger_digest
        || receipt.authorization_ref != authorization.certificate_id
        || receipt.authorization_digest != authorization.authorization_digest
        || receipt.seed_ref != lineage.seed.seed_id
        || receipt.seed_digest != lineage.seed.seed_digest
        || receipt.candidate_ref != candidate.candidate_id
        || receipt.candidate_digest != candidate.candidate_digest
        || receipt.candidate_projection_digest != lineage.projection.projection_digest
        || receipt.build_plan_ref != plan.plan_id
        || receipt.build_plan_digest != plan.plan_digest
        || receipt.sandbox_admission_ref != sandbox.admission_id
        || receipt.sandbox_admission_digest != sandbox.admission_digest
        || receipt.runner_id != plan.runner.runner_id
        || receipt.runner_executable_digest != plan.runner.executable_digest
        || expected_artifact != Some(&receipt.artifact)
        || receipt.lifecycle != NativeArtifactReceiptLifecycle::ProducedUnverified
    {
        return form_fault(
            SemanticCompilerFormFaultKind::InvalidReference,
            "artifact_receipt.lineage",
            "artifact receipt differs from its exact successful authorized and accounted observation lineage",
        );
    }
    exact_observation_non_authority(&receipt.non_authority, "artifact_receipt.non_authority")?;
    validate_digest(&receipt.receipt_digest, "artifact_receipt.receipt_digest")?;
    require_digest(
        &receipt.receipt_digest,
        native_artifact_receipt_digest(receipt)?,
        "artifact_receipt.receipt_digest",
    )
}

fn validate_observed_artifact(
    map_id: &SemanticId,
    artifact: &NativeObservedArtifact,
    candidate: &super::NativeArtifactCandidate,
) -> SemanticCompilerValidation {
    if map_id != &artifact.artifact_id
        || !is_safe_relative_path(&artifact.relative_path)
        || artifact.byte_size == 0
        || artifact.build_input_digest != candidate.candidate_digest
    {
        return form_fault(
            SemanticCompilerFormFaultKind::InvalidReference,
            "build_observation.artifact",
            "observed artifact identity path size or build input binding is invalid",
        );
    }
    bounded_text(
        &artifact.media_type,
        "build_observation.artifact.media_type",
    )?;
    bounded_text(
        &artifact.target_triple,
        "build_observation.artifact.target_triple",
    )?;
    validate_digest(
        &artifact.artifact_digest,
        "build_observation.artifact.digest",
    )
}

fn validate_observation_disposition(
    observation: &NativeBuildObservation,
    candidate: &super::NativeArtifactCandidate,
) -> SemanticCompilerValidation {
    match observation.disposition {
        NativeBuildObservationDisposition::Succeeded => {
            let expected = observation
                .artifacts
                .get(&candidate.build.expected_output_id);
            if observation.exit_code != Some(0)
                || !observation.fault_codes.is_empty()
                || observation.artifacts.len() != 1
                || expected.is_none_or(|artifact| {
                    artifact.relative_path != candidate.build.expected_output_relative_path
                        || artifact.media_type != EXECUTABLE_MEDIA_TYPE
                        || artifact.artifact_kind != candidate.artifact_kind
                        || artifact.target_triple != candidate.toolchain.target_triple
                })
            {
                return form_fault(
                    SemanticCompilerFormFaultKind::AccountingMismatch,
                    "build_observation.success",
                    "successful observation must contain only the exact expected executable and zero exit without faults",
                );
            }
        }
        NativeBuildObservationDisposition::Failed => {
            if observation.exit_code.is_none_or(|code| code == 0)
                || observation.fault_codes.is_empty()
            {
                return form_fault(
                    SemanticCompilerFormFaultKind::AccountingMismatch,
                    "build_observation.failure",
                    "failed observation requires a nonzero exit and a bounded fault code",
                );
            }
        }
        NativeBuildObservationDisposition::TimedOut
        | NativeBuildObservationDisposition::Cancelled
        | NativeBuildObservationDisposition::InfrastructureFault => {
            if observation.fault_codes.is_empty() {
                return form_fault(
                    SemanticCompilerFormFaultKind::AccountingMismatch,
                    "build_observation.interruption",
                    "interrupted observation requires a bounded fault code",
                );
            }
        }
    }
    Ok(())
}

fn exact_observation_non_authority(value: &str, field: &str) -> SemanticCompilerValidation {
    if value == NATIVE_BUILD_OBSERVATION_NON_AUTHORITY {
        Ok(())
    } else {
        form_fault(
            SemanticCompilerFormFaultKind::NonAuthorityMismatch,
            field,
            "observation or receipt changed its produced-unverified authority boundary",
        )
    }
}
