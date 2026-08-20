//! Authority-separated native build and artifact receipt lifecycle.
//!
//! The core validates exact plans, supplied containment evidence, dual
//! approvals, observations, and receipts. It contains no production filesystem,
//! process, clock, environment, network, signing-key, installation, or execution
//! adapter.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use super::{CandidateCompilationPlan, NativeArtifactCandidate};
use super::{
    CapabilityDisposition, CompilerBackendKind, CompilerCapability, ContentDigest,
    NativeArtifactBackendProjection, NativeArtifactBackendRequest, SemanticCompilerFormFaultKind,
    SemanticCompilerValidation, SemanticId, SopSeed, TypedSopIr, bounded_text, digest_form,
    exact_profile, form_fault, require_digest, validate_digest,
    validate_native_artifact_backend_projection, validate_sop_seed,
};

mod observation;
pub use observation::*;

mod verification;
pub use verification::*;

pub const NATIVE_BUILD_EXECUTION_PLAN_PROFILE: &str = "cantor-native-build-execution-plan/0.1";
pub const NATIVE_BUILD_CAPABILITY_RECEIPT_PROFILE: &str =
    "cantor-native-build-capability-receipt/0.1";
pub const NATIVE_SANDBOX_ADMISSION_PROFILE: &str = "cantor-native-sandbox-admission/0.1";
pub const NATIVE_BUILD_APPROVAL_STATEMENT_PROFILE: &str =
    "cantor-native-build-approval-statement/0.1";
pub const NATIVE_BUILD_TRUST_STORE_PROFILE: &str = "cantor-native-build-trust-store/0.1";
pub const NATIVE_BUILD_AUTHORIZATION_PROFILE: &str =
    "cantor-native-build-authorization-certificate/0.1";
pub const NATIVE_BUILD_SIGNATURE_PROFILE: &str = "Ed25519/Cantor-Native-Build-Approval-v1";
pub const NATIVE_BUILD_PLAN_NON_AUTHORITY: &str = "Native build planning and approval evidence only. Physical containment, process execution, artifact production, reproducibility, verification, signing, admission, installation, deployment, runtime execution, effect authority, and successor recognition are not granted by this form.";

const PLAN_DOMAIN: &str = "cantor.native-build.execution-plan.v1";
const CAPABILITY_DOMAIN: &str = "cantor.native-build.capability-receipt.v1";
const SANDBOX_DOMAIN: &str = "cantor.native-build.sandbox-admission.v1";
const APPROVAL_DOMAIN: &str = "cantor.native-build.approval-statement.v1";
const TRUST_STORE_DOMAIN: &str = "cantor.native-build.trust-store.v1";
const AUTHORIZATION_DOMAIN: &str = "cantor.native-build.authorization.v1";
const APPROVAL_SIGNING_DOMAIN: &str = "cantor.native-build.approval-signature.v1";
const MAX_ID_ITEMS: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeDeniedWriteClass {
    OutsideDisposableRoot,
    Repository,
    SealRoot,
    Credential,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeBuildPlanLifecycle {
    Proposed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeSandboxContainment {
    ProvenForProfile,
    Unresolved,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeSandboxDisposition {
    Admitted,
    Refused,
    Unresolved,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBuildRunnerPin {
    pub runner_id: SemanticId,
    pub adapter_profile: String,
    pub executable_digest: ContentDigest,
    pub configuration_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBuildRootPolicy {
    pub disposable_root_id: SemanticId,
    pub disposable_root_relative_path: String,
    pub expected_artifact_relative_path: String,
    pub disposable_root_create_new: bool,
    pub artifact_create_new: bool,
    pub denied_write_classes: BTreeSet<NativeDeniedWriteClass>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBuildExecutionPlan {
    pub profile: String,
    pub plan_id: SemanticId,
    pub seed_ref: SemanticId,
    pub seed_digest: ContentDigest,
    pub candidate_ref: SemanticId,
    pub candidate_digest: ContentDigest,
    pub candidate_projection_digest: ContentDigest,
    pub backend: CompilerBackendKind,
    pub runner: NativeBuildRunnerPin,
    pub sandbox_profile: String,
    pub command_schema: Vec<String>,
    pub environment_digest: ContentDigest,
    pub root_policy: NativeBuildRootPolicy,
    pub logical_not_before: u64,
    pub logical_not_after: u64,
    pub requested_capabilities: BTreeSet<CompilerCapability>,
    pub maximum_seconds: u32,
    pub maximum_processes: u32,
    pub maximum_memory_bytes: u64,
    pub maximum_stdout_bytes: u64,
    pub maximum_stderr_bytes: u64,
    pub maximum_output_bytes: u64,
    pub maximum_artifacts: u32,
    pub lifecycle: NativeBuildPlanLifecycle,
    pub non_authority: String,
    pub plan_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBuildCapabilityReceipt {
    pub profile: String,
    pub receipt_id: SemanticId,
    pub build_plan_ref: SemanticId,
    pub build_plan_digest: ContentDigest,
    pub seed_ref: SemanticId,
    pub seed_digest: ContentDigest,
    pub ceiling_ref: SemanticId,
    pub ceiling_digest: ContentDigest,
    pub requested_capabilities: BTreeSet<CompilerCapability>,
    pub admitted_capabilities: BTreeSet<CompilerCapability>,
    pub denied_capabilities: BTreeSet<CompilerCapability>,
    pub admitted_resource_scopes: BTreeSet<String>,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub disposition: CapabilityDisposition,
    pub non_authority: String,
    pub receipt_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSandboxAdmission {
    pub profile: String,
    pub admission_id: SemanticId,
    pub provider_id: SemanticId,
    pub platform_profile: String,
    pub sandbox_profile: String,
    pub root_policy: NativeBuildRootPolicy,
    pub containment: NativeSandboxContainment,
    pub network_denied: bool,
    pub repository_writes_denied: bool,
    pub seal_root_writes_denied: bool,
    pub credential_access_denied: bool,
    pub runner_executable_digest: ContentDigest,
    pub environment_digest: ContentDigest,
    pub logical_valid_from: u64,
    pub logical_valid_until: u64,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub disposition: NativeSandboxDisposition,
    pub non_authority: String,
    pub admission_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBuildApprovalStatement {
    pub profile: String,
    pub approval_id: SemanticId,
    pub seed_ref: SemanticId,
    pub seed_digest: ContentDigest,
    pub candidate_ref: SemanticId,
    pub candidate_digest: ContentDigest,
    pub build_plan_ref: SemanticId,
    pub build_plan_digest: ContentDigest,
    pub capability_receipt_ref: SemanticId,
    pub capability_receipt_digest: ContentDigest,
    pub sandbox_admission_ref: SemanticId,
    pub sandbox_admission_digest: ContentDigest,
    pub runner_id: SemanticId,
    pub runner_executable_digest: ContentDigest,
    pub logical_valid_from: u64,
    pub logical_valid_until: u64,
    pub single_use: bool,
    pub non_authority: String,
    pub statement_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBuildTrustStore {
    pub profile: String,
    pub store_id: SemanticId,
    pub security_verifying_keys: BTreeMap<SemanticId, Vec<u8>>,
    pub authority_verifying_keys: BTreeMap<SemanticId, Vec<u8>>,
    pub revoked_approval_ids: BTreeSet<SemanticId>,
    pub revoked_certificate_ids: BTreeSet<SemanticId>,
    pub store_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBuildAuthorizationCertificate {
    pub profile: String,
    pub certificate_id: SemanticId,
    pub statement: NativeBuildApprovalStatement,
    pub trust_store_ref: SemanticId,
    pub trust_store_digest: ContentDigest,
    pub security_signer_id: SemanticId,
    pub authority_signer_id: SemanticId,
    pub signature_profile: String,
    pub security_signature: Vec<u8>,
    pub authority_signature: Vec<u8>,
    pub authorization_digest: ContentDigest,
}

pub struct NativeArtifactBuildLineage<'a> {
    pub seed: &'a SopSeed,
    pub ir: &'a TypedSopIr,
    pub candidate_plan: &'a CandidateCompilationPlan,
    pub candidate_request: &'a NativeArtifactBackendRequest,
    pub projection: &'a NativeArtifactBackendProjection,
}

impl NativeArtifactBuildLineage<'_> {
    pub fn validate(&self) -> SemanticCompilerValidation {
        validate_native_artifact_backend_projection(
            self.seed,
            self.ir,
            self.candidate_plan,
            self.candidate_request,
            self.projection,
        )
    }

    pub fn candidate(&self) -> &NativeArtifactCandidate {
        &self.projection.candidate
    }
}

pub fn native_build_execution_plan_digest(
    plan: &NativeBuildExecutionPlan,
) -> SemanticCompilerValidation<ContentDigest> {
    let mut body = plan.clone();
    body.plan_digest = empty_digest();
    digest_form(PLAN_DOMAIN, &body)
}

pub fn native_build_capability_receipt_digest(
    receipt: &NativeBuildCapabilityReceipt,
) -> SemanticCompilerValidation<ContentDigest> {
    let mut body = receipt.clone();
    body.receipt_digest = empty_digest();
    digest_form(CAPABILITY_DOMAIN, &body)
}

pub fn native_sandbox_admission_digest(
    admission: &NativeSandboxAdmission,
) -> SemanticCompilerValidation<ContentDigest> {
    let mut body = admission.clone();
    body.admission_digest = empty_digest();
    digest_form(SANDBOX_DOMAIN, &body)
}

pub fn native_build_approval_statement_digest(
    statement: &NativeBuildApprovalStatement,
) -> SemanticCompilerValidation<ContentDigest> {
    let mut body = statement.clone();
    body.statement_digest = empty_digest();
    digest_form(APPROVAL_DOMAIN, &body)
}

pub fn native_build_trust_store_digest(
    store: &NativeBuildTrustStore,
) -> SemanticCompilerValidation<ContentDigest> {
    let mut body = store.clone();
    body.store_digest = empty_digest();
    digest_form(TRUST_STORE_DOMAIN, &body)
}

pub fn native_build_authorization_digest(
    certificate: &NativeBuildAuthorizationCertificate,
) -> SemanticCompilerValidation<ContentDigest> {
    let mut body = certificate.clone();
    body.authorization_digest = empty_digest();
    digest_form(AUTHORIZATION_DOMAIN, &body)
}

#[allow(clippy::too_many_arguments)]
pub fn project_native_build_execution_plan(
    lineage: &NativeArtifactBuildLineage<'_>,
    plan_id: SemanticId,
    runner: NativeBuildRunnerPin,
    sandbox_profile: String,
    root_policy: NativeBuildRootPolicy,
    logical_not_before: u64,
    logical_not_after: u64,
) -> SemanticCompilerValidation<NativeBuildExecutionPlan> {
    lineage.validate()?;
    let seed = lineage.seed;
    let projection = lineage.projection;
    let candidate = lineage.candidate();
    let mut value = NativeBuildExecutionPlan {
        profile: NATIVE_BUILD_EXECUTION_PLAN_PROFILE.to_owned(),
        plan_id,
        seed_ref: seed.seed_id.clone(),
        seed_digest: seed.seed_digest.clone(),
        candidate_ref: candidate.candidate_id.clone(),
        candidate_digest: candidate.candidate_digest.clone(),
        candidate_projection_digest: projection.projection_digest.clone(),
        backend: CompilerBackendKind::NativeArtifact,
        runner,
        sandbox_profile,
        command_schema: candidate.build.command_schema.clone(),
        environment_digest: candidate.toolchain.configuration_digest.clone(),
        root_policy,
        logical_not_before,
        logical_not_after,
        requested_capabilities: required_build_capabilities(),
        maximum_seconds: candidate.build.maximum_seconds,
        maximum_processes: candidate.build.maximum_processes,
        maximum_memory_bytes: candidate.build.maximum_memory_bytes,
        maximum_stdout_bytes: candidate.build.maximum_output_bytes,
        maximum_stderr_bytes: candidate.build.maximum_output_bytes,
        maximum_output_bytes: candidate.build.maximum_output_bytes,
        maximum_artifacts: candidate.build.maximum_artifacts,
        lifecycle: NativeBuildPlanLifecycle::Proposed,
        non_authority: NATIVE_BUILD_PLAN_NON_AUTHORITY.to_owned(),
        plan_digest: empty_digest(),
    };
    value.plan_digest = native_build_execution_plan_digest(&value)?;
    validate_native_build_execution_plan(lineage, &value)?;
    Ok(value)
}

pub fn validate_native_build_execution_plan(
    lineage: &NativeArtifactBuildLineage<'_>,
    plan: &NativeBuildExecutionPlan,
) -> SemanticCompilerValidation {
    lineage.validate()?;
    let seed = lineage.seed;
    let candidate = lineage.candidate();
    validate_sop_seed(seed)?;
    exact_profile(
        &plan.profile,
        NATIVE_BUILD_EXECUTION_PLAN_PROFILE,
        "build_plan.profile",
    )?;
    validate_digest(&candidate.candidate_digest, "build_plan.candidate_digest")?;
    if plan.seed_ref != seed.seed_id
        || plan.seed_digest != seed.seed_digest
        || plan.candidate_ref != candidate.candidate_id
        || plan.candidate_digest != candidate.candidate_digest
        || plan.candidate_projection_digest != lineage.projection.projection_digest
        || plan.backend != CompilerBackendKind::NativeArtifact
        || plan.command_schema != candidate.build.command_schema
        || plan.environment_digest != candidate.toolchain.configuration_digest
        || plan.requested_capabilities != required_build_capabilities()
        || plan.maximum_seconds != candidate.build.maximum_seconds
        || plan.maximum_processes != candidate.build.maximum_processes
        || plan.maximum_memory_bytes != candidate.build.maximum_memory_bytes
        || plan.maximum_stdout_bytes != candidate.build.maximum_output_bytes
        || plan.maximum_stderr_bytes != candidate.build.maximum_output_bytes
        || plan.maximum_output_bytes != candidate.build.maximum_output_bytes
        || plan.maximum_artifacts != 1
        || plan.lifecycle != NativeBuildPlanLifecycle::Proposed
    {
        return form_fault(
            SemanticCompilerFormFaultKind::InvalidReference,
            "build_plan.lineage",
            "build plan differs from exact seed candidate command capability or bounds",
        );
    }
    validate_runner(&plan.runner)?;
    bounded_text(&plan.sandbox_profile, "build_plan.sandbox_profile")?;
    validate_root_policy(&plan.root_policy, candidate)?;
    if plan.logical_not_before >= plan.logical_not_after {
        return form_fault(
            SemanticCompilerFormFaultKind::InvalidBound,
            "build_plan.logical_validity",
            "build plan validity interval must be positive",
        );
    }
    exact_build_non_authority(&plan.non_authority, "build_plan.non_authority")?;
    validate_digest(&plan.plan_digest, "build_plan.plan_digest")?;
    require_digest(
        &plan.plan_digest,
        native_build_execution_plan_digest(plan)?,
        "build_plan.plan_digest",
    )
}

pub fn project_native_build_capability_receipt(
    lineage: &NativeArtifactBuildLineage<'_>,
    plan: &NativeBuildExecutionPlan,
    receipt_id: SemanticId,
    admitted_capabilities: BTreeSet<CompilerCapability>,
    admitted_resource_scopes: BTreeSet<String>,
    evidence_refs: BTreeSet<SemanticId>,
) -> SemanticCompilerValidation<NativeBuildCapabilityReceipt> {
    validate_native_build_execution_plan(lineage, plan)?;
    let seed = lineage.seed;
    let denied_capabilities: BTreeSet<CompilerCapability> = plan
        .requested_capabilities
        .difference(&admitted_capabilities)
        .cloned()
        .collect();
    let disposition = if !evidence_refs.is_empty()
        && denied_capabilities.is_empty()
        && admitted_resource_scopes.is_subset(&seed.capability_ceiling.resource_scopes)
        && !admitted_resource_scopes.is_empty()
    {
        CapabilityDisposition::WithinCeiling
    } else if denied_capabilities.is_empty() {
        CapabilityDisposition::Unresolved
    } else {
        CapabilityDisposition::ExceedsCeiling
    };
    let mut value = NativeBuildCapabilityReceipt {
        profile: NATIVE_BUILD_CAPABILITY_RECEIPT_PROFILE.to_owned(),
        receipt_id,
        build_plan_ref: plan.plan_id.clone(),
        build_plan_digest: plan.plan_digest.clone(),
        seed_ref: seed.seed_id.clone(),
        seed_digest: seed.seed_digest.clone(),
        ceiling_ref: seed.capability_ceiling.ceiling_id.clone(),
        ceiling_digest: seed.capability_ceiling.ceiling_digest.clone(),
        requested_capabilities: plan.requested_capabilities.clone(),
        admitted_capabilities,
        denied_capabilities,
        admitted_resource_scopes,
        evidence_refs,
        disposition,
        non_authority: NATIVE_BUILD_PLAN_NON_AUTHORITY.to_owned(),
        receipt_digest: empty_digest(),
    };
    value.receipt_digest = native_build_capability_receipt_digest(&value)?;
    validate_native_build_capability_receipt(lineage, plan, &value)?;
    Ok(value)
}

pub fn validate_native_build_capability_receipt(
    lineage: &NativeArtifactBuildLineage<'_>,
    plan: &NativeBuildExecutionPlan,
    receipt: &NativeBuildCapabilityReceipt,
) -> SemanticCompilerValidation {
    validate_native_build_execution_plan(lineage, plan)?;
    let seed = lineage.seed;
    validate_sop_seed(seed)?;
    exact_profile(
        &receipt.profile,
        NATIVE_BUILD_CAPABILITY_RECEIPT_PROFILE,
        "build_capability.profile",
    )?;
    if receipt.build_plan_ref != plan.plan_id
        || receipt.build_plan_digest != plan.plan_digest
        || receipt.seed_ref != seed.seed_id
        || receipt.seed_digest != seed.seed_digest
        || receipt.ceiling_ref != seed.capability_ceiling.ceiling_id
        || receipt.ceiling_digest != seed.capability_ceiling.ceiling_digest
        || receipt.requested_capabilities != plan.requested_capabilities
        || !receipt
            .admitted_capabilities
            .is_subset(&seed.capability_ceiling.capabilities)
        || !receipt
            .admitted_resource_scopes
            .is_subset(&seed.capability_ceiling.resource_scopes)
        || !receipt
            .admitted_capabilities
            .is_disjoint(&receipt.denied_capabilities)
        || receipt
            .admitted_capabilities
            .union(&receipt.denied_capabilities)
            .cloned()
            .collect::<BTreeSet<_>>()
            != receipt.requested_capabilities
    {
        return form_fault(
            SemanticCompilerFormFaultKind::AccountingMismatch,
            "build_capability.account",
            "later-stage plan ceiling capability or resource accounting differs",
        );
    }
    if receipt.evidence_refs.len() > MAX_ID_ITEMS {
        return form_fault(
            SemanticCompilerFormFaultKind::InvalidBound,
            "build_capability.evidence_refs",
            "evidence reference count exceeds the finite form bound",
        );
    }
    let expected = if !receipt.evidence_refs.is_empty()
        && receipt.denied_capabilities.is_empty()
        && !receipt.admitted_resource_scopes.is_empty()
    {
        CapabilityDisposition::WithinCeiling
    } else if receipt.denied_capabilities.is_empty() {
        CapabilityDisposition::Unresolved
    } else {
        CapabilityDisposition::ExceedsCeiling
    };
    if receipt.disposition != expected {
        return form_fault(
            SemanticCompilerFormFaultKind::AccountingMismatch,
            "build_capability.disposition",
            "capability disposition differs from exact accounting and evidence",
        );
    }
    exact_build_non_authority(&receipt.non_authority, "build_capability.non_authority")?;
    validate_digest(&receipt.receipt_digest, "build_capability.receipt_digest")?;
    require_digest(
        &receipt.receipt_digest,
        native_build_capability_receipt_digest(receipt)?,
        "build_capability.receipt_digest",
    )
}

pub fn validate_native_sandbox_admission(
    plan: &NativeBuildExecutionPlan,
    admission: &NativeSandboxAdmission,
) -> SemanticCompilerValidation {
    exact_profile(
        &admission.profile,
        NATIVE_SANDBOX_ADMISSION_PROFILE,
        "sandbox.profile",
    )?;
    if admission.sandbox_profile != plan.sandbox_profile
        || admission.root_policy != plan.root_policy
        || admission.runner_executable_digest != plan.runner.executable_digest
        || admission.environment_digest != plan.environment_digest
        || admission.logical_valid_from > plan.logical_not_before
        || admission.logical_valid_until < plan.logical_not_after
        || admission.logical_valid_from >= admission.logical_valid_until
    {
        return form_fault(
            SemanticCompilerFormFaultKind::InvalidReference,
            "sandbox.lineage",
            "sandbox root runner environment profile or validity differs from plan",
        );
    }
    bounded_text(&admission.platform_profile, "sandbox.platform_profile")?;
    if admission.evidence_refs.len() > MAX_ID_ITEMS {
        return form_fault(
            SemanticCompilerFormFaultKind::InvalidBound,
            "sandbox.evidence_refs",
            "sandbox evidence exceeds the finite form bound",
        );
    }
    let admitted = admission.containment == NativeSandboxContainment::ProvenForProfile
        && admission.network_denied
        && admission.repository_writes_denied
        && admission.seal_root_writes_denied
        && admission.credential_access_denied
        && !admission.evidence_refs.is_empty();
    let expected = if admitted {
        NativeSandboxDisposition::Admitted
    } else if admission.containment == NativeSandboxContainment::Unresolved {
        NativeSandboxDisposition::Unresolved
    } else {
        NativeSandboxDisposition::Refused
    };
    if admission.disposition != expected {
        return form_fault(
            SemanticCompilerFormFaultKind::AccountingMismatch,
            "sandbox.disposition",
            "sandbox disposition differs from supplied containment and denial evidence",
        );
    }
    exact_build_non_authority(&admission.non_authority, "sandbox.non_authority")?;
    validate_digest(&admission.admission_digest, "sandbox.admission_digest")?;
    require_digest(
        &admission.admission_digest,
        native_sandbox_admission_digest(admission)?,
        "sandbox.admission_digest",
    )
}

pub fn project_native_build_approval_statement(
    lineage: &NativeArtifactBuildLineage<'_>,
    plan: &NativeBuildExecutionPlan,
    capability: &NativeBuildCapabilityReceipt,
    sandbox: &NativeSandboxAdmission,
    approval_id: SemanticId,
) -> SemanticCompilerValidation<NativeBuildApprovalStatement> {
    let seed = lineage.seed;
    let candidate = lineage.candidate();
    validate_native_build_execution_plan(lineage, plan)?;
    validate_native_build_capability_receipt(lineage, plan, capability)?;
    validate_native_sandbox_admission(plan, sandbox)?;
    if capability.disposition != CapabilityDisposition::WithinCeiling
        || sandbox.disposition != NativeSandboxDisposition::Admitted
    {
        return form_fault(
            SemanticCompilerFormFaultKind::RecognitionBoundary,
            "approval.prerequisites",
            "approval requires within-ceiling capability and admitted supplied sandbox evidence",
        );
    }
    let mut value = NativeBuildApprovalStatement {
        profile: NATIVE_BUILD_APPROVAL_STATEMENT_PROFILE.to_owned(),
        approval_id,
        seed_ref: seed.seed_id.clone(),
        seed_digest: seed.seed_digest.clone(),
        candidate_ref: candidate.candidate_id.clone(),
        candidate_digest: candidate.candidate_digest.clone(),
        build_plan_ref: plan.plan_id.clone(),
        build_plan_digest: plan.plan_digest.clone(),
        capability_receipt_ref: capability.receipt_id.clone(),
        capability_receipt_digest: capability.receipt_digest.clone(),
        sandbox_admission_ref: sandbox.admission_id.clone(),
        sandbox_admission_digest: sandbox.admission_digest.clone(),
        runner_id: plan.runner.runner_id.clone(),
        runner_executable_digest: plan.runner.executable_digest.clone(),
        logical_valid_from: plan.logical_not_before,
        logical_valid_until: plan.logical_not_after,
        single_use: true,
        non_authority: NATIVE_BUILD_PLAN_NON_AUTHORITY.to_owned(),
        statement_digest: empty_digest(),
    };
    value.statement_digest = native_build_approval_statement_digest(&value)?;
    validate_native_build_approval_statement(lineage, plan, capability, sandbox, &value)?;
    Ok(value)
}

pub fn validate_native_build_approval_statement(
    lineage: &NativeArtifactBuildLineage<'_>,
    plan: &NativeBuildExecutionPlan,
    capability: &NativeBuildCapabilityReceipt,
    sandbox: &NativeSandboxAdmission,
    statement: &NativeBuildApprovalStatement,
) -> SemanticCompilerValidation {
    let seed = lineage.seed;
    let candidate = lineage.candidate();
    validate_native_build_execution_plan(lineage, plan)?;
    validate_native_build_capability_receipt(lineage, plan, capability)?;
    validate_native_sandbox_admission(plan, sandbox)?;
    if statement.seed_ref != seed.seed_id
        || statement.seed_digest != seed.seed_digest
        || statement.candidate_ref != candidate.candidate_id
        || statement.candidate_digest != candidate.candidate_digest
        || statement.build_plan_ref != plan.plan_id
        || statement.build_plan_digest != plan.plan_digest
        || statement.capability_receipt_ref != capability.receipt_id
        || statement.capability_receipt_digest != capability.receipt_digest
        || statement.sandbox_admission_ref != sandbox.admission_id
        || statement.sandbox_admission_digest != sandbox.admission_digest
        || statement.runner_id != plan.runner.runner_id
        || statement.runner_executable_digest != plan.runner.executable_digest
        || statement.logical_valid_from != plan.logical_not_before
        || statement.logical_valid_until != plan.logical_not_after
        || !statement.single_use
    {
        return form_fault(
            SemanticCompilerFormFaultKind::InvalidReference,
            "approval.lineage",
            "approval statement differs from exact candidate plan capability sandbox or runner",
        );
    }
    exact_profile(
        &statement.profile,
        NATIVE_BUILD_APPROVAL_STATEMENT_PROFILE,
        "approval.profile",
    )?;
    exact_build_non_authority(&statement.non_authority, "approval.non_authority")?;
    validate_digest(&statement.statement_digest, "approval.statement_digest")?;
    require_digest(
        &statement.statement_digest,
        native_build_approval_statement_digest(statement)?,
        "approval.statement_digest",
    )
}

pub fn native_build_approval_signing_bytes(
    statement: &NativeBuildApprovalStatement,
) -> SemanticCompilerValidation<Vec<u8>> {
    validate_digest(&statement.statement_digest, "approval.statement_digest")?;
    require_digest(
        &statement.statement_digest,
        native_build_approval_statement_digest(statement)?,
        "approval.statement_digest",
    )?;
    let serialized =
        serde_json::to_vec(statement).map_err(|error| super::SemanticCompilerFormFault {
            kind: SemanticCompilerFormFaultKind::InvalidProfile,
            field: "approval.signature_payload".to_owned(),
            detail: error.to_string(),
        })?;
    let mut bytes = Vec::with_capacity(APPROVAL_SIGNING_DOMAIN.len() + 1 + serialized.len());
    bytes.extend_from_slice(APPROVAL_SIGNING_DOMAIN.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&serialized);
    Ok(bytes)
}

pub fn validate_native_build_trust_store(
    store: &NativeBuildTrustStore,
) -> SemanticCompilerValidation {
    exact_profile(
        &store.profile,
        NATIVE_BUILD_TRUST_STORE_PROFILE,
        "build_trust.profile",
    )?;
    if store.security_verifying_keys.is_empty()
        || store.authority_verifying_keys.is_empty()
        || store.security_verifying_keys.len() > MAX_ID_ITEMS
        || store.authority_verifying_keys.len() > MAX_ID_ITEMS
        || store.revoked_approval_ids.len() > MAX_ID_ITEMS
        || store.revoked_certificate_ids.len() > MAX_ID_ITEMS
    {
        return form_fault(
            SemanticCompilerFormFaultKind::InvalidBound,
            "build_trust.entries",
            "trust store must contain bounded nonempty Security and authority key sets",
        );
    }
    for key in store
        .security_verifying_keys
        .values()
        .chain(store.authority_verifying_keys.values())
    {
        parse_verifying_key(key, "build_trust.verifying_key")?;
    }
    if store.security_verifying_keys.values().any(|security_key| {
        store
            .authority_verifying_keys
            .values()
            .any(|authority_key| authority_key == security_key)
    }) {
        return form_fault(
            SemanticCompilerFormFaultKind::InvalidReference,
            "build_trust.role_separation",
            "Security and external authority must not share a verifying key",
        );
    }
    validate_digest(&store.store_digest, "build_trust.store_digest")?;
    require_digest(
        &store.store_digest,
        native_build_trust_store_digest(store)?,
        "build_trust.store_digest",
    )
}

#[allow(clippy::too_many_arguments)]
pub fn issue_native_build_authorization_certificate(
    lineage: &NativeArtifactBuildLineage<'_>,
    plan: &NativeBuildExecutionPlan,
    capability: &NativeBuildCapabilityReceipt,
    sandbox: &NativeSandboxAdmission,
    statement: NativeBuildApprovalStatement,
    trust_store: &NativeBuildTrustStore,
    certificate_id: SemanticId,
    security_signature: Vec<u8>,
    authority_signature: Vec<u8>,
    logical_now: u64,
) -> SemanticCompilerValidation<NativeBuildAuthorizationCertificate> {
    let seed = lineage.seed;
    let mut value = NativeBuildAuthorizationCertificate {
        profile: NATIVE_BUILD_AUTHORIZATION_PROFILE.to_owned(),
        certificate_id,
        statement,
        trust_store_ref: trust_store.store_id.clone(),
        trust_store_digest: trust_store.store_digest.clone(),
        security_signer_id: seed.security_trust_root_ref.clone(),
        authority_signer_id: seed.authority_trust_root_ref.clone(),
        signature_profile: NATIVE_BUILD_SIGNATURE_PROFILE.to_owned(),
        security_signature,
        authority_signature,
        authorization_digest: empty_digest(),
    };
    value.authorization_digest = native_build_authorization_digest(&value)?;
    validate_native_build_authorization_certificate(
        lineage,
        plan,
        capability,
        sandbox,
        trust_store,
        &value,
        logical_now,
    )?;
    Ok(value)
}

#[allow(clippy::too_many_arguments)]
pub fn validate_native_build_authorization_certificate(
    lineage: &NativeArtifactBuildLineage<'_>,
    plan: &NativeBuildExecutionPlan,
    capability: &NativeBuildCapabilityReceipt,
    sandbox: &NativeSandboxAdmission,
    trust_store: &NativeBuildTrustStore,
    certificate: &NativeBuildAuthorizationCertificate,
    logical_now: u64,
) -> SemanticCompilerValidation {
    let seed = lineage.seed;
    validate_native_build_approval_statement(
        lineage,
        plan,
        capability,
        sandbox,
        &certificate.statement,
    )?;
    validate_native_build_trust_store(trust_store)?;
    exact_profile(
        &certificate.profile,
        NATIVE_BUILD_AUTHORIZATION_PROFILE,
        "authorization.profile",
    )?;
    if certificate.trust_store_ref != trust_store.store_id
        || certificate.trust_store_digest != trust_store.store_digest
        || certificate.security_signer_id != seed.security_trust_root_ref
        || certificate.authority_signer_id != seed.authority_trust_root_ref
        || certificate.signature_profile != NATIVE_BUILD_SIGNATURE_PROFILE
        || logical_now < certificate.statement.logical_valid_from
        || logical_now > certificate.statement.logical_valid_until
        || trust_store
            .revoked_approval_ids
            .contains(&certificate.statement.approval_id)
        || trust_store
            .revoked_certificate_ids
            .contains(&certificate.certificate_id)
    {
        return form_fault(
            SemanticCompilerFormFaultKind::RecognitionBoundary,
            "authorization.trust",
            "authorization trust root profile validity or revocation boundary differs",
        );
    }
    let security_key = trust_store
        .security_verifying_keys
        .get(&certificate.security_signer_id)
        .ok_or_else(|| super::SemanticCompilerFormFault {
            kind: SemanticCompilerFormFaultKind::RecognitionBoundary,
            field: "authorization.security_signer".to_owned(),
            detail: "seed-bound Security verifying key is absent".to_owned(),
        })?;
    let authority_key = trust_store
        .authority_verifying_keys
        .get(&certificate.authority_signer_id)
        .ok_or_else(|| super::SemanticCompilerFormFault {
            kind: SemanticCompilerFormFaultKind::RecognitionBoundary,
            field: "authorization.authority_signer".to_owned(),
            detail: "seed-bound authority verifying key is absent".to_owned(),
        })?;
    let payload = native_build_approval_signing_bytes(&certificate.statement)?;
    verify_signature(
        security_key,
        &certificate.security_signature,
        &payload,
        "authorization.security_signature",
    )?;
    verify_signature(
        authority_key,
        &certificate.authority_signature,
        &payload,
        "authorization.authority_signature",
    )?;
    validate_digest(
        &certificate.authorization_digest,
        "authorization.authorization_digest",
    )?;
    require_digest(
        &certificate.authorization_digest,
        native_build_authorization_digest(certificate)?,
        "authorization.authorization_digest",
    )
}

fn required_build_capabilities() -> BTreeSet<CompilerCapability> {
    BTreeSet::from([
        CompilerCapability::SourceRead,
        CompilerCapability::Build,
        CompilerCapability::FileWrite,
        CompilerCapability::ProcessExecute,
    ])
}

fn validate_runner(runner: &NativeBuildRunnerPin) -> SemanticCompilerValidation {
    bounded_text(&runner.adapter_profile, "build_plan.runner.adapter_profile")?;
    validate_digest(
        &runner.executable_digest,
        "build_plan.runner.executable_digest",
    )?;
    validate_digest(
        &runner.configuration_digest,
        "build_plan.runner.configuration_digest",
    )
}

fn validate_root_policy(
    policy: &NativeBuildRootPolicy,
    candidate: &NativeArtifactCandidate,
) -> SemanticCompilerValidation {
    let required_denials = BTreeSet::from([
        NativeDeniedWriteClass::OutsideDisposableRoot,
        NativeDeniedWriteClass::Repository,
        NativeDeniedWriteClass::SealRoot,
        NativeDeniedWriteClass::Credential,
    ]);
    if !is_safe_relative_path(&policy.disposable_root_relative_path)
        || !is_safe_relative_path(&policy.expected_artifact_relative_path)
        || policy.expected_artifact_relative_path != candidate.build.expected_output_relative_path
        || !policy.disposable_root_create_new
        || !policy.artifact_create_new
        || policy.denied_write_classes != required_denials
    {
        return form_fault(
            SemanticCompilerFormFaultKind::InvalidReference,
            "build_plan.root_policy",
            "build root artifact path create-new or denied-write policy differs",
        );
    }
    Ok(())
}

fn is_safe_relative_path(value: &str) -> bool {
    !value.trim().is_empty()
        && !value.starts_with(['/', '\\'])
        && !value.contains(':')
        && !value
            .split(['/', '\\'])
            .any(|part| part.is_empty() || part == "." || part == "..")
}

fn exact_build_non_authority(value: &str, field: &str) -> SemanticCompilerValidation {
    if value == NATIVE_BUILD_PLAN_NON_AUTHORITY {
        Ok(())
    } else {
        form_fault(
            SemanticCompilerFormFaultKind::NonAuthorityMismatch,
            field,
            "native build form changed or omitted the fixed non-authority boundary",
        )
    }
}

fn parse_verifying_key(bytes: &[u8], field: &str) -> SemanticCompilerValidation<VerifyingKey> {
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| super::SemanticCompilerFormFault {
            kind: SemanticCompilerFormFaultKind::RecognitionBoundary,
            field: field.to_owned(),
            detail: "Ed25519 verifying key must contain exactly 32 bytes".to_owned(),
        })?;
    VerifyingKey::from_bytes(&key).map_err(|error| super::SemanticCompilerFormFault {
        kind: SemanticCompilerFormFaultKind::RecognitionBoundary,
        field: field.to_owned(),
        detail: error.to_string(),
    })
}

fn verify_signature(
    key: &[u8],
    signature: &[u8],
    payload: &[u8],
    field: &str,
) -> SemanticCompilerValidation {
    let verifying_key = parse_verifying_key(key, field)?;
    let signature =
        Signature::try_from(signature).map_err(|error| super::SemanticCompilerFormFault {
            kind: SemanticCompilerFormFaultKind::RecognitionBoundary,
            field: field.to_owned(),
            detail: error.to_string(),
        })?;
    verifying_key
        .verify_strict(payload, &signature)
        .map_err(|error| super::SemanticCompilerFormFault {
            kind: SemanticCompilerFormFaultKind::RecognitionBoundary,
            field: field.to_owned(),
            detail: error.to_string(),
        })
}

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: String::new(),
    }
}
