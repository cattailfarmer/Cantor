//! Read-only machine protocol for replaying a complete native build lifecycle.
//!
//! The protocol owns supplied forms so callers can cross a JSON boundary, then
//! reuses the existing pure validators in causal order. It does not author,
//! repair, sign, execute, admit, install, deploy, or recognize anything.

use serde::{Deserialize, Serialize};

use super::{
    CandidateCompilationPlan, ContentDigest, NativeArtifactBackendProjection,
    NativeArtifactBackendRequest, NativeArtifactBuildLineage, NativeArtifactReceipt,
    NativeArtifactReceiptLineage, NativeArtifactVerificationDisposition,
    NativeArtifactVerificationObservation, NativeArtifactVerificationPlan,
    NativeArtifactVerificationReceipt, NativeBuildApprovalStatement, NativeBuildAttemptLedger,
    NativeBuildAuthorizationCertificate, NativeBuildCapabilityReceipt, NativeBuildExecutionPlan,
    NativeBuildObservation, NativeBuildTrustStore, NativeSandboxAdmission,
    SemanticCompilerFormFault, SemanticCompilerFormFaultKind, SemanticId, SopSeed, TypedSopIr,
    validate_candidate_compilation_plan, validate_native_artifact_backend_projection,
    validate_native_artifact_verification_observation, validate_native_artifact_verification_plan,
    validate_native_artifact_verification_receipt, validate_native_build_approval_statement,
    validate_native_build_attempt_ledger, validate_native_build_authorization_certificate,
    validate_native_build_capability_receipt, validate_native_build_execution_plan,
    validate_native_build_observation, validate_native_build_trust_store,
    validate_native_sandbox_admission, validate_sop_seed, validate_typed_sop_ir,
};

pub const NATIVE_LIFECYCLE_VALIDATION_PROTOCOL: &str = "cantor.native_lifecycle_validation.v1";
pub const NATIVE_LIFECYCLE_MAX_INPUT_BYTES: usize = 8 * 1024 * 1024;
pub const NATIVE_LIFECYCLE_MAX_RESPONSE_BYTES: usize = 1024 * 1024;
pub const NATIVE_LIFECYCLE_VALIDATION_NON_AUTHORITY: &str = "Read-only coherence replay over caller-supplied forms and public trust context only. This response does not establish physical truth, artifact correctness, safety, verification passage, authorization, globally atomic single-use consumption, signing, admission, installation, deployment, runtime execution, effect authority, or successor recognition.";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeLifecycleValidationOperation {
    ValidateArtifact,
    ValidateVerification,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeArtifactLifecycleBundle {
    pub seed: SopSeed,
    pub ir: TypedSopIr,
    pub candidate_plan: CandidateCompilationPlan,
    pub candidate_request: NativeArtifactBackendRequest,
    pub candidate_projection: NativeArtifactBackendProjection,
    pub build_plan: NativeBuildExecutionPlan,
    pub build_capability: NativeBuildCapabilityReceipt,
    pub sandbox_admission: NativeSandboxAdmission,
    pub approval: NativeBuildApprovalStatement,
    pub trust_store: NativeBuildTrustStore,
    pub authorization: NativeBuildAuthorizationCertificate,
    pub observation: NativeBuildObservation,
    pub attempt_ledger: NativeBuildAttemptLedger,
    pub artifact_receipt: NativeArtifactReceipt,
}

impl NativeArtifactLifecycleBundle {
    fn build_lineage(&self) -> NativeArtifactBuildLineage<'_> {
        NativeArtifactBuildLineage {
            seed: &self.seed,
            ir: &self.ir,
            candidate_plan: &self.candidate_plan,
            candidate_request: &self.candidate_request,
            projection: &self.candidate_projection,
        }
    }

    fn receipt_lineage(&self) -> NativeArtifactReceiptLineage<'_> {
        NativeArtifactReceiptLineage {
            build: self.build_lineage(),
            plan: &self.build_plan,
            capability: &self.build_capability,
            sandbox: &self.sandbox_admission,
            trust_store: &self.trust_store,
            authorization: &self.authorization,
            observation: &self.observation,
            attempt_ledger: &self.attempt_ledger,
            receipt: &self.artifact_receipt,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeVerificationLifecycleBundle {
    pub plan: NativeArtifactVerificationPlan,
    pub observation: NativeArtifactVerificationObservation,
    pub receipt: NativeArtifactVerificationReceipt,
    pub second_artifact: Option<Box<NativeArtifactLifecycleBundle>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeLifecycleValidationRequest {
    pub protocol: String,
    pub request_id: SemanticId,
    pub operation: NativeLifecycleValidationOperation,
    pub artifact: NativeArtifactLifecycleBundle,
    pub verification: Option<NativeVerificationLifecycleBundle>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeLifecycleValidationStage {
    Envelope,
    Seed,
    TypedSopIr,
    CandidatePlan,
    NativeCandidateProjection,
    NativeBuildPlan,
    NativeBuildCapability,
    SandboxAdmission,
    ApprovalStatement,
    TrustStore,
    Authorization,
    BuildObservation,
    AttemptLedger,
    ArtifactReceipt,
    VerificationPlan,
    SecondArtifactReceipt,
    VerificationObservation,
    VerificationReceipt,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeLifecycleValidationOutcome {
    ArtifactValid,
    VerificationValid,
    LifecycleRefused,
    InputRefused,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeLifecycleValidationFaultKind {
    Wire,
    UnsupportedProfile,
    OperationMismatch,
    InvalidProfile,
    InvalidDigest,
    InvalidBound,
    InvalidReference,
    MissingSourceMap,
    DependencyCycle,
    BackendMismatch,
    CapabilityExceeded,
    AccountingMismatch,
    StageOrder,
    RecognitionBoundary,
    NonAuthorityMismatch,
    DigestMismatch,
}

impl From<SemanticCompilerFormFaultKind> for NativeLifecycleValidationFaultKind {
    fn from(value: SemanticCompilerFormFaultKind) -> Self {
        match value {
            SemanticCompilerFormFaultKind::InvalidProfile => Self::InvalidProfile,
            SemanticCompilerFormFaultKind::InvalidDigest => Self::InvalidDigest,
            SemanticCompilerFormFaultKind::InvalidBound => Self::InvalidBound,
            SemanticCompilerFormFaultKind::InvalidReference => Self::InvalidReference,
            SemanticCompilerFormFaultKind::MissingSourceMap => Self::MissingSourceMap,
            SemanticCompilerFormFaultKind::DependencyCycle => Self::DependencyCycle,
            SemanticCompilerFormFaultKind::BackendMismatch => Self::BackendMismatch,
            SemanticCompilerFormFaultKind::CapabilityExceeded => Self::CapabilityExceeded,
            SemanticCompilerFormFaultKind::AccountingMismatch => Self::AccountingMismatch,
            SemanticCompilerFormFaultKind::StageOrder => Self::StageOrder,
            SemanticCompilerFormFaultKind::RecognitionBoundary => Self::RecognitionBoundary,
            SemanticCompilerFormFaultKind::NonAuthorityMismatch => Self::NonAuthorityMismatch,
            SemanticCompilerFormFaultKind::DigestMismatch => Self::DigestMismatch,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeLifecycleValidationFault {
    pub stage: Option<NativeLifecycleValidationStage>,
    pub kind: NativeLifecycleValidationFaultKind,
    pub field: String,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeLifecycleValidationResponse {
    pub protocol: String,
    pub request_id: Option<SemanticId>,
    pub operation: Option<NativeLifecycleValidationOperation>,
    pub outcome: NativeLifecycleValidationOutcome,
    pub deepest_valid_stage: Option<NativeLifecycleValidationStage>,
    pub stage_account: Vec<NativeLifecycleValidationStage>,
    pub artifact_id: Option<SemanticId>,
    pub artifact_digest: Option<ContentDigest>,
    pub verification_disposition: Option<NativeArtifactVerificationDisposition>,
    pub faults: Vec<NativeLifecycleValidationFault>,
    pub non_authority: String,
}

impl NativeLifecycleValidationResponse {
    pub fn input_refused(
        kind: NativeLifecycleValidationFaultKind,
        field: impl Into<String>,
        detail: impl AsRef<str>,
    ) -> Self {
        Self {
            protocol: NATIVE_LIFECYCLE_VALIDATION_PROTOCOL.to_owned(),
            request_id: None,
            operation: None,
            outcome: NativeLifecycleValidationOutcome::InputRefused,
            deepest_valid_stage: None,
            stage_account: Vec::new(),
            artifact_id: None,
            artifact_digest: None,
            verification_disposition: None,
            faults: vec![NativeLifecycleValidationFault {
                stage: None,
                kind,
                field: bounded_fault_text(field.into()),
                detail: bounded_fault_text(detail.as_ref()),
            }],
            non_authority: NATIVE_LIFECYCLE_VALIDATION_NON_AUTHORITY.to_owned(),
        }
    }

    pub fn exit_code(&self) -> u8 {
        match self.outcome {
            NativeLifecycleValidationOutcome::ArtifactValid
            | NativeLifecycleValidationOutcome::VerificationValid => 0,
            NativeLifecycleValidationOutcome::LifecycleRefused => 1,
            NativeLifecycleValidationOutcome::InputRefused => 2,
        }
    }
}

pub fn validate_native_lifecycle_request(
    request: &NativeLifecycleValidationRequest,
) -> NativeLifecycleValidationResponse {
    let mut stages = Vec::new();
    if request.protocol != NATIVE_LIFECYCLE_VALIDATION_PROTOCOL {
        return refused(
            request,
            stages,
            NativeLifecycleValidationStage::Envelope,
            NativeLifecycleValidationFaultKind::UnsupportedProfile,
            "request.protocol",
            "unsupported native lifecycle validation protocol",
        );
    }
    let serialized_size = match serde_json::to_vec(request) {
        Ok(bytes) => bytes.len(),
        Err(error) => {
            return refused(
                request,
                stages,
                NativeLifecycleValidationStage::Envelope,
                NativeLifecycleValidationFaultKind::Wire,
                "request",
                error.to_string(),
            );
        }
    };
    if serialized_size > NATIVE_LIFECYCLE_MAX_INPUT_BYTES {
        return refused(
            request,
            stages,
            NativeLifecycleValidationStage::Envelope,
            NativeLifecycleValidationFaultKind::InvalidBound,
            "request",
            "serialized request exceeds the protocol input bound",
        );
    }
    if !matches!(
        (&request.operation, &request.verification),
        (NativeLifecycleValidationOperation::ValidateArtifact, None)
            | (
                NativeLifecycleValidationOperation::ValidateVerification,
                Some(_)
            )
    ) {
        return refused(
            request,
            stages,
            NativeLifecycleValidationStage::Envelope,
            NativeLifecycleValidationFaultKind::OperationMismatch,
            "request.verification",
            "verification bundle presence differs from the selected operation",
        );
    }
    stages.push(NativeLifecycleValidationStage::Envelope);

    if let Err(failure) = validate_artifact_bundle(&request.artifact, &mut stages, false) {
        return refused_from_semantic(request, stages, failure);
    }

    let Some(verification) = &request.verification else {
        return valid_response(request, stages, None);
    };
    let primary = request.artifact.receipt_lineage();
    if let Err(fault) = validate_native_artifact_verification_plan(&primary, &verification.plan) {
        return refused_from_semantic(
            request,
            stages,
            (NativeLifecycleValidationStage::VerificationPlan, fault),
        );
    }
    stages.push(NativeLifecycleValidationStage::VerificationPlan);

    if let Some(second) = verification.second_artifact.as_deref() {
        let mut ignored_second_stages = Vec::new();
        if let Err((_, mut fault)) =
            validate_artifact_bundle(second, &mut ignored_second_stages, true)
        {
            fault.field = format!("second_artifact.{}", fault.field);
            return refused_from_semantic(
                request,
                stages,
                (NativeLifecycleValidationStage::SecondArtifactReceipt, fault),
            );
        }
        stages.push(NativeLifecycleValidationStage::SecondArtifactReceipt);
    }
    let second_lineage = verification
        .second_artifact
        .as_deref()
        .map(NativeArtifactLifecycleBundle::receipt_lineage);
    if let Err(fault) = validate_native_artifact_verification_observation(
        &primary,
        &verification.plan,
        &verification.observation,
        second_lineage.as_ref(),
    ) {
        return refused_from_semantic(
            request,
            stages,
            (
                NativeLifecycleValidationStage::VerificationObservation,
                fault,
            ),
        );
    }
    stages.push(NativeLifecycleValidationStage::VerificationObservation);
    if let Err(fault) = validate_native_artifact_verification_receipt(
        &primary,
        &verification.plan,
        &verification.observation,
        second_lineage.as_ref(),
        &verification.receipt,
    ) {
        return refused_from_semantic(
            request,
            stages,
            (NativeLifecycleValidationStage::VerificationReceipt, fault),
        );
    }
    stages.push(NativeLifecycleValidationStage::VerificationReceipt);
    valid_response(
        request,
        stages,
        Some(verification.receipt.disposition.clone()),
    )
}

pub fn validate_native_lifecycle_json(bytes: &[u8]) -> NativeLifecycleValidationResponse {
    if bytes.is_empty() {
        return NativeLifecycleValidationResponse::input_refused(
            NativeLifecycleValidationFaultKind::Wire,
            "input",
            "input is empty",
        );
    }
    if bytes.len() > NATIVE_LIFECYCLE_MAX_INPUT_BYTES {
        return NativeLifecycleValidationResponse::input_refused(
            NativeLifecycleValidationFaultKind::InvalidBound,
            "input",
            "input exceeds the native lifecycle protocol bound",
        );
    }
    let request: NativeLifecycleValidationRequest = match serde_json::from_slice(bytes) {
        Ok(request) => request,
        Err(error) => {
            return NativeLifecycleValidationResponse::input_refused(
                NativeLifecycleValidationFaultKind::Wire,
                "input",
                format!("input is not one strict request JSON object: {error}"),
            );
        }
    };
    validate_native_lifecycle_request(&request)
}

fn validate_artifact_bundle(
    bundle: &NativeArtifactLifecycleBundle,
    stages: &mut Vec<NativeLifecycleValidationStage>,
    second: bool,
) -> Result<(), (NativeLifecycleValidationStage, SemanticCompilerFormFault)> {
    run_stage(stages, NativeLifecycleValidationStage::Seed, || {
        validate_sop_seed(&bundle.seed)
    })?;
    run_stage(stages, NativeLifecycleValidationStage::TypedSopIr, || {
        validate_typed_sop_ir(&bundle.ir)
    })?;
    run_stage(
        stages,
        NativeLifecycleValidationStage::CandidatePlan,
        || validate_candidate_compilation_plan(&bundle.seed, &bundle.ir, &bundle.candidate_plan),
    )?;
    let build = bundle.build_lineage();
    run_stage(
        stages,
        NativeLifecycleValidationStage::NativeCandidateProjection,
        || {
            validate_native_artifact_backend_projection(
                &bundle.seed,
                &bundle.ir,
                &bundle.candidate_plan,
                &bundle.candidate_request,
                &bundle.candidate_projection,
            )
        },
    )?;
    run_stage(
        stages,
        NativeLifecycleValidationStage::NativeBuildPlan,
        || validate_native_build_execution_plan(&build, &bundle.build_plan),
    )?;
    run_stage(
        stages,
        NativeLifecycleValidationStage::NativeBuildCapability,
        || {
            validate_native_build_capability_receipt(
                &build,
                &bundle.build_plan,
                &bundle.build_capability,
            )
        },
    )?;
    run_stage(
        stages,
        NativeLifecycleValidationStage::SandboxAdmission,
        || validate_native_sandbox_admission(&bundle.build_plan, &bundle.sandbox_admission),
    )?;
    run_stage(
        stages,
        NativeLifecycleValidationStage::ApprovalStatement,
        || {
            validate_native_build_approval_statement(
                &build,
                &bundle.build_plan,
                &bundle.build_capability,
                &bundle.sandbox_admission,
                &bundle.approval,
            )?;
            if bundle.authorization.statement != bundle.approval {
                return Err(SemanticCompilerFormFault {
                    kind: SemanticCompilerFormFaultKind::InvalidReference,
                    field: "authorization.statement".to_owned(),
                    detail: "authorization embeds a different approval statement".to_owned(),
                });
            }
            Ok(())
        },
    )?;
    run_stage(stages, NativeLifecycleValidationStage::TrustStore, || {
        validate_native_build_trust_store(&bundle.trust_store)
    })?;
    run_stage(
        stages,
        NativeLifecycleValidationStage::Authorization,
        || {
            validate_native_build_authorization_certificate(
                &build,
                &bundle.build_plan,
                &bundle.build_capability,
                &bundle.sandbox_admission,
                &bundle.trust_store,
                &bundle.authorization,
                bundle.observation.logical_started_at,
            )
        },
    )?;
    run_stage(
        stages,
        NativeLifecycleValidationStage::BuildObservation,
        || {
            validate_native_build_observation(
                &build,
                &bundle.build_plan,
                &bundle.build_capability,
                &bundle.sandbox_admission,
                &bundle.trust_store,
                &bundle.authorization,
                &bundle.observation,
            )
        },
    )?;
    run_stage(
        stages,
        NativeLifecycleValidationStage::AttemptLedger,
        || validate_native_build_attempt_ledger(&bundle.attempt_ledger),
    )?;
    let receipt = bundle.receipt_lineage();
    run_stage(
        stages,
        NativeLifecycleValidationStage::ArtifactReceipt,
        || receipt.validate(),
    )?;
    if second {
        // The caller reports the second lifecycle as one stage; its internal
        // stage account was intentionally kept local to this replay.
        stages.clear();
    }
    Ok(())
}

fn run_stage(
    stages: &mut Vec<NativeLifecycleValidationStage>,
    stage: NativeLifecycleValidationStage,
    operation: impl FnOnce() -> Result<(), SemanticCompilerFormFault>,
) -> Result<(), (NativeLifecycleValidationStage, SemanticCompilerFormFault)> {
    operation().map_err(|fault| (stage.clone(), fault))?;
    stages.push(stage);
    Ok(())
}

fn valid_response(
    request: &NativeLifecycleValidationRequest,
    stages: Vec<NativeLifecycleValidationStage>,
    verification_disposition: Option<NativeArtifactVerificationDisposition>,
) -> NativeLifecycleValidationResponse {
    let outcome = if verification_disposition.is_some() {
        NativeLifecycleValidationOutcome::VerificationValid
    } else {
        NativeLifecycleValidationOutcome::ArtifactValid
    };
    NativeLifecycleValidationResponse {
        protocol: NATIVE_LIFECYCLE_VALIDATION_PROTOCOL.to_owned(),
        request_id: Some(request.request_id.clone()),
        operation: Some(request.operation.clone()),
        outcome,
        deepest_valid_stage: stages.last().cloned(),
        stage_account: stages,
        artifact_id: Some(
            request
                .artifact
                .artifact_receipt
                .artifact
                .artifact_id
                .clone(),
        ),
        artifact_digest: Some(
            request
                .artifact
                .artifact_receipt
                .artifact
                .artifact_digest
                .clone(),
        ),
        verification_disposition,
        faults: Vec::new(),
        non_authority: NATIVE_LIFECYCLE_VALIDATION_NON_AUTHORITY.to_owned(),
    }
}

fn refused_from_semantic(
    request: &NativeLifecycleValidationRequest,
    stages: Vec<NativeLifecycleValidationStage>,
    failure: (NativeLifecycleValidationStage, SemanticCompilerFormFault),
) -> NativeLifecycleValidationResponse {
    refused(
        request,
        stages,
        failure.0,
        failure.1.kind.into(),
        failure.1.field,
        failure.1.detail,
    )
}

fn refused(
    request: &NativeLifecycleValidationRequest,
    stages: Vec<NativeLifecycleValidationStage>,
    failed_stage: NativeLifecycleValidationStage,
    kind: NativeLifecycleValidationFaultKind,
    field: impl Into<String>,
    detail: impl AsRef<str>,
) -> NativeLifecycleValidationResponse {
    let artifact_valid = stages.contains(&NativeLifecycleValidationStage::ArtifactReceipt);
    NativeLifecycleValidationResponse {
        protocol: NATIVE_LIFECYCLE_VALIDATION_PROTOCOL.to_owned(),
        request_id: Some(request.request_id.clone()),
        operation: Some(request.operation.clone()),
        outcome: NativeLifecycleValidationOutcome::LifecycleRefused,
        deepest_valid_stage: stages.last().cloned(),
        stage_account: stages,
        artifact_id: artifact_valid.then(|| {
            request
                .artifact
                .artifact_receipt
                .artifact
                .artifact_id
                .clone()
        }),
        artifact_digest: artifact_valid.then(|| {
            request
                .artifact
                .artifact_receipt
                .artifact
                .artifact_digest
                .clone()
        }),
        verification_disposition: None,
        faults: vec![NativeLifecycleValidationFault {
            stage: Some(failed_stage),
            kind,
            field: bounded_fault_text(field.into()),
            detail: bounded_fault_text(detail.as_ref()),
        }],
        non_authority: NATIVE_LIFECYCLE_VALIDATION_NON_AUTHORITY.to_owned(),
    }
}

fn bounded_fault_text(value: impl AsRef<str>) -> String {
    value.as_ref().chars().take(512).collect()
}
