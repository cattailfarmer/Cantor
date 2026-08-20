//! Independent verification planning and derived verification receipts.
//!
//! Verification is an evidence-accounting layer over a produced-unverified
//! artifact receipt. It declares an identity boundary between runner, approval
//! signers, and verifier; it grants no signing, admission, installation,
//! deployment, execution, or successor authority.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{
    NativeArtifactReceiptLineage, NativeObservedArtifact, empty_digest, is_safe_relative_path,
};
use crate::semantic_compiler::{
    ContentDigest, SemanticCompilerFormFaultKind, SemanticCompilerValidation, SemanticId,
    bounded_text, digest_form, exact_profile, form_fault, require_digest, validate_digest,
};

pub const NATIVE_ARTIFACT_VERIFICATION_PLAN_PROFILE: &str =
    "cantor-native-artifact-verification-plan/0.1";
pub const NATIVE_ARTIFACT_VERIFICATION_OBSERVATION_PROFILE: &str =
    "cantor-native-artifact-verification-observation/0.1";
pub const NATIVE_ARTIFACT_VERIFICATION_RECEIPT_PROFILE: &str =
    "cantor-native-artifact-verification-receipt/0.1";
pub const NATIVE_ARTIFACT_VERIFICATION_NON_AUTHORITY: &str = "Independent verification evidence only. Passed means the predeclared checks match the supplied evidence; it grants no semantic correctness beyond those checks and no signing, admission, installation, deployment, runtime execution, effect authority, or successor recognition.";

const VERIFICATION_PLAN_DOMAIN: &str = "cantor.native-artifact.verification-plan.v1";
const VERIFICATION_OBSERVATION_DOMAIN: &str = "cantor.native-artifact.verification-observation.v1";
const VERIFICATION_RECEIPT_DOMAIN: &str = "cantor.native-artifact.verification-receipt.v1";
const MAX_EVIDENCE_ITEMS: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeArtifactVerificationCheck {
    ArtifactIdentity,
    ArtifactDigest,
    ByteSize,
    MediaType,
    TargetTriple,
    BuildInput,
    InterfaceInputSchema,
    InterfaceOutputSchema,
    EvidenceCoverage,
    Reproducibility,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeArtifactVerificationCheckDisposition {
    Passed,
    Failed,
    Unresolved,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeArtifactVerificationDisposition {
    Passed,
    Failed,
    Unresolved,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeArtifactVerifierPin {
    pub verifier_id: SemanticId,
    pub verifier_profile: String,
    pub program_digest: ContentDigest,
    pub configuration_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeArtifactVerificationPlan {
    pub profile: String,
    pub plan_id: SemanticId,
    pub artifact_receipt_ref: SemanticId,
    pub artifact_receipt_digest: ContentDigest,
    pub expected_artifact: NativeObservedArtifact,
    pub expected_interface_input_schema_digest: ContentDigest,
    pub expected_interface_output_schema_digest: ContentDigest,
    pub expected_toolchain_configuration_digest: ContentDigest,
    pub verifier: NativeArtifactVerifierPin,
    pub required_evidence_refs: BTreeSet<SemanticId>,
    pub checks: BTreeSet<NativeArtifactVerificationCheck>,
    pub require_reproducibility: bool,
    pub non_authority: String,
    pub plan_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSecondBuildEvidence {
    pub artifact_receipt_ref: SemanticId,
    pub artifact_receipt_digest: ContentDigest,
    pub authorization_ref: SemanticId,
    pub attempt_ref: SemanticId,
    pub artifact: NativeObservedArtifact,
    pub toolchain_configuration_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeArtifactVerificationObservation {
    pub profile: String,
    pub observation_id: SemanticId,
    pub plan_ref: SemanticId,
    pub plan_digest: ContentDigest,
    pub artifact_receipt_ref: SemanticId,
    pub artifact_receipt_digest: ContentDigest,
    pub verifier: NativeArtifactVerifierPin,
    pub observed_artifact: Option<NativeObservedArtifact>,
    pub observed_interface_input_schema_digest: Option<ContentDigest>,
    pub observed_interface_output_schema_digest: Option<ContentDigest>,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub second_build: Option<NativeSecondBuildEvidence>,
    pub non_authority: String,
    pub observation_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeArtifactVerificationReceipt {
    pub profile: String,
    pub receipt_id: SemanticId,
    pub plan_ref: SemanticId,
    pub plan_digest: ContentDigest,
    pub artifact_receipt_ref: SemanticId,
    pub artifact_receipt_digest: ContentDigest,
    pub observation_ref: SemanticId,
    pub observation_digest: ContentDigest,
    pub verifier_id: SemanticId,
    pub checks:
        BTreeMap<NativeArtifactVerificationCheck, NativeArtifactVerificationCheckDisposition>,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub unresolved_items: BTreeSet<String>,
    pub disposition: NativeArtifactVerificationDisposition,
    pub non_authority: String,
    pub receipt_digest: ContentDigest,
}

pub fn native_artifact_verification_plan_digest(
    plan: &NativeArtifactVerificationPlan,
) -> SemanticCompilerValidation<ContentDigest> {
    let mut body = plan.clone();
    body.plan_digest = empty_digest();
    digest_form(VERIFICATION_PLAN_DOMAIN, &body)
}

pub fn native_artifact_verification_observation_digest(
    observation: &NativeArtifactVerificationObservation,
) -> SemanticCompilerValidation<ContentDigest> {
    let mut body = observation.clone();
    body.observation_digest = empty_digest();
    digest_form(VERIFICATION_OBSERVATION_DOMAIN, &body)
}

pub fn native_artifact_verification_receipt_digest(
    receipt: &NativeArtifactVerificationReceipt,
) -> SemanticCompilerValidation<ContentDigest> {
    let mut body = receipt.clone();
    body.receipt_digest = empty_digest();
    digest_form(VERIFICATION_RECEIPT_DOMAIN, &body)
}

pub fn project_native_artifact_verification_plan(
    lineage: &NativeArtifactReceiptLineage<'_>,
    plan_id: SemanticId,
    verifier: NativeArtifactVerifierPin,
    required_evidence_refs: BTreeSet<SemanticId>,
    require_reproducibility: bool,
) -> SemanticCompilerValidation<NativeArtifactVerificationPlan> {
    lineage.validate()?;
    let candidate = lineage.build.candidate();
    let mut value = NativeArtifactVerificationPlan {
        profile: NATIVE_ARTIFACT_VERIFICATION_PLAN_PROFILE.to_owned(),
        plan_id,
        artifact_receipt_ref: lineage.receipt.receipt_id.clone(),
        artifact_receipt_digest: lineage.receipt.receipt_digest.clone(),
        expected_artifact: lineage.receipt.artifact.clone(),
        expected_interface_input_schema_digest: candidate.interface.input_schema_digest.clone(),
        expected_interface_output_schema_digest: candidate.interface.output_schema_digest.clone(),
        expected_toolchain_configuration_digest: candidate.toolchain.configuration_digest.clone(),
        verifier,
        required_evidence_refs,
        checks: required_checks(require_reproducibility),
        require_reproducibility,
        non_authority: NATIVE_ARTIFACT_VERIFICATION_NON_AUTHORITY.to_owned(),
        plan_digest: empty_digest(),
    };
    value.plan_digest = native_artifact_verification_plan_digest(&value)?;
    validate_native_artifact_verification_plan(lineage, &value)?;
    Ok(value)
}

pub fn validate_native_artifact_verification_plan(
    lineage: &NativeArtifactReceiptLineage<'_>,
    plan: &NativeArtifactVerificationPlan,
) -> SemanticCompilerValidation {
    lineage.validate()?;
    exact_profile(
        &plan.profile,
        NATIVE_ARTIFACT_VERIFICATION_PLAN_PROFILE,
        "verification_plan.profile",
    )?;
    let candidate = lineage.build.candidate();
    if plan.artifact_receipt_ref != lineage.receipt.receipt_id
        || plan.artifact_receipt_digest != lineage.receipt.receipt_digest
        || plan.expected_artifact != lineage.receipt.artifact
        || plan.expected_interface_input_schema_digest != candidate.interface.input_schema_digest
        || plan.expected_interface_output_schema_digest != candidate.interface.output_schema_digest
        || plan.expected_toolchain_configuration_digest != candidate.toolchain.configuration_digest
        || plan.checks != required_checks(plan.require_reproducibility)
        || plan.required_evidence_refs.is_empty()
        || plan.required_evidence_refs.len() > MAX_EVIDENCE_ITEMS
    {
        return form_fault(
            SemanticCompilerFormFaultKind::InvalidReference,
            "verification_plan.lineage",
            "verification plan differs from receipt artifact interface toolchain checks or evidence contract",
        );
    }
    validate_verifier_pin(lineage, &plan.verifier)?;
    exact_verification_non_authority(&plan.non_authority, "verification_plan.non_authority")?;
    validate_digest(&plan.plan_digest, "verification_plan.plan_digest")?;
    require_digest(
        &plan.plan_digest,
        native_artifact_verification_plan_digest(plan)?,
        "verification_plan.plan_digest",
    )
}

#[allow(clippy::too_many_arguments)]
pub fn project_native_artifact_verification_observation(
    lineage: &NativeArtifactReceiptLineage<'_>,
    plan: &NativeArtifactVerificationPlan,
    observation_id: SemanticId,
    observed_artifact: Option<NativeObservedArtifact>,
    observed_interface_input_schema_digest: Option<ContentDigest>,
    observed_interface_output_schema_digest: Option<ContentDigest>,
    evidence_refs: BTreeSet<SemanticId>,
    second_lineage: Option<&NativeArtifactReceiptLineage<'_>>,
) -> SemanticCompilerValidation<NativeArtifactVerificationObservation> {
    validate_native_artifact_verification_plan(lineage, plan)?;
    let second_build = second_lineage
        .map(project_second_build_evidence)
        .transpose()?;
    let mut value = NativeArtifactVerificationObservation {
        profile: NATIVE_ARTIFACT_VERIFICATION_OBSERVATION_PROFILE.to_owned(),
        observation_id,
        plan_ref: plan.plan_id.clone(),
        plan_digest: plan.plan_digest.clone(),
        artifact_receipt_ref: lineage.receipt.receipt_id.clone(),
        artifact_receipt_digest: lineage.receipt.receipt_digest.clone(),
        verifier: plan.verifier.clone(),
        observed_artifact,
        observed_interface_input_schema_digest,
        observed_interface_output_schema_digest,
        evidence_refs,
        second_build,
        non_authority: NATIVE_ARTIFACT_VERIFICATION_NON_AUTHORITY.to_owned(),
        observation_digest: empty_digest(),
    };
    value.observation_digest = native_artifact_verification_observation_digest(&value)?;
    validate_native_artifact_verification_observation(lineage, plan, &value, second_lineage)?;
    Ok(value)
}

pub fn validate_native_artifact_verification_observation(
    lineage: &NativeArtifactReceiptLineage<'_>,
    plan: &NativeArtifactVerificationPlan,
    observation: &NativeArtifactVerificationObservation,
    second_lineage: Option<&NativeArtifactReceiptLineage<'_>>,
) -> SemanticCompilerValidation {
    validate_native_artifact_verification_plan(lineage, plan)?;
    exact_profile(
        &observation.profile,
        NATIVE_ARTIFACT_VERIFICATION_OBSERVATION_PROFILE,
        "verification_observation.profile",
    )?;
    if observation.plan_ref != plan.plan_id
        || observation.plan_digest != plan.plan_digest
        || observation.artifact_receipt_ref != lineage.receipt.receipt_id
        || observation.artifact_receipt_digest != lineage.receipt.receipt_digest
        || observation.verifier != plan.verifier
        || observation.evidence_refs.len() > MAX_EVIDENCE_ITEMS
    {
        return form_fault(
            SemanticCompilerFormFaultKind::InvalidReference,
            "verification_observation.lineage",
            "verification observation differs from its exact plan receipt verifier or bounds",
        );
    }
    if let Some(artifact) = &observation.observed_artifact {
        validate_independently_observed_artifact(artifact)?;
    }
    if let Some(digest) = &observation.observed_interface_input_schema_digest {
        validate_digest(digest, "verification_observation.input_schema")?;
    }
    if let Some(digest) = &observation.observed_interface_output_schema_digest {
        validate_digest(digest, "verification_observation.output_schema")?;
    }
    match (
        plan.require_reproducibility,
        &observation.second_build,
        second_lineage,
    ) {
        (true, Some(observed), Some(second)) => {
            second.validate()?;
            if observed != &project_second_build_evidence(second)? {
                return form_fault(
                    SemanticCompilerFormFaultKind::InvalidReference,
                    "verification_observation.second_build",
                    "second-build evidence differs from its whole-replay-valid receipt lineage",
                );
            }
        }
        (true, None, None) => {}
        (false, None, None) => {}
        _ => {
            return form_fault(
                SemanticCompilerFormFaultKind::InvalidReference,
                "verification_observation.second_build",
                "second-build evidence presence differs from the plan or supplied lineage",
            );
        }
    }
    exact_verification_non_authority(
        &observation.non_authority,
        "verification_observation.non_authority",
    )?;
    validate_digest(
        &observation.observation_digest,
        "verification_observation.observation_digest",
    )?;
    require_digest(
        &observation.observation_digest,
        native_artifact_verification_observation_digest(observation)?,
        "verification_observation.observation_digest",
    )
}

pub fn project_native_artifact_verification_receipt(
    lineage: &NativeArtifactReceiptLineage<'_>,
    plan: &NativeArtifactVerificationPlan,
    observation: &NativeArtifactVerificationObservation,
    second_lineage: Option<&NativeArtifactReceiptLineage<'_>>,
    receipt_id: SemanticId,
) -> SemanticCompilerValidation<NativeArtifactVerificationReceipt> {
    validate_native_artifact_verification_observation(lineage, plan, observation, second_lineage)?;
    let checks = derive_checks(lineage, plan, observation, second_lineage);
    let unresolved_items = checks
        .iter()
        .filter(|(_, disposition)| {
            disposition == &&NativeArtifactVerificationCheckDisposition::Unresolved
        })
        .map(|(check, _)| check_name(check).to_owned())
        .collect();
    let disposition = derive_disposition(&checks);
    let mut value = NativeArtifactVerificationReceipt {
        profile: NATIVE_ARTIFACT_VERIFICATION_RECEIPT_PROFILE.to_owned(),
        receipt_id,
        plan_ref: plan.plan_id.clone(),
        plan_digest: plan.plan_digest.clone(),
        artifact_receipt_ref: lineage.receipt.receipt_id.clone(),
        artifact_receipt_digest: lineage.receipt.receipt_digest.clone(),
        observation_ref: observation.observation_id.clone(),
        observation_digest: observation.observation_digest.clone(),
        verifier_id: plan.verifier.verifier_id.clone(),
        checks,
        evidence_refs: observation.evidence_refs.clone(),
        unresolved_items,
        disposition,
        non_authority: NATIVE_ARTIFACT_VERIFICATION_NON_AUTHORITY.to_owned(),
        receipt_digest: empty_digest(),
    };
    value.receipt_digest = native_artifact_verification_receipt_digest(&value)?;
    validate_native_artifact_verification_receipt(
        lineage,
        plan,
        observation,
        second_lineage,
        &value,
    )?;
    Ok(value)
}

pub fn validate_native_artifact_verification_receipt(
    lineage: &NativeArtifactReceiptLineage<'_>,
    plan: &NativeArtifactVerificationPlan,
    observation: &NativeArtifactVerificationObservation,
    second_lineage: Option<&NativeArtifactReceiptLineage<'_>>,
    receipt: &NativeArtifactVerificationReceipt,
) -> SemanticCompilerValidation {
    validate_native_artifact_verification_observation(lineage, plan, observation, second_lineage)?;
    exact_profile(
        &receipt.profile,
        NATIVE_ARTIFACT_VERIFICATION_RECEIPT_PROFILE,
        "verification_receipt.profile",
    )?;
    let expected_checks = derive_checks(lineage, plan, observation, second_lineage);
    let expected_unresolved = expected_checks
        .iter()
        .filter(|(_, disposition)| {
            disposition == &&NativeArtifactVerificationCheckDisposition::Unresolved
        })
        .map(|(check, _)| check_name(check).to_owned())
        .collect::<BTreeSet<_>>();
    if receipt.plan_ref != plan.plan_id
        || receipt.plan_digest != plan.plan_digest
        || receipt.artifact_receipt_ref != lineage.receipt.receipt_id
        || receipt.artifact_receipt_digest != lineage.receipt.receipt_digest
        || receipt.observation_ref != observation.observation_id
        || receipt.observation_digest != observation.observation_digest
        || receipt.verifier_id != plan.verifier.verifier_id
        || receipt.checks != expected_checks
        || receipt.evidence_refs != observation.evidence_refs
        || receipt.unresolved_items != expected_unresolved
        || receipt.disposition != derive_disposition(&receipt.checks)
    {
        return form_fault(
            SemanticCompilerFormFaultKind::AccountingMismatch,
            "verification_receipt.derivation",
            "verification receipt differs from its exact plan observation check or evidence derivation",
        );
    }
    exact_verification_non_authority(&receipt.non_authority, "verification_receipt.non_authority")?;
    validate_digest(
        &receipt.receipt_digest,
        "verification_receipt.receipt_digest",
    )?;
    require_digest(
        &receipt.receipt_digest,
        native_artifact_verification_receipt_digest(receipt)?,
        "verification_receipt.receipt_digest",
    )
}

fn required_checks(require_reproducibility: bool) -> BTreeSet<NativeArtifactVerificationCheck> {
    let mut checks = BTreeSet::from([
        NativeArtifactVerificationCheck::ArtifactIdentity,
        NativeArtifactVerificationCheck::ArtifactDigest,
        NativeArtifactVerificationCheck::ByteSize,
        NativeArtifactVerificationCheck::MediaType,
        NativeArtifactVerificationCheck::TargetTriple,
        NativeArtifactVerificationCheck::BuildInput,
        NativeArtifactVerificationCheck::InterfaceInputSchema,
        NativeArtifactVerificationCheck::InterfaceOutputSchema,
        NativeArtifactVerificationCheck::EvidenceCoverage,
    ]);
    if require_reproducibility {
        checks.insert(NativeArtifactVerificationCheck::Reproducibility);
    }
    checks
}

fn validate_verifier_pin(
    lineage: &NativeArtifactReceiptLineage<'_>,
    verifier: &NativeArtifactVerifierPin,
) -> SemanticCompilerValidation {
    bounded_text(
        &verifier.verifier_profile,
        "verification_plan.verifier_profile",
    )?;
    validate_digest(
        &verifier.program_digest,
        "verification_plan.verifier_program_digest",
    )?;
    validate_digest(
        &verifier.configuration_digest,
        "verification_plan.verifier_configuration_digest",
    )?;
    if verifier.verifier_id == lineage.plan.runner.runner_id
        || verifier.verifier_id == lineage.authorization.security_signer_id
        || verifier.verifier_id == lineage.authorization.authority_signer_id
        || verifier.program_digest == lineage.plan.runner.executable_digest
    {
        return form_fault(
            SemanticCompilerFormFaultKind::RecognitionBoundary,
            "verification_plan.verifier_independence",
            "verifier identity and program must differ from runner and approval signers",
        );
    }
    Ok(())
}

fn project_second_build_evidence(
    lineage: &NativeArtifactReceiptLineage<'_>,
) -> SemanticCompilerValidation<NativeSecondBuildEvidence> {
    lineage.validate()?;
    Ok(NativeSecondBuildEvidence {
        artifact_receipt_ref: lineage.receipt.receipt_id.clone(),
        artifact_receipt_digest: lineage.receipt.receipt_digest.clone(),
        authorization_ref: lineage.authorization.certificate_id.clone(),
        attempt_ref: lineage.observation.attempt_id.clone(),
        artifact: lineage.receipt.artifact.clone(),
        toolchain_configuration_digest: lineage
            .build
            .candidate()
            .toolchain
            .configuration_digest
            .clone(),
    })
}

fn validate_independently_observed_artifact(
    artifact: &NativeObservedArtifact,
) -> SemanticCompilerValidation {
    if !is_safe_relative_path(&artifact.relative_path) || artifact.byte_size == 0 {
        return form_fault(
            SemanticCompilerFormFaultKind::InvalidReference,
            "verification_observation.artifact",
            "independently observed artifact path or byte size is invalid",
        );
    }
    bounded_text(
        &artifact.media_type,
        "verification_observation.artifact.media_type",
    )?;
    bounded_text(
        &artifact.target_triple,
        "verification_observation.artifact.target_triple",
    )?;
    validate_digest(
        &artifact.artifact_digest,
        "verification_observation.artifact.digest",
    )?;
    validate_digest(
        &artifact.build_input_digest,
        "verification_observation.artifact.build_input_digest",
    )
}

fn derive_checks(
    primary: &NativeArtifactReceiptLineage<'_>,
    plan: &NativeArtifactVerificationPlan,
    observation: &NativeArtifactVerificationObservation,
    second: Option<&NativeArtifactReceiptLineage<'_>>,
) -> BTreeMap<NativeArtifactVerificationCheck, NativeArtifactVerificationCheckDisposition> {
    let mut checks = BTreeMap::new();
    let observed = observation.observed_artifact.as_ref();
    checks.insert(
        NativeArtifactVerificationCheck::ArtifactIdentity,
        compare_optional(
            observed.map(|item| &item.artifact_id),
            &plan.expected_artifact.artifact_id,
        ),
    );
    checks.insert(
        NativeArtifactVerificationCheck::ArtifactDigest,
        compare_optional(
            observed.map(|item| &item.artifact_digest),
            &plan.expected_artifact.artifact_digest,
        ),
    );
    checks.insert(
        NativeArtifactVerificationCheck::ByteSize,
        compare_optional(
            observed.map(|item| &item.byte_size),
            &plan.expected_artifact.byte_size,
        ),
    );
    checks.insert(
        NativeArtifactVerificationCheck::MediaType,
        compare_optional(
            observed.map(|item| &item.media_type),
            &plan.expected_artifact.media_type,
        ),
    );
    checks.insert(
        NativeArtifactVerificationCheck::TargetTriple,
        compare_optional(
            observed.map(|item| &item.target_triple),
            &plan.expected_artifact.target_triple,
        ),
    );
    checks.insert(
        NativeArtifactVerificationCheck::BuildInput,
        compare_optional(
            observed.map(|item| &item.build_input_digest),
            &plan.expected_artifact.build_input_digest,
        ),
    );
    checks.insert(
        NativeArtifactVerificationCheck::InterfaceInputSchema,
        compare_optional(
            observation.observed_interface_input_schema_digest.as_ref(),
            &plan.expected_interface_input_schema_digest,
        ),
    );
    checks.insert(
        NativeArtifactVerificationCheck::InterfaceOutputSchema,
        compare_optional(
            observation.observed_interface_output_schema_digest.as_ref(),
            &plan.expected_interface_output_schema_digest,
        ),
    );
    checks.insert(
        NativeArtifactVerificationCheck::EvidenceCoverage,
        if plan
            .required_evidence_refs
            .is_subset(&observation.evidence_refs)
        {
            NativeArtifactVerificationCheckDisposition::Passed
        } else {
            NativeArtifactVerificationCheckDisposition::Unresolved
        },
    );
    if plan.require_reproducibility {
        checks.insert(
            NativeArtifactVerificationCheck::Reproducibility,
            derive_reproducibility(primary, observation.second_build.as_ref(), second),
        );
    }
    checks
}

fn derive_reproducibility(
    primary: &NativeArtifactReceiptLineage<'_>,
    observed: Option<&NativeSecondBuildEvidence>,
    second: Option<&NativeArtifactReceiptLineage<'_>>,
) -> NativeArtifactVerificationCheckDisposition {
    let (Some(observed), Some(second)) = (observed, second) else {
        return NativeArtifactVerificationCheckDisposition::Unresolved;
    };
    let distinct = observed.artifact_receipt_ref != primary.receipt.receipt_id
        && observed.authorization_ref != primary.authorization.certificate_id
        && observed.attempt_ref != primary.observation.attempt_id;
    let equal_output = observed.artifact.artifact_id == primary.receipt.artifact.artifact_id
        && observed.artifact.artifact_digest == primary.receipt.artifact.artifact_digest
        && observed.artifact.byte_size == primary.receipt.artifact.byte_size
        && observed.artifact.target_triple == primary.receipt.artifact.target_triple
        && observed.artifact.build_input_digest == primary.receipt.artifact.build_input_digest
        && observed.toolchain_configuration_digest
            == primary.build.candidate().toolchain.configuration_digest;
    let exact_second = observed.artifact_receipt_ref == second.receipt.receipt_id
        && observed.artifact_receipt_digest == second.receipt.receipt_digest;
    if distinct && equal_output && exact_second {
        NativeArtifactVerificationCheckDisposition::Passed
    } else {
        NativeArtifactVerificationCheckDisposition::Failed
    }
}

fn compare_optional<T: PartialEq>(
    observed: Option<&T>,
    expected: &T,
) -> NativeArtifactVerificationCheckDisposition {
    match observed {
        Some(actual) if actual == expected => NativeArtifactVerificationCheckDisposition::Passed,
        Some(_) => NativeArtifactVerificationCheckDisposition::Failed,
        None => NativeArtifactVerificationCheckDisposition::Unresolved,
    }
}

fn derive_disposition(
    checks: &BTreeMap<NativeArtifactVerificationCheck, NativeArtifactVerificationCheckDisposition>,
) -> NativeArtifactVerificationDisposition {
    if checks
        .values()
        .any(|item| item == &NativeArtifactVerificationCheckDisposition::Failed)
    {
        NativeArtifactVerificationDisposition::Failed
    } else if checks
        .values()
        .any(|item| item == &NativeArtifactVerificationCheckDisposition::Unresolved)
    {
        NativeArtifactVerificationDisposition::Unresolved
    } else {
        NativeArtifactVerificationDisposition::Passed
    }
}

fn check_name(check: &NativeArtifactVerificationCheck) -> &'static str {
    match check {
        NativeArtifactVerificationCheck::ArtifactIdentity => "artifact_identity",
        NativeArtifactVerificationCheck::ArtifactDigest => "artifact_digest",
        NativeArtifactVerificationCheck::ByteSize => "byte_size",
        NativeArtifactVerificationCheck::MediaType => "media_type",
        NativeArtifactVerificationCheck::TargetTriple => "target_triple",
        NativeArtifactVerificationCheck::BuildInput => "build_input",
        NativeArtifactVerificationCheck::InterfaceInputSchema => "interface_input_schema",
        NativeArtifactVerificationCheck::InterfaceOutputSchema => "interface_output_schema",
        NativeArtifactVerificationCheck::EvidenceCoverage => "evidence_coverage",
        NativeArtifactVerificationCheck::Reproducibility => "reproducibility",
    }
}

fn exact_verification_non_authority(value: &str, field: &str) -> SemanticCompilerValidation {
    if value == NATIVE_ARTIFACT_VERIFICATION_NON_AUTHORITY {
        Ok(())
    } else {
        form_fault(
            SemanticCompilerFormFaultKind::NonAuthorityMismatch,
            field,
            "verification form changed or omitted its fixed later-authority boundary",
        )
    }
}
