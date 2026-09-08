//! A8 supplied public logical broker-projection correspondence verifier.
//!
//! This pure core has no endpoint resolver, dynamic loader, broker client,
//! credential input, permit consumer, writer, or effect interface.
use crate::{
    B1OaprCandidateDescriptor, B1OaprCandidateOrigin, B1OaprConfidentiality, B1OaprPacket,
    B1OaprRequest, EocvFault, EocvFaultCode, KcvInputClass, PercPredecessor,
    PercVerificationReceipt, PercVerificationRequest, TwvEffectAccount, b1oapr_descriptor_digest,
    b1oapr_request_digest, compile_b1oapr_packet, eocv_domain_digest, eocv_fault,
    parse_eocv_canonical, valid_eocv_uuid, validate_perc_receipt_fields,
    verify_perc_reference_correspondence,
};
use cantor_core::{ContentDigest, sha256_bytes};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const PBPC_DECLARATION_PROFILE: &str = "cantor-b1-production-broker-projection-declaration/0.1";
pub const PBPC_REQUEST_PROFILE: &str = "cantor-b1-production-broker-projection-request/0.1";
pub const PBPC_RECEIPT_PROFILE: &str = "cantor-b1-production-broker-projection-receipt/0.1";
pub const PBPC_EVIDENCE_PROFILE: &str = "cantor-b1-production-broker-projection-evidence/0.1";
pub const PBPC_SOURCE_SNAPSHOT_UUID: &str = "3a14ad38-fca5-4528-9a56-ccda97d7f158";
pub const PBPC_CANONICAL_UUID: &str = "6a0ee327-1235-4d4c-8a0d-fb1b47f525c1";
pub const PBPC_SIGNATURE_UUID: &str = "2943ebdb-7e37-4203-a99f-dbd6b7fea798";
pub const PBPC_SOURCE_CUSTODY_COMMIT: &str = "a95b30bc24fe4e72f04d488ab2ca7a933d55ba9a";
pub const PBPC_SOURCE_BOOKEND_COMMIT: &str = "b491279e9160673f3208bb945531f2cd55e25188";
pub const PBPC_FORMATION_COMMIT: &str = "0c512041316d5d0ecbd6c5db9174dfb025f070fd";
pub const PBPC_FORMATION_BOOKEND_COMMIT: &str = "7407f055ff5ea9fff1624e23ffa0fc379b265e2b";
pub const PBPC_A7_IMPLEMENTATION_COMMIT: &str = "49f5c95cfc4584d07b179499f67c1f67d240de6d";
pub const PBPC_A7_BOOKEND_COMMIT: &str = "0d5ba710af366d181c09cb0e0ebbeb8103e53b3e";
pub const PBPC_A7_PROOF_UUID: &str = "477b0a89-4e2a-42e3-b995-29e9c63a430a";
pub const PBPC_A8_CANDIDATE_UUID: &str = "a1000000-0000-4000-8000-000000000008";
pub const PBPC_DECLARATION_DOMAIN: &str = "cantor.b1.production-broker-projection.declaration.v1";
pub const PBPC_REQUEST_DOMAIN: &str = "cantor.b1.production-broker-projection.request.v1";
pub const PBPC_RECEIPT_DOMAIN: &str = "cantor.b1.production-broker-projection.receipt.v1";
pub const PBPC_EVIDENCE_DOMAIN: &str = "cantor.b1.production-broker-projection.evidence.v1";
pub const PBPC_MATCHED_STATUS: &str =
    "supplied_production_broker_projection_correspondence_matched_execution_unresolved";
pub const PBPC_MISMATCHED_STATUS: &str =
    "supplied_production_broker_projection_correspondence_mismatched_execution_unresolved";
pub const PBPC_AUTHORITY: &str = "supplied_production_broker_projection_correspondence_only";
pub const PBPC_MAX_FORM_BYTES: usize = 1_048_576;
pub const PBPC_MAX_EVIDENCE_BYTES: u64 = 16_777_216;
pub const PBPC_MAX_EVIDENCE_REFERENCES: usize = 48;
const PBPC_MAX_IDENTIFIER_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PbpcMismatchReason {
    A7ReceiptMismatch,
    PacketMismatch,
    DescriptorMismatch,
    ProjectionRawBytesMismatch,
    ProjectionSelfDigestMismatch,
    ProjectionUuidMismatch,
    CandidateUuidMismatch,
    AuthorityNameMismatch,
    ArtifactKindMismatch,
    OpaqueReferenceMismatch,
    ContentSha256Mismatch,
    DeclaredBytesMismatch,
    ConfidentialityMismatch,
    VerifierProfileMismatch,
    FixtureFlagMismatch,
    DependencyOrdinalMismatch,
    InputClassMismatch,
    PreparationPlanMismatch,
    AdapterProfileMismatch,
    OperationKindMismatch,
    SubjectMismatch,
    InputReceiptProfileMismatch,
    OutputReceiptProfileMismatch,
    RequiresPrivatePermitMismatch,
    ActivationRequestedMismatch,
    EvidenceReferencesMismatch,
}

pub const PBPC_MISMATCH_REASONS: [PbpcMismatchReason; 26] = [
    PbpcMismatchReason::A7ReceiptMismatch,
    PbpcMismatchReason::PacketMismatch,
    PbpcMismatchReason::DescriptorMismatch,
    PbpcMismatchReason::ProjectionRawBytesMismatch,
    PbpcMismatchReason::ProjectionSelfDigestMismatch,
    PbpcMismatchReason::ProjectionUuidMismatch,
    PbpcMismatchReason::CandidateUuidMismatch,
    PbpcMismatchReason::AuthorityNameMismatch,
    PbpcMismatchReason::ArtifactKindMismatch,
    PbpcMismatchReason::OpaqueReferenceMismatch,
    PbpcMismatchReason::ContentSha256Mismatch,
    PbpcMismatchReason::DeclaredBytesMismatch,
    PbpcMismatchReason::ConfidentialityMismatch,
    PbpcMismatchReason::VerifierProfileMismatch,
    PbpcMismatchReason::FixtureFlagMismatch,
    PbpcMismatchReason::DependencyOrdinalMismatch,
    PbpcMismatchReason::InputClassMismatch,
    PbpcMismatchReason::PreparationPlanMismatch,
    PbpcMismatchReason::AdapterProfileMismatch,
    PbpcMismatchReason::OperationKindMismatch,
    PbpcMismatchReason::SubjectMismatch,
    PbpcMismatchReason::InputReceiptProfileMismatch,
    PbpcMismatchReason::OutputReceiptProfileMismatch,
    PbpcMismatchReason::RequiresPrivatePermitMismatch,
    PbpcMismatchReason::ActivationRequestedMismatch,
    PbpcMismatchReason::EvidenceReferencesMismatch,
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PbpcProjectionDeclaration {
    pub profile: String,
    pub projection_uuid: String,
    pub a7_receipt_sha256: ContentDigest,
    pub preparation_plan_sha256: ContentDigest,
    pub candidate_uuid: String,
    pub authority_name: String,
    pub artifact_kind: String,
    pub opaque_reference: String,
    pub content_sha256: ContentDigest,
    pub declared_bytes: u64,
    pub confidentiality: B1OaprConfidentiality,
    pub required_verifier_profile: String,
    pub fixture_only: bool,
    pub dependency_ordinal: u8,
    pub input_class: KcvInputClass,
    pub broker_adapter_profile: String,
    pub broker_operation_kind: String,
    pub broker_subject: String,
    pub required_input_receipt_profile: String,
    pub expected_output_receipt_profile: String,
    pub requires_private_permit: bool,
    pub activation_requested: bool,
    pub evidence_references: Vec<String>,
    pub projection_sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PbpcEvidenceArtifact {
    pub path: String,
    pub bytes: u64,
    pub sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PbpcEvidenceManifest {
    pub profile: String,
    pub manifest_uuid: String,
    pub source_snapshot_uuid: String,
    pub canonical_uuid: String,
    pub artifacts: Vec<PbpcEvidenceArtifact>,
    pub artifact_count: u8,
    pub total_artifact_bytes: u64,
    pub retained_authority_packet_sha256: ContentDigest,
    pub retained_a7_receipt_sha256: ContentDigest,
    pub retained_projection_declaration_sha256: ContentDigest,
    pub retained_receipt_sha256: ContentDigest,
    pub deterministic_replay_count: u8,
    pub required_fresh_process_replay_count: u8,
    pub byte_identical: bool,
    pub effect_count: u8,
    pub manifest_sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PbpcVerificationRequest {
    pub profile: String,
    pub source_snapshot_uuid: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub source_custody_commit: String,
    pub source_bookend_commit: String,
    pub formation_commit: String,
    pub formation_bookend_commit: String,
    pub a7_implementation_commit: String,
    pub a7_bookend_commit: String,
    pub a7_proof_uuid: String,
    pub a7_verification_request_sha256: ContentDigest,
    pub expected_a7_receipt_sha256: ContentDigest,
    pub authority_packet_request_sha256: ContentDigest,
    pub expected_authority_packet_sha256: ContentDigest,
    pub expected_candidate_uuid: String,
    pub expected_descriptor_sha256: ContentDigest,
    pub expected_projection_uuid: String,
    pub expected_projection_bytes: u64,
    pub expected_projection_raw_sha256: ContentDigest,
    pub expected_projection_sha256: ContentDigest,
    pub expected_authority_name: String,
    pub expected_artifact_kind: String,
    pub expected_opaque_reference: String,
    pub expected_content_sha256: ContentDigest,
    pub expected_declared_bytes: u64,
    pub expected_confidentiality: B1OaprConfidentiality,
    pub expected_verifier_profile: String,
    pub expected_fixture_only: bool,
    pub expected_dependency_ordinal: u8,
    pub input_class: KcvInputClass,
    pub expected_preparation_plan_sha256: ContentDigest,
    pub expected_broker_adapter_profile: String,
    pub expected_broker_operation_kind: String,
    pub expected_broker_subject: String,
    pub expected_input_receipt_profile: String,
    pub expected_output_receipt_profile: String,
    pub expected_requires_private_permit: bool,
    pub expected_activation_requested: bool,
    pub evidence_references: Vec<String>,
    pub maximum_attempts: u8,
    pub automatic_retry_count: u8,
    pub automatic_cleanup_count: u8,
    pub request_sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PbpcComparisonAccount {
    pub a7_receipt_matches: bool,
    pub packet_matches: bool,
    pub descriptor_matches: bool,
    pub projection_bytes_matches: bool,
    pub projection_digest_valid: bool,
    pub projection_uuid_matches: bool,
    pub candidate_uuid_matches: bool,
    pub authority_name_matches: bool,
    pub artifact_kind_matches: bool,
    pub opaque_reference_matches: bool,
    pub content_sha256_matches: bool,
    pub declared_bytes_matches: bool,
    pub confidentiality_matches: bool,
    pub verifier_profile_matches: bool,
    pub fixture_only_matches: bool,
    pub dependency_ordinal_matches: bool,
    pub input_class_matches: bool,
    pub preparation_plan_matches: bool,
    pub adapter_profile_matches: bool,
    pub operation_kind_matches: bool,
    pub subject_matches: bool,
    pub input_receipt_profile_matches: bool,
    pub output_receipt_profile_matches: bool,
    pub requires_private_permit_matches: bool,
    pub activation_requested_false: bool,
    pub evidence_references_match: bool,
    pub all_correspondence_matches: bool,
    pub mismatch_reasons: Vec<PbpcMismatchReason>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PbpcVerificationReceipt {
    pub profile: String,
    pub status: String,
    pub authority: String,
    pub source_snapshot_uuid: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub source_custody_commit: String,
    pub formation_commit: String,
    pub formation_bookend_commit: String,
    pub a7_implementation_commit: String,
    pub a7_bookend_commit: String,
    pub a7_proof_uuid: String,
    pub request_sha256: ContentDigest,
    pub a7_verification_request_sha256: ContentDigest,
    pub a7_receipt_sha256: ContentDigest,
    pub a7_receipt: PercVerificationReceipt,
    pub authority_packet_request_sha256: ContentDigest,
    pub authority_packet_sha256: ContentDigest,
    pub a8_candidate_uuid: String,
    pub a8_descriptor_sha256: ContentDigest,
    pub projection_declaration_bytes: u64,
    pub projection_declaration_raw_sha256: ContentDigest,
    pub projection_declaration_sha256: ContentDigest,
    pub projection_uuid: String,
    pub opaque_reference: String,
    pub content_sha256: ContentDigest,
    pub declared_bytes: u64,
    pub confidentiality: B1OaprConfidentiality,
    pub required_verifier_profile: String,
    pub dependency_ordinal: u8,
    pub input_class: KcvInputClass,
    pub fixture_only: bool,
    pub preparation_plan_sha256: ContentDigest,
    pub broker_adapter_profile: String,
    pub broker_operation_kind: String,
    pub broker_subject: String,
    pub required_input_receipt_profile: String,
    pub expected_output_receipt_profile: String,
    pub requires_private_permit: bool,
    pub activation_requested: bool,
    pub comparison_account: PbpcComparisonAccount,
    pub evidence_references: Vec<String>,
    pub maximum_attempts: u8,
    pub automatic_retry_count: u8,
    pub automatic_cleanup_count: u8,
    pub a7_correspondence_receipt_verified: bool,
    pub packet_replayed: bool,
    pub descriptor_correspondence_verified: bool,
    pub projection_declaration_bytes_matched: bool,
    pub comparison_reconstructed: bool,
    pub production_broker_projection_correspondence_proved: bool,
    pub production_authority_claimed: bool,
    pub private_execution_permit_present: bool,
    pub permit_material_authenticated: bool,
    pub permit_dependency_satisfied: bool,
    pub broker_endpoint_resolved: bool,
    pub broker_reachable: bool,
    pub broker_identity_proved: bool,
    pub broker_authority_proved: bool,
    pub broker_session_authenticated: bool,
    pub broker_activation_authorized: bool,
    pub production_broker_projection_present: bool,
    pub live_authorization_admitted: bool,
    pub physical_preparation_authorized: bool,
    pub ready_for_physical_execution: bool,
    pub execution_authorized: bool,
    pub effect_account: TwvEffectAccount,
    pub receipt_sha256: ContentDigest,
}

pub struct PbpcPredecessor<'a> {
    pub a7_request: &'a PercVerificationRequest,
    pub a7_predecessor: PercPredecessor<'a>,
    pub raw_a7_envelope: &'a [u8],
    pub a7_receipt: &'a PercVerificationReceipt,
}

pub const PBPC_REQUEST_FIELDS: [&str; 44] = [
    "profile",
    "source_snapshot_uuid",
    "canonical_uuid",
    "signature_uuid",
    "source_custody_commit",
    "source_bookend_commit",
    "formation_commit",
    "formation_bookend_commit",
    "a7_implementation_commit",
    "a7_bookend_commit",
    "a7_proof_uuid",
    "a7_verification_request_sha256",
    "expected_a7_receipt_sha256",
    "authority_packet_request_sha256",
    "expected_authority_packet_sha256",
    "expected_candidate_uuid",
    "expected_descriptor_sha256",
    "expected_projection_uuid",
    "expected_projection_bytes",
    "expected_projection_raw_sha256",
    "expected_projection_sha256",
    "expected_authority_name",
    "expected_artifact_kind",
    "expected_opaque_reference",
    "expected_content_sha256",
    "expected_declared_bytes",
    "expected_confidentiality",
    "expected_verifier_profile",
    "expected_fixture_only",
    "expected_dependency_ordinal",
    "input_class",
    "expected_preparation_plan_sha256",
    "expected_broker_adapter_profile",
    "expected_broker_operation_kind",
    "expected_broker_subject",
    "expected_input_receipt_profile",
    "expected_output_receipt_profile",
    "expected_requires_private_permit",
    "expected_activation_requested",
    "evidence_references",
    "maximum_attempts",
    "automatic_retry_count",
    "automatic_cleanup_count",
    "request_sha256",
];

pub const PBPC_RECEIPT_FIELDS: [&str; 68] = [
    "profile",
    "status",
    "authority",
    "source_snapshot_uuid",
    "canonical_uuid",
    "signature_uuid",
    "source_custody_commit",
    "formation_commit",
    "formation_bookend_commit",
    "a7_implementation_commit",
    "a7_bookend_commit",
    "a7_proof_uuid",
    "request_sha256",
    "a7_verification_request_sha256",
    "a7_receipt_sha256",
    "a7_receipt",
    "authority_packet_request_sha256",
    "authority_packet_sha256",
    "a8_candidate_uuid",
    "a8_descriptor_sha256",
    "projection_declaration_bytes",
    "projection_declaration_raw_sha256",
    "projection_declaration_sha256",
    "projection_uuid",
    "opaque_reference",
    "content_sha256",
    "declared_bytes",
    "confidentiality",
    "required_verifier_profile",
    "dependency_ordinal",
    "input_class",
    "fixture_only",
    "preparation_plan_sha256",
    "broker_adapter_profile",
    "broker_operation_kind",
    "broker_subject",
    "required_input_receipt_profile",
    "expected_output_receipt_profile",
    "requires_private_permit",
    "activation_requested",
    "comparison_account",
    "evidence_references",
    "maximum_attempts",
    "automatic_retry_count",
    "automatic_cleanup_count",
    "a7_correspondence_receipt_verified",
    "packet_replayed",
    "descriptor_correspondence_verified",
    "projection_declaration_bytes_matched",
    "comparison_reconstructed",
    "production_broker_projection_correspondence_proved",
    "production_authority_claimed",
    "private_execution_permit_present",
    "permit_material_authenticated",
    "permit_dependency_satisfied",
    "broker_endpoint_resolved",
    "broker_reachable",
    "broker_identity_proved",
    "broker_authority_proved",
    "broker_session_authenticated",
    "broker_activation_authorized",
    "production_broker_projection_present",
    "live_authorization_admitted",
    "physical_preparation_authorized",
    "ready_for_physical_execution",
    "execution_authorized",
    "effect_account",
    "receipt_sha256",
];

pub const PBPC_EVIDENCE_FIELDS: [&str; 16] = [
    "profile",
    "manifest_uuid",
    "source_snapshot_uuid",
    "canonical_uuid",
    "artifacts",
    "artifact_count",
    "total_artifact_bytes",
    "retained_authority_packet_sha256",
    "retained_a7_receipt_sha256",
    "retained_projection_declaration_sha256",
    "retained_receipt_sha256",
    "deterministic_replay_count",
    "required_fresh_process_replay_count",
    "byte_identical",
    "effect_count",
    "manifest_sha256",
];

pub fn pbpc_comparison_from_flags(flags: [bool; 26]) -> PbpcComparisonAccount {
    let mismatch_reasons = flags
        .iter()
        .enumerate()
        .filter_map(|(index, matched)| (!matched).then_some(PBPC_MISMATCH_REASONS[index]))
        .collect();
    PbpcComparisonAccount {
        a7_receipt_matches: flags[0],
        packet_matches: flags[1],
        descriptor_matches: flags[2],
        projection_bytes_matches: flags[3],
        projection_digest_valid: flags[4],
        projection_uuid_matches: flags[5],
        candidate_uuid_matches: flags[6],
        authority_name_matches: flags[7],
        artifact_kind_matches: flags[8],
        opaque_reference_matches: flags[9],
        content_sha256_matches: flags[10],
        declared_bytes_matches: flags[11],
        confidentiality_matches: flags[12],
        verifier_profile_matches: flags[13],
        fixture_only_matches: flags[14],
        dependency_ordinal_matches: flags[15],
        input_class_matches: flags[16],
        preparation_plan_matches: flags[17],
        adapter_profile_matches: flags[18],
        operation_kind_matches: flags[19],
        subject_matches: flags[20],
        input_receipt_profile_matches: flags[21],
        output_receipt_profile_matches: flags[22],
        requires_private_permit_matches: flags[23],
        activation_requested_false: flags[24],
        evidence_references_match: flags[25],
        all_correspondence_matches: flags.into_iter().all(|flag| flag),
        mismatch_reasons,
    }
}

pub fn validate_pbpc_comparison_account(account: &PbpcComparisonAccount) -> Result<(), EocvFault> {
    let expected = pbpc_comparison_from_flags([
        account.a7_receipt_matches,
        account.packet_matches,
        account.descriptor_matches,
        account.projection_bytes_matches,
        account.projection_digest_valid,
        account.projection_uuid_matches,
        account.candidate_uuid_matches,
        account.authority_name_matches,
        account.artifact_kind_matches,
        account.opaque_reference_matches,
        account.content_sha256_matches,
        account.declared_bytes_matches,
        account.confidentiality_matches,
        account.verifier_profile_matches,
        account.fixture_only_matches,
        account.dependency_ordinal_matches,
        account.input_class_matches,
        account.preparation_plan_matches,
        account.adapter_profile_matches,
        account.operation_kind_matches,
        account.subject_matches,
        account.input_receipt_profile_matches,
        account.output_receipt_profile_matches,
        account.requires_private_permit_matches,
        account.activation_requested_false,
        account.evidence_references_match,
    ]);
    if *account != expected {
        return Err(eocv_fault(
            EocvFaultCode::Receipt,
            "A8 comparison account differs",
        ));
    }
    Ok(())
}

pub fn compare_pbpc_projection_metadata(
    expected: &PbpcProjectionDeclaration,
    supplied: &PbpcProjectionDeclaration,
    a7_receipt_matches: bool,
    packet_matches: bool,
    descriptor_matches: bool,
    projection_raw_bytes_match: bool,
) -> Result<PbpcComparisonAccount, EocvFault> {
    validate_pbpc_declaration(expected)?;
    validate_pbpc_declaration(supplied)?;
    let supplied_digest = pbpc_declaration_digest(supplied)?;
    Ok(pbpc_comparison_from_flags([
        a7_receipt_matches,
        packet_matches,
        descriptor_matches,
        projection_raw_bytes_match,
        supplied.projection_sha256 == supplied_digest,
        supplied.projection_uuid == expected.projection_uuid,
        supplied.candidate_uuid == expected.candidate_uuid,
        supplied.authority_name == expected.authority_name,
        supplied.artifact_kind == expected.artifact_kind,
        supplied.opaque_reference == expected.opaque_reference,
        supplied.content_sha256 == expected.content_sha256,
        supplied.declared_bytes == expected.declared_bytes,
        supplied.confidentiality == expected.confidentiality,
        supplied.required_verifier_profile == expected.required_verifier_profile,
        supplied.fixture_only == expected.fixture_only,
        supplied.dependency_ordinal == expected.dependency_ordinal,
        supplied.input_class == expected.input_class,
        supplied.preparation_plan_sha256 == expected.preparation_plan_sha256,
        supplied.broker_adapter_profile == expected.broker_adapter_profile,
        supplied.broker_operation_kind == expected.broker_operation_kind,
        supplied.broker_subject == expected.broker_subject,
        supplied.required_input_receipt_profile == expected.required_input_receipt_profile,
        supplied.expected_output_receipt_profile == expected.expected_output_receipt_profile,
        supplied.requires_private_permit == expected.requires_private_permit,
        !supplied.activation_requested,
        supplied.evidence_references == expected.evidence_references,
    ]))
}

pub fn compare_pbpc_projection_to_request(
    request: &PbpcVerificationRequest,
    supplied: &PbpcProjectionDeclaration,
    a7_receipt_matches: bool,
    packet_matches: bool,
    descriptor_matches: bool,
    projection_raw_bytes_match: bool,
) -> Result<PbpcComparisonAccount, EocvFault> {
    validate_pbpc_request(request)?;
    validate_pbpc_declaration(supplied)?;
    let supplied_digest = pbpc_declaration_digest(supplied)?;
    Ok(pbpc_comparison_from_flags([
        a7_receipt_matches,
        packet_matches,
        descriptor_matches,
        projection_raw_bytes_match,
        supplied.projection_sha256 == supplied_digest,
        supplied.projection_uuid == request.expected_projection_uuid,
        supplied.candidate_uuid == request.expected_candidate_uuid,
        supplied.authority_name == request.expected_authority_name,
        supplied.artifact_kind == request.expected_artifact_kind,
        supplied.opaque_reference == request.expected_opaque_reference,
        supplied.content_sha256 == request.expected_content_sha256,
        supplied.declared_bytes == request.expected_declared_bytes,
        supplied.confidentiality == request.expected_confidentiality,
        supplied.required_verifier_profile == request.expected_verifier_profile,
        supplied.fixture_only == request.expected_fixture_only,
        supplied.dependency_ordinal == request.expected_dependency_ordinal,
        supplied.input_class == request.input_class,
        supplied.preparation_plan_sha256 == request.expected_preparation_plan_sha256,
        supplied.broker_adapter_profile == request.expected_broker_adapter_profile,
        supplied.broker_operation_kind == request.expected_broker_operation_kind,
        supplied.broker_subject == request.expected_broker_subject,
        supplied.required_input_receipt_profile == request.expected_input_receipt_profile,
        supplied.expected_output_receipt_profile == request.expected_output_receipt_profile,
        supplied.requires_private_permit == request.expected_requires_private_permit,
        !supplied.activation_requested && !request.expected_activation_requested,
        supplied.evidence_references == request.evidence_references,
    ]))
}

pub fn pbpc_declaration_digest(
    declaration: &PbpcProjectionDeclaration,
) -> Result<ContentDigest, EocvFault> {
    bounded(declaration)?;
    let mut normalized = declaration.clone();
    normalized.projection_sha256 = sha256_bytes(b"");
    eocv_domain_digest(PBPC_DECLARATION_DOMAIN, &normalized)
}

pub fn validate_pbpc_declaration(declaration: &PbpcProjectionDeclaration) -> Result<(), EocvFault> {
    bounded(declaration)?;
    if declaration.profile != PBPC_DECLARATION_PROFILE
        || !valid_eocv_uuid(&declaration.projection_uuid)
        || declaration.dependency_ordinal != 7
        || !declaration.requires_private_permit
        || declaration.activation_requested
        || declaration.evidence_references.is_empty()
        || declaration.evidence_references.len() > PBPC_MAX_EVIDENCE_REFERENCES
        || declaration.projection_sha256 != pbpc_declaration_digest(declaration)?
    {
        return Err(eocv_fault(
            EocvFaultCode::Shape,
            "A8 projection declaration shape differs",
        ));
    }
    for value in [
        &declaration.authority_name,
        &declaration.artifact_kind,
        &declaration.opaque_reference,
        &declaration.broker_operation_kind,
        &declaration.broker_subject,
    ] {
        if !valid_inert_identifier(value, false) {
            return Err(eocv_fault(
                EocvFaultCode::Shape,
                "A8 inert identifier shape differs",
            ));
        }
    }
    for value in [
        &declaration.required_verifier_profile,
        &declaration.broker_adapter_profile,
        &declaration.required_input_receipt_profile,
        &declaration.expected_output_receipt_profile,
    ] {
        if !valid_inert_identifier(value, true) {
            return Err(eocv_fault(
                EocvFaultCode::Shape,
                "A8 inert profile shape differs",
            ));
        }
    }
    let mut unique = BTreeSet::new();
    if declaration
        .evidence_references
        .iter()
        .any(|value| !valid_inert_identifier(value, false) || !unique.insert(value))
    {
        return Err(eocv_fault(
            EocvFaultCode::Shape,
            "A8 evidence reference shape differs",
        ));
    }
    Ok(())
}

pub fn to_pbpc_declaration_machine_form(
    declaration: &PbpcProjectionDeclaration,
) -> Result<String, EocvFault> {
    validate_pbpc_declaration(declaration)?;
    serde_json::to_string(declaration).map_err(|_| {
        eocv_fault(
            EocvFaultCode::MachineForm,
            "A8 declaration encoding differs",
        )
    })
}

pub fn from_pbpc_declaration_machine_form(
    text: &str,
) -> Result<PbpcProjectionDeclaration, EocvFault> {
    let value = parse_eocv_canonical(text)?;
    validate_pbpc_declaration(&value)?;
    Ok(value)
}

pub fn pbpc_request_digest(request: &PbpcVerificationRequest) -> Result<ContentDigest, EocvFault> {
    bounded(request)?;
    let mut normalized = request.clone();
    normalized.request_sha256 = sha256_bytes(b"");
    eocv_domain_digest(PBPC_REQUEST_DOMAIN, &normalized)
}

pub fn validate_pbpc_request(request: &PbpcVerificationRequest) -> Result<(), EocvFault> {
    bounded(request)?;
    if request.profile != PBPC_REQUEST_PROFILE {
        return Err(eocv_fault(
            EocvFaultCode::Profile,
            "A8 request profile differs",
        ));
    }
    if request.source_snapshot_uuid != PBPC_SOURCE_SNAPSHOT_UUID
        || request.canonical_uuid != PBPC_CANONICAL_UUID
        || request.signature_uuid != PBPC_SIGNATURE_UUID
        || request.source_custody_commit != PBPC_SOURCE_CUSTODY_COMMIT
        || request.source_bookend_commit != PBPC_SOURCE_BOOKEND_COMMIT
        || request.formation_commit != PBPC_FORMATION_COMMIT
        || request.formation_bookend_commit != PBPC_FORMATION_BOOKEND_COMMIT
        || request.a7_implementation_commit != PBPC_A7_IMPLEMENTATION_COMMIT
        || request.a7_bookend_commit != PBPC_A7_BOOKEND_COMMIT
        || request.a7_proof_uuid != PBPC_A7_PROOF_UUID
    {
        return Err(eocv_fault(
            EocvFaultCode::Lineage,
            "A8 request lineage differs",
        ));
    }
    if request.expected_candidate_uuid != PBPC_A8_CANDIDATE_UUID
        || !valid_eocv_uuid(&request.expected_projection_uuid)
        || request.expected_authority_name != "broker_projection"
        || request.expected_artifact_kind != "production_broker_projection_candidate"
        || request.expected_confidentiality != B1OaprConfidentiality::PublicMetadata
        || request.expected_verifier_profile != "production-broker-projection-verifier/0.1"
        || request.expected_broker_adapter_profile != "cantor-production-broker-adapter/0.1"
        || request.expected_broker_operation_kind != "project_preparation_contract"
        || request.expected_broker_subject != "cantor_b1_cdrive_production_preparation_p0"
        || request.expected_input_receipt_profile != crate::PERC_RECEIPT_PROFILE
        || request.expected_output_receipt_profile != PBPC_RECEIPT_PROFILE
        || request.expected_dependency_ordinal != 7
        || !request.expected_requires_private_permit
        || request.expected_activation_requested
    {
        return Err(eocv_fault(
            EocvFaultCode::Coordinate,
            "A8 request coordinate differs",
        ));
    }
    let fixture = request.input_class == KcvInputClass::DeterministicFixtureCandidate;
    if request.expected_fixture_only != fixture
        || request.expected_projection_bytes == 0
        || request.expected_projection_bytes > PBPC_MAX_FORM_BYTES as u64
        || request.expected_declared_bytes == 0
        || request.expected_declared_bytes > 16_777_216
        || request.maximum_attempts != 1
        || request.automatic_retry_count != 0
        || request.automatic_cleanup_count != 0
    {
        return Err(eocv_fault(EocvFaultCode::Shape, "A8 request bounds differ"));
    }
    for digest in [
        &request.a7_verification_request_sha256,
        &request.expected_a7_receipt_sha256,
        &request.authority_packet_request_sha256,
        &request.expected_authority_packet_sha256,
        &request.expected_descriptor_sha256,
        &request.expected_projection_raw_sha256,
        &request.expected_projection_sha256,
        &request.expected_content_sha256,
        &request.expected_preparation_plan_sha256,
    ] {
        if !valid_content_digest(digest) {
            return Err(eocv_fault(
                EocvFaultCode::Digest,
                "A8 request digest shape differs",
            ));
        }
    }
    for value in [
        &request.expected_authority_name,
        &request.expected_artifact_kind,
        &request.expected_opaque_reference,
        &request.expected_broker_operation_kind,
        &request.expected_broker_subject,
    ] {
        if !valid_inert_identifier(value, false) {
            return Err(eocv_fault(
                EocvFaultCode::Shape,
                "A8 request identifier differs",
            ));
        }
    }
    for value in [
        &request.expected_verifier_profile,
        &request.expected_broker_adapter_profile,
        &request.expected_input_receipt_profile,
        &request.expected_output_receipt_profile,
    ] {
        if !valid_inert_identifier(value, true) {
            return Err(eocv_fault(
                EocvFaultCode::Shape,
                "A8 request profile shape differs",
            ));
        }
    }
    validate_reference_set(&request.evidence_references)?;
    if request.request_sha256 != pbpc_request_digest(request)? {
        return Err(eocv_fault(
            EocvFaultCode::Digest,
            "A8 request self digest differs",
        ));
    }
    Ok(())
}

pub fn to_pbpc_request_machine_form(
    request: &PbpcVerificationRequest,
) -> Result<String, EocvFault> {
    validate_pbpc_request(request)?;
    serde_json::to_string(request)
        .map_err(|_| eocv_fault(EocvFaultCode::MachineForm, "A8 request encoding differs"))
}

pub fn from_pbpc_request_machine_form(text: &str) -> Result<PbpcVerificationRequest, EocvFault> {
    let value = parse_eocv_canonical(text)?;
    validate_pbpc_request(&value)?;
    Ok(value)
}

pub fn pbpc_evidence_manifest_digest(
    manifest: &PbpcEvidenceManifest,
) -> Result<ContentDigest, EocvFault> {
    bounded(manifest)?;
    let mut normalized = manifest.clone();
    normalized.manifest_sha256 = sha256_bytes(b"");
    eocv_domain_digest(PBPC_EVIDENCE_DOMAIN, &normalized)
}

pub fn validate_pbpc_evidence_manifest(manifest: &PbpcEvidenceManifest) -> Result<(), EocvFault> {
    bounded(manifest)?;
    if manifest.profile != PBPC_EVIDENCE_PROFILE
        || !valid_eocv_uuid(&manifest.manifest_uuid)
        || manifest.source_snapshot_uuid != PBPC_SOURCE_SNAPSHOT_UUID
        || manifest.canonical_uuid != PBPC_CANONICAL_UUID
        || manifest.artifacts.len() != 33
        || manifest.artifact_count != 33
        || manifest.deterministic_replay_count != 2
        || manifest.required_fresh_process_replay_count != 2
        || !manifest.byte_identical
        || manifest.effect_count != 0
    {
        return Err(eocv_fault(
            EocvFaultCode::Evidence,
            "A8 evidence manifest identity or account differs",
        ));
    }
    let mut paths = BTreeSet::new();
    let mut total = 0u64;
    for artifact in &manifest.artifacts {
        if !valid_artifact_path(&artifact.path)
            || !paths.insert(artifact.path.as_str())
            || artifact.bytes == 0
            || artifact.bytes > (PBPC_MAX_FORM_BYTES + 1) as u64
            || !valid_content_digest(&artifact.sha256)
        {
            return Err(eocv_fault(
                EocvFaultCode::Evidence,
                "A8 evidence artifact shape differs",
            ));
        }
        total = total.checked_add(artifact.bytes).ok_or_else(|| {
            eocv_fault(EocvFaultCode::Arithmetic, "A8 evidence byte total overflow")
        })?;
    }
    for digest in [
        &manifest.retained_authority_packet_sha256,
        &manifest.retained_a7_receipt_sha256,
        &manifest.retained_projection_declaration_sha256,
        &manifest.retained_receipt_sha256,
    ] {
        if !valid_content_digest(digest) {
            return Err(eocv_fault(
                EocvFaultCode::Digest,
                "A8 retained evidence digest shape differs",
            ));
        }
    }
    if total > PBPC_MAX_EVIDENCE_BYTES
        || total != manifest.total_artifact_bytes
        || manifest.manifest_sha256 != pbpc_evidence_manifest_digest(manifest)?
    {
        return Err(eocv_fault(
            EocvFaultCode::Digest,
            "A8 evidence manifest digest or total differs",
        ));
    }
    Ok(())
}

pub fn to_pbpc_evidence_manifest_machine_form(
    manifest: &PbpcEvidenceManifest,
) -> Result<String, EocvFault> {
    validate_pbpc_evidence_manifest(manifest)?;
    serde_json::to_string(manifest).map_err(|_| {
        eocv_fault(
            EocvFaultCode::MachineForm,
            "A8 evidence manifest encoding differs",
        )
    })
}

pub fn from_pbpc_evidence_manifest_machine_form(
    text: &str,
) -> Result<PbpcEvidenceManifest, EocvFault> {
    let value = parse_eocv_canonical(text)?;
    validate_pbpc_evidence_manifest(&value)?;
    Ok(value)
}

pub fn pbpc_receipt_digest(receipt: &PbpcVerificationReceipt) -> Result<ContentDigest, EocvFault> {
    bounded(receipt)?;
    let mut normalized = receipt.clone();
    normalized.receipt_sha256 = sha256_bytes(b"");
    eocv_domain_digest(PBPC_RECEIPT_DOMAIN, &normalized)
}

pub fn validate_pbpc_receipt_fields(receipt: &PbpcVerificationReceipt) -> Result<(), EocvFault> {
    bounded(receipt)?;
    let status = if receipt.comparison_account.all_correspondence_matches {
        PBPC_MATCHED_STATUS
    } else {
        PBPC_MISMATCHED_STATUS
    };
    if receipt.profile != PBPC_RECEIPT_PROFILE
        || receipt.status != status
        || receipt.authority != PBPC_AUTHORITY
    {
        return Err(eocv_fault(
            EocvFaultCode::Profile,
            "A8 receipt profile differs",
        ));
    }
    if receipt.production_authority_claimed
        || receipt.private_execution_permit_present
        || receipt.permit_material_authenticated
        || receipt.permit_dependency_satisfied
        || receipt.broker_endpoint_resolved
        || receipt.broker_reachable
        || receipt.broker_identity_proved
        || receipt.broker_authority_proved
        || receipt.broker_session_authenticated
        || receipt.broker_activation_authorized
        || receipt.production_broker_projection_present
        || receipt.live_authorization_admitted
        || receipt.physical_preparation_authorized
        || receipt.ready_for_physical_execution
        || receipt.execution_authorized
    {
        return Err(eocv_fault(
            EocvFaultCode::Truth,
            "A8 receipt promotes authority",
        ));
    }
    if !receipt.a7_correspondence_receipt_verified
        || !receipt.packet_replayed
        || !receipt.descriptor_correspondence_verified
        || !receipt.projection_declaration_bytes_matched
        || !receipt.comparison_reconstructed
        || receipt.production_broker_projection_correspondence_proved
            != receipt.comparison_account.all_correspondence_matches
        || !receipt.requires_private_permit
        || receipt.activation_requested
    {
        return Err(eocv_fault(EocvFaultCode::Truth, "A8 receipt truth differs"));
    }
    if receipt.effect_account != TwvEffectAccount::default()
        || receipt.maximum_attempts != 1
        || receipt.automatic_retry_count != 0
        || receipt.automatic_cleanup_count != 0
    {
        return Err(eocv_fault(
            EocvFaultCode::Effect,
            "A8 receipt effect account differs",
        ));
    }
    if receipt.source_snapshot_uuid != PBPC_SOURCE_SNAPSHOT_UUID
        || receipt.canonical_uuid != PBPC_CANONICAL_UUID
        || receipt.signature_uuid != PBPC_SIGNATURE_UUID
        || receipt.source_custody_commit != PBPC_SOURCE_CUSTODY_COMMIT
        || receipt.formation_commit != PBPC_FORMATION_COMMIT
        || receipt.formation_bookend_commit != PBPC_FORMATION_BOOKEND_COMMIT
        || receipt.a7_implementation_commit != PBPC_A7_IMPLEMENTATION_COMMIT
        || receipt.a7_bookend_commit != PBPC_A7_BOOKEND_COMMIT
        || receipt.a7_proof_uuid != PBPC_A7_PROOF_UUID
        || receipt.a7_receipt_sha256 != receipt.a7_receipt.receipt_sha256
    {
        return Err(eocv_fault(
            EocvFaultCode::Lineage,
            "A8 receipt lineage differs",
        ));
    }
    if receipt.a8_candidate_uuid != PBPC_A8_CANDIDATE_UUID
        || !valid_eocv_uuid(&receipt.projection_uuid)
        || receipt.projection_declaration_bytes == 0
        || receipt.projection_declaration_bytes > PBPC_MAX_FORM_BYTES as u64
        || receipt.declared_bytes == 0
        || receipt.declared_bytes > PBPC_MAX_EVIDENCE_BYTES
        || receipt.confidentiality != B1OaprConfidentiality::PublicMetadata
        || receipt.required_verifier_profile != "production-broker-projection-verifier/0.1"
        || receipt.dependency_ordinal != 7
        || receipt.fixture_only
            != (receipt.input_class == KcvInputClass::DeterministicFixtureCandidate)
        || receipt.broker_adapter_profile != "cantor-production-broker-adapter/0.1"
        || receipt.broker_operation_kind != "project_preparation_contract"
        || receipt.broker_subject != "cantor_b1_cdrive_production_preparation_p0"
        || receipt.required_input_receipt_profile != crate::PERC_RECEIPT_PROFILE
        || receipt.expected_output_receipt_profile != PBPC_RECEIPT_PROFILE
    {
        return Err(eocv_fault(
            EocvFaultCode::Coordinate,
            "A8 receipt coordinate differs",
        ));
    }
    for digest in [
        &receipt.request_sha256,
        &receipt.a7_verification_request_sha256,
        &receipt.a7_receipt_sha256,
        &receipt.authority_packet_request_sha256,
        &receipt.authority_packet_sha256,
        &receipt.a8_descriptor_sha256,
        &receipt.projection_declaration_raw_sha256,
        &receipt.projection_declaration_sha256,
        &receipt.content_sha256,
        &receipt.preparation_plan_sha256,
    ] {
        if !valid_content_digest(digest) {
            return Err(eocv_fault(
                EocvFaultCode::Digest,
                "A8 receipt digest shape differs",
            ));
        }
    }
    validate_reference_set(&receipt.evidence_references)?;
    validate_pbpc_comparison_account(&receipt.comparison_account)?;
    validate_perc_receipt_fields(&receipt.a7_receipt).map_err(predecessor_fault)?;
    if receipt.receipt_sha256 != pbpc_receipt_digest(receipt)? {
        return Err(eocv_fault(
            EocvFaultCode::Digest,
            "A8 receipt self digest differs",
        ));
    }
    Ok(())
}

pub fn to_pbpc_receipt_machine_form(
    request: &PbpcVerificationRequest,
    predecessor: &PbpcPredecessor<'_>,
    raw_projection: &[u8],
    receipt: &PbpcVerificationReceipt,
) -> Result<String, EocvFault> {
    validate_pbpc_receipt(request, predecessor, raw_projection, receipt)?;
    serde_json::to_string(receipt)
        .map_err(|_| eocv_fault(EocvFaultCode::MachineForm, "A8 receipt encoding differs"))
}

pub fn from_pbpc_receipt_machine_form(
    request: &PbpcVerificationRequest,
    predecessor: &PbpcPredecessor<'_>,
    raw_projection: &[u8],
    text: &str,
) -> Result<PbpcVerificationReceipt, EocvFault> {
    let value = parse_eocv_canonical(text)?;
    validate_pbpc_receipt(request, predecessor, raw_projection, &value)?;
    Ok(value)
}

pub fn verify_pbpc_projection_correspondence(
    request: &PbpcVerificationRequest,
    predecessor: &PbpcPredecessor<'_>,
    raw_projection: &[u8],
) -> Result<PbpcVerificationReceipt, EocvFault> {
    validate_pbpc_request(request)?;
    raw_bound(raw_projection)?;
    let a7 = verify_perc_reference_correspondence(
        predecessor.a7_request,
        &predecessor.a7_predecessor,
        predecessor.raw_a7_envelope,
    )
    .map_err(predecessor_fault)?;
    if a7 != *predecessor.a7_receipt
        || request.a7_verification_request_sha256 != predecessor.a7_request.request_sha256
        || request.expected_a7_receipt_sha256 != a7.receipt_sha256
    {
        return Err(eocv_fault(
            EocvFaultCode::Predecessor,
            "complete A7 replay binding differs",
        ));
    }
    if request.expected_projection_bytes != raw_projection.len() as u64
        || request.expected_projection_raw_sha256 != sha256_bytes(raw_projection)
    {
        return Err(eocv_fault(
            EocvFaultCode::RawBytes,
            "A8 projection declaration raw identity differs",
        ));
    }
    let projection =
        from_pbpc_declaration_machine_form(std::str::from_utf8(raw_projection).map_err(|_| {
            eocv_fault(
                EocvFaultCode::MachineForm,
                "A8 projection declaration UTF-8 differs",
            )
        })?)?;
    if projection.projection_uuid != request.expected_projection_uuid
        || projection.projection_sha256 != request.expected_projection_sha256
    {
        return Err(eocv_fault(
            EocvFaultCode::Identity,
            "A8 projection declaration identity differs",
        ));
    }
    let (packet_request, packet) = reconstruct_pbpc_packet(
        request,
        predecessor.a7_request,
        predecessor.a7_predecessor.a6_request,
    )?;
    let comparison = compare_pbpc_projection_to_request(
        request,
        &projection,
        true,
        packet.packet_sha256 == request.expected_authority_packet_sha256,
        packet_request.descriptors[7].descriptor_sha256 == request.expected_descriptor_sha256,
        true,
    )?;
    let receipt = build_pbpc_receipt(request, a7, &projection, &comparison)?;
    validate_pbpc_receipt_fields(&receipt)?;
    Ok(receipt)
}

pub fn validate_pbpc_receipt(
    request: &PbpcVerificationRequest,
    predecessor: &PbpcPredecessor<'_>,
    raw_projection: &[u8],
    receipt: &PbpcVerificationReceipt,
) -> Result<(), EocvFault> {
    if *receipt != verify_pbpc_projection_correspondence(request, predecessor, raw_projection)? {
        return Err(eocv_fault(
            EocvFaultCode::Restart,
            "A8 retained receipt differs",
        ));
    }
    Ok(())
}

fn reconstruct_a7_packet_request(
    request: &PercVerificationRequest,
    a6_packet_request: &B1OaprRequest,
) -> Result<B1OaprRequest, EocvFault> {
    let descriptor = B1OaprCandidateDescriptor {
        ordinal: 7,
        candidate_uuid: request.expected_candidate_uuid.clone(),
        authority_name: request.expected_authority_name.clone(),
        artifact_kind: request.expected_artifact_kind.clone(),
        origin: candidate_origin(request.input_class),
        opaque_reference: request.expected_opaque_reference.clone(),
        content_sha256: request.expected_content_sha256.clone(),
        declared_bytes: request.expected_declared_bytes,
        confidentiality: request.expected_confidentiality,
        required_verifier_profile: request.expected_verifier_profile.clone(),
        fixture_only: request.expected_fixture_only,
        dependency_ordinal: Some(request.expected_dependency_ordinal),
        descriptor_sha256: request.expected_descriptor_sha256.clone(),
    };
    if descriptor.descriptor_sha256
        != b1oapr_descriptor_digest(&descriptor).map_err(predecessor_fault)?
        || a6_packet_request.descriptors.len() != 9
    {
        return Err(eocv_fault(
            EocvFaultCode::Predecessor,
            "A7 packet reconstruction input differs",
        ));
    }
    let mut current = a6_packet_request.clone();
    current.descriptors[6] = descriptor;
    current.request_sha256 = b1oapr_request_digest(&current).map_err(predecessor_fault)?;
    if current.request_sha256 != request.authority_packet_request_sha256 {
        return Err(eocv_fault(
            EocvFaultCode::Predecessor,
            "A7 packet request reconstruction differs",
        ));
    }
    Ok(current)
}

fn reconstruct_pbpc_packet(
    request: &PbpcVerificationRequest,
    a7_request: &PercVerificationRequest,
    a6_request: &crate::EocvVerificationRequest,
) -> Result<(B1OaprRequest, B1OaprPacket), EocvFault> {
    let prior = reconstruct_a7_packet_request(a7_request, &a6_request.authority_packet_request)?;
    let descriptor = B1OaprCandidateDescriptor {
        ordinal: 8,
        candidate_uuid: request.expected_candidate_uuid.clone(),
        authority_name: request.expected_authority_name.clone(),
        artifact_kind: request.expected_artifact_kind.clone(),
        origin: candidate_origin(request.input_class),
        opaque_reference: request.expected_opaque_reference.clone(),
        content_sha256: request.expected_content_sha256.clone(),
        declared_bytes: request.expected_declared_bytes,
        confidentiality: request.expected_confidentiality,
        required_verifier_profile: request.expected_verifier_profile.clone(),
        fixture_only: request.expected_fixture_only,
        dependency_ordinal: Some(request.expected_dependency_ordinal),
        descriptor_sha256: request.expected_descriptor_sha256.clone(),
    };
    if descriptor.descriptor_sha256
        != b1oapr_descriptor_digest(&descriptor).map_err(predecessor_fault)?
    {
        return Err(eocv_fault(
            EocvFaultCode::Digest,
            "A8 descriptor digest differs",
        ));
    }
    let mut current = prior.clone();
    current.descriptors[7] = descriptor;
    current.request_sha256 = b1oapr_request_digest(&current).map_err(predecessor_fault)?;
    if current.request_sha256 != request.authority_packet_request_sha256 {
        return Err(eocv_fault(
            EocvFaultCode::Digest,
            "A8 packet request identity differs",
        ));
    }
    let first = compile_b1oapr_packet(&current).map_err(predecessor_fault)?;
    let second = compile_b1oapr_packet(&current).map_err(predecessor_fault)?;
    if first != second || first.packet_sha256 != request.expected_authority_packet_sha256 {
        return Err(eocv_fault(
            EocvFaultCode::Digest,
            "A8 packet reconstruction differs",
        ));
    }
    if prior.descriptors[..7] != current.descriptors[..7]
        || prior.descriptors[8..] != current.descriptors[8..]
    {
        return Err(eocv_fault(
            EocvFaultCode::Dependency,
            "A8 changed another packet descriptor",
        ));
    }
    let mut normalized = current.clone();
    normalized.descriptors[7] = prior.descriptors[7].clone();
    normalized.request_sha256 = prior.request_sha256.clone();
    if normalized != prior {
        return Err(eocv_fault(
            EocvFaultCode::Lineage,
            "A8 changed packet subjects or policy",
        ));
    }
    Ok((current, first))
}

fn build_pbpc_receipt(
    request: &PbpcVerificationRequest,
    a7: PercVerificationReceipt,
    projection: &PbpcProjectionDeclaration,
    comparison: &PbpcComparisonAccount,
) -> Result<PbpcVerificationReceipt, EocvFault> {
    let mut receipt = PbpcVerificationReceipt {
        profile: PBPC_RECEIPT_PROFILE.to_owned(),
        status: if comparison.all_correspondence_matches {
            PBPC_MATCHED_STATUS
        } else {
            PBPC_MISMATCHED_STATUS
        }
        .to_owned(),
        authority: PBPC_AUTHORITY.to_owned(),
        source_snapshot_uuid: request.source_snapshot_uuid.clone(),
        canonical_uuid: request.canonical_uuid.clone(),
        signature_uuid: request.signature_uuid.clone(),
        source_custody_commit: request.source_custody_commit.clone(),
        formation_commit: PBPC_FORMATION_COMMIT.to_owned(),
        formation_bookend_commit: PBPC_FORMATION_BOOKEND_COMMIT.to_owned(),
        a7_implementation_commit: request.a7_implementation_commit.clone(),
        a7_bookend_commit: request.a7_bookend_commit.clone(),
        a7_proof_uuid: request.a7_proof_uuid.clone(),
        request_sha256: request.request_sha256.clone(),
        a7_verification_request_sha256: request.a7_verification_request_sha256.clone(),
        a7_receipt_sha256: a7.receipt_sha256.clone(),
        a7_receipt: a7,
        authority_packet_request_sha256: request.authority_packet_request_sha256.clone(),
        authority_packet_sha256: request.expected_authority_packet_sha256.clone(),
        a8_candidate_uuid: request.expected_candidate_uuid.clone(),
        a8_descriptor_sha256: request.expected_descriptor_sha256.clone(),
        projection_declaration_bytes: request.expected_projection_bytes,
        projection_declaration_raw_sha256: request.expected_projection_raw_sha256.clone(),
        projection_declaration_sha256: projection.projection_sha256.clone(),
        projection_uuid: projection.projection_uuid.clone(),
        opaque_reference: projection.opaque_reference.clone(),
        content_sha256: projection.content_sha256.clone(),
        declared_bytes: projection.declared_bytes,
        confidentiality: projection.confidentiality,
        required_verifier_profile: projection.required_verifier_profile.clone(),
        dependency_ordinal: projection.dependency_ordinal,
        input_class: projection.input_class,
        fixture_only: projection.fixture_only,
        preparation_plan_sha256: projection.preparation_plan_sha256.clone(),
        broker_adapter_profile: projection.broker_adapter_profile.clone(),
        broker_operation_kind: projection.broker_operation_kind.clone(),
        broker_subject: projection.broker_subject.clone(),
        required_input_receipt_profile: projection.required_input_receipt_profile.clone(),
        expected_output_receipt_profile: projection.expected_output_receipt_profile.clone(),
        requires_private_permit: projection.requires_private_permit,
        activation_requested: projection.activation_requested,
        comparison_account: comparison.clone(),
        evidence_references: projection.evidence_references.clone(),
        maximum_attempts: request.maximum_attempts,
        automatic_retry_count: request.automatic_retry_count,
        automatic_cleanup_count: request.automatic_cleanup_count,
        a7_correspondence_receipt_verified: true,
        packet_replayed: true,
        descriptor_correspondence_verified: true,
        projection_declaration_bytes_matched: true,
        comparison_reconstructed: true,
        production_broker_projection_correspondence_proved: comparison.all_correspondence_matches,
        production_authority_claimed: false,
        private_execution_permit_present: false,
        permit_material_authenticated: false,
        permit_dependency_satisfied: false,
        broker_endpoint_resolved: false,
        broker_reachable: false,
        broker_identity_proved: false,
        broker_authority_proved: false,
        broker_session_authenticated: false,
        broker_activation_authorized: false,
        production_broker_projection_present: false,
        live_authorization_admitted: false,
        physical_preparation_authorized: false,
        ready_for_physical_execution: false,
        execution_authorized: false,
        effect_account: TwvEffectAccount::default(),
        receipt_sha256: sha256_bytes(b""),
    };
    receipt.receipt_sha256 = pbpc_receipt_digest(&receipt)?;
    Ok(receipt)
}

fn candidate_origin(input_class: KcvInputClass) -> B1OaprCandidateOrigin {
    if input_class == KcvInputClass::DeterministicFixtureCandidate {
        B1OaprCandidateOrigin::DeterministicFixtureCandidate
    } else {
        B1OaprCandidateOrigin::ExternallySuppliedCandidate
    }
}

fn raw_bound(bytes: &[u8]) -> Result<(), EocvFault> {
    if bytes.is_empty() || bytes.len() > PBPC_MAX_FORM_BYTES {
        return Err(eocv_fault(
            EocvFaultCode::Size,
            "A8 raw projection declaration exceeds bound",
        ));
    }
    Ok(())
}

fn predecessor_fault(_: impl std::fmt::Display) -> EocvFault {
    eocv_fault(
        EocvFaultCode::Predecessor,
        "A8 predecessor verification refused",
    )
}

fn valid_artifact_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.is_ascii()
        && !value.starts_with('/')
        && !value.contains('/')
        && !value.contains('\\')
        && !value.contains(':')
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn bounded<T: Serialize>(value: &T) -> Result<(), EocvFault> {
    if serde_json::to_vec(value)
        .map_err(|_| eocv_fault(EocvFaultCode::MachineForm, "A8 typed encoding differs"))?
        .len()
        > PBPC_MAX_FORM_BYTES
    {
        return Err(eocv_fault(
            EocvFaultCode::Size,
            "A8 typed form exceeds bound",
        ));
    }
    Ok(())
}

fn valid_identifier(value: &str, profile: bool) -> bool {
    if value.is_empty() || value.len() > PBPC_MAX_IDENTIFIER_BYTES || !value.is_ascii() {
        return false;
    }
    let mut slash_count = 0;
    for (index, byte) in value.bytes().enumerate() {
        let allowed = byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || matches!(byte, b'_' | b'-')
            || (profile && slash_count == 1 && byte == b'.')
            || (profile && byte == b'/');
        if !allowed || (index == 0 && !byte.is_ascii_lowercase()) {
            return false;
        }
        if byte == b'/' {
            slash_count += 1;
        }
    }
    (!profile && slash_count == 0) || (profile && slash_count == 1)
}

fn valid_inert_identifier(value: &str, profile: bool) -> bool {
    if !valid_identifier(value, profile) {
        return false;
    }
    let stem = value.split('/').next().unwrap_or(value);
    [
        "localhost",
        "host",
        "server",
        "socket",
        "pipe",
        "endpoint",
        "credential",
        "password",
        "private_key",
        "access_token",
        "bearer",
        "secret",
        "permit_material",
        "lease",
        "command",
        "cmd_exe",
        "powershell",
        "module",
        "loader",
        "environment",
        "env_var",
        "registry",
        "log_control",
    ]
    .into_iter()
    .all(|forbidden| !stem.contains(forbidden))
}

fn valid_content_digest(value: &ContentDigest) -> bool {
    value.algorithm == "sha256"
        && value.value.len() == 64
        && value
            .value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn validate_reference_set(values: &[String]) -> Result<(), EocvFault> {
    let mut unique = BTreeSet::new();
    if values.is_empty()
        || values.len() > PBPC_MAX_EVIDENCE_REFERENCES
        || values
            .iter()
            .any(|value| !valid_inert_identifier(value, false) || !unique.insert(value))
    {
        return Err(eocv_fault(
            EocvFaultCode::Shape,
            "A8 evidence reference set differs",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::de::DeserializeOwned;

    fn fixture() -> PbpcProjectionDeclaration {
        let mut value = PbpcProjectionDeclaration {
            profile: PBPC_DECLARATION_PROFILE.into(),
            projection_uuid: "a8000000-0000-4000-8000-000000000001".into(),
            a7_receipt_sha256: sha256_bytes(b"a7-receipt"),
            preparation_plan_sha256: sha256_bytes(b"preparation-plan"),
            candidate_uuid: "a1000000-0000-4000-8000-000000000008".into(),
            authority_name: "broker_projection".into(),
            artifact_kind: "production_broker_projection_candidate".into(),
            opaque_reference: "fixture_candidate_a8".into(),
            content_sha256: sha256_bytes(b"projection"),
            declared_bytes: 8192,
            confidentiality: B1OaprConfidentiality::PublicMetadata,
            required_verifier_profile: "production-broker-projection-verifier/0.1".into(),
            fixture_only: true,
            dependency_ordinal: 7,
            input_class: KcvInputClass::DeterministicFixtureCandidate,
            broker_adapter_profile: "cantor-production-broker-adapter/0.1".into(),
            broker_operation_kind: "project_preparation_contract".into(),
            broker_subject: "cantor_b1_cdrive_production_preparation_p0".into(),
            required_input_receipt_profile:
                "cantor-b1-private-execution-permit-reference-receipt/0.1".into(),
            expected_output_receipt_profile: PBPC_RECEIPT_PROFILE.into(),
            requires_private_permit: true,
            activation_requested: false,
            evidence_references: vec!["fixture_a8_projection".into()],
            projection_sha256: sha256_bytes(b""),
        };
        value.projection_sha256 = pbpc_declaration_digest(&value).unwrap();
        value
    }

    fn request_fixture() -> PbpcVerificationRequest {
        let digest = sha256_bytes(b"fixture-binding");
        let mut value = PbpcVerificationRequest {
            profile: PBPC_REQUEST_PROFILE.into(),
            source_snapshot_uuid: PBPC_SOURCE_SNAPSHOT_UUID.into(),
            canonical_uuid: PBPC_CANONICAL_UUID.into(),
            signature_uuid: PBPC_SIGNATURE_UUID.into(),
            source_custody_commit: PBPC_SOURCE_CUSTODY_COMMIT.into(),
            source_bookend_commit: PBPC_SOURCE_BOOKEND_COMMIT.into(),
            formation_commit: PBPC_FORMATION_COMMIT.into(),
            formation_bookend_commit: PBPC_FORMATION_BOOKEND_COMMIT.into(),
            a7_implementation_commit: PBPC_A7_IMPLEMENTATION_COMMIT.into(),
            a7_bookend_commit: PBPC_A7_BOOKEND_COMMIT.into(),
            a7_proof_uuid: PBPC_A7_PROOF_UUID.into(),
            a7_verification_request_sha256: digest.clone(),
            expected_a7_receipt_sha256: digest.clone(),
            authority_packet_request_sha256: digest.clone(),
            expected_authority_packet_sha256: digest.clone(),
            expected_candidate_uuid: "a1000000-0000-4000-8000-000000000008".into(),
            expected_descriptor_sha256: digest.clone(),
            expected_projection_uuid: "a8000000-0000-4000-8000-000000000001".into(),
            expected_projection_bytes: 8192,
            expected_projection_raw_sha256: digest.clone(),
            expected_projection_sha256: digest.clone(),
            expected_authority_name: "broker_projection".into(),
            expected_artifact_kind: "production_broker_projection_candidate".into(),
            expected_opaque_reference: "fixture_candidate_a8".into(),
            expected_content_sha256: digest.clone(),
            expected_declared_bytes: 8192,
            expected_confidentiality: B1OaprConfidentiality::PublicMetadata,
            expected_verifier_profile: "production-broker-projection-verifier/0.1".into(),
            expected_fixture_only: true,
            expected_dependency_ordinal: 7,
            input_class: KcvInputClass::DeterministicFixtureCandidate,
            expected_preparation_plan_sha256: digest,
            expected_broker_adapter_profile: "cantor-production-broker-adapter/0.1".into(),
            expected_broker_operation_kind: "project_preparation_contract".into(),
            expected_broker_subject: "cantor_b1_cdrive_production_preparation_p0".into(),
            expected_input_receipt_profile:
                "cantor-b1-private-execution-permit-reference-receipt/0.1".into(),
            expected_output_receipt_profile: PBPC_RECEIPT_PROFILE.into(),
            expected_requires_private_permit: true,
            expected_activation_requested: false,
            evidence_references: vec!["fixture_a8_projection".into()],
            maximum_attempts: 1,
            automatic_retry_count: 0,
            automatic_cleanup_count: 0,
            request_sha256: sha256_bytes(b""),
        };
        value.request_sha256 = pbpc_request_digest(&value).unwrap();
        value
    }

    fn retained<T: DeserializeOwned>(text: &str) -> T {
        serde_json::from_str(text.trim_end_matches('\n')).unwrap()
    }

    fn retained_payload(bytes: &'static [u8]) -> &'static [u8] {
        bytes.strip_suffix(b"\n").unwrap()
    }

    fn rotate_first_field(text: &str) -> String {
        let inner = &text[1..text.len() - 1];
        let comma = inner.find(',').unwrap();
        format!("{{{},{}}}", &inner[comma + 1..], &inner[..comma])
    }

    fn executable_fixture() -> (
        PbpcVerificationRequest,
        PbpcProjectionDeclaration,
        Vec<u8>,
        PercVerificationReceipt,
        crate::EocvVerificationRequest,
        PercVerificationRequest,
    ) {
        let a6_request: crate::EocvVerificationRequest = retained(include_str!(
            "../../../experiments/b1_private_execution_permit_reference_correspondence_p0/implementation_provider_free_evidence/a6_verification_request.json"
        ));
        let a7_request: PercVerificationRequest = retained(include_str!(
            "../../../experiments/b1_private_execution_permit_reference_correspondence_p0/implementation_provider_free_evidence/verification_request.json"
        ));
        let a7_receipt: PercVerificationReceipt = retained(include_str!(
            "../../../experiments/b1_private_execution_permit_reference_correspondence_p0/implementation_provider_free_evidence/receipt.json"
        ));
        let mut projection = fixture();
        projection.a7_receipt_sha256 = a7_receipt.receipt_sha256.clone();
        projection.projection_sha256 = pbpc_declaration_digest(&projection).unwrap();
        let raw_projection = serde_json::to_vec(&projection).unwrap();

        let mut request = request_fixture();
        request.a7_verification_request_sha256 = a7_request.request_sha256.clone();
        request.expected_a7_receipt_sha256 = a7_receipt.receipt_sha256.clone();
        request.expected_candidate_uuid = projection.candidate_uuid.clone();
        request.expected_projection_uuid = projection.projection_uuid.clone();
        request.expected_projection_bytes = raw_projection.len() as u64;
        request.expected_projection_raw_sha256 = sha256_bytes(&raw_projection);
        request.expected_projection_sha256 = projection.projection_sha256.clone();
        request.expected_authority_name = projection.authority_name.clone();
        request.expected_artifact_kind = projection.artifact_kind.clone();
        request.expected_opaque_reference = projection.opaque_reference.clone();
        request.expected_content_sha256 = projection.content_sha256.clone();
        request.expected_declared_bytes = projection.declared_bytes;
        request.expected_confidentiality = projection.confidentiality;
        request.expected_verifier_profile = projection.required_verifier_profile.clone();
        request.expected_fixture_only = projection.fixture_only;
        request.expected_dependency_ordinal = projection.dependency_ordinal;
        request.input_class = projection.input_class;
        request.expected_preparation_plan_sha256 = projection.preparation_plan_sha256.clone();
        request.expected_broker_adapter_profile = projection.broker_adapter_profile.clone();
        request.expected_broker_operation_kind = projection.broker_operation_kind.clone();
        request.expected_broker_subject = projection.broker_subject.clone();
        request.expected_input_receipt_profile = projection.required_input_receipt_profile.clone();
        request.expected_output_receipt_profile =
            projection.expected_output_receipt_profile.clone();
        request.expected_requires_private_permit = projection.requires_private_permit;
        request.expected_activation_requested = projection.activation_requested;
        request.evidence_references = projection.evidence_references.clone();

        let prior =
            reconstruct_a7_packet_request(&a7_request, &a6_request.authority_packet_request)
                .unwrap();
        let mut descriptor = B1OaprCandidateDescriptor {
            ordinal: 8,
            candidate_uuid: request.expected_candidate_uuid.clone(),
            authority_name: request.expected_authority_name.clone(),
            artifact_kind: request.expected_artifact_kind.clone(),
            origin: candidate_origin(request.input_class),
            opaque_reference: request.expected_opaque_reference.clone(),
            content_sha256: request.expected_content_sha256.clone(),
            declared_bytes: request.expected_declared_bytes,
            confidentiality: request.expected_confidentiality,
            required_verifier_profile: request.expected_verifier_profile.clone(),
            fixture_only: request.expected_fixture_only,
            dependency_ordinal: Some(request.expected_dependency_ordinal),
            descriptor_sha256: sha256_bytes(b""),
        };
        descriptor.descriptor_sha256 = b1oapr_descriptor_digest(&descriptor).unwrap();
        request.expected_descriptor_sha256 = descriptor.descriptor_sha256.clone();
        let mut current = prior;
        current.descriptors[7] = descriptor;
        current.request_sha256 = b1oapr_request_digest(&current).unwrap();
        request.authority_packet_request_sha256 = current.request_sha256.clone();
        request.expected_authority_packet_sha256 =
            compile_b1oapr_packet(&current).unwrap().packet_sha256;
        request.request_sha256 = pbpc_request_digest(&request).unwrap();
        (
            request,
            projection,
            raw_projection,
            a7_receipt,
            a6_request,
            a7_request,
        )
    }

    #[test]
    fn canonical_declaration_has_exact_order_and_round_trips() {
        let value = fixture();
        let text = to_pbpc_declaration_machine_form(&value).unwrap();
        assert_eq!(from_pbpc_declaration_machine_form(&text).unwrap(), value);
        let keys = serde_json::from_str::<serde_json::Value>(&text)
            .unwrap()
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(keys.len(), 24);
        assert!(text.starts_with("{\"profile\":"));
        assert!(text.ends_with('}'));
    }

    #[test]
    fn every_single_comparison_mismatch_is_ordered() {
        for index in 0..26 {
            let mut flags = [true; 26];
            flags[index] = false;
            let account = pbpc_comparison_from_flags(flags);
            assert!(!account.all_correspondence_matches);
            assert_eq!(account.mismatch_reasons, vec![PBPC_MISMATCH_REASONS[index]]);
            validate_pbpc_comparison_account(&account).unwrap();
        }
    }

    #[test]
    fn all_mismatch_and_bounded_subset_accounts_are_exact() {
        let all = pbpc_comparison_from_flags([false; 26]);
        assert_eq!(all.mismatch_reasons, PBPC_MISMATCH_REASONS);
        assert!(!all.all_correspondence_matches);
        validate_pbpc_comparison_account(&all).unwrap();
        for mask in 0u16..4096 {
            let mut flags = [true; 26];
            for (index, flag) in flags.iter_mut().take(12).enumerate() {
                *flag = mask & (1 << index) == 0;
            }
            validate_pbpc_comparison_account(&pbpc_comparison_from_flags(flags)).unwrap();
        }
    }

    #[test]
    fn matching_metadata_remains_dependency_without_activation() {
        let value = fixture();
        let account =
            compare_pbpc_projection_metadata(&value, &value, true, true, true, true).unwrap();
        assert!(account.all_correspondence_matches);
        assert!(value.requires_private_permit);
        assert!(!value.activation_requested);
    }

    #[test]
    fn endpoint_and_capability_shapes_refuse_without_echo() {
        for hostile in [
            "https://broker.example",
            "broker.example",
            "localhost",
            "server:443",
            "server_443",
            "..\\broker",
            "\\\\.\\pipe\\broker",
            "named_pipe",
            "socket_handle",
            "run broker",
            "$credential",
            "credential_handle",
            "private_key_material",
            "permit_material",
            "lease_identifier",
            "environment_variable",
            "cmd_exe",
            "log_control",
            "module::load",
        ] {
            let mut value = fixture();
            value.broker_subject = hostile.into();
            value.projection_sha256 = pbpc_declaration_digest(&value).unwrap();
            let error = validate_pbpc_declaration(&value).unwrap_err();
            assert!(!error.message.contains(hostile));
        }
        for hostile in [
            "localhost/0.1",
            "socket-loader/0.1",
            "environment-module/0.1",
            "credential-adapter/0.1",
        ] {
            let mut value = fixture();
            value.broker_adapter_profile = hostile.into();
            value.projection_sha256 = pbpc_declaration_digest(&value).unwrap();
            let error = validate_pbpc_declaration(&value).unwrap_err();
            assert!(!error.message.contains(hostile));
        }
        for hostile in [
            "endpoint_handle",
            "secret_value",
            "access_token",
            "log_control",
        ] {
            let mut value = fixture();
            value.evidence_references = vec![hostile.into()];
            value.projection_sha256 = pbpc_declaration_digest(&value).unwrap();
            let error = validate_pbpc_declaration(&value).unwrap_err();
            assert!(!error.message.contains(hostile));
        }
    }

    #[test]
    fn activation_and_missing_dependency_refuse() {
        let mut activation = fixture();
        activation.activation_requested = true;
        activation.projection_sha256 = pbpc_declaration_digest(&activation).unwrap();
        assert!(validate_pbpc_declaration(&activation).is_err());
        let mut dependency = fixture();
        dependency.requires_private_permit = false;
        dependency.projection_sha256 = pbpc_declaration_digest(&dependency).unwrap();
        assert!(validate_pbpc_declaration(&dependency).is_err());
    }

    #[test]
    fn forged_comparison_summary_refuses() {
        let mut account = pbpc_comparison_from_flags([true; 26]);
        account
            .mismatch_reasons
            .push(PbpcMismatchReason::PacketMismatch);
        assert!(validate_pbpc_comparison_account(&account).is_err());
    }

    #[test]
    fn frozen_carrier_shapes_domains_and_nonauthorizing_statuses_are_exact() {
        assert_eq!(
            (PBPC_REQUEST_FIELDS[0], PBPC_REQUEST_FIELDS[43]),
            ("profile", "request_sha256")
        );
        assert_eq!(
            (PBPC_RECEIPT_FIELDS[0], PBPC_RECEIPT_FIELDS[67]),
            ("profile", "receipt_sha256")
        );
        assert_eq!(
            (PBPC_EVIDENCE_FIELDS[0], PBPC_EVIDENCE_FIELDS[15]),
            ("profile", "manifest_sha256")
        );
        assert_eq!(
            PBPC_REQUEST_FIELDS
                .into_iter()
                .collect::<BTreeSet<_>>()
                .len(),
            44
        );
        assert_eq!(
            PBPC_RECEIPT_FIELDS
                .into_iter()
                .collect::<BTreeSet<_>>()
                .len(),
            68
        );
        assert_eq!(
            PBPC_EVIDENCE_FIELDS
                .into_iter()
                .collect::<BTreeSet<_>>()
                .len(),
            16
        );
        assert!(PBPC_MATCHED_STATUS.ends_with("_execution_unresolved"));
        assert!(PBPC_MISMATCHED_STATUS.ends_with("_execution_unresolved"));
        assert_eq!(
            PBPC_AUTHORITY,
            "supplied_production_broker_projection_correspondence_only"
        );
        assert_ne!(PBPC_DECLARATION_DOMAIN, PBPC_REQUEST_DOMAIN);
        assert_ne!(PBPC_REQUEST_DOMAIN, PBPC_RECEIPT_DOMAIN);
        assert_ne!(PBPC_RECEIPT_DOMAIN, PBPC_EVIDENCE_DOMAIN);
    }

    #[test]
    fn request_is_canonical_bound_inactive_and_refuses_hazards_without_echo() {
        let value = request_fixture();
        let text = to_pbpc_request_machine_form(&value).unwrap();
        assert_eq!(from_pbpc_request_machine_form(&text).unwrap(), value);
        assert!(text.starts_with("{\"profile\":"));

        let mut activated = value.clone();
        activated.expected_activation_requested = true;
        activated.request_sha256 = pbpc_request_digest(&activated).unwrap();
        assert!(validate_pbpc_request(&activated).is_err());

        let mut repeated = value.clone();
        repeated
            .evidence_references
            .push(repeated.evidence_references[0].clone());
        repeated.request_sha256 = pbpc_request_digest(&repeated).unwrap();
        assert!(validate_pbpc_request(&repeated).is_err());

        let hostile = "https://broker.example";
        let mut endpoint = value;
        endpoint.expected_broker_subject = hostile.into();
        endpoint.request_sha256 = pbpc_request_digest(&endpoint).unwrap();
        let error = validate_pbpc_request(&endpoint).unwrap_err();
        assert!(!error.message.contains(hostile));
    }

    #[test]
    fn strict_canonical_framing_refuses_ambiguity_and_resource_excess() {
        let declaration = fixture();
        let text = to_pbpc_declaration_machine_form(&declaration).unwrap();
        let duplicate = text.replacen('{', "{\"profile\":\"duplicate/0.1\",", 1);
        let unknown = text.replacen('{', "{\"unknown\":true,", 1);
        let escaped = text.replacen("/0.1", "\\/0.1", 1);
        for hostile in [
            format!("\u{feff}{text}"),
            format!(" {text}"),
            format!("{text} "),
            format!("{text}\n"),
            format!("{text}\r\n"),
            format!("{text}{text}"),
            rotate_first_field(&text),
            duplicate,
            unknown,
            escaped,
        ] {
            assert!(from_pbpc_declaration_machine_form(&hostile).is_err());
        }
        assert!(from_pbpc_declaration_machine_form("{}").is_err());
        assert!(from_pbpc_declaration_machine_form(&"x".repeat(PBPC_MAX_FORM_BYTES + 1)).is_err());

        let request = request_fixture();
        let request_text = to_pbpc_request_machine_form(&request).unwrap();
        assert!(from_pbpc_request_machine_form(&rotate_first_field(&request_text)).is_err());
        assert!(from_pbpc_request_machine_form(&format!("{request_text}\n")).is_err());
        assert!(
            from_pbpc_request_machine_form(&request_text.replacen(
                '{',
                "{\"profile\":\"duplicate/0.1\",",
                1
            ))
            .is_err()
        );
    }

    #[test]
    fn ordinal_eight_packet_reconstruction_preserves_every_other_coordinate() {
        let (request, _, _, _, a6_request, a7_request) = executable_fixture();
        let prior =
            reconstruct_a7_packet_request(&a7_request, &a6_request.authority_packet_request)
                .unwrap();
        let (current, first) = reconstruct_pbpc_packet(&request, &a7_request, &a6_request).unwrap();
        let second = compile_b1oapr_packet(&current).unwrap();
        assert_eq!(first, second);
        assert_eq!(current.descriptors[..7], prior.descriptors[..7]);
        assert_eq!(current.descriptors[8..], prior.descriptors[8..]);
        assert_eq!(current.descriptors[7].ordinal, 8);
        assert_eq!(current.descriptors[7].dependency_ordinal, Some(7));
    }

    #[test]
    fn receipt_is_canonical_nonauthorizing_and_restart_tamper_refuses() {
        let (request, projection, _, a7_receipt, _, _) = executable_fixture();
        let comparison =
            compare_pbpc_projection_metadata(&projection, &projection, true, true, true, true)
                .unwrap();
        let receipt = build_pbpc_receipt(&request, a7_receipt, &projection, &comparison).unwrap();
        validate_pbpc_receipt_fields(&receipt).unwrap();
        let text = serde_json::to_string(&receipt).unwrap();
        let decoded: PbpcVerificationReceipt = parse_eocv_canonical(&text).unwrap();
        validate_pbpc_receipt_fields(&decoded).unwrap();
        assert_eq!(decoded, receipt);
        assert!(!receipt.production_authority_claimed);
        assert!(!receipt.broker_endpoint_resolved);
        assert!(!receipt.execution_authorized);
        assert_eq!(receipt.effect_account, TwvEffectAccount::default());

        let mut promoted = receipt.clone();
        promoted.broker_activation_authorized = true;
        promoted.receipt_sha256 = pbpc_receipt_digest(&promoted).unwrap();
        assert!(validate_pbpc_receipt_fields(&promoted).is_err());

        let mut restarted = receipt;
        restarted.receipt_sha256 = sha256_bytes(b"restart-tamper");
        assert_eq!(
            validate_pbpc_receipt_fields(&restarted).unwrap_err().code,
            EocvFaultCode::Digest
        );
    }

    #[test]
    fn evidence_manifest_is_bounded_canonical_and_path_safe() {
        let artifacts = (0..33)
            .map(|index| PbpcEvidenceArtifact {
                path: format!("retained_artifact_{index:02}.json"),
                bytes: 1,
                sha256: sha256_bytes(&[index]),
            })
            .collect::<Vec<_>>();
        let binding = sha256_bytes(b"retained-binding");
        let mut manifest = PbpcEvidenceManifest {
            profile: PBPC_EVIDENCE_PROFILE.to_owned(),
            manifest_uuid: "a8000000-0000-4000-8000-000000000002".to_owned(),
            source_snapshot_uuid: PBPC_SOURCE_SNAPSHOT_UUID.to_owned(),
            canonical_uuid: PBPC_CANONICAL_UUID.to_owned(),
            artifacts,
            artifact_count: 33,
            total_artifact_bytes: 33,
            retained_authority_packet_sha256: binding.clone(),
            retained_a7_receipt_sha256: binding.clone(),
            retained_projection_declaration_sha256: binding.clone(),
            retained_receipt_sha256: binding,
            deterministic_replay_count: 2,
            required_fresh_process_replay_count: 2,
            byte_identical: true,
            effect_count: 0,
            manifest_sha256: sha256_bytes(b""),
        };
        manifest.manifest_sha256 = pbpc_evidence_manifest_digest(&manifest).unwrap();
        let text = to_pbpc_evidence_manifest_machine_form(&manifest).unwrap();
        assert_eq!(
            from_pbpc_evidence_manifest_machine_form(&text).unwrap(),
            manifest
        );

        let mut escaped = manifest.clone();
        escaped.artifacts[0].path = "../escape.json".to_owned();
        escaped.manifest_sha256 = pbpc_evidence_manifest_digest(&escaped).unwrap();
        assert!(validate_pbpc_evidence_manifest(&escaped).is_err());

        let mut duplicate = manifest;
        duplicate.artifacts[1].path = duplicate.artifacts[0].path.clone();
        duplicate.manifest_sha256 = pbpc_evidence_manifest_digest(&duplicate).unwrap();
        assert!(validate_pbpc_evidence_manifest(&duplicate).is_err());
    }

    #[test]
    fn full_a7_replay_produces_byte_identical_a8_receipt_and_refuses_tamper() {
        let predecessor_request: B1OaprRequest = retained(include_str!(
            "../../../experiments/b1_private_execution_permit_reference_correspondence_p0/implementation_provider_free_evidence/predecessor_request.json"
        ));
        let predecessor_packet: B1OaprPacket = retained(include_str!(
            "../../../experiments/b1_private_execution_permit_reference_correspondence_p0/implementation_provider_free_evidence/predecessor_packet.json"
        ));
        let predecessor_verification: crate::B1OaprVerification = retained(include_str!(
            "../../../experiments/b1_private_execution_permit_reference_correspondence_p0/implementation_provider_free_evidence/predecessor_verification.json"
        ));
        let a1_envelope: crate::BpvPolicyEnvelope = retained(include_str!(
            "../../../experiments/b1_private_execution_permit_reference_correspondence_p0/implementation_provider_free_evidence/a1_policy_envelope.json"
        ));
        let a1_request: crate::BpvVerificationRequest = retained(include_str!(
            "../../../experiments/b1_private_execution_permit_reference_correspondence_p0/implementation_provider_free_evidence/a1_verification_request.json"
        ));
        let a1_receipt: crate::BpvVerificationReceipt = retained(include_str!(
            "../../../experiments/b1_private_execution_permit_reference_correspondence_p0/implementation_provider_free_evidence/a1_receipt.json"
        ));
        let a2_attestation: crate::KcvCustodyAttestation = retained(include_str!(
            "../../../experiments/b1_private_execution_permit_reference_correspondence_p0/implementation_provider_free_evidence/custody_attestation.json"
        ));
        let a2_request: crate::KcvVerificationRequest = retained(include_str!(
            "../../../experiments/b1_private_execution_permit_reference_correspondence_p0/implementation_provider_free_evidence/a2_verification_request.json"
        ));
        let a2_receipt: crate::KcvVerificationReceipt = retained(include_str!(
            "../../../experiments/b1_private_execution_permit_reference_correspondence_p0/implementation_provider_free_evidence/a2_receipt.json"
        ));
        let a3_request: crate::KrvVerificationRequest = retained(include_str!(
            "../../../experiments/b1_private_execution_permit_reference_correspondence_p0/implementation_provider_free_evidence/a3_verification_request.json"
        ));
        let a3_receipt: crate::KrvVerificationReceipt = retained(include_str!(
            "../../../experiments/b1_private_execution_permit_reference_correspondence_p0/implementation_provider_free_evidence/a3_receipt.json"
        ));
        let a4_request: crate::TwvVerificationRequest = retained(include_str!(
            "../../../experiments/b1_private_execution_permit_reference_correspondence_p0/implementation_provider_free_evidence/a4_verification_request.json"
        ));
        let a4_receipt: crate::TwvVerificationReceipt = retained(include_str!(
            "../../../experiments/b1_private_execution_permit_reference_correspondence_p0/implementation_provider_free_evidence/a4_receipt.json"
        ));
        let policy: crate::B1CDriveOperatorDecisionPolicy = retained(include_str!(
            "../../../experiments/b1_private_execution_permit_reference_correspondence_p0/implementation_provider_free_evidence/operator_decision_policy.json"
        ));
        let legacy_request: crate::B1CDriveOperatorDecisionRequest = retained(include_str!(
            "../../../experiments/b1_private_execution_permit_reference_correspondence_p0/implementation_provider_free_evidence/operator_decision_request.json"
        ));
        let a5_request: crate::OdcvVerificationRequest = retained(include_str!(
            "../../../experiments/b1_private_execution_permit_reference_correspondence_p0/implementation_provider_free_evidence/a5_verification_request.json"
        ));
        let a5_receipt: crate::OdcvVerificationReceipt = retained(include_str!(
            "../../../experiments/b1_private_execution_permit_reference_correspondence_p0/implementation_provider_free_evidence/a5_receipt.json"
        ));
        let (request, _, raw_projection, a7_receipt, a6_request, a7_request) = executable_fixture();
        let a6_receipt: crate::EocvVerificationReceipt = retained(include_str!(
            "../../../experiments/b1_private_execution_permit_reference_correspondence_p0/implementation_provider_free_evidence/a6_receipt.json"
        ));
        let a6_predecessor = crate::EocvPredecessor {
            upstream: crate::OdcvPredecessor {
                upstream: crate::TwvPredecessor {
                    request: &predecessor_request,
                    packet: &predecessor_packet,
                    verification: &predecessor_verification,
                    a1_envelope: &a1_envelope,
                    raw_a1_envelope: retained_payload(include_bytes!(
                        "../../../experiments/b1_private_execution_permit_reference_correspondence_p0/implementation_provider_free_evidence/a1_policy_envelope.json"
                    )),
                    a1_request: &a1_request,
                    a1_receipt: &a1_receipt,
                    a2_attestation: &a2_attestation,
                    raw_a2_attestation: retained_payload(include_bytes!(
                        "../../../experiments/b1_private_execution_permit_reference_correspondence_p0/implementation_provider_free_evidence/custody_attestation.json"
                    )),
                    a2_request: &a2_request,
                    a2_receipt: &a2_receipt,
                    raw_a3_snapshot: retained_payload(include_bytes!(
                        "../../../experiments/b1_private_execution_permit_reference_correspondence_p0/implementation_provider_free_evidence/revocation_snapshot.json"
                    )),
                    a3_request: &a3_request,
                    a3_receipt: &a3_receipt,
                },
                raw_a4_witness: retained_payload(include_bytes!(
                    "../../../experiments/b1_private_execution_permit_reference_correspondence_p0/implementation_provider_free_evidence/time_witness_receipt.json"
                )),
                a4_request: &a4_request,
                a4_receipt: &a4_receipt,
            },
            a5_policy: &policy,
            a5_legacy_request: &legacy_request,
            raw_a5_envelope: retained_payload(include_bytes!(
                "../../../experiments/b1_private_execution_permit_reference_correspondence_p0/implementation_provider_free_evidence/operator_decision_envelope.json"
            )),
            a5_request: &a5_request,
            a5_receipt: &a5_receipt,
        };
        let predecessor = PbpcPredecessor {
            a7_request: &a7_request,
            a7_predecessor: PercPredecessor {
                a6_request: &a6_request,
                a6_predecessor,
                raw_plan_request: retained_payload(include_bytes!(
                    "../../../experiments/b1_private_execution_permit_reference_correspondence_p0/implementation_provider_free_evidence/preparation_plan_request.json"
                )),
                raw_plan: retained_payload(include_bytes!(
                    "../../../experiments/b1_private_execution_permit_reference_correspondence_p0/implementation_provider_free_evidence/preparation_plan.json"
                )),
                raw_observation_bundle: retained_payload(include_bytes!(
                    "../../../experiments/b1_private_execution_permit_reference_correspondence_p0/implementation_provider_free_evidence/observation_bundle.json"
                )),
                a6_receipt: &a6_receipt,
            },
            raw_a7_envelope: retained_payload(include_bytes!(
                "../../../experiments/b1_private_execution_permit_reference_correspondence_p0/implementation_provider_free_evidence/permit_reference_envelope.json"
            )),
            a7_receipt: &a7_receipt,
        };
        let first =
            verify_pbpc_projection_correspondence(&request, &predecessor, &raw_projection).unwrap();
        let second =
            verify_pbpc_projection_correspondence(&request, &predecessor, &raw_projection).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            to_pbpc_receipt_machine_form(&request, &predecessor, &raw_projection, &first).unwrap(),
            to_pbpc_receipt_machine_form(&request, &predecessor, &raw_projection, &second).unwrap()
        );
        validate_pbpc_receipt(&request, &predecessor, &raw_projection, &first).unwrap();
        let receipt_text =
            to_pbpc_receipt_machine_form(&request, &predecessor, &raw_projection, &first).unwrap();
        assert_eq!(
            from_pbpc_receipt_machine_form(&request, &predecessor, &raw_projection, &receipt_text,)
                .unwrap(),
            first
        );

        let mut mismatching_request = request.clone();
        mismatching_request.evidence_references = vec!["alternate_a8_evidence".to_owned()];
        mismatching_request.request_sha256 = pbpc_request_digest(&mismatching_request).unwrap();
        let mismatch = verify_pbpc_projection_correspondence(
            &mismatching_request,
            &predecessor,
            &raw_projection,
        )
        .unwrap();
        assert_eq!(mismatch.status, PBPC_MISMATCHED_STATUS);
        assert_eq!(
            mismatch.comparison_account.mismatch_reasons,
            vec![PbpcMismatchReason::EvidenceReferencesMismatch]
        );
        assert!(!mismatch.production_broker_projection_correspondence_proved);
        assert!(!mismatch.broker_activation_authorized);

        let mut tampered = raw_projection;
        tampered.push(b' ');
        assert_eq!(
            verify_pbpc_projection_correspondence(&request, &predecessor, &tampered)
                .unwrap_err()
                .code,
            EocvFaultCode::RawBytes
        );
    }
}
