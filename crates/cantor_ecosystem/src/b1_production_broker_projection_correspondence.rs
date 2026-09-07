//! A8 supplied public logical broker-projection correspondence forms.
//!
//! This partial core has no endpoint resolver, dynamic loader, broker client,
//! credential input, permit consumer, writer, or effect interface.
use crate::{
    B1OaprConfidentiality, EocvFault, EocvFaultCode, KcvInputClass, PercVerificationReceipt,
    TwvEffectAccount, eocv_domain_digest, eocv_fault, parse_eocv_canonical, valid_eocv_uuid,
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
    pub projection_raw_bytes_match: bool,
    pub projection_self_digest_matches: bool,
    pub projection_uuid_matches: bool,
    pub candidate_uuid_matches: bool,
    pub authority_name_matches: bool,
    pub artifact_kind_matches: bool,
    pub opaque_reference_matches: bool,
    pub content_sha256_matches: bool,
    pub declared_bytes_matches: bool,
    pub confidentiality_matches: bool,
    pub verifier_profile_matches: bool,
    pub fixture_flag_matches: bool,
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
        projection_raw_bytes_match: flags[3],
        projection_self_digest_matches: flags[4],
        projection_uuid_matches: flags[5],
        candidate_uuid_matches: flags[6],
        authority_name_matches: flags[7],
        artifact_kind_matches: flags[8],
        opaque_reference_matches: flags[9],
        content_sha256_matches: flags[10],
        declared_bytes_matches: flags[11],
        confidentiality_matches: flags[12],
        verifier_profile_matches: flags[13],
        fixture_flag_matches: flags[14],
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
        account.projection_raw_bytes_match,
        account.projection_self_digest_matches,
        account.projection_uuid_matches,
        account.candidate_uuid_matches,
        account.authority_name_matches,
        account.artifact_kind_matches,
        account.opaque_reference_matches,
        account.content_sha256_matches,
        account.declared_bytes_matches,
        account.confidentiality_matches,
        account.verifier_profile_matches,
        account.fixture_flag_matches,
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
        if !valid_identifier(value, false) {
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
        if !valid_identifier(value, true) {
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
        .any(|value| !valid_identifier(value, false) || !unique.insert(value))
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
            || matches!(byte, b'_' | b'-' | b'.')
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

#[cfg(test)]
mod tests {
    use super::*;

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
            "server:443",
            "..\\broker",
            "\\\\.\\pipe\\broker",
            "run broker",
            "$credential",
            "module::load",
        ] {
            let mut value = fixture();
            value.broker_adapter_profile = hostile.into();
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
}
