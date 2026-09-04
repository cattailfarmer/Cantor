//! A7 supplied private-execution-permit reference correspondence over full A6.
//!
//! This module compares bounded public metadata. It never resolves the opaque
//! reference, reads permit material, authenticates an issuer, or grants effects.
use crate::{
    B1OaprCandidateDescriptor, B1OaprCandidateOrigin, B1OaprConfidentiality, B1OaprRequest,
    EocvFault, EocvFaultCode, EocvPredecessor, EocvVerificationReceipt, EocvVerificationRequest,
    KcvInputClass, TwvEffectAccount, b1oapr_descriptor_digest, b1oapr_request_digest,
    compile_b1oapr_packet, eocv_domain_digest, eocv_fault, parse_eocv_canonical, valid_eocv_uuid,
    verify_eocv_expected_observation,
};
use cantor_core::{ContentDigest, sha256_bytes};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const PERC_ENVELOPE_PROFILE: &str = "cantor-b1-private-execution-permit-reference-envelope/0.1";
pub const PERC_REQUEST_PROFILE: &str = "cantor-b1-private-execution-permit-reference-request/0.1";
pub const PERC_RECEIPT_PROFILE: &str = "cantor-b1-private-execution-permit-reference-receipt/0.1";
pub const PERC_EVIDENCE_PROFILE: &str = "cantor-b1-private-execution-permit-reference-evidence/0.1";
pub const PERC_SOURCE_SNAPSHOT_UUID: &str = "cdbd323b-c260-415e-9473-d32604242e54";
pub const PERC_CANONICAL_UUID: &str = "35543ac8-934f-4e0d-9549-8930f0af7e92";
pub const PERC_SIGNATURE_UUID: &str = "31d86973-d52b-4c8d-9711-b36ed85f4f18";
pub const PERC_SOURCE_CUSTODY_COMMIT: &str = "15d3798e5c7e0a2c3263f76f435bc8a7ee9c59f2";
pub const PERC_SOURCE_BOOKEND_COMMIT: &str = "fa031dcfc47cf0435e32975949621148006a8f19";
pub const PERC_FORMATION_COMMIT: &str = "421294db8482413fe468710c0e0924ec09982774";
pub const PERC_FORMATION_BOOKEND_COMMIT: &str = "f49c259084405269368fd5e3bfae667f00574e40";
pub const PERC_A6_IMPLEMENTATION_COMMIT: &str = "cd7258ad0275722aba94caa541022c6d593a9fe8";
pub const PERC_A6_BOOKEND_COMMIT: &str = "77d42ee5169cde768126681b235e385cf3be558b";
pub const PERC_A6_PROOF_UUID: &str = "17d6a930-d45e-4c98-98be-b7b87a190212";
pub const PERC_MATCHED_STATUS: &str =
    "supplied_private_permit_reference_correspondence_matched_execution_unresolved";
pub const PERC_MISMATCHED_STATUS: &str =
    "supplied_private_permit_reference_correspondence_mismatched_execution_unresolved";
pub const PERC_AUTHORITY: &str = "supplied_private_permit_reference_correspondence_only";
pub const PERC_MAX_FORM_BYTES: usize = 1_048_576;
pub const PERC_MAX_EVIDENCE_BYTES: u64 = 16_777_216;
pub const PERC_MAX_EVIDENCE_REFERENCES: usize = 48;
const PERC_MAX_REFERENCE_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PercMismatchReason {
    A6ReceiptMismatch,
    PacketMismatch,
    DescriptorMismatch,
    EnvelopeRawBytesMismatch,
    EnvelopeSelfDigestMismatch,
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
    EvidenceReferencesMismatch,
}

pub const PERC_MISMATCH_REASONS: [PercMismatchReason; 17] = [
    PercMismatchReason::A6ReceiptMismatch,
    PercMismatchReason::PacketMismatch,
    PercMismatchReason::DescriptorMismatch,
    PercMismatchReason::EnvelopeRawBytesMismatch,
    PercMismatchReason::EnvelopeSelfDigestMismatch,
    PercMismatchReason::CandidateUuidMismatch,
    PercMismatchReason::AuthorityNameMismatch,
    PercMismatchReason::ArtifactKindMismatch,
    PercMismatchReason::OpaqueReferenceMismatch,
    PercMismatchReason::ContentSha256Mismatch,
    PercMismatchReason::DeclaredBytesMismatch,
    PercMismatchReason::ConfidentialityMismatch,
    PercMismatchReason::VerifierProfileMismatch,
    PercMismatchReason::FixtureFlagMismatch,
    PercMismatchReason::DependencyOrdinalMismatch,
    PercMismatchReason::InputClassMismatch,
    PercMismatchReason::EvidenceReferencesMismatch,
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PercReferenceEnvelope {
    pub profile: String,
    pub envelope_uuid: String,
    pub a6_receipt_sha256: ContentDigest,
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
    pub evidence_references: Vec<String>,
    pub envelope_sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PercEvidenceArtifact {
    pub path: String,
    pub bytes: u64,
    pub sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PercEvidenceManifest {
    pub profile: String,
    pub manifest_uuid: String,
    pub source_snapshot_uuid: String,
    pub canonical_uuid: String,
    pub artifacts: Vec<PercEvidenceArtifact>,
    pub artifact_count: u8,
    pub total_artifact_bytes: u64,
    pub retained_authority_packet_sha256: ContentDigest,
    pub retained_a6_receipt_sha256: ContentDigest,
    pub retained_reference_envelope_sha256: ContentDigest,
    pub retained_receipt_sha256: ContentDigest,
    pub deterministic_replay_count: u8,
    pub required_fresh_process_replay_count: u8,
    pub byte_identical: bool,
    pub effect_count: u8,
    pub manifest_sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PercVerificationRequest {
    pub profile: String,
    pub source_snapshot_uuid: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub source_custody_commit: String,
    pub source_bookend_commit: String,
    pub a6_implementation_commit: String,
    pub a6_bookend_commit: String,
    pub a6_proof_uuid: String,
    pub a6_verification_request_sha256: ContentDigest,
    pub expected_a6_receipt_sha256: ContentDigest,
    pub authority_packet_request_sha256: ContentDigest,
    pub expected_authority_packet_sha256: ContentDigest,
    pub expected_candidate_uuid: String,
    pub expected_descriptor_sha256: ContentDigest,
    pub expected_envelope_uuid: String,
    pub expected_envelope_bytes: u64,
    pub expected_envelope_raw_sha256: ContentDigest,
    pub expected_envelope_sha256: ContentDigest,
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
    pub evidence_references: Vec<String>,
    pub maximum_attempts: u8,
    pub automatic_retry_count: u8,
    pub automatic_cleanup_count: u8,
    pub request_sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PercComparisonAccount {
    pub a6_receipt_matches: bool,
    pub packet_matches: bool,
    pub descriptor_matches: bool,
    pub envelope_raw_bytes_match: bool,
    pub envelope_self_digest_matches: bool,
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
    pub evidence_references_match: bool,
    pub all_correspondence_matches: bool,
    pub mismatch_reasons: Vec<PercMismatchReason>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PercVerificationReceipt {
    pub profile: String,
    pub status: String,
    pub authority: String,
    pub source_snapshot_uuid: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub source_custody_commit: String,
    pub formation_commit: String,
    pub formation_bookend_commit: String,
    pub a6_implementation_commit: String,
    pub a6_bookend_commit: String,
    pub a6_proof_uuid: String,
    pub request_sha256: ContentDigest,
    pub a6_verification_request_sha256: ContentDigest,
    pub a6_receipt_sha256: ContentDigest,
    pub a6_receipt: EocvVerificationReceipt,
    pub authority_packet_request_sha256: ContentDigest,
    pub authority_packet_sha256: ContentDigest,
    pub a7_candidate_uuid: String,
    pub a7_descriptor_sha256: ContentDigest,
    pub reference_envelope_bytes: u64,
    pub reference_envelope_raw_sha256: ContentDigest,
    pub reference_envelope_sha256: ContentDigest,
    pub envelope_uuid: String,
    pub opaque_reference: String,
    pub content_sha256: ContentDigest,
    pub declared_bytes: u64,
    pub confidentiality: B1OaprConfidentiality,
    pub required_verifier_profile: String,
    pub dependency_ordinal: u8,
    pub input_class: KcvInputClass,
    pub fixture_only: bool,
    pub correspondence_account: PercComparisonAccount,
    pub evidence_references: Vec<String>,
    pub maximum_attempts: u8,
    pub automatic_retry_count: u8,
    pub automatic_cleanup_count: u8,
    pub a6_correspondence_receipt_verified: bool,
    pub packet_replayed: bool,
    pub descriptor_correspondence_verified: bool,
    pub reference_envelope_bytes_matched: bool,
    pub comparison_reconstructed: bool,
    pub private_execution_permit_reference_correspondence_proved: bool,
    pub production_authority_claimed: bool,
    pub private_execution_permit_present: bool,
    pub permit_material_authenticated: bool,
    pub permit_signer_identity_proved: bool,
    pub permit_signer_authority_proved: bool,
    pub permit_scope_proved: bool,
    pub permit_subject_proved: bool,
    pub permit_freshness_proved: bool,
    pub permit_nonexpired: bool,
    pub permit_revocation_checked: bool,
    pub permit_single_use_proved: bool,
    pub permit_unconsumed: bool,
    pub permit_consumed: bool,
    pub live_authorization_admitted: bool,
    pub production_broker_projection_present: bool,
    pub physical_preparation_authorized: bool,
    pub ready_for_physical_execution: bool,
    pub execution_authorized: bool,
    pub effect_account: TwvEffectAccount,
    pub receipt_sha256: ContentDigest,
}

pub struct PercPredecessor<'a> {
    pub a6_request: &'a EocvVerificationRequest,
    pub a6_predecessor: EocvPredecessor<'a>,
    pub raw_plan_request: &'a [u8],
    pub raw_plan: &'a [u8],
    pub raw_observation_bundle: &'a [u8],
    pub a6_receipt: &'a EocvVerificationReceipt,
}

/// Compare only caller-supplied envelope fields. The packet/raw/self-digest
/// flags deliberately remain false until the full verifier establishes them.
pub fn compare_perc_reference_metadata(
    request: &PercVerificationRequest,
    envelope: &PercReferenceEnvelope,
) -> PercComparisonAccount {
    comparison_from_flags([
        envelope.a6_receipt_sha256 == request.expected_a6_receipt_sha256,
        false,
        false,
        false,
        false,
        envelope.candidate_uuid == request.expected_candidate_uuid,
        envelope.authority_name == request.expected_authority_name,
        envelope.artifact_kind == request.expected_artifact_kind,
        envelope.opaque_reference == request.expected_opaque_reference,
        envelope.content_sha256 == request.expected_content_sha256,
        envelope.declared_bytes == request.expected_declared_bytes,
        envelope.confidentiality == request.expected_confidentiality,
        envelope.required_verifier_profile == request.expected_verifier_profile,
        envelope.fixture_only == request.expected_fixture_only,
        envelope.dependency_ordinal == request.expected_dependency_ordinal,
        envelope.input_class == request.input_class,
        envelope.evidence_references == request.evidence_references,
    ])
}

pub fn validate_perc_comparison_account(account: &PercComparisonAccount) -> Result<(), EocvFault> {
    let expected = comparison_from_flags([
        account.a6_receipt_matches,
        account.packet_matches,
        account.descriptor_matches,
        account.envelope_raw_bytes_match,
        account.envelope_self_digest_matches,
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
        account.evidence_references_match,
    ]);
    if *account != expected {
        return Err(fault(EocvFaultCode::Receipt, "comparison account differs"));
    }
    Ok(())
}

fn comparison_from_flags(flags: [bool; 17]) -> PercComparisonAccount {
    let mismatch_reasons = flags
        .iter()
        .enumerate()
        .filter_map(|(index, matched)| (!matched).then_some(PERC_MISMATCH_REASONS[index]))
        .collect();
    PercComparisonAccount {
        a6_receipt_matches: flags[0],
        packet_matches: flags[1],
        descriptor_matches: flags[2],
        envelope_raw_bytes_match: flags[3],
        envelope_self_digest_matches: flags[4],
        candidate_uuid_matches: flags[5],
        authority_name_matches: flags[6],
        artifact_kind_matches: flags[7],
        opaque_reference_matches: flags[8],
        content_sha256_matches: flags[9],
        declared_bytes_matches: flags[10],
        confidentiality_matches: flags[11],
        verifier_profile_matches: flags[12],
        fixture_flag_matches: flags[13],
        dependency_ordinal_matches: flags[14],
        input_class_matches: flags[15],
        evidence_references_match: flags[16],
        all_correspondence_matches: flags.into_iter().all(|flag| flag),
        mismatch_reasons,
    }
}

pub fn verify_perc_reference_correspondence(
    request: &PercVerificationRequest,
    predecessor: &PercPredecessor<'_>,
    raw_envelope: &[u8],
) -> Result<PercVerificationReceipt, EocvFault> {
    validate_request(request)?;
    raw_bound(raw_envelope)?;
    let a6 = verify_eocv_expected_observation(
        predecessor.a6_request,
        &predecessor.a6_predecessor,
        predecessor.raw_plan_request,
        predecessor.raw_plan,
        predecessor.raw_observation_bundle,
    )
    .map_err(predecessor_fault)?;
    if a6 != *predecessor.a6_receipt
        || request.a6_verification_request_sha256 != predecessor.a6_request.request_sha256
        || request.expected_a6_receipt_sha256 != a6.receipt_sha256
    {
        return Err(fault(
            EocvFaultCode::Predecessor,
            "complete A6 replay binding differs",
        ));
    }
    if request.expected_envelope_bytes != raw_envelope.len() as u64
        || request.expected_envelope_raw_sha256 != sha256_bytes(raw_envelope)
    {
        return Err(fault(
            EocvFaultCode::RawBytes,
            "reference envelope raw identity differs",
        ));
    }
    let envelope =
        from_perc_envelope_machine_form(std::str::from_utf8(raw_envelope).map_err(|_| {
            fault(
                EocvFaultCode::MachineForm,
                "reference envelope UTF-8 differs",
            )
        })?)?;
    if envelope.envelope_uuid != request.expected_envelope_uuid
        || envelope.envelope_sha256 != request.expected_envelope_sha256
    {
        return Err(fault(
            EocvFaultCode::Identity,
            "reference envelope identity differs",
        ));
    }
    let (packet_request, packet) = reconstruct_current_packet(request, predecessor.a6_request)?;
    let mut comparison = compare_perc_reference_metadata(request, &envelope);
    comparison.a6_receipt_matches = true;
    comparison.packet_matches = packet.packet_sha256 == request.expected_authority_packet_sha256;
    comparison.descriptor_matches =
        packet_request.descriptors[6].descriptor_sha256 == request.expected_descriptor_sha256;
    comparison.envelope_raw_bytes_match = true;
    comparison.envelope_self_digest_matches = true;
    comparison = comparison_from_flags([
        comparison.a6_receipt_matches,
        comparison.packet_matches,
        comparison.descriptor_matches,
        comparison.envelope_raw_bytes_match,
        comparison.envelope_self_digest_matches,
        comparison.candidate_uuid_matches,
        comparison.authority_name_matches,
        comparison.artifact_kind_matches,
        comparison.opaque_reference_matches,
        comparison.content_sha256_matches,
        comparison.declared_bytes_matches,
        comparison.confidentiality_matches,
        comparison.verifier_profile_matches,
        comparison.fixture_flag_matches,
        comparison.dependency_ordinal_matches,
        comparison.input_class_matches,
        comparison.evidence_references_match,
    ]);
    let receipt = build_receipt(request, a6, &envelope, &comparison)?;
    validate_perc_receipt_fields(&receipt)?;
    Ok(receipt)
}

fn reconstruct_current_packet(
    request: &PercVerificationRequest,
    a6_request: &EocvVerificationRequest,
) -> Result<(B1OaprRequest, crate::B1OaprPacket), EocvFault> {
    let fixture = request.input_class == KcvInputClass::DeterministicFixtureCandidate;
    let descriptor = B1OaprCandidateDescriptor {
        ordinal: 7,
        candidate_uuid: request.expected_candidate_uuid.clone(),
        authority_name: request.expected_authority_name.clone(),
        artifact_kind: request.expected_artifact_kind.clone(),
        origin: if fixture {
            B1OaprCandidateOrigin::DeterministicFixtureCandidate
        } else {
            B1OaprCandidateOrigin::ExternallySuppliedCandidate
        },
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
        return Err(fault(EocvFaultCode::Digest, "A7 descriptor digest differs"));
    }
    let prior = &a6_request.authority_packet_request;
    if prior.descriptors.len() != 9 {
        return Err(fault(
            EocvFaultCode::Coordinate,
            "authority packet coordinate count differs",
        ));
    }
    let mut current = prior.clone();
    current.descriptors[6] = descriptor;
    current.request_sha256 = b1oapr_request_digest(&current).map_err(predecessor_fault)?;
    if current.request_sha256 != request.authority_packet_request_sha256 {
        return Err(fault(
            EocvFaultCode::Digest,
            "A7 packet request identity differs",
        ));
    }
    let first = compile_b1oapr_packet(&current).map_err(predecessor_fault)?;
    let second = compile_b1oapr_packet(&current).map_err(predecessor_fault)?;
    if first != second || first.packet_sha256 != request.expected_authority_packet_sha256 {
        return Err(fault(
            EocvFaultCode::Digest,
            "A7 packet reconstruction differs",
        ));
    }
    if prior.descriptors[..6] != current.descriptors[..6]
        || prior.descriptors[7..] != current.descriptors[7..]
    {
        return Err(fault(
            EocvFaultCode::Dependency,
            "A7 changed another packet descriptor",
        ));
    }
    let mut normalized = current.clone();
    normalized.descriptors[6] = prior.descriptors[6].clone();
    normalized.request_sha256 = prior.request_sha256.clone();
    if normalized != *prior {
        return Err(fault(
            EocvFaultCode::Lineage,
            "A7 changed packet subjects or policy",
        ));
    }
    Ok((current, first))
}

fn build_receipt(
    request: &PercVerificationRequest,
    a6: EocvVerificationReceipt,
    envelope: &PercReferenceEnvelope,
    comparison: &PercComparisonAccount,
) -> Result<PercVerificationReceipt, EocvFault> {
    let mut receipt = PercVerificationReceipt {
        profile: PERC_RECEIPT_PROFILE.to_owned(),
        status: if comparison.all_correspondence_matches {
            PERC_MATCHED_STATUS
        } else {
            PERC_MISMATCHED_STATUS
        }
        .to_owned(),
        authority: PERC_AUTHORITY.to_owned(),
        source_snapshot_uuid: request.source_snapshot_uuid.clone(),
        canonical_uuid: request.canonical_uuid.clone(),
        signature_uuid: request.signature_uuid.clone(),
        source_custody_commit: request.source_custody_commit.clone(),
        formation_commit: PERC_FORMATION_COMMIT.to_owned(),
        formation_bookend_commit: PERC_FORMATION_BOOKEND_COMMIT.to_owned(),
        a6_implementation_commit: request.a6_implementation_commit.clone(),
        a6_bookend_commit: request.a6_bookend_commit.clone(),
        a6_proof_uuid: request.a6_proof_uuid.clone(),
        request_sha256: request.request_sha256.clone(),
        a6_verification_request_sha256: request.a6_verification_request_sha256.clone(),
        a6_receipt_sha256: a6.receipt_sha256.clone(),
        a6_receipt: a6,
        authority_packet_request_sha256: request.authority_packet_request_sha256.clone(),
        authority_packet_sha256: request.expected_authority_packet_sha256.clone(),
        a7_candidate_uuid: request.expected_candidate_uuid.clone(),
        a7_descriptor_sha256: request.expected_descriptor_sha256.clone(),
        reference_envelope_bytes: request.expected_envelope_bytes,
        reference_envelope_raw_sha256: request.expected_envelope_raw_sha256.clone(),
        reference_envelope_sha256: envelope.envelope_sha256.clone(),
        envelope_uuid: envelope.envelope_uuid.clone(),
        opaque_reference: envelope.opaque_reference.clone(),
        content_sha256: envelope.content_sha256.clone(),
        declared_bytes: envelope.declared_bytes,
        confidentiality: envelope.confidentiality,
        required_verifier_profile: envelope.required_verifier_profile.clone(),
        dependency_ordinal: envelope.dependency_ordinal,
        input_class: envelope.input_class,
        fixture_only: envelope.fixture_only,
        correspondence_account: comparison.clone(),
        evidence_references: envelope.evidence_references.clone(),
        maximum_attempts: request.maximum_attempts,
        automatic_retry_count: request.automatic_retry_count,
        automatic_cleanup_count: request.automatic_cleanup_count,
        a6_correspondence_receipt_verified: true,
        packet_replayed: true,
        descriptor_correspondence_verified: true,
        reference_envelope_bytes_matched: true,
        comparison_reconstructed: true,
        private_execution_permit_reference_correspondence_proved: comparison
            .all_correspondence_matches,
        production_authority_claimed: false,
        private_execution_permit_present: false,
        permit_material_authenticated: false,
        permit_signer_identity_proved: false,
        permit_signer_authority_proved: false,
        permit_scope_proved: false,
        permit_subject_proved: false,
        permit_freshness_proved: false,
        permit_nonexpired: false,
        permit_revocation_checked: false,
        permit_single_use_proved: false,
        permit_unconsumed: false,
        permit_consumed: false,
        live_authorization_admitted: false,
        production_broker_projection_present: false,
        physical_preparation_authorized: false,
        ready_for_physical_execution: false,
        execution_authorized: false,
        effect_account: TwvEffectAccount::default(),
        receipt_sha256: sha256_bytes(b""),
    };
    receipt.receipt_sha256 = perc_receipt_digest(&receipt)?;
    Ok(receipt)
}

fn validate_request(request: &PercVerificationRequest) -> Result<(), EocvFault> {
    bounded(request)?;
    if request.profile != PERC_REQUEST_PROFILE {
        return Err(fault(EocvFaultCode::Profile, "A7 request profile differs"));
    }
    if request.source_snapshot_uuid != PERC_SOURCE_SNAPSHOT_UUID
        || request.canonical_uuid != PERC_CANONICAL_UUID
        || request.signature_uuid != PERC_SIGNATURE_UUID
        || request.source_custody_commit != PERC_SOURCE_CUSTODY_COMMIT
        || request.source_bookend_commit != PERC_SOURCE_BOOKEND_COMMIT
        || request.a6_implementation_commit != PERC_A6_IMPLEMENTATION_COMMIT
        || request.a6_bookend_commit != PERC_A6_BOOKEND_COMMIT
        || request.a6_proof_uuid != PERC_A6_PROOF_UUID
    {
        return Err(fault(
            EocvFaultCode::Lineage,
            "A7 governance lineage differs",
        ));
    }
    if !valid_eocv_uuid(&request.expected_candidate_uuid)
        || !valid_envelope_uuid(&request.expected_envelope_uuid)
        || request.expected_authority_name != "private_execution_permit"
        || request.expected_artifact_kind != "private_execution_permit_reference_candidate"
        || request.expected_confidentiality != B1OaprConfidentiality::SecretReferenceOnly
        || request.expected_verifier_profile != "private-execution-permit-verifier/0.1"
        || request.expected_dependency_ordinal != 6
    {
        return Err(fault(
            EocvFaultCode::Coordinate,
            "A7 expected coordinate differs",
        ));
    }
    validate_opaque_reference(&request.expected_opaque_reference)?;
    validate_references(&request.evidence_references)?;
    if !valid_digest(&request.a6_verification_request_sha256)
        || !valid_digest(&request.expected_a6_receipt_sha256)
        || !valid_digest(&request.authority_packet_request_sha256)
        || !valid_digest(&request.expected_authority_packet_sha256)
        || !valid_digest(&request.expected_descriptor_sha256)
        || !valid_digest(&request.expected_envelope_raw_sha256)
        || !valid_digest(&request.expected_envelope_sha256)
        || !valid_digest(&request.expected_content_sha256)
    {
        return Err(fault(
            EocvFaultCode::Digest,
            "A7 request digest shape differs",
        ));
    }
    let fixture = request.input_class == KcvInputClass::DeterministicFixtureCandidate;
    if request.expected_fixture_only != fixture
        || request.expected_envelope_bytes == 0
        || request.expected_envelope_bytes > PERC_MAX_FORM_BYTES as u64
        || request.expected_declared_bytes == 0
        || request.expected_declared_bytes > 16_777_216
    {
        return Err(fault(
            EocvFaultCode::Shape,
            "A7 request class or size differs",
        ));
    }
    if request.maximum_attempts != 1
        || request.automatic_retry_count != 0
        || request.automatic_cleanup_count != 0
    {
        return Err(fault(EocvFaultCode::Effect, "A7 attempt account differs"));
    }
    if request.request_sha256 != perc_request_digest(request)? {
        return Err(fault(
            EocvFaultCode::Digest,
            "A7 request self digest differs",
        ));
    }
    Ok(())
}

fn validate_envelope(envelope: &PercReferenceEnvelope) -> Result<(), EocvFault> {
    bounded(envelope)?;
    if envelope.profile != PERC_ENVELOPE_PROFILE {
        return Err(fault(EocvFaultCode::Profile, "A7 envelope profile differs"));
    }
    if !valid_envelope_uuid(&envelope.envelope_uuid)
        || !valid_eocv_uuid(&envelope.candidate_uuid)
        || !valid_digest(&envelope.a6_receipt_sha256)
        || !valid_digest(&envelope.content_sha256)
        || !safe_coordinate_text(&envelope.authority_name)
        || !safe_coordinate_text(&envelope.artifact_kind)
        || !safe_coordinate_text(&envelope.required_verifier_profile)
        || envelope.declared_bytes == 0
        || envelope.declared_bytes > 16_777_216
    {
        return Err(fault(
            EocvFaultCode::Shape,
            "A7 envelope coordinate shape differs",
        ));
    }
    validate_opaque_reference(&envelope.opaque_reference)?;
    validate_references(&envelope.evidence_references)?;
    if envelope.envelope_sha256 != perc_envelope_digest(envelope)? {
        return Err(fault(
            EocvFaultCode::Digest,
            "A7 envelope self digest differs",
        ));
    }
    Ok(())
}

pub fn validate_perc_receipt_fields(receipt: &PercVerificationReceipt) -> Result<(), EocvFault> {
    bounded(receipt)?;
    let status = if receipt.correspondence_account.all_correspondence_matches {
        PERC_MATCHED_STATUS
    } else {
        PERC_MISMATCHED_STATUS
    };
    if receipt.profile != PERC_RECEIPT_PROFILE
        || receipt.status != status
        || receipt.authority != PERC_AUTHORITY
    {
        return Err(fault(EocvFaultCode::Profile, "A7 receipt profile differs"));
    }
    if receipt.production_authority_claimed
        || receipt.private_execution_permit_present
        || receipt.permit_material_authenticated
        || receipt.permit_signer_identity_proved
        || receipt.permit_signer_authority_proved
        || receipt.permit_scope_proved
        || receipt.permit_subject_proved
        || receipt.permit_freshness_proved
        || receipt.permit_nonexpired
        || receipt.permit_revocation_checked
        || receipt.permit_single_use_proved
        || receipt.permit_unconsumed
        || receipt.permit_consumed
        || receipt.live_authorization_admitted
        || receipt.production_broker_projection_present
        || receipt.physical_preparation_authorized
        || receipt.ready_for_physical_execution
        || receipt.execution_authorized
    {
        return Err(fault(EocvFaultCode::Truth, "A7 receipt promotes authority"));
    }
    if !receipt.a6_correspondence_receipt_verified
        || !receipt.packet_replayed
        || !receipt.descriptor_correspondence_verified
        || !receipt.reference_envelope_bytes_matched
        || !receipt.comparison_reconstructed
        || receipt.private_execution_permit_reference_correspondence_proved
            != receipt.correspondence_account.all_correspondence_matches
    {
        return Err(fault(EocvFaultCode::Truth, "A7 receipt truth differs"));
    }
    if receipt.effect_account != TwvEffectAccount::default()
        || receipt.maximum_attempts != 1
        || receipt.automatic_retry_count != 0
        || receipt.automatic_cleanup_count != 0
    {
        return Err(fault(EocvFaultCode::Effect, "A7 receipt effects differ"));
    }
    if receipt.a6_receipt_sha256 != receipt.a6_receipt.receipt_sha256
        || receipt.source_snapshot_uuid != PERC_SOURCE_SNAPSHOT_UUID
        || receipt.canonical_uuid != PERC_CANONICAL_UUID
        || receipt.signature_uuid != PERC_SIGNATURE_UUID
        || receipt.source_custody_commit != PERC_SOURCE_CUSTODY_COMMIT
        || receipt.formation_commit != PERC_FORMATION_COMMIT
        || receipt.formation_bookend_commit != PERC_FORMATION_BOOKEND_COMMIT
    {
        return Err(fault(EocvFaultCode::Lineage, "A7 receipt lineage differs"));
    }
    validate_perc_comparison_account(&receipt.correspondence_account)?;
    crate::b1_expected_observation_correspondence::validate_eocv_receipt_fields(
        &receipt.a6_receipt,
    )
    .map_err(predecessor_fault)?;
    if receipt.receipt_sha256 != perc_receipt_digest(receipt)? {
        return Err(fault(
            EocvFaultCode::Digest,
            "A7 receipt self digest differs",
        ));
    }
    Ok(())
}

pub fn validate_perc_receipt(
    request: &PercVerificationRequest,
    predecessor: &PercPredecessor<'_>,
    raw_envelope: &[u8],
    receipt: &PercVerificationReceipt,
) -> Result<(), EocvFault> {
    if *receipt != verify_perc_reference_correspondence(request, predecessor, raw_envelope)? {
        return Err(fault(EocvFaultCode::Restart, "A7 retained receipt differs"));
    }
    Ok(())
}

pub fn to_perc_envelope_machine_form(
    envelope: &PercReferenceEnvelope,
) -> Result<String, EocvFault> {
    validate_envelope(envelope)?;
    serde_json::to_string(envelope)
        .map_err(|_| fault(EocvFaultCode::MachineForm, "A7 envelope encoding differs"))
}
pub fn from_perc_envelope_machine_form(text: &str) -> Result<PercReferenceEnvelope, EocvFault> {
    let value = parse_eocv_canonical(text)?;
    validate_envelope(&value)?;
    Ok(value)
}
pub fn to_perc_request_machine_form(
    request: &PercVerificationRequest,
) -> Result<String, EocvFault> {
    validate_request(request)?;
    serde_json::to_string(request)
        .map_err(|_| fault(EocvFaultCode::MachineForm, "A7 request encoding differs"))
}
pub fn from_perc_request_machine_form(text: &str) -> Result<PercVerificationRequest, EocvFault> {
    let value = parse_eocv_canonical(text)?;
    validate_request(&value)?;
    Ok(value)
}
pub fn to_perc_receipt_machine_form(
    request: &PercVerificationRequest,
    predecessor: &PercPredecessor<'_>,
    raw_envelope: &[u8],
    receipt: &PercVerificationReceipt,
) -> Result<String, EocvFault> {
    validate_perc_receipt(request, predecessor, raw_envelope, receipt)?;
    serde_json::to_string(receipt)
        .map_err(|_| fault(EocvFaultCode::MachineForm, "A7 receipt encoding differs"))
}
pub fn from_perc_receipt_machine_form(
    request: &PercVerificationRequest,
    predecessor: &PercPredecessor<'_>,
    raw_envelope: &[u8],
    text: &str,
) -> Result<PercVerificationReceipt, EocvFault> {
    let value = parse_eocv_canonical(text)?;
    validate_perc_receipt(request, predecessor, raw_envelope, &value)?;
    Ok(value)
}

pub fn perc_envelope_digest(envelope: &PercReferenceEnvelope) -> Result<ContentDigest, EocvFault> {
    bounded(envelope)?;
    let mut normalized = envelope.clone();
    normalized.envelope_sha256 = sha256_bytes(b"");
    eocv_domain_digest(
        "cantor.b1.private-execution-permit-reference.envelope.v1",
        &normalized,
    )
}
pub fn perc_request_digest(request: &PercVerificationRequest) -> Result<ContentDigest, EocvFault> {
    bounded(request)?;
    let mut normalized = request.clone();
    normalized.request_sha256 = sha256_bytes(b"");
    eocv_domain_digest(
        "cantor.b1.private-execution-permit-reference.request.v1",
        &normalized,
    )
}
pub fn perc_receipt_digest(receipt: &PercVerificationReceipt) -> Result<ContentDigest, EocvFault> {
    bounded(receipt)?;
    let mut normalized = receipt.clone();
    normalized.receipt_sha256 = sha256_bytes(b"");
    eocv_domain_digest(
        "cantor.b1.private-execution-permit-reference.receipt.v1",
        &normalized,
    )
}

fn bounded<T: Serialize>(value: &T) -> Result<(), EocvFault> {
    if serde_json::to_vec(value)
        .map_err(|_| fault(EocvFaultCode::MachineForm, "A7 typed encoding differs"))?
        .len()
        > PERC_MAX_FORM_BYTES
    {
        return Err(fault(EocvFaultCode::Size, "A7 typed form exceeds bound"));
    }
    Ok(())
}
fn raw_bound(bytes: &[u8]) -> Result<(), EocvFault> {
    if bytes.is_empty() || bytes.len() > PERC_MAX_FORM_BYTES {
        return Err(fault(EocvFaultCode::Size, "A7 raw form exceeds bound"));
    }
    Ok(())
}
fn valid_envelope_uuid(value: &str) -> bool {
    valid_eocv_uuid(value)
        && ![
            PERC_SOURCE_SNAPSHOT_UUID,
            PERC_CANONICAL_UUID,
            PERC_SIGNATURE_UUID,
        ]
        .contains(&value)
}
fn valid_digest(value: &ContentDigest) -> bool {
    value.algorithm == "sha256"
        && value.value.len() == 64
        && value
            .value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
fn safe_coordinate_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= PERC_MAX_REFERENCE_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'/'))
        && !value.contains("..")
        && !value.starts_with('/')
}
fn safe_evidence_reference(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= PERC_MAX_REFERENCE_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}
fn validate_opaque_reference(value: &str) -> Result<(), EocvFault> {
    if value.is_empty()
        || value.len() > PERC_MAX_REFERENCE_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(fault(
            EocvFaultCode::Shape,
            "A7 opaque reference shape differs",
        ));
    }
    Ok(())
}
fn validate_references(values: &[String]) -> Result<(), EocvFault> {
    if values.is_empty()
        || values.len() > PERC_MAX_EVIDENCE_REFERENCES
        || values.iter().any(|value| !safe_evidence_reference(value))
        || values.iter().collect::<BTreeSet<_>>().len() != values.len()
    {
        return Err(fault(
            EocvFaultCode::Evidence,
            "A7 evidence references differ",
        ));
    }
    Ok(())
}
fn predecessor_fault(error: impl std::fmt::Display) -> EocvFault {
    fault(EocvFaultCode::Predecessor, &error.to_string())
}
fn fault(code: EocvFaultCode, message: &str) -> EocvFault {
    eocv_fault(code, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_forms() -> (
        EocvVerificationRequest,
        EocvVerificationReceipt,
        PercReferenceEnvelope,
        PercVerificationRequest,
    ) {
        let a6_request_text = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../experiments/b1_expected_observation_correspondence_p0/implementation_provider_free_evidence/verification_request.json"
        ))
        .trim_end_matches(['\r', '\n']);
        let a6_request = crate::from_eocv_request_machine_form(a6_request_text)
            .expect("retained A6 request is canonical");
        let a6_receipt_text = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../experiments/b1_expected_observation_correspondence_p0/implementation_provider_free_evidence/receipt.json"
        ));
        let a6_receipt: EocvVerificationReceipt =
            serde_json::from_str(a6_receipt_text).expect("retained A6 receipt parses");
        crate::b1_expected_observation_correspondence::validate_eocv_receipt_fields(&a6_receipt)
            .expect("retained A6 receipt account is internally valid");
        let descriptor = a6_request.authority_packet_request.descriptors[6].clone();
        let mut envelope = PercReferenceEnvelope {
            profile: PERC_ENVELOPE_PROFILE.to_owned(),
            envelope_uuid: "a7000000-0000-4000-8000-000000000001".to_owned(),
            a6_receipt_sha256: a6_receipt.receipt_sha256.clone(),
            candidate_uuid: descriptor.candidate_uuid.clone(),
            authority_name: descriptor.authority_name.clone(),
            artifact_kind: descriptor.artifact_kind.clone(),
            opaque_reference: descriptor.opaque_reference.clone(),
            content_sha256: descriptor.content_sha256.clone(),
            declared_bytes: descriptor.declared_bytes,
            confidentiality: descriptor.confidentiality,
            required_verifier_profile: descriptor.required_verifier_profile.clone(),
            fixture_only: descriptor.fixture_only,
            dependency_ordinal: descriptor.dependency_ordinal.expect("A7 dependency"),
            input_class: KcvInputClass::DeterministicFixtureCandidate,
            evidence_references: vec!["evidence_a7".to_owned()],
            envelope_sha256: sha256_bytes(b""),
        };
        envelope.envelope_sha256 = perc_envelope_digest(&envelope).expect("envelope digest");
        let raw_envelope = serde_json::to_vec(&envelope).expect("envelope bytes");
        let packet = compile_b1oapr_packet(&a6_request.authority_packet_request)
            .expect("retained packet request compiles");
        let mut request = PercVerificationRequest {
            profile: PERC_REQUEST_PROFILE.to_owned(),
            source_snapshot_uuid: PERC_SOURCE_SNAPSHOT_UUID.to_owned(),
            canonical_uuid: PERC_CANONICAL_UUID.to_owned(),
            signature_uuid: PERC_SIGNATURE_UUID.to_owned(),
            source_custody_commit: PERC_SOURCE_CUSTODY_COMMIT.to_owned(),
            source_bookend_commit: PERC_SOURCE_BOOKEND_COMMIT.to_owned(),
            a6_implementation_commit: PERC_A6_IMPLEMENTATION_COMMIT.to_owned(),
            a6_bookend_commit: PERC_A6_BOOKEND_COMMIT.to_owned(),
            a6_proof_uuid: PERC_A6_PROOF_UUID.to_owned(),
            a6_verification_request_sha256: a6_request.request_sha256.clone(),
            expected_a6_receipt_sha256: a6_receipt.receipt_sha256.clone(),
            authority_packet_request_sha256: a6_request
                .authority_packet_request
                .request_sha256
                .clone(),
            expected_authority_packet_sha256: packet.packet_sha256,
            expected_candidate_uuid: descriptor.candidate_uuid,
            expected_descriptor_sha256: descriptor.descriptor_sha256,
            expected_envelope_uuid: envelope.envelope_uuid.clone(),
            expected_envelope_bytes: raw_envelope.len() as u64,
            expected_envelope_raw_sha256: sha256_bytes(&raw_envelope),
            expected_envelope_sha256: envelope.envelope_sha256.clone(),
            expected_authority_name: descriptor.authority_name,
            expected_artifact_kind: descriptor.artifact_kind,
            expected_opaque_reference: descriptor.opaque_reference,
            expected_content_sha256: descriptor.content_sha256,
            expected_declared_bytes: descriptor.declared_bytes,
            expected_confidentiality: descriptor.confidentiality,
            expected_verifier_profile: descriptor.required_verifier_profile,
            expected_fixture_only: descriptor.fixture_only,
            expected_dependency_ordinal: descriptor.dependency_ordinal.expect("A7 dependency"),
            input_class: KcvInputClass::DeterministicFixtureCandidate,
            evidence_references: envelope.evidence_references.clone(),
            maximum_attempts: 1,
            automatic_retry_count: 0,
            automatic_cleanup_count: 0,
            request_sha256: sha256_bytes(b""),
        };
        request.request_sha256 = perc_request_digest(&request).expect("request digest");
        (a6_request, a6_receipt, envelope, request)
    }

    #[test]
    fn mismatch_account_is_ordered_and_complete() {
        let mut flags = [true; 17];
        flags[5] = false;
        flags[8] = false;
        flags[16] = false;
        let account = comparison_from_flags(flags);
        assert_eq!(
            account.mismatch_reasons,
            vec![
                PercMismatchReason::CandidateUuidMismatch,
                PercMismatchReason::OpaqueReferenceMismatch,
                PercMismatchReason::EvidenceReferencesMismatch,
            ]
        );
        assert!(!account.all_correspondence_matches);
        assert!(validate_perc_comparison_account(&account).is_ok());
    }

    #[test]
    fn forged_comparison_summary_refuses() {
        let mut account = comparison_from_flags([true; 17]);
        account
            .mismatch_reasons
            .push(PercMismatchReason::PacketMismatch);
        assert_eq!(
            validate_perc_comparison_account(&account)
                .expect_err("forged summary must refuse")
                .code,
            EocvFaultCode::Receipt
        );
    }

    #[test]
    fn every_mismatch_subset_has_exact_order_and_conjunction() {
        for mask in 0_u32..(1_u32 << 17) {
            let mut flags = [true; 17];
            for (index, flag) in flags.iter_mut().enumerate() {
                *flag = mask & (1 << index) == 0;
            }
            let account = comparison_from_flags(flags);
            let expected: Vec<_> = PERC_MISMATCH_REASONS
                .iter()
                .enumerate()
                .filter_map(|(index, reason)| (mask & (1 << index) != 0).then_some(*reason))
                .collect();
            assert_eq!(account.mismatch_reasons, expected);
            assert_eq!(account.all_correspondence_matches, mask == 0);
            assert!(validate_perc_comparison_account(&account).is_ok());
        }
    }

    #[test]
    fn opaque_reference_is_deliberately_non_resolvable() {
        for rejected in [
            "../secret",
            "C:\\secret",
            "https://secret",
            "$ENV_SECRET",
            "secret value",
            "token:abc",
            "line\nbreak",
        ] {
            let error = validate_opaque_reference(rejected).expect_err("locator-like input");
            assert_eq!(error.code, EocvFaultCode::Shape);
            assert!(!error.message.contains(rejected));
        }
        assert!(validate_opaque_reference("fixture_candidate_a7").is_ok());
    }

    #[test]
    fn evidence_references_reject_locator_and_log_shapes_without_echo() {
        for rejected in [
            "../proof",
            "C_drive",
            "https_ref",
            "two words",
            "line\nbreak",
        ] {
            let values = vec![rejected.to_owned()];
            let result = validate_references(&values);
            if matches!(rejected, "C_drive" | "https_ref") {
                assert!(result.is_ok());
            } else {
                let error = result.expect_err("unsafe evidence reference");
                assert_eq!(error.code, EocvFaultCode::Evidence);
                assert!(!error.message.contains(rejected));
            }
        }
    }

    #[test]
    fn retained_a6_coordinate_builds_canonical_a7_forms_and_packet() {
        let (a6_request, _a6_receipt, envelope, request) = fixture_forms();
        let envelope_form = to_perc_envelope_machine_form(&envelope).expect("envelope form");
        assert_eq!(
            from_perc_envelope_machine_form(&envelope_form).expect("envelope replay"),
            envelope
        );
        let request_form = to_perc_request_machine_form(&request).expect("request form");
        assert_eq!(
            from_perc_request_machine_form(&request_form).expect("request replay"),
            request
        );
        let (rebuilt_request, rebuilt_packet) =
            reconstruct_current_packet(&request, &a6_request).expect("packet replay");
        assert_eq!(
            rebuilt_request.request_sha256,
            request.authority_packet_request_sha256
        );
        assert_eq!(
            rebuilt_packet.packet_sha256,
            request.expected_authority_packet_sha256
        );
        let comparison = compare_perc_reference_metadata(&request, &envelope);
        assert!(comparison.a6_receipt_matches);
        assert!(!comparison.packet_matches);
        assert!(!comparison.descriptor_matches);
        assert!(!comparison.envelope_raw_bytes_match);
        assert!(!comparison.envelope_self_digest_matches);
        assert!(comparison.candidate_uuid_matches);
        assert!(comparison.evidence_references_match);
        assert!(!comparison.all_correspondence_matches);
    }

    #[test]
    fn canonical_adverse_reference_stays_a_descriptive_mismatch() {
        let (_a6_request, _a6_receipt, mut envelope, mut request) = fixture_forms();
        envelope.opaque_reference = "different_fixture_reference".to_owned();
        envelope.envelope_sha256 = perc_envelope_digest(&envelope).expect("adverse digest");
        let raw = serde_json::to_vec(&envelope).expect("adverse bytes");
        request.expected_envelope_bytes = raw.len() as u64;
        request.expected_envelope_raw_sha256 = sha256_bytes(&raw);
        request.expected_envelope_sha256 = envelope.envelope_sha256.clone();
        request.request_sha256 = perc_request_digest(&request).expect("rebound request");
        assert!(validate_request(&request).is_ok());
        let comparison = compare_perc_reference_metadata(&request, &envelope);
        assert!(!comparison.opaque_reference_matches);
        assert_eq!(
            comparison.mismatch_reasons,
            vec![
                PercMismatchReason::PacketMismatch,
                PercMismatchReason::DescriptorMismatch,
                PercMismatchReason::EnvelopeRawBytesMismatch,
                PercMismatchReason::EnvelopeSelfDigestMismatch,
                PercMismatchReason::OpaqueReferenceMismatch,
            ]
        );
    }
}
