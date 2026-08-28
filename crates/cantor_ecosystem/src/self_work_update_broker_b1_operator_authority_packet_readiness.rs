//! Pure provider-free compiler for the B1 operator-authority candidate packet.
//!
//! Candidate descriptors are bounded metadata claims. This module deliberately
//! has no surface for resolving a reference, authenticating candidate material,
//! promoting authority, observing a host, or causing an effect.

use std::fmt;

use cantor_core::{ContentDigest, sha256_bytes};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;

pub const B1OAPR_REQUEST_PROFILE: &str = "cantor-self-work-update-broker-b1-cdrive-production-preparation-operator-authority-packet-readiness-request/0.1";
pub const B1OAPR_PACKET_PROFILE: &str =
    "cantor-self-work-update-broker-b1-cdrive-production-preparation-operator-authority-packet/0.1";
pub const B1OAPR_VERIFICATION_PROFILE: &str = "cantor-self-work-update-broker-b1-cdrive-production-preparation-operator-authority-packet-readiness-verification/0.1";
pub const B1OAPR_STATUS: &str =
    "operator_authority_packet_shape_verified_all_candidate_material_untrusted_and_unadmitted";
pub const B1OAPR_AUTHORITY: &str = "authority_packet_shape_only";
pub const B1OAPR_DISPOSITION: &str = "candidate_shape_admitted_external_verification_required";
pub const B1OAPR_SOURCE_SNAPSHOT_UUID: &str = "3e948be9-4f53-4ade-bec6-83f4ade6db33";
pub const B1OAPR_CANONICAL_UUID: &str = "c0460d30-4870-44fc-82d2-baf2bc5cc0f5";
pub const B1OAPR_SIGNATURE_UUID: &str = "28af539f-21de-4f1b-af3c-a5215172bba0";
pub const B1OAPR_SOURCE_CUSTODY_COMMIT: &str = "09d6a812a3622f7b19bb1119a844f330e9bd88e5";
pub const B1OAPR_FORMATION_COMMIT: &str = "6ca0a0f392b44677fbb6d1746fe22e7126623fd6";
pub const B1OAPR_PREDECESSOR_IMPLEMENTATION_COMMIT: &str =
    "025de395f0f469ba68eba3f488ac85a0ff0d8480";
pub const B1OAPR_PREDECESSOR_BOOKEND_COMMIT: &str = "11539da2ebdbd56b328d1408befce91815e38e1b";
pub const B1OAPR_PREDECESSOR_PROOF_UUID: &str = "16f598e8-3546-447b-9941-d67100871af6";
pub const B1OAPR_MAX_FORM_BYTES: usize = 1_048_576;
pub const B1OAPR_MAX_TEXT_BYTES: usize = 8_192;
pub const B1OAPR_MAX_CANDIDATE_BYTES: u64 = 16_777_216;
pub const B1OAPR_MAX_AGGREGATE_BYTES: u64 = 67_108_864;

const MAX_JSON_DEPTH: usize = 24;
const MAX_JSON_FIELDS: usize = 512;
const REQUEST_DOMAIN: &str = "cantor.b1.operator-authority-packet-readiness.request.v1";
const DESCRIPTOR_DOMAIN: &str = "cantor.b1.operator-authority-packet-readiness.descriptor.v1";
const PACKET_DOMAIN: &str = "cantor.b1.operator-authority-packet-readiness.packet.v1";
const VERIFICATION_DOMAIN: &str = "cantor.b1.operator-authority-packet-readiness.verification.v1";
const EXACT_BRANCH: &str = "codex/self-hosted-corpus";
const EXACT_REMOTE: &str = "https://github.com/cattailfarmer/Cantor";
const EXACT_PRINCIPAL: &str = r"THEBRAIN\enjer";
const EXACT_ROLE: &str = "operator_authorizer";
const EXACT_SUBJECT: &str = "cantor_b1_cdrive_production_preparation_p0";
const CEREMONY_REQUEST_DIGEST: &str =
    "fdfbe3c683bce440f77ecc96c4d541ec9c565a8df2724c54521c7a461d01ad32";
const CEREMONY_PLAN_DIGEST: &str =
    "ee51d65ddfdc220545a6e58a50fe0109f8ea1ac2c36ab425d1bb4afe670d71d4";
const CEREMONY_VERIFICATION_DIGEST: &str =
    "0607aa9b03db49162a6fba22944a201e4018e34dcf3fef9819f215d38ddee24c";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum B1OaprCandidateOrigin {
    DeterministicFixtureCandidate,
    ExternallySuppliedCandidate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum B1OaprConfidentiality {
    PublicMetadata,
    SecretReferenceOnly,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1OaprCandidateDescriptor {
    pub ordinal: u8,
    pub candidate_uuid: String,
    pub authority_name: String,
    pub artifact_kind: String,
    pub origin: B1OaprCandidateOrigin,
    pub opaque_reference: String,
    pub content_sha256: ContentDigest,
    pub declared_bytes: u64,
    pub confidentiality: B1OaprConfidentiality,
    pub required_verifier_profile: String,
    pub fixture_only: bool,
    pub dependency_ordinal: Option<u8>,
    pub descriptor_sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1OaprRequest {
    pub profile: String,
    pub source_snapshot_uuid: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub source_custody_commit: String,
    pub formation_commit: String,
    pub predecessor_implementation_commit: String,
    pub predecessor_bookend_commit: String,
    pub predecessor_proof_uuid: String,
    pub ceremony_request_digest: String,
    pub ceremony_plan_digest: String,
    pub ceremony_verification_digest: String,
    pub branch: String,
    pub canonical_remote: String,
    pub principal: String,
    pub role: String,
    pub subject: String,
    pub descriptors: Vec<B1OaprCandidateDescriptor>,
    pub maximum_attempts: u8,
    pub automatic_retry_count: u8,
    pub automatic_cleanup_count: u8,
    pub request_sha256: ContentDigest,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1OaprEffectAccount {
    pub candidate_reference_resolution_count: u32,
    pub candidate_material_read_count: u32,
    pub key_read_count: u32,
    pub signing_count: u32,
    pub clock_read_count: u32,
    pub environment_read_count: u32,
    pub host_observation_count: u32,
    pub process_count: u32,
    pub provider_trial_count: u32,
    pub model_turn_count: u32,
    pub mcp_call_count: u32,
    pub network_contact_count: u32,
    pub writer_run_count: u32,
    pub broker_projection_count: u32,
    pub filesystem_mutation_count: u32,
    pub git_mutation_count: u32,
    pub cleanup_effect_count: u32,
    pub physical_contact: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1OaprCoordinateDisposition {
    pub ordinal: u8,
    pub candidate_uuid: String,
    pub authority_name: String,
    pub disposition: String,
    pub externally_verified: bool,
    pub authority_admitted: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1OaprPacket {
    pub profile: String,
    pub status: String,
    pub authority: String,
    pub request_sha256: ContentDigest,
    pub descriptors: Vec<B1OaprCandidateDescriptor>,
    pub dispositions: Vec<B1OaprCoordinateDisposition>,
    pub unresolved_authorities: Vec<String>,
    pub aggregate_declared_bytes: u64,
    pub maximum_attempts: u8,
    pub automatic_retry_count: u8,
    pub automatic_cleanup_count: u8,
    pub candidate_material_authenticated: bool,
    pub policy_governance_proved: bool,
    pub key_custody_proved: bool,
    pub revocation_truth_proved: bool,
    pub current_nonexpired: bool,
    pub live_authorization_admitted: bool,
    pub fresh_observation_proved: bool,
    pub private_execution_permit_present: bool,
    pub production_broker_projection_present: bool,
    pub physical_preparation_authorized: bool,
    pub ready_for_physical_execution: bool,
    pub effect_account: B1OaprEffectAccount,
    pub packet_sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1OaprVerification {
    pub profile: String,
    pub status: String,
    pub authority: String,
    pub request_sha256: ContentDigest,
    pub packet_sha256: ContentDigest,
    pub descriptor_count: u8,
    pub unresolved_authority_count: u8,
    pub deterministic_replay_count: u8,
    pub byte_identical: bool,
    pub all_candidate_material_untrusted: bool,
    pub all_authority_unadmitted: bool,
    pub effect_account: B1OaprEffectAccount,
    pub verification_sha256: ContentDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum B1OaprFaultCode {
    Bound,
    MachineForm,
    Identity,
    Coordinate,
    Origin,
    Confidentiality,
    Dependency,
    Authority,
    Effect,
    Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct B1OaprFault {
    pub code: B1OaprFaultCode,
    pub message: String,
}

impl fmt::Display for B1OaprFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for B1OaprFault {}

pub fn canonical_b1oapr_request() -> Result<B1OaprRequest, B1OaprFault> {
    let mut descriptors = Vec::with_capacity(9);
    for coordinate in exact_coordinates() {
        let fixture_text = format!(
            "cantor deterministic fixture candidate a{}",
            coordinate.ordinal
        );
        let mut descriptor = B1OaprCandidateDescriptor {
            ordinal: coordinate.ordinal,
            candidate_uuid: format!("a1000000-0000-4000-8000-{:012}", coordinate.ordinal),
            authority_name: coordinate.authority_name.to_owned(),
            artifact_kind: coordinate.artifact_kind.to_owned(),
            origin: B1OaprCandidateOrigin::DeterministicFixtureCandidate,
            opaque_reference: format!("fixture_candidate_a{}", coordinate.ordinal),
            content_sha256: sha256_bytes(fixture_text.as_bytes()),
            declared_bytes: 1_024 * u64::from(coordinate.ordinal),
            confidentiality: coordinate.confidentiality,
            required_verifier_profile: coordinate.verifier_profile.to_owned(),
            fixture_only: true,
            dependency_ordinal: coordinate.dependency_ordinal,
            descriptor_sha256: empty_digest(),
        };
        descriptor.descriptor_sha256 = b1oapr_descriptor_digest(&descriptor)?;
        descriptors.push(descriptor);
    }
    let mut request = B1OaprRequest {
        profile: B1OAPR_REQUEST_PROFILE.to_owned(),
        source_snapshot_uuid: B1OAPR_SOURCE_SNAPSHOT_UUID.to_owned(),
        canonical_uuid: B1OAPR_CANONICAL_UUID.to_owned(),
        signature_uuid: B1OAPR_SIGNATURE_UUID.to_owned(),
        source_custody_commit: B1OAPR_SOURCE_CUSTODY_COMMIT.to_owned(),
        formation_commit: B1OAPR_FORMATION_COMMIT.to_owned(),
        predecessor_implementation_commit: B1OAPR_PREDECESSOR_IMPLEMENTATION_COMMIT.to_owned(),
        predecessor_bookend_commit: B1OAPR_PREDECESSOR_BOOKEND_COMMIT.to_owned(),
        predecessor_proof_uuid: B1OAPR_PREDECESSOR_PROOF_UUID.to_owned(),
        ceremony_request_digest: CEREMONY_REQUEST_DIGEST.to_owned(),
        ceremony_plan_digest: CEREMONY_PLAN_DIGEST.to_owned(),
        ceremony_verification_digest: CEREMONY_VERIFICATION_DIGEST.to_owned(),
        branch: EXACT_BRANCH.to_owned(),
        canonical_remote: EXACT_REMOTE.to_owned(),
        principal: EXACT_PRINCIPAL.to_owned(),
        role: EXACT_ROLE.to_owned(),
        subject: EXACT_SUBJECT.to_owned(),
        descriptors,
        maximum_attempts: 1,
        automatic_retry_count: 0,
        automatic_cleanup_count: 0,
        request_sha256: empty_digest(),
    };
    request.request_sha256 = b1oapr_request_digest(&request)?;
    validate_b1oapr_request(&request)?;
    Ok(request)
}

pub fn compile_b1oapr_packet(request: &B1OaprRequest) -> Result<B1OaprPacket, B1OaprFault> {
    validate_b1oapr_request(request)?;
    let aggregate_declared_bytes = request
        .descriptors
        .iter()
        .map(|descriptor| descriptor.declared_bytes)
        .sum();
    let mut packet = B1OaprPacket {
        profile: B1OAPR_PACKET_PROFILE.to_owned(),
        status: B1OAPR_STATUS.to_owned(),
        authority: B1OAPR_AUTHORITY.to_owned(),
        request_sha256: request.request_sha256.clone(),
        descriptors: request.descriptors.clone(),
        dispositions: request
            .descriptors
            .iter()
            .map(|descriptor| B1OaprCoordinateDisposition {
                ordinal: descriptor.ordinal,
                candidate_uuid: descriptor.candidate_uuid.clone(),
                authority_name: descriptor.authority_name.clone(),
                disposition: B1OAPR_DISPOSITION.to_owned(),
                externally_verified: false,
                authority_admitted: false,
            })
            .collect(),
        unresolved_authorities: expected_b1oapr_unresolved_authorities(),
        aggregate_declared_bytes,
        maximum_attempts: 1,
        automatic_retry_count: 0,
        automatic_cleanup_count: 0,
        candidate_material_authenticated: false,
        policy_governance_proved: false,
        key_custody_proved: false,
        revocation_truth_proved: false,
        current_nonexpired: false,
        live_authorization_admitted: false,
        fresh_observation_proved: false,
        private_execution_permit_present: false,
        production_broker_projection_present: false,
        physical_preparation_authorized: false,
        ready_for_physical_execution: false,
        effect_account: B1OaprEffectAccount::default(),
        packet_sha256: empty_digest(),
    };
    packet.packet_sha256 = b1oapr_packet_digest(&packet)?;
    validate_b1oapr_packet(request, &packet)?;
    Ok(packet)
}

pub fn verify_b1oapr_packet(
    request: &B1OaprRequest,
    packet: &B1OaprPacket,
) -> Result<B1OaprVerification, B1OaprFault> {
    validate_b1oapr_packet(request, packet)?;
    let first = compile_b1oapr_packet(request)?;
    let second = compile_b1oapr_packet(request)?;
    let first_bytes = serde_json::to_vec(&first).map_err(machine_fault)?;
    let second_bytes = serde_json::to_vec(&second).map_err(machine_fault)?;
    if packet != &first || first != second || first_bytes != second_bytes {
        return Err(fault(B1OaprFaultCode::Digest, "packet replay differs"));
    }
    let mut verification = B1OaprVerification {
        profile: B1OAPR_VERIFICATION_PROFILE.to_owned(),
        status: B1OAPR_STATUS.to_owned(),
        authority: B1OAPR_AUTHORITY.to_owned(),
        request_sha256: request.request_sha256.clone(),
        packet_sha256: packet.packet_sha256.clone(),
        descriptor_count: 9,
        unresolved_authority_count: 9,
        deterministic_replay_count: 2,
        byte_identical: true,
        all_candidate_material_untrusted: true,
        all_authority_unadmitted: true,
        effect_account: B1OaprEffectAccount::default(),
        verification_sha256: empty_digest(),
    };
    verification.verification_sha256 = b1oapr_verification_digest(&verification)?;
    validate_b1oapr_verification(request, packet, &verification)?;
    Ok(verification)
}

pub fn validate_b1oapr_request(request: &B1OaprRequest) -> Result<(), B1OaprFault> {
    if request.profile != B1OAPR_REQUEST_PROFILE
        || request.source_snapshot_uuid != B1OAPR_SOURCE_SNAPSHOT_UUID
        || request.canonical_uuid != B1OAPR_CANONICAL_UUID
        || request.signature_uuid != B1OAPR_SIGNATURE_UUID
        || request.source_custody_commit != B1OAPR_SOURCE_CUSTODY_COMMIT
        || request.formation_commit != B1OAPR_FORMATION_COMMIT
        || request.predecessor_implementation_commit != B1OAPR_PREDECESSOR_IMPLEMENTATION_COMMIT
        || request.predecessor_bookend_commit != B1OAPR_PREDECESSOR_BOOKEND_COMMIT
        || request.predecessor_proof_uuid != B1OAPR_PREDECESSOR_PROOF_UUID
        || request.ceremony_request_digest != CEREMONY_REQUEST_DIGEST
        || request.ceremony_plan_digest != CEREMONY_PLAN_DIGEST
        || request.ceremony_verification_digest != CEREMONY_VERIFICATION_DIGEST
        || request.branch != EXACT_BRANCH
        || request.canonical_remote != EXACT_REMOTE
        || request.principal != EXACT_PRINCIPAL
        || request.role != EXACT_ROLE
        || request.subject != EXACT_SUBJECT
        || request.maximum_attempts != 1
        || request.automatic_retry_count != 0
        || request.automatic_cleanup_count != 0
        || request.descriptors.len() != 9
    {
        return Err(fault(
            B1OaprFaultCode::Identity,
            "request lineage, profile, or ceiling differs",
        ));
    }
    let mut aggregate = 0_u64;
    let mut candidate_uuids = Vec::with_capacity(9);
    for (index, descriptor) in request.descriptors.iter().enumerate() {
        validate_descriptor(descriptor, &exact_coordinates()[index])?;
        if candidate_uuids.contains(&descriptor.candidate_uuid) {
            return Err(fault(
                B1OaprFaultCode::Coordinate,
                "candidate UUID is duplicated",
            ));
        }
        candidate_uuids.push(descriptor.candidate_uuid.clone());
        aggregate = aggregate
            .checked_add(descriptor.declared_bytes)
            .ok_or_else(|| fault(B1OaprFaultCode::Bound, "aggregate bytes overflow"))?;
    }
    if aggregate > B1OAPR_MAX_AGGREGATE_BYTES {
        return Err(fault(
            B1OaprFaultCode::Bound,
            "aggregate candidate bytes exceed bound",
        ));
    }
    if request.request_sha256 != b1oapr_request_digest(request)? {
        return Err(fault(B1OaprFaultCode::Digest, "request digest differs"));
    }
    Ok(())
}

pub fn validate_b1oapr_packet(
    request: &B1OaprRequest,
    packet: &B1OaprPacket,
) -> Result<(), B1OaprFault> {
    validate_b1oapr_request(request)?;
    let expected = compile_packet_without_validation(request)?;
    if packet.profile != B1OAPR_PACKET_PROFILE
        || packet.status != B1OAPR_STATUS
        || packet.authority != B1OAPR_AUTHORITY
        || packet.request_sha256 != request.request_sha256
        || packet.descriptors != request.descriptors
        || packet.dispositions != expected.dispositions
        || packet.unresolved_authorities != expected_b1oapr_unresolved_authorities()
        || packet.aggregate_declared_bytes != expected.aggregate_declared_bytes
        || packet.maximum_attempts != 1
        || packet.automatic_retry_count != 0
        || packet.automatic_cleanup_count != 0
    {
        return Err(fault(
            B1OaprFaultCode::Authority,
            "packet shape, disposition, or unresolved authority differs",
        ));
    }
    validate_non_authority(packet)?;
    if packet.packet_sha256 != b1oapr_packet_digest(packet)? {
        return Err(fault(B1OaprFaultCode::Digest, "packet digest differs"));
    }
    Ok(())
}

pub fn validate_b1oapr_verification(
    request: &B1OaprRequest,
    packet: &B1OaprPacket,
    verification: &B1OaprVerification,
) -> Result<(), B1OaprFault> {
    validate_b1oapr_packet(request, packet)?;
    if verification.profile != B1OAPR_VERIFICATION_PROFILE
        || verification.status != B1OAPR_STATUS
        || verification.authority != B1OAPR_AUTHORITY
        || verification.request_sha256 != request.request_sha256
        || verification.packet_sha256 != packet.packet_sha256
        || verification.descriptor_count != 9
        || verification.unresolved_authority_count != 9
        || verification.deterministic_replay_count != 2
        || !verification.byte_identical
        || !verification.all_candidate_material_untrusted
        || !verification.all_authority_unadmitted
    {
        return Err(fault(
            B1OaprFaultCode::Authority,
            "verification nonauthority account differs",
        ));
    }
    if verification.effect_account != B1OaprEffectAccount::default() {
        return Err(fault(
            B1OaprFaultCode::Effect,
            "verification reports an effect",
        ));
    }
    if verification.verification_sha256 != b1oapr_verification_digest(verification)? {
        return Err(fault(
            B1OaprFaultCode::Digest,
            "verification digest differs",
        ));
    }
    Ok(())
}

pub fn expected_b1oapr_unresolved_authorities() -> Vec<String> {
    exact_coordinates()
        .iter()
        .map(|coordinate| coordinate.authority_name.to_owned())
        .collect()
}

pub fn b1oapr_descriptor_digest(
    descriptor: &B1OaprCandidateDescriptor,
) -> Result<ContentDigest, B1OaprFault> {
    let mut unsigned = descriptor.clone();
    unsigned.descriptor_sha256 = empty_digest();
    domain_digest(DESCRIPTOR_DOMAIN, &unsigned)
}

pub fn b1oapr_request_digest(request: &B1OaprRequest) -> Result<ContentDigest, B1OaprFault> {
    let mut unsigned = request.clone();
    unsigned.request_sha256 = empty_digest();
    domain_digest(REQUEST_DOMAIN, &unsigned)
}

pub fn b1oapr_packet_digest(packet: &B1OaprPacket) -> Result<ContentDigest, B1OaprFault> {
    let mut unsigned = packet.clone();
    unsigned.packet_sha256 = empty_digest();
    domain_digest(PACKET_DOMAIN, &unsigned)
}

pub fn b1oapr_verification_digest(
    verification: &B1OaprVerification,
) -> Result<ContentDigest, B1OaprFault> {
    let mut unsigned = verification.clone();
    unsigned.verification_sha256 = empty_digest();
    domain_digest(VERIFICATION_DOMAIN, &unsigned)
}

pub fn to_b1oapr_request_machine_form(request: &B1OaprRequest) -> Result<String, B1OaprFault> {
    validate_b1oapr_request(request)?;
    to_machine_form(request)
}

pub fn from_b1oapr_request_machine_form(text: &str) -> Result<B1OaprRequest, B1OaprFault> {
    let request = from_machine_form(text)?;
    validate_b1oapr_request(&request)?;
    Ok(request)
}

pub fn to_b1oapr_packet_machine_form(
    request: &B1OaprRequest,
    packet: &B1OaprPacket,
) -> Result<String, B1OaprFault> {
    validate_b1oapr_packet(request, packet)?;
    to_machine_form(packet)
}

pub fn from_b1oapr_packet_machine_form(
    request: &B1OaprRequest,
    text: &str,
) -> Result<B1OaprPacket, B1OaprFault> {
    let packet = from_machine_form(text)?;
    validate_b1oapr_packet(request, &packet)?;
    Ok(packet)
}

pub fn to_b1oapr_verification_machine_form(
    request: &B1OaprRequest,
    packet: &B1OaprPacket,
    verification: &B1OaprVerification,
) -> Result<String, B1OaprFault> {
    validate_b1oapr_verification(request, packet, verification)?;
    to_machine_form(verification)
}

pub fn from_b1oapr_verification_machine_form(
    request: &B1OaprRequest,
    packet: &B1OaprPacket,
    text: &str,
) -> Result<B1OaprVerification, B1OaprFault> {
    let verification = from_machine_form(text)?;
    validate_b1oapr_verification(request, packet, &verification)?;
    Ok(verification)
}

fn validate_descriptor(
    descriptor: &B1OaprCandidateDescriptor,
    coordinate: &Coordinate,
) -> Result<(), B1OaprFault> {
    if descriptor.ordinal != coordinate.ordinal
        || descriptor.authority_name != coordinate.authority_name
        || descriptor.artifact_kind != coordinate.artifact_kind
        || descriptor.required_verifier_profile != coordinate.verifier_profile
    {
        return Err(fault(
            B1OaprFaultCode::Coordinate,
            "descriptor coordinate mapping differs",
        ));
    }
    if descriptor.dependency_ordinal != coordinate.dependency_ordinal {
        return Err(fault(
            B1OaprFaultCode::Dependency,
            "descriptor dependency differs",
        ));
    }
    if descriptor.confidentiality != coordinate.confidentiality {
        return Err(fault(
            B1OaprFaultCode::Confidentiality,
            "descriptor confidentiality differs",
        ));
    }
    let expected_origin = if descriptor.fixture_only {
        B1OaprCandidateOrigin::DeterministicFixtureCandidate
    } else {
        B1OaprCandidateOrigin::ExternallySuppliedCandidate
    };
    if descriptor.origin != expected_origin {
        return Err(fault(
            B1OaprFaultCode::Origin,
            "descriptor origin and fixture label differ",
        ));
    }
    if !valid_uuid(&descriptor.candidate_uuid)
        || !safe_text(&descriptor.opaque_reference)
        || !valid_digest(&descriptor.content_sha256)
        || descriptor.declared_bytes == 0
        || descriptor.declared_bytes > B1OAPR_MAX_CANDIDATE_BYTES
    {
        return Err(fault(
            B1OaprFaultCode::Bound,
            "descriptor UUID, reference, digest, or byte bound differs",
        ));
    }
    if descriptor.descriptor_sha256 != b1oapr_descriptor_digest(descriptor)? {
        return Err(fault(B1OaprFaultCode::Digest, "descriptor digest differs"));
    }
    Ok(())
}

fn validate_non_authority(packet: &B1OaprPacket) -> Result<(), B1OaprFault> {
    if packet.candidate_material_authenticated
        || packet.policy_governance_proved
        || packet.key_custody_proved
        || packet.revocation_truth_proved
        || packet.current_nonexpired
        || packet.live_authorization_admitted
        || packet.fresh_observation_proved
        || packet.private_execution_permit_present
        || packet.production_broker_projection_present
        || packet.physical_preparation_authorized
        || packet.ready_for_physical_execution
    {
        return Err(fault(
            B1OaprFaultCode::Authority,
            "packet attempts to promote candidate truth or authority",
        ));
    }
    if packet.effect_account != B1OaprEffectAccount::default() {
        return Err(fault(B1OaprFaultCode::Effect, "packet reports an effect"));
    }
    Ok(())
}

fn compile_packet_without_validation(request: &B1OaprRequest) -> Result<B1OaprPacket, B1OaprFault> {
    let aggregate_declared_bytes =
        request
            .descriptors
            .iter()
            .try_fold(0_u64, |total, descriptor| {
                total
                    .checked_add(descriptor.declared_bytes)
                    .ok_or_else(|| fault(B1OaprFaultCode::Bound, "aggregate bytes overflow"))
            })?;
    Ok(B1OaprPacket {
        profile: B1OAPR_PACKET_PROFILE.to_owned(),
        status: B1OAPR_STATUS.to_owned(),
        authority: B1OAPR_AUTHORITY.to_owned(),
        request_sha256: request.request_sha256.clone(),
        descriptors: request.descriptors.clone(),
        dispositions: request
            .descriptors
            .iter()
            .map(|descriptor| B1OaprCoordinateDisposition {
                ordinal: descriptor.ordinal,
                candidate_uuid: descriptor.candidate_uuid.clone(),
                authority_name: descriptor.authority_name.clone(),
                disposition: B1OAPR_DISPOSITION.to_owned(),
                externally_verified: false,
                authority_admitted: false,
            })
            .collect(),
        unresolved_authorities: expected_b1oapr_unresolved_authorities(),
        aggregate_declared_bytes,
        maximum_attempts: 1,
        automatic_retry_count: 0,
        automatic_cleanup_count: 0,
        candidate_material_authenticated: false,
        policy_governance_proved: false,
        key_custody_proved: false,
        revocation_truth_proved: false,
        current_nonexpired: false,
        live_authorization_admitted: false,
        fresh_observation_proved: false,
        private_execution_permit_present: false,
        production_broker_projection_present: false,
        physical_preparation_authorized: false,
        ready_for_physical_execution: false,
        effect_account: B1OaprEffectAccount::default(),
        packet_sha256: empty_digest(),
    })
}

#[derive(Clone, Copy)]
struct Coordinate {
    ordinal: u8,
    authority_name: &'static str,
    artifact_kind: &'static str,
    verifier_profile: &'static str,
    confidentiality: B1OaprConfidentiality,
    dependency_ordinal: Option<u8>,
}

fn exact_coordinates() -> [Coordinate; 9] {
    use B1OaprConfidentiality::{PublicMetadata, SecretReferenceOnly};
    [
        Coordinate {
            ordinal: 1,
            authority_name: "policy_governance",
            artifact_kind: "operator_policy_governance_bundle_candidate",
            verifier_profile: "operator-policy-governance-verifier/0.1",
            confidentiality: PublicMetadata,
            dependency_ordinal: None,
        },
        Coordinate {
            ordinal: 2,
            authority_name: "key_custody",
            artifact_kind: "public_verifying_key_custody_attestation_candidate",
            verifier_profile: "public-key-custody-verifier/0.1",
            confidentiality: PublicMetadata,
            dependency_ordinal: Some(1),
        },
        Coordinate {
            ordinal: 3,
            authority_name: "revocation_truth",
            artifact_kind: "revocation_snapshot_candidate",
            verifier_profile: "revocation-snapshot-verifier/0.1",
            confidentiality: PublicMetadata,
            dependency_ordinal: Some(2),
        },
        Coordinate {
            ordinal: 4,
            authority_name: "current_time",
            artifact_kind: "trusted_time_witness_receipt_candidate",
            verifier_profile: "trusted-time-witness-verifier/0.1",
            confidentiality: PublicMetadata,
            dependency_ordinal: Some(3),
        },
        Coordinate {
            ordinal: 5,
            authority_name: "live_decision",
            artifact_kind: "operator_decision_envelope_candidate",
            verifier_profile: "live-operator-decision-verifier/0.1",
            confidentiality: PublicMetadata,
            dependency_ordinal: Some(4),
        },
        Coordinate {
            ordinal: 6,
            authority_name: "fresh_observation",
            artifact_kind: "expected_current_observation_bundle_candidate",
            verifier_profile: "expected-current-observation-verifier/0.1",
            confidentiality: PublicMetadata,
            dependency_ordinal: Some(5),
        },
        Coordinate {
            ordinal: 7,
            authority_name: "private_execution_permit",
            artifact_kind: "private_execution_permit_reference_candidate",
            verifier_profile: "private-execution-permit-verifier/0.1",
            confidentiality: SecretReferenceOnly,
            dependency_ordinal: Some(6),
        },
        Coordinate {
            ordinal: 8,
            authority_name: "broker_projection",
            artifact_kind: "production_broker_projection_candidate",
            verifier_profile: "production-broker-projection-verifier/0.1",
            confidentiality: PublicMetadata,
            dependency_ordinal: Some(7),
        },
        Coordinate {
            ordinal: 9,
            authority_name: "physical_preparation",
            artifact_kind: "physical_preparation_authorization_candidate",
            verifier_profile: "physical-preparation-authorization-verifier/0.1",
            confidentiality: PublicMetadata,
            dependency_ordinal: Some(8),
        },
    ]
}

fn to_machine_form<T: Serialize>(value: &T) -> Result<String, B1OaprFault> {
    let text = serde_json::to_string(value).map_err(machine_fault)?;
    if text.len() > B1OAPR_MAX_FORM_BYTES {
        return Err(fault(
            B1OaprFaultCode::Bound,
            "machine form exceeds byte bound",
        ));
    }
    Ok(text)
}

fn from_machine_form<T: DeserializeOwned + Serialize>(text: &str) -> Result<T, B1OaprFault> {
    if text.is_empty() || text.len() > B1OAPR_MAX_FORM_BYTES {
        return Err(fault(
            B1OaprFaultCode::Bound,
            "machine form byte bound differs",
        ));
    }
    let value: Value = serde_json::from_str(text).map_err(machine_fault)?;
    let mut fields = 0_usize;
    measure_value(&value, 1, &mut fields)?;
    let parsed: T = serde_json::from_str(text).map_err(machine_fault)?;
    if serde_json::to_string(&parsed).map_err(machine_fault)? != text {
        return Err(fault(
            B1OaprFaultCode::MachineForm,
            "machine form is not canonical duplicate-free JSON",
        ));
    }
    Ok(parsed)
}

fn measure_value(value: &Value, depth: usize, fields: &mut usize) -> Result<(), B1OaprFault> {
    if depth > MAX_JSON_DEPTH {
        return Err(fault(B1OaprFaultCode::Bound, "JSON depth exceeds bound"));
    }
    match value {
        Value::Object(map) => {
            *fields = fields
                .checked_add(map.len())
                .ok_or_else(|| fault(B1OaprFaultCode::Bound, "JSON field count overflow"))?;
            if *fields > MAX_JSON_FIELDS {
                return Err(fault(
                    B1OaprFaultCode::Bound,
                    "JSON field count exceeds bound",
                ));
            }
            for child in map.values() {
                measure_value(child, depth + 1, fields)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                measure_value(child, depth + 1, fields)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn safe_text(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= B1OAPR_MAX_TEXT_BYTES
        && !text.chars().any(|character| character.is_control())
}

fn valid_uuid(text: &str) -> bool {
    text.len() == 36
        && text.as_bytes()[8] == b'-'
        && text.as_bytes()[13] == b'-'
        && text.as_bytes()[18] == b'-'
        && text.as_bytes()[23] == b'-'
        && text != "00000000-0000-0000-0000-000000000000"
        && text.chars().enumerate().all(|(index, character)| {
            matches!(index, 8 | 13 | 18 | 23)
                || character.is_ascii_digit()
                || ('a'..='f').contains(&character)
        })
}

fn valid_digest(digest: &ContentDigest) -> bool {
    digest.algorithm == "sha256"
        && digest.value.len() == 64
        && digest
            .value
            .chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
}

fn domain_digest<T: Serialize>(domain: &str, value: &T) -> Result<ContentDigest, B1OaprFault> {
    let payload = serde_json::to_vec(value).map_err(machine_fault)?;
    let mut bytes = Vec::with_capacity(domain.len() + 1 + payload.len());
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&payload);
    Ok(sha256_bytes(&bytes))
}

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: String::new(),
    }
}

fn machine_fault(error: impl fmt::Display) -> B1OaprFault {
    fault(B1OaprFaultCode::MachineForm, error)
}

fn fault(code: B1OaprFaultCode, message: impl fmt::Display) -> B1OaprFault {
    B1OaprFault {
        code,
        message: message.to_string(),
    }
}
