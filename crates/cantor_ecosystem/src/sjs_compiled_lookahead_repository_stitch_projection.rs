//! Pure, deterministic composition of one fully verified repository-slice
//! observation into the published compiled-lookahead stitch lifecycle.
//!
//! This module never observes a repository and never contacts a provider. It
//! accepts the complete RSO request/receipt/verification triplet as supplied
//! data, replays that triplet, projects only its selected candidates, and then
//! delegates lifecycle compilation and verification to the published LAS
//! contract.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use cantor_core::{
    ContentDigest, SJS_LAS_CANONICAL_UUID, SJS_LAS_NON_AUTHORITY, SJS_LAS_PARENT_SOURCE_UUID,
    SJS_LAS_REQUEST_PROFILE, SJS_LAS_SIGNATURE_UUID, SJS_LAS_SOURCE_UUID, SemanticId,
    SjsLasAuthority, SjsLasBoundaryKind, SjsLasEffectAccount, SjsLasEnvelope, SjsLasExactScope,
    SjsLasInputClass, SjsLasInvocationCoordinate, SjsLasLifecycleState, SjsLasObservation,
    SjsLasObservationKind, SjsLasPredicate, SjsLasRequest, SjsLasStitchDeclaration,
    SjsLasVerification, SjsLtoResultStatus, compile_sjs_las, seal_sjs_las_request, sha256_bytes,
    sjs_las_scope_digest, sjs_las_stitch_digest, verify_sjs_las,
};
use serde::de::{DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::sjs_compiled_lookahead_repository_slice_observation::{
    SJS_RSO_CANONICAL_UUID, SjsRsoEffectAccount, SjsRsoReceipt, SjsRsoRequest, SjsRsoVerification,
    from_sjs_rso_receipt_machine_form, from_sjs_rso_request_machine_form,
    from_sjs_rso_verification_machine_form, validate_sjs_rso_receipt, validate_sjs_rso_request,
    validate_sjs_rso_verification, verify_sjs_rso_receipt,
};

pub const SJS_RSP_REQUEST_PROFILE: &str =
    "cantor-sjs-lookahead-repository-stitch-projection-request/0.1";
pub const SJS_RSP_ENVELOPE_PROFILE: &str =
    "cantor-sjs-lookahead-repository-stitch-projection-envelope/0.1";
pub const SJS_RSP_VERIFICATION_PROFILE: &str =
    "cantor-sjs-lookahead-repository-stitch-projection-verification/0.1";
pub const SJS_RSP_EVIDENCE_PROFILE: &str =
    "cantor-sjs-lookahead-repository-stitch-projection-evidence/0.1";
pub const SJS_RSP_CANONICAL_UUID: &str = "fc3a2e9e-1fc5-4b04-a867-431c2ab0584f";
pub const SJS_RSP_SIGNATURE_UUID: &str = "0359eae5-48cc-4f84-95ee-a5c96a3cfba8";
pub const SJS_RSP_SOURCE_UUID: &str = "2d9f052d-52d5-4a82-be77-2c32ffaecfbc";
pub const SJS_RSP_RSO_COMPLETION_UUID: &str = "735a0e32-3e9c-4abf-857c-51eae5a06d47";
pub const SJS_RSP_RSO_IMPLEMENTATION_COMMIT: &str = "8cf8969a2ded68a03e1ddf0c59ed23b05b9bac9b";
pub const SJS_RSP_RSO_BOOKEND_COMMIT: &str = "195935df0db5eb072fedba4e8a395241d49679d6";
pub const SJS_RSP_RSO_CLOSURE_COMMIT: &str = "052a37aab0237ca08c4d73669bc8af9174a8d313";
pub const SJS_RSP_STITCH_COMPLETION_UUID: &str = "b70fc4bc-c652-449c-ba19-a381f8a99d59";
pub const SJS_RSP_MAX_MACHINE_FORM_BYTES: usize = 1_048_576;
pub const SJS_RSP_MAX_EVIDENCE_BUNDLE_BYTES: usize = 8_388_608;
pub const SJS_RSP_NON_AUTHORITY: &str = "Verified supplied-data projection only. Historical RSO physical contact remains input evidence. A projection request, receipt, stitch packet, lifecycle record, verification, digest, or evidence bundle grants no repository observation, prose parsing, semantic generation, candidate scoring, tokenizer truth, prompt mutation, provider or model contact, inference, performance truth, autonomous work, durable custody, workspace authority, remote-hardware authority, or external-effect authority.";

const REQUEST_DOMAIN: &str = "cantor.sjs-rsp.request.v1";
const RECEIPT_DOMAIN: &str = "cantor.sjs-rsp.receipt.v1";
const ENVELOPE_DOMAIN: &str = "cantor.sjs-rsp.envelope.v1";
const VERIFICATION_DOMAIN: &str = "cantor.sjs-rsp.verification.v1";
const DOWNSTREAM_VERIFICATION_DOMAIN: &str = "cantor.sjs-rsp.downstream-verification.v1";
const REQUEST_FILE: &str = "request.json";
const ENVELOPE_FILE: &str = "envelope.json";
const VERIFICATION_FILE: &str = "verification.json";
const MANIFEST_FILE: &str = "evidence_manifest.json";
const MAX_DEPTH: usize = 40;
const MAX_FIELDS: usize = 16_384;
const MAX_TEXT_BYTES: usize = 4_096;
const MAX_SELECTED: usize = 8;
const MAX_EVIDENCE_REFS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SjsRspInputClass {
    SyntheticProviderFreeFixture,
    VerifiedRepositorySelection,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsRspRequest {
    pub profile: String,
    pub request_id: SemanticId,
    pub run_id: SemanticId,
    pub receipt_id: SemanticId,
    pub downstream_request_id: SemanticId,
    pub downstream_run_id: SemanticId,
    pub downstream_packet_id: SemanticId,
    pub downstream_policy_id: SemanticId,
    pub input_class: SjsRspInputClass,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub source_snapshot_uuid: String,
    pub parent_observation_canonical_uuid: String,
    pub parent_observation_completion_signature_uuid: String,
    pub parent_observation_implementation_commit: String,
    pub parent_observation_bookend_commit: String,
    pub parent_observation_closure_commit: String,
    pub stitch_canonical_uuid: String,
    pub stitch_completion_signature_uuid: String,
    pub upstream_request: SjsRsoRequest,
    pub upstream_receipt: SjsRsoReceipt,
    pub upstream_verification: SjsRsoVerification,
    pub provider_profile: String,
    pub invocation_ordinal: u32,
    pub boundary_kind: SjsLasBoundaryKind,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub non_authority: String,
    pub request_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsRspReceipt {
    pub receipt_id: SemanticId,
    pub request_digest: ContentDigest,
    pub upstream_request_digest: ContentDigest,
    pub upstream_receipt_digest: ContentDigest,
    pub upstream_verification_digest: ContentDigest,
    pub downstream_request_digest: ContentDigest,
    pub downstream_envelope_digest: ContentDigest,
    pub downstream_verification_digest: ContentDigest,
    pub selected_candidate_digests: Vec<ContentDigest>,
    pub selected_count: u32,
    pub stitch_count: u32,
    pub hint_count: u32,
    pub source_binding_count: u32,
    pub observation_count: u32,
    pub coordinate_count: u32,
    pub projection_count: u32,
    pub projected_inclusion_count: u32,
    pub projected_bytes: u64,
    pub physical_input_account_count: u32,
    pub historical_physical_contact: bool,
    pub current_effects: SjsLasEffectAccount,
    pub receipt_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsRspEnvelope {
    pub profile: String,
    pub request: SjsRspRequest,
    pub downstream_request: SjsLasRequest,
    pub downstream_envelope: SjsLasEnvelope,
    pub downstream_verification: SjsLasVerification,
    pub receipt: SjsRspReceipt,
    pub execution_authorized: bool,
    pub effects: SjsLasEffectAccount,
    pub envelope_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsRspVerification {
    pub profile: String,
    pub status: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub input_class: SjsRspInputClass,
    pub request_digest: ContentDigest,
    pub envelope_digest: ContentDigest,
    pub receipt_digest: ContentDigest,
    pub upstream_request_digest: ContentDigest,
    pub upstream_receipt_digest: ContentDigest,
    pub upstream_verification_digest: ContentDigest,
    pub downstream_request_digest: ContentDigest,
    pub downstream_envelope_digest: ContentDigest,
    pub downstream_verification_digest: ContentDigest,
    pub selected_count: u32,
    pub stitch_count: u32,
    pub hint_count: u32,
    pub source_binding_count: u32,
    pub observation_count: u32,
    pub coordinate_count: u32,
    pub projection_count: u32,
    pub projected_inclusion_count: u32,
    pub projected_bytes: u64,
    pub physical_input_account_count: u32,
    pub historical_physical_contact: bool,
    pub downstream_authority: SjsLasAuthority,
    pub execution_authorized: bool,
    pub effects: SjsLasEffectAccount,
    pub verification_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsRspEvidenceFile {
    pub bytes: u64,
    pub sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsRspEvidenceManifest {
    pub profile: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub replay_count: u32,
    pub files: BTreeMap<String, SjsRspEvidenceFile>,
    pub request_digest: ContentDigest,
    pub envelope_digest: ContentDigest,
    pub receipt_digest: ContentDigest,
    pub verification_digest: ContentDigest,
    pub upstream_request_digest: ContentDigest,
    pub upstream_receipt_digest: ContentDigest,
    pub upstream_verification_digest: ContentDigest,
    pub downstream_request_digest: ContentDigest,
    pub downstream_envelope_digest: ContentDigest,
    pub downstream_verification_digest: ContentDigest,
    pub selected_count: u32,
    pub stitch_count: u32,
    pub hint_count: u32,
    pub source_binding_count: u32,
    pub observation_count: u32,
    pub coordinate_count: u32,
    pub projection_count: u32,
    pub projected_inclusion_count: u32,
    pub projected_bytes: u64,
    pub physical_input_account_count: u32,
    pub historical_physical_contact: bool,
    pub execution_authorized: bool,
    pub effects: SjsLasEffectAccount,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsRspEvidenceBundle {
    pub request_file: String,
    pub envelope_file: String,
    pub verification_file: String,
    pub manifest_file: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SjsRspFaultCode {
    InvalidProfile,
    InvalidInputClass,
    InvalidIdentity,
    InvalidText,
    InvalidDigest,
    InvalidBound,
    InvalidUpstream,
    InvalidMapping,
    InvalidAuthority,
    InvalidAccount,
    InvalidMachineForm,
    DownstreamRefusal,
    ArithmeticOverflow,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SjsRspFault {
    pub code: SjsRspFaultCode,
    pub detail: String,
}

impl fmt::Display for SjsRspFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.detail)
    }
}
impl std::error::Error for SjsRspFault {}

pub fn synthetic_sjs_rsp_request() -> Result<SjsRspRequest, SjsRspFault> {
    const RSO_REQUEST: &str = include_str!(
        "../../../experiments/sjs_compiled_lookahead_repository_slice_observation_p0/artifacts/request.json"
    );
    const RSO_RECEIPT: &str = include_str!(
        "../../../experiments/sjs_compiled_lookahead_repository_slice_observation_p0/artifacts/receipt.json"
    );
    const RSO_VERIFICATION: &str = include_str!(
        "../../../experiments/sjs_compiled_lookahead_repository_slice_observation_p0/artifacts/verification.json"
    );
    let upstream_request = from_sjs_rso_request_machine_form(canonical_evidence_body(
        RSO_REQUEST,
        "published RSO request",
    )?)
    .map_err(upstream_fault)?;
    let upstream_receipt = from_sjs_rso_receipt_machine_form(
        &upstream_request,
        canonical_evidence_body(RSO_RECEIPT, "published RSO receipt")?,
    )
    .map_err(upstream_fault)?;
    let upstream_verification = from_sjs_rso_verification_machine_form(
        &upstream_request,
        &upstream_receipt,
        canonical_evidence_body(RSO_VERIFICATION, "published RSO verification")?,
    )
    .map_err(upstream_fault)?;
    seal_sjs_rsp_request(SjsRspRequest {
        profile: SJS_RSP_REQUEST_PROFILE.to_owned(),
        request_id: fixed_id("request:86000000-0000-4000-8000-000000000001")?,
        run_id: fixed_id("run:86000000-0000-4000-8000-000000000002")?,
        receipt_id: fixed_id("receipt:86000000-0000-4000-8000-000000000003")?,
        downstream_request_id: fixed_id("request:86000000-0000-4000-8000-000000000004")?,
        downstream_run_id: fixed_id("run:86000000-0000-4000-8000-000000000005")?,
        downstream_packet_id: fixed_id("packet:86000000-0000-4000-8000-000000000006")?,
        downstream_policy_id: fixed_id("policy:86000000-0000-4000-8000-000000000007")?,
        input_class: SjsRspInputClass::SyntheticProviderFreeFixture,
        canonical_uuid: SJS_RSP_CANONICAL_UUID.to_owned(),
        signature_uuid: SJS_RSP_SIGNATURE_UUID.to_owned(),
        source_snapshot_uuid: SJS_RSP_SOURCE_UUID.to_owned(),
        parent_observation_canonical_uuid: SJS_RSO_CANONICAL_UUID.to_owned(),
        parent_observation_completion_signature_uuid: SJS_RSP_RSO_COMPLETION_UUID.to_owned(),
        parent_observation_implementation_commit: SJS_RSP_RSO_IMPLEMENTATION_COMMIT.to_owned(),
        parent_observation_bookend_commit: SJS_RSP_RSO_BOOKEND_COMMIT.to_owned(),
        parent_observation_closure_commit: SJS_RSP_RSO_CLOSURE_COMMIT.to_owned(),
        stitch_canonical_uuid: SJS_LAS_CANONICAL_UUID.to_owned(),
        stitch_completion_signature_uuid: SJS_RSP_STITCH_COMPLETION_UUID.to_owned(),
        upstream_request,
        upstream_receipt,
        upstream_verification,
        provider_profile: "fixture-provider-declaration/0.1".to_owned(),
        invocation_ordinal: 1,
        boundary_kind: SjsLasBoundaryKind::Initial,
        evidence_refs: [fixed_id("evidence:86000000-0000-4000-8000-000000000008")?]
            .into_iter()
            .collect(),
        non_authority: SJS_RSP_NON_AUTHORITY.to_owned(),
        request_digest: empty_digest(),
    })
}

pub fn seal_sjs_rsp_request(mut request: SjsRspRequest) -> Result<SjsRspRequest, SjsRspFault> {
    request.request_digest = empty_digest();
    validate_request_body(&request)?;
    request.request_digest = sha256_form(REQUEST_DOMAIN, &request)?;
    validate_sjs_rsp_request(&request)?;
    Ok(request)
}

pub fn validate_sjs_rsp_request(request: &SjsRspRequest) -> Result<(), SjsRspFault> {
    validate_request_body(request)?;
    let expected = digest_without(request, REQUEST_DOMAIN, |value| &mut value.request_digest)?;
    if request.request_digest != expected {
        return Err(fault(
            SjsRspFaultCode::InvalidDigest,
            "request digest differs",
        ));
    }
    Ok(())
}

pub fn compile_sjs_rsp(request: &SjsRspRequest) -> Result<SjsRspEnvelope, SjsRspFault> {
    validate_sjs_rsp_request(request)?;
    let envelope = compile_internal(request)?;
    validate_sjs_rsp_envelope(&envelope)?;
    Ok(envelope)
}

pub fn validate_sjs_rsp_envelope(envelope: &SjsRspEnvelope) -> Result<(), SjsRspFault> {
    if envelope.profile != SJS_RSP_ENVELOPE_PROFILE
        || envelope.execution_authorized
        || envelope.effects != SjsLasEffectAccount::default()
    {
        return Err(fault(
            SjsRspFaultCode::InvalidAuthority,
            "envelope profile authority or effects differ",
        ));
    }
    validate_sjs_rsp_request(&envelope.request)?;
    let expected = compile_internal(&envelope.request)?;
    if envelope.downstream_request != expected.downstream_request
        || envelope.downstream_envelope != expected.downstream_envelope
        || envelope.downstream_verification != expected.downstream_verification
        || envelope.receipt != expected.receipt
    {
        return Err(fault(
            SjsRspFaultCode::InvalidAccount,
            "independent projection replay differs",
        ));
    }
    let expected_digest = digest_without(envelope, ENVELOPE_DOMAIN, |value| {
        &mut value.envelope_digest
    })?;
    if envelope.envelope_digest != expected_digest {
        return Err(fault(
            SjsRspFaultCode::InvalidDigest,
            "envelope digest differs",
        ));
    }
    Ok(())
}

pub fn verify_sjs_rsp(envelope: &SjsRspEnvelope) -> Result<SjsRspVerification, SjsRspFault> {
    validate_sjs_rsp_envelope(envelope)?;
    let mut verification = verification_from(envelope)?;
    verification.verification_digest = sha256_form(VERIFICATION_DOMAIN, &verification)?;
    validate_sjs_rsp_verification(envelope, &verification)?;
    Ok(verification)
}

pub fn validate_sjs_rsp_verification(
    envelope: &SjsRspEnvelope,
    verification: &SjsRspVerification,
) -> Result<(), SjsRspFault> {
    validate_sjs_rsp_envelope(envelope)?;
    let mut expected = verification_from(envelope)?;
    expected.verification_digest = sha256_form(VERIFICATION_DOMAIN, &expected)?;
    if verification != &expected {
        return Err(fault(
            SjsRspFaultCode::InvalidAccount,
            "verification differs from independent projection replay",
        ));
    }
    Ok(())
}

pub fn to_sjs_rsp_request_machine_form(request: &SjsRspRequest) -> Result<String, SjsRspFault> {
    validate_sjs_rsp_request(request)?;
    to_machine_form(request)
}

pub fn from_sjs_rsp_request_machine_form(value: &str) -> Result<SjsRspRequest, SjsRspFault> {
    let request = parse_bounded(value)?;
    validate_sjs_rsp_request(&request)?;
    Ok(request)
}

pub fn to_sjs_rsp_envelope_machine_form(envelope: &SjsRspEnvelope) -> Result<String, SjsRspFault> {
    validate_sjs_rsp_envelope(envelope)?;
    to_machine_form(envelope)
}

pub fn from_sjs_rsp_envelope_machine_form(value: &str) -> Result<SjsRspEnvelope, SjsRspFault> {
    let envelope = parse_bounded(value)?;
    validate_sjs_rsp_envelope(&envelope)?;
    Ok(envelope)
}

pub fn to_sjs_rsp_verification_machine_form(
    envelope: &SjsRspEnvelope,
    verification: &SjsRspVerification,
) -> Result<String, SjsRspFault> {
    validate_sjs_rsp_verification(envelope, verification)?;
    to_machine_form(verification)
}

pub fn from_sjs_rsp_verification_machine_form(
    envelope: &SjsRspEnvelope,
    value: &str,
) -> Result<SjsRspVerification, SjsRspFault> {
    let verification = parse_bounded(value)?;
    validate_sjs_rsp_verification(envelope, &verification)?;
    Ok(verification)
}

pub fn build_sjs_rsp_evidence_bundle(
    request: &SjsRspRequest,
    envelope: &SjsRspEnvelope,
    verification: &SjsRspVerification,
    replay_envelope: &SjsRspEnvelope,
    replay_verification: &SjsRspVerification,
) -> Result<SjsRspEvidenceBundle, SjsRspFault> {
    validate_sjs_rsp_request(request)?;
    validate_sjs_rsp_envelope(envelope)?;
    validate_sjs_rsp_verification(envelope, verification)?;
    validate_sjs_rsp_envelope(replay_envelope)?;
    validate_sjs_rsp_verification(replay_envelope, replay_verification)?;
    if envelope.request != *request
        || replay_envelope.request != *request
        || replay_envelope != envelope
        || replay_verification != verification
    {
        return Err(fault(
            SjsRspFaultCode::InvalidAccount,
            "evidence replay differs",
        ));
    }
    let request_file = canonical_evidence_file(to_sjs_rsp_request_machine_form(request)?);
    let envelope_file = canonical_evidence_file(to_sjs_rsp_envelope_machine_form(envelope)?);
    let verification_file = canonical_evidence_file(to_sjs_rsp_verification_machine_form(
        envelope,
        verification,
    )?);
    let mut files = BTreeMap::new();
    for (name, value) in [
        (REQUEST_FILE, &request_file),
        (ENVELOPE_FILE, &envelope_file),
        (VERIFICATION_FILE, &verification_file),
    ] {
        files.insert(name.to_owned(), evidence_file(value)?);
    }
    let manifest = manifest_from(verification, files)?;
    let manifest_file = canonical_evidence_file(to_machine_form(&manifest)?);
    let bundle = SjsRspEvidenceBundle {
        request_file,
        envelope_file,
        verification_file,
        manifest_file,
    };
    ensure_evidence_bound(&bundle)?;
    verify_sjs_rsp_evidence_bundle(&bundle)?;
    Ok(bundle)
}

pub fn verify_sjs_rsp_evidence_bundle(
    bundle: &SjsRspEvidenceBundle,
) -> Result<SjsRspVerification, SjsRspFault> {
    ensure_evidence_bound(bundle)?;
    let request = from_sjs_rsp_request_machine_form(canonical_evidence_body(
        &bundle.request_file,
        REQUEST_FILE,
    )?)?;
    let retained_envelope = from_sjs_rsp_envelope_machine_form(canonical_evidence_body(
        &bundle.envelope_file,
        ENVELOPE_FILE,
    )?)?;
    if retained_envelope.request != request {
        return Err(fault(
            SjsRspFaultCode::InvalidAccount,
            "evidence request and envelope differ",
        ));
    }
    let retained_verification = from_sjs_rsp_verification_machine_form(
        &retained_envelope,
        canonical_evidence_body(&bundle.verification_file, VERIFICATION_FILE)?,
    )?;
    let manifest: SjsRspEvidenceManifest = parse_bounded(canonical_evidence_body(
        &bundle.manifest_file,
        MANIFEST_FILE,
    )?)?;
    let replay_envelope = compile_sjs_rsp(&request)?;
    let replay_verification = verify_sjs_rsp(&replay_envelope)?;
    if retained_envelope != replay_envelope || retained_verification != replay_verification {
        return Err(fault(
            SjsRspFaultCode::InvalidAccount,
            "retained evidence differs from pure replay",
        ));
    }
    let mut files = BTreeMap::new();
    for (name, value) in [
        (REQUEST_FILE, &bundle.request_file),
        (ENVELOPE_FILE, &bundle.envelope_file),
        (VERIFICATION_FILE, &bundle.verification_file),
    ] {
        files.insert(name.to_owned(), evidence_file(value)?);
    }
    let expected_manifest = manifest_from(&replay_verification, files)?;
    if manifest != expected_manifest {
        return Err(fault(
            SjsRspFaultCode::InvalidAccount,
            "evidence manifest differs",
        ));
    }
    Ok(replay_verification)
}

pub fn to_sjs_rsp_evidence_bundle_machine_form(
    bundle: &SjsRspEvidenceBundle,
) -> Result<String, SjsRspFault> {
    verify_sjs_rsp_evidence_bundle(bundle)?;
    let value = serde_json::to_string(bundle).map_err(machine_fault)?;
    if value.len() > SJS_RSP_MAX_EVIDENCE_BUNDLE_BYTES {
        return Err(fault(
            SjsRspFaultCode::InvalidBound,
            "evidence carrier exceeds 8388608 bytes",
        ));
    }
    Ok(value)
}

pub fn from_sjs_rsp_evidence_bundle_machine_form(
    value: &str,
) -> Result<SjsRspEvidenceBundle, SjsRspFault> {
    if value.len() > SJS_RSP_MAX_EVIDENCE_BUNDLE_BYTES {
        return Err(fault(
            SjsRspFaultCode::InvalidBound,
            "evidence carrier exceeds 8388608 bytes",
        ));
    }
    let mut deserializer = serde_json::Deserializer::from_str(value);
    NoDuplicateJson::deserialize(&mut deserializer).map_err(machine_fault)?;
    deserializer.end().map_err(machine_fault)?;
    let bundle: SjsRspEvidenceBundle = serde_json::from_str(value).map_err(machine_fault)?;
    if serde_json::to_string(&bundle).map_err(machine_fault)? != value {
        return Err(fault(
            SjsRspFaultCode::InvalidMachineForm,
            "evidence carrier is not compact canonical JSON",
        ));
    }
    verify_sjs_rsp_evidence_bundle(&bundle)?;
    Ok(bundle)
}

fn compile_internal(request: &SjsRspRequest) -> Result<SjsRspEnvelope, SjsRspFault> {
    let downstream_request = downstream_request_from(request)?;
    let downstream_envelope = compile_sjs_las(&downstream_request).map_err(downstream_fault)?;
    let downstream_verification = verify_sjs_las(&downstream_envelope).map_err(downstream_fault)?;
    validate_mapping(
        request,
        &downstream_request,
        &downstream_envelope,
        &downstream_verification,
    )?;
    let receipt = receipt_from(
        request,
        &downstream_request,
        &downstream_envelope,
        &downstream_verification,
    )?;
    let mut envelope = SjsRspEnvelope {
        profile: SJS_RSP_ENVELOPE_PROFILE.to_owned(),
        request: request.clone(),
        downstream_request,
        downstream_envelope,
        downstream_verification,
        receipt,
        execution_authorized: false,
        effects: SjsLasEffectAccount::default(),
        envelope_digest: empty_digest(),
    };
    envelope.envelope_digest = sha256_form(ENVELOPE_DOMAIN, &envelope)?;
    Ok(envelope)
}

fn downstream_request_from(request: &SjsRspRequest) -> Result<SjsLasRequest, SjsRspFault> {
    let selected = selected_candidates(request)?;
    let selection_scope = &request
        .upstream_receipt
        .parent_envelope
        .downstream_envelope
        .request
        .scope;
    let mut mapped = selected
        .iter()
        .map(|candidate| {
            let stitch_id = derived_id("stitch", &candidate.candidate_id)?;
            let mut declaration = SjsLasStitchDeclaration {
                stitch_id,
                predecessor_id: None,
                subject_anchor: candidate.subject_anchor.clone(),
                semantic_turn: candidate.semantic_turn.clone(),
                transform: candidate.transform.clone(),
                scope_id: candidate.scope_id.clone(),
                key_hints: vec![candidate.projected_surface.clone()],
                source_bindings: vec![candidate.source_binding.clone()],
                completion_cue: candidate.completion_cue.clone(),
                invalidators: candidate.invalidators.clone(),
                declaration_digest: empty_digest(),
            };
            declaration.invalidators.sort_by(|left, right| {
                (&left.field, &left.equals).cmp(&(&right.field, &right.equals))
            });
            declaration.declaration_digest =
                sjs_las_stitch_digest(&declaration).map_err(downstream_fault)?;
            Ok((candidate.candidate_id.clone(), declaration))
        })
        .collect::<Result<Vec<_>, SjsRspFault>>()?;
    mapped.sort_by(|left, right| left.1.stitch_id.cmp(&right.1.stitch_id));
    if mapped
        .windows(2)
        .any(|pair| pair[0].1.stitch_id == pair[1].1.stitch_id)
    {
        return Err(fault(
            SjsRspFaultCode::InvalidIdentity,
            "derived stitch identities collide",
        ));
    }
    let stitches = mapped
        .iter()
        .map(|(_, declaration)| declaration.clone())
        .collect::<Vec<_>>();
    let source_identities = stitches
        .iter()
        .flat_map(|stitch| {
            stitch
                .source_bindings
                .iter()
                .map(|binding| binding.source_id.clone())
        })
        .collect::<BTreeSet<_>>();
    let completion_conditions = stitches
        .iter()
        .map(|stitch| predicate_text(&stitch.completion_cue))
        .collect::<BTreeSet<_>>();
    let invalidation_conditions = stitches
        .iter()
        .flat_map(|stitch| stitch.invalidators.iter().map(predicate_text))
        .collect::<BTreeSet<_>>();
    let mut scope = SjsLasExactScope {
        scope_id: selection_scope.scope_id.clone(),
        source_identities,
        objective: selection_scope.objective.clone(),
        phase: selection_scope.phase.clone(),
        feature: selection_scope.feature.clone(),
        requirement: selection_scope.requirement.clone(),
        artifact: selection_scope.artifact.clone(),
        invocation_start: request.invocation_ordinal,
        invocation_end: request.invocation_ordinal,
        model_profile: selection_scope.model_profile.clone(),
        provider_profile: request.provider_profile.clone(),
        tool_policy: selection_scope.tool_policy.clone(),
        authority_ceiling: selection_scope.authority_ceiling.clone(),
        completion_conditions,
        invalidation_conditions,
        scope_exit_cue: SjsLasPredicate {
            field: "scope_state".to_owned(),
            equals: "exited".to_owned(),
        },
        scope_digest: empty_digest(),
    };
    scope.scope_digest = sjs_las_scope_digest(&scope).map_err(downstream_fault)?;
    let observations = stitches
        .iter()
        .enumerate()
        .map(|(index, stitch)| {
            Ok(SjsLasObservation {
                observation_id: derived_id("observation", &stitch.stitch_id)?,
                ordinal: count_u32(index + 1, "observation count")?,
                kind: SjsLasObservationKind::Activate,
                stitch_id: Some(stitch.stitch_id.clone()),
                fields: BTreeMap::new(),
            })
        })
        .collect::<Result<Vec<_>, SjsRspFault>>()?;
    let latest_observation = observations.last().ok_or_else(|| {
        fault(
            SjsRspFaultCode::InvalidBound,
            "selected candidate set is empty",
        )
    })?;
    let coordinate = SjsLasInvocationCoordinate {
        coordinate_id: derived_id("coordinate", &request.downstream_packet_id)?,
        ordinal: 1,
        after_observation_ordinal: latest_observation.ordinal,
        invocation_ordinal: request.invocation_ordinal,
        phase: scope.phase.clone(),
        objective: scope.objective.clone(),
        feature: scope.feature.clone(),
        requirement: scope.requirement.clone(),
        artifact: scope.artifact.clone(),
        model_profile: scope.model_profile.clone(),
        provider_profile: scope.provider_profile.clone(),
        tool_policy: scope.tool_policy.clone(),
        authority_ceiling: scope.authority_ceiling.clone(),
        boundary_kind: request.boundary_kind,
        last_accepted_receipt_id: Some(derived_id("receipt", &latest_observation.observation_id)?),
    };
    seal_sjs_las_request(SjsLasRequest {
        profile: SJS_LAS_REQUEST_PROFILE.to_owned(),
        request_id: request.downstream_request_id.clone(),
        run_id: request.downstream_run_id.clone(),
        packet_id: request.downstream_packet_id.clone(),
        policy_id: request.downstream_policy_id.clone(),
        input_class: SjsLasInputClass::SuppliedUnobservedDeclaration,
        canonical_uuid: SJS_LAS_CANONICAL_UUID.to_owned(),
        signature_uuid: SJS_LAS_SIGNATURE_UUID.to_owned(),
        source_snapshot_uuid: SJS_LAS_SOURCE_UUID.to_owned(),
        parent_source_uuid: SJS_LAS_PARENT_SOURCE_UUID.to_owned(),
        scope,
        stitches,
        observations,
        coordinates: vec![coordinate],
        evidence_refs: request.evidence_refs.clone(),
        non_authority: SJS_LAS_NON_AUTHORITY.to_owned(),
        request_digest: empty_digest(),
    })
    .map_err(downstream_fault)
}

fn validate_mapping(
    request: &SjsRspRequest,
    downstream_request: &SjsLasRequest,
    downstream_envelope: &SjsLasEnvelope,
    downstream_verification: &SjsLasVerification,
) -> Result<(), SjsRspFault> {
    let selected = selected_candidates(request)?;
    if downstream_envelope.request != *downstream_request
        || verify_sjs_las(downstream_envelope).map_err(downstream_fault)?
            != *downstream_verification
        || downstream_envelope.authority != SjsLasAuthority::SuppliedPublicStitchCompilationOnly
        || downstream_envelope.execution_authorized
        || downstream_envelope.effects != SjsLasEffectAccount::default()
        || downstream_verification.execution_authorized
        || downstream_verification.effects != SjsLasEffectAccount::default()
    {
        return Err(fault(
            SjsRspFaultCode::InvalidAuthority,
            "downstream authority or verifier correspondence differs",
        ));
    }
    let by_stitch = selected
        .iter()
        .map(|candidate| Ok((derived_id("stitch", &candidate.candidate_id)?, candidate)))
        .collect::<Result<BTreeMap<_, _>, SjsRspFault>>()?;
    if by_stitch.len() != selected.len() || downstream_request.stitches.len() != selected.len() {
        return Err(fault(
            SjsRspFaultCode::InvalidMapping,
            "selected-to-stitch cardinality differs",
        ));
    }
    for stitch in &downstream_request.stitches {
        let candidate = by_stitch.get(&stitch.stitch_id).ok_or_else(|| {
            fault(
                SjsRspFaultCode::InvalidMapping,
                "unselected stitch entered projection",
            )
        })?;
        if stitch.predecessor_id.is_some()
            || stitch.subject_anchor != candidate.subject_anchor
            || stitch.semantic_turn != candidate.semantic_turn
            || stitch.transform != candidate.transform
            || stitch.scope_id != candidate.scope_id
            || stitch.key_hints != [candidate.projected_surface.clone()]
            || stitch.source_bindings != [candidate.source_binding.clone()]
            || stitch.completion_cue != candidate.completion_cue
            || stitch.invalidators != candidate.invalidators
        {
            return Err(fault(
                SjsRspFaultCode::InvalidMapping,
                "selected candidate field mapping differs",
            ));
        }
    }
    let expected_count = count_u32(selected.len(), "selected count")?;
    if downstream_verification.stitch_count != expected_count
        || downstream_verification.hint_count != expected_count
        || downstream_verification.source_binding_count != expected_count
        || downstream_verification.observation_count != expected_count
        || downstream_verification.activation_count != expected_count
        || downstream_verification.coordinate_count != 1
        || downstream_verification.projection_count != 1
        || downstream_verification.projected_inclusion_count != expected_count
        || downstream_verification.initial_boundary_count != 1
        || downstream_verification.stop_boundary_count != 0
        || downstream_verification.tool_result_boundary_count != 0
        || downstream_verification.reentry_boundary_count != 0
        || downstream_verification.fulfillment_count != 0
        || downstream_verification.invalidation_count != 0
        || downstream_verification.release_count != 0
        || downstream_verification.refused_transition_count != 0
        || downstream_envelope
            .final_states
            .iter()
            .any(|state| state.state != SjsLasLifecycleState::Active)
    {
        return Err(fault(
            SjsRspFaultCode::InvalidMapping,
            "downstream lifecycle or projection counts differ",
        ));
    }
    Ok(())
}

fn receipt_from(
    request: &SjsRspRequest,
    downstream_request: &SjsLasRequest,
    downstream_envelope: &SjsLasEnvelope,
    downstream_verification: &SjsLasVerification,
) -> Result<SjsRspReceipt, SjsRspFault> {
    let selected = selected_candidates(request)?;
    let selected_by_stitch = selected
        .iter()
        .map(|candidate| Ok((derived_id("stitch", &candidate.candidate_id)?, candidate)))
        .collect::<Result<BTreeMap<_, _>, SjsRspFault>>()?;
    let selected_candidate_digests = downstream_request
        .stitches
        .iter()
        .map(|stitch| {
            selected_by_stitch
                .get(&stitch.stitch_id)
                .map(|candidate| candidate.candidate_digest.clone())
                .ok_or_else(|| fault(SjsRspFaultCode::InvalidMapping, "receipt candidate absent"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut receipt = SjsRspReceipt {
        receipt_id: request.receipt_id.clone(),
        request_digest: request.request_digest.clone(),
        upstream_request_digest: request.upstream_request.request_digest.clone(),
        upstream_receipt_digest: request.upstream_receipt.receipt_digest.clone(),
        upstream_verification_digest: request.upstream_verification.verification_digest.clone(),
        downstream_request_digest: downstream_request.request_digest.clone(),
        downstream_envelope_digest: downstream_envelope.envelope_digest.clone(),
        downstream_verification_digest: sha256_form(
            DOWNSTREAM_VERIFICATION_DOMAIN,
            downstream_verification,
        )?,
        selected_candidate_digests,
        selected_count: downstream_verification.stitch_count,
        stitch_count: downstream_verification.stitch_count,
        hint_count: downstream_verification.hint_count,
        source_binding_count: downstream_verification.source_binding_count,
        observation_count: downstream_verification.observation_count,
        coordinate_count: downstream_verification.coordinate_count,
        projection_count: downstream_verification.projection_count,
        projected_inclusion_count: downstream_verification.projected_inclusion_count,
        projected_bytes: downstream_verification.total_projected_bytes,
        physical_input_account_count: count_u32(
            request.upstream_receipt.accounts.len(),
            "physical input account count",
        )?,
        historical_physical_contact: true,
        current_effects: SjsLasEffectAccount::default(),
        receipt_digest: empty_digest(),
    };
    receipt.receipt_digest = sha256_form(RECEIPT_DOMAIN, &receipt)?;
    Ok(receipt)
}

fn verification_from(envelope: &SjsRspEnvelope) -> Result<SjsRspVerification, SjsRspFault> {
    let receipt = &envelope.receipt;
    Ok(SjsRspVerification {
        profile: SJS_RSP_VERIFICATION_PROFILE.to_owned(),
        status: "verified_repository_selection_projected_to_stitch_only".to_owned(),
        canonical_uuid: SJS_RSP_CANONICAL_UUID.to_owned(),
        signature_uuid: SJS_RSP_SIGNATURE_UUID.to_owned(),
        input_class: envelope.request.input_class,
        request_digest: envelope.request.request_digest.clone(),
        envelope_digest: envelope.envelope_digest.clone(),
        receipt_digest: receipt.receipt_digest.clone(),
        upstream_request_digest: receipt.upstream_request_digest.clone(),
        upstream_receipt_digest: receipt.upstream_receipt_digest.clone(),
        upstream_verification_digest: receipt.upstream_verification_digest.clone(),
        downstream_request_digest: receipt.downstream_request_digest.clone(),
        downstream_envelope_digest: receipt.downstream_envelope_digest.clone(),
        downstream_verification_digest: receipt.downstream_verification_digest.clone(),
        selected_count: receipt.selected_count,
        stitch_count: receipt.stitch_count,
        hint_count: receipt.hint_count,
        source_binding_count: receipt.source_binding_count,
        observation_count: receipt.observation_count,
        coordinate_count: receipt.coordinate_count,
        projection_count: receipt.projection_count,
        projected_inclusion_count: receipt.projected_inclusion_count,
        projected_bytes: receipt.projected_bytes,
        physical_input_account_count: receipt.physical_input_account_count,
        historical_physical_contact: receipt.historical_physical_contact,
        downstream_authority: envelope.downstream_envelope.authority,
        execution_authorized: false,
        effects: SjsLasEffectAccount::default(),
        verification_digest: empty_digest(),
    })
}

fn selected_candidates(
    request: &SjsRspRequest,
) -> Result<&[cantor_core::SjsLtoTermCandidate], SjsRspFault> {
    let envelope = &request.upstream_receipt.parent_envelope;
    let selected = envelope.downstream_envelope.selected_candidates.as_slice();
    let selected_ids = selected
        .iter()
        .map(|candidate| candidate.candidate_id.clone())
        .collect::<Vec<_>>();
    let expected_count = count_u32(selected.len(), "selected count")?;
    if selected.is_empty() || selected.len() > MAX_SELECTED {
        return Err(fault(
            SjsRspFaultCode::InvalidBound,
            "selected candidate count exceeds one-through-eight bound",
        ));
    }
    if selected_ids != envelope.downstream_envelope.receipt.selected_candidate_ids
        || envelope.receipt.downstream_selected_count != expected_count
        || envelope.downstream_verification.selected_count != expected_count
        || request
            .upstream_verification
            .parent_verification
            .selected_count
            != expected_count
        || envelope.downstream_verification.result_status != SjsLtoResultStatus::SelectedExact
    {
        return Err(fault(
            SjsRspFaultCode::InvalidUpstream,
            "upstream canonical selected set differs",
        ));
    }
    Ok(selected)
}

fn validate_request_body(request: &SjsRspRequest) -> Result<(), SjsRspFault> {
    if request.profile != SJS_RSP_REQUEST_PROFILE {
        return Err(fault(
            SjsRspFaultCode::InvalidProfile,
            "request profile differs",
        ));
    }
    if request.canonical_uuid != SJS_RSP_CANONICAL_UUID
        || request.signature_uuid != SJS_RSP_SIGNATURE_UUID
        || request.source_snapshot_uuid != SJS_RSP_SOURCE_UUID
        || request.parent_observation_canonical_uuid != SJS_RSO_CANONICAL_UUID
        || request.parent_observation_completion_signature_uuid != SJS_RSP_RSO_COMPLETION_UUID
        || request.parent_observation_implementation_commit != SJS_RSP_RSO_IMPLEMENTATION_COMMIT
        || request.parent_observation_bookend_commit != SJS_RSP_RSO_BOOKEND_COMMIT
        || request.parent_observation_closure_commit != SJS_RSP_RSO_CLOSURE_COMMIT
        || request.stitch_canonical_uuid != SJS_LAS_CANONICAL_UUID
        || request.stitch_completion_signature_uuid != SJS_RSP_STITCH_COMPLETION_UUID
    {
        return Err(fault(
            SjsRspFaultCode::InvalidIdentity,
            "governing lineage identity differs",
        ));
    }
    let identities = [
        (&request.request_id, "request"),
        (&request.run_id, "run"),
        (&request.receipt_id, "receipt"),
        (&request.downstream_request_id, "request"),
        (&request.downstream_run_id, "run"),
        (&request.downstream_packet_id, "packet"),
        (&request.downstream_policy_id, "policy"),
    ];
    let mut uuid_components = BTreeSet::new();
    for (identity, prefix) in identities {
        validate_uuid_id(identity, prefix)?;
        uuid_components.insert(uuid_component(identity)?.to_owned());
    }
    if uuid_components.len() != 7 {
        return Err(fault(
            SjsRspFaultCode::InvalidIdentity,
            "projection and downstream UUID components are not distinct",
        ));
    }
    validate_text(&request.provider_profile, "provider profile")?;
    if request.invocation_ordinal == 0 || request.boundary_kind != SjsLasBoundaryKind::Initial {
        return Err(fault(
            SjsRspFaultCode::InvalidBound,
            "invocation ordinal or boundary differs",
        ));
    }
    if request.evidence_refs.is_empty() || request.evidence_refs.len() > MAX_EVIDENCE_REFS {
        return Err(fault(
            SjsRspFaultCode::InvalidBound,
            "evidence reference bounds differ",
        ));
    }
    for reference in &request.evidence_refs {
        validate_uuid_id(reference, "evidence")?;
    }
    if request.non_authority != SJS_RSP_NON_AUTHORITY {
        return Err(fault(
            SjsRspFaultCode::InvalidAuthority,
            "request nonauthority differs",
        ));
    }
    let selected = selected_candidates(request)?;
    validate_upstream(request)?;
    for candidate in selected {
        if candidate.projected_surface.is_empty()
            || candidate.projected_bytes
                != u64::try_from(candidate.projected_surface.len()).map_err(|_| {
                    fault(
                        SjsRspFaultCode::ArithmeticOverflow,
                        "projected bytes exceed u64",
                    )
                })?
        {
            return Err(fault(
                SjsRspFaultCode::InvalidMapping,
                "selected projected surface differs",
            ));
        }
        validate_uuid_id(&derived_id("stitch", &candidate.candidate_id)?, "stitch")?;
    }
    let fixed_fixture =
        request.request_id.as_str() == "request:86000000-0000-4000-8000-000000000001";
    if fixed_fixture && request.input_class != SjsRspInputClass::SyntheticProviderFreeFixture {
        return Err(fault(
            SjsRspFaultCode::InvalidInputClass,
            "known synthetic fixture cannot be relabeled",
        ));
    }
    if request.input_class == SjsRspInputClass::SyntheticProviderFreeFixture
        && (request.request_id.as_str() != "request:86000000-0000-4000-8000-000000000001"
            || request.run_id.as_str() != "run:86000000-0000-4000-8000-000000000002"
            || request.receipt_id.as_str() != "receipt:86000000-0000-4000-8000-000000000003"
            || request.downstream_request_id.as_str()
                != "request:86000000-0000-4000-8000-000000000004"
            || request.downstream_run_id.as_str() != "run:86000000-0000-4000-8000-000000000005"
            || request.downstream_packet_id.as_str()
                != "packet:86000000-0000-4000-8000-000000000006"
            || request.downstream_policy_id.as_str()
                != "policy:86000000-0000-4000-8000-000000000007"
            || request.provider_profile != "fixture-provider-declaration/0.1"
            || request.invocation_ordinal != 1
            || selected.len() != 3
            || request.upstream_receipt.accounts.len() != 8
            || request
                .upstream_verification
                .parent_verification
                .rejected_count
                != 5
            || request
                .upstream_verification
                .parent_verification
                .dominated_count
                != 1
            || request
                .upstream_verification
                .parent_verification
                .uncovered_count
                != 0)
    {
        return Err(fault(
            SjsRspFaultCode::InvalidInputClass,
            "synthetic fixture shape differs",
        ));
    }
    Ok(())
}

fn validate_upstream(request: &SjsRspRequest) -> Result<(), SjsRspFault> {
    validate_sjs_rso_request(&request.upstream_request).map_err(upstream_fault)?;
    validate_sjs_rso_receipt(&request.upstream_request, &request.upstream_receipt)
        .map_err(upstream_fault)?;
    validate_sjs_rso_verification(
        &request.upstream_request,
        &request.upstream_receipt,
        &request.upstream_verification,
    )
    .map_err(upstream_fault)?;
    let replay = verify_sjs_rso_receipt(&request.upstream_request, &request.upstream_receipt)
        .map_err(upstream_fault)?;
    if replay != request.upstream_verification
        || request.upstream_verification.status != "verified_exact_commit_tree_observation"
        || !request.upstream_receipt.physical_contact
        || !request.upstream_verification.physical_contact
        || request.upstream_verification.execution_authorized
        || request.upstream_receipt.effects != expected_upstream_effects()
        || request.upstream_verification.effects != expected_upstream_effects()
        || request
            .upstream_receipt
            .parent_envelope
            .execution_authorized
        || request.upstream_receipt.parent_envelope.effects != Default::default()
    {
        return Err(fault(
            SjsRspFaultCode::InvalidUpstream,
            "upstream verification authority or effects differ",
        ));
    }
    Ok(())
}

fn expected_upstream_effects() -> SjsRsoEffectAccount {
    SjsRsoEffectAccount {
        read_only_filesystem_observation: true,
        read_only_git_process_observation: true,
        ..SjsRsoEffectAccount::default()
    }
}

fn manifest_from(
    verification: &SjsRspVerification,
    files: BTreeMap<String, SjsRspEvidenceFile>,
) -> Result<SjsRspEvidenceManifest, SjsRspFault> {
    let expected_names = [REQUEST_FILE, ENVELOPE_FILE, VERIFICATION_FILE]
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if files.keys().cloned().collect::<BTreeSet<_>>() != expected_names {
        return Err(fault(
            SjsRspFaultCode::InvalidAccount,
            "manifest preimage file set differs",
        ));
    }
    Ok(SjsRspEvidenceManifest {
        profile: SJS_RSP_EVIDENCE_PROFILE.to_owned(),
        canonical_uuid: SJS_RSP_CANONICAL_UUID.to_owned(),
        signature_uuid: SJS_RSP_SIGNATURE_UUID.to_owned(),
        replay_count: 2,
        files,
        request_digest: verification.request_digest.clone(),
        envelope_digest: verification.envelope_digest.clone(),
        receipt_digest: verification.receipt_digest.clone(),
        verification_digest: verification.verification_digest.clone(),
        upstream_request_digest: verification.upstream_request_digest.clone(),
        upstream_receipt_digest: verification.upstream_receipt_digest.clone(),
        upstream_verification_digest: verification.upstream_verification_digest.clone(),
        downstream_request_digest: verification.downstream_request_digest.clone(),
        downstream_envelope_digest: verification.downstream_envelope_digest.clone(),
        downstream_verification_digest: verification.downstream_verification_digest.clone(),
        selected_count: verification.selected_count,
        stitch_count: verification.stitch_count,
        hint_count: verification.hint_count,
        source_binding_count: verification.source_binding_count,
        observation_count: verification.observation_count,
        coordinate_count: verification.coordinate_count,
        projection_count: verification.projection_count,
        projected_inclusion_count: verification.projected_inclusion_count,
        projected_bytes: verification.projected_bytes,
        physical_input_account_count: verification.physical_input_account_count,
        historical_physical_contact: verification.historical_physical_contact,
        execution_authorized: false,
        effects: SjsLasEffectAccount::default(),
    })
}

fn evidence_file(value: &str) -> Result<SjsRspEvidenceFile, SjsRspFault> {
    Ok(SjsRspEvidenceFile {
        bytes: u64::try_from(value.len()).map_err(|_| {
            fault(
                SjsRspFaultCode::ArithmeticOverflow,
                "evidence bytes exceed u64",
            )
        })?,
        sha256: sha256_bytes(value.as_bytes()),
    })
}

fn canonical_evidence_file(mut value: String) -> String {
    value.push('\n');
    value
}

fn canonical_evidence_body<'a>(value: &'a str, label: &str) -> Result<&'a str, SjsRspFault> {
    let body = value.strip_suffix('\n').ok_or_else(|| {
        fault(
            SjsRspFaultCode::InvalidMachineForm,
            format!("{label} lacks one terminal LF"),
        )
    })?;
    if body.is_empty() || body.contains(['\r', '\n']) {
        return Err(fault(
            SjsRspFaultCode::InvalidMachineForm,
            format!("{label} is not one compact LF-terminated UTF-8 form"),
        ));
    }
    Ok(body)
}

fn ensure_evidence_bound(bundle: &SjsRspEvidenceBundle) -> Result<(), SjsRspFault> {
    let mut total = 0usize;
    for (label, value) in [
        (REQUEST_FILE, &bundle.request_file),
        (ENVELOPE_FILE, &bundle.envelope_file),
        (VERIFICATION_FILE, &bundle.verification_file),
        (MANIFEST_FILE, &bundle.manifest_file),
    ] {
        if value.len() > SJS_RSP_MAX_MACHINE_FORM_BYTES {
            return Err(fault(
                SjsRspFaultCode::InvalidBound,
                format!("{label} exceeds 1048576 bytes"),
            ));
        }
        total = total.checked_add(value.len()).ok_or_else(|| {
            fault(
                SjsRspFaultCode::ArithmeticOverflow,
                "evidence total overflow",
            )
        })?;
        canonical_evidence_body(value, label)?;
    }
    if total > SJS_RSP_MAX_EVIDENCE_BUNDLE_BYTES {
        return Err(fault(
            SjsRspFaultCode::InvalidBound,
            "evidence total exceeds 8388608 bytes",
        ));
    }
    Ok(())
}

fn predicate_text(predicate: &SjsLasPredicate) -> String {
    format!("{} equals {}", predicate.field, predicate.equals)
}

fn derived_id(prefix: &str, source: &SemanticId) -> Result<SemanticId, SjsRspFault> {
    SemanticId::new(format!("{prefix}:{}", uuid_component(source)?))
        .map_err(|error| fault(SjsRspFaultCode::InvalidIdentity, error.to_string()))
}

fn fixed_id(value: &str) -> Result<SemanticId, SjsRspFault> {
    SemanticId::new(value)
        .map_err(|error| fault(SjsRspFaultCode::InvalidIdentity, error.to_string()))
}

fn uuid_component(identity: &SemanticId) -> Result<&str, SjsRspFault> {
    let suffix = identity.as_str().rsplit(':').next().unwrap_or_default();
    let bytes = suffix.as_bytes();
    let valid = bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                *byte == b'-'
            } else {
                byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
            }
        })
        && suffix != "00000000-0000-0000-0000-000000000000";
    if valid {
        Ok(suffix)
    } else {
        Err(fault(
            SjsRspFaultCode::InvalidIdentity,
            "identity lacks a lowercase nonnil UUID component",
        ))
    }
}

fn validate_uuid_id(identity: &SemanticId, expected_prefix: &str) -> Result<(), SjsRspFault> {
    uuid_component(identity)?;
    if identity
        .as_str()
        .strip_prefix(expected_prefix)
        .and_then(|suffix| suffix.strip_prefix(':'))
        .is_none()
    {
        return Err(fault(
            SjsRspFaultCode::InvalidIdentity,
            format!("identity prefix differs from {expected_prefix}"),
        ));
    }
    Ok(())
}

fn validate_text(value: &str, label: &str) -> Result<(), SjsRspFault> {
    if value.is_empty()
        || value.len() > MAX_TEXT_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(fault(
            SjsRspFaultCode::InvalidText,
            format!("{label} differs"),
        ));
    }
    Ok(())
}

fn count_u32(value: usize, label: &str) -> Result<u32, SjsRspFault> {
    u32::try_from(value).map_err(|_| {
        fault(
            SjsRspFaultCode::ArithmeticOverflow,
            format!("{label} exceeds u32"),
        )
    })
}

fn digest_without<T: Clone + Serialize>(
    value: &T,
    domain: &str,
    field: impl Fn(&mut T) -> &mut ContentDigest,
) -> Result<ContentDigest, SjsRspFault> {
    let mut copy = value.clone();
    *field(&mut copy) = empty_digest();
    sha256_form(domain, &copy)
}

fn sha256_form<T: Serialize>(domain: &str, value: &T) -> Result<ContentDigest, SjsRspFault> {
    let body = serde_json::to_vec(value).map_err(machine_fault)?;
    let mut bytes = Vec::with_capacity(domain.len() + 1 + body.len());
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&body);
    Ok(sha256_bytes(&bytes))
}

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: "0".repeat(64),
    }
}

fn to_machine_form<T: Serialize>(value: &T) -> Result<String, SjsRspFault> {
    let form = serde_json::to_string(value).map_err(machine_fault)?;
    if form.len() > SJS_RSP_MAX_MACHINE_FORM_BYTES {
        return Err(fault(
            SjsRspFaultCode::InvalidBound,
            "machine form exceeds 1048576 bytes",
        ));
    }
    Ok(form)
}

fn parse_bounded<T: DeserializeOwned + Serialize>(value: &str) -> Result<T, SjsRspFault> {
    parse_bounded_with_limit(value, SJS_RSP_MAX_MACHINE_FORM_BYTES)
}

fn parse_bounded_with_limit<T: DeserializeOwned + Serialize>(
    value: &str,
    maximum_bytes: usize,
) -> Result<T, SjsRspFault> {
    if value.is_empty() || value.len() > maximum_bytes {
        return Err(fault(
            SjsRspFaultCode::InvalidBound,
            "machine form byte bound differs",
        ));
    }
    let mut deserializer = serde_json::Deserializer::from_str(value);
    NoDuplicateJson::deserialize(&mut deserializer).map_err(machine_fault)?;
    deserializer.end().map_err(machine_fault)?;
    let shape: Value = serde_json::from_str(value).map_err(machine_fault)?;
    let mut fields = 0usize;
    validate_shape(&shape, 1, &mut fields)?;
    let parsed: T = serde_json::from_str(value).map_err(machine_fault)?;
    if serde_json::to_string(&parsed).map_err(machine_fault)? != value {
        return Err(fault(
            SjsRspFaultCode::InvalidMachineForm,
            "machine form is not compact canonical JSON",
        ));
    }
    Ok(parsed)
}

struct NoDuplicateJson;
impl<'de> Deserialize<'de> for NoDuplicateJson {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(NoDuplicateVisitor)?;
        Ok(Self)
    }
}

struct NoDuplicateVisitor;
impl<'de> Visitor<'de> for NoDuplicateVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("strict JSON")
    }
    fn visit_bool<E>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_string<E>(self, _: String) -> Result<(), E> {
        Ok(())
    }
    fn visit_none<E>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<(), A::Error> {
        while sequence.next_element::<NoDuplicateJson>()?.is_some() {}
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(serde::de::Error::custom(format!("duplicate key {key}")));
            }
            map.next_value::<NoDuplicateJson>()?;
        }
        Ok(())
    }
}

fn validate_shape(value: &Value, depth: usize, fields: &mut usize) -> Result<(), SjsRspFault> {
    if depth > MAX_DEPTH {
        return Err(fault(
            SjsRspFaultCode::InvalidMachineForm,
            "depth exceeds 40",
        ));
    }
    match value {
        Value::Object(map) => {
            *fields = fields.checked_add(map.len()).ok_or_else(|| {
                fault(SjsRspFaultCode::ArithmeticOverflow, "field count overflow")
            })?;
            if *fields > MAX_FIELDS {
                return Err(fault(
                    SjsRspFaultCode::InvalidMachineForm,
                    "fields exceed 16384",
                ));
            }
            for (key, nested) in map {
                validate_text(key, "field")?;
                validate_shape(nested, depth + 1, fields)?;
            }
        }
        Value::Array(array) => {
            for nested in array {
                validate_shape(nested, depth + 1, fields)?;
            }
        }
        Value::String(text) => validate_text(text, "machine text")?,
        _ => {}
    }
    Ok(())
}

fn upstream_fault(error: impl fmt::Display) -> SjsRspFault {
    fault(SjsRspFaultCode::InvalidUpstream, error.to_string())
}

fn downstream_fault(error: impl fmt::Display) -> SjsRspFault {
    fault(SjsRspFaultCode::DownstreamRefusal, error.to_string())
}

fn machine_fault(error: impl fmt::Display) -> SjsRspFault {
    fault(SjsRspFaultCode::InvalidMachineForm, error.to_string())
}

fn fault(code: SjsRspFaultCode, detail: impl Into<String>) -> SjsRspFault {
    SjsRspFault {
        code,
        detail: detail.into(),
    }
}
