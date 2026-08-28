//! Pure provider-free forms for proposed inner Cantor process lineage.
//!
//! This module validates supplied identity data only. It performs no I/O,
//! observes or launches no process, loads no model, contacts no provider, and
//! grants no physical ancestry, workspace, persistence, remote, or effect
//! authority.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    ContentDigest, NestedOuterHostIdentityEnvelope, SemanticId, sha256_bytes,
    validate_nested_outer_host_identity_envelope,
};

pub const NESTED_INNER_PROCESS_LINEAGE_REQUEST_PROFILE: &str =
    "cantor-nested-inner-process-lineage-request/0.1";
pub const NESTED_INNER_PROCESS_LINEAGE_ENVELOPE_PROFILE: &str =
    "cantor-nested-inner-process-lineage-envelope/0.1";
pub const NESTED_INNER_PROCESS_LINEAGE_VERIFICATION_PROFILE: &str =
    "cantor-nested-inner-process-lineage-verification/0.1";
pub const NESTED_INNER_PROCESS_LINEAGE_EVIDENCE_PROFILE: &str =
    "cantor-nested-inner-process-lineage-evidence/0.1";
pub const NESTED_INNER_PROCESS_LINEAGE_NON_AUTHORITY: &str = "Supplied identity correspondence only. It does not establish physical ancestry, process observation, launch, model admission or loading, provider contact, custody, shared attention, workspace mutation, persistence, remote access, or external-effect authority.";
pub const NESTED_INNER_PROCESS_LINEAGE_MAX_MACHINE_FORM_BYTES: usize = 1_048_576;
pub const NESTED_INNER_PROCESS_LINEAGE_MAX_EVIDENCE_BUNDLE_BYTES: usize = 4_194_304;

const REQUEST_DOMAIN: &str = "cantor.nested-inner-process-lineage.request.v1";
const LINEAGE_DOMAIN: &str = "cantor.nested-inner-process-lineage.lineage.v1";
const ENVELOPE_DOMAIN: &str = "cantor.nested-inner-process-lineage.envelope.v1";
const MAX_DEPTH: usize = 24;
const MAX_FIELDS: usize = 256;
const MAX_TEXT_BYTES: usize = 1024;
const MAX_EVIDENCE_REFS: usize = 32;
const REQUEST_EVIDENCE_PATH: &str = "request.json";
const ENVELOPE_EVIDENCE_PATH: &str = "envelope.json";
const VERIFICATION_EVIDENCE_PATH: &str = "verification.json";

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InnerCantorKind {
    InnerCantor,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InnerProcessBindingState {
    DeclaredUnobserved,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InnerProcessLineageRelationship {
    ProposedParentChildUnobserved,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InnerProcessLineageLifecycle {
    ProposedLineageOnly,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InnerProcessLineageAuthority {
    LineageCorrespondenceOnly,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InnerProcessLineageCapabilityDenial {
    ProcessObservation,
    ProcessLaunch,
    ModelAdmission,
    ModelLoad,
    ProviderCall,
    SharedAttention,
    Persistence,
    WorkspaceMutation,
    ExternalEffect,
    RemoteAccess,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InnerCantorProcessBinding {
    pub inner_session_id: SemanticId,
    pub inner_cantor_id: SemanticId,
    pub inner_process_id: SemanticId,
    pub kind: InnerCantorKind,
    pub binding_state: InnerProcessBindingState,
    pub implementation_digest: ContentDigest,
    pub configuration_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NestedInnerProcessLineageRequest {
    pub profile: String,
    pub request_id: SemanticId,
    pub lineage_id: SemanticId,
    pub parent: NestedOuterHostIdentityEnvelope,
    pub parent_session_id: SemanticId,
    pub parent_outer_host_id: SemanticId,
    pub parent_outer_process_id: SemanticId,
    pub parent_envelope_digest: ContentDigest,
    pub inner: InnerCantorProcessBinding,
    pub relationship: InnerProcessLineageRelationship,
    pub lineage_depth: u32,
    pub child_ordinal: u32,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub unresolved_account: BTreeSet<String>,
    pub non_authority: String,
    pub request_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NestedInnerProcessLineageEnvelope {
    pub profile: String,
    pub request: NestedInnerProcessLineageRequest,
    pub lifecycle: InnerProcessLineageLifecycle,
    pub authority: InnerProcessLineageAuthority,
    pub capability_denials: BTreeSet<InnerProcessLineageCapabilityDenial>,
    pub parent_envelope_digest: ContentDigest,
    pub request_digest: ContentDigest,
    pub lineage_digest: ContentDigest,
    pub envelope_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NestedInnerProcessLineageEffectAccount {
    pub physical_parenthood_proved: bool,
    pub parent_process_observed: bool,
    pub child_process_observed: bool,
    pub child_launched: bool,
    pub model_admitted: bool,
    pub provider_contacted: bool,
    pub process_count: u32,
    pub provider_trial_count: u32,
    pub model_turn_count: u32,
    pub mcp_call_count: u32,
    pub workspace_mutation_count: u32,
    pub network_contact_count: u32,
    pub remote_contact_count: u32,
    pub persistence_count: u32,
    pub activation_count: u32,
    pub cleanup_effect_count: u32,
    pub foreign_effect_count: u32,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NestedInnerProcessLineageVerification {
    pub profile: String,
    pub status: String,
    pub authority: InnerProcessLineageAuthority,
    pub request_digest: ContentDigest,
    pub lineage_digest: ContentDigest,
    pub envelope_digest: ContentDigest,
    pub operational_identity_count: u32,
    pub capability_denial_count: u32,
    pub unresolved_truth_count: u32,
    pub lineage_depth: u32,
    pub child_ordinal: u32,
    pub effects: NestedInnerProcessLineageEffectAccount,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NestedInnerProcessLineageEvidenceFile {
    pub path: String,
    pub bytes: u64,
    pub sha256: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NestedInnerProcessLineageEvidenceManifest {
    pub profile: String,
    pub replay_count: u32,
    pub files: BTreeMap<String, NestedInnerProcessLineageEvidenceFile>,
    pub operational_identity_count: u32,
    pub capability_denial_count: u32,
    pub unresolved_truth_count: u32,
    pub effects: NestedInnerProcessLineageEffectAccount,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NestedInnerProcessLineageEvidenceBundle {
    pub request_file: String,
    pub envelope_file: String,
    pub verification_file: String,
    pub manifest_file: String,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NestedInnerProcessLineageFaultCode {
    InvalidProfile,
    InvalidMachineForm,
    InvalidIdentity,
    IdentityCollision,
    InvalidParent,
    InvalidBinding,
    InvalidRelationship,
    InvalidBounds,
    InvalidDigest,
    InvalidEvidence,
    InvalidUnresolvedAccount,
    InvalidAuthority,
    InvalidLifecycle,
    InvalidCorrespondence,
    InvalidVerification,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NestedInnerProcessLineageFault {
    pub code: NestedInnerProcessLineageFaultCode,
    pub message: String,
}

impl fmt::Display for NestedInnerProcessLineageFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for NestedInnerProcessLineageFault {}

pub fn seal_nested_inner_process_lineage_request(
    mut request: NestedInnerProcessLineageRequest,
) -> Result<NestedInnerProcessLineageRequest, NestedInnerProcessLineageFault> {
    request.request_digest = empty_digest();
    validate_request_body(&request)?;
    request.request_digest = nested_inner_process_lineage_request_digest(&request)?;
    validate_nested_inner_process_lineage_request(&request)?;
    Ok(request)
}

pub fn compile_nested_inner_process_lineage(
    request: &NestedInnerProcessLineageRequest,
) -> Result<NestedInnerProcessLineageEnvelope, NestedInnerProcessLineageFault> {
    validate_nested_inner_process_lineage_request(request)?;
    let mut envelope = NestedInnerProcessLineageEnvelope {
        profile: NESTED_INNER_PROCESS_LINEAGE_ENVELOPE_PROFILE.to_owned(),
        request: request.clone(),
        lifecycle: InnerProcessLineageLifecycle::ProposedLineageOnly,
        authority: InnerProcessLineageAuthority::LineageCorrespondenceOnly,
        capability_denials: required_capability_denials(),
        parent_envelope_digest: request.parent_envelope_digest.clone(),
        request_digest: request.request_digest.clone(),
        lineage_digest: nested_inner_process_lineage_digest(request)?,
        envelope_digest: empty_digest(),
    };
    envelope.envelope_digest = nested_inner_process_lineage_envelope_digest(&envelope)?;
    validate_nested_inner_process_lineage_envelope(request, &envelope)?;
    Ok(envelope)
}

pub fn validate_nested_inner_process_lineage_request(
    request: &NestedInnerProcessLineageRequest,
) -> Result<(), NestedInnerProcessLineageFault> {
    validate_request_body(request)?;
    validate_digest(&request.request_digest, "request digest")?;
    if request.request_digest != nested_inner_process_lineage_request_digest(request)? {
        return Err(fault(
            NestedInnerProcessLineageFaultCode::InvalidDigest,
            "request digest differs",
        ));
    }
    Ok(())
}

fn validate_request_body(
    request: &NestedInnerProcessLineageRequest,
) -> Result<(), NestedInnerProcessLineageFault> {
    if request.profile != NESTED_INNER_PROCESS_LINEAGE_REQUEST_PROFILE {
        return Err(fault(
            NestedInnerProcessLineageFaultCode::InvalidProfile,
            "request profile differs",
        ));
    }
    validate_uuid_semantic_id(&request.request_id, "request:", "request identity")?;
    validate_uuid_semantic_id(&request.lineage_id, "lineage:", "lineage identity")?;
    validate_nested_outer_host_identity_envelope(&request.parent.request, &request.parent)
        .map_err(|error| {
            fault(
                NestedInnerProcessLineageFaultCode::InvalidParent,
                format!("NHC-01 parent envelope refused: {error}"),
            )
        })?;
    if request.parent_session_id != request.parent.request.session_id
        || request.parent_outer_host_id != request.parent.request.outer_host_id
        || request.parent_outer_process_id != request.parent.request.process.process_id
        || request.parent_envelope_digest != request.parent.envelope_digest
    {
        return Err(fault(
            NestedInnerProcessLineageFaultCode::InvalidParent,
            "parent anchors or envelope digest differ from the complete NHC-01 envelope",
        ));
    }
    validate_uuid_semantic_id(
        &request.inner.inner_session_id,
        "inner-session:",
        "inner session identity",
    )?;
    validate_uuid_semantic_id(
        &request.inner.inner_cantor_id,
        "inner-cantor:",
        "inner Cantor identity",
    )?;
    validate_uuid_semantic_id(
        &request.inner.inner_process_id,
        "inner-process:",
        "inner process identity",
    )?;
    if request.inner.kind != InnerCantorKind::InnerCantor
        || request.inner.binding_state != InnerProcessBindingState::DeclaredUnobserved
    {
        return Err(fault(
            NestedInnerProcessLineageFaultCode::InvalidBinding,
            "inner binding must remain inner-cantor declared-unobserved",
        ));
    }
    validate_digest(
        &request.inner.implementation_digest,
        "inner implementation digest",
    )?;
    validate_digest(
        &request.inner.configuration_digest,
        "inner configuration digest",
    )?;

    let identities = [
        request.parent.request.session_id.as_str(),
        request.parent.request.outer_host_id.as_str(),
        request.parent.request.process.process_id.as_str(),
        request.parent.request.model.model_id.as_str(),
        request.inner.inner_session_id.as_str(),
        request.inner.inner_cantor_id.as_str(),
        request.inner.inner_process_id.as_str(),
    ];
    if identities.into_iter().collect::<BTreeSet<_>>().len() != identities.len() {
        return Err(fault(
            NestedInnerProcessLineageFaultCode::IdentityCollision,
            "all four outer and three inner operational identities must be distinct",
        ));
    }
    if request.relationship != InnerProcessLineageRelationship::ProposedParentChildUnobserved {
        return Err(fault(
            NestedInnerProcessLineageFaultCode::InvalidRelationship,
            "lineage relationship differs",
        ));
    }
    if request.lineage_depth != 1 || request.child_ordinal != 1 {
        return Err(fault(
            NestedInnerProcessLineageFaultCode::InvalidBounds,
            "lineage depth and child ordinal must both equal one",
        ));
    }
    if request.evidence_refs.is_empty() || request.evidence_refs.len() > MAX_EVIDENCE_REFS {
        return Err(fault(
            NestedInnerProcessLineageFaultCode::InvalidEvidence,
            "evidence reference count must be within 1..=32",
        ));
    }
    if request.unresolved_account != required_unresolved_account() {
        return Err(fault(
            NestedInnerProcessLineageFaultCode::InvalidUnresolvedAccount,
            "unresolved account differs from the exact P0 declaration",
        ));
    }
    if request.non_authority != NESTED_INNER_PROCESS_LINEAGE_NON_AUTHORITY {
        return Err(fault(
            NestedInnerProcessLineageFaultCode::InvalidAuthority,
            "request non-authority statement differs",
        ));
    }
    Ok(())
}

pub fn validate_nested_inner_process_lineage_envelope(
    expected_request: &NestedInnerProcessLineageRequest,
    envelope: &NestedInnerProcessLineageEnvelope,
) -> Result<(), NestedInnerProcessLineageFault> {
    validate_nested_inner_process_lineage_request(&envelope.request)?;
    if &envelope.request != expected_request {
        return Err(fault(
            NestedInnerProcessLineageFaultCode::InvalidCorrespondence,
            "envelope request differs from the supplied request",
        ));
    }
    if envelope.profile != NESTED_INNER_PROCESS_LINEAGE_ENVELOPE_PROFILE {
        return Err(fault(
            NestedInnerProcessLineageFaultCode::InvalidProfile,
            "envelope profile differs",
        ));
    }
    if envelope.lifecycle != InnerProcessLineageLifecycle::ProposedLineageOnly {
        return Err(fault(
            NestedInnerProcessLineageFaultCode::InvalidLifecycle,
            "envelope lifecycle differs",
        ));
    }
    if envelope.authority != InnerProcessLineageAuthority::LineageCorrespondenceOnly
        || envelope.capability_denials != required_capability_denials()
    {
        return Err(fault(
            NestedInnerProcessLineageFaultCode::InvalidAuthority,
            "envelope authority or capability denials differ",
        ));
    }
    if envelope.parent_envelope_digest != expected_request.parent_envelope_digest
        || envelope.request_digest != expected_request.request_digest
        || envelope.lineage_digest != nested_inner_process_lineage_digest(expected_request)?
    {
        return Err(fault(
            NestedInnerProcessLineageFaultCode::InvalidDigest,
            "parent request or lineage digest differs",
        ));
    }
    validate_digest(&envelope.envelope_digest, "envelope digest")?;
    if envelope.envelope_digest != nested_inner_process_lineage_envelope_digest(envelope)? {
        return Err(fault(
            NestedInnerProcessLineageFaultCode::InvalidDigest,
            "envelope digest differs",
        ));
    }
    Ok(())
}

pub fn verify_nested_inner_process_lineage(
    envelope: &NestedInnerProcessLineageEnvelope,
) -> Result<NestedInnerProcessLineageVerification, NestedInnerProcessLineageFault> {
    validate_nested_inner_process_lineage_envelope(&envelope.request, envelope)?;
    Ok(NestedInnerProcessLineageVerification {
        profile: NESTED_INNER_PROCESS_LINEAGE_VERIFICATION_PROFILE.to_owned(),
        status: "verified_provider_free_lineage_correspondence".to_owned(),
        authority: InnerProcessLineageAuthority::LineageCorrespondenceOnly,
        request_digest: envelope.request_digest.clone(),
        lineage_digest: envelope.lineage_digest.clone(),
        envelope_digest: envelope.envelope_digest.clone(),
        operational_identity_count: 7,
        capability_denial_count: 10,
        unresolved_truth_count: 6,
        lineage_depth: 1,
        child_ordinal: 1,
        effects: zero_effect_account(),
    })
}

pub fn validate_nested_inner_process_lineage_verification(
    verification: &NestedInnerProcessLineageVerification,
) -> Result<(), NestedInnerProcessLineageFault> {
    if verification.profile != NESTED_INNER_PROCESS_LINEAGE_VERIFICATION_PROFILE
        || verification.status != "verified_provider_free_lineage_correspondence"
        || verification.authority != InnerProcessLineageAuthority::LineageCorrespondenceOnly
        || verification.operational_identity_count != 7
        || verification.capability_denial_count != 10
        || verification.unresolved_truth_count != 6
        || verification.lineage_depth != 1
        || verification.child_ordinal != 1
        || verification.effects != zero_effect_account()
    {
        return Err(fault(
            NestedInnerProcessLineageFaultCode::InvalidVerification,
            "verification status authority counts bounds or effects differ",
        ));
    }
    validate_digest(&verification.request_digest, "verified request digest")?;
    validate_digest(&verification.lineage_digest, "verified lineage digest")?;
    validate_digest(&verification.envelope_digest, "verified envelope digest")
}

pub fn nested_inner_process_lineage_request_digest(
    request: &NestedInnerProcessLineageRequest,
) -> Result<ContentDigest, NestedInnerProcessLineageFault> {
    let mut body = request.clone();
    body.request_digest = empty_digest();
    sha256_form(REQUEST_DOMAIN, &body)
}

pub fn nested_inner_process_lineage_digest(
    request: &NestedInnerProcessLineageRequest,
) -> Result<ContentDigest, NestedInnerProcessLineageFault> {
    #[derive(Serialize)]
    struct LineageBody<'a> {
        lineage_id: &'a SemanticId,
        parent_envelope_digest: &'a ContentDigest,
        parent_session_id: &'a SemanticId,
        parent_outer_host_id: &'a SemanticId,
        parent_outer_process_id: &'a SemanticId,
        inner: &'a InnerCantorProcessBinding,
        relationship: InnerProcessLineageRelationship,
        lineage_depth: u32,
        child_ordinal: u32,
    }
    sha256_form(
        LINEAGE_DOMAIN,
        &LineageBody {
            lineage_id: &request.lineage_id,
            parent_envelope_digest: &request.parent_envelope_digest,
            parent_session_id: &request.parent_session_id,
            parent_outer_host_id: &request.parent_outer_host_id,
            parent_outer_process_id: &request.parent_outer_process_id,
            inner: &request.inner,
            relationship: request.relationship,
            lineage_depth: request.lineage_depth,
            child_ordinal: request.child_ordinal,
        },
    )
}

pub fn nested_inner_process_lineage_envelope_digest(
    envelope: &NestedInnerProcessLineageEnvelope,
) -> Result<ContentDigest, NestedInnerProcessLineageFault> {
    let mut body = envelope.clone();
    body.envelope_digest = empty_digest();
    sha256_form(ENVELOPE_DOMAIN, &body)
}

pub fn to_nested_inner_process_lineage_request_machine_form(
    request: &NestedInnerProcessLineageRequest,
) -> Result<String, NestedInnerProcessLineageFault> {
    validate_nested_inner_process_lineage_request(request)?;
    to_machine_form(request)
}

pub fn from_nested_inner_process_lineage_request_machine_form(
    value: &str,
) -> Result<NestedInnerProcessLineageRequest, NestedInnerProcessLineageFault> {
    let request = parse_bounded(value)?;
    validate_nested_inner_process_lineage_request(&request)?;
    Ok(request)
}

pub fn to_nested_inner_process_lineage_envelope_machine_form(
    envelope: &NestedInnerProcessLineageEnvelope,
) -> Result<String, NestedInnerProcessLineageFault> {
    validate_nested_inner_process_lineage_envelope(&envelope.request, envelope)?;
    to_machine_form(envelope)
}

pub fn from_nested_inner_process_lineage_envelope_machine_form(
    value: &str,
) -> Result<NestedInnerProcessLineageEnvelope, NestedInnerProcessLineageFault> {
    let envelope: NestedInnerProcessLineageEnvelope = parse_bounded(value)?;
    validate_nested_inner_process_lineage_envelope(&envelope.request, &envelope)?;
    Ok(envelope)
}

pub fn to_nested_inner_process_lineage_verification_machine_form(
    verification: &NestedInnerProcessLineageVerification,
) -> Result<String, NestedInnerProcessLineageFault> {
    validate_nested_inner_process_lineage_verification(verification)?;
    to_machine_form(verification)
}

pub fn from_nested_inner_process_lineage_verification_machine_form(
    value: &str,
) -> Result<NestedInnerProcessLineageVerification, NestedInnerProcessLineageFault> {
    let verification: NestedInnerProcessLineageVerification = parse_bounded(value)?;
    validate_nested_inner_process_lineage_verification(&verification)?;
    Ok(verification)
}

pub fn build_nested_inner_process_lineage_evidence_bundle(
    request: &NestedInnerProcessLineageRequest,
) -> Result<NestedInnerProcessLineageEvidenceBundle, NestedInnerProcessLineageFault> {
    let envelope = compile_nested_inner_process_lineage(request)?;
    let verification = verify_nested_inner_process_lineage(&envelope)?;
    let request_file = canonical_file(to_nested_inner_process_lineage_request_machine_form(
        request,
    )?);
    let envelope_file = canonical_file(to_nested_inner_process_lineage_envelope_machine_form(
        &envelope,
    )?);
    let verification_file = canonical_file(
        to_nested_inner_process_lineage_verification_machine_form(&verification)?,
    );
    let manifest = evidence_manifest(&request_file, &envelope_file, &verification_file);
    let manifest_file = canonical_file(to_machine_form(&manifest)?);
    Ok(NestedInnerProcessLineageEvidenceBundle {
        request_file,
        envelope_file,
        verification_file,
        manifest_file,
    })
}

pub fn verify_nested_inner_process_lineage_evidence_bundle(
    bundle: &NestedInnerProcessLineageEvidenceBundle,
) -> Result<NestedInnerProcessLineageVerification, NestedInnerProcessLineageFault> {
    let request_form = canonical_file_body(&bundle.request_file, "request evidence")?;
    let envelope_form = canonical_file_body(&bundle.envelope_file, "envelope evidence")?;
    let verification_form =
        canonical_file_body(&bundle.verification_file, "verification evidence")?;
    let manifest_form = canonical_file_body(&bundle.manifest_file, "manifest evidence")?;
    let request = from_nested_inner_process_lineage_request_machine_form(request_form)?;
    let retained_envelope = from_nested_inner_process_lineage_envelope_machine_form(envelope_form)?;
    let retained_verification =
        from_nested_inner_process_lineage_verification_machine_form(verification_form)?;
    let retained_manifest: NestedInnerProcessLineageEvidenceManifest =
        parse_bounded(manifest_form)?;

    let expected_manifest = evidence_manifest(
        &bundle.request_file,
        &bundle.envelope_file,
        &bundle.verification_file,
    );
    if retained_manifest != expected_manifest {
        return Err(fault(
            NestedInnerProcessLineageFaultCode::InvalidEvidence,
            "retained evidence manifest differs from exact file identities or zero-effect account",
        ));
    }

    let first_envelope = compile_nested_inner_process_lineage(&request)?;
    let second_envelope = compile_nested_inner_process_lineage(&request)?;
    if first_envelope != retained_envelope || second_envelope != retained_envelope {
        return Err(fault(
            NestedInnerProcessLineageFaultCode::InvalidEvidence,
            "retained envelope differs from two deterministic compilations",
        ));
    }
    let first_verification = verify_nested_inner_process_lineage(&first_envelope)?;
    let second_verification = verify_nested_inner_process_lineage(&second_envelope)?;
    if first_verification != retained_verification || second_verification != retained_verification {
        return Err(fault(
            NestedInnerProcessLineageFaultCode::InvalidEvidence,
            "retained verification differs from two independent replays",
        ));
    }
    Ok(retained_verification)
}

pub fn to_nested_inner_process_lineage_evidence_bundle_machine_form(
    bundle: &NestedInnerProcessLineageEvidenceBundle,
) -> Result<String, NestedInnerProcessLineageFault> {
    verify_nested_inner_process_lineage_evidence_bundle(bundle)?;
    to_machine_form(bundle)
}

pub fn from_nested_inner_process_lineage_evidence_bundle_machine_form(
    value: &str,
) -> Result<NestedInnerProcessLineageEvidenceBundle, NestedInnerProcessLineageFault> {
    if value.len() > NESTED_INNER_PROCESS_LINEAGE_MAX_EVIDENCE_BUNDLE_BYTES {
        return Err(fault(
            NestedInnerProcessLineageFaultCode::InvalidMachineForm,
            "evidence bundle exceeds 4194304 bytes",
        ));
    }
    let bundle: NestedInnerProcessLineageEvidenceBundle =
        serde_json::from_str(value).map_err(|error| machine_fault("evidence bundle", error))?;
    verify_nested_inner_process_lineage_evidence_bundle(&bundle)?;
    Ok(bundle)
}

fn evidence_manifest(
    request_file: &str,
    envelope_file: &str,
    verification_file: &str,
) -> NestedInnerProcessLineageEvidenceManifest {
    let files = [
        (
            "request".to_owned(),
            evidence_file(REQUEST_EVIDENCE_PATH, request_file),
        ),
        (
            "envelope".to_owned(),
            evidence_file(ENVELOPE_EVIDENCE_PATH, envelope_file),
        ),
        (
            "verification".to_owned(),
            evidence_file(VERIFICATION_EVIDENCE_PATH, verification_file),
        ),
    ]
    .into_iter()
    .collect();
    NestedInnerProcessLineageEvidenceManifest {
        profile: NESTED_INNER_PROCESS_LINEAGE_EVIDENCE_PROFILE.to_owned(),
        replay_count: 2,
        files,
        operational_identity_count: 7,
        capability_denial_count: 10,
        unresolved_truth_count: 6,
        effects: zero_effect_account(),
    }
}

fn evidence_file(path: &str, value: &str) -> NestedInnerProcessLineageEvidenceFile {
    NestedInnerProcessLineageEvidenceFile {
        path: path.to_owned(),
        bytes: value.len() as u64,
        sha256: sha256_bytes(value.as_bytes()),
    }
}

fn canonical_file(value: String) -> String {
    format!("{value}\n")
}

fn canonical_file_body<'a>(
    value: &'a str,
    label: &str,
) -> Result<&'a str, NestedInnerProcessLineageFault> {
    let Some(body) = value.strip_suffix('\n') else {
        return Err(fault(
            NestedInnerProcessLineageFaultCode::InvalidEvidence,
            format!("{label} lacks one canonical LF terminator"),
        ));
    };
    if body.is_empty() || body.chars().last().is_some_and(char::is_whitespace) {
        return Err(fault(
            NestedInnerProcessLineageFaultCode::InvalidEvidence,
            format!("{label} has empty or non-canonical trailing content"),
        ));
    }
    Ok(body)
}

fn parse_bounded<T: DeserializeOwned>(value: &str) -> Result<T, NestedInnerProcessLineageFault> {
    if value.len() > NESTED_INNER_PROCESS_LINEAGE_MAX_MACHINE_FORM_BYTES {
        return Err(fault(
            NestedInnerProcessLineageFaultCode::InvalidMachineForm,
            "machine form exceeds 1048576 bytes",
        ));
    }
    let shape: Value =
        serde_json::from_str(value).map_err(|error| machine_fault("machine form shape", error))?;
    let mut fields = 0;
    validate_json_shape(&shape, 1, &mut fields)?;
    serde_json::from_str(value).map_err(|error| machine_fault("machine form", error))
}

fn validate_json_shape(
    value: &Value,
    depth: usize,
    fields: &mut usize,
) -> Result<(), NestedInnerProcessLineageFault> {
    if depth > MAX_DEPTH {
        return Err(fault(
            NestedInnerProcessLineageFaultCode::InvalidMachineForm,
            "machine form exceeds depth 24",
        ));
    }
    match value {
        Value::Object(map) => {
            *fields = fields.saturating_add(map.len());
            if *fields > MAX_FIELDS {
                return Err(fault(
                    NestedInnerProcessLineageFaultCode::InvalidMachineForm,
                    "machine form exceeds 256 fields",
                ));
            }
            for (key, child) in map {
                validate_text(key, "machine field")?;
                validate_json_shape(child, depth + 1, fields)?;
            }
        }
        Value::Array(values) => {
            if values.iter().all(Value::is_string) {
                let strings = values
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<BTreeSet<_>>();
                if strings.len() != values.len() {
                    return Err(fault(
                        NestedInnerProcessLineageFaultCode::InvalidMachineForm,
                        "machine form contains a duplicate string set member",
                    ));
                }
            }
            for child in values {
                validate_json_shape(child, depth + 1, fields)?;
            }
        }
        Value::String(text) => validate_text(text, "machine text")?,
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    Ok(())
}

fn validate_uuid_semantic_id(
    id: &SemanticId,
    prefix: &str,
    label: &str,
) -> Result<(), NestedInnerProcessLineageFault> {
    let Some(uuid) = id.as_str().strip_prefix(prefix) else {
        return Err(fault(
            NestedInnerProcessLineageFaultCode::InvalidIdentity,
            format!("{label} lacks the exact {prefix} prefix"),
        ));
    };
    let bytes = uuid.as_bytes();
    let valid = bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(byte),
        })
        && bytes
            .iter()
            .any(|byte| byte.is_ascii_digit() && *byte != b'0' || (b'a'..=b'f').contains(byte));
    if !valid {
        return Err(fault(
            NestedInnerProcessLineageFaultCode::InvalidIdentity,
            format!("{label} must contain a nonnil lowercase canonical UUID"),
        ));
    }
    Ok(())
}

fn validate_text(value: &str, label: &str) -> Result<(), NestedInnerProcessLineageFault> {
    if value.len() > MAX_TEXT_BYTES || value.chars().any(char::is_control) {
        return Err(fault(
            NestedInnerProcessLineageFaultCode::InvalidMachineForm,
            format!("{label} exceeds 1024 bytes or contains control text"),
        ));
    }
    Ok(())
}

fn validate_digest(
    digest: &ContentDigest,
    label: &str,
) -> Result<(), NestedInnerProcessLineageFault> {
    let valid = digest.algorithm == "sha256"
        && digest.value.len() == 64
        && digest
            .value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !valid {
        return Err(fault(
            NestedInnerProcessLineageFaultCode::InvalidDigest,
            format!("{label} must be lowercase SHA256"),
        ));
    }
    Ok(())
}

fn required_unresolved_account() -> BTreeSet<String> {
    [
        "parent_process_not_observed",
        "child_process_not_observed",
        "child_not_launched",
        "lineage_not_observed",
        "model_not_admitted",
        "provider_not_contacted",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn required_capability_denials() -> BTreeSet<InnerProcessLineageCapabilityDenial> {
    [
        InnerProcessLineageCapabilityDenial::ProcessObservation,
        InnerProcessLineageCapabilityDenial::ProcessLaunch,
        InnerProcessLineageCapabilityDenial::ModelAdmission,
        InnerProcessLineageCapabilityDenial::ModelLoad,
        InnerProcessLineageCapabilityDenial::ProviderCall,
        InnerProcessLineageCapabilityDenial::SharedAttention,
        InnerProcessLineageCapabilityDenial::Persistence,
        InnerProcessLineageCapabilityDenial::WorkspaceMutation,
        InnerProcessLineageCapabilityDenial::ExternalEffect,
        InnerProcessLineageCapabilityDenial::RemoteAccess,
    ]
    .into_iter()
    .collect()
}

fn zero_effect_account() -> NestedInnerProcessLineageEffectAccount {
    NestedInnerProcessLineageEffectAccount {
        physical_parenthood_proved: false,
        parent_process_observed: false,
        child_process_observed: false,
        child_launched: false,
        model_admitted: false,
        provider_contacted: false,
        process_count: 0,
        provider_trial_count: 0,
        model_turn_count: 0,
        mcp_call_count: 0,
        workspace_mutation_count: 0,
        network_contact_count: 0,
        remote_contact_count: 0,
        persistence_count: 0,
        activation_count: 0,
        cleanup_effect_count: 0,
        foreign_effect_count: 0,
    }
}

fn sha256_form<T: Serialize>(
    domain: &str,
    value: &T,
) -> Result<ContentDigest, NestedInnerProcessLineageFault> {
    let body = serde_json::to_vec(value).map_err(|error| machine_fault("digest form", error))?;
    let mut bytes = Vec::with_capacity(domain.len() + 1 + body.len());
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&body);
    Ok(sha256_bytes(&bytes))
}

fn to_machine_form<T: Serialize>(value: &T) -> Result<String, NestedInnerProcessLineageFault> {
    serde_json::to_string(value).map_err(|error| machine_fault("machine form", error))
}

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: "0".repeat(64),
    }
}

fn machine_fault(label: &str, error: serde_json::Error) -> NestedInnerProcessLineageFault {
    fault(
        NestedInnerProcessLineageFaultCode::InvalidMachineForm,
        format!("nested inner process lineage {label} failed: {error}"),
    )
}

fn fault(
    code: NestedInnerProcessLineageFaultCode,
    message: impl Into<String>,
) -> NestedInnerProcessLineageFault {
    NestedInnerProcessLineageFault {
        code,
        message: message.into(),
    }
}
