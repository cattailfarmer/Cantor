//! Self-digested transport packets with a separate canonical reconstruction check.

use cantor_core::ContentDigest;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::{
    AttentionReentryFrame, AttentionTransportKind, AttentionTransportRecord,
    IterativeProviderPhase, ScriptedCompactTransportProjection, TerminalReflectionTransport,
    generate_scripted_compact_transport_projection, validate_scripted_compact_transport_projection,
};

pub const ATTENTION_TRANSPORT_ENVELOPE_PROFILE: &str = "cantor-attention-transport-envelope/0.1";
pub const SCRIPTED_TRANSPORT_ENVELOPE_SET_PROFILE: &str =
    "cantor-scripted-transport-envelope-set/0.1";
pub const ATTENTION_TRANSPORT_ENVELOPE_NONCLAIMS: [&str; 6] = [
    "local digest agreement is not canonical replay binding",
    "sha256 content commitment is not a producer signature",
    "retained-prefix digest does not reconstruct omitted history",
    "packet integrity is not semantic truth or output equivalence",
    "envelope construction is not provider execution",
    "no hidden-state live-token external-effect persistence or remote operation",
];
pub const SCRIPTED_TRANSPORT_ENVELOPE_SET_NONCLAIMS: [&str; 5] = [
    "fixture envelopes are reconstructed without a provider",
    "canonical projection remains the stronger replay authority",
    "canonical reconstruction is not producer authentication",
    "no provider compatibility or semantic-equivalence claim",
    "no process network persistence hidden-state or external-effect operation",
];

const REQUEST_DIGEST_DOMAIN: &str = "cantor.attention-transport.request.v1";
const FRAME_DIGEST_DOMAIN: &str = "cantor.attention-transport.frame.v1";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AttentionTransportEnvelope {
    pub profile: String,
    pub phase: IterativeProviderPhase,
    pub transport_kind: AttentionTransportKind,
    pub iteration_index: Option<u32>,
    pub actual_request: Value,
    pub request_digest: ContentDigest,
    pub reentry_frame: Option<AttentionReentryFrame>,
    pub reentry_frame_digest: Option<ContentDigest>,
    pub retained_prefix_digest: Option<ContentDigest>,
    pub local_integrity_only: bool,
    pub producer_authentication_claimed: bool,
    pub nonclaims: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScriptedTransportEnvelopeSet {
    pub profile: String,
    pub source_projection: ScriptedCompactTransportProjection,
    pub iteration_envelopes: Vec<AttentionTransportEnvelope>,
    pub terminal_reflection_envelope: AttentionTransportEnvelope,
    pub provider_execution_claimed: bool,
    pub semantic_equivalence_claimed: bool,
    pub producer_authentication_claimed: bool,
    pub nonclaims: Vec<String>,
}

pub fn compile_iteration_transport_envelope(
    transport: &AttentionTransportRecord,
) -> Result<AttentionTransportEnvelope, String> {
    let envelope = compile_envelope(
        IterativeProviderPhase::Advance,
        transport.transport_kind,
        Some(transport.iteration_index),
        &transport.actual_request,
        transport.reentry_frame.as_ref(),
    )?;
    validate_attention_transport_envelope(&envelope)?;
    Ok(envelope)
}

pub fn compile_terminal_transport_envelope(
    transport: &TerminalReflectionTransport,
) -> Result<AttentionTransportEnvelope, String> {
    let envelope = compile_envelope(
        IterativeProviderPhase::ReflectTerminal,
        transport.transport_kind,
        None,
        &transport.actual_request,
        Some(&transport.reentry_frame),
    )?;
    validate_attention_transport_envelope(&envelope)?;
    Ok(envelope)
}

pub fn validate_attention_transport_envelope(
    envelope: &AttentionTransportEnvelope,
) -> Result<(), String> {
    if envelope.profile != ATTENTION_TRANSPORT_ENVELOPE_PROFILE
        || !envelope.local_integrity_only
        || envelope.producer_authentication_claimed
        || envelope.nonclaims != envelope_nonclaims()
    {
        return Err("attention transport envelope identity or claims are invalid".to_owned());
    }
    let expected_request_digest = digest_json(REQUEST_DIGEST_DOMAIN, &envelope.actual_request)?;
    if envelope.request_digest != expected_request_digest {
        return Err("attention transport request digest differs from carried bytes".to_owned());
    }
    match envelope.transport_kind {
        AttentionTransportKind::FullPrefix => {
            if envelope.phase != IterativeProviderPhase::Advance
                || envelope.iteration_index != Some(0)
                || envelope.reentry_frame.is_some()
                || envelope.reentry_frame_digest.is_some()
                || envelope.retained_prefix_digest.is_some()
            {
                return Err("full-prefix transport envelope shape is invalid".to_owned());
            }
        }
        AttentionTransportKind::CompactReentry => {
            let frame = envelope
                .reentry_frame
                .as_ref()
                .ok_or_else(|| "compact transport envelope omitted reentry frame".to_owned())?;
            let frame_digest = envelope
                .reentry_frame_digest
                .as_ref()
                .ok_or_else(|| "compact transport envelope omitted frame digest".to_owned())?;
            if frame_digest != &digest_json(FRAME_DIGEST_DOMAIN, frame)?
                || envelope.retained_prefix_digest.as_ref() != Some(&frame.retained_prefix_digest)
                || frame.phase != envelope.phase
            {
                return Err("compact transport frame commitment is invalid".to_owned());
            }
            match envelope.phase {
                IterativeProviderPhase::Advance => {
                    if envelope.iteration_index.is_none() {
                        return Err("compact advance envelope omitted iteration index".to_owned());
                    }
                }
                IterativeProviderPhase::ReflectTerminal => {
                    if envelope.iteration_index.is_some() {
                        return Err(
                            "terminal reflection envelope carried iteration index".to_owned()
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

pub fn validate_iteration_transport_envelope_against(
    envelope: &AttentionTransportEnvelope,
    transport: &AttentionTransportRecord,
) -> Result<(), String> {
    validate_attention_transport_envelope(envelope)?;
    let expected = compile_iteration_transport_envelope(transport)?;
    if envelope != &expected {
        return Err(
            "attention transport envelope differs from canonical iteration reconstruction"
                .to_owned(),
        );
    }
    Ok(())
}

pub fn validate_terminal_transport_envelope_against(
    envelope: &AttentionTransportEnvelope,
    transport: &TerminalReflectionTransport,
) -> Result<(), String> {
    validate_attention_transport_envelope(envelope)?;
    let expected = compile_terminal_transport_envelope(transport)?;
    if envelope != &expected {
        return Err(
            "attention transport envelope differs from canonical terminal reconstruction"
                .to_owned(),
        );
    }
    Ok(())
}

pub fn generate_scripted_transport_envelope_set() -> Result<ScriptedTransportEnvelopeSet, String> {
    let projection = generate_scripted_compact_transport_projection()?;
    project_transport_envelopes(&projection)
}

pub fn project_transport_envelopes(
    projection: &ScriptedCompactTransportProjection,
) -> Result<ScriptedTransportEnvelopeSet, String> {
    validate_scripted_compact_transport_projection(projection)?;
    let iteration_envelopes = projection
        .iteration_transports
        .iter()
        .map(compile_iteration_transport_envelope)
        .collect::<Result<Vec<_>, _>>()?;
    let terminal_reflection_envelope =
        compile_terminal_transport_envelope(&projection.terminal_reflection_transport)?;
    let set = ScriptedTransportEnvelopeSet {
        profile: SCRIPTED_TRANSPORT_ENVELOPE_SET_PROFILE.to_owned(),
        source_projection: projection.clone(),
        iteration_envelopes,
        terminal_reflection_envelope,
        provider_execution_claimed: false,
        semantic_equivalence_claimed: false,
        producer_authentication_claimed: false,
        nonclaims: set_nonclaims(),
    };
    validate_scripted_transport_envelope_set(&set)?;
    Ok(set)
}

pub fn validate_scripted_transport_envelope_set(
    set: &ScriptedTransportEnvelopeSet,
) -> Result<(), String> {
    if set.profile != SCRIPTED_TRANSPORT_ENVELOPE_SET_PROFILE
        || set.provider_execution_claimed
        || set.semantic_equivalence_claimed
        || set.producer_authentication_claimed
        || set.nonclaims != set_nonclaims()
    {
        return Err("scripted transport envelope set identity or claims are invalid".to_owned());
    }
    validate_scripted_compact_transport_projection(&set.source_projection)?;
    if set.iteration_envelopes.len() != set.source_projection.iteration_transports.len() {
        return Err("transport envelope count differs from canonical projection".to_owned());
    }
    for (envelope, transport) in set
        .iteration_envelopes
        .iter()
        .zip(&set.source_projection.iteration_transports)
    {
        validate_iteration_transport_envelope_against(envelope, transport)?;
    }
    validate_terminal_transport_envelope_against(
        &set.terminal_reflection_envelope,
        &set.source_projection.terminal_reflection_transport,
    )?;
    Ok(())
}

pub fn pretty_scripted_transport_envelope_set_bytes(
    set: &ScriptedTransportEnvelopeSet,
) -> Result<Vec<u8>, String> {
    validate_scripted_transport_envelope_set(set)?;
    let mut bytes = serde_json::to_vec_pretty(set)
        .map_err(|error| format!("transport envelope set serialization failed: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn compile_envelope(
    phase: IterativeProviderPhase,
    transport_kind: AttentionTransportKind,
    iteration_index: Option<u32>,
    actual_request: &Value,
    reentry_frame: Option<&AttentionReentryFrame>,
) -> Result<AttentionTransportEnvelope, String> {
    Ok(AttentionTransportEnvelope {
        profile: ATTENTION_TRANSPORT_ENVELOPE_PROFILE.to_owned(),
        phase,
        transport_kind,
        iteration_index,
        actual_request: actual_request.clone(),
        request_digest: digest_json(REQUEST_DIGEST_DOMAIN, actual_request)?,
        reentry_frame: reentry_frame.cloned(),
        reentry_frame_digest: reentry_frame
            .map(|frame| digest_json(FRAME_DIGEST_DOMAIN, frame))
            .transpose()?,
        retained_prefix_digest: reentry_frame.map(|frame| frame.retained_prefix_digest.clone()),
        local_integrity_only: true,
        producer_authentication_claimed: false,
        nonclaims: envelope_nonclaims(),
    })
}

fn digest_json<T: Serialize>(domain: &str, value: &T) -> Result<ContentDigest, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("attention transport digest serialization failed: {error}"))?;
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(bytes);
    Ok(ContentDigest {
        algorithm: "sha256".to_owned(),
        value: hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    })
}

fn envelope_nonclaims() -> Vec<String> {
    ATTENTION_TRANSPORT_ENVELOPE_NONCLAIMS
        .iter()
        .map(ToString::to_string)
        .collect()
}

fn set_nonclaims() -> Vec<String> {
    SCRIPTED_TRANSPORT_ENVELOPE_SET_NONCLAIMS
        .iter()
        .map(ToString::to_string)
        .collect()
}
