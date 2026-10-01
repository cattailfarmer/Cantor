//! Effect-free machine envelope for composed SOP semantic inspection.
//!
//! The caller supplies and retains every byte. This crate performs no I/O and
//! grants no host, process, transport, storage, provider, or execution authority.

use cantor_sop_inspect::{
    CAPABILITY, InspectionRequest, InspectionResult, MAX_REQUEST_MACHINE_BYTES,
    MAX_RESULT_MACHINE_BYTES, inspect,
};
use cantor_sop_semantics::{Fault, Result, digest};
use serde::{Deserialize, Serialize};

pub const REQUEST_PROFILE: &str = "cantor-sop-inspection-wire-request/0.1";
pub const RESPONSE_PROFILE: &str = "cantor-sop-inspection-wire-response/0.1";
pub const MAX_WIRE_REQUEST_BYTES: usize = MAX_REQUEST_MACHINE_BYTES + 65_536;
pub const MAX_WIRE_RESPONSE_BYTES: usize = MAX_RESULT_MACHINE_BYTES + 65_536;
pub const MAX_FAULT_CODE_BYTES: usize = 128;
pub const MAX_FAULT_MESSAGE_BYTES: usize = 1_024;
pub const NON_AUTHORITY: &str = "In-memory semantic inspection wire representation only. No stdin, stdout, filesystem, socket, service, process, transport, storage, provider, model, operator, installation, update, remote, mutation, publication, or external-effect authority is granted.";

const RESPONSE_DIGEST_DOMAIN: &str = "cantor-sop-inspection-wire-response/0.1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    SemanticInspect,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Succeeded,
    Refused,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireRequest {
    pub profile: String,
    pub operation: Operation,
    pub request: InspectionRequest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireFault {
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireResponse {
    pub profile: String,
    pub capability: String,
    pub operation: Operation,
    pub status: Status,
    pub request_digest: Option<String>,
    pub result: Option<InspectionResult>,
    pub fault: Option<WireFault>,
    pub non_authority: String,
    pub response_digest: String,
}

pub fn request(request: InspectionRequest) -> WireRequest {
    WireRequest {
        profile: REQUEST_PROFILE.to_owned(),
        operation: Operation::SemanticInspect,
        request,
    }
}

pub fn parse_request(bytes: &[u8]) -> Result<WireRequest> {
    if bytes.len() > MAX_WIRE_REQUEST_BYTES {
        return Err(Fault::new(
            "wire_request_limit",
            "wire request exceeds its machine bound",
        ));
    }
    let request: WireRequest = serde_json::from_slice(bytes).map_err(Fault::from)?;
    if request.profile != REQUEST_PROFILE {
        return Err(Fault::new(
            "unsupported_wire",
            format!("expected {REQUEST_PROFILE}"),
        ));
    }
    Ok(request)
}

pub fn parse_response(bytes: &[u8]) -> Result<WireResponse> {
    if bytes.len() > MAX_WIRE_RESPONSE_BYTES {
        return Err(Fault::new(
            "wire_response_limit",
            "wire response exceeds its machine bound",
        ));
    }
    let response: WireResponse = serde_json::from_slice(bytes).map_err(Fault::from)?;
    validate_response_shape(&response, true)?;
    Ok(response)
}

pub fn respond(bytes: &[u8]) -> Result<Vec<u8>> {
    let response = match parse_request(bytes) {
        Ok(request) => match inspect(&request.request) {
            Ok(result) => success(&request.request, result)?,
            Err(fault) => refusal(valid_request_digest(&request.request), fault)?,
        },
        Err(fault) => refusal(None, fault)?,
    };
    let encoded = serde_json::to_vec(&response).map_err(Fault::from)?;
    if encoded.len() <= MAX_WIRE_RESPONSE_BYTES {
        return Ok(encoded);
    }
    let bounded = refusal(
        None,
        Fault::new(
            "wire_response_limit",
            "wire response exceeds its machine bound",
        ),
    )?;
    let encoded = serde_json::to_vec(&bounded).map_err(Fault::from)?;
    if encoded.len() > MAX_WIRE_RESPONSE_BYTES {
        return Err(Fault::new(
            "wire_response_limit",
            "bounded refusal exceeds the wire response machine bound",
        ));
    }
    Ok(encoded)
}

pub fn validate_response(request_bytes: &[u8], response: &WireResponse) -> Result<()> {
    validate_response_shape(response, true)?;
    let expected = parse_response(&respond(request_bytes)?)?;
    if &expected != response {
        return Err(Fault::new(
            "wire_response_mismatch",
            "wire response differs from deterministic replay",
        ));
    }
    Ok(())
}

pub fn validate_response_bytes(request_bytes: &[u8], response_bytes: &[u8]) -> Result<()> {
    let response = parse_response(response_bytes)?;
    validate_response(request_bytes, &response)
}

fn success(request: &InspectionRequest, result: InspectionResult) -> Result<WireResponse> {
    seal(WireResponse {
        profile: RESPONSE_PROFILE.to_owned(),
        capability: CAPABILITY.to_owned(),
        operation: Operation::SemanticInspect,
        status: Status::Succeeded,
        request_digest: valid_request_digest(request),
        result: Some(result),
        fault: None,
        non_authority: NON_AUTHORITY.to_owned(),
        response_digest: String::new(),
    })
}

fn refusal(request_digest: Option<String>, fault: Fault) -> Result<WireResponse> {
    let code = if !fault.code.is_empty() && fault.code.len() <= MAX_FAULT_CODE_BYTES {
        fault.code
    } else {
        "internal_fault".to_owned()
    };
    seal(WireResponse {
        profile: RESPONSE_PROFILE.to_owned(),
        capability: CAPABILITY.to_owned(),
        operation: Operation::SemanticInspect,
        status: Status::Refused,
        request_digest,
        result: None,
        fault: Some(WireFault {
            code,
            message: bounded_utf8(&fault.message, MAX_FAULT_MESSAGE_BYTES),
        }),
        non_authority: NON_AUTHORITY.to_owned(),
        response_digest: String::new(),
    })
}

fn seal(mut response: WireResponse) -> Result<WireResponse> {
    validate_response_shape(&response, false)?;
    response.response_digest = digest::value(RESPONSE_DIGEST_DOMAIN, &response)?;
    Ok(response)
}

fn validate_response_shape(response: &WireResponse, sealed: bool) -> Result<()> {
    if response.profile != RESPONSE_PROFILE
        || response.capability != CAPABILITY
        || response.non_authority != NON_AUTHORITY
    {
        return Err(Fault::new(
            "unsupported_wire",
            "wire response coordinates differ",
        ));
    }
    if response
        .request_digest
        .as_ref()
        .is_some_and(|value| !is_lower_sha256(value))
    {
        return Err(Fault::new(
            "wire_response_mismatch",
            "wire request digest shape differs",
        ));
    }
    match (&response.status, &response.result, &response.fault) {
        (Status::Succeeded, Some(_), None) | (Status::Refused, None, Some(_)) => {}
        _ => {
            return Err(Fault::new(
                "wire_response_mismatch",
                "wire success and refusal fields are not exclusive",
            ));
        }
    }
    if let Some(fault) = &response.fault
        && (fault.code.is_empty()
            || fault.code.len() > MAX_FAULT_CODE_BYTES
            || fault.message.len() > MAX_FAULT_MESSAGE_BYTES)
    {
        return Err(Fault::new(
            "wire_response_mismatch",
            "wire fault exceeds its bound",
        ));
    }
    if sealed {
        if !is_lower_sha256(&response.response_digest) {
            return Err(Fault::new(
                "wire_response_mismatch",
                "wire response digest is not lowercase SHA256",
            ));
        }
        let mut unsigned = response.clone();
        unsigned.response_digest.clear();
        if digest::value(RESPONSE_DIGEST_DOMAIN, &unsigned)? != response.response_digest {
            return Err(Fault::new(
                "wire_response_mismatch",
                "wire response digest differs",
            ));
        }
    } else if !response.response_digest.is_empty() {
        return Err(Fault::new(
            "wire_response_mismatch",
            "unsealed wire response contains a digest",
        ));
    }
    Ok(())
}

fn valid_request_digest(request: &InspectionRequest) -> Option<String> {
    is_lower_sha256(&request.request_digest).then(|| request.request_digest.clone())
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn bounded_utf8(value: &str, maximum: usize) -> String {
    if value.len() <= maximum {
        return value.to_owned();
    }
    let mut end = maximum;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf8_fault_bounds_end_at_character_boundary() {
        let text = "é".repeat(MAX_FAULT_MESSAGE_BYTES);
        let bounded = bounded_utf8(&text, MAX_FAULT_MESSAGE_BYTES - 1);
        assert!(bounded.len() < MAX_FAULT_MESSAGE_BYTES);
        assert!(bounded.is_char_boundary(bounded.len()));
    }

    #[test]
    fn oversized_fault_code_becomes_internal_fault() {
        let response = refusal(None, Fault::new("x".repeat(129), "bounded")).unwrap();
        assert_eq!(response.fault.unwrap().code, "internal_fault");
    }
}
