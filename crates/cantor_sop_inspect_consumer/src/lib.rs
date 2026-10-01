//! Exact, effect-free consumer contract and caller-supplied transcript receipts.
//!
//! A receipt proves byte correspondence, not that a process ran or that an
//! executable is trusted. Application launch and acceptance remain separate.

use cantor_sop_inspect_wire::{
    MAX_WIRE_REQUEST_BYTES, MAX_WIRE_RESPONSE_BYTES, REQUEST_PROFILE, RESPONSE_PROFILE, Status,
    parse_request, parse_response, respond,
};
use cantor_sop_semantics::{Fault, Result, digest};
use serde::{Deserialize, Serialize};

pub const CONTRACT_PROFILE: &str = "cantor-semantic-inspection-consumer-contract/0.1";
pub const RECEIPT_PROFILE: &str = "cantor-semantic-inspection-consumer-receipt/0.1";
pub const MAX_CONTRACT_BYTES: usize = 8_192;
pub const MAX_RECEIPT_BYTES: usize = 16_384;
pub const MAX_STDERR_BYTES: usize = 128;
pub const PUBLIC_HOST_FAULT: &[u8] = b"cantor_stdio_host_refused\n";
pub const NON_AUTHORITY: &str = "Read-only caller-supplied transcript correspondence only. A receipt does not prove actual process execution, executable identity, operator approval, application acceptance, or semantic authority. No I/O, process launch, filesystem, storage, service, transport, provider, model, installation, update, remote, message, mutation, or publication authority is granted.";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumerContract {
    pub profile: String,
    pub host_binary: String,
    pub capability: String,
    pub request_profile: String,
    pub response_profile: String,
    pub argument_count: u32,
    pub stdin_framing: String,
    pub stdout_framing: String,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub max_stderr_bytes: usize,
    pub successful_exit: i32,
    pub refused_exit: i32,
    pub public_host_fault: String,
    pub non_authority: String,
    pub contract_digest: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    InspectionSucceeded,
    SemanticRefused,
    HostRefused,
}

/// The zero-argument invocation is a contract assumption, not a launch API.
#[derive(Clone, Copy, Debug)]
pub struct Transcript<'a> {
    pub exit_code: i32,
    pub stdout: &'a [u8],
    pub stderr: &'a [u8],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub profile: String,
    pub contract_digest: String,
    pub request_bytes: usize,
    pub request_sha256: String,
    pub stdout_bytes: usize,
    pub stdout_sha256: String,
    pub stderr_bytes: usize,
    pub stderr_sha256: String,
    pub exit_code: i32,
    pub outcome: Outcome,
    pub wire_request_digest: Option<String>,
    pub wire_response_digest: Option<String>,
    pub non_authority: String,
    pub receipt_digest: String,
}

pub fn contract() -> Result<ConsumerContract> {
    let mut contract = ConsumerContract {
        profile: CONTRACT_PROFILE.to_owned(),
        host_binary: "cantor-sop-inspect-stdio".to_owned(),
        capability: "kernel.sop.semantic-inspect".to_owned(),
        request_profile: REQUEST_PROFILE.to_owned(),
        response_profile: RESPONSE_PROFILE.to_owned(),
        argument_count: 0,
        stdin_framing: "one_nonempty_raw_json_value_then_observed_eof".to_owned(),
        stdout_framing: "one_exact_wire_json_value_without_prefix_suffix_or_newline".to_owned(),
        max_request_bytes: MAX_WIRE_REQUEST_BYTES,
        max_response_bytes: MAX_WIRE_RESPONSE_BYTES,
        max_stderr_bytes: MAX_STDERR_BYTES,
        successful_exit: 0,
        refused_exit: 2,
        public_host_fault: String::from_utf8(PUBLIC_HOST_FAULT.to_vec())
            .expect("the fixed public host fault is ASCII"),
        non_authority: NON_AUTHORITY.to_owned(),
        contract_digest: String::new(),
    };
    contract.contract_digest = digest::value(CONTRACT_PROFILE, &contract)?;
    Ok(contract)
}

pub fn parse_contract(bytes: &[u8]) -> Result<ConsumerContract> {
    if bytes.len() > MAX_CONTRACT_BYTES {
        return Err(Fault::new(
            "consumer_contract_limit",
            "contract exceeds its byte bound",
        ));
    }
    let supplied: ConsumerContract = serde_json::from_slice(bytes).map_err(Fault::from)?;
    if supplied != contract()? {
        return Err(Fault::new(
            "unsupported_consumer_contract",
            "consumer contract coordinates differ",
        ));
    }
    Ok(supplied)
}

pub fn verify(request: &[u8], transcript: Transcript<'_>) -> Result<Receipt> {
    if request.len() > MAX_WIRE_REQUEST_BYTES + 1
        || transcript.stdout.len() > MAX_WIRE_RESPONSE_BYTES
        || transcript.stderr.len() > MAX_STDERR_BYTES
    {
        return Err(Fault::new(
            "consumer_transcript_limit",
            "transcript exceeds its byte bound",
        ));
    }

    let (outcome, wire_request_digest, wire_response_digest) = if parse_request(request).is_err() {
        if transcript.exit_code != 2
            || !transcript.stdout.is_empty()
            || transcript.stderr != PUBLIC_HOST_FAULT
        {
            return Err(Fault::new(
                "consumer_host_refusal_mismatch",
                "invalid outer input lacks the exact host refusal",
            ));
        }
        (Outcome::HostRefused, None, None)
    } else {
        if transcript.exit_code != 0 || !transcript.stderr.is_empty() {
            return Err(Fault::new(
                "consumer_host_failure",
                "valid outer input did not complete its transport",
            ));
        }
        let expected = respond(request)?;
        if transcript.stdout != expected {
            return Err(Fault::new(
                "consumer_response_mismatch",
                "stdout differs from exact deterministic wire replay",
            ));
        }
        let response = parse_response(transcript.stdout)?;
        let outcome = match response.status {
            Status::Succeeded => Outcome::InspectionSucceeded,
            Status::Refused => Outcome::SemanticRefused,
        };
        (
            outcome,
            response.request_digest,
            Some(response.response_digest),
        )
    };

    let mut receipt = Receipt {
        profile: RECEIPT_PROFILE.to_owned(),
        contract_digest: contract()?.contract_digest,
        request_bytes: request.len(),
        request_sha256: digest::bytes(request),
        stdout_bytes: transcript.stdout.len(),
        stdout_sha256: digest::bytes(transcript.stdout),
        stderr_bytes: transcript.stderr.len(),
        stderr_sha256: digest::bytes(transcript.stderr),
        exit_code: transcript.exit_code,
        outcome,
        wire_request_digest,
        wire_response_digest,
        non_authority: NON_AUTHORITY.to_owned(),
        receipt_digest: String::new(),
    };
    receipt.receipt_digest = digest::value(RECEIPT_PROFILE, &receipt)?;
    Ok(receipt)
}

/// Full acceptance always reconstructs from the request and transcript.
pub fn validate_receipt(
    request: &[u8],
    transcript: Transcript<'_>,
    receipt: &Receipt,
) -> Result<()> {
    if verify(request, transcript)? != *receipt {
        return Err(Fault::new(
            "consumer_receipt_mismatch",
            "receipt differs from transcript reconstruction",
        ));
    }
    Ok(())
}

/// Shape/seal parsing is not transcript acceptance; call `validate_receipt`.
pub fn parse_receipt(bytes: &[u8]) -> Result<Receipt> {
    if bytes.len() > MAX_RECEIPT_BYTES {
        return Err(Fault::new(
            "consumer_receipt_limit",
            "receipt exceeds its byte bound",
        ));
    }
    let receipt: Receipt = serde_json::from_slice(bytes).map_err(Fault::from)?;
    if receipt.profile != RECEIPT_PROFILE
        || receipt.contract_digest != contract()?.contract_digest
        || receipt.non_authority != NON_AUTHORITY
        || receipt.request_bytes > MAX_WIRE_REQUEST_BYTES + 1
        || receipt.stdout_bytes > MAX_WIRE_RESPONSE_BYTES
        || receipt.stderr_bytes > MAX_STDERR_BYTES
        || ![
            &receipt.request_sha256,
            &receipt.stdout_sha256,
            &receipt.stderr_sha256,
            &receipt.receipt_digest,
        ]
        .into_iter()
        .all(|value| is_lower_sha256(value))
        || receipt
            .wire_request_digest
            .as_ref()
            .is_some_and(|value| !is_lower_sha256(value))
        || receipt
            .wire_response_digest
            .as_ref()
            .is_some_and(|value| !is_lower_sha256(value))
    {
        return Err(Fault::new(
            "consumer_receipt_mismatch",
            "receipt coordinates or bounds differ",
        ));
    }
    match receipt.outcome {
        Outcome::HostRefused
            if receipt.exit_code == 2
                && receipt.stdout_bytes == 0
                && receipt.stderr_bytes == PUBLIC_HOST_FAULT.len()
                && receipt.wire_request_digest.is_none()
                && receipt.wire_response_digest.is_none() => {}
        Outcome::InspectionSucceeded
            if receipt.exit_code == 0
                && receipt.stderr_bytes == 0
                && receipt.stdout_bytes > 0
                && receipt.wire_request_digest.is_some()
                && receipt.wire_response_digest.is_some() => {}
        Outcome::SemanticRefused
            if receipt.exit_code == 0
                && receipt.stderr_bytes == 0
                && receipt.stdout_bytes > 0
                && receipt.wire_response_digest.is_some() => {}
        _ => {
            return Err(Fault::new(
                "consumer_receipt_mismatch",
                "receipt outcome coordinates differ",
            ));
        }
    }
    let mut unsigned = receipt.clone();
    unsigned.receipt_digest.clear();
    if digest::value(RECEIPT_PROFILE, &unsigned)? != receipt.receipt_digest {
        return Err(Fault::new(
            "consumer_receipt_mismatch",
            "receipt digest differs",
        ));
    }
    Ok(receipt)
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
