//! Typed request and accounting boundary for exact read-only observation of a
//! supplied compiled-lookahead repository slice.
//!
//! This checkpoint defines and validates the pure request ABI only. It performs
//! no filesystem access and starts no Git process. Physical observation is a
//! later function inside this already-signed module boundary.

use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;

use cantor_core::{
    ContentDigest, SJS_RCX_CANONICAL_UUID, SJS_RCX_SIGNATURE_UUID, SemanticId, SjsRcxInputClass,
    SjsRcxRequest, sha256_bytes, validate_sjs_rcx_request,
};
use serde::de::{DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const SJS_RSO_REQUEST_PROFILE: &str =
    "cantor-sjs-lookahead-repository-slice-observation-request/0.1";
pub const SJS_RSO_RECEIPT_PROFILE: &str =
    "cantor-sjs-lookahead-repository-slice-observation-receipt/0.1";
pub const SJS_RSO_VERIFICATION_PROFILE: &str =
    "cantor-sjs-lookahead-repository-slice-observation-verification/0.1";
pub const SJS_RSO_EVIDENCE_PROFILE: &str =
    "cantor-sjs-lookahead-repository-slice-observation-evidence/0.1";
pub const SJS_RSO_CANONICAL_UUID: &str = "f1fd1689-f290-4be6-ad82-e36d58103e1b";
pub const SJS_RSO_SIGNATURE_UUID: &str = "7966d8e4-4944-4547-ae12-cebbc5f80383";
pub const SJS_RSO_SOURCE_UUID: &str = "e4ca7100-5a6f-4276-8797-e5e79395720c";
pub const SJS_RSO_PARENT_COMPLETION_UUID: &str = "c14b101c-5e52-4ef6-927a-729381f95a2e";
pub const SJS_RSO_MAX_MACHINE_FORM_BYTES: usize = 1_048_576;
pub const SJS_RSO_NON_AUTHORITY: &str = "Request validation only until the separately verified observer executes. A request digest or validation result proves no Git executable identity, repository identity, branch, HEAD, commit bytes, blob bytes, physical contact, parent semantic truth, prompt fit, provider behavior, performance, autonomy, write authority, remote state, or external effect.";

const REQUEST_DOMAIN: &str = "cantor.sjs-rso.request.v1";
const MAX_DEPTH: usize = 40;
const MAX_FIELDS: usize = 16_384;
const MAX_TEXT_BYTES: usize = 4_096;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SjsRsoInputClass {
    DisposableLocalGitFixture,
    PinnedLocalCommitTree,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsRsoLimits {
    pub maximum_git_commands: u32,
    pub maximum_command_milliseconds: u64,
    pub maximum_stdout_bytes: u64,
    pub maximum_stderr_bytes: u64,
    pub maximum_executable_bytes: u64,
    pub maximum_index_bytes: u64,
    pub maximum_commit_bytes: u64,
    pub maximum_blob_bytes: u64,
    pub maximum_total_blob_bytes: u64,
    pub maximum_path_bytes: u32,
    pub maximum_evidence_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SjsRsoRequest {
    pub profile: String,
    pub request_id: SemanticId,
    pub run_id: SemanticId,
    pub receipt_id: SemanticId,
    pub input_class: SjsRsoInputClass,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub source_snapshot_uuid: String,
    pub parent_canonical_uuid: String,
    pub parent_completion_signature_uuid: String,
    pub parent_request: SjsRcxRequest,
    pub repository_root: String,
    pub git_executable: String,
    pub expected_git_sha256: ContentDigest,
    pub expected_branch_ref: String,
    pub expected_head: String,
    pub object_format: String,
    pub limits: SjsRsoLimits,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub non_authority: String,
    pub request_digest: ContentDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SjsRsoFaultCode {
    InvalidProfile,
    InvalidIdentity,
    InvalidParent,
    InvalidPath,
    InvalidDigest,
    InvalidGitIdentity,
    InvalidBound,
    InvalidAuthority,
    InvalidMachineForm,
    ArithmeticOverflow,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SjsRsoFault {
    pub code: SjsRsoFaultCode,
    pub detail: String,
}

impl fmt::Display for SjsRsoFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.detail)
    }
}
impl std::error::Error for SjsRsoFault {}

pub fn seal_sjs_rso_request(mut request: SjsRsoRequest) -> Result<SjsRsoRequest, SjsRsoFault> {
    request.request_digest = empty_digest();
    validate_request_body(&request)?;
    request.request_digest = sha256_form(REQUEST_DOMAIN, &request)?;
    validate_sjs_rso_request(&request)?;
    Ok(request)
}

pub fn validate_sjs_rso_request(request: &SjsRsoRequest) -> Result<(), SjsRsoFault> {
    validate_request_body(request)?;
    let expected = digest_without(request, REQUEST_DOMAIN, |value| &mut value.request_digest)?;
    if request.request_digest != expected {
        return Err(fault(
            SjsRsoFaultCode::InvalidDigest,
            "request digest differs",
        ));
    }
    Ok(())
}

fn validate_request_body(request: &SjsRsoRequest) -> Result<(), SjsRsoFault> {
    if request.profile != SJS_RSO_REQUEST_PROFILE {
        return Err(fault(
            SjsRsoFaultCode::InvalidProfile,
            "request profile differs",
        ));
    }
    if request.canonical_uuid != SJS_RSO_CANONICAL_UUID
        || request.signature_uuid != SJS_RSO_SIGNATURE_UUID
        || request.source_snapshot_uuid != SJS_RSO_SOURCE_UUID
        || request.parent_canonical_uuid != SJS_RCX_CANONICAL_UUID
        || request.parent_completion_signature_uuid != SJS_RSO_PARENT_COMPLETION_UUID
        || request.non_authority != SJS_RSO_NON_AUTHORITY
    {
        return Err(fault(
            SjsRsoFaultCode::InvalidAuthority,
            "authority identity differs",
        ));
    }
    for (identity, label) in [
        (&request.request_id, "request"),
        (&request.run_id, "run"),
        (&request.receipt_id, "receipt"),
    ] {
        validate_uuid_id(identity, label)?;
    }
    for evidence_ref in &request.evidence_refs {
        validate_uuid_id(evidence_ref, "evidence reference")?;
    }
    if request.evidence_refs.len() > 64 {
        return Err(fault(
            SjsRsoFaultCode::InvalidBound,
            "evidence references exceed 64",
        ));
    }
    validate_sjs_rcx_request(&request.parent_request).map_err(|error| {
        fault(
            SjsRsoFaultCode::InvalidParent,
            format!("parent request refuses: {error}"),
        )
    })?;
    if request.parent_request.input_class != SjsRcxInputClass::SuppliedUnobservedRepositorySlice
        || request.parent_request.canonical_uuid != SJS_RCX_CANONICAL_UUID
        || request.parent_request.signature_uuid != SJS_RCX_SIGNATURE_UUID
    {
        return Err(fault(
            SjsRsoFaultCode::InvalidParent,
            "parent class or identity differs",
        ));
    }
    validate_absolute_path(&request.repository_root, "repository root")?;
    validate_absolute_path(&request.git_executable, "Git executable")?;
    let normalized_root = request.repository_root.replace('\\', "/");
    if normalized_root != request.parent_request.scope.repository {
        return Err(fault(
            SjsRsoFaultCode::InvalidPath,
            "repository root and parent identity differ",
        ));
    }
    validate_digest(&request.expected_git_sha256, "Git executable SHA256")?;
    validate_text(&request.expected_branch_ref, "branch ref")?;
    let expected_branch = request
        .expected_branch_ref
        .strip_prefix("refs/heads/")
        .ok_or_else(|| {
            fault(
                SjsRsoFaultCode::InvalidGitIdentity,
                "branch ref is not heads",
            )
        })?;
    if expected_branch != request.parent_request.scope.branch {
        return Err(fault(
            SjsRsoFaultCode::InvalidGitIdentity,
            "branch ref and parent branch differ",
        ));
    }
    let head_width = match request.object_format.as_str() {
        "sha1" => 40,
        "sha256" => 64,
        _ => {
            return Err(fault(
                SjsRsoFaultCode::InvalidGitIdentity,
                "object format differs",
            ));
        }
    };
    if request.expected_head.len() != head_width || !is_lower_hex(&request.expected_head) {
        return Err(fault(
            SjsRsoFaultCode::InvalidGitIdentity,
            "HEAD identity differs",
        ));
    }
    validate_limits(&request.limits)?;
    Ok(())
}

fn validate_limits(limits: &SjsRsoLimits) -> Result<(), SjsRsoFault> {
    let valid = (1..=32).contains(&limits.maximum_git_commands)
        && (1..=120_000).contains(&limits.maximum_command_milliseconds)
        && (1..=8_388_608).contains(&limits.maximum_stdout_bytes)
        && (1..=1_048_576).contains(&limits.maximum_stderr_bytes)
        && (1..=67_108_864).contains(&limits.maximum_executable_bytes)
        && (1..=67_108_864).contains(&limits.maximum_index_bytes)
        && (1..=4_194_304).contains(&limits.maximum_commit_bytes)
        && (1..=8_388_608).contains(&limits.maximum_blob_bytes)
        && limits.maximum_total_blob_bytes >= limits.maximum_blob_bytes
        && limits.maximum_total_blob_bytes <= 67_108_864
        && (1..=4_096).contains(&limits.maximum_path_bytes)
        && (1..=8_388_608).contains(&limits.maximum_evidence_bytes);
    if valid {
        Ok(())
    } else {
        Err(fault(
            SjsRsoFaultCode::InvalidBound,
            "observation limits differ",
        ))
    }
}

pub fn to_sjs_rso_request_machine_form(request: &SjsRsoRequest) -> Result<String, SjsRsoFault> {
    to_machine_form(request)
}

pub fn from_sjs_rso_request_machine_form(value: &str) -> Result<SjsRsoRequest, SjsRsoFault> {
    parse_bounded(value)
}

fn validate_absolute_path(value: &str, label: &str) -> Result<(), SjsRsoFault> {
    validate_text(value, label)?;
    if Path::new(value).is_absolute()
        && !value.contains('\0')
        && !value
            .split(['/', '\\'])
            .any(|part| matches!(part, "." | ".."))
    {
        Ok(())
    } else {
        Err(fault(
            SjsRsoFaultCode::InvalidPath,
            format!("{label} is not absolute stable form"),
        ))
    }
}

fn validate_digest(digest: &ContentDigest, label: &str) -> Result<(), SjsRsoFault> {
    if digest.algorithm == "sha256" && digest.value.len() == 64 && is_lower_hex(&digest.value) {
        Ok(())
    } else {
        Err(fault(
            SjsRsoFaultCode::InvalidDigest,
            format!("{label} differs"),
        ))
    }
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn validate_uuid_id(identity: &SemanticId, label: &str) -> Result<(), SjsRsoFault> {
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
        Ok(())
    } else {
        Err(fault(
            SjsRsoFaultCode::InvalidIdentity,
            format!("{label} is not lowercase nonnil UUID-bearing"),
        ))
    }
}

fn validate_text(value: &str, label: &str) -> Result<(), SjsRsoFault> {
    if !value.is_empty()
        && value.len() <= MAX_TEXT_BYTES
        && value.trim() == value
        && value.chars().all(|character| !character.is_control())
    {
        Ok(())
    } else {
        Err(fault(
            SjsRsoFaultCode::InvalidPath,
            format!("{label} text differs"),
        ))
    }
}

fn digest_without<T: Clone + Serialize>(
    value: &T,
    domain: &str,
    field: impl Fn(&mut T) -> &mut ContentDigest,
) -> Result<ContentDigest, SjsRsoFault> {
    let mut copy = value.clone();
    *field(&mut copy) = empty_digest();
    sha256_form(domain, &copy)
}

fn sha256_form<T: Serialize>(domain: &str, value: &T) -> Result<ContentDigest, SjsRsoFault> {
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

fn to_machine_form<T: Serialize>(value: &T) -> Result<String, SjsRsoFault> {
    serde_json::to_string(value).map_err(machine_fault)
}

fn parse_bounded<T: DeserializeOwned + Serialize>(value: &str) -> Result<T, SjsRsoFault> {
    if value.len() > SJS_RSO_MAX_MACHINE_FORM_BYTES {
        return Err(fault(
            SjsRsoFaultCode::InvalidBound,
            "machine form exceeds 1048576 bytes",
        ));
    }
    let mut deserializer = serde_json::Deserializer::from_str(value);
    NoDuplicateJson::deserialize(&mut deserializer).map_err(machine_fault)?;
    deserializer.end().map_err(machine_fault)?;
    let shape: Value = serde_json::from_str(value).map_err(machine_fault)?;
    let mut fields = 0;
    validate_shape(&shape, 1, &mut fields)?;
    let parsed: T = serde_json::from_str(value).map_err(machine_fault)?;
    if to_machine_form(&parsed)? != value {
        return Err(fault(
            SjsRsoFaultCode::InvalidMachineForm,
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

fn validate_shape(value: &Value, depth: usize, fields: &mut usize) -> Result<(), SjsRsoFault> {
    if depth > MAX_DEPTH {
        return Err(fault(
            SjsRsoFaultCode::InvalidMachineForm,
            "depth exceeds 40",
        ));
    }
    match value {
        Value::Object(map) => {
            *fields = fields.checked_add(map.len()).ok_or_else(|| {
                fault(SjsRsoFaultCode::ArithmeticOverflow, "field count overflow")
            })?;
            if *fields > MAX_FIELDS {
                return Err(fault(
                    SjsRsoFaultCode::InvalidMachineForm,
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

fn machine_fault(error: impl fmt::Display) -> SjsRsoFault {
    fault(SjsRsoFaultCode::InvalidMachineForm, error.to_string())
}
fn fault(code: SjsRsoFaultCode, detail: impl Into<String>) -> SjsRsoFault {
    SjsRsoFault {
        code,
        detail: detail.into(),
    }
}
