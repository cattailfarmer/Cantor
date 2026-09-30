//! Effect-free exact source recovery from a sealed, supplied SOP project.
//!
//! Logical paths remain attribution labels. This component reads only
//! caller-owned values and grants no host, storage, execution, or effect authority.

use cantor_sop_project::{ProjectAssemblyResult, validate_complete_result};
use cantor_sop_semantics::{Fault, Result, SnapshotInput, SourceSpan, digest, source, validate};
use serde::{Deserialize, Serialize};

pub const REQUEST_PROFILE: &str = "cantor-sop-source-excerpt-request/0.1";
pub const RESULT_PROFILE: &str = "cantor-sop-source-excerpt-result/0.1";
pub const CAPABILITY: &str = "kernel.sop.source-excerpt";
pub const MAX_REQUEST_MACHINE_BYTES: usize = 16 * 1024;
pub const MAX_RESULT_MACHINE_BYTES: usize = source::MAX_DOCUMENT_BYTES + 1024 * 1024;
pub const NON_AUTHORITY: &str = "Read-only supplied-value source recovery only. Logical paths grant no host access. No filesystem, storage, index, search, execution, provider, operator, installation, update, remote, mutation, publication, or external-effect authority is granted.";

const REQUEST_DIGEST_DOMAIN: &str = "cantor-sop-source-excerpt-request/0.1";
const RESULT_DIGEST_DOMAIN: &str = "cantor-sop-source-excerpt-result/0.1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceExcerptRequest {
    pub profile: String,
    pub record_id: String,
    pub request_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceExcerptResult {
    pub profile: String,
    pub capability: String,
    pub assembly_result_digest: String,
    pub generation: String,
    pub request_digest: String,
    pub record_id: String,
    pub span: SourceSpan,
    pub path: String,
    pub source_digest: String,
    pub span_digest: String,
    pub text: String,
    pub non_authority: String,
    pub result_digest: String,
}

pub fn request(record_id: impl Into<String>) -> Result<SourceExcerptRequest> {
    let mut request = SourceExcerptRequest {
        profile: REQUEST_PROFILE.to_owned(),
        record_id: record_id.into(),
        request_digest: String::new(),
    };
    validate::identifier(&request.record_id)?;
    request.request_digest = digest::value(REQUEST_DIGEST_DOMAIN, &request)?;
    Ok(request)
}

pub fn parse_request(bytes: &[u8]) -> Result<SourceExcerptRequest> {
    if bytes.len() > MAX_REQUEST_MACHINE_BYTES {
        return Err(Fault::new(
            "excerpt_machine_limit",
            format!("source excerpt request exceeds {MAX_REQUEST_MACHINE_BYTES} bytes"),
        ));
    }
    serde_json::from_slice(bytes).map_err(Fault::from)
}

pub fn parse_result(bytes: &[u8]) -> Result<SourceExcerptResult> {
    if bytes.len() > MAX_RESULT_MACHINE_BYTES {
        return Err(Fault::new(
            "excerpt_result_machine_limit",
            format!("source excerpt result exceeds {MAX_RESULT_MACHINE_BYTES} bytes"),
        ));
    }
    serde_json::from_slice(bytes).map_err(Fault::from)
}

pub fn extract(
    assembly: &ProjectAssemblyResult,
    request: &SourceExcerptRequest,
) -> Result<SourceExcerptResult> {
    validate_complete_result(assembly)?;
    validate_request(request)?;
    let input = &assembly.analysis.input;
    let span = locate_span(input, &request.record_id)?;
    let document = input
        .sources
        .iter()
        .find(|source| source.id == span.source)
        .ok_or_else(|| Fault::new("invalid_span", "source span names an absent document"))?;
    let start = usize::try_from(span.start)
        .map_err(|_| Fault::new("invalid_span", "source span start overflows this host"))?;
    let end = usize::try_from(span.end)
        .map_err(|_| Fault::new("invalid_span", "source span end overflows this host"))?;
    let text = document
        .text
        .get(start..end)
        .ok_or_else(|| Fault::new("invalid_span", "source span is not an exact UTF-8 range"))?
        .to_owned();
    let mut result = SourceExcerptResult {
        profile: RESULT_PROFILE.to_owned(),
        capability: CAPABILITY.to_owned(),
        assembly_result_digest: assembly.result_digest.clone(),
        generation: assembly.snapshot_digest.clone(),
        request_digest: request.request_digest.clone(),
        record_id: request.record_id.clone(),
        span,
        path: document.path.clone(),
        source_digest: digest::bytes(document.text.as_bytes()),
        span_digest: digest::bytes(text.as_bytes()),
        text,
        non_authority: NON_AUTHORITY.to_owned(),
        result_digest: String::new(),
    };
    result.result_digest = digest::value(RESULT_DIGEST_DOMAIN, &result)?;
    Ok(result)
}

pub fn validate_result(
    assembly: &ProjectAssemblyResult,
    request: &SourceExcerptRequest,
    result: &SourceExcerptResult,
) -> Result<()> {
    if extract(assembly, request)? != *result {
        return Err(Fault::new(
            "excerpt_result_mismatch",
            "source excerpt result differs from deterministic replay",
        ));
    }
    Ok(())
}

fn validate_request(request: &SourceExcerptRequest) -> Result<()> {
    if request.profile != REQUEST_PROFILE {
        return Err(Fault::new(
            "unsupported_excerpt",
            format!("expected {REQUEST_PROFILE}"),
        ));
    }
    validate::identifier(&request.record_id)?;
    if !is_sha256(&request.request_digest) {
        return Err(Fault::new(
            "excerpt_request_mismatch",
            "request digest is not lowercase SHA256",
        ));
    }
    let mut unsigned = request.clone();
    unsigned.request_digest.clear();
    if digest::value(REQUEST_DIGEST_DOMAIN, &unsigned)? != request.request_digest {
        return Err(Fault::new(
            "excerpt_request_mismatch",
            "request digest differs",
        ));
    }
    Ok(())
}

fn locate_span(input: &SnapshotInput, record_id: &str) -> Result<SourceSpan> {
    if let Some(document) = input.sources.iter().find(|source| source.id == record_id) {
        return Ok(SourceSpan {
            source: document.id.clone(),
            start: 0,
            end: document.text.len() as u64,
        });
    }
    if input.packages.iter().any(|package| package.id == record_id) {
        return Err(Fault::new(
            "source_unavailable",
            "known package has no declaration source span",
        )
        .at(record_id));
    }
    let spans = input
        .kinds
        .iter()
        .map(|record| (&record.id, &record.source))
        .chain(
            input
                .contexts
                .iter()
                .map(|record| (&record.id, &record.source)),
        )
        .chain(
            input
                .units
                .iter()
                .map(|record| (&record.id, &record.source)),
        )
        .chain(
            input
                .relation_types
                .iter()
                .map(|record| (&record.id, &record.source)),
        )
        .chain(
            input
                .relations
                .iter()
                .map(|record| (&record.id, &record.source)),
        )
        .chain(
            input
                .rules
                .iter()
                .map(|record| (&record.id, &record.source)),
        )
        .chain(
            input
                .views
                .iter()
                .map(|record| (&record.id, &record.source)),
        );
    spans
        .into_iter()
        .find(|(id, _)| id.as_str() == record_id)
        .map(|(_, span)| span.clone())
        .ok_or_else(|| {
            Fault::new("unknown_record", "record is not in the supplied project").at(record_id)
        })
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
