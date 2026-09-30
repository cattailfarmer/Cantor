//! Effect-free SOP semantic forms, source analysis, validation, and identity.
//!
//! Every operation consumes supplied in-memory values and returns data or a
//! bounded fault. Semantic validity grants no execution or external authority.

pub mod digest;
pub mod error;
pub mod expression;
pub mod model;
pub mod source;
pub mod validate;

use serde::{Deserialize, Serialize};

pub use error::{Fault, Result};
pub use model::*;

pub const INPUT_PROFILE: &str = "cantor-sop-semantics-input/0.1";
pub const SNAPSHOT_PROFILE: &str = "cantor-sop-semantics-snapshot/0.1";
pub const ANALYSIS_REQUEST_PROFILE: &str = "cantor-sop-semantic-analysis-request/0.1";
pub const ANALYSIS_RESULT_PROFILE: &str = "cantor-sop-semantic-analysis-result/0.1";
pub const SEMANTIC_SCHEMA: &str = "sop-semantic-study/0.1";
pub const STORAGE_VERSION: u32 = 1;
pub const COMPILER_ID: &str = "cantor_sop_semantics/0.1.0";
pub const MAX_INPUT_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_RECORDS: usize = 250_000;
pub const CAPABILITY: &str = "kernel.sop.semantic-analyze";
pub const NON_AUTHORITY: &str = "Pure semantic analysis only. No execution, provider, operator, installation, update, remote, mutation, publication, or external-effect authority is granted.";
pub const REQUIRED_FEATURES: &[&str] = &[
    "exact-source-spans",
    "typed-role-relations",
    "three-valued-guards",
    "named-views",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisRequest {
    pub profile: String,
    pub source: SourceDocument,
    pub namespace: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisResult {
    pub profile: String,
    pub capability: String,
    pub source_digest: String,
    pub analysis: source::DocumentAnalysis,
    pub non_authority: String,
    pub result_digest: String,
}

pub fn parse_analysis_request(bytes: &[u8]) -> Result<AnalysisRequest> {
    serde_json::from_slice(bytes).map_err(Fault::from)
}

pub fn parse_snapshot_input(bytes: &[u8]) -> Result<SnapshotInput> {
    serde_json::from_slice(bytes).map_err(Fault::from)
}

pub fn analyze(request: &AnalysisRequest) -> Result<AnalysisResult> {
    if request.profile != ANALYSIS_REQUEST_PROFILE {
        return Err(Fault::new(
            "unsupported_profile",
            format!("expected {ANALYSIS_REQUEST_PROFILE}"),
        ));
    }
    validate::source_document(&request.source)?;
    validate::identifier(&request.namespace)?;
    let source_digest = digest::value("cantor-sop-source-document/0.1", &request.source)?;
    let mut result = AnalysisResult {
        profile: ANALYSIS_RESULT_PROFILE.to_owned(),
        capability: CAPABILITY.to_owned(),
        source_digest,
        analysis: source::analyze(&request.source, &request.namespace),
        non_authority: NON_AUTHORITY.to_owned(),
        result_digest: String::new(),
    };
    result.result_digest = digest::value("cantor-sop-semantic-analysis-result/0.1", &result)?;
    Ok(result)
}

pub fn validate_analysis_result(request: &AnalysisRequest, result: &AnalysisResult) -> Result<()> {
    let expected = analyze(request)?;
    if &expected != result {
        return Err(Fault::new(
            "analysis_digest_mismatch",
            "analysis result differs from deterministic replay",
        ));
    }
    Ok(())
}
