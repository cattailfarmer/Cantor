//! Effect-free composition of supplied SOP assembly, discovery, and source recovery.
//!
//! Every input is caller-owned. This crate adds correspondence and an outer
//! receipt; it grants no host, storage, transport, execution, or effect authority.

use cantor_sop_excerpt::{SourceExcerptResult, extract, request as excerpt_request};
use cantor_sop_project::{
    ProjectAssemblyResult, SuppliedProject, assemble, validate_complete_result,
};
use cantor_sop_query::{FindRequest, FindResult, find};
use cantor_sop_semantics::{Fault, Result, digest};
use serde::{Deserialize, Serialize};

pub const REQUEST_PROFILE: &str = "cantor-sop-semantic-inspection-request/0.1";
pub const RESULT_PROFILE: &str = "cantor-sop-semantic-inspection-result/0.1";
pub const CAPABILITY: &str = "kernel.sop.semantic-inspect";
pub const MAX_PAGE_SIZE: u32 = 64;
pub const MAX_AGGREGATE_EXCERPT_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_REQUEST_MACHINE_BYTES: usize = 80 * 1024 * 1024;
pub const MAX_RESULT_MACHINE_BYTES: usize = 128 * 1024 * 1024;
pub const NON_AUTHORITY: &str = "Read-only supplied-value semantic inspection only. Logical paths grant no host access. No filesystem, storage, cache, transport, execution, provider, operator, installation, update, remote, mutation, publication, or external-effect authority is granted.";

const REQUEST_DIGEST_DOMAIN: &str = "cantor-sop-semantic-inspection-request/0.1";
const RESULT_DIGEST_DOMAIN: &str = "cantor-sop-semantic-inspection-result/0.1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Projection {
    PageHitsWithExactSource,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InspectionRequest {
    pub profile: String,
    pub project: SuppliedProject,
    pub find: FindRequest,
    pub projection: Projection,
    pub request_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssemblyReceipt {
    pub project_digest: String,
    pub snapshot_digest: String,
    pub assembly_result_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InspectionResult {
    pub profile: String,
    pub capability: String,
    pub request_digest: String,
    pub projection: Projection,
    pub assembly: AssemblyReceipt,
    pub find: FindResult,
    pub excerpts: Vec<SourceExcerptResult>,
    pub non_authority: String,
    pub result_digest: String,
}

pub fn request(project: SuppliedProject, find: FindRequest) -> Result<InspectionRequest> {
    let mut request = InspectionRequest {
        profile: REQUEST_PROFILE.to_owned(),
        project,
        find,
        projection: Projection::PageHitsWithExactSource,
        request_digest: String::new(),
    };
    validate_request_shape(&request, false)?;
    request.request_digest = digest::value(REQUEST_DIGEST_DOMAIN, &request)?;
    Ok(request)
}

pub fn parse_request(bytes: &[u8]) -> Result<InspectionRequest> {
    if bytes.len() > MAX_REQUEST_MACHINE_BYTES {
        return Err(Fault::new(
            "inspection_machine_limit",
            "inspection request exceeds its machine bound",
        ));
    }
    serde_json::from_slice(bytes).map_err(Fault::from)
}

pub fn parse_result(bytes: &[u8]) -> Result<InspectionResult> {
    if bytes.len() > MAX_RESULT_MACHINE_BYTES {
        return Err(Fault::new(
            "inspection_result_machine_limit",
            "inspection result exceeds its machine bound",
        ));
    }
    serde_json::from_slice(bytes).map_err(Fault::from)
}

pub fn inspect(request: &InspectionRequest) -> Result<InspectionResult> {
    validate_request_shape(request, true)?;
    let assembly = assemble(&request.project)?;
    validate_complete_result(&assembly)?;
    let found = find(&assembly, &request.find)?;
    let mut excerpts = Vec::with_capacity(found.items.len());
    let mut excerpt_bytes = 0usize;
    for hit in &found.items {
        let excerpt_request = excerpt_request(hit.unit.id.clone())?;
        let excerpt = extract(&assembly, &excerpt_request)?;
        excerpt_bytes = excerpt_bytes
            .checked_add(excerpt.text.len())
            .ok_or_else(|| Fault::new("inspection_limit", "aggregate excerpt bytes overflow"))?;
        if excerpt_bytes > MAX_AGGREGATE_EXCERPT_BYTES {
            return Err(Fault::new(
                "inspection_limit",
                "aggregate excerpt bytes exceed the inspection bound",
            ));
        }
        excerpts.push(excerpt);
    }
    validate_correspondence(&assembly, &found, &excerpts)?;
    let mut result = InspectionResult {
        profile: RESULT_PROFILE.to_owned(),
        capability: CAPABILITY.to_owned(),
        request_digest: request.request_digest.clone(),
        projection: request.projection,
        assembly: assembly_receipt(&assembly),
        find: found,
        excerpts,
        non_authority: NON_AUTHORITY.to_owned(),
        result_digest: String::new(),
    };
    result.result_digest = digest::value(RESULT_DIGEST_DOMAIN, &result)?;
    Ok(result)
}

pub fn validate_result(request: &InspectionRequest, result: &InspectionResult) -> Result<()> {
    if inspect(request)? != *result {
        return Err(Fault::new(
            "inspection_result_mismatch",
            "inspection result differs from deterministic replay",
        ));
    }
    Ok(())
}

fn validate_request_shape(request: &InspectionRequest, sealed: bool) -> Result<()> {
    if request.profile != REQUEST_PROFILE {
        return Err(Fault::new(
            "unsupported_inspection",
            format!("expected {REQUEST_PROFILE}"),
        ));
    }
    if request.find.limit > MAX_PAGE_SIZE {
        return Err(Fault::new(
            "inspection_limit",
            format!("inspection page limit exceeds {MAX_PAGE_SIZE}"),
        ));
    }
    if sealed {
        if request.request_digest.len() != 64
            || !request
                .request_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(Fault::new(
                "inspection_request_mismatch",
                "request digest is not lowercase SHA256",
            ));
        }
        let mut unsigned = request.clone();
        unsigned.request_digest.clear();
        if digest::value(REQUEST_DIGEST_DOMAIN, &unsigned)? != request.request_digest {
            return Err(Fault::new(
                "inspection_request_mismatch",
                "request digest differs",
            ));
        }
    } else if !request.request_digest.is_empty() {
        return Err(Fault::new(
            "inspection_request_mismatch",
            "unsealed request contains a digest",
        ));
    }
    Ok(())
}

fn assembly_receipt(assembly: &ProjectAssemblyResult) -> AssemblyReceipt {
    AssemblyReceipt {
        project_digest: assembly.project_digest.clone(),
        snapshot_digest: assembly.snapshot_digest.clone(),
        assembly_result_digest: assembly.result_digest.clone(),
    }
}

fn validate_correspondence(
    assembly: &ProjectAssemblyResult,
    found: &FindResult,
    excerpts: &[SourceExcerptResult],
) -> Result<()> {
    if found.assembly_result_digest != assembly.result_digest
        || found.generation != assembly.snapshot_digest
        || found.items.len() != excerpts.len()
    {
        return Err(Fault::new(
            "correspondence_mismatch",
            "nested result lineage or cardinality differs",
        ));
    }
    for (hit, excerpt) in found.items.iter().zip(excerpts) {
        if excerpt.record_id != hit.unit.id
            || excerpt.assembly_result_digest != assembly.result_digest
            || excerpt.generation != assembly.snapshot_digest
        {
            return Err(Fault::new(
                "correspondence_mismatch",
                "find hit and source excerpt differ",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cantor_sop_project::{PROJECT_PROFILE, SuppliedFile, SuppliedPackage};
    use cantor_sop_query::FindRequest;

    const SOURCE: &str = "kind [kind:fact] \"Fact\" { meaning \"An observation\" }\ncontext [context:any] { scopes () purposes () perspectives () }\nterm [site:cafe] \"Café reviewed\" { kind [kind:fact] context [context:any] meaning \"The café was reviewed\" aliases (\"Reviewed\") }\n";

    fn project() -> SuppliedProject {
        SuppliedProject {
            profile: PROJECT_PROFILE.to_owned(),
            packages: vec![SuppliedPackage {
                id: "pkg:site".to_owned(),
                version: "1.0.0".to_owned(),
                namespaces: ["site".to_owned()].into_iter().collect(),
                dependencies: Default::default(),
                files: vec![SuppliedFile {
                    id: "source:site".to_owned(),
                    path: "site/main.sop".to_owned(),
                    namespace: "site".to_owned(),
                    text: SOURCE.to_owned(),
                }],
            }],
        }
    }

    #[test]
    fn one_request_returns_exact_source_bearing_hits() {
        let request = request(project(), FindRequest::prefix("Caf")).unwrap();
        let result = inspect(&request).unwrap();
        assert_eq!(result.capability, CAPABILITY);
        assert_eq!(result.find.items.len(), 1);
        assert_eq!(result.excerpts.len(), 1);
        assert_eq!(result.excerpts[0].record_id, "site:cafe");
        assert!(
            result.excerpts[0]
                .text
                .starts_with("term [site:cafe] \"Café")
        );
        validate_result(&request, &result).unwrap();
    }

    #[test]
    fn empty_page_is_exact_and_repeatable() {
        let request = request(project(), FindRequest::prefix("Absent")).unwrap();
        let first = inspect(&request).unwrap();
        assert!(first.find.items.is_empty());
        assert!(first.excerpts.is_empty());
        assert_eq!(first, inspect(&request).unwrap());
    }

    #[test]
    fn request_digest_and_page_bound_refuse() {
        let mut request = request(project(), FindRequest::prefix("Caf")).unwrap();
        request.find.text.push('!');
        assert_eq!(
            inspect(&request).unwrap_err().code,
            "inspection_request_mismatch"
        );
        let mut find = FindRequest::prefix("Caf");
        find.limit = MAX_PAGE_SIZE + 1;
        assert_eq!(
            super::request(project(), find).unwrap_err().code,
            "inspection_limit"
        );
    }

    #[test]
    fn nested_and_outer_tampering_refuse() {
        let request = request(project(), FindRequest::prefix("Caf")).unwrap();
        let result = inspect(&request).unwrap();
        for mutate in [
            |value: &mut InspectionResult| value.excerpts[0].record_id = "site:other".to_owned(),
            |value: &mut InspectionResult| value.find.items.clear(),
            |value: &mut InspectionResult| value.assembly.snapshot_digest = "0".repeat(64),
            |value: &mut InspectionResult| value.result_digest = "0".repeat(64),
        ] {
            let mut changed = result.clone();
            mutate(&mut changed);
            assert_eq!(
                validate_result(&request, &changed).unwrap_err().code,
                "inspection_result_mismatch"
            );
        }
    }

    #[test]
    fn strict_machine_forms_and_raw_bounds_refuse() {
        let request = request(project(), FindRequest::prefix("Caf")).unwrap();
        assert_eq!(
            parse_request(&serde_json::to_vec(&request).unwrap()).unwrap(),
            request
        );
        assert!(parse_request(br#"{}{}"#).is_err());
        assert_eq!(
            parse_request(&vec![b' '; MAX_REQUEST_MACHINE_BYTES + 1])
                .unwrap_err()
                .code,
            "inspection_machine_limit"
        );
        let result = inspect(&request).unwrap();
        let bytes = serde_json::to_vec(&result).unwrap();
        assert_eq!(parse_result(&bytes).unwrap(), result);
        let mut trailing = bytes;
        trailing.extend_from_slice(b"{}");
        assert!(parse_result(&trailing).is_err());
    }
}
