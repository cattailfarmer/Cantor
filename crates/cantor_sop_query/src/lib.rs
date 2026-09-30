//! Effect-free lexical discovery over a sealed, supplied SOP project.
//!
//! This crate reads caller-owned in-memory values only. A successful lookup is
//! not a truth, relevance, authorization, execution, or external-effect claim.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use cantor_sop_project::{ProjectAssemblyResult, validate_complete_result};
use cantor_sop_semantics::{Context, Fault, Result, Status, Unit, digest, validate};
use serde::de;
use serde::{Deserialize, Deserializer, Serialize};

pub const FIND_REQUEST_PROFILE: &str = "cantor-sop-semantic-find-request/0.1";
pub const FIND_RESULT_PROFILE: &str = "cantor-sop-semantic-find-result/0.1";
pub const CAPABILITY: &str = "kernel.sop.semantic-find";
pub const MAX_QUERY_MACHINE_BYTES: usize = 1024 * 1024;
pub const MAX_RESULT_MACHINE_BYTES: usize = 80 * 1024 * 1024;
pub const MAX_PAGE_SIZE: u32 = 1_000;
pub const NON_AUTHORITY: &str = "Read-only supplied-value lexical discovery only. No truth, relevance, authorization, filesystem, storage, index, execution, provider, operator, installation, update, remote, mutation, publication, or external-effect authority is granted.";

const QUERY_DIGEST_DOMAIN: &str = "cantor-sop-semantic-find-query/0.1";
const CURSOR_DIGEST_DOMAIN: &str = "cantor-sop-semantic-find-cursor/0.1";
const RESULT_DIGEST_DOMAIN: &str = "cantor-sop-semantic-find-result/0.1";

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchMode {
    Exact,
    #[default]
    Prefix,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct QueryContext {
    pub scope: Option<String>,
    pub purpose: Option<String>,
    pub perspective: Option<String>,
    pub at_epoch_seconds: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindCursor {
    pub generation: String,
    pub query_digest: String,
    pub after_matched_key: String,
    pub after_unit: String,
    pub cursor_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindRequest {
    pub profile: String,
    pub text: String,
    #[serde(default)]
    pub mode: MatchMode,
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default)]
    pub visible_from: Option<String>,
    #[serde(default, deserialize_with = "deserialize_unique_set")]
    pub kinds: BTreeSet<String>,
    #[serde(default)]
    pub context: QueryContext,
    #[serde(default)]
    pub include_superseded: bool,
    #[serde(default = "default_limit")]
    pub limit: u32,
    #[serde(default)]
    pub cursor: Option<FindCursor>,
}

impl FindRequest {
    pub fn prefix(text: impl Into<String>) -> Self {
        Self {
            profile: FIND_REQUEST_PROFILE.to_owned(),
            text: text.into(),
            mode: MatchMode::Prefix,
            namespace: None,
            visible_from: None,
            kinds: BTreeSet::new(),
            context: QueryContext::default(),
            include_superseded: false,
            limit: 50,
            cursor: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindHit {
    pub unit: Unit,
    pub matched_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindResult {
    pub profile: String,
    pub capability: String,
    pub assembly_result_digest: String,
    pub generation: String,
    pub query_digest: String,
    pub items: Vec<FindHit>,
    pub complete: bool,
    pub next: Option<FindCursor>,
    pub non_authority: String,
    pub result_digest: String,
}

pub fn parse_find_request(bytes: &[u8]) -> Result<FindRequest> {
    if bytes.len() > MAX_QUERY_MACHINE_BYTES {
        return Err(Fault::new(
            "query_machine_limit",
            format!("find request exceeds {MAX_QUERY_MACHINE_BYTES} bytes"),
        ));
    }
    serde_json::from_slice(bytes).map_err(Fault::from)
}

pub fn parse_find_result(bytes: &[u8]) -> Result<FindResult> {
    if bytes.len() > MAX_RESULT_MACHINE_BYTES {
        return Err(Fault::new(
            "query_result_machine_limit",
            format!("find result exceeds {MAX_RESULT_MACHINE_BYTES} bytes"),
        ));
    }
    serde_json::from_slice(bytes).map_err(Fault::from)
}

pub fn find(assembly: &ProjectAssemblyResult, request: &FindRequest) -> Result<FindResult> {
    validate_complete_result(assembly)?;
    validate_request(request)?;

    let generation = assembly.snapshot_digest.clone();
    let query_digest = query_digest(request)?;
    let after = match &request.cursor {
        Some(cursor) => {
            validate_cursor(cursor, &generation, &query_digest)?;
            Some((&cursor.after_matched_key, &cursor.after_unit))
        }
        None => None,
    };
    let input = &assembly.analysis.input;
    let packages: BTreeMap<_, _> = input
        .packages
        .iter()
        .map(|package| (package.id.as_str(), package))
        .collect();
    let visible = visible_packages(&packages, request.visible_from.as_deref())?;
    let known_kinds: BTreeSet<_> = input.kinds.iter().map(|kind| kind.id.as_str()).collect();
    for kind in &request.kinds {
        if !known_kinds.contains(kind.as_str()) {
            return Err(Fault::new("unknown_kind", "kind filter is not in the snapshot").at(kind));
        }
    }
    let contexts: BTreeMap<_, _> = input
        .contexts
        .iter()
        .map(|context| (context.id.as_str(), context))
        .collect();
    let needle = digest::label_key(&request.text);
    let mut matches = Vec::new();
    for unit in &input.units {
        if !visible.contains(unit.package.as_str())
            || (!request.kinds.is_empty() && !request.kinds.contains(&unit.kind))
            || request
                .namespace
                .as_ref()
                .is_some_and(|namespace| namespace != &unit.namespace)
            || (!request.include_superseded && matches!(unit.status, Status::Superseded))
        {
            continue;
        }
        let context = contexts.get(unit.context.as_str()).ok_or_else(|| {
            Fault::new("project_result_mismatch", "unit context is absent").at(&unit.id)
        })?;
        if !context_matches(context, &request.context) {
            continue;
        }
        let matched_key = std::iter::once(&unit.label)
            .chain(unit.aliases.iter())
            .map(|label| digest::label_key(label))
            .filter(|label| match request.mode {
                MatchMode::Exact => label == &needle,
                MatchMode::Prefix => label.starts_with(&needle),
            })
            .min();
        if let Some(matched_key) = matched_key {
            matches.push(FindHit {
                unit: unit.clone(),
                matched_key,
            });
        }
    }
    matches.sort_by(|left, right| {
        (&left.matched_key, &left.unit.id).cmp(&(&right.matched_key, &right.unit.id))
    });
    if let Some((after_key, after_unit)) = after {
        matches.retain(|hit| {
            (hit.matched_key.as_str(), hit.unit.id.as_str())
                > (after_key.as_str(), after_unit.as_str())
        });
    }
    let limit = request.limit as usize;
    let complete = matches.len() <= limit;
    matches.truncate(limit);
    let next = if complete {
        None
    } else {
        matches
            .last()
            .map(|last| seal_cursor(&generation, &query_digest, &last.matched_key, &last.unit.id))
            .transpose()?
    };
    let mut result = FindResult {
        profile: FIND_RESULT_PROFILE.to_owned(),
        capability: CAPABILITY.to_owned(),
        assembly_result_digest: assembly.result_digest.clone(),
        generation,
        query_digest,
        items: matches,
        complete,
        next,
        non_authority: NON_AUTHORITY.to_owned(),
        result_digest: String::new(),
    };
    result.result_digest = digest::value(RESULT_DIGEST_DOMAIN, &result)?;
    Ok(result)
}

pub fn validate_find_result(
    assembly: &ProjectAssemblyResult,
    request: &FindRequest,
    result: &FindResult,
) -> Result<()> {
    let expected = find(assembly, request)?;
    if &expected != result {
        return Err(Fault::new(
            "query_result_mismatch",
            "find result differs from deterministic replay",
        ));
    }
    Ok(())
}

fn default_limit() -> u32 {
    50
}

fn validate_request(request: &FindRequest) -> Result<()> {
    if request.profile != FIND_REQUEST_PROFILE {
        return Err(Fault::new(
            "unsupported_query",
            format!("expected {FIND_REQUEST_PROFILE}"),
        ));
    }
    if request.text.len() > 4_096 || request.text.contains('\0') {
        return Err(Fault::new(
            "query_limit",
            "search text exceeds 4096 bytes or contains NUL",
        ));
    }
    if request.limit == 0 || request.limit > MAX_PAGE_SIZE {
        return Err(Fault::new(
            "invalid_budget",
            format!("limit must be 1..{MAX_PAGE_SIZE}"),
        ));
    }
    if request.kinds.len() > 128 {
        return Err(Fault::new("query_limit", "too many kind filters"));
    }
    if let Some(namespace) = &request.namespace {
        validate::identifier(namespace)?;
    }
    if let Some(package) = &request.visible_from {
        validate::identifier(package)?;
    }
    for kind in &request.kinds {
        validate::identifier(kind)?;
    }
    for value in [
        &request.context.scope,
        &request.context.purpose,
        &request.context.perspective,
    ]
    .into_iter()
    .flatten()
    {
        if value.is_empty() || value.len() > 4_096 || value.contains('\0') {
            return Err(Fault::new(
                "invalid_context",
                "context filters require 1..4096 non-NUL UTF-8 bytes",
            ));
        }
    }
    Ok(())
}

fn query_digest(request: &FindRequest) -> Result<String> {
    let mut bound = request.clone();
    bound.cursor = None;
    bound.limit = 0;
    digest::value(QUERY_DIGEST_DOMAIN, &bound)
}

fn seal_cursor(
    generation: &str,
    query_digest: &str,
    after_matched_key: &str,
    after_unit: &str,
) -> Result<FindCursor> {
    let mut cursor = FindCursor {
        generation: generation.to_owned(),
        query_digest: query_digest.to_owned(),
        after_matched_key: after_matched_key.to_owned(),
        after_unit: after_unit.to_owned(),
        cursor_digest: String::new(),
    };
    cursor.cursor_digest = digest::value(CURSOR_DIGEST_DOMAIN, &cursor)?;
    Ok(cursor)
}

fn validate_cursor(cursor: &FindCursor, generation: &str, query_digest: &str) -> Result<()> {
    if cursor.generation != generation {
        return Err(Fault::new(
            "stale_cursor",
            "cursor belongs to another snapshot generation",
        ));
    }
    if cursor.query_digest != query_digest
        || cursor.after_matched_key.len() > 65_536
        || cursor.after_unit.len() > 512
    {
        return Err(Fault::new(
            "cursor_mismatch",
            "cursor does not match this query",
        ));
    }
    validate::identifier(&cursor.after_unit)
        .map_err(|_| Fault::new("cursor_mismatch", "cursor continuation unit is malformed"))?;
    let mut unsigned = cursor.clone();
    unsigned.cursor_digest.clear();
    if digest::value(CURSOR_DIGEST_DOMAIN, &unsigned)? != cursor.cursor_digest {
        return Err(Fault::new("cursor_mismatch", "cursor digest differs"));
    }
    Ok(())
}

fn visible_packages<'a>(
    packages: &BTreeMap<&'a str, &'a cantor_sop_semantics::Package>,
    from: Option<&str>,
) -> Result<BTreeSet<&'a str>> {
    let Some(from) = from else {
        return Ok(packages.keys().copied().collect());
    };
    let root = packages
        .get_key_value(from)
        .map(|(id, _)| *id)
        .ok_or_else(|| {
            Fault::new(
                "unknown_package",
                "visible_from package is not in the snapshot",
            )
            .at(from)
        })?;
    let mut visible = BTreeSet::new();
    let mut queue = VecDeque::from([root]);
    while let Some(id) = queue.pop_front() {
        if !visible.insert(id) {
            continue;
        }
        let package = packages.get(id).ok_or_else(|| {
            Fault::new("project_result_mismatch", "package dependency is absent").at(id)
        })?;
        for dependency in &package.dependencies {
            queue.push_back(dependency.as_str());
        }
    }
    Ok(visible)
}

fn context_matches(context: &Context, query: &QueryContext) -> bool {
    for (allowed, actual) in [
        (&context.scopes, &query.scope),
        (&context.purposes, &query.purpose),
        (&context.perspectives, &query.perspective),
    ] {
        if let Some(actual) = actual
            && !allowed.is_empty()
            && !allowed.contains(actual)
        {
            return false;
        }
    }
    if let Some(at) = query.at_epoch_seconds
        && (context.validity.not_before.is_some_and(|start| at < start)
            || context.validity.not_after.is_some_and(|end| at > end))
    {
        return false;
    }
    true
}

fn deserialize_unique_set<'de, D>(
    deserializer: D,
) -> std::result::Result<BTreeSet<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let values = Vec::<String>::deserialize(deserializer)?;
    let mut result = BTreeSet::new();
    for value in values {
        if !result.insert(value.clone()) {
            return Err(de::Error::custom(format!(
                "duplicate semantic set member refused: {value}"
            )));
        }
    }
    Ok(result)
}
