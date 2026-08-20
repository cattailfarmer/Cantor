use std::env;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use cantor_core::{
    CatalogueDerivationRequest, ContentDigest, EmbeddedRuntimeEnvironment,
    LEXICAL_ANCHOR_LOOKUP_PROFILE, LEXICAL_TOKENIZER_PROFILE, LexicalAnchorLookupBudget,
    LexicalAnchorLookupRequest, LexicalAnchorLookupResult, LexicalIndexDerivationRequest,
    MAX_LEXICAL_LOOKUP_MATCHES, MAX_LEXICAL_LOOKUP_POSTINGS, SemanticFabric, SemanticId,
    admit_package, derive_lexical_association_index, derive_semantic_anchor_catalogue,
    lookup_lexical_anchors, preflight_runtime_environment, sha256_bytes,
};
use serde::Serialize;

const MAX_ENVIRONMENT_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_MAXIMUM_POSTINGS: u32 = 16_384;
const DEFAULT_MAXIMUM_MATCHES: u32 = 256;

fn main() -> ExitCode {
    match run(env::args().skip(1).collect()) {
        Ok(success) => {
            let mut stdout = io::stdout().lock();
            if serde_json::to_writer(&mut stdout, &success).is_err() || writeln!(stdout).is_err() {
                write_fallback_fault("output", "failed to serialize lookup success");
                return ExitCode::from(70);
            }
            ExitCode::SUCCESS
        }
        Err(fault) => {
            let mut stderr = io::stderr().lock();
            if serde_json::to_writer(&mut stderr, &fault).is_ok() {
                let _ = writeln!(stderr);
            }
            ExitCode::from(2)
        }
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct LookupSuccess {
    status: &'static str,
    environment_digest: ContentDigest,
    result: LexicalAnchorLookupResult,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct LookupFault {
    status: &'static str,
    stage: String,
    kind: String,
    detail: String,
}

impl LookupFault {
    fn new(stage: &str, kind: &str, detail: impl AsRef<str>) -> Self {
        Self {
            status: "fault",
            stage: stage.to_owned(),
            kind: kind.to_owned(),
            detail: detail.as_ref().chars().take(512).collect(),
        }
    }
}

struct LookupArguments {
    environment: PathBuf,
    text: String,
    maximum_postings: u32,
    maximum_matches: u32,
}

fn run(arguments: Vec<String>) -> Result<LookupSuccess, LookupFault> {
    let arguments = parse_arguments(&arguments)?;
    let environment_bytes = read_bounded_environment(&arguments.environment)?;
    let environment: EmbeddedRuntimeEnvironment = serde_json::from_slice(&environment_bytes)
        .map_err(|error| {
            LookupFault::new(
                "environment",
                "malformed_environment",
                format!("environment is not strict valid JSON: {error}"),
            )
        })?;
    let environment_digest = preflight_runtime_environment(&environment).map_err(|fault| {
        LookupFault::new("environment", "environment_rejected", fault.to_string())
    })?;
    let mut admitted = Vec::with_capacity(environment.packages.len());
    for package in &environment.packages {
        let certificate = package.certificate.as_ref().ok_or_else(|| {
            LookupFault::new(
                "admission",
                "missing_certificate",
                format!(
                    "package {} has no recognition certificate",
                    package.package_id
                ),
            )
        })?;
        admitted.push(
            admit_package(
                package,
                &environment.trust_store,
                &certificate.authority_scope,
                environment.now_epoch_seconds,
            )
            .map_err(|fault| LookupFault::new("admission", "package_rejected", fault.message))?,
        );
    }
    let fabric = SemanticFabric::from_admitted(admitted)
        .map_err(|fault| LookupFault::new("fabric", "fabric_rejected", format!("{fault:?}")))?;
    let logical_revision = format!("environment:{}", environment_digest.value);
    let catalogue = derive_semantic_anchor_catalogue(
        &fabric,
        CatalogueDerivationRequest {
            catalogue_id: semantic_id("catalogue:cantor_anchor_lab")?,
            logical_revision: logical_revision.clone(),
        },
    )
    .map_err(|fault| {
        LookupFault::new(
            "catalogue",
            "catalogue_derivation_failed",
            format!("{}: {}", fault.stage, fault.detail),
        )
    })?;
    let index = derive_lexical_association_index(
        &fabric,
        &catalogue,
        LexicalIndexDerivationRequest {
            index_id: semantic_id("lexical-index:cantor_anchor_lab")?,
            logical_revision,
            tokenizer_profile: LEXICAL_TOKENIZER_PROFILE.to_owned(),
        },
    )
    .map_err(|fault| {
        LookupFault::new(
            "lexical_index",
            &format!("{:?}", fault.kind),
            format!("{}: {}", fault.field, fault.detail),
        )
    })?;
    let request_digest = sha256_bytes(arguments.text.as_bytes());
    let request = LexicalAnchorLookupRequest {
        profile: LEXICAL_ANCHOR_LOOKUP_PROFILE.to_owned(),
        request_id: semantic_id(&format!("request:anchor_lab:{}", request_digest.value))?,
        terms: vec![arguments.text],
        budget: LexicalAnchorLookupBudget {
            maximum_terms: 1,
            maximum_query_bytes: 65_536,
            maximum_unique_tokens: 4_096,
            maximum_postings: arguments.maximum_postings,
            maximum_matches: arguments.maximum_matches,
            maximum_serialized_result_bytes: 16 * 1024 * 1024,
        },
    };
    let result = lookup_lexical_anchors(&fabric, &catalogue, &index, request).map_err(|fault| {
        LookupFault::new(
            "lookup",
            &format!("{:?}", fault.kind),
            format!("{}: {}", fault.field, fault.detail),
        )
    })?;
    Ok(LookupSuccess {
        status: "success",
        environment_digest,
        result,
    })
}

fn parse_arguments(arguments: &[String]) -> Result<LookupArguments, LookupFault> {
    if arguments.first().map(String::as_str) != Some("query") {
        return Err(LookupFault::new(
            "arguments",
            "invalid_command",
            "usage: cantor-anchor-lab query --environment <path> --text <text> [--maximum-postings N] [--maximum-matches N]",
        ));
    }
    let mut environment = None;
    let mut text = None;
    let mut maximum_postings = None;
    let mut maximum_matches = None;
    let mut position = 1;
    while position < arguments.len() {
        let flag = &arguments[position];
        let value = arguments
            .get(position + 1)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                LookupFault::new(
                    "arguments",
                    "missing_value",
                    format!("{flag} requires a value"),
                )
            })?;
        match flag.as_str() {
            "--environment" if environment.is_none() => {
                environment = Some(PathBuf::from(value));
            }
            "--text" if text.is_none() => {
                text = Some(value.clone());
            }
            "--maximum-postings" if maximum_postings.is_none() => {
                maximum_postings = Some(parse_positive_bound(
                    value,
                    flag,
                    MAX_LEXICAL_LOOKUP_POSTINGS,
                )?);
            }
            "--maximum-matches" if maximum_matches.is_none() => {
                maximum_matches = Some(parse_positive_bound(
                    value,
                    flag,
                    MAX_LEXICAL_LOOKUP_MATCHES,
                )?);
            }
            "--environment" | "--text" | "--maximum-postings" | "--maximum-matches" => {
                return Err(LookupFault::new(
                    "arguments",
                    "duplicate_argument",
                    format!("{flag} may be supplied only once"),
                ));
            }
            _ => {
                return Err(LookupFault::new(
                    "arguments",
                    "unknown_argument",
                    format!("unknown argument {flag:?}"),
                ));
            }
        }
        position += 2;
    }
    Ok(LookupArguments {
        environment: environment.ok_or_else(|| {
            LookupFault::new(
                "arguments",
                "missing_environment",
                "--environment is required",
            )
        })?,
        text: text
            .ok_or_else(|| LookupFault::new("arguments", "missing_text", "--text is required"))?,
        maximum_postings: maximum_postings.unwrap_or(DEFAULT_MAXIMUM_POSTINGS),
        maximum_matches: maximum_matches.unwrap_or(DEFAULT_MAXIMUM_MATCHES),
    })
}

fn parse_positive_bound(value: &str, flag: &str, maximum: u32) -> Result<u32, LookupFault> {
    let parsed = value.parse::<u32>().map_err(|_| {
        LookupFault::new(
            "arguments",
            "invalid_bound",
            format!("{flag} requires an unsigned integer"),
        )
    })?;
    if parsed == 0 || parsed > maximum {
        return Err(LookupFault::new(
            "arguments",
            "invalid_bound",
            format!("{flag} must be from 1 through {maximum}"),
        ));
    }
    Ok(parsed)
}

fn read_bounded_environment(path: &PathBuf) -> Result<Vec<u8>, LookupFault> {
    let file = File::open(path).map_err(|error| {
        LookupFault::new(
            "environment",
            "environment_read_failed",
            format!("cannot open environment: {error}"),
        )
    })?;
    let mut bytes = Vec::new();
    file.take(MAX_ENVIRONMENT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            LookupFault::new(
                "environment",
                "environment_read_failed",
                format!("cannot read environment: {error}"),
            )
        })?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_ENVIRONMENT_BYTES {
        return Err(LookupFault::new(
            "environment",
            "environment_size_invalid",
            "environment is empty or exceeds the 64-MiB local limit",
        ));
    }
    Ok(bytes)
}

fn semantic_id(value: &str) -> Result<SemanticId, LookupFault> {
    SemanticId::new(value)
        .map_err(|fault| LookupFault::new("identity", "semantic_identity_invalid", fault.message))
}

fn write_fallback_fault(stage: &str, detail: &str) {
    eprintln!(
        "{{\"status\":\"fault\",\"stage\":\"{stage}\",\"kind\":\"output_failure\",\"detail\":\"{detail}\"}}"
    );
}
