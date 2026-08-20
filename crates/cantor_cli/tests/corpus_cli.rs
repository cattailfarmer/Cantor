use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use cantor_core::{
    ExitClass, ProtocolOutcome, ProtocolResponse, verify_protocol_response_against_environment,
};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

#[test]
fn tracked_corpus_build_is_deterministic_secret_free_and_direct_cli_queryable() {
    let root = workspace_root();
    let manifest = root.join("corpus/self_hosted/corpus.json");
    let temporary = temporary_directory("product");
    let authority_key = temporary.join("authority.key");
    let compiler_key = temporary.join("compiler.key");
    let first_output = temporary.join("first");
    let second_output = temporary.join("second");
    let authority_hex = "11".repeat(32);
    let compiler_hex = "2a".repeat(32);
    fs::write(&authority_key, format!("{authority_hex}\n"))
        .expect("temporary authority seed must be written");
    fs::write(&compiler_key, format!("{compiler_hex}\r\n"))
        .expect("temporary compiler seed must be written");

    let first = run_corpus(
        &manifest,
        &authority_key,
        &compiler_key,
        &first_output,
        false,
    );
    assert_eq!(
        first.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let first_receipt: serde_json::Value =
        serde_json::from_slice(&first.stdout).expect("receipt must be one JSON value");
    assert_eq!(first_receipt["status"], "success");
    assert_eq!(first_receipt["source_count"], 3);
    assert!(first_receipt["unit_count"].as_u64().unwrap_or_default() > 300);
    assert!(first_receipt["relation_count"].as_u64().unwrap_or_default() > 250);

    let expected_names = [
        "build-manifest.json",
        "environment.json",
        "inspect-fabric.json",
        "query-cantor.json",
        "query-prepared-runtime.json",
        "query-semantic-unit.json",
    ];
    for name in expected_names {
        assert!(first_output.join(name).is_file(), "missing artifact {name}");
    }
    let all_artifacts = expected_names
        .iter()
        .flat_map(|name| fs::read(first_output.join(name)).expect("artifact must read"))
        .collect::<Vec<_>>();
    let artifact_text = String::from_utf8(all_artifacts).expect("JSON artifacts are UTF-8");
    assert!(!artifact_text.contains(&authority_hex));
    assert!(!artifact_text.contains(&compiler_hex));

    let environment_path = first_output.join("environment.json");
    let first_lookup = run_anchor_lab(&environment_path, "PreparedRuntime", None, None);
    assert_eq!(
        first_lookup.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&first_lookup.stderr)
    );
    assert!(first_lookup.stderr.is_empty());
    let second_lookup = run_anchor_lab(&environment_path, "PreparedRuntime", None, None);
    assert_eq!(second_lookup.status.code(), Some(0));
    assert_eq!(first_lookup.stdout, second_lookup.stdout);
    let lookup_value: serde_json::Value = serde_json::from_slice(&first_lookup.stdout)
        .expect("anchor lab output must be one JSON value");
    assert_eq!(lookup_value["status"], "success");
    assert_eq!(
        lookup_value["result"]["eligible_tokens"],
        serde_json::json!(["preparedruntime"])
    );
    assert!(
        lookup_value["result"]["matches"]
            .as_array()
            .is_some_and(|matches| !matches.is_empty())
    );
    assert!(
        lookup_value["result"]["matches"][0]["address"]["source_anchors"]
            .as_array()
            .is_some_and(|anchors| !anchors.is_empty())
    );
    assert!(
        lookup_value["result"]["non_authority_statement"]
            .as_str()
            .is_some_and(|statement| statement.contains("Semantic purpose"))
    );

    let substring = run_anchor_lab(&environment_path, "reparedruntime", None, None);
    assert_eq!(substring.status.code(), Some(0));
    let substring_value: serde_json::Value =
        serde_json::from_slice(&substring.stdout).expect("substring control must be JSON");
    assert_eq!(substring_value["result"]["matches"], serde_json::json!([]));
    assert_eq!(
        substring_value["result"]["unmatched_tokens"],
        serde_json::json!(["reparedruntime"])
    );

    let invalid_bound = run_anchor_lab(&environment_path, "PreparedRuntime", Some(0), None);
    assert_eq!(invalid_bound.status.code(), Some(2));
    assert!(invalid_bound.stdout.is_empty());
    let invalid_value: serde_json::Value = serde_json::from_slice(&invalid_bound.stderr)
        .expect("anchor lab fault must be one JSON value");
    assert_eq!(invalid_value["status"], "fault");
    assert_eq!(invalid_value["kind"], "invalid_bound");

    for (request_name, expected_expression, expected_quote_prefix) in [
        (
            "query-semantic-unit.json",
            "SemanticUnit",
            "& [SemanticUnit]",
        ),
        ("query-cantor.json", "Cantor", "+ [Cantor]"),
        (
            "query-prepared-runtime.json",
            "PreparedRuntime",
            "& [PreparedRuntime]",
        ),
    ] {
        let request_path = first_output.join(request_name);
        let output = Command::new(env!("CARGO_BIN_EXE_cantor"))
            .arg("query")
            .arg("--environment")
            .arg(&environment_path)
            .arg("--input")
            .arg(&request_path)
            .output()
            .expect("Cantor query subprocess must run");
        assert_eq!(
            output.status.code(),
            Some(i32::from(ExitClass::Success.code())),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        let response: ProtocolResponse =
            serde_json::from_slice(&output.stdout).expect("CLI response must be protocol JSON");
        let ProtocolOutcome::Query(result) = &response.result else {
            panic!("generated query must produce a query result");
        };
        assert!(
            result
                .records
                .iter()
                .any(|record| record.expression == expected_expression)
        );
        assert!(
            result
                .verified_quotes
                .iter()
                .any(|quote| quote.text.starts_with(expected_quote_prefix))
        );
        let environment =
            serde_json::from_slice(&fs::read(&environment_path).expect("environment must read"))
                .expect("environment must decode");
        let request = serde_json::from_slice(&fs::read(request_path).expect("request must read"))
            .expect("request must decode");
        verify_protocol_response_against_environment(&environment, &request, &response)
            .expect("generated CLI response must equal pinned core execution");
    }

    let conflict = run_corpus(
        &manifest,
        &authority_key,
        &compiler_key,
        &first_output,
        false,
    );
    assert_eq!(conflict.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&conflict.stderr).contains("ArtifactConflict"));

    let second = run_corpus(
        &manifest,
        &authority_key,
        &compiler_key,
        &second_output,
        false,
    );
    assert_eq!(
        second.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    for name in expected_names {
        assert_eq!(
            fs::read(first_output.join(name)).expect("first artifact must read"),
            fs::read(second_output.join(name)).expect("second artifact must read"),
            "artifact {name} must be byte deterministic"
        );
    }

    let replaced = run_corpus(
        &manifest,
        &authority_key,
        &compiler_key,
        &first_output,
        true,
    );
    assert_eq!(
        replaced.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&replaced.stderr)
    );
    for name in expected_names {
        assert_eq!(
            fs::read(first_output.join(name)).expect("replaced artifact must read"),
            fs::read(second_output.join(name)).expect("comparison artifact must read")
        );
    }
    fs::remove_dir_all(&temporary).expect("bounded temporary test directory must be removed");
}

#[test]
fn manifest_unknown_fields_and_equal_signing_seeds_fail_before_publication() {
    let root = workspace_root();
    let tracked_manifest = root.join("corpus/self_hosted/corpus.json");
    let temporary = temporary_directory("negative");
    let malformed_manifest = temporary.join("malformed.json");
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(&tracked_manifest).expect("tracked manifest must read"))
            .expect("tracked manifest must decode");
    value["unexpected"] = serde_json::json!(true);
    fs::write(
        &malformed_manifest,
        serde_json::to_vec(&value).expect("malformed fixture must encode"),
    )
    .expect("malformed fixture must write");
    let key = temporary.join("same.key");
    fs::write(&key, "33".repeat(32)).expect("temporary seed must write");
    let output = temporary.join("output");
    let malformed = run_corpus(&malformed_manifest, &key, &key, &output, false);
    assert_eq!(malformed.status.code(), Some(2));
    assert!(!output.exists());
    assert!(String::from_utf8_lossy(&malformed.stderr).contains("unknown field"));

    let same_key = run_corpus(&tracked_manifest, &key, &key, &output, false);
    assert_eq!(same_key.status.code(), Some(2));
    assert!(!output.exists());
    assert!(String::from_utf8_lossy(&same_key.stderr).contains("Signing"));

    let source_root = temporary.join("source");
    fs::create_dir(&source_root).expect("temporary source root must be created");
    fs::write(
        temporary.join("outside.sop"),
        "Subject: Outside\n& [SemanticUnit] is outside\n",
    )
    .expect("outside source fixture must write");
    let mut escape_value: serde_json::Value =
        serde_json::from_slice(&fs::read(&tracked_manifest).expect("tracked manifest must read"))
            .expect("tracked manifest must decode");
    escape_value["source_root"] = serde_json::json!("source");
    escape_value["documents"] = serde_json::json!([
        {
            "document_id": "escape",
            "path": "../outside.sop"
        }
    ]);
    let escape_manifest = temporary.join("escape.json");
    fs::write(
        &escape_manifest,
        serde_json::to_vec(&escape_value).expect("escape fixture must encode"),
    )
    .expect("escape fixture must write");
    let other_key = temporary.join("other.key");
    fs::write(&other_key, "44".repeat(32)).expect("second seed must write");
    let escaped = run_corpus(&escape_manifest, &key, &other_key, &output, false);
    assert_eq!(escaped.status.code(), Some(2));
    assert!(!output.exists());
    assert!(String::from_utf8_lossy(&escaped.stderr).contains("escapes declared source_root"));

    let private_path = temporary.join("do-not-print-private.key");
    let missing_secret = run_corpus(&tracked_manifest, &private_path, &other_key, &output, false);
    assert_eq!(missing_secret.status.code(), Some(2));
    let diagnostic = String::from_utf8_lossy(&missing_secret.stderr);
    assert!(!diagnostic.contains("do-not-print-private.key"));
    assert!(diagnostic.contains("cannot open authority key"));
    fs::remove_dir_all(&temporary).expect("bounded temporary test directory must be removed");
}

fn run_corpus(
    manifest: &Path,
    authority_key: &Path,
    compiler_key: &Path,
    output: &Path,
    replace: bool,
) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_cantor-corpus"));
    command
        .arg("compile")
        .arg("--manifest")
        .arg(manifest)
        .arg("--authority-key")
        .arg(authority_key)
        .arg("--compiler-key")
        .arg(compiler_key)
        .arg("--output")
        .arg(output);
    if replace {
        command.arg("--replace");
    }
    command.output().expect("cantor-corpus must run")
}

fn run_anchor_lab(
    environment: &Path,
    text: &str,
    maximum_postings: Option<u32>,
    maximum_matches: Option<u32>,
) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_cantor-anchor-lab"));
    command
        .arg("query")
        .arg("--environment")
        .arg(environment)
        .arg("--text")
        .arg(text);
    if let Some(value) = maximum_postings {
        command.arg("--maximum-postings").arg(value.to_string());
    }
    if let Some(value) = maximum_matches {
        command.arg("--maximum-matches").arg(value.to_string());
    }
    command.output().expect("anchor lab subprocess must run")
}

fn temporary_directory(label: &str) -> PathBuf {
    let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "cantor-corpus-test-{}-{sequence}-{label}",
        std::process::id()
    ));
    fs::create_dir(&path).expect("unique temporary directory must be created");
    path
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("CLI crate is nested beneath workspace root")
        .to_path_buf()
}
