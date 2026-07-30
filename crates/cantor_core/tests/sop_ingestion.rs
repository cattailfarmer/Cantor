use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use cantor_core::{
    ExitClass, ProtocolOutcome, RequestedDetailKind, SemanticId, SopCompilerIdentity,
    SopCorpusContext, SopCorpusManifest, SopDocumentInput, SopDocumentManifest, SopFaultKind,
    SopQueryTemplate, SopSigningKeys, build_sop_corpus, embedded_environment_digest,
    lower_sop_corpus,
};
use ed25519_dalek::SigningKey;

fn id(value: &str) -> SemanticId {
    SemanticId::new(value).expect("test identity is valid")
}

fn manifest(path: &str) -> SopCorpusManifest {
    SopCorpusManifest {
        corpus_version: "cantor-sop-corpus/0.1".to_owned(),
        source_root: ".".to_owned(),
        context: SopCorpusContext {
            project: "cantor".to_owned(),
            namespace: "tests".to_owned(),
            source_scope: "test_source".to_owned(),
            purpose: "test governed meaning".to_owned(),
            perspective: "test".to_owned(),
            world: "test/0.1".to_owned(),
        },
        compiler: SopCompilerIdentity {
            compiler_id: id("compiler:sop_test"),
            compiler_version: "0.1.0".to_owned(),
            authority_signer_id: id("signer:sop_test_authority"),
            compiler_signer_id: id("signer:sop_test_compiler"),
        },
        dependency_lock: [("cantor-sop".to_owned(), "0.1".to_owned())]
            .into_iter()
            .collect(),
        proof_ids: vec!["proof:sop_test".to_owned()],
        issued_at_epoch_seconds: 120,
        not_before_epoch_seconds: 100,
        not_after_epoch_seconds: 200,
        documents: vec![SopDocumentManifest {
            document_id: "test_document".to_owned(),
            path: path.to_owned(),
        }],
        queries: vec![SopQueryTemplate {
            name: "semantic-unit".to_owned(),
            terms: ["SemanticUnit".to_owned()].into_iter().collect(),
            subject: None,
            requested_detail_kinds: [
                RequestedDetailKind::Term,
                RequestedDetailKind::Clause,
                RequestedDetailKind::SourceSpan,
            ]
            .into_iter()
            .collect(),
        }],
    }
}

fn input(path: &str, text: &str) -> SopDocumentInput {
    SopDocumentInput {
        document_id: "test_document".to_owned(),
        path: path.to_owned(),
        bytes: text.as_bytes().to_vec(),
    }
}

#[test]
fn bounded_parser_lowers_all_supported_markers_and_exact_unicode_spans() {
    let text = concat!(
        "Subject: Parser Fixture\r\n",
        "Description: exact source fixture\r\n",
        "\r\n",
        "& [SemanticUnit] is a governed meaning\r\n",
        "  + [label] is café\r\n",
        "  @ [source] specifications/SOP_Core.sop\r\n",
        "  ! [claim] is source bytes remain exact\r\n",
        "  = must: verify the quote\r\n",
        "  - never: replace invalid UTF-8\r\n",
    );
    let lowered = lower_sop_corpus(&manifest("fixture.sop"), vec![input("fixture.sop", text)])
        .expect("supported document must lower");
    assert_eq!(lowered.source_count, 1);
    assert_eq!(lowered.unit_count, 6);
    assert_eq!(lowered.relation_count, 5);
    let source = &lowered.package_input.sources[0];
    for unit in &lowered.package_input.units {
        let quote = std::str::from_utf8(&source.bytes[unit.byte_start..unit.byte_end])
            .expect("source quote is valid UTF-8");
        assert!(!quote.starts_with(' '));
        assert!(!quote.ends_with('\r'));
        assert!(!quote.ends_with('\n'));
        assert!(text.contains(quote));
    }
    let cafe = lowered
        .package_input
        .units
        .iter()
        .find(|unit| unit.unit.expression == "label")
        .expect("Unicode member is present");
    assert_eq!(
        &source.bytes[cafe.byte_start..cafe.byte_end],
        "+ [label] is café".as_bytes()
    );
}

#[test]
fn identity_is_stable_across_path_line_ending_and_display_line_relocation() {
    let lf = "Subject: Fixture\n& [SemanticUnit] is governed\n  + [field] is exact\n";
    let crlf_relocated = "Subject: Fixture\r\nDescription: moved lines\r\n\r\n& [SemanticUnit] is governed\r\n  + [field] is exact\r\n";
    let first = lower_sop_corpus(&manifest("first.sop"), vec![input("first.sop", lf)])
        .expect("first source must lower");
    let second = lower_sop_corpus(
        &manifest("moved/second.sop"),
        vec![input("moved/second.sop", crlf_relocated)],
    )
    .expect("relocated source must lower");
    let first_ids = first
        .package_input
        .units
        .iter()
        .map(|unit| unit.unit.unit_id.clone())
        .collect::<BTreeSet<_>>();
    let second_ids = second
        .package_input
        .units
        .iter()
        .map(|unit| unit.unit.unit_id.clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(first_ids, second_ids);
    assert_eq!(
        first.package_input.sources[0].file_id,
        second.package_input.sources[0].file_id
    );
    assert_ne!(
        first.package_input.units[0].byte_start,
        second.package_input.units[0].byte_start
    );
}

#[test]
fn repeated_named_members_are_content_addressed_without_encounter_ordinals() {
    let first = concat!(
        "Subject: Fixture\n",
        "& [Registry] is a record\n",
        "  + [edge] is source to canonical\n",
        "  + [edge] is canonical to solution\n",
    );
    let second = concat!(
        "Subject: Fixture\n",
        "& [Registry] is a record\n",
        "  + [edge] is canonical to solution\n",
        "  + [edge] is source to canonical\n",
    );
    let left = lower_sop_corpus(&manifest("fixture.sop"), vec![input("fixture.sop", first)])
        .expect("repeated field names with distinct bodies are valid");
    let right = lower_sop_corpus(&manifest("fixture.sop"), vec![input("fixture.sop", second)])
        .expect("reordered repeated fields are valid");
    let left_ids = left
        .package_input
        .units
        .iter()
        .map(|unit| unit.unit.unit_id.clone())
        .collect::<BTreeSet<_>>();
    let right_ids = right
        .package_input
        .units
        .iter()
        .map(|unit| unit.unit.unit_id.clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(left_ids, right_ids);
}

#[test]
fn unsupported_malformed_duplicate_and_indentation_inputs_fail_closed() {
    let cases = [
        (
            "Subject: Fixture\n? [condition] is unsupported\n",
            SopFaultKind::InvalidSyntax,
        ),
        (
            "Subject: Fixture\n& [Term]  is double separated\n",
            SopFaultKind::InvalidSyntax,
        ),
        (
            "Subject: Fixture\n & [Term] is odd indentation\n",
            SopFaultKind::InvalidIndentation,
        ),
        (
            "Subject: Fixture\n\t& [Term] is tab indentation\n",
            SopFaultKind::InvalidIndentation,
        ),
        (
            "Subject: Fixture\n& [Term] is same\n& [Term] is same\n",
            SopFaultKind::DuplicateIdentity,
        ),
        (
            "Subject: Fixture\n    + [orphan] is too deep\n",
            SopFaultKind::InvalidIndentation,
        ),
    ];
    for (text, expected_kind) in cases {
        let faults = lower_sop_corpus(&manifest("fixture.sop"), vec![input("fixture.sop", text)])
            .expect_err("malformed source must fail closed");
        assert!(
            faults.iter().any(|fault| fault.kind == expected_kind),
            "missing {expected_kind:?} in {faults:?}"
        );
        assert!(faults.iter().all(|fault| {
            fault.message.len() < 512
                && fault
                    .document_id
                    .as_deref()
                    .is_none_or(|value| value == "test_document")
        }));
    }
}

#[test]
fn separated_keys_build_admitted_verified_protocol_artifacts() {
    let text = concat!(
        "Subject: Fixture\n",
        "& [SemanticUnit] is a governed unit\n",
        "  + [boundary] is exact source only\n",
    );
    let built = build_sop_corpus(
        &manifest("fixture.sop"),
        vec![input("fixture.sop", text)],
        SopSigningKeys {
            authority: SigningKey::from_bytes(&[17_u8; 32]),
            compiler: SigningKey::from_bytes(&[29_u8; 32]),
        },
    )
    .expect("separated keys and governed source must build");
    assert_eq!(built.source_count, 1);
    assert_eq!(built.unit_count, 2);
    assert_eq!(built.relation_count, 1);
    assert_eq!(built.requests.len(), 2);
    let response = cantor_core::execute_protocol_request(
        &built.environment,
        built.requests[1].request.clone(),
    );
    let ProtocolOutcome::Query(result) = response.result else {
        panic!("query preflight must return a query result");
    };
    assert!(
        result
            .records
            .iter()
            .any(|unit| unit.expression == "SemanticUnit")
    );
    assert!(
        result
            .verified_quotes
            .iter()
            .any(|quote| quote.text == "& [SemanticUnit] is a governed unit")
    );

    let faults = build_sop_corpus(
        &manifest("fixture.sop"),
        vec![input("fixture.sop", text)],
        SopSigningKeys {
            authority: SigningKey::from_bytes(&[17_u8; 32]),
            compiler: SigningKey::from_bytes(&[17_u8; 32]),
        },
    )
    .expect_err("one signing seed cannot occupy both roles");
    assert_eq!(faults[0].kind, SopFaultKind::Signing);
}

#[test]
fn self_hosted_environment_rejects_signed_source_tampering_and_scope_drift() {
    let text = concat!(
        "Subject: Fixture\n",
        "& [SemanticUnit] is a governed unit\n",
        "  + [boundary] is exact source only\n",
    );
    let built = build_sop_corpus(
        &manifest("fixture.sop"),
        vec![input("fixture.sop", text)],
        SopSigningKeys {
            authority: SigningKey::from_bytes(&[53_u8; 32]),
            compiler: SigningKey::from_bytes(&[59_u8; 32]),
        },
    )
    .expect("fixture corpus must build");
    let request = built.requests[1].request.clone();

    let mut tampered_environment = built.environment.clone();
    tampered_environment.packages[0].content.sources[0].bytes[0] ^= 1;
    let mut tampered_request = request.clone();
    tampered_request.expected_environment_digest =
        embedded_environment_digest(&tampered_environment)
            .expect("tampered environment remains serializable");
    let tampered = cantor_core::execute_protocol_request(&tampered_environment, tampered_request);
    assert_eq!(tampered.exit_class, ExitClass::TrustFailure);
    assert!(
        tampered
            .faults
            .iter()
            .any(|fault| fault.stage.contains("trust") || fault.stage.contains("package"))
    );

    let mut scope_drift = request;
    scope_drift
        .requested_scope
        .namespaces
        .insert("unauthorized_namespace".to_owned());
    let drifted = cantor_core::execute_protocol_request(&built.environment, scope_drift);
    assert_eq!(drifted.exit_class, ExitClass::TrustFailure);
}

#[test]
fn tracked_self_hosted_manifest_parses_every_selected_semantic_line() {
    let root = workspace_root();
    let manifest_path = root.join("corpus/self_hosted/corpus.json");
    let manifest: SopCorpusManifest = serde_json::from_slice(
        &fs::read(&manifest_path).expect("tracked corpus manifest must be readable"),
    )
    .expect("tracked corpus manifest must be strict valid JSON");
    let source_root = manifest_path
        .parent()
        .expect("manifest has parent")
        .join(&manifest.source_root)
        .canonicalize()
        .expect("source root exists");
    let documents = load_documents(&source_root, &manifest);
    let lowered =
        lower_sop_corpus(&manifest, documents).expect("all selected canonical files must parse");
    assert_eq!(lowered.source_count, 3);
    assert!(lowered.unit_count > 300);
    assert!(lowered.relation_count > 250);
    let expressions = lowered
        .package_input
        .units
        .iter()
        .map(|unit| unit.unit.expression.as_str())
        .collect::<BTreeSet<_>>();
    assert!(expressions.contains("SemanticUnit"));
    assert!(expressions.contains("Cantor"));
    assert!(expressions.contains("PreparedRuntime"));
}

fn load_documents(root: &Path, manifest: &SopCorpusManifest) -> Vec<SopDocumentInput> {
    manifest
        .documents
        .iter()
        .map(|document| {
            let path = root.join(&document.path);
            SopDocumentInput {
                document_id: document.document_id.clone(),
                path: document.path.clone(),
                bytes: fs::read(path).expect("tracked source must be readable"),
            }
        })
        .collect()
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("core crate is nested under workspace root")
        .to_path_buf()
}
