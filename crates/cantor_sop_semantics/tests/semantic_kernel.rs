use std::collections::{BTreeMap, BTreeSet};

use cantor_sop_semantics::expression;
use cantor_sop_semantics::source;
use cantor_sop_semantics::{
    ANALYSIS_REQUEST_PROFILE, AnalysisRequest, Expr, Package, SnapshotInput, SourceDocument, Truth,
    analyze, digest, parse_analysis_request, parse_snapshot_input, validate,
    validate_analysis_result,
};

const SOURCE_TEXT: &str = r#"kind [kind:concept] "Concept" { meaning "A semantic concept" }
context [context:general] { scopes ("semantic") purposes ("test") perspectives ("kernel") }
term [term:a] "Alpha" { kind [kind:concept] context [context:general] meaning "Alpha meaning" aliases ("A") }
term [term:b] "Beta" { kind [kind:concept] context [context:general] meaning "Beta meaning" }
relation-type [relation:links] "Links" { meaning "Directed semantic link" role from input ([kind:concept]) 1..1 role to output ([kind:concept]) 1..1 }
relation [relation:alpha-beta] { type [relation:links] context [context:general] participant from [term:a] participant to [term:b] guard all(fact([term:a]),not(fact([term:b]))) }
rule [rule:derive-beta] "Derive beta" { context [context:general] when any(fact([term:a]),fact([term:b])) then [term:b] }
view [view:main] "Main" { context [context:general] units ([term:a],[term:b]) relations ([relation:alpha-beta]) }
"#;

fn source_document(text: &str) -> SourceDocument {
    SourceDocument {
        id: "source:main".to_owned(),
        package: "package:core".to_owned(),
        path: "semantic.sop".to_owned(),
        text: text.to_owned(),
    }
}

fn full_input() -> SnapshotInput {
    let source = source_document(SOURCE_TEXT);
    let analysis = source::analyze(&source, "term");
    assert!(analysis.complete, "{:?}", analysis.diagnostics);
    let mut input = SnapshotInput {
        profile: cantor_sop_semantics::INPUT_PROFILE.to_owned(),
        packages: vec![Package {
            id: "package:core".to_owned(),
            version: "1.0.0".to_owned(),
            namespaces: BTreeSet::from(["term".to_owned()]),
            dependencies: BTreeSet::new(),
        }],
        sources: vec![source],
        kinds: Vec::new(),
        contexts: Vec::new(),
        units: Vec::new(),
        relation_types: Vec::new(),
        relations: Vec::new(),
        rules: Vec::new(),
        views: Vec::new(),
    };
    analysis.declarations.append_to(&mut input);
    input
}

#[test]
fn complete_source_analysis_preserves_exact_spans_and_validates() {
    let input = full_input();
    validate::validate(&input).unwrap();
    assert_eq!(input.kinds.len(), 1);
    assert_eq!(input.contexts.len(), 1);
    assert_eq!(input.units.len(), 2);
    assert_eq!(input.relation_types.len(), 1);
    assert_eq!(input.relations.len(), 1);
    assert_eq!(input.rules.len(), 1);
    assert_eq!(input.views.len(), 1);
    assert_eq!(input.kinds[0].source.start, 0);
    let span_end = usize::try_from(input.kinds[0].source.end).unwrap();
    assert_eq!(
        &SOURCE_TEXT[..span_end],
        &SOURCE_TEXT[..SOURCE_TEXT.find('\n').unwrap()]
    );

    let manifest = validate::manifest(&input).unwrap();
    assert_eq!(manifest.counts["units"], 2);
    assert_eq!(manifest.recognition, "unrecognized_preview");
}

#[test]
fn normalization_and_generation_are_order_independent_for_records() {
    let input = full_input();
    let expected = digest::generation(&input).unwrap();
    let mut reordered = input.clone();
    reordered.units.reverse();
    reordered.relation_types[0].roles.reverse();
    reordered.relations[0].participants.reverse();
    assert_eq!(digest::generation(&reordered).unwrap(), expected);
    assert_eq!(
        validate::manifest(&reordered).unwrap().generation,
        validate::manifest(&input).unwrap().generation
    );
}

#[test]
fn three_valued_expression_evaluation_propagates_unknown() {
    let expr = Expr::All {
        args: vec![
            Expr::Fact {
                unit: "term:a".to_owned(),
            },
            Expr::Not {
                arg: Box::new(Expr::Fact {
                    unit: "term:b".to_owned(),
                }),
            },
        ],
    };
    let evaluation =
        expression::evaluate(&expr, &BTreeMap::from([("term:a".to_owned(), Truth::True)]));
    assert_eq!(evaluation.truth, Truth::Unknown);
    assert_eq!(evaluation.observed["term:a"], Truth::True);
    assert_eq!(evaluation.observed["term:b"], Truth::Unknown);

    let false_evaluation = expression::evaluate(
        &expr,
        &BTreeMap::from([
            ("term:a".to_owned(), Truth::True),
            ("term:b".to_owned(), Truth::True),
        ]),
    );
    assert_eq!(false_evaluation.truth, Truth::False);
}

#[test]
fn analysis_result_is_deterministic_and_tamper_evident() {
    let request = AnalysisRequest {
        profile: ANALYSIS_REQUEST_PROFILE.to_owned(),
        source: source_document(SOURCE_TEXT),
        namespace: "term".to_owned(),
    };
    let first = analyze(&request).unwrap();
    let second = analyze(&request).unwrap();
    assert_eq!(first, second);
    validate_analysis_result(&request, &first).unwrap();

    let mut tampered = first;
    tampered.analysis.complete = false;
    assert_eq!(
        validate_analysis_result(&request, &tampered)
            .unwrap_err()
            .code,
        "analysis_digest_mismatch"
    );
}

#[test]
fn parser_recovers_a_later_declaration_after_a_fault() {
    let text = r#"kind [kind:bad] "Bad" { unsupported "field" }
kind [kind:good] "Good" { meaning "Retained after recovery" }
"#;
    let analysis = source::analyze(&source_document(text), "term");
    assert!(!analysis.complete);
    assert_eq!(analysis.diagnostics.len(), 1);
    assert_eq!(analysis.diagnostics[0].code, "unknown_field");
    assert_eq!(analysis.declarations.kinds.len(), 1);
    assert_eq!(analysis.declarations.kinds[0].id, "kind:good");
}

#[test]
fn parser_refuses_duplicate_sets_fields_and_unsupported_operators() {
    let duplicate_set = source::analyze(
        &source_document(
            r#"context [context:x] { scopes ("same","same") purposes ("p") perspectives ("v") }"#,
        ),
        "term",
    );
    assert_eq!(duplicate_set.diagnostics[0].code, "duplicate_list_item");

    let duplicate_field = source::analyze(
        &source_document(r#"kind [kind:x] "X" { meaning "one" meaning "two" }"#),
        "term",
    );
    assert_eq!(duplicate_field.diagnostics[0].code, "duplicate_field");

    let unsupported = source::analyze(
        &source_document(
            r#"rule [rule:x] "X" { context [context:x] when maybe(fact([term:x])) then [term:x] }"#,
        ),
        "term",
    );
    assert_eq!(unsupported.diagnostics[0].code, "unsupported_operator");
}

#[test]
fn strict_machine_forms_refuse_unknown_fields_and_duplicate_set_members() {
    let request = AnalysisRequest {
        profile: ANALYSIS_REQUEST_PROFILE.to_owned(),
        source: source_document(SOURCE_TEXT),
        namespace: "term".to_owned(),
    };
    let mut request_value = serde_json::to_value(&request).unwrap();
    request_value
        .as_object_mut()
        .unwrap()
        .insert("execute".to_owned(), serde_json::Value::Bool(true));
    assert_eq!(
        parse_analysis_request(&serde_json::to_vec(&request_value).unwrap())
            .unwrap_err()
            .code,
        "invalid_json"
    );

    let encoded = serde_json::to_string(&full_input()).unwrap();
    let duplicate = encoded.replacen(
        "\"namespaces\":[\"term\"]",
        "\"namespaces\":[\"term\",\"term\"]",
        1,
    );
    assert_ne!(duplicate, encoded);
    let error = parse_snapshot_input(duplicate.as_bytes()).unwrap_err();
    assert_eq!(error.code, "invalid_json");
    assert!(
        error
            .message
            .contains("duplicate semantic set member refused")
    );
}

#[test]
fn validation_refuses_duplicate_identity_invalid_utf8_span_and_expression_depth() {
    let mut duplicate = full_input();
    duplicate.units[1].id = duplicate.units[0].id.clone();
    assert_eq!(
        validate::validate(&duplicate).unwrap_err().code,
        "duplicate_identity"
    );

    let mut invalid_span = full_input();
    invalid_span.sources[0].text.push('é');
    invalid_span.kinds[0].source.start = (invalid_span.sources[0].text.len() - 1) as u64;
    invalid_span.kinds[0].source.end = invalid_span.sources[0].text.len() as u64;
    assert_eq!(
        validate::validate(&invalid_span).unwrap_err().code,
        "invalid_span"
    );

    let mut deep = full_input();
    let mut expr = Expr::Fact {
        unit: "term:a".to_owned(),
    };
    for _ in 0..18 {
        expr = Expr::Not {
            arg: Box::new(expr),
        };
    }
    deep.rules[0].condition = expr;
    assert_eq!(
        validate::validate(&deep).unwrap_err().code,
        "expression_limit"
    );
}
