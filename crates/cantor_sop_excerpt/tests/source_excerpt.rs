use cantor_sop_excerpt::{
    CAPABILITY, MAX_REQUEST_MACHINE_BYTES, extract, parse_request, parse_result, request,
    validate_result,
};
use cantor_sop_project::{
    PROJECT_PROFILE, ProjectAssemblyResult, SuppliedFile, SuppliedPackage, SuppliedProject,
    assemble,
};

const SOURCE: &str = r#"kind [kind:fact] "Fact" { meaning "An observation" }
context [context:any] { scopes () purposes () perspectives () }
term [site:cafe] "Café reviewed" { kind [kind:fact] context [context:any] meaning "The café was reviewed" aliases ("Reviewed") }
"#;

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

fn assembly() -> ProjectAssemblyResult {
    let result = assemble(&project()).unwrap();
    assert!(
        result.analysis.complete,
        "{:?}",
        result.analysis.diagnostics
    );
    result
}

#[test]
fn exact_unicode_declaration_and_full_document_recover() {
    let assembly = assembly();
    let unit = request("site:cafe").unwrap();
    let excerpt = extract(&assembly, &unit).unwrap();
    assert_eq!(excerpt.capability, CAPABILITY);
    assert_eq!(excerpt.path, "site/main.sop");
    assert_eq!(
        excerpt.text,
        "term [site:cafe] \"Café reviewed\" { kind [kind:fact] context [context:any] meaning \"The café was reviewed\" aliases (\"Reviewed\") }"
    );
    validate_result(&assembly, &unit, &excerpt).unwrap();

    let source = extract(&assembly, &request("source:site").unwrap()).unwrap();
    assert_eq!(source.text, SOURCE);
    assert_eq!(source.span.start, 0);
    assert_eq!(source.span.end, SOURCE.len() as u64);
    assert_ne!(source.source_digest, excerpt.span_digest);
}

#[test]
fn kind_context_and_unit_spans_are_exact_and_repeatable() {
    let assembly = assembly();
    for (id, prefix) in [
        ("kind:fact", "kind [kind:fact]"),
        ("context:any", "context [context:any]"),
        ("site:cafe", "term [site:cafe]"),
    ] {
        let request = request(id).unwrap();
        let first = extract(&assembly, &request).unwrap();
        let second = extract(&assembly, &request).unwrap();
        assert_eq!(first, second);
        assert!(first.text.starts_with(prefix));
    }
}

#[test]
fn unknown_source_less_and_invalid_request_states_refuse() {
    let assembly = assembly();
    assert_eq!(
        extract(&assembly, &request("pkg:site").unwrap())
            .unwrap_err()
            .code,
        "source_unavailable"
    );
    assert_eq!(
        extract(&assembly, &request("site:absent").unwrap())
            .unwrap_err()
            .code,
        "unknown_record"
    );
    assert!(request("bad\0identity").is_err());
}

#[test]
fn assembly_request_and_result_tampering_refuse() {
    let assembly = assembly();
    let request = request("site:cafe").unwrap();
    let result = extract(&assembly, &request).unwrap();

    let mut bad_assembly = assembly.clone();
    bad_assembly.analysis.input.sources[0].text.push('!');
    assert_eq!(
        extract(&bad_assembly, &request).unwrap_err().code,
        "project_result_mismatch"
    );

    let mut bad_request = request.clone();
    bad_request.record_id = "kind:fact".to_owned();
    assert_eq!(
        extract(&assembly, &bad_request).unwrap_err().code,
        "excerpt_request_mismatch"
    );

    for mutate in [
        |value: &mut cantor_sop_excerpt::SourceExcerptResult| value.text.push('!'),
        |value: &mut cantor_sop_excerpt::SourceExcerptResult| value.path.push('!'),
        |value: &mut cantor_sop_excerpt::SourceExcerptResult| value.span.start += 1,
        |value: &mut cantor_sop_excerpt::SourceExcerptResult| value.span_digest = "0".repeat(64),
        |value: &mut cantor_sop_excerpt::SourceExcerptResult| value.source_digest = "0".repeat(64),
        |value: &mut cantor_sop_excerpt::SourceExcerptResult| value.result_digest = "0".repeat(64),
    ] {
        let mut changed = result.clone();
        mutate(&mut changed);
        assert_eq!(
            validate_result(&assembly, &request, &changed)
                .unwrap_err()
                .code,
            "excerpt_result_mismatch"
        );
    }
}

#[test]
fn strict_machine_forms_and_raw_bounds_refuse() {
    let request = request("site:cafe").unwrap();
    let bytes = serde_json::to_vec(&request).unwrap();
    assert_eq!(parse_request(&bytes).unwrap(), request);
    for raw in [
        br#"{"profile":"cantor-sop-source-excerpt-request/0.1","record_id":"site:cafe","request_digest":"0","extra":false}"#.as_slice(),
        br#"{"profile":"cantor-sop-source-excerpt-request/0.1","profile":"cantor-sop-source-excerpt-request/0.1","record_id":"site:cafe","request_digest":"0"}"#.as_slice(),
        br#"{}{}"#.as_slice(),
    ] {
        assert!(parse_request(raw).is_err());
    }
    assert_eq!(
        parse_request(&vec![b' '; MAX_REQUEST_MACHINE_BYTES + 1])
            .unwrap_err()
            .code,
        "excerpt_machine_limit"
    );

    let assembly = assembly();
    let result = extract(&assembly, &request).unwrap();
    let result_bytes = serde_json::to_vec(&result).unwrap();
    assert_eq!(parse_result(&result_bytes).unwrap(), result);
    let mut trailing = result_bytes.clone();
    trailing.extend_from_slice(b"{}");
    assert!(parse_result(&trailing).is_err());
}
