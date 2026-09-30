use std::collections::BTreeSet;

use cantor_sop_project::{
    PROJECT_PROFILE, ProjectAssemblyResult, SuppliedFile, SuppliedPackage, SuppliedProject,
    assemble,
};
use cantor_sop_query::{
    CAPABILITY, FIND_REQUEST_PROFILE, FindRequest, MAX_QUERY_MACHINE_BYTES, MatchMode, find,
    parse_find_request, validate_find_result,
};

const FOUNDATION: &str = r#"kind [kind:fact] "Fact" { meaning "An observation" }
kind [kind:action] "Action" { meaning "An action" }
context [context:review] { scopes ("workspace") purposes ("review") perspectives ("auditor") not-before 100 not-after 200 }
context [context:any] { scopes () purposes () perspectives () }
term [common:ready] "Ready" { kind [kind:fact] context [context:review] meaning "Foundation is ready" aliases ("Prepared","Café") }
term [common:retired] "Ready retired" { kind [kind:fact] context [context:any] meaning "Old readiness" status superseded }
term [common:publish] "Publish" { kind [kind:action] context [context:any] meaning "Publish an artifact" }
"#;

const SITE: &str = r#"term [site:ready] "Ready" { kind [kind:fact] context [context:review] meaning "Site is ready" }
term [site:reviewed] "Reviewed" { kind [kind:fact] context [context:review] meaning "Site was reviewed" aliases ("Human reviewed","Café preview") }
"#;

fn package(
    id: &str,
    namespaces: &[&str],
    dependencies: &[&str],
    files: Vec<SuppliedFile>,
) -> SuppliedPackage {
    SuppliedPackage {
        id: id.to_owned(),
        version: "1.0.0".to_owned(),
        namespaces: namespaces.iter().map(|value| (*value).to_owned()).collect(),
        dependencies: dependencies
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        files,
    }
}

fn file(id: &str, path: &str, namespace: &str, text: &str) -> SuppliedFile {
    SuppliedFile {
        id: id.to_owned(),
        path: path.to_owned(),
        namespace: namespace.to_owned(),
        text: text.to_owned(),
    }
}

fn project() -> SuppliedProject {
    SuppliedProject {
        profile: PROJECT_PROFILE.to_owned(),
        packages: vec![
            package(
                "pkg:foundation",
                &["common"],
                &[],
                vec![file(
                    "source:foundation",
                    "foundation.sop",
                    "common",
                    FOUNDATION,
                )],
            ),
            package(
                "pkg:site",
                &["site"],
                &["pkg:foundation"],
                vec![file("source:site", "site.sop", "site", SITE)],
            ),
        ],
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
fn exact_lookup_preserves_ambiguity_namespace_visibility_and_context() {
    let assembly = assembly();
    let mut request = FindRequest::prefix("READY");
    request.mode = MatchMode::Exact;
    let result = find(&assembly, &request).unwrap();
    assert_eq!(result.capability, CAPABILITY);
    assert_eq!(
        result
            .items
            .iter()
            .map(|hit| hit.unit.id.as_str())
            .collect::<Vec<_>>(),
        ["common:ready", "site:ready"]
    );

    request.namespace = Some("site".to_owned());
    assert_eq!(
        find(&assembly, &request).unwrap().items[0].unit.id,
        "site:ready"
    );
    request.namespace = None;
    request.visible_from = Some("pkg:foundation".to_owned());
    assert_eq!(
        find(&assembly, &request).unwrap().items[0].unit.id,
        "common:ready"
    );
    request.visible_from = None;
    request.context.purpose = Some("unrelated".to_owned());
    assert!(find(&assembly, &request).unwrap().items.is_empty());
    request.context.purpose = Some("review".to_owned());
    request.context.scope = Some("workspace".to_owned());
    request.context.perspective = Some("auditor".to_owned());
    request.context.at_epoch_seconds = Some(150);
    assert_eq!(find(&assembly, &request).unwrap().items.len(), 2);
    request.context.at_epoch_seconds = Some(99);
    assert!(find(&assembly, &request).unwrap().items.is_empty());
}

#[test]
fn aliases_prefixes_literal_metacharacters_kinds_and_superseded_filter() {
    let assembly = assembly();
    let result = find(&assembly, &FindRequest::prefix("CAFÉ")).unwrap();
    assert_eq!(
        result
            .items
            .iter()
            .map(|hit| hit.unit.id.as_str())
            .collect::<Vec<_>>(),
        ["common:ready", "site:reviewed"]
    );
    assert!(
        find(&assembly, &FindRequest::prefix("%' OR 1=1 --"))
            .unwrap()
            .items
            .is_empty()
    );

    let mut kind = FindRequest::prefix("");
    kind.kinds.insert("kind:action".to_owned());
    assert_eq!(
        find(&assembly, &kind).unwrap().items[0].unit.id,
        "common:publish"
    );

    let mut status = FindRequest::prefix("Ready");
    assert_eq!(find(&assembly, &status).unwrap().items.len(), 2);
    status.include_superseded = true;
    assert_eq!(find(&assembly, &status).unwrap().items.len(), 3);
}

#[test]
fn pagination_is_deterministic_duplicate_free_and_cursor_bound() {
    let assembly = assembly();
    let mut request = FindRequest::prefix("");
    request.limit = 1;
    let first = find(&assembly, &request).unwrap();
    assert!(!first.complete);
    let mut ids = BTreeSet::from([first.items[0].unit.id.clone()]);
    request.cursor = first.next.clone();

    let mut changed = request.clone();
    changed.text = "Ready".to_owned();
    assert_eq!(
        find(&assembly, &changed).unwrap_err().code,
        "cursor_mismatch"
    );

    let mut stale = request.clone();
    stale.cursor.as_mut().unwrap().generation = "0".repeat(64);
    assert_eq!(find(&assembly, &stale).unwrap_err().code, "stale_cursor");

    let mut tampered = request.clone();
    tampered.cursor.as_mut().unwrap().after_unit = "site:ready".to_owned();
    assert_eq!(
        find(&assembly, &tampered).unwrap_err().code,
        "cursor_mismatch"
    );

    loop {
        let page = find(&assembly, &request).unwrap();
        for hit in page.items {
            assert!(ids.insert(hit.unit.id));
        }
        if page.complete {
            break;
        }
        request.cursor = page.next;
    }
    assert_eq!(ids.len(), 4);
}

#[test]
fn sealed_result_replays_and_refuses_assembly_or_page_tampering() {
    let assembly = assembly();
    let request = FindRequest::prefix("Ready");
    let result = find(&assembly, &request).unwrap();
    validate_find_result(&assembly, &request, &result).unwrap();

    let mut tampered_result = result.clone();
    tampered_result.items[0].matched_key.push('x');
    assert_eq!(
        validate_find_result(&assembly, &request, &tampered_result)
            .unwrap_err()
            .code,
        "query_result_mismatch"
    );

    let mut incomplete = assembly.clone();
    incomplete.analysis.complete = false;
    assert_eq!(
        find(&incomplete, &request).unwrap_err().code,
        "incomplete_project"
    );

    let mut tampered_assembly = assembly;
    tampered_assembly.project_digest = "0".repeat(64);
    assert_eq!(
        find(&tampered_assembly, &request).unwrap_err().code,
        "project_result_mismatch"
    );
}

#[test]
fn strict_machine_forms_and_budgets_refuse() {
    let request = FindRequest::prefix("Ready");
    let mut value = serde_json::to_value(&request).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("open_database".to_owned(), serde_json::Value::Bool(true));
    assert_eq!(
        parse_find_request(&serde_json::to_vec(&value).unwrap())
            .unwrap_err()
            .code,
        "invalid_json"
    );

    let mut with_kind = request.clone();
    with_kind.kinds.insert("kind:fact".to_owned());
    let encoded = serde_json::to_string(&with_kind).unwrap();
    let duplicate = encoded.replacen(
        "\"kinds\":[\"kind:fact\"]",
        "\"kinds\":[\"kind:fact\",\"kind:fact\"]",
        1,
    );
    assert_ne!(duplicate, encoded);
    assert!(
        parse_find_request(duplicate.as_bytes())
            .unwrap_err()
            .message
            .contains("duplicate semantic set member refused")
    );
    assert_eq!(
        parse_find_request(&vec![b' '; MAX_QUERY_MACHINE_BYTES + 1])
            .unwrap_err()
            .code,
        "query_machine_limit"
    );

    let assembly = assembly();
    for limit in [0, 1_001] {
        let mut invalid = request.clone();
        invalid.limit = limit;
        assert_eq!(
            find(&assembly, &invalid).unwrap_err().code,
            "invalid_budget"
        );
    }
    let mut bad_profile = request.clone();
    bad_profile.profile = "other".to_owned();
    assert_eq!(
        find(&assembly, &bad_profile).unwrap_err().code,
        "unsupported_query"
    );
}

#[test]
fn unknown_filters_and_excessive_context_refuse() {
    let assembly = assembly();
    let mut request = FindRequest::prefix("");
    request.visible_from = Some("pkg:unknown".to_owned());
    assert_eq!(
        find(&assembly, &request).unwrap_err().code,
        "unknown_package"
    );
    request.visible_from = None;
    request.kinds.insert("kind:unknown".to_owned());
    assert_eq!(find(&assembly, &request).unwrap_err().code, "unknown_kind");
    request.kinds.clear();
    request.context.scope = Some("x".repeat(4_097));
    assert_eq!(
        find(&assembly, &request).unwrap_err().code,
        "invalid_context"
    );
}

#[test]
fn supplied_order_does_not_change_query_result() {
    let first = project();
    let mut second = first.clone();
    second.packages.reverse();
    for package in &mut second.packages {
        package.files.reverse();
    }
    let request = FindRequest {
        profile: FIND_REQUEST_PROFILE.to_owned(),
        ..FindRequest::prefix("")
    };
    assert_eq!(
        find(&assemble(&first).unwrap(), &request).unwrap(),
        find(&assemble(&second).unwrap(), &request).unwrap()
    );
}
