use std::collections::BTreeSet;

use cantor_sop_project::{
    CAPABILITY, MAX_PROJECT_MACHINE_BYTES, PROJECT_PROFILE, SuppliedFile, SuppliedPackage,
    SuppliedProject, assemble, parse_project, validate_result,
};

const FOUNDATION: &str = r#"kind [kind:fact] "Fact" { meaning "An observation" }
context [context:study] { scopes ("workspace") purposes ("review") perspectives () }
term [common:ready] "Ready" { kind [kind:fact] context [context:study] meaning "Foundation is ready" }
"#;

const SITE: &str = r#"term [site:reviewed] "Reviewed" { kind [kind:fact] context [context:study] meaning "The site was reviewed" }
view [view:site] "Site" { context [context:study] units ([site:reviewed]) relations () }
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
                vec![file("source:site", "nested/site.sop", "site", SITE)],
            ),
        ],
    }
}

#[test]
fn supplied_multi_package_project_assembles_and_replays() {
    let project = project();
    let result = assemble(&project).unwrap();
    assert_eq!(result.capability, CAPABILITY);
    assert!(
        result.analysis.complete,
        "{:?}",
        result.analysis.diagnostics
    );
    assert_eq!(result.analysis.input.packages.len(), 2);
    assert_eq!(result.analysis.input.sources.len(), 2);
    assert_eq!(result.analysis.input.units.len(), 2);
    assert_eq!(result.analysis.input.views.len(), 1);
    assert!(result.analysis.semantic_manifest.is_some());
    let start = usize::try_from(result.analysis.input.units[1].source.start).unwrap();
    let end = usize::try_from(result.analysis.input.units[1].source.end).unwrap();
    assert_eq!(&SITE[start..end], SITE.lines().next().unwrap());
    validate_result(&project, &result).unwrap();
}

#[test]
fn package_and_file_order_do_not_change_the_sealed_result() {
    let first = project();
    let mut second = first.clone();
    second.packages.reverse();
    assert_eq!(assemble(&first).unwrap(), assemble(&second).unwrap());
}

#[test]
fn source_and_semantic_faults_remain_noncomplete_diagnostics() {
    let mut syntax = project();
    syntax.packages[1].files[0].text = "term [unfinished".to_owned();
    let result = assemble(&syntax).unwrap();
    assert!(!result.analysis.complete);
    assert!(result.analysis.semantic_manifest.is_none());
    assert_eq!(
        result.analysis.diagnostics[0].source.as_deref(),
        Some("source:site")
    );
    assert_eq!(
        result.analysis.diagnostics[0].path.as_deref(),
        Some("nested/site.sop")
    );

    let mut semantic = project();
    semantic.packages[1].dependencies.clear();
    let result = assemble(&semantic).unwrap();
    assert!(!result.analysis.complete);
    assert!(
        result.analysis.diagnostics[0]
            .diagnostic
            .message
            .contains("dependency closure")
    );
}

#[test]
fn strict_machine_form_refuses_unknown_fields_duplicate_sets_and_oversize() {
    let mut value = serde_json::to_value(project()).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("read_files".to_owned(), serde_json::Value::Bool(true));
    assert_eq!(
        parse_project(&serde_json::to_vec(&value).unwrap())
            .unwrap_err()
            .code,
        "invalid_json"
    );

    let encoded = serde_json::to_string(&project()).unwrap();
    let duplicate = encoded.replacen(
        "\"namespaces\":[\"common\"]",
        "\"namespaces\":[\"common\",\"common\"]",
        1,
    );
    assert_ne!(duplicate, encoded);
    assert!(
        parse_project(duplicate.as_bytes())
            .unwrap_err()
            .message
            .contains("duplicate semantic set member refused")
    );

    let oversized = vec![b' '; MAX_PROJECT_MACHINE_BYTES + 1];
    assert_eq!(
        parse_project(&oversized).unwrap_err().code,
        "project_machine_limit"
    );
}

#[test]
fn structural_bounds_refuse_paths_namespaces_duplicates_and_source_limits() {
    for path in [
        "",
        "/absolute.sop",
        "C:/drive.sop",
        "a\\b.sop",
        "a/../b.sop",
        "a//b.sop",
    ] {
        let mut candidate = project();
        candidate.packages[0].files[0].path = path.to_owned();
        assert_eq!(
            assemble(&candidate).unwrap_err().code,
            "invalid_source_path"
        );
    }

    let mut namespace = project();
    namespace.packages[0].files[0].namespace = "not-declared".to_owned();
    assert_eq!(
        assemble(&namespace).unwrap_err().code,
        "undeclared_namespace"
    );

    let mut duplicate = project();
    duplicate.packages[1].files[0].id = "source:foundation".to_owned();
    assert_eq!(assemble(&duplicate).unwrap_err().code, "duplicate_source");

    let mut too_large = project();
    too_large.packages[0].files[0].text =
        "x".repeat(cantor_sop_semantics::source::MAX_DOCUMENT_BYTES + 1);
    assert_eq!(assemble(&too_large).unwrap_err().code, "source_limit");
}

#[test]
fn dependency_cycles_diagnostic_budget_and_result_tampering_refuse() {
    let mut cycle = project();
    cycle.packages[0].dependencies.insert("pkg:site".to_owned());
    let result = assemble(&cycle).unwrap();
    assert_eq!(
        result.analysis.diagnostics[0].diagnostic.code,
        "dependency_cycle"
    );

    let mut diagnostic_flood = SuppliedProject {
        profile: PROJECT_PROFILE.to_owned(),
        packages: vec![package("pkg:flood", &["flood"], &[], Vec::new())],
    };
    diagnostic_flood.packages[0].files = (0..=1_000)
        .map(|index| {
            file(
                &format!("source:{index}"),
                &format!("{index}.sop"),
                "flood",
                "[",
            )
        })
        .collect();
    assert_eq!(
        assemble(&diagnostic_flood).unwrap_err().code,
        "diagnostic_limit"
    );

    let project = project();
    let mut tampered = assemble(&project).unwrap();
    tampered.analysis.complete = false;
    assert_eq!(
        validate_result(&project, &tampered).unwrap_err().code,
        "project_result_mismatch"
    );
}

#[test]
fn supplied_sets_are_real_sets_in_constructive_forms() {
    let result = assemble(&project()).unwrap();
    assert_eq!(
        result.analysis.input.packages[1].dependencies,
        BTreeSet::from(["pkg:foundation".to_owned()])
    );
}
