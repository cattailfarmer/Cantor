use std::{fs, path::PathBuf};

use cantor_ecosystem::sjs_repository_graph::{
    GraphFaultCode, compile_sjs_repository_graph_verification, element_history_event_digest,
    from_change_set_machine_form, from_diff_inventory_machine_form, validate_change_set_manifest,
};

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("workspace root")
        .to_path_buf()
}

#[test]
fn production_library_is_pure_and_surface_is_closed() {
    let root = repository_root();
    let source =
        fs::read_to_string(root.join("crates/cantor_ecosystem/src/sjs_repository_graph.rs"))
            .unwrap();
    let production = source.split("#[cfg(test)]").next().unwrap();
    for denied in [
        "std::fs",
        "std::process",
        "Command::new",
        "std::env",
        "unsafe {",
        "TcpStream",
        "reqwest",
        "tokio",
        "git diff",
        "git add",
        "git commit",
        "git push",
    ] {
        assert!(!production.contains(denied), "denied token: {denied}");
    }
    assert_eq!(source.matches("pub enum GraphNodeKind").count(), 1);
    assert_eq!(source.matches("pub enum GraphEdgeKind").count(), 1);
    assert_eq!(source.matches("pub enum ElementOperation").count(), 1);
    assert!(source.contains("VerificationOnly"));
    assert!(source.contains("physical_contact"));
}

#[test]
fn verifier_binary_reads_supplied_forms_without_invoking_git() {
    let root = repository_root();
    let source =
        fs::read_to_string(root.join("crates/cantor_ecosystem/src/bin/cantor-sjs-graph-verify.rs"))
            .unwrap();
    assert!(source.contains("--change-set"));
    assert!(source.contains("--diff-inventory"));
    assert!(source.contains(".filter(|parent| !parent.as_os_str().is_empty())"));
    for denied in [
        "Command::new",
        "git diff",
        "git add",
        "git commit",
        "git push",
    ] {
        assert!(!source.contains(denied), "denied token: {denied}");
    }
}

#[test]
fn checked_fixture_verifies_and_argument_tamper_refuses() {
    let root = repository_root();
    let inventory_bytes =
        fs::read(root.join("fixtures/sjs_repository_graph_p0/diff_inventory.json")).unwrap();
    let inventory = from_diff_inventory_machine_form(&inventory_bytes).unwrap();
    let change_set_bytes =
        fs::read(root.join("fixtures/sjs_repository_graph_p0/change_set.json")).unwrap();
    let change_set = from_change_set_machine_form(&change_set_bytes, &inventory).unwrap();
    let receipt = compile_sjs_repository_graph_verification(&change_set, &inventory).unwrap();
    assert_eq!(receipt.diff_entry_count, 5);
    assert_eq!(receipt.element_event_count, 5);
    assert_eq!(receipt.covered_change_count, 5);
    assert!(receipt.complete_coverage);
    assert!(!receipt.physical_contact);

    let mut tampered = change_set.clone();
    tampered.events[0].reason_summary.push_str(" tampered");
    tampered.events[0].event_sha256 = element_history_event_digest(&tampered.events[0]).unwrap();
    assert_eq!(
        validate_change_set_manifest(&tampered, &inventory)
            .unwrap_err()
            .code,
        GraphFaultCode::Digest
    );
}
