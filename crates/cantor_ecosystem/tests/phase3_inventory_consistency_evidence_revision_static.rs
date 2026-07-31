#[test]
fn inventory_consistency_evidence_revision_is_closed_pure_and_strict() {
    let phase3_source = include_str!("../src/phase3_evidence.rs");
    let topology_source = include_str!("../src/topology_forms.rs");
    let phase3_production = phase3_source
        .split_once("#[cfg(test)]")
        .expect("phase3 test boundary")
        .0;
    let topology_production = topology_source
        .split_once("#[cfg(test)]")
        .expect("topology test boundary")
        .0;

    for required in [
        "cantor-phase3-machine-forms/0.2",
        "pub enum InventoryConsistencyEvidence {",
        "NonAtomicRepeatedInventoryEqual,",
        "OsSnapshotProven,",
        "impl ValidatePhase3 for InventoryConsistencyEvidence",
        "does not prove that",
    ] {
        assert!(
            phase3_production.contains(required),
            "missing machine-forms token: {required}"
        );
    }

    let evidence_body = phase3_production
        .split_once("pub enum InventoryConsistencyEvidence {")
        .expect("evidence enum")
        .1
        .split_once('}')
        .expect("evidence enum body")
        .0;
    let variants = evidence_body
        .lines()
        .map(str::trim)
        .filter(|line| line.ends_with(','))
        .collect::<Vec<_>>();
    assert_eq!(
        variants,
        ["NonAtomicRepeatedInventoryEqual,", "OsSnapshotProven,"]
    );

    for required in [
        "cantor-phase3-topology-forms/0.3",
        "cantor-phase3-topology-receipt/0.3",
        "cantor-windows-candidate-topology/0.1",
        "use crate::InventoryConsistencyEvidence;",
        "pub consistency_evidence: InventoryConsistencyEvidence,",
        "InventoryConsistencyEvidence::NonAtomicRepeatedInventoryEqual",
        "\"consistency_evidence\"",
        "\"receipt 0.3 permits only non_atomic_repeated_inventory_equal\"",
        "not self-authenticating support or proof",
    ] {
        assert!(
            topology_production.contains(required),
            "missing topology-forms token: {required}"
        );
    }

    for forbidden in [
        "ConsistencyClass",
        "QuiescentDoubleInventory",
        "quiescent_double_inventory",
        "pub consistency:",
        "serde(alias",
        "serde(default",
        "impl From<InventoryConsistencyEvidence",
        "impl Into<InventoryConsistencyEvidence",
        "WindowsSuppliedOrderedTopologyInventoryDigestReconciliation",
        "windows_sys",
        "unsafe {",
        "std::fs",
        "std::process",
        "SystemTime",
        "Instant",
    ] {
        assert!(
            !phase3_production.contains(forbidden) && !topology_production.contains(forbidden),
            "forbidden production token: {forbidden}"
        );
    }

    assert!(!evidence_body.contains("Default"));
    assert!(!evidence_body.contains("Unknown"));
    assert!(!evidence_body.contains("Other"));
}
