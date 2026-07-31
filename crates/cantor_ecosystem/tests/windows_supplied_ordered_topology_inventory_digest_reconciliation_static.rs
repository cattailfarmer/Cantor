#[test]
fn supplied_ordered_inventory_digest_reconciliation_surface_is_pure_closed_and_output_only() {
    let source =
        include_str!("../src/windows_supplied_ordered_topology_inventory_digest_reconciliation.rs");
    let production = source.split_once("#[cfg(test)]").expect("test boundary").0;

    for forbidden in [
        "windows_sys",
        "unsafe {",
        "std::fs",
        "std::path",
        "std::process",
        "std::env",
        "std::net",
        "SystemTime",
        "Instant",
        "File::",
        "Command::",
        "TopologyReceipt",
        "impl From<",
        "impl Into<",
        "pub fn new(",
        "pub fn from_",
    ] {
        assert!(
            !production.contains(forbidden),
            "forbidden production token: {forbidden}"
        );
    }

    for required in [
        "WINDOWS_SUPPLIED_ORDERED_TOPOLOGY_INVENTORY_DIGEST_RECONCILIATION_PROFILE",
        "WINDOWS_SUPPLIED_ORDERED_TOPOLOGY_INVENTORY_DIGEST_RECONCILIATION_PLAN_MAX_BYTES",
        "derive_windows_supplied_ordered_topology_inventory_digest(",
        "if rederived != *supplied",
        "left.ordered_inventory_sha256() == right.ordered_inventory_sha256()",
        "left_limits != right_limits",
        "TopologyEntryKind::RootDirectory",
        "left_root.relative_path.is_some()",
        "left_root.identity.volume_serial != right_root.identity.volume_serial",
        "left_root.identity.file_id_hex != right_root.identity.file_id_hex",
        "root_relative_path: None",
        "current pure rederivation",
        "positional roles, not acquisition time",
        "physical, temporal, stability, double-inventory, quiescence, receipt, or",
    ] {
        assert!(production.contains(required), "missing token: {required}");
    }

    for declaration in [
        "pub struct WindowsSuppliedOrderedTopologyInventoryDigestReconciliationScope {",
        "pub struct WindowsSuppliedOrderedTopologyInventoryDigestReconciliation {",
    ] {
        let position = production.find(declaration).expect("output declaration");
        let prefix = &production[..position];
        let derive = &production[prefix.rfind("#[derive(").expect("output derive")..position];
        assert!(derive.contains("Serialize"));
        assert!(!derive.contains("Deserialize"));
        assert!(!derive.contains("Default"));
        let body = production
            .split_once(declaration)
            .expect("output declaration")
            .1
            .split_once('}')
            .expect("output body")
            .0;
        assert!(!body.contains("pub "), "output fields must remain private");
    }

    let plan = "pub struct WindowsSuppliedOrderedTopologyInventoryDigestReconciliationPlan {";
    let plan_body = production
        .split_once(plan)
        .expect("plan declaration")
        .1
        .split_once('}')
        .expect("plan body")
        .0;
    assert!(
        !plan_body.contains("pub "),
        "plan fields must remain private"
    );
    assert!(production.contains("#[serde(deny_unknown_fields)]\npub struct WindowsSuppliedOrderedTopologyInventoryDigestReconciliationPlan"));

    assert_eq!(
        production.matches("pub fn ").count(),
        17,
        "public callable surface changed; review authority before accepting it"
    );
}
