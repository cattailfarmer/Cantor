#[test]
fn supplied_topology_inventory_assembly_surface_is_pure_and_lineage_closed() {
    let source = include_str!("../src/windows_supplied_topology_inventory_assembly.rs");
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
        "ordered_inventory_sha256",
        "impl From<",
        "impl Into<",
    ] {
        assert!(
            !production.contains(forbidden),
            "forbidden token: {forbidden}"
        );
    }

    for required in [
        "WINDOWS_SUPPLIED_TOPOLOGY_INVENTORY_ASSEMBLY_PROFILE",
        "WINDOWS_SUPPLIED_TOPOLOGY_INVENTORY_ASSEMBLY_PLAN_MAX_BYTES",
        "root: WindowsSuppliedRootTopologyProjection",
        "Vec<WindowsSuppliedDirectoryTopologyProjection>",
        "Vec<WindowsSuppliedRegularFileTopologyProjection>",
        ".validate()",
        "BTreeSet<StrongFileIdentity>",
        "enforce_parent_closure",
        "compare_structural_paths",
        "checked_add",
        "does not prove runtime origin",
    ] {
        assert!(production.contains(required), "missing token: {required}");
    }

    for raw_input in [
        "Vec<TopologyEntryObservation>",
        "WindowsSuppliedEntryStablePair,",
        "WindowsSuppliedContentStableBinding,",
        "WindowsPlatformPreflightRecord,",
    ] {
        assert!(
            !production.contains(raw_input),
            "raw input surface: {raw_input}"
        );
    }

    let output = "pub struct WindowsSuppliedTopologyInventoryAssembly {";
    let position = production.find(output).expect("output");
    let prefix = &production[..position];
    let derive = &production[prefix.rfind("#[derive(").expect("derive")..position];
    assert!(derive.contains("Serialize"));
    assert!(!derive.contains("Deserialize"));
    let body = production
        .split_once(output)
        .unwrap()
        .1
        .split_once('}')
        .unwrap()
        .0;
    assert!(!body.contains("pub "));
    for field in [
        "plan:",
        "ordered_members:",
        "entry_count:",
        "total_file_bytes:",
    ] {
        assert!(body.contains(field));
    }
}
