#[test]
fn supplied_root_topology_projection_surface_is_pure_and_lineage_closed() {
    let source = include_str!("../src/windows_supplied_root_topology_projection.rs");
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
    ] {
        assert!(
            !production.contains(forbidden),
            "forbidden token: {forbidden}"
        );
    }
    for required in [
        "WINDOWS_SUPPLIED_ROOT_TOPOLOGY_PROJECTION_PROFILE",
        "WINDOWS_SUPPLIED_ROOT_TOPOLOGY_PROJECTION_PLAN_MAX_BYTES",
        "preflight_record: WindowsPlatformPreflightRecord",
        "stability_input: WindowsSuppliedEntryStabilityInput",
        ".validate()",
        "reconcile_windows_supplied_entry_stability(stability_input)",
        "PlatformPreflightDisposition::EligibleLocalNtfs",
        "seed.identity != root_identity",
        "TopologyEntryKind::RootDirectory",
        "TopologyModeClass::Directory",
        "relative_path: None",
        "observation_ordinal: 1",
        "does not prove runtime",
    ] {
        assert!(production.contains(required), "missing token: {required}");
    }

    for name in [
        "project_windows_supplied_root_topology(",
        "decode_and_project_windows_supplied_root_topology(",
    ] {
        let signature = production
            .split_once(name)
            .expect("function")
            .1
            .split_once(") -> Result<")
            .expect("signature")
            .0;
        assert!(signature.contains("WindowsPlatformPreflightRecord"));
        assert!(signature.contains("WindowsSuppliedEntryStabilityInput"));
        assert!(!signature.contains("WindowsSuppliedEntryStablePair"));
    }

    let output = "pub struct WindowsSuppliedRootTopologyProjection {";
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
        "preflight_record:",
        "stable_pair:",
        "topology_observation:",
    ] {
        assert!(body.contains(field));
    }
}
