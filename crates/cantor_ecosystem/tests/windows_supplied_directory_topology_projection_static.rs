#[test]
fn supplied_directory_topology_projection_surface_is_pure_and_lineage_closed() {
    let source = include_str!("../src/windows_supplied_directory_topology_projection.rs");
    let production = source
        .split_once("#[cfg(test)]")
        .expect("unit-test boundary")
        .0;

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
        "workspace_admission",
        "impl From<",
        "impl Into<",
    ] {
        assert!(
            !production.contains(forbidden),
            "forbidden production token: {forbidden}"
        );
    }

    for required in [
        "WINDOWS_SUPPLIED_DIRECTORY_TOPOLOGY_PROJECTION_PROFILE",
        "WINDOWS_SUPPLIED_DIRECTORY_TOPOLOGY_PROJECTION_PLAN_MAX_BYTES",
        "stability_input: WindowsSuppliedEntryStabilityInput",
        "reconcile_windows_supplied_entry_stability(stability_input)",
        "topology_projection_seed()",
        "TopologyEntryObservation {",
        ".validate()",
        "TopologyModeClass::Directory",
        "length: None",
        "content_sha256: None",
        ".rsplit('/')",
        "does not prove",
    ] {
        assert!(
            production.contains(required),
            "missing projection token: {required}"
        );
    }

    let direct_function = production
        .split_once("pub fn project_windows_supplied_directory_topology(")
        .expect("projection function")
        .1
        .split_once(") -> Result<")
        .expect("projection signature")
        .0;
    assert!(direct_function.contains("WindowsSuppliedEntryStabilityInput"));
    assert!(!direct_function.contains("WindowsSuppliedEntryStablePair"));

    let decode_function = production
        .split_once("pub fn decode_and_project_windows_supplied_directory_topology(")
        .expect("decode projection function")
        .1
        .split_once(") -> Result<")
        .expect("decode projection signature")
        .0;
    assert!(decode_function.contains("WindowsSuppliedEntryStabilityInput"));
    assert!(!decode_function.contains("WindowsSuppliedEntryStablePair"));

    let output_type = "pub struct WindowsSuppliedDirectoryTopologyProjection {";
    let position = production.find(output_type).expect("output type");
    let prefix = &production[..position];
    let derive_start = prefix.rfind("#[derive(").expect("derive attribute");
    let derive = &production[derive_start..position];
    assert!(derive.contains("Serialize"), "output must serialize");
    assert!(
        !derive.contains("Deserialize"),
        "successful output must not deserialize"
    );

    let output_body = production
        .split_once(output_type)
        .expect("output declaration")
        .1
        .split_once('}')
        .expect("output body")
        .0;
    assert!(!output_body.contains("pub "), "output fields are private");
    assert!(output_body.contains("plan:"));
    assert!(output_body.contains("stable_pair:"));
    assert!(output_body.contains("topology_observation:"));
}
