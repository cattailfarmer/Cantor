#[test]
fn supplied_regular_file_topology_projection_surface_is_pure_and_lineage_closed() {
    let source = include_str!("../src/windows_supplied_regular_file_topology_projection.rs");
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
        "WINDOWS_SUPPLIED_REGULAR_FILE_TOPOLOGY_PROJECTION_PROFILE",
        "WINDOWS_SUPPLIED_REGULAR_FILE_TOPOLOGY_PROJECTION_PLAN_MAX_BYTES",
        "WindowsSuppliedContentStableBinding",
        "topology_projection_seed()",
        "TopologyEntryObservation {",
        ".validate()",
        ".derived_sha256()",
        ".rsplit('/')",
        "TopologyModeClass::RegularNonExecutable",
        "TopologyModeClass::RegularExecutable",
        "does not prove a",
    ] {
        assert!(
            production.contains(required),
            "missing projection token: {required}"
        );
    }

    let output_type = "pub struct WindowsSuppliedRegularFileTopologyProjection {";
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
        .split_once("pub struct WindowsSuppliedRegularFileTopologyProjection {")
        .expect("output declaration")
        .1
        .split_once('}')
        .expect("output body")
        .0;
    assert!(!output_body.contains("pub "), "output fields are private");
    assert!(output_body.contains("plan:"));
    assert!(output_body.contains("content_binding:"));
    assert!(output_body.contains("topology_observation:"));
}
