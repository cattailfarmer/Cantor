#[test]
fn windows_supplied_entry_observation_surface_is_pure_and_provenance_closed() {
    let source = include_str!("../src/windows_supplied_entry_observation.rs");
    let production = source
        .split_once("#[cfg(test)]")
        .expect("unit-test boundary")
        .0;
    for forbidden in [
        "windows_sys",
        "unsafe {",
        "std::fs",
        "std::process",
        "std::env",
        "std::net",
        "SystemTime",
        "Instant",
        "File::",
        "Command::",
        "GetFileInformationByHandleEx(",
        "from_raw_parts",
        "*const",
        "*mut",
        "same_handle:",
        "query_succeeded:",
        "fully_initialized:",
        "trusted:",
        "complete:",
        "impl From<WindowsSuppliedEntryObservation",
        "impl Into<TopologyEntryObservation",
    ] {
        assert!(
            !production.contains(forbidden),
            "forbidden production token: {forbidden}"
        );
    }
    for required in [
        "WINDOWS_SUPPLIED_ENTRY_OBSERVATION_PROFILE",
        "WindowsSuppliedRecordCorrelation",
        "WindowsSuppliedEntryAssemblyInput",
        "WindowsSuppliedEntryObservation",
        "WindowsTopologyEntryProjectionSeed",
        "assemble_windows_supplied_entry_observation",
        "evaluate_windows_entry_policy",
        "file identity must contain exactly sixteen bytes",
        "source offsets must increase strictly",
        "Correlation identifiers are equality syntax",
    ] {
        assert!(
            production.contains(required),
            "missing pure assembly token: {required}"
        );
    }
    for intentionally_absent in [
        "pub relative_path:",
        "pub mode_class:",
        "pub content_sha256:",
        "pub observation_ordinal:",
    ] {
        assert!(
            !production
                .split("pub struct WindowsTopologyEntryProjectionSeed")
                .nth(1)
                .and_then(|tail| tail.split('}').next())
                .expect("projection seed body")
                .contains(intentionally_absent),
            "projection seed must omit {intentionally_absent}"
        );
    }
}
