#[test]
fn windows_supplied_entry_stability_surface_is_pure_and_provenance_closed() {
    let source = include_str!("../src/windows_supplied_entry_stability.rs");
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
        "TopologyEntryObservation",
        "content_sha256",
        "relative_path",
        "same_handle",
        "physically_observed",
        "query_succeeded",
        "fully_initialized",
        "receipt",
        "seal",
        "promote",
    ] {
        assert!(
            !production.contains(forbidden),
            "forbidden production token: {forbidden}"
        );
    }
    for required in [
        "WINDOWS_SUPPLIED_ENTRY_STABILITY_PROFILE",
        "WINDOWS_SUPPLIED_ENTRY_STABILITY_COMPARED_FIELDS",
        "WindowsSuppliedEntryStabilityInput",
        "WindowsSuppliedEntryStablePair",
        "WindowsSuppliedEntryStabilityFault",
        "assemble_windows_supplied_entry_observation(input.pre_read)",
        "assemble_windows_supplied_entry_observation(input.post_read)",
        "entry_reference_identity",
        "batch_identity",
        "difference_field",
        "pre_read",
        "post_read",
        "does not prove physical time",
    ] {
        assert!(
            production.contains(required),
            "missing pure stability token: {required}"
        );
    }
}
