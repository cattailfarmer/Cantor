#[test]
fn windows_supplied_content_digest_surface_is_pure_unforgeable_and_provenance_closed() {
    let source = include_str!("../src/windows_supplied_content_digest.rs");
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
        "relative_path",
        "GitMode",
        "TopologyReceipt",
        "admission",
        "promotion",
    ] {
        assert!(
            !production.contains(forbidden),
            "forbidden production token: {forbidden}"
        );
    }

    for required in [
        "WINDOWS_SUPPLIED_CONTENT_DIGEST_PROFILE",
        "WINDOWS_SUPPLIED_CONTENT_DIGEST_PLAN_MAX_BYTES",
        "WindowsSuppliedContentDigestAccumulator",
        "WindowsSuppliedContentDigestObservation",
        "WindowsSuppliedContentStableBinding",
        "checked_add",
        "self.hasher.update(chunk)",
        "reconcile_windows_supplied_entry_stability(stability_input)",
        "WindowsEntryPolicyKind::RegularFile",
        "stable_pair.pre_read.end_of_file",
        "stable_pair.post_read.end_of_file",
        "does not prove file origin",
    ] {
        assert!(
            production.contains(required),
            "missing pure digest token: {required}"
        );
    }

    for output_type in [
        "pub struct WindowsSuppliedContentDigestObservation",
        "pub struct WindowsSuppliedContentStableBinding",
    ] {
        let position = production.find(output_type).expect("output type");
        let prefix = &production[..position];
        let derive_start = prefix.rfind("#[derive(").expect("derive attribute");
        let derive = &production[derive_start..position];
        assert!(derive.contains("Serialize"), "output must serialize");
        assert!(
            !derive.contains("Deserialize"),
            "successful output must not deserialize"
        );
    }

    let observation_body = production
        .split_once("pub struct WindowsSuppliedContentDigestObservation {")
        .expect("observation declaration")
        .1
        .split_once('}')
        .expect("observation body")
        .0;
    let binding_body = production
        .split_once("pub struct WindowsSuppliedContentStableBinding {")
        .expect("binding declaration")
        .1
        .split_once('}')
        .expect("binding body")
        .0;
    assert!(
        !observation_body.contains("pub "),
        "observation fields are private"
    );
    assert!(!binding_body.contains("pub "), "binding fields are private");
}
