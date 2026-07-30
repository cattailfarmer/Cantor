#[test]
fn windows_entry_policy_production_surface_is_pure_and_safe() {
    let source = include_str!("../src/windows_entry_policy.rs");
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
    ] {
        assert!(
            !production.contains(forbidden),
            "forbidden production token: {forbidden}"
        );
    }
    for required in [
        "WINDOWS_ENTRY_BENIGN_ATTRIBUTE_MASK",
        "WINDOWS_ENTRY_DIRECTORY_ALLOWED_MASK",
        "decode_and_evaluate_windows_entry_policy",
        "evaluate_windows_entry_policy",
        "is_reserved_device_stem",
        "encode_utf16",
    ] {
        assert!(
            production.contains(required),
            "missing pure policy token: {required}"
        );
    }
}
