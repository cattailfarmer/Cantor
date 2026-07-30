#[test]
fn windows_stream_info_parser_production_surface_is_pure_and_pointer_free() {
    let source = include_str!("../src/windows_stream_info_parser.rs");
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
        "File::",
        "Command::",
        "GetFileInformationByHandleEx(",
        "from_raw_parts",
        "*const",
        "*mut",
    ] {
        assert!(!production.contains(forbidden), "{forbidden}");
    }
    for required in [
        "from_le_bytes",
        "from_utf16",
        "checked_add",
        "next.is_multiple_of(8)",
        "name_end != bytes.len()",
    ] {
        assert!(production.contains(required), "{required}");
    }
}
