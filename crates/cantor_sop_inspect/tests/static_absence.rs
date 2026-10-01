const SOURCE: &str = include_str!("../src/lib.rs");
const MANIFEST: &str = include_str!("../Cargo.toml");

#[test]
fn implementation_has_no_ambient_or_effectful_api_surface() {
    for forbidden in [
        "std::fs",
        "std::path",
        "std::process",
        "std::net",
        "TcpStream",
        "UdpSocket",
        "std::env",
        "std::time",
        "std::thread",
        "SystemTime",
        "Instant::now",
        "rusqlite",
        "redb::",
        "sled::",
        "reqwest::",
        "tokio::",
        "rmcp::",
        "rand::",
        "unsafe {",
        "Command::",
        "File::",
    ] {
        assert!(
            !SOURCE.contains(forbidden),
            "effectful or ambient surface appeared: {forbidden}"
        );
        assert!(
            !MANIFEST.contains(forbidden),
            "effectful dependency appeared: {forbidden}"
        );
    }
}

#[test]
fn dependency_surface_is_the_exact_pure_composition() {
    for forbidden in [
        "rusqlite",
        "redb",
        "sled",
        "tokio",
        "rmcp",
        "reqwest",
        "windows-sys",
        "sha2",
        "rand",
    ] {
        assert!(
            !MANIFEST.contains(forbidden),
            "forbidden dependency surfaced: {forbidden}"
        );
    }
    for required in [
        "cantor_sop_project",
        "cantor_sop_query",
        "cantor_sop_excerpt",
        "cantor_sop_semantics",
        "serde.workspace",
        "serde_json.workspace",
    ] {
        assert!(
            MANIFEST.contains(required),
            "required dependency absent: {required}"
        );
    }
    assert_eq!(MANIFEST.matches("{ path =").count(), 4);
}
