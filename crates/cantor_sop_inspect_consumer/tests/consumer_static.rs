use cantor_sop_semantics::digest;

#[test]
fn production_source_has_no_io_launch_or_external_effect_surface() {
    let source = include_str!("../src/lib.rs");
    for forbidden in [
        "std::fs",
        "std::process",
        "Command::",
        "std::env",
        "std::time",
        "std::net",
        "tokio::",
        "reqwest",
        "rmcp::",
        "TcpStream",
        "TcpListener",
        "thread::",
        "unsafe",
    ] {
        assert!(
            !source.contains(forbidden),
            "unexpected product surface {forbidden}"
        );
    }
}

#[test]
fn production_dependencies_exclude_development_process_transport() {
    let manifest = include_str!("../Cargo.toml");
    let production = manifest
        .split("[dependencies]")
        .nth(1)
        .unwrap()
        .split("[dev-dependencies]")
        .next()
        .unwrap();
    for forbidden in ["tokio", "rmcp", "reqwest", "winapi", "windows", "rusqlite"] {
        assert!(!production.contains(forbidden));
    }
    assert!(production.contains("cantor_sop_inspect_wire"));
    assert!(manifest.contains("[lints]\nworkspace = true"));
}

#[test]
fn published_wire_and_stdio_host_are_exactly_unchanged() {
    assert_eq!(
        digest::bytes(include_bytes!("../../cantor_sop_inspect_wire/src/lib.rs")),
        "5c2895fe0995a9403c5f8fdac3e4f507f6a7a7de8c5902507bdbac3f792bca07"
    );
    assert_eq!(
        digest::bytes(include_bytes!(
            "../../cantor_sop_inspect_wire/src/bin/cantor-sop-inspect-stdio.rs"
        )),
        "0fe4a5d00afe7d7efd5de62a8a7ce8fe0042293c5d72b7bbfdba5fbbee02bece"
    );
}
