use std::path::PathBuf;

#[test]
fn project_component_has_only_effect_free_dependencies() {
    let manifest =
        std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .unwrap();
    for forbidden in [
        "rusqlite",
        "tokio",
        "rmcp",
        "reqwest",
        "windows-sys",
        "sha2",
    ] {
        assert!(
            !manifest.contains(forbidden),
            "forbidden dependency surfaced: {forbidden}"
        );
    }
}

#[test]
fn project_component_source_has_no_ambient_or_unsafe_surface() {
    let source =
        std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"))
            .unwrap();
    for forbidden in [
        "std::fs",
        "std::path",
        "std::process",
        "std::env",
        "std::net",
        "rusqlite",
        "tokio::",
        "rmcp::",
        "reqwest::",
        "unsafe {",
        "Command::",
        "File::",
    ] {
        assert!(!source.contains(forbidden), "forbidden surface {forbidden}");
    }
}
