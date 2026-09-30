use std::path::PathBuf;

#[test]
fn promoted_kernel_has_only_bounded_dependencies() {
    let manifest =
        std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .unwrap();
    for forbidden in [
        "rusqlite",
        "tokio",
        "rmcp",
        "reqwest",
        "url =",
        "windows-sys",
    ] {
        assert!(
            !manifest.contains(forbidden),
            "forbidden dependency surfaced: {forbidden}"
        );
    }
}

#[test]
fn promoted_kernel_source_has_no_ambient_or_unsafe_surface() {
    let source_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    for name in [
        "lib.rs",
        "model.rs",
        "error.rs",
        "digest.rs",
        "validate.rs",
        "source.rs",
        "expression.rs",
    ] {
        let text = std::fs::read_to_string(source_root.join(name)).unwrap();
        for forbidden in [
            "std::fs",
            "std::process",
            "std::env",
            "std::net",
            "rusqlite",
            "tokio::",
            "rmcp::",
            "reqwest::",
            "unsafe {",
            "Command::",
        ] {
            assert!(
                !text.contains(forbidden),
                "forbidden surface {forbidden} in {name}"
            );
        }
    }
}
