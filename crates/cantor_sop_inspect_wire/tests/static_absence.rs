use std::{fs, path::PathBuf};

#[test]
fn dependency_and_source_surface_remain_effect_free() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let manifest = fs::read_to_string(root.join("Cargo.toml")).unwrap();
    for required in [
        "cantor_sop_inspect",
        "cantor_sop_semantics",
        "serde.workspace",
        "serde_json.workspace",
    ] {
        assert!(manifest.contains(required), "missing {required}");
    }
    for forbidden in [
        "tokio",
        "rmcp",
        "reqwest",
        "redb",
        "sled",
        "rusqlite",
        "windows-sys",
        "rand",
        "sha2",
    ] {
        assert!(
            !manifest.contains(forbidden),
            "forbidden dependency {forbidden}"
        );
    }

    let source = fs::read_to_string(root.join("src/lib.rs")).unwrap();
    for forbidden in [
        "std::fs",
        "std::io",
        "std::net",
        "std::path",
        "std::process",
        "std::thread",
        "std::time",
        "std::env",
        "TcpStream",
        "UdpSocket",
        "Command::",
        "File::",
        "SystemTime",
        "Instant::",
        "unsafe ",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden source token {forbidden}"
        );
    }
}
