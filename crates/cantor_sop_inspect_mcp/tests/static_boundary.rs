use cantor_sop_inspect_mcp::*;
use cantor_sop_semantics::digest;

#[test]
fn pinned_wire_stdio_semantics_consumer_and_fixture_bytes_are_unchanged() {
    for (bytes, expected) in [
        (
            include_bytes!("../../cantor_sop_inspect_wire/src/lib.rs").as_slice(),
            "5c2895fe0995a9403c5f8fdac3e4f507f6a7a7de8c5902507bdbac3f792bca07",
        ),
        (
            include_bytes!("../../cantor_sop_inspect_wire/src/bin/cantor-sop-inspect-stdio.rs")
                .as_slice(),
            "0fe4a5d00afe7d7efd5de62a8a7ce8fe0042293c5d72b7bbfdba5fbbee02bece",
        ),
        (
            include_bytes!("../../cantor_sop_inspect/src/lib.rs").as_slice(),
            "5cae18e1d96adb8023452e0fc658281b2f0f6fae6c74f311c58574e840006f84",
        ),
        (
            include_bytes!("../../cantor_sop_inspect_consumer/src/lib.rs").as_slice(),
            "5bb4d7e470b942f967eaaca6b40823f2d3cd6cabcc4d128ee148aa72d20e37d9",
        ),
        (
            include_bytes!(
                "../../../fixtures/semantic_inspection_consumer_handoff_p0/fixtures.json"
            )
            .as_slice(),
            "6ba11d93f80d8c9819be33624550809d94e5e2ac2106a6559fbcf62c8d803162",
        ),
    ] {
        assert_eq!(digest::bytes(bytes), expected);
    }
}
#[test]
fn production_effects_are_inherited_stream_only_not_ambient_paths_or_providers() {
    for source in [
        include_str!("../src/lib.rs"),
        include_str!("../src/transport.rs"),
        include_str!("../src/main.rs"),
    ] {
        for forbidden in [
            "unsafe {",
            "reqwest",
            "TcpListener",
            "TcpStream",
            "File::open",
            "File::create",
            "OpenOptions",
            "read_to_string",
            "create_dir",
            "std::process::Command",
            "tokio::process",
            "std::env::var",
            "std::env::current_dir",
        ] {
            assert!(
                !source.contains(forbidden),
                "forbidden ambient source surface: {forbidden}"
            );
        }
    }
    let native = include_str!("../src/main.rs");
    assert!(native.contains("try_clone_to_owned"));
    assert!(native.contains("tokio::fs::File::from_std"));
    assert!(native.contains("shutdown_timeout"));
    assert!(native.contains("worker_threads(2)"));
    assert!(native.contains("max_blocking_threads(2)"));
    assert!(!native.contains("#[tokio::main"));
}
#[test]
fn fixed_signed_p0_ceilings_are_not_inherited_large_wire_bounds() {
    assert_eq!((MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES), (262144, 1048576));
    assert_eq!(
        (MAX_INPUT_FRAME_BYTES, MAX_OUTPUT_FRAME_BYTES),
        (2097152, 4194304)
    );
    assert_eq!(
        (MAX_INPUT_BYTES, MAX_RESERVED_OUTPUT_BYTES),
        (8388608, 8388608)
    );
    assert_eq!(
        (MAX_MESSAGES, SESSION_SECONDS, SHUTDOWN_MILLISECONDS),
        (32, 60, 250)
    );
}
