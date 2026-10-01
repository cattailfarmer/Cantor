use std::{fs, path::PathBuf};

#[test]
fn stdio_host_surface_is_exact_and_has_no_broader_authority() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source = fs::read_to_string(root.join("src/bin/cantor-sop-inspect-stdio.rs")).unwrap();
    for required in [
        "MAX_WIRE_REQUEST_BYTES",
        "MAX_WIRE_RESPONSE_BYTES",
        "parse_request",
        "respond",
        "read_request",
        "write_all",
        "flush",
        "ExitCode",
    ] {
        assert!(source.contains(required), "missing {required}");
    }
    for forbidden in [
        "std::fs",
        "std::net",
        "std::path",
        "TcpStream",
        "UdpSocket",
        "Command::",
        "File::",
        "current_dir",
        "set_current_dir",
        "env::var",
        "thread::",
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
