use std::{fs, path::Path};

const MODULE: &str = "src/staged_diff_acquisition.rs";
const BINARY: &str = "src/bin/cantor-sjs-staged-diff-acquire.rs";

fn read(path: &str) -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(path)).unwrap()
}

#[test]
fn process_surface_is_exactly_read_only_git() {
    let source = read(MODULE);
    for required in [
        "Command::new(&self.executable)",
        ".env_clear()",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_GLOBAL",
        "GIT_TERMINAL_PROMPT",
        "GIT_OPTIONAL_LOCKS",
        "GIT_NO_LAZY_FETCH",
        "GIT_NO_REPLACE_OBJECTS",
        "--no-ext-diff",
        "--no-textconv",
        "--find-renames=50%",
        "cat-file",
        "index changed during acquisition",
    ] {
        assert!(source.contains(required), "missing control: {required}");
    }
    for forbidden in [
        "update-index",
        "write-tree",
        "checkout",
        "restore",
        "reset",
        "commit\"",
        "push\"",
        "fetch\"",
        "notes\"",
        "std::net",
        "reqwest",
        "unsafe {",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden surface: {forbidden}"
        );
    }
}

#[test]
fn cli_is_stdout_only_and_has_no_output_path() {
    let source = read(BINARY);
    assert!(source.contains("std::io::stdout"));
    assert!(source.contains("--inventory-only"));
    assert!(!source.contains("--output"));
    assert!(!source.contains("create_dir_all"));
    assert!(!source.contains("File::create"));
    assert!(!source.contains("fs::write"));
}

#[test]
fn public_contract_keeps_physical_observation_nonauthorizing() {
    let source = read(MODULE);
    assert!(source.contains("ObservationOnly"));
    assert!(source.contains("physical_contact: true"));
    assert!(source.contains("no staging mutation commit push publication"));
    assert!(source.contains("change-set self-inclusion authority"));
}
