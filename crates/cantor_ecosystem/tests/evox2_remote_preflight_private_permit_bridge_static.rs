//! Reviewed-tree absence and cardinality gates for the crate-private permit bridge.

use std::{fs, path::Path};

const LIB: &str = include_str!("../src/lib.rs");
const BRIDGE: &str = include_str!("../src/evox2_remote_preflight_private_permit_bridge.rs");
const RUNNER: &str = include_str!("../src/evox2_scratch_build_remote_preflight_runner.rs");

fn occurrences(haystack: &str, needle: &str) -> usize {
    haystack.match_indices(needle).count()
}

fn rust_sources(root: &Path) -> String {
    let mut combined = String::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let mut entries: Vec<_> = fs::read_dir(directory)
            .expect("source directory must remain readable")
            .map(|entry| entry.expect("source entry must remain readable"))
            .collect();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let metadata =
                fs::symlink_metadata(&path).expect("source metadata must remain readable");
            assert!(
                !metadata.file_type().is_symlink(),
                "source link is forbidden"
            );
            if metadata.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                combined.push_str(&fs::read_to_string(path).expect("Rust source must be UTF-8"));
                combined.push('\n');
            }
        }
    }
    combined
}

fn production_bridge() -> &'static str {
    BRIDGE
        .split_once("#[cfg(test)]")
        .expect("private bridge must keep fixtures behind cfg(test)")
        .0
}

#[test]
fn module_and_capabilities_remain_crate_private_and_unconstructible() {
    assert_eq!(
        occurrences(
            LIB,
            "pub(crate) mod evox2_remote_preflight_private_permit_bridge;"
        ),
        1
    );
    assert!(!LIB.contains("pub mod evox2_remote_preflight_private_permit_bridge;"));
    assert!(!LIB.contains("pub use evox2_remote_preflight_private_permit_bridge"));

    let production = production_bridge();
    assert_eq!(
        occurrences(
            production,
            "pub(crate) struct Evox2RemotePreflightLiveAdmission"
        ),
        1
    );
    assert_eq!(
        occurrences(production, "struct Evox2RemotePreflightLiveAdmission {"),
        1
    );
    assert_eq!(
        occurrences(
            production,
            "pub(crate) fn run_evox2_remote_preflight_private_permit_bridge_once("
        ),
        1
    );
    assert_eq!(occurrences(production, "runner(permit)"), 1);
    assert!(!production.contains("live_initiation"));
}

#[test]
fn bridge_has_no_clone_serialization_persistence_retry_or_alternate_process_surface() {
    let production = production_bridge();
    for forbidden in [
        "Serialize",
        "Deserialize",
        "Default",
        "std::fs",
        "std::net",
        "std::process",
        "Command::",
        "std::env",
        "loop {",
        "while ",
        "retry(",
        "thread::spawn",
    ] {
        assert!(
            !production.contains(forbidden),
            "private bridge gained forbidden production token: {forbidden}"
        );
    }
    assert_eq!(occurrences(production, "FnOnce("), 1);
    assert_eq!(
        occurrences(production, "run_evox2_scratch_build_remote_preflight_once("),
        1
    );
    assert_eq!(
        occurrences(
            RUNNER,
            "pub(crate) fn issue_evox2_scratch_build_remote_preflight_single_use_permit("
        ),
        1
    );
    assert!(!RUNNER.contains("impl Clone for Evox2ScratchBuildRemotePreflightSingleUsePermit"));
    assert!(!RUNNER.contains("impl Serialize for Evox2ScratchBuildRemotePreflightSingleUsePermit"));
    assert!(
        !RUNNER.contains("impl Deserialize for Evox2ScratchBuildRemotePreflightSingleUsePermit")
    );
}

#[test]
fn no_bridge_binary_or_live_initiation_source_exists() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    for relative in [
        "src/bin/cantor-evox2-remote-preflight-private-permit-bridge.rs",
        "src/evox2_remote_preflight_private_permit_bridge/live_initiation.rs",
        "src/evox2_remote_preflight_private_permit_bridge/live_initiation/mod.rs",
    ] {
        assert!(
            !manifest.join(relative).exists(),
            "forbidden bridge route exists: {relative}"
        );
    }

    let all_source = rust_sources(&manifest.join("src"));
    assert_eq!(
        occurrences(
            &all_source,
            "issue_evox2_scratch_build_remote_preflight_single_use_permit("
        ),
        2,
        "issuer must have exactly one definition and one bridge call"
    );
    assert_eq!(
        occurrences(
            &all_source,
            "run_evox2_remote_preflight_private_permit_bridge_once("
        ),
        1,
        "production bridge entry must remain uncalled"
    );
}
