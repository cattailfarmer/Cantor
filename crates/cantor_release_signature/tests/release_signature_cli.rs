use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

use cantor_release_signature::{
    PORTABLE_EVIDENCE_NON_AUTHORITY, PORTABLE_EVIDENCE_PROFILE, PORTABLE_EVIDENCE_STATUS,
    ReleaseSignatureReceipt, generate_synthetic_release_signature_fixture,
};
use serde_json::json;
use sha2::{Digest, Sha256};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);

struct Fixture {
    root: PathBuf,
    bundle: PathBuf,
    evidence: PathBuf,
    policy: PathBuf,
    envelope: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "cantor-release-signature-tests-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let bundle_bytes = b"synthetic portable archive bytes";
        let evidence_bytes = serde_json::to_vec_pretty(&json!({
            "profile": PORTABLE_EVIDENCE_PROFILE,
            "status": PORTABLE_EVIDENCE_STATUS,
            "source_commit": "f23a6ce7788aa1fc4988a2dcd0c51d9054092ec7",
            "target": "windows-x86_64",
            "build_mode": "verified_prebuilt",
            "cargo_lock": { "path": "Cargo.lock" },
            "archive": {
                "file_name": "cantor-provider-free-windows-x86_64-p0.zip",
                "bytes": bundle_bytes.len(),
                "sha256": digest(bundle_bytes),
                "format": "zip",
                "compression": "store",
                "timestamp_contract": "zip_dos_epoch_1980_01_01_00_00_00",
                "entry_count": 6
            },
            "embedded_manifest": { "path": "bundle-manifest.json" },
            "entries": [0, 1, 2, 3, 4, 5],
            "determinism": { "byte_equal": true },
            "safety": { "archive_extracted": false },
            "capability_denials": ["production_trust"],
            "non_authority_statement": PORTABLE_EVIDENCE_NON_AUTHORITY
        }))
        .unwrap();
        let fixture =
            generate_synthetic_release_signature_fixture(bundle_bytes, &evidence_bytes).unwrap();
        let bundle = root.join("bundle.zip");
        let evidence = root.join("evidence.json");
        let policy = root.join("policy.json");
        let envelope = root.join("envelope.json");
        fs::write(&bundle, bundle_bytes).unwrap();
        fs::write(&evidence, evidence_bytes).unwrap();
        fs::write(&policy, serde_json::to_vec(&fixture.policy).unwrap()).unwrap();
        fs::write(&envelope, serde_json::to_vec(&fixture.envelope).unwrap()).unwrap();
        Self {
            root,
            bundle,
            evidence,
            policy,
            envelope,
        }
    }

    fn invoke(&self) -> Output {
        invoke_paths(&self.bundle, &self.evidence, &self.policy, &self.envelope)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

#[test]
fn cli_emits_one_compact_verified_receipt() {
    let fixture = Fixture::new();
    let first = fixture.invoke();
    let second = fixture.invoke();
    assert_eq!(first.status.code(), Some(0));
    assert!(first.stderr.is_empty());
    assert_eq!(first.stdout, second.stdout);
    assert!(first.stdout.ends_with(b"\n"));
    assert!(!first.stdout[..first.stdout.len() - 1].contains(&b'\n'));
    let receipt: ReleaseSignatureReceipt = serde_json::from_slice(&first.stdout).unwrap();
    assert!(receipt.signature_verified);
    assert!(!receipt.safety.policy_governance_proved);
    assert!(!receipt.safety.production_publisher_authenticity_proved);
}

#[test]
fn cli_invocation_and_input_transport_refusals_use_exit_two() {
    let binary = env!("CARGO_BIN_EXE_cantor-release-verify");
    assert_eq!(
        Command::new(binary).output().unwrap().status.code(),
        Some(2)
    );
    assert_eq!(
        Command::new(binary)
            .arg("--unknown")
            .output()
            .unwrap()
            .status
            .code(),
        Some(2)
    );
    assert_eq!(
        Command::new(binary)
            .arg("--help")
            .output()
            .unwrap()
            .status
            .code(),
        Some(0)
    );
    let fixture = Fixture::new();
    let duplicate = Command::new(binary)
        .args(["--bundle", fixture.bundle.to_str().unwrap()])
        .args(["--bundle", fixture.bundle.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(duplicate.status.code(), Some(2));
    let alias = invoke_paths(
        &fixture.bundle,
        &fixture.bundle,
        &fixture.policy,
        &fixture.envelope,
    );
    assert_eq!(alias.status.code(), Some(2));
    let directory = invoke_paths(
        &fixture.root,
        &fixture.evidence,
        &fixture.policy,
        &fixture.envelope,
    );
    assert_eq!(directory.status.code(), Some(2));
    fs::write(&fixture.policy, vec![b'x'; 16 * 1024 + 1]).unwrap();
    assert_eq!(fixture.invoke().status.code(), Some(2));
}

#[test]
fn cli_verification_refusals_use_exit_three() {
    let fixture = Fixture::new();
    fs::write(&fixture.bundle, b"changed bundle bytes").unwrap();
    assert_eq!(fixture.invoke().status.code(), Some(3));

    let fixture = Fixture::new();
    fs::write(&fixture.policy, b"{").unwrap();
    assert_eq!(fixture.invoke().status.code(), Some(3));

    let fixture = Fixture::new();
    let mut envelope: serde_json::Value =
        serde_json::from_slice(&fs::read(&fixture.envelope).unwrap()).unwrap();
    envelope["signature_hex"] = json!("0".repeat(128));
    fs::write(&fixture.envelope, serde_json::to_vec(&envelope).unwrap()).unwrap();
    assert_eq!(fixture.invoke().status.code(), Some(3));
}

#[cfg(windows)]
#[test]
fn cli_refuses_symlink_when_host_permits_fixture() {
    use std::os::windows::fs::symlink_file;

    let fixture = Fixture::new();
    let link = fixture.root.join("bundle-link.zip");
    if symlink_file(&fixture.bundle, &link).is_err() {
        return;
    }
    let output = invoke_paths(&link, &fixture.evidence, &fixture.policy, &fixture.envelope);
    assert_eq!(output.status.code(), Some(2));
}

#[cfg(unix)]
#[test]
fn cli_refuses_symlink() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    let link = fixture.root.join("bundle-link.zip");
    symlink(&fixture.bundle, &link).unwrap();
    let output = invoke_paths(&link, &fixture.evidence, &fixture.policy, &fixture.envelope);
    assert_eq!(output.status.code(), Some(2));
}

fn invoke_paths(bundle: &Path, evidence: &Path, policy: &Path, envelope: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cantor-release-verify"))
        .args(["--bundle", bundle.to_str().unwrap()])
        .args(["--bundle-evidence", evidence.to_str().unwrap()])
        .args(["--policy", policy.to_str().unwrap()])
        .args(["--envelope", envelope.to_str().unwrap()])
        .output()
        .unwrap()
}

fn digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0F) as usize] as char);
    }
    output
}
