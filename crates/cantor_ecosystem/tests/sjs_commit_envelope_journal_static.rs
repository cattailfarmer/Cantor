use std::{fs, path::PathBuf, process::Command};

use cantor_ecosystem::sjs_commit_envelope_journal::{
    JournalFault, JournalVerificationReceipt, compile_commit_envelope_journal_verification,
    parse_journal_json,
};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn one_and_two_link_fixtures_verify_and_replay() {
    let root = root();
    for (name, links, tip) in [
        (
            "one_link.json",
            1,
            "2222222222222222222222222222222222222222",
        ),
        (
            "two_link.json",
            2,
            "3333333333333333333333333333333333333333",
        ),
    ] {
        let bytes = fs::read(
            root.join("fixtures/sjs_commit_envelope_journal_p2")
                .join(name),
        )
        .unwrap();
        let journal = parse_journal_json(&bytes).unwrap();
        let first = compile_commit_envelope_journal_verification(&journal).unwrap();
        let second = compile_commit_envelope_journal_verification(&journal).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.link_count, links);
        assert_eq!(first.open_tip_count, 1);
        assert_eq!(first.open_tip_commit, tip);
        assert!(!first.physical_contact);
    }
}

#[test]
fn cli_emits_receipt_to_stdout_and_typed_refusal_to_stderr() {
    let root = root();
    let binary = env!("CARGO_BIN_EXE_cantor-sjs-commit-envelope-journal-verify");
    let success = Command::new(binary)
        .current_dir(&root)
        .args([
            "--bundle",
            "fixtures/sjs_commit_envelope_journal_p2/two_link.json",
        ])
        .output()
        .unwrap();
    assert!(success.status.success());
    assert!(success.stderr.is_empty());
    let receipt: JournalVerificationReceipt = serde_json::from_slice(&success.stdout).unwrap();
    assert_eq!(receipt.link_count, 2);
    assert_eq!(receipt.open_tip_count, 1);

    let refusal = Command::new(binary)
        .args(["--output", "forbidden.json"])
        .output()
        .unwrap();
    assert_eq!(refusal.status.code(), Some(2));
    assert!(refusal.stdout.is_empty());
    let fault: JournalFault = serde_json::from_slice(&refusal.stderr).unwrap();
    assert_eq!(
        fault.code,
        cantor_ecosystem::sjs_commit_envelope_journal::JournalFaultCode::Cli
    );
    assert!(!root.join("forbidden.json").exists());
}

#[test]
fn signed_boundary_and_effect_absence_are_static() {
    let root = root();
    let module =
        fs::read_to_string(root.join("crates/cantor_ecosystem/src/sjs_commit_envelope_journal.rs"))
            .unwrap();
    let cli = fs::read_to_string(
        root.join("crates/cantor_ecosystem/src/bin/cantor-sjs-commit-envelope-journal-verify.rs"),
    )
    .unwrap();
    let specification =
        fs::read_to_string(root.join("specifications/Cantor_SJS_Commit_Envelope_Journal_P2.sop"))
            .unwrap();
    let signature = fs::read_to_string(root.join(
        "narrative/registries/Cantor_SJS_Commit_Envelope_Journal_P2_Satisfaction_Signature.sop",
    ))
    .unwrap();
    let threat_review = fs::read_to_string(root.join(
        "narrative/research/Cantor_SJS_Commit_Envelope_Journal_P2_Threat_Review_2026-08-24.sop",
    ))
    .unwrap();
    let source = fs::read_to_string(root.join(
        "source_documents/2026-08-24_cantor_sjs_commit_envelope_journal_p2/Cantor_SJS_Commit_Envelope_Journal_P2_Source.sop",
    ))
    .unwrap();

    for requirement in 1..=20 {
        assert!(specification.contains(&format!("CEJ-{requirement:03}")));
    }
    for threat in 1..=18 {
        assert!(threat_review.contains(&format!("T{threat:02}")));
    }
    assert!(source.contains("exactly one intentionally open current tip"));
    assert!(signature.contains("[status] valid"));
    assert!(signature.contains("68b2e626-f5e1-4ce1-a631-1784e24caa15"));

    for forbidden in [
        "std::process::Command",
        "Command::new",
        "fs::write",
        "File::create",
        "OpenOptions",
        "TcpStream",
        "reqwest",
        "unsafe {",
    ] {
        assert!(!module.contains(forbidden), "module contains {forbidden}");
    }
    let cli_production = cli.split("#[cfg(test)]").next().unwrap();
    for forbidden in ["--output", "fs::write", "File::create", "Command::new"] {
        assert!(
            !cli_production.contains(forbidden),
            "CLI contains {forbidden}"
        );
    }
}
