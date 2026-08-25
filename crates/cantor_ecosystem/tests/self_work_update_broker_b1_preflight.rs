use std::{
    fs,
    path::{Path, PathBuf},
    process,
    sync::atomic::{AtomicU64, Ordering},
};

use cantor_ecosystem::{
    B1_REFUSAL_CODE, B1PreflightAuthority, B1PreflightDisposition, B1PreflightFaultCode,
    from_b1_preflight_record_machine_form, to_b1_preflight_record_machine_form,
    verify_b1_preparation_evidence,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
const MEMBERS: [&str; 5] = [
    "directory_inventory.tsv",
    "envelope_inventory.tsv",
    "manifest.json",
    "preparation_result.json",
    "schema_inventory.tsv",
];

struct EvidenceCopy(PathBuf);

impl EvidenceCopy {
    fn new() -> Self {
        let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("cantor-b1-{0}-{id}", process::id()));
        fs::create_dir(&root).expect("create isolated test evidence root");
        let source = evidence_root();
        for member in MEMBERS {
            fs::copy(source.join(member), root.join(member)).expect("copy evidence member");
        }
        Self(root)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn mutate_result(&self, mutation: impl FnOnce(&mut Value)) {
        let path = self.0.join("preparation_result.json");
        let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        mutation(&mut value);
        fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        self.rehash_member("preparation_result.json");
    }

    fn rehash_member(&self, name: &str) {
        let member = fs::read(self.0.join(name)).unwrap();
        let manifest_path = self.0.join("manifest.json");
        let mut manifest: Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        let artifact = manifest["artifacts"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|artifact| artifact["path"] == name)
            .unwrap();
        artifact["bytes"] = Value::from(member.len() as u64);
        artifact["sha256"] = Value::from(sha256_upper(&member));
        fs::write(manifest_path, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
    }
}

impl Drop for EvidenceCopy {
    fn drop(&mut self) {
        let expected_prefix = format!("cantor-b1-{}-", process::id());
        assert!(
            self.0
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(&expected_prefix))
        );
        fs::remove_dir_all(&self.0).expect("remove isolated test evidence root");
    }
}

#[test]
fn exact_preparation_evidence_yields_equal_not_run_replay() {
    let first = verify_b1_preparation_evidence(&evidence_root()).expect("exact evidence verifies");
    let second = verify_b1_preparation_evidence(&evidence_root()).expect("exact replay verifies");
    assert_eq!(first, second);
    assert_eq!(first.disposition, B1PreflightDisposition::NotRun);
    assert_eq!(
        first.authority,
        B1PreflightAuthority::PreflightObservationOnly
    );
    assert_eq!(first.refusal_code, B1_REFUSAL_CODE);
    assert_eq!(first.run_count, 0);
    assert_eq!(first.transcript_frame_count, 0);
    assert!(!first.physical_contact);
    assert!(!first.live_process_launched);
    assert!(first.fixture_quarantined);
    assert!(!first.cleanup_performed);

    let machine = to_b1_preflight_record_machine_form(&first).expect("record machine form");
    let reparsed = from_b1_preflight_record_machine_form(&machine).expect("record reparses");
    assert_eq!(reparsed, first);
}

#[test]
fn manifest_raw_and_machine_form_mutations_refuse() {
    let raw = EvidenceCopy::new();
    let mut bytes = fs::read(raw.path().join("schema_inventory.tsv")).unwrap();
    bytes[0] ^= 1;
    fs::write(raw.path().join("schema_inventory.tsv"), bytes).unwrap();
    assert_fault(raw.path(), B1PreflightFaultCode::Digest);

    let unknown = EvidenceCopy::new();
    let path = unknown.path().join("manifest.json");
    let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    value["unexpected"] = Value::Bool(true);
    fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert_fault(unknown.path(), B1PreflightFaultCode::MachineForm);

    let duplicate = EvidenceCopy::new();
    let path = duplicate.path().join("preparation_result.json");
    let original = String::from_utf8(fs::read(&path).unwrap()).unwrap();
    let bytes = original.replacen('{', "{\"profile\":\"duplicate\",", 1);
    fs::write(&path, bytes).unwrap();
    duplicate.rehash_member("preparation_result.json");
    assert_fault(duplicate.path(), B1PreflightFaultCode::MachineForm);
}

#[test]
fn inventory_coordinate_mutations_refuse() {
    let duplicate = EvidenceCopy::new();
    let path = duplicate.path().join("schema_inventory.tsv");
    let mut text = String::from_utf8(fs::read(&path).unwrap()).unwrap();
    let first = text.lines().next().unwrap().to_owned();
    text.push_str(&first);
    text.push('\n');
    fs::write(&path, text).unwrap();
    duplicate.rehash_member("schema_inventory.tsv");
    assert_fault(duplicate.path(), B1PreflightFaultCode::Inventory);

    let order = EvidenceCopy::new();
    let path = order.path().join("schema_inventory.tsv");
    let text = String::from_utf8(fs::read(&path).unwrap()).unwrap();
    let mut lines: Vec<_> = text.lines().collect();
    lines.swap(0, 1);
    fs::write(&path, lines.join("\n") + "\n").unwrap();
    order.rehash_member("schema_inventory.tsv");
    assert_fault(order.path(), B1PreflightFaultCode::Inventory);

    let escape = EvidenceCopy::new();
    let path = escape.path().join("schema_inventory.tsv");
    let text = String::from_utf8(fs::read(&path).unwrap()).unwrap();
    let mutated = text.replacen("ApplyPatchApprovalParams.json", "../escape.json", 1);
    fs::write(&path, mutated).unwrap();
    escape.rehash_member("schema_inventory.tsv");
    assert_fault(escape.path(), B1PreflightFaultCode::Inventory);

    let malformed = EvidenceCopy::new();
    let path = malformed.path().join("schema_inventory.tsv");
    let text = String::from_utf8(fs::read(&path).unwrap()).unwrap();
    let mutated = text.replacen(
        "9DE5A28A543214033B546DB66AD8D34748A949C9878A7E51EC57A99FEB2B8E67",
        "not-a-digest",
        1,
    );
    fs::write(&path, mutated).unwrap();
    malformed.rehash_member("schema_inventory.tsv");
    assert_fault(malformed.path(), B1PreflightFaultCode::Inventory);
}

#[test]
fn selection_process_and_schema_mutations_refuse() {
    let executable = EvidenceCopy::new();
    executable.mutate_result(|value| {
        value["selected_executable"]["sha256"] = Value::from("0".repeat(64))
    });
    assert_fault(executable.path(), B1PreflightFaultCode::Selection);

    let raw_argument = EvidenceCopy::new();
    raw_argument
        .mutate_result(|value| value["schema_generation"]["argv"][1] = Value::from("generate-ts"));
    assert_fault(raw_argument.path(), B1PreflightFaultCode::Schema);

    let restart_time = EvidenceCopy::new();
    restart_time.mutate_result(|value| {
        value["schema_generation"]["started_utc"] = Value::from("2026-08-25T17:15:48.0000000+00:00")
    });
    assert_fault(restart_time.path(), B1PreflightFaultCode::Schema);

    let schema_total = EvidenceCopy::new();
    schema_total.mutate_result(|value| {
        value["schema_generation"]["schema_total_bytes"] = Value::from(2_468_057)
    });
    assert_fault(schema_total.path(), B1PreflightFaultCode::Schema);

    let policy = EvidenceCopy::new();
    policy.mutate_result(|value| {
        value["final_b1_admission"]["read_only_policy_properties"] =
            serde_json::json!(["networkAccess", "readableRoots", "type"])
    });
    assert_fault(policy.path(), B1PreflightFaultCode::Compatibility);
}

#[test]
fn disposition_and_zero_count_mutations_refuse() {
    let disposition = EvidenceCopy::new();
    disposition.mutate_result(|value| value["disposition"] = Value::from("prepared_live_run"));
    assert_fault(disposition.path(), B1PreflightFaultCode::Selection);

    for key in [
        "run_count",
        "transcript_frame_count",
        "provider_contact_count",
        "model_turn_count",
        "mcp_call_count",
        "external_network_count",
        "mutation_count",
    ] {
        let evidence = EvidenceCopy::new();
        evidence.mutate_result(|value| value["final_b1_admission"][key] = Value::from(1));
        assert_fault(evidence.path(), B1PreflightFaultCode::Compatibility);
    }

    let refusal = EvidenceCopy::new();
    refusal.mutate_result(|value| {
        value["final_b1_admission"]["refusal_code"] = Value::from("provider_unavailable")
    });
    assert_fault(refusal.path(), B1PreflightFaultCode::Compatibility);
}

#[test]
fn record_unknown_duplicate_authority_and_digest_mutations_refuse() {
    let record = verify_b1_preparation_evidence(&evidence_root()).unwrap();
    let exact = to_b1_preflight_record_machine_form(&record).unwrap();

    let duplicate = exact.replacen('{', "{\"profile\":\"duplicate\",", 1);
    assert!(from_b1_preflight_record_machine_form(&duplicate).is_err());

    let mut value: Value = serde_json::from_str(&exact).unwrap();
    value["unexpected"] = Value::Bool(true);
    assert!(from_b1_preflight_record_machine_form(&value.to_string()).is_err());

    for (key, replacement) in [
        ("physical_contact", Value::Bool(true)),
        ("may_have_mutated", Value::Bool(true)),
        ("live_process_launched", Value::Bool(true)),
        ("fixture_quarantined", Value::Bool(false)),
        ("cleanup_performed", Value::Bool(true)),
        ("run_count", Value::from(1)),
    ] {
        let mut value: Value = serde_json::from_str(&exact).unwrap();
        value[key] = replacement;
        let error = from_b1_preflight_record_machine_form(&value.to_string()).unwrap_err();
        assert_eq!(error.code, B1PreflightFaultCode::Authority);
    }

    let mut value: Value = serde_json::from_str(&exact).unwrap();
    value["record_digest"]["value"] = Value::from("0".repeat(64));
    let error = from_b1_preflight_record_machine_form(&value.to_string()).unwrap_err();
    assert_eq!(error.code, B1PreflightFaultCode::Digest);
}

fn evidence_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("evidence/self_work_update_broker_b1_preparation")
}

fn assert_fault(path: &Path, expected: B1PreflightFaultCode) {
    let error = verify_b1_preparation_evidence(path).expect_err("mutation must refuse");
    assert_eq!(error.code, expected, "{error}");
}

fn sha256_upper(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect()
}
