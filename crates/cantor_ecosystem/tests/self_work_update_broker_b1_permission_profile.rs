use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

use cantor_ecosystem::{
    B1PermissionProfileFaultCode, from_b1_permission_profile_receipt_machine_form,
    to_b1_permission_profile_receipt_machine_form, verify_b1_permission_profile_evidence,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

static NEXT_COPY: AtomicU64 = AtomicU64::new(1);

#[test]
fn checked_evidence_verifies_twice_and_round_trips() {
    let first = verify_b1_permission_profile_evidence(&evidence_root()).unwrap();
    let second = verify_b1_permission_profile_evidence(&evidence_root()).unwrap();
    let first_form = to_b1_permission_profile_receipt_machine_form(&first).unwrap();
    let second_form = to_b1_permission_profile_receipt_machine_form(&second).unwrap();
    assert_eq!(first_form, second_form);
    assert_eq!(
        from_b1_permission_profile_receipt_machine_form(&first_form).unwrap(),
        first
    );
    assert!(first.selected_host_pinned);
    assert!(first.historical_not_run_preserved);
    assert!(first.read_scope_representable);
    assert!(first.allowed_read_enforced);
    assert!(first.denied_read_enforced);
    assert_eq!(first.writer_run_count, 0);
    assert!(!first.live_writer_allowed);
    assert!(first.next_writer_preflight_formation_supported);
}

#[test]
fn bounded_cli_emits_the_exact_receipt_and_refuses_wrong_arity() {
    let expected = verify_b1_permission_profile_evidence(&evidence_root()).unwrap();
    let expected = to_b1_permission_profile_receipt_machine_form(&expected).unwrap();
    let binary = env!("CARGO_BIN_EXE_cantor-self-work-update-broker-b1-permission-profile");
    let output = Command::new(binary).arg(evidence_root()).output().unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("{expected}\n")
    );
    assert!(output.stderr.is_empty());

    let output = Command::new(binary).output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .starts_with("usage:")
    );
}

#[test]
fn manifest_raw_path_count_and_digest_mutations_refuse() {
    let duplicate = EvidenceCopy::new();
    duplicate.replace_raw(
        "manifest.json",
        "{\n",
        "{\n    \"profile\": \"duplicate\",\n",
    );
    assert_fault(duplicate.path(), B1PermissionProfileFaultCode::MachineForm);

    let unknown = EvidenceCopy::new();
    unknown.mutate_json("manifest.json", |value| {
        value["unknown"] = Value::Bool(true)
    });
    assert_fault(unknown.path(), B1PermissionProfileFaultCode::MachineForm);

    let profile = EvidenceCopy::new();
    profile.mutate_json("manifest.json", |value| {
        value["profile"] = Value::from("wrong")
    });
    assert_fault(profile.path(), B1PermissionProfileFaultCode::Manifest);

    let count = EvidenceCopy::new();
    count.mutate_json("manifest.json", |value| {
        value["artifacts"].as_array_mut().unwrap().pop();
    });
    assert_fault(count.path(), B1PermissionProfileFaultCode::Manifest);

    let path = EvidenceCopy::new();
    path.mutate_json("manifest.json", |value| {
        value["artifacts"][0]["path"] = Value::from("../escape")
    });
    assert_fault(path.path(), B1PermissionProfileFaultCode::Manifest);

    let digest = EvidenceCopy::new();
    digest.mutate_json("manifest.json", |value| {
        value["artifacts"][0]["sha256"] = Value::from("0".repeat(64))
    });
    assert_fault(digest.path(), B1PermissionProfileFaultCode::Digest);
}

#[test]
fn observation_duplicate_unknown_lineage_and_selection_mutations_refuse() {
    let duplicate = EvidenceCopy::new();
    duplicate.replace_raw_and_rehash(
        "observation.json",
        "{\n",
        "{\n    \"profile\": \"duplicate\",\n",
    );
    assert_fault(duplicate.path(), B1PermissionProfileFaultCode::MachineForm);

    let unknown = EvidenceCopy::new();
    unknown.mutate_artifact_json("observation.json", |value| {
        value["unknown"] = Value::Bool(true)
    });
    assert_fault(unknown.path(), B1PermissionProfileFaultCode::MachineForm);

    let lineage = EvidenceCopy::new();
    lineage.mutate_artifact_json("observation.json", |value| {
        value["predecessor_commit"] = Value::from("0".repeat(40))
    });
    assert_fault(lineage.path(), B1PermissionProfileFaultCode::Lineage);

    for key in ["path", "sha256", "version_output"] {
        let selection = EvidenceCopy::new();
        selection.mutate_artifact_json("observation.json", |value| {
            value["selected_executable"][key] = Value::from("wrong")
        });
        assert_fault(selection.path(), B1PermissionProfileFaultCode::Selection);
    }
}

#[test]
fn stable_and_experimental_schema_semantic_mutations_refuse() {
    let stable = EvidenceCopy::new();
    stable.mutate_artifact_json("standard_schema.json", |value| {
        let variants = value
            .pointer_mut("/definitions/v2/SandboxPolicy/oneOf")
            .unwrap()
            .as_array_mut()
            .unwrap();
        let read_only = variants
            .iter_mut()
            .find(|variant| variant["title"] == "ReadOnlySandboxPolicy")
            .unwrap();
        read_only["properties"]["readableRoots"] = serde_json::json!({"type":"array"});
    });
    assert_fault(stable.path(), B1PermissionProfileFaultCode::Schema);

    let experimental = EvidenceCopy::new();
    experimental.mutate_artifact_json("experimental_schema.json", |value| {
        replace_string(value, "permissionProfile/list", "permissionProfile/absent");
    });
    assert_fault(experimental.path(), B1PermissionProfileFaultCode::Schema);

    let mode = EvidenceCopy::new();
    mode.mutate_artifact_json("experimental_schema.json", |value| {
        value
            .pointer_mut("/definitions/v2/FileSystemAccessMode/enum")
            .unwrap()
            .as_array_mut()
            .unwrap()
            .retain(|entry| entry != "deny");
    });
    assert_fault(mode.path(), B1PermissionProfileFaultCode::Schema);
}

#[test]
fn permission_profile_and_sentinel_mutations_refuse() {
    for (pointer, replacement, expected) in [
        (
            "/permission_profile/root_access",
            Value::from("read"),
            B1PermissionProfileFaultCode::Profile,
        ),
        (
            "/permission_profile/network_enabled",
            Value::Bool(true),
            B1PermissionProfileFaultCode::Profile,
        ),
        (
            "/permission_profile/denied_access",
            Value::from("read"),
            B1PermissionProfileFaultCode::Profile,
        ),
        (
            "/sentinels/allowed_sha256",
            Value::from("0".repeat(64)),
            B1PermissionProfileFaultCode::Enforcement,
        ),
    ] {
        let evidence = EvidenceCopy::new();
        evidence.mutate_artifact_json("observation.json", |value| {
            *value.pointer_mut(pointer).unwrap() = replacement.clone()
        });
        assert_fault(evidence.path(), expected);
    }
}

#[test]
fn transcript_order_identity_and_enforcement_mutations_refuse() {
    let dropped = EvidenceCopy::new();
    dropped.mutate_artifact_json("observation.json", |value| {
        value["transcript"].as_array_mut().unwrap().pop();
    });
    assert_fault(dropped.path(), B1PermissionProfileFaultCode::Transcript);

    let reordered = EvidenceCopy::new();
    reordered.mutate_artifact_json("observation.json", |value| {
        value["transcript"].as_array_mut().unwrap().swap(2, 3);
    });
    assert_fault(reordered.path(), B1PermissionProfileFaultCode::Transcript);

    let id = EvidenceCopy::new();
    id.mutate_artifact_json("observation.json", |value| {
        value["transcript"][3]["id"] = Value::from(9)
    });
    assert_fault(id.path(), B1PermissionProfileFaultCode::Transcript);

    let allowed = EvidenceCopy::new();
    allowed.mutate_artifact_json("observation.json", |value| {
        value["transcript"][3]["result"]["stdout"] = Value::from("wrong\n")
    });
    assert_fault(allowed.path(), B1PermissionProfileFaultCode::Enforcement);

    for (key, replacement) in [
        ("exitCode", Value::from(0)),
        ("stdout", Value::from("SWA05_DENIED_READ_SENTINEL\n")),
        ("stderr", Value::from("")),
    ] {
        let denied = EvidenceCopy::new();
        denied.mutate_artifact_json("observation.json", |value| {
            value["transcript"][4]["result"][key] = replacement.clone()
        });
        assert_fault(denied.path(), B1PermissionProfileFaultCode::Enforcement);
    }
}

#[test]
fn effect_boundary_and_receipt_authority_mutations_refuse() {
    for key in [
        "writer_run_count",
        "provider_contact_count",
        "model_turn_count",
        "mcp_call_count",
        "git_command_count",
        "remote_contact_count",
        "d_drive_contact_count",
        "product_mutation_count",
        "cleanup_count",
    ] {
        let evidence = EvidenceCopy::new();
        evidence.mutate_artifact_json("observation.json", |value| {
            value["boundaries"][key] = Value::from(1)
        });
        assert_fault(evidence.path(), B1PermissionProfileFaultCode::Authority);
    }

    let receipt = verify_b1_permission_profile_evidence(&evidence_root()).unwrap();
    let exact = to_b1_permission_profile_receipt_machine_form(&receipt).unwrap();

    let duplicate = exact.replacen('{', "{\"profile\":\"duplicate\",", 1);
    assert!(from_b1_permission_profile_receipt_machine_form(&duplicate).is_err());

    for (key, replacement) in [
        ("live_writer_allowed", Value::Bool(true)),
        ("writer_run_count", Value::from(1)),
        ("denied_read_enforced", Value::Bool(false)),
        (
            "next_writer_preflight_formation_supported",
            Value::Bool(false),
        ),
    ] {
        let mut value: Value = serde_json::from_str(&exact).unwrap();
        value[key] = replacement;
        let error =
            from_b1_permission_profile_receipt_machine_form(&value.to_string()).unwrap_err();
        assert_eq!(error.code, B1PermissionProfileFaultCode::Authority);
    }

    let mut value: Value = serde_json::from_str(&exact).unwrap();
    value["receipt_digest"]["value"] = Value::from("0".repeat(64));
    let error = from_b1_permission_profile_receipt_machine_form(&value.to_string()).unwrap_err();
    assert_eq!(error.code, B1PermissionProfileFaultCode::Digest);
}

struct EvidenceCopy {
    root: PathBuf,
}

impl EvidenceCopy {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "cantor-b1-permission-profile-{}-{}",
            std::process::id(),
            NEXT_COPY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        for name in [
            "experimental_schema.json",
            "manifest.json",
            "observation.json",
            "standard_schema.json",
        ] {
            fs::copy(evidence_root().join(name), root.join(name)).unwrap();
        }
        Self { root }
    }

    fn path(&self) -> &Path {
        &self.root
    }

    fn mutate_json(&self, name: &str, mutate: impl FnOnce(&mut Value)) {
        let path = self.root.join(name);
        let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        mutate(&mut value);
        fs::write(
            path,
            format!("{}\n", serde_json::to_string(&value).unwrap()),
        )
        .unwrap();
    }

    fn mutate_artifact_json(&self, name: &str, mutate: impl FnOnce(&mut Value)) {
        self.mutate_json(name, mutate);
        self.rehash_artifact(name);
    }

    fn replace_raw(&self, name: &str, from: &str, to: &str) {
        let path = self.root.join(name);
        let raw = fs::read_to_string(&path).unwrap();
        assert!(raw.contains(from));
        fs::write(path, raw.replacen(from, to, 1)).unwrap();
    }

    fn replace_raw_and_rehash(&self, name: &str, from: &str, to: &str) {
        self.replace_raw(name, from, to);
        self.rehash_artifact(name);
    }

    fn rehash_artifact(&self, name: &str) {
        let path = self.root.join(name);
        let bytes = fs::read(&path).unwrap();
        let digest = sha256_upper(&bytes);
        self.mutate_json("manifest.json", |value| {
            let artifact = value["artifacts"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|artifact| artifact["path"] == name)
                .unwrap();
            artifact["bytes"] = Value::from(bytes.len() as u64);
            artifact["sha256"] = Value::from(digest);
        });
    }
}

impl Drop for EvidenceCopy {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

fn evidence_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(
        "../../experiments/self_work_update_broker_b1_permission_profile_revalidation_p0/artifacts",
    )
}

fn assert_fault(path: &Path, expected: B1PermissionProfileFaultCode) {
    let error = verify_b1_permission_profile_evidence(path).expect_err("mutation must refuse");
    assert_eq!(error.code, expected, "{error}");
}

fn sha256_upper(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect()
}

fn replace_string(value: &mut Value, from: &str, to: &str) {
    match value {
        Value::String(value) if value == from => *value = to.to_owned(),
        Value::Array(values) => {
            for value in values {
                replace_string(value, from, to);
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                replace_string(value, from, to);
            }
        }
        _ => {}
    }
}
