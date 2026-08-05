#![cfg(feature = "json-schema")]

use std::collections::BTreeSet;
use std::path::PathBuf;

use cantor_core::sha256_bytes;
use cantor_procedure_tool::{
    ExactSchemaBundleReplay, MachineSchemaGenerationContext, MachineSchemaRootKind,
    SchemaContractDirection, SchemaDocumentFormationFaultKind, SchemaGenerationLimits,
    canonical_machine_schema_artifacts, generate_public_procedure_schema_bundle,
    generate_public_procedure_schema_universes, materialize_public_procedure_schema_bundle,
    verify_exact_schema_bundle_replay,
};

const TEST_REVISION: &str = "0123456789abcdef0123456789abcdef01234567";
const GOLDEN_SOURCE_REVISION: &str = "aba99b1431727578679fa0b784ea8261cfd456fb";
const UPDATE_FLAG: &str = "CANTOR_UPDATE_MACHINE_SCHEMA_GOLDENS";
const REVISION_FLAG: &str = "CANTOR_MACHINE_SCHEMA_SOURCE_REVISION";
const DESTINATION_FLAG: &str = "CANTOR_MACHINE_SCHEMA_GOLDEN_DIR";

fn context() -> MachineSchemaGenerationContext {
    MachineSchemaGenerationContext {
        supplied_source_revision: TEST_REVISION.to_owned(),
        limits: SchemaGenerationLimits::default(),
    }
}

#[test]
fn five_documents_are_local_closed_unique_and_deterministic() {
    let universes = generate_public_procedure_schema_universes(&context()).expect("universes");
    let first = materialize_public_procedure_schema_bundle(&universes).expect("bundle");
    let second = materialize_public_procedure_schema_bundle(&universes).expect("repeat");
    assert_eq!(first, second);
    assert_eq!(first.payload.documents.len(), 5);
    assert_eq!(first.payload.direction_inventories.len(), 2);

    let mut ids = BTreeSet::new();
    for document in first.payload.documents.values() {
        assert!(ids.insert(document.schema_id.clone()));
        let object = document.schema.as_object().expect("schema object");
        assert_eq!(
            object["$schema"].as_str(),
            Some("https://json-schema.org/draft/2020-12/schema")
        );
        assert_eq!(object["$id"].as_str(), Some(document.schema_id.as_str()));
        assert!(
            object["$defs"]
                .as_object()
                .is_some_and(|defs| !defs.is_empty())
        );
        assert!(document.canonical_byte_length > 0);
        assert_eq!(
            document.resources.canonical_bytes,
            document.canonical_byte_length
        );
    }

    assert_eq!(
        first.payload.documents[&MachineSchemaRootKind::PrepareInput].direction,
        SchemaContractDirection::InputDeserialize
    );
    assert_eq!(
        first.payload.documents[&MachineSchemaRootKind::BaseResponse].direction,
        SchemaContractDirection::OutputSerialize
    );
}

#[test]
fn intended_use_ids_separate_equal_raw_response_roots() {
    let universes = generate_public_procedure_schema_universes(&context()).expect("universes");
    let output = &universes[&SchemaContractDirection::OutputSerialize];
    let raw_base = &output.roots[&MachineSchemaRootKind::BaseResponse];
    let raw_preparation = &output.roots[&MachineSchemaRootKind::PreparationResponse];
    assert_eq!(
        raw_base.raw_content_digest,
        raw_preparation.raw_content_digest
    );

    let bundle = materialize_public_procedure_schema_bundle(&universes).expect("bundle");
    let base = &bundle.payload.documents[&MachineSchemaRootKind::BaseResponse];
    let preparation = &bundle.payload.documents[&MachineSchemaRootKind::PreparationResponse];
    assert_ne!(base.schema_id, preparation.schema_id);
    assert_ne!(base.document_digest, preparation.document_digest);
    assert_ne!(base.document_fingerprint, preparation.document_fingerprint);
}

#[test]
fn bundle_artifacts_and_exact_replay_are_closed() {
    let bundle = generate_public_procedure_schema_bundle(&context()).expect("bundle");
    let artifacts = canonical_machine_schema_artifacts(&bundle).expect("artifacts");
    assert_eq!(artifacts.len(), 6);
    assert_eq!(
        artifacts.keys().cloned().collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "input_deserialize.prepare_input.schema.json".to_owned(),
            "input_deserialize.run_input.schema.json".to_owned(),
            "input_deserialize.verify_input.schema.json".to_owned(),
            "output_serialize.base_response.schema.json".to_owned(),
            "output_serialize.preparation_response.schema.json".to_owned(),
            "public_procedure_machine_schema.bundle.json".to_owned(),
        ])
    );
    assert_eq!(
        verify_exact_schema_bundle_replay(&bundle.exact_baseline_fingerprint, &bundle)
            .expect("exact replay"),
        ExactSchemaBundleReplay::Identical
    );

    let unrelated = sha256_bytes(b"not-the-baseline");
    let fault = verify_exact_schema_bundle_replay(&unrelated, &bundle)
        .expect_err("different baseline must remain unclassified");
    assert_eq!(
        fault.kind,
        SchemaDocumentFormationFaultKind::BaselineMismatch
    );
    assert_eq!(fault.expected_digest, Some(Box::new(unrelated)));
}

#[test]
fn missing_tampered_and_exhausted_inputs_fail_without_artifacts() {
    let mut universes = generate_public_procedure_schema_universes(&context()).expect("universes");
    universes.remove(&SchemaContractDirection::OutputSerialize);
    assert_eq!(
        materialize_public_procedure_schema_bundle(&universes)
            .expect_err("missing direction")
            .kind,
        SchemaDocumentFormationFaultKind::InvalidUniversePair
    );

    let mut bundle = generate_public_procedure_schema_bundle(&context()).expect("bundle");
    bundle
        .payload
        .documents
        .get_mut(&MachineSchemaRootKind::PrepareInput)
        .expect("prepare document")
        .schema["title"] = serde_json::Value::String("tampered".to_owned());
    assert_eq!(
        canonical_machine_schema_artifacts(&bundle)
            .expect_err("tampered document")
            .kind,
        SchemaDocumentFormationFaultKind::DigestMismatch
    );

    let observed = generate_public_procedure_schema_bundle(&context())
        .expect("measured bundle")
        .payload
        .documents[&MachineSchemaRootKind::PrepareInput]
        .canonical_byte_length;
    let mut limited = context();
    limited.limits.maximum_canonical_document_bytes = observed - 1;
    assert_eq!(
        generate_public_procedure_schema_bundle(&limited)
            .expect_err("one-below document limit")
            .kind,
        SchemaDocumentFormationFaultKind::LimitExceeded
    );
}

#[test]
fn checked_in_goldens_equal_the_pure_artifact_projection() {
    let bundle = generate_public_procedure_schema_bundle(&MachineSchemaGenerationContext {
        supplied_source_revision: GOLDEN_SOURCE_REVISION.to_owned(),
        limits: SchemaGenerationLimits::default(),
    })
    .expect("bundle");
    let expected = canonical_machine_schema_artifacts(&bundle).expect("artifacts");
    let directory = golden_directory();
    for (name, bytes) in expected {
        assert_eq!(
            std::fs::read(directory.join(name)).expect("checked-in golden must exist"),
            bytes
        );
    }
}

#[test]
#[ignore = "explicit checkpoint B developer action; never run in normal tests"]
fn update_machine_schema_goldens_only_when_explicitly_authorized() {
    assert_eq!(
        std::env::var(UPDATE_FLAG).as_deref(),
        Ok("1"),
        "explicit golden update opt-in is required"
    );
    let revision = std::env::var(REVISION_FLAG).expect("checkpoint A revision is required");
    assert!(
        matches!(revision.len(), 40 | 64)
            && revision
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "revision must be full lowercase Git object text"
    );
    let destination = PathBuf::from(
        std::env::var(DESTINATION_FLAG).expect("explicit golden destination is required"),
    );
    let expected_destination = golden_directory();
    assert_eq!(
        destination, expected_destination,
        "writer destination must be the exact repository-local golden directory"
    );

    let bundle = generate_public_procedure_schema_bundle(&MachineSchemaGenerationContext {
        supplied_source_revision: revision,
        limits: SchemaGenerationLimits::default(),
    })
    .expect("bundle");
    let artifacts = canonical_machine_schema_artifacts(&bundle).expect("artifacts");
    std::fs::create_dir_all(&destination).expect("golden directory");
    for (name, bytes) in artifacts {
        let path = destination.join(name);
        if path.exists() {
            assert_eq!(
                std::fs::read(&path).expect("existing golden"),
                bytes,
                "refuse to overwrite an unequal existing golden"
            );
        } else {
            std::fs::write(path, bytes).expect("explicit golden write");
        }
    }
}

fn golden_directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("goldens")
        .join("machine_schema")
}
