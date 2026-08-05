#![cfg(feature = "json-schema")]

use cantor_procedure_tool::{
    DefinitionRecursionClass, MachineSchemaGenerationContext, MachineSchemaGenerationFaultKind,
    MachineSchemaRootKind, SchemaContractDirection, SchemaGenerationLimits, SchemaResourceAccount,
    generate_contract_definition_universe, generate_public_procedure_schema_universes,
};

fn context() -> MachineSchemaGenerationContext {
    MachineSchemaGenerationContext {
        supplied_source_revision: "0123456789abcdef0123456789abcdef01234567".to_owned(),
        limits: SchemaGenerationLimits::default(),
    }
}

#[test]
fn both_direction_universes_are_deterministic_closed_and_distinct() {
    let first = generate_public_procedure_schema_universes(&context()).expect("generation passes");
    let second = generate_public_procedure_schema_universes(&context()).expect("repeat passes");
    assert_eq!(first, second);
    assert_eq!(first.len(), 2);

    let input = &first[&SchemaContractDirection::InputDeserialize];
    let output = &first[&SchemaContractDirection::OutputSerialize];
    assert_eq!(
        input.resources,
        SchemaResourceAccount {
            canonical_bytes: 53_936,
            definitions: 80,
            reference_occurrences: 406,
            maximum_document_depth: 8,
            object_properties: 571,
            alternatives: 250,
            semantic_residuals: 6,
        }
    );
    assert_eq!(
        output.resources,
        SchemaResourceAccount {
            canonical_bytes: 53_846,
            definitions: 83,
            reference_occurrences: 398,
            maximum_document_depth: 8,
            object_properties: 567,
            alternatives: 271,
            semantic_residuals: 6,
        }
    );
    assert_eq!(input.roots.len(), 3);
    assert_eq!(output.roots.len(), 2);
    assert!(
        input
            .roots
            .contains_key(&MachineSchemaRootKind::PrepareInput)
    );
    assert!(input.roots.contains_key(&MachineSchemaRootKind::RunInput));
    assert!(
        input
            .roots
            .contains_key(&MachineSchemaRootKind::VerifyInput)
    );
    assert!(
        output
            .roots
            .contains_key(&MachineSchemaRootKind::BaseResponse)
    );
    assert!(
        output
            .roots
            .contains_key(&MachineSchemaRootKind::PreparationResponse)
    );
    assert_ne!(input.universe_fingerprint, output.universe_fingerprint);

    assert_eq!(
        input.roots[&MachineSchemaRootKind::PrepareInput]
            .resources
            .canonical_bytes,
        16_955
    );
    assert_eq!(
        input.roots[&MachineSchemaRootKind::RunInput]
            .resources
            .canonical_bytes,
        47_285
    );
    assert_eq!(
        input.roots[&MachineSchemaRootKind::VerifyInput]
            .resources
            .canonical_bytes,
        51_098
    );
    assert_eq!(
        output.roots[&MachineSchemaRootKind::BaseResponse]
            .resources
            .canonical_bytes,
        52_936
    );
    assert_eq!(
        output.roots[&MachineSchemaRootKind::PreparationResponse]
            .resources
            .canonical_bytes,
        52_936
    );

    for universe in [input, output] {
        assert!(universe.resources.definitions <= universe.limits.maximum_definitions);
        assert!(
            universe.resources.reference_occurrences
                <= universe.limits.maximum_reference_occurrences
        );
        for account in universe.definition_accounts.values() {
            for target in &account.direct_local_reference_targets {
                assert!(universe.definitions.contains_key(target));
            }
        }
    }
}

#[test]
fn recursive_accounts_and_crossing_root_identities_are_explicit() {
    let universes =
        generate_public_procedure_schema_universes(&context()).expect("generation passes");
    let input = &universes[&SchemaContractDirection::InputDeserialize];
    assert_eq!(
        input.definition_accounts["ProcedureType"].recursion_class,
        DefinitionRecursionClass::DirectSelf
    );
    assert_eq!(
        input.definition_accounts["ProcedureValue"].recursion_class,
        DefinitionRecursionClass::DirectSelf
    );

    let output = &universes[&SchemaContractDirection::OutputSerialize];
    let base = &output.roots[&MachineSchemaRootKind::BaseResponse];
    let preparation = &output.roots[&MachineSchemaRootKind::PreparationResponse];
    assert_eq!(base.raw_content_digest, preparation.raw_content_digest);
    assert_ne!(base.root_fingerprint, preparation.root_fingerprint);
    assert_ne!(base.schema_id, preparation.schema_id);

    let run = &input.roots[&MachineSchemaRootKind::RunInput];
    assert_eq!(run.type_name, "PreparedRunRequest");
    assert!(run.definition_closure.contains("ProviderNeutralToolSchema"));
    assert!(run.definition_closure.contains("AuthorshipLaneEvidence"));
}

#[test]
fn source_revision_and_lowered_limits_fail_closed() {
    let mut invalid_revision = context();
    invalid_revision.supplied_source_revision = "ABC".to_owned();
    assert_eq!(
        generate_public_procedure_schema_universes(&invalid_revision)
            .expect_err("invalid revision must fail")
            .kind,
        MachineSchemaGenerationFaultKind::InvalidSourceRevision
    );

    let mut over_profile = context();
    over_profile.limits.maximum_definitions += 1;
    assert_eq!(
        generate_public_procedure_schema_universes(&over_profile)
            .expect_err("raised profile must fail")
            .kind,
        MachineSchemaGenerationFaultKind::InvalidLimit
    );

    let mut exhausted = context();
    exhausted.limits.maximum_definitions = 1;
    let fault = generate_contract_definition_universe(
        SchemaContractDirection::InputDeserialize,
        &exhausted,
    )
    .expect_err("definition exhaustion must fail");
    assert_eq!(fault.kind, MachineSchemaGenerationFaultKind::LimitExceeded);
    assert_eq!(fault.limit, Some(1));
    assert!(fault.observed.is_some_and(|observed| observed > 1));
}

#[test]
fn every_active_resource_axis_fails_at_one_below_observed() {
    let cases = [
        SchemaGenerationLimits {
            maximum_canonical_document_bytes: 1,
            ..SchemaGenerationLimits::default()
        },
        SchemaGenerationLimits {
            maximum_canonical_bundle_bytes: 53_935,
            ..SchemaGenerationLimits::default()
        },
        SchemaGenerationLimits {
            maximum_definitions: 79,
            ..SchemaGenerationLimits::default()
        },
        SchemaGenerationLimits {
            maximum_reference_occurrences: 405,
            ..SchemaGenerationLimits::default()
        },
        SchemaGenerationLimits {
            maximum_document_depth: 7,
            ..SchemaGenerationLimits::default()
        },
        SchemaGenerationLimits {
            maximum_object_properties: 570,
            ..SchemaGenerationLimits::default()
        },
        SchemaGenerationLimits {
            maximum_alternatives: 249,
            ..SchemaGenerationLimits::default()
        },
        SchemaGenerationLimits {
            maximum_semantic_residuals: 5,
            ..SchemaGenerationLimits::default()
        },
    ];

    for limits in cases {
        let fault = generate_contract_definition_universe(
            SchemaContractDirection::InputDeserialize,
            &MachineSchemaGenerationContext {
                supplied_source_revision: context().supplied_source_revision,
                limits,
            },
        )
        .expect_err("one-below-observed limit must fail");
        assert_eq!(fault.kind, MachineSchemaGenerationFaultKind::LimitExceeded);
    }
}
