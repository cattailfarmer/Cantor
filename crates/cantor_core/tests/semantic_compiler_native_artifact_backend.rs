use std::collections::{BTreeMap, BTreeSet};

use cantor_core::*;

fn id(value: &str) -> SemanticId {
    SemanticId::new(value).expect("fixture identity")
}

fn digest(byte: char) -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: byte.to_string().repeat(64),
    }
}

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: String::new(),
    }
}

fn ir() -> TypedSopIr {
    fn address(name: &str, kind: UnitKind, byte: char) -> SemanticAddress {
        let package_id = id("package:native");
        let unit_id = id(&format!("unit:{name}"));
        SemanticAddress {
            unit_id: unit_id.clone(),
            unit_digest: digest(byte),
            package_id: package_id.clone(),
            package_digest: digest('2'),
            kind,
            context_id: id("context:native"),
            version: "0.1.0".to_owned(),
            source_anchors: vec![SourceAnchor {
                package_id,
                file_id: id("file:native"),
                unit_id,
                clause_id: id(&format!("clause:{name}")),
                byte_start: 1,
                byte_end: 10,
                span_digest: digest('3'),
                display_line_start: 1,
                display_line_end: 1,
            }],
        }
    }
    let type_id = id("node:native-type");
    let input_id = id("node:native-input");
    let output_id = id("node:native-output");
    let nodes = BTreeMap::from([
        (
            type_id.clone(),
            SemanticIrNode {
                node_id: type_id.clone(),
                kind: SemanticIrNodeKind::Type,
                semantic_address: address("native-type", UnitKind::Term, '1'),
                type_ref: None,
                dependency_refs: BTreeSet::new(),
                generated_derivation_refs: BTreeSet::new(),
            },
        ),
        (
            input_id.clone(),
            SemanticIrNode {
                node_id: input_id.clone(),
                kind: SemanticIrNodeKind::Input,
                semantic_address: address("native-input", UnitKind::Declaration, '4'),
                type_ref: Some(type_id.clone()),
                dependency_refs: BTreeSet::from([type_id.clone()]),
                generated_derivation_refs: BTreeSet::new(),
            },
        ),
        (
            output_id.clone(),
            SemanticIrNode {
                node_id: output_id,
                kind: SemanticIrNodeKind::Output,
                semantic_address: address("native-output", UnitKind::Declaration, '5'),
                type_ref: Some(type_id),
                dependency_refs: BTreeSet::from([input_id]),
                generated_derivation_refs: BTreeSet::new(),
            },
        ),
    ]);
    let source_map = nodes
        .iter()
        .map(|(node_id, node)| {
            (
                node_id.clone(),
                CompilerSourceMapEntry {
                    node_ref: node_id.clone(),
                    semantic_address: node.semantic_address.clone(),
                    derivation_refs: BTreeSet::new(),
                },
            )
        })
        .collect();
    let mut value = TypedSopIr {
        profile: TYPED_SOP_IR_PROFILE.to_owned(),
        ir_id: id("ir:native"),
        source_manifest_digest: digest('4'),
        canonical_specification_ref: id("spec:seeded-compiler"),
        canonical_specification_digest: digest('5'),
        nodes,
        source_map,
        unresolved_account: BTreeSet::new(),
        non_authority: COMPILER_NON_AUTHORITY.to_owned(),
        ir_digest: empty_digest(),
    };
    value.ir_digest = typed_sop_ir_digest(&value).expect("IR digest");
    value
}

fn seed() -> SopSeed {
    let mut ceiling = CompilerCapabilityCeiling {
        profile: COMPILER_CAPABILITY_CEILING_PROFILE.to_owned(),
        ceiling_id: id("ceiling:native"),
        capabilities: BTreeSet::from([
            CompilerCapability::SemanticRead,
            CompilerCapability::SourceRead,
            CompilerCapability::Build,
        ]),
        resource_scopes: BTreeSet::from(["fixture-only".to_owned()]),
        maximum_artifacts: 1,
        maximum_serialized_bytes: 1_048_576,
        ceiling_digest: empty_digest(),
    };
    ceiling.ceiling_digest = compiler_capability_ceiling_digest(&ceiling).expect("ceiling digest");
    let mut value = SopSeed {
        profile: SOP_SEED_PROFILE.to_owned(),
        seed_id: id("seed:native"),
        generation_id: id("generation:native:r1"),
        purpose: "project one native CLI artifact candidate".to_owned(),
        honesty_trust_root_ref: id("trust:honesty"),
        security_trust_root_ref: id("trust:security"),
        authority_trust_root_ref: id("trust:authority"),
        compiler_trust_root_ref: id("trust:compiler"),
        dependency_roots: BTreeMap::from([(id("dependency:sop-core"), digest('6'))]),
        discovery_contract_ref: id("contract:seed-discovery"),
        semantic_frontend_profile: "cantor-semantic-frontend/0.1".to_owned(),
        backend_profiles: BTreeMap::from([
            (
                CompilerBackendKind::AttentionProcedure,
                "cantor-attention-procedure-backend/0.1".to_owned(),
            ),
            (
                CompilerBackendKind::InferenceHostIntegration,
                "cantor-inference-host-backend/0.1".to_owned(),
            ),
            (
                CompilerBackendKind::NativeArtifact,
                "cantor-native-artifact-backend/0.1".to_owned(),
            ),
        ]),
        capability_ceiling: ceiling,
        predecessor_generation_ref: Some(id("generation:native:r0")),
        successor_policy_ref: id("policy:external-successor-recognition"),
        seed_digest: empty_digest(),
    };
    value.seed_digest = sop_seed_digest(&value).expect("seed digest");
    value
}

fn plan() -> CandidateCompilationPlan {
    let seed = seed();
    let ir = ir();
    let mut value = CandidateCompilationPlan {
        profile: CANDIDATE_COMPILATION_PLAN_PROFILE.to_owned(),
        plan_id: id("plan:native"),
        seed_ref: seed.seed_id.clone(),
        seed_digest: seed.seed_digest,
        ir_ref: ir.ir_id.clone(),
        ir_digest: ir.ir_digest,
        backend: CompilerBackendKind::NativeArtifact,
        backend_profile: seed.backend_profiles[&CompilerBackendKind::NativeArtifact].clone(),
        purpose: seed.purpose,
        requested_capabilities: BTreeSet::from([
            CompilerCapability::SemanticRead,
            CompilerCapability::SourceRead,
        ]),
        input_refs: BTreeSet::from([id("node:native-input")]),
        expected_output_refs: BTreeSet::from([id("node:native-output")]),
        verifier_refs: BTreeSet::from([id("verifier:native")]),
        rollback_ref: id("rollback:native"),
        unresolved_account: BTreeSet::new(),
        non_authority: COMPILER_NON_AUTHORITY.to_owned(),
        plan_digest: empty_digest(),
    };
    value.plan_digest = candidate_compilation_plan_digest(&value).expect("plan digest");
    value
}

fn request() -> NativeArtifactBackendRequest {
    let ir = ir();
    let plan = plan();
    let source_id = id("source:cantor-cli-main");
    NativeArtifactBackendRequest {
        profile: NATIVE_ARTIFACT_BACKEND_REQUEST_PROFILE.to_owned(),
        request_id: id("request:native"),
        candidate_id: id("candidate:native"),
        plan_ref: plan.plan_id,
        plan_digest: plan.plan_digest,
        ir_ref: ir.ir_id,
        ir_digest: ir.ir_digest,
        purpose: plan.purpose,
        artifact_kind: NativeArtifactKind::CliExecutable,
        source_inputs: BTreeMap::from([(
            source_id.clone(),
            NativeSourceInputPin {
                source_id,
                relative_path: "crates/cantor_cli/src/main.rs".to_owned(),
                source_digest: digest('7'),
                provenance: SourceInputProvenance::SelectedExisting,
                semantic_node_refs: ir.nodes.keys().cloned().collect(),
            },
        )]),
        toolchain: NativeToolchainPin {
            language: NativeLanguage::Rust,
            edition: "2024".to_owned(),
            channel: "stable".to_owned(),
            compiler_version: "rustc fixture".to_owned(),
            cargo_version: "cargo fixture".to_owned(),
            target_triple: "x86_64-unknown-linux-gnu".to_owned(),
            compiler_digest: digest('8'),
            cargo_digest: digest('9'),
            linker_digest: digest('a'),
            configuration_digest: digest('b'),
        },
        interface: NativeInterfaceBinding {
            interface_profile: "cantor-cli-jsonl/0.1".to_owned(),
            input_schema_digest: digest('c'),
            output_schema_digest: digest('d'),
        },
        build: NativeBuildContract {
            build_profile: CARGO_LOCKED_OFFLINE_BUILD_PROFILE.to_owned(),
            command_schema: vec![
                "cargo".to_owned(),
                "build".to_owned(),
                "--locked".to_owned(),
                "--offline".to_owned(),
                "--release".to_owned(),
                "--package".to_owned(),
                "cantor_cli".to_owned(),
                "--bin".to_owned(),
                "cantor".to_owned(),
            ],
            environment_policy: SANITIZED_BUILD_ENVIRONMENT_POLICY.to_owned(),
            workspace_manifest_digest: digest('e'),
            package_manifest_digest: digest('f'),
            dependency_lock_digest: digest('0'),
            dependency_policy: DependencyPolicy::LockedOffline,
            package_name: "cantor_cli".to_owned(),
            binary_name: "cantor".to_owned(),
            cargo_profile: "release".to_owned(),
            features: BTreeSet::new(),
            expected_output_id: id("artifact:cantor-cli"),
            expected_output_relative_path: "target/release/cantor".to_owned(),
            maximum_seconds: 600,
            maximum_processes: 8,
            maximum_memory_bytes: 2_147_483_648,
            maximum_output_bytes: 134_217_728,
            maximum_artifacts: 1,
            expected_receipt_refs: BTreeSet::from([id("receipt:native-build")]),
            verifier_refs: plan.verifier_refs,
            cleanup_ref: id("cleanup:native"),
        },
        runtime_requirements: BTreeSet::from([
            NativeRuntimeRequirement::StandardInput,
            NativeRuntimeRequirement::StandardOutput,
            NativeRuntimeRequirement::AdmittedEnvironmentRead,
        ]),
        rollback_ref: plan.rollback_ref,
        unresolved_account: BTreeSet::from([
            "post-build artifact digest is intentionally absent".to_owned()
        ]),
        non_authority: COMPILER_NON_AUTHORITY.to_owned(),
    }
}

#[test]
fn native_candidate_is_deterministic_strict_and_has_no_artifact_receipt() {
    let seed = seed();
    let ir = ir();
    let plan = plan();
    let request = request();
    let first =
        project_native_artifact_backend(&seed, &ir, &plan, &request).expect("first projection");
    let second =
        project_native_artifact_backend(&seed, &ir, &plan, &request).expect("second projection");
    assert_eq!(first, second);
    assert_eq!(
        first.candidate.lifecycle,
        NativeCandidateLifecycle::Proposed
    );
    assert_eq!(first.candidate.build.maximum_artifacts, 1);
    validate_native_artifact_backend_projection(&seed, &ir, &plan, &request, &first)
        .expect("projection validates");
    let json = serde_json::to_string(&first).expect("projection JSON");
    assert!(!json.contains("artifact_digest"));

    let mut unknown = serde_json::to_value(&request).expect("request JSON");
    unknown["invented_execution_authority"] = serde_json::json!(true);
    assert!(serde_json::from_value::<NativeArtifactBackendRequest>(unknown).is_err());
}

#[test]
fn generated_source_path_escape_and_build_capability_refuse() {
    let seed = seed();
    let ir = ir();
    let plan = plan();

    let mut generated = request();
    generated
        .source_inputs
        .values_mut()
        .next()
        .unwrap()
        .provenance = SourceInputProvenance::GeneratedCandidate;
    assert_eq!(
        project_native_artifact_backend(&seed, &ir, &plan, &generated)
            .expect_err("generated source refuses")
            .kind,
        SemanticCompilerFormFaultKind::InvalidReference
    );

    let mut escaped = request();
    escaped
        .source_inputs
        .values_mut()
        .next()
        .unwrap()
        .relative_path = "../outside.rs".to_owned();
    assert_eq!(
        project_native_artifact_backend(&seed, &ir, &plan, &escaped)
            .expect_err("path escape refuses")
            .kind,
        SemanticCompilerFormFaultKind::InvalidReference
    );

    let mut elevated_plan = plan.clone();
    elevated_plan
        .requested_capabilities
        .insert(CompilerCapability::Build);
    elevated_plan.plan_digest =
        candidate_compilation_plan_digest(&elevated_plan).expect("reseal plan");
    let mut elevated_request = request();
    elevated_request.plan_digest = elevated_plan.plan_digest.clone();
    assert_eq!(
        project_native_artifact_backend(&seed, &ir, &elevated_plan, &elevated_request)
            .expect_err("build capability refuses")
            .kind,
        SemanticCompilerFormFaultKind::CapabilityExceeded
    );
}

#[test]
fn incomplete_coverage_unbounded_build_and_substitution_refuse() {
    let seed = seed();
    let ir = ir();
    let plan = plan();

    let mut incomplete = request();
    incomplete
        .source_inputs
        .values_mut()
        .next()
        .unwrap()
        .semantic_node_refs
        .clear();
    assert_eq!(
        project_native_artifact_backend(&seed, &ir, &plan, &incomplete)
            .expect_err("incomplete source coverage refuses")
            .kind,
        SemanticCompilerFormFaultKind::InvalidReference
    );

    let mut unbounded = request();
    unbounded.build.maximum_artifacts = 2;
    assert_eq!(
        project_native_artifact_backend(&seed, &ir, &plan, &unbounded)
            .expect_err("multiple artifacts refuse")
            .kind,
        SemanticCompilerFormFaultKind::InvalidBound
    );

    let mut substituted_command = request();
    substituted_command
        .build
        .command_schema
        .push("--frozen".to_owned());
    assert_eq!(
        project_native_artifact_backend(&seed, &ir, &plan, &substituted_command)
            .expect_err("command substitution refuses")
            .kind,
        SemanticCompilerFormFaultKind::InvalidBound
    );

    let request = request();
    let mut projection =
        project_native_artifact_backend(&seed, &ir, &plan, &request).expect("projection");
    projection.candidate.build.expected_output_relative_path =
        "target/release/substituted".to_owned();
    projection.projection_digest =
        native_artifact_backend_projection_digest(&projection).expect("reseal outer digest");
    assert_eq!(
        validate_native_artifact_backend_projection(&seed, &ir, &plan, &request, &projection)
            .expect_err("resealed substitution refuses")
            .kind,
        SemanticCompilerFormFaultKind::InvalidReference
    );
}
