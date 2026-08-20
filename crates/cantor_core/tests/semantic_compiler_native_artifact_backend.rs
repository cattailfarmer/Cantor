use std::collections::{BTreeMap, BTreeSet};

use cantor_core::*;
use ed25519_dalek::{Signer, SigningKey};

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
            CompilerCapability::FileWrite,
            CompilerCapability::ProcessExecute,
        ]),
        resource_scopes: BTreeSet::from(["root:native-fixture".to_owned()]),
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

struct AuthorizationFixture {
    seed: SopSeed,
    ir: TypedSopIr,
    candidate_plan: CandidateCompilationPlan,
    candidate_request: NativeArtifactBackendRequest,
    projection: NativeArtifactBackendProjection,
    build_plan: NativeBuildExecutionPlan,
    capability: NativeBuildCapabilityReceipt,
    sandbox: NativeSandboxAdmission,
    statement: NativeBuildApprovalStatement,
    trust_store: NativeBuildTrustStore,
    security_key: SigningKey,
    authority_key: SigningKey,
}

fn authorization_fixture() -> AuthorizationFixture {
    let seed = seed();
    let ir = ir();
    let candidate_plan = plan();
    let candidate_request = request();
    let projection =
        project_native_artifact_backend(&seed, &ir, &candidate_plan, &candidate_request)
            .expect("candidate projection");
    let lineage = NativeArtifactBuildLineage {
        seed: &seed,
        ir: &ir,
        candidate_plan: &candidate_plan,
        candidate_request: &candidate_request,
        projection: &projection,
    };
    let runner = NativeBuildRunnerPin {
        runner_id: id("runner:native-fixture"),
        adapter_profile: "cantor-fake-native-runner/0.1".to_owned(),
        executable_digest: digest('1'),
        configuration_digest: digest('2'),
    };
    let root_policy = NativeBuildRootPolicy {
        disposable_root_id: id("root:native-fixture"),
        disposable_root_relative_path: ".cantor-build/native-fixture".to_owned(),
        expected_artifact_relative_path: "target/release/cantor".to_owned(),
        disposable_root_create_new: true,
        artifact_create_new: true,
        denied_write_classes: BTreeSet::from([
            NativeDeniedWriteClass::OutsideDisposableRoot,
            NativeDeniedWriteClass::Repository,
            NativeDeniedWriteClass::SealRoot,
            NativeDeniedWriteClass::Credential,
        ]),
    };
    let build_plan = project_native_build_execution_plan(
        &lineage,
        id("build-plan:native-fixture"),
        runner,
        "fixture-physical-sandbox/0.1".to_owned(),
        root_policy.clone(),
        100,
        200,
    )
    .expect("build plan");
    let capability = project_native_build_capability_receipt(
        &lineage,
        &build_plan,
        id("build-capability:native-fixture"),
        build_plan.requested_capabilities.clone(),
        BTreeSet::from(["root:native-fixture".to_owned()]),
        BTreeSet::from([id("evidence:capability")]),
    )
    .expect("build capability");
    let mut sandbox = NativeSandboxAdmission {
        profile: NATIVE_SANDBOX_ADMISSION_PROFILE.to_owned(),
        admission_id: id("sandbox:native-fixture"),
        provider_id: id("sandbox-provider:fixture"),
        platform_profile: "fixture-platform/0.1".to_owned(),
        sandbox_profile: build_plan.sandbox_profile.clone(),
        root_policy,
        containment: NativeSandboxContainment::ProvenForProfile,
        network_denied: true,
        repository_writes_denied: true,
        seal_root_writes_denied: true,
        credential_access_denied: true,
        runner_executable_digest: build_plan.runner.executable_digest.clone(),
        environment_digest: build_plan.environment_digest.clone(),
        logical_valid_from: 90,
        logical_valid_until: 210,
        evidence_refs: BTreeSet::from([id("evidence:sandbox-denial-matrix")]),
        disposition: NativeSandboxDisposition::Admitted,
        non_authority: NATIVE_BUILD_PLAN_NON_AUTHORITY.to_owned(),
        admission_digest: empty_digest(),
    };
    sandbox.admission_digest = native_sandbox_admission_digest(&sandbox).expect("sandbox digest");
    let statement = project_native_build_approval_statement(
        &lineage,
        &build_plan,
        &capability,
        &sandbox,
        id("approval:native-fixture"),
    )
    .expect("approval statement");
    let security_key = SigningKey::from_bytes(&[7; 32]);
    let authority_key = SigningKey::from_bytes(&[9; 32]);
    let mut trust_store = NativeBuildTrustStore {
        profile: NATIVE_BUILD_TRUST_STORE_PROFILE.to_owned(),
        store_id: id("trust-store:native-fixture"),
        security_verifying_keys: BTreeMap::from([(
            seed.security_trust_root_ref.clone(),
            security_key.verifying_key().to_bytes().to_vec(),
        )]),
        authority_verifying_keys: BTreeMap::from([(
            seed.authority_trust_root_ref.clone(),
            authority_key.verifying_key().to_bytes().to_vec(),
        )]),
        revoked_approval_ids: BTreeSet::new(),
        revoked_certificate_ids: BTreeSet::new(),
        store_digest: empty_digest(),
    };
    trust_store.store_digest =
        native_build_trust_store_digest(&trust_store).expect("trust store digest");
    AuthorizationFixture {
        seed,
        ir,
        candidate_plan,
        candidate_request,
        projection,
        build_plan,
        capability,
        sandbox,
        statement,
        trust_store,
        security_key,
        authority_key,
    }
}

fn issue_authorization(fixture: &AuthorizationFixture) -> NativeBuildAuthorizationCertificate {
    let lineage = NativeArtifactBuildLineage {
        seed: &fixture.seed,
        ir: &fixture.ir,
        candidate_plan: &fixture.candidate_plan,
        candidate_request: &fixture.candidate_request,
        projection: &fixture.projection,
    };
    let payload = native_build_approval_signing_bytes(&fixture.statement).expect("signing payload");
    issue_native_build_authorization_certificate(
        &lineage,
        &fixture.build_plan,
        &fixture.capability,
        &fixture.sandbox,
        fixture.statement.clone(),
        &fixture.trust_store,
        id("authorization:native-fixture"),
        fixture.security_key.sign(&payload).to_bytes().to_vec(),
        fixture.authority_key.sign(&payload).to_bytes().to_vec(),
        150,
    )
    .expect("authorization certificate")
}

fn successful_observation(
    fixture: &AuthorizationFixture,
    authorization: &NativeBuildAuthorizationCertificate,
) -> NativeBuildObservation {
    let lineage = NativeArtifactBuildLineage {
        seed: &fixture.seed,
        ir: &fixture.ir,
        candidate_plan: &fixture.candidate_plan,
        candidate_request: &fixture.candidate_request,
        projection: &fixture.projection,
    };
    let candidate = &fixture.projection.candidate;
    let artifact = NativeObservedArtifact {
        artifact_id: candidate.build.expected_output_id.clone(),
        relative_path: candidate.build.expected_output_relative_path.clone(),
        artifact_digest: digest('a'),
        byte_size: 4096,
        media_type: "application/vnd.cantor.native-executable".to_owned(),
        artifact_kind: candidate.artifact_kind.clone(),
        target_triple: candidate.toolchain.target_triple.clone(),
        build_input_digest: candidate.candidate_digest.clone(),
    };
    seal_native_build_observation(
        &lineage,
        &fixture.build_plan,
        &fixture.capability,
        &fixture.sandbox,
        &fixture.trust_store,
        authorization,
        NativeBuildObservation {
            profile: NATIVE_BUILD_OBSERVATION_PROFILE.to_owned(),
            attempt_id: id("attempt:native-fixture:1"),
            authorization_ref: authorization.certificate_id.clone(),
            authorization_digest: authorization.authorization_digest.clone(),
            build_plan_ref: fixture.build_plan.plan_id.clone(),
            build_plan_digest: fixture.build_plan.plan_digest.clone(),
            candidate_ref: candidate.candidate_id.clone(),
            candidate_digest: candidate.candidate_digest.clone(),
            runner_id: fixture.build_plan.runner.runner_id.clone(),
            runner_executable_digest: fixture.build_plan.runner.executable_digest.clone(),
            sandbox_admission_ref: fixture.sandbox.admission_id.clone(),
            sandbox_admission_digest: fixture.sandbox.admission_digest.clone(),
            command_digest: native_build_command_digest(&fixture.build_plan)
                .expect("command digest"),
            environment_digest: fixture.build_plan.environment_digest.clone(),
            logical_started_at: 151,
            logical_finished_at: 153,
            disposition: NativeBuildObservationDisposition::Succeeded,
            exit_code: Some(0),
            stdout_digest: digest('b'),
            stderr_digest: digest('c'),
            resources: NativeBuildResourceUsage {
                process_count: 2,
                peak_memory_bytes: 1024 * 1024,
                stdout_bytes: 128,
                stderr_bytes: 0,
                artifact_bytes: artifact.byte_size,
            },
            artifacts: BTreeMap::from([(artifact.artifact_id.clone(), artifact)]),
            fault_codes: BTreeSet::new(),
            non_authority: NATIVE_BUILD_OBSERVATION_NON_AUTHORITY.to_owned(),
            observation_digest: empty_digest(),
        },
    )
    .expect("successful supplied observation")
}

struct ProducedFixture {
    authorization_fixture: AuthorizationFixture,
    authorization: NativeBuildAuthorizationCertificate,
    observation: NativeBuildObservation,
    ledger: NativeBuildAttemptLedger,
    receipt: NativeArtifactReceipt,
}

impl ProducedFixture {
    fn lineage(&self) -> NativeArtifactReceiptLineage<'_> {
        NativeArtifactReceiptLineage {
            build: NativeArtifactBuildLineage {
                seed: &self.authorization_fixture.seed,
                ir: &self.authorization_fixture.ir,
                candidate_plan: &self.authorization_fixture.candidate_plan,
                candidate_request: &self.authorization_fixture.candidate_request,
                projection: &self.authorization_fixture.projection,
            },
            plan: &self.authorization_fixture.build_plan,
            capability: &self.authorization_fixture.capability,
            sandbox: &self.authorization_fixture.sandbox,
            trust_store: &self.authorization_fixture.trust_store,
            authorization: &self.authorization,
            observation: &self.observation,
            attempt_ledger: &self.ledger,
            receipt: &self.receipt,
        }
    }
}

fn produced_fixture(distinct_suffix: Option<&str>) -> ProducedFixture {
    let authorization_fixture = authorization_fixture();
    let authorization = if let Some(suffix) = distinct_suffix {
        let lineage = NativeArtifactBuildLineage {
            seed: &authorization_fixture.seed,
            ir: &authorization_fixture.ir,
            candidate_plan: &authorization_fixture.candidate_plan,
            candidate_request: &authorization_fixture.candidate_request,
            projection: &authorization_fixture.projection,
        };
        let statement = project_native_build_approval_statement(
            &lineage,
            &authorization_fixture.build_plan,
            &authorization_fixture.capability,
            &authorization_fixture.sandbox,
            id(&format!("approval:native-fixture:{suffix}")),
        )
        .expect("distinct approval statement");
        let payload = native_build_approval_signing_bytes(&statement).expect("signing payload");
        issue_native_build_authorization_certificate(
            &lineage,
            &authorization_fixture.build_plan,
            &authorization_fixture.capability,
            &authorization_fixture.sandbox,
            statement,
            &authorization_fixture.trust_store,
            id(&format!("authorization:native-fixture:{suffix}")),
            authorization_fixture
                .security_key
                .sign(&payload)
                .to_bytes()
                .to_vec(),
            authorization_fixture
                .authority_key
                .sign(&payload)
                .to_bytes()
                .to_vec(),
            150,
        )
        .expect("distinct authorization certificate")
    } else {
        issue_authorization(&authorization_fixture)
    };
    let mut observation = successful_observation(&authorization_fixture, &authorization);
    if let Some(suffix) = distinct_suffix {
        observation.attempt_id = id(&format!("attempt:native-fixture:{suffix}"));
        observation.observation_digest = empty_digest();
        let lineage = NativeArtifactBuildLineage {
            seed: &authorization_fixture.seed,
            ir: &authorization_fixture.ir,
            candidate_plan: &authorization_fixture.candidate_plan,
            candidate_request: &authorization_fixture.candidate_request,
            projection: &authorization_fixture.projection,
        };
        observation = seal_native_build_observation(
            &lineage,
            &authorization_fixture.build_plan,
            &authorization_fixture.capability,
            &authorization_fixture.sandbox,
            &authorization_fixture.trust_store,
            &authorization,
            observation,
        )
        .expect("distinct observation");
    }
    let suffix = distinct_suffix.unwrap_or("primary");
    let initial = new_native_build_attempt_ledger(id(&format!("attempt-ledger:{suffix}")))
        .expect("initial ledger");
    let ledger = record_native_build_attempt(&initial, &authorization, &observation)
        .expect("consume distinct signed approval");
    let lineage = NativeArtifactBuildLineage {
        seed: &authorization_fixture.seed,
        ir: &authorization_fixture.ir,
        candidate_plan: &authorization_fixture.candidate_plan,
        candidate_request: &authorization_fixture.candidate_request,
        projection: &authorization_fixture.projection,
    };
    let receipt = project_native_artifact_receipt(
        &lineage,
        &authorization_fixture.build_plan,
        &authorization_fixture.capability,
        &authorization_fixture.sandbox,
        &authorization_fixture.trust_store,
        &authorization,
        &observation,
        &ledger,
        id(&format!("artifact-receipt:{suffix}")),
    )
    .expect("artifact receipt");
    ProducedFixture {
        authorization_fixture,
        authorization,
        observation,
        ledger,
        receipt,
    }
}

#[test]
fn native_build_plan_capability_sandbox_and_dual_approval_are_exact() {
    let fixture = authorization_fixture();
    let first = issue_authorization(&fixture);
    let second = issue_authorization(&fixture);
    assert_eq!(first, second);
    assert_eq!(
        fixture.capability.disposition,
        CapabilityDisposition::WithinCeiling
    );
    assert_eq!(
        fixture.sandbox.disposition,
        NativeSandboxDisposition::Admitted
    );
    let lineage = NativeArtifactBuildLineage {
        seed: &fixture.seed,
        ir: &fixture.ir,
        candidate_plan: &fixture.candidate_plan,
        candidate_request: &fixture.candidate_request,
        projection: &fixture.projection,
    };
    validate_native_build_authorization_certificate(
        &lineage,
        &fixture.build_plan,
        &fixture.capability,
        &fixture.sandbox,
        &fixture.trust_store,
        &first,
        150,
    )
    .expect("certificate validates");
}

#[test]
fn read_only_capability_and_unresolved_sandbox_cannot_authorize() {
    let fixture = authorization_fixture();
    let lineage = NativeArtifactBuildLineage {
        seed: &fixture.seed,
        ir: &fixture.ir,
        candidate_plan: &fixture.candidate_plan,
        candidate_request: &fixture.candidate_request,
        projection: &fixture.projection,
    };
    let read_only = project_native_build_capability_receipt(
        &lineage,
        &fixture.build_plan,
        id("build-capability:read-only"),
        BTreeSet::from([CompilerCapability::SourceRead]),
        BTreeSet::from(["root:native-fixture".to_owned()]),
        BTreeSet::from([id("evidence:read-only")]),
    )
    .expect("denied receipt is still exact accounting");
    assert_eq!(read_only.disposition, CapabilityDisposition::ExceedsCeiling);
    assert_eq!(
        project_native_build_approval_statement(
            &lineage,
            &fixture.build_plan,
            &read_only,
            &fixture.sandbox,
            id("approval:read-only"),
        )
        .expect_err("read-only receipt refuses")
        .kind,
        SemanticCompilerFormFaultKind::RecognitionBoundary
    );

    assert_eq!(
        project_native_build_capability_receipt(
            &lineage,
            &fixture.build_plan,
            id("build-capability:irrelevant-scope"),
            fixture.build_plan.requested_capabilities.clone(),
            BTreeSet::from(["root:unrelated".to_owned()]),
            BTreeSet::from([id("evidence:irrelevant-scope")]),
        )
        .expect_err("an unrelated admitted scope cannot authorize the build root")
        .kind,
        SemanticCompilerFormFaultKind::AccountingMismatch
    );

    let mut unresolved = fixture.sandbox.clone();
    unresolved.containment = NativeSandboxContainment::Unresolved;
    unresolved.disposition = NativeSandboxDisposition::Unresolved;
    unresolved.admission_digest =
        native_sandbox_admission_digest(&unresolved).expect("reseal sandbox");
    assert_eq!(
        project_native_build_approval_statement(
            &lineage,
            &fixture.build_plan,
            &fixture.capability,
            &unresolved,
            id("approval:unresolved"),
        )
        .expect_err("unresolved containment refuses")
        .kind,
        SemanticCompilerFormFaultKind::RecognitionBoundary
    );
}

#[test]
fn projection_binding_and_approval_role_separation_refuse_aliases() {
    let fixture = authorization_fixture();
    let lineage = NativeArtifactBuildLineage {
        seed: &fixture.seed,
        ir: &fixture.ir,
        candidate_plan: &fixture.candidate_plan,
        candidate_request: &fixture.candidate_request,
        projection: &fixture.projection,
    };

    let mut rebound_plan = fixture.build_plan.clone();
    rebound_plan.candidate_projection_digest = digest('f');
    rebound_plan.plan_digest =
        native_build_execution_plan_digest(&rebound_plan).expect("reseal plan");
    assert_eq!(
        validate_native_build_execution_plan(&lineage, &rebound_plan)
            .expect_err("projection substitution refuses")
            .kind,
        SemanticCompilerFormFaultKind::InvalidReference
    );

    let mut aliased_roles = fixture.trust_store.clone();
    aliased_roles.authority_verifying_keys = BTreeMap::from([(
        fixture.seed.authority_trust_root_ref.clone(),
        fixture.security_key.verifying_key().to_bytes().to_vec(),
    )]);
    aliased_roles.store_digest =
        native_build_trust_store_digest(&aliased_roles).expect("reseal aliased trust store");
    assert_eq!(
        validate_native_build_trust_store(&aliased_roles)
            .expect_err("one key cannot inhabit both approval roles")
            .kind,
        SemanticCompilerFormFaultKind::InvalidReference
    );
}

#[test]
fn stale_signature_revocation_and_whole_lineage_substitution_refuse() {
    let fixture = authorization_fixture();
    let authorization = issue_authorization(&fixture);
    let lineage = NativeArtifactBuildLineage {
        seed: &fixture.seed,
        ir: &fixture.ir,
        candidate_plan: &fixture.candidate_plan,
        candidate_request: &fixture.candidate_request,
        projection: &fixture.projection,
    };

    let mut bad_signature = authorization.clone();
    bad_signature.security_signature[0] ^= 1;
    bad_signature.authorization_digest =
        native_build_authorization_digest(&bad_signature).expect("reseal authorization");
    assert_eq!(
        validate_native_build_authorization_certificate(
            &lineage,
            &fixture.build_plan,
            &fixture.capability,
            &fixture.sandbox,
            &fixture.trust_store,
            &bad_signature,
            150,
        )
        .expect_err("bad signature refuses")
        .kind,
        SemanticCompilerFormFaultKind::RecognitionBoundary
    );

    let mut revoked = fixture.trust_store.clone();
    revoked
        .revoked_certificate_ids
        .insert(authorization.certificate_id.clone());
    revoked.store_digest = native_build_trust_store_digest(&revoked).expect("reseal store");
    let mut rebound = authorization.clone();
    rebound.trust_store_digest = revoked.store_digest.clone();
    rebound.authorization_digest =
        native_build_authorization_digest(&rebound).expect("reseal authorization");
    assert_eq!(
        validate_native_build_authorization_certificate(
            &lineage,
            &fixture.build_plan,
            &fixture.capability,
            &fixture.sandbox,
            &revoked,
            &rebound,
            150,
        )
        .expect_err("revoked certificate refuses")
        .kind,
        SemanticCompilerFormFaultKind::RecognitionBoundary
    );

    assert_eq!(
        validate_native_build_authorization_certificate(
            &lineage,
            &fixture.build_plan,
            &fixture.capability,
            &fixture.sandbox,
            &fixture.trust_store,
            &authorization,
            201,
        )
        .expect_err("expired certificate refuses")
        .kind,
        SemanticCompilerFormFaultKind::RecognitionBoundary
    );

    let mut substituted_projection = fixture.projection.clone();
    substituted_projection.candidate.build.binary_name = "other".to_owned();
    substituted_projection.candidate.candidate_digest =
        native_artifact_candidate_digest(&substituted_projection.candidate)
            .expect("reseal candidate");
    substituted_projection.projection_digest =
        native_artifact_backend_projection_digest(&substituted_projection)
            .expect("reseal projection");
    let substituted_lineage = NativeArtifactBuildLineage {
        seed: &fixture.seed,
        ir: &fixture.ir,
        candidate_plan: &fixture.candidate_plan,
        candidate_request: &fixture.candidate_request,
        projection: &substituted_projection,
    };
    assert_eq!(
        validate_native_build_execution_plan(&substituted_lineage, &fixture.build_plan)
            .expect_err("whole-lineage substitution refuses")
            .kind,
        SemanticCompilerFormFaultKind::InvalidReference
    );
}

#[test]
fn successful_observation_is_single_use_and_produces_only_unverified_receipt() {
    let fixture = authorization_fixture();
    let authorization = issue_authorization(&fixture);
    let observation = successful_observation(&fixture, &authorization);
    let initial = new_native_build_attempt_ledger(id("attempt-ledger:native-fixture"))
        .expect("initial attempt ledger");
    let consumed = record_native_build_attempt(&initial, &authorization, &observation)
        .expect("single-use attempt accounting");
    assert_eq!(
        record_native_build_attempt(&consumed, &authorization, &observation)
            .expect_err("authorization cannot be consumed twice")
            .kind,
        SemanticCompilerFormFaultKind::StageOrder
    );
    let mut replay_envelope = authorization.clone();
    replay_envelope.certificate_id = id("authorization:native-fixture:replay-envelope");
    replay_envelope.authorization_digest =
        native_build_authorization_digest(&replay_envelope).expect("reseal replay envelope");
    let mut replay_observation = observation.clone();
    replay_observation.attempt_id = id("attempt:native-fixture:replay-envelope");
    replay_observation.authorization_ref = replay_envelope.certificate_id.clone();
    replay_observation.authorization_digest = replay_envelope.authorization_digest.clone();
    replay_observation.observation_digest = empty_digest();
    replay_observation = seal_native_build_observation(
        &NativeArtifactBuildLineage {
            seed: &fixture.seed,
            ir: &fixture.ir,
            candidate_plan: &fixture.candidate_plan,
            candidate_request: &fixture.candidate_request,
            projection: &fixture.projection,
        },
        &fixture.build_plan,
        &fixture.capability,
        &fixture.sandbox,
        &fixture.trust_store,
        &replay_envelope,
        replay_observation,
    )
    .expect("certificate envelope remains self-consistent");
    assert_eq!(
        record_native_build_attempt(&consumed, &replay_envelope, &replay_observation)
            .expect_err("a new certificate envelope cannot launder the signed approval")
            .kind,
        SemanticCompilerFormFaultKind::StageOrder
    );
    let lineage = NativeArtifactBuildLineage {
        seed: &fixture.seed,
        ir: &fixture.ir,
        candidate_plan: &fixture.candidate_plan,
        candidate_request: &fixture.candidate_request,
        projection: &fixture.projection,
    };
    let first = project_native_artifact_receipt(
        &lineage,
        &fixture.build_plan,
        &fixture.capability,
        &fixture.sandbox,
        &fixture.trust_store,
        &authorization,
        &observation,
        &consumed,
        id("artifact-receipt:native-fixture"),
    )
    .expect("produced-unverified artifact receipt");
    let second = project_native_artifact_receipt(
        &lineage,
        &fixture.build_plan,
        &fixture.capability,
        &fixture.sandbox,
        &fixture.trust_store,
        &authorization,
        &observation,
        &consumed,
        id("artifact-receipt:native-fixture"),
    )
    .expect("deterministic artifact receipt");
    assert_eq!(first, second);
    assert_eq!(
        first.lifecycle,
        NativeArtifactReceiptLifecycle::ProducedUnverified
    );
}

#[test]
fn failed_observation_is_preserved_but_cannot_produce_artifact_receipt() {
    let fixture = authorization_fixture();
    let authorization = issue_authorization(&fixture);
    let mut failed = successful_observation(&fixture, &authorization);
    failed.attempt_id = id("attempt:native-fixture:failed");
    failed.logical_finished_at = 154;
    failed.disposition = NativeBuildObservationDisposition::Failed;
    failed.exit_code = Some(101);
    failed.artifacts.clear();
    failed.resources.artifact_bytes = 0;
    failed.fault_codes = BTreeSet::from(["compiler_exit_nonzero".to_owned()]);
    failed.observation_digest = empty_digest();
    let lineage = NativeArtifactBuildLineage {
        seed: &fixture.seed,
        ir: &fixture.ir,
        candidate_plan: &fixture.candidate_plan,
        candidate_request: &fixture.candidate_request,
        projection: &fixture.projection,
    };
    let failed = seal_native_build_observation(
        &lineage,
        &fixture.build_plan,
        &fixture.capability,
        &fixture.sandbox,
        &fixture.trust_store,
        &authorization,
        failed,
    )
    .expect("failed observation remains evidence");
    let initial = new_native_build_attempt_ledger(id("attempt-ledger:failed")).expect("ledger");
    let consumed = record_native_build_attempt(&initial, &authorization, &failed)
        .expect("failed attempt still consumes authorization");
    assert_eq!(
        project_native_artifact_receipt(
            &lineage,
            &fixture.build_plan,
            &fixture.capability,
            &fixture.sandbox,
            &fixture.trust_store,
            &authorization,
            &failed,
            &consumed,
            id("artifact-receipt:must-refuse"),
        )
        .expect_err("failed build cannot produce receipt")
        .kind,
        SemanticCompilerFormFaultKind::StageOrder
    );
}

#[test]
fn observation_bounds_artifact_accounting_and_lineage_substitution_refuse() {
    let fixture = authorization_fixture();
    let authorization = issue_authorization(&fixture);
    let lineage = NativeArtifactBuildLineage {
        seed: &fixture.seed,
        ir: &fixture.ir,
        candidate_plan: &fixture.candidate_plan,
        candidate_request: &fixture.candidate_request,
        projection: &fixture.projection,
    };

    let mut oversized = successful_observation(&fixture, &authorization);
    oversized.resources.peak_memory_bytes = fixture.build_plan.maximum_memory_bytes + 1;
    oversized.observation_digest = empty_digest();
    assert_eq!(
        seal_native_build_observation(
            &lineage,
            &fixture.build_plan,
            &fixture.capability,
            &fixture.sandbox,
            &fixture.trust_store,
            &authorization,
            oversized,
        )
        .expect_err("resource overflow refuses")
        .kind,
        SemanticCompilerFormFaultKind::InvalidBound
    );

    let mut mismatched = successful_observation(&fixture, &authorization);
    mismatched.resources.artifact_bytes += 1;
    mismatched.observation_digest = empty_digest();
    assert_eq!(
        seal_native_build_observation(
            &lineage,
            &fixture.build_plan,
            &fixture.capability,
            &fixture.sandbox,
            &fixture.trust_store,
            &authorization,
            mismatched,
        )
        .expect_err("artifact byte accounting mismatch refuses")
        .kind,
        SemanticCompilerFormFaultKind::AccountingMismatch
    );

    let mut substituted = successful_observation(&fixture, &authorization);
    substituted.authorization_digest = digest('f');
    substituted.observation_digest = empty_digest();
    assert_eq!(
        seal_native_build_observation(
            &lineage,
            &fixture.build_plan,
            &fixture.capability,
            &fixture.sandbox,
            &fixture.trust_store,
            &authorization,
            substituted,
        )
        .expect_err("authorization substitution refuses")
        .kind,
        SemanticCompilerFormFaultKind::InvalidReference
    );
}

fn independent_verifier() -> NativeArtifactVerifierPin {
    NativeArtifactVerifierPin {
        verifier_id: id("verifier:native-fixture"),
        verifier_profile: "cantor-fake-independent-verifier/0.1".to_owned(),
        program_digest: digest('d'),
        configuration_digest: digest('e'),
    }
}

#[test]
fn independent_exact_checks_derive_passed_without_granting_later_authority() {
    let produced = produced_fixture(None);
    let lineage = produced.lineage();
    let evidence = BTreeSet::from([id("evidence:independent-byte-inspection")]);
    let plan = project_native_artifact_verification_plan(
        &lineage,
        id("verification-plan:primary"),
        independent_verifier(),
        evidence.clone(),
        false,
    )
    .expect("verification plan");
    let observation = project_native_artifact_verification_observation(
        &lineage,
        &plan,
        id("verification-observation:primary"),
        Some(produced.receipt.artifact.clone()),
        Some(
            produced
                .authorization_fixture
                .projection
                .candidate
                .interface
                .input_schema_digest
                .clone(),
        ),
        Some(
            produced
                .authorization_fixture
                .projection
                .candidate
                .interface
                .output_schema_digest
                .clone(),
        ),
        evidence,
        None,
    )
    .expect("independent facts");
    let first = project_native_artifact_verification_receipt(
        &lineage,
        &plan,
        &observation,
        None,
        id("verification-receipt:primary"),
    )
    .expect("verification receipt");
    let second = project_native_artifact_verification_receipt(
        &lineage,
        &plan,
        &observation,
        None,
        id("verification-receipt:primary"),
    )
    .expect("deterministic verification receipt");
    assert_eq!(first, second);
    assert_eq!(
        first.disposition,
        NativeArtifactVerificationDisposition::Passed
    );
    assert!(first.unresolved_items.is_empty());
    assert_eq!(first.checks.len(), 9);
    assert_eq!(
        first.non_authority,
        NATIVE_ARTIFACT_VERIFICATION_NON_AUTHORITY
    );
}

#[test]
fn runner_cannot_be_verifier_and_missing_or_mismatched_facts_are_not_passed() {
    let produced = produced_fixture(None);
    let lineage = produced.lineage();
    let required_evidence = BTreeSet::from([id("evidence:independent-byte-inspection")]);
    let mut runner_as_verifier = independent_verifier();
    runner_as_verifier.verifier_id = produced
        .authorization_fixture
        .build_plan
        .runner
        .runner_id
        .clone();
    assert_eq!(
        project_native_artifact_verification_plan(
            &lineage,
            id("verification-plan:collapsed"),
            runner_as_verifier,
            required_evidence.clone(),
            false,
        )
        .expect_err("runner/verifier collapse refuses")
        .kind,
        SemanticCompilerFormFaultKind::RecognitionBoundary
    );

    let plan = project_native_artifact_verification_plan(
        &lineage,
        id("verification-plan:incomplete"),
        independent_verifier(),
        required_evidence,
        true,
    )
    .expect("reproducibility verification plan");
    let unresolved_observation = project_native_artifact_verification_observation(
        &lineage,
        &plan,
        id("verification-observation:unresolved"),
        None,
        None,
        None,
        BTreeSet::new(),
        None,
    )
    .expect("absent evidence is representable");
    let unresolved = project_native_artifact_verification_receipt(
        &lineage,
        &plan,
        &unresolved_observation,
        None,
        id("verification-receipt:unresolved"),
    )
    .expect("unresolved receipt");
    assert_eq!(
        unresolved.disposition,
        NativeArtifactVerificationDisposition::Unresolved
    );
    assert!(!unresolved.unresolved_items.is_empty());

    let mismatch_plan = project_native_artifact_verification_plan(
        &lineage,
        id("verification-plan:mismatch"),
        independent_verifier(),
        BTreeSet::from([id("evidence:mismatch")]),
        false,
    )
    .expect("mismatch plan");
    let mut mismatched_artifact = produced.receipt.artifact.clone();
    mismatched_artifact.artifact_digest = digest('f');
    let mismatch_observation = project_native_artifact_verification_observation(
        &lineage,
        &mismatch_plan,
        id("verification-observation:mismatch"),
        Some(mismatched_artifact),
        Some(mismatch_plan.expected_interface_input_schema_digest.clone()),
        Some(
            mismatch_plan
                .expected_interface_output_schema_digest
                .clone(),
        ),
        mismatch_plan.required_evidence_refs.clone(),
        None,
    )
    .expect("mismatch remains inspectable evidence");
    let failed = project_native_artifact_verification_receipt(
        &lineage,
        &mismatch_plan,
        &mismatch_observation,
        None,
        id("verification-receipt:failed"),
    )
    .expect("failed receipt");
    assert_eq!(
        failed.disposition,
        NativeArtifactVerificationDisposition::Failed
    );
    assert_eq!(
        failed
            .checks
            .get(&NativeArtifactVerificationCheck::ArtifactDigest),
        Some(&NativeArtifactVerificationCheckDisposition::Failed)
    );
}

#[test]
fn reproducibility_requires_distinct_signed_approval_attempt_and_equal_bytes() {
    let primary = produced_fixture(None);
    let second = produced_fixture(Some("reproducibility"));
    let primary_lineage = primary.lineage();
    let second_lineage = second.lineage();
    let evidence = BTreeSet::from([id("evidence:two-build-comparison")]);
    let plan = project_native_artifact_verification_plan(
        &primary_lineage,
        id("verification-plan:reproducibility"),
        independent_verifier(),
        evidence.clone(),
        true,
    )
    .expect("reproducibility plan");
    let observation = project_native_artifact_verification_observation(
        &primary_lineage,
        &plan,
        id("verification-observation:reproducibility"),
        Some(primary.receipt.artifact.clone()),
        Some(plan.expected_interface_input_schema_digest.clone()),
        Some(plan.expected_interface_output_schema_digest.clone()),
        evidence,
        Some(&second_lineage),
    )
    .expect("distinct second-build facts");
    let passed = project_native_artifact_verification_receipt(
        &primary_lineage,
        &plan,
        &observation,
        Some(&second_lineage),
        id("verification-receipt:reproducibility"),
    )
    .expect("reproducibility receipt");
    assert_eq!(
        passed
            .checks
            .get(&NativeArtifactVerificationCheck::Reproducibility),
        Some(&NativeArtifactVerificationCheckDisposition::Passed)
    );

    let replay_observation = project_native_artifact_verification_observation(
        &primary_lineage,
        &plan,
        id("verification-observation:self-replay"),
        Some(primary.receipt.artifact.clone()),
        Some(plan.expected_interface_input_schema_digest.clone()),
        Some(plan.expected_interface_output_schema_digest.clone()),
        plan.required_evidence_refs.clone(),
        Some(&primary_lineage),
    )
    .expect("self replay is preserved for failed derivation");
    let replay = project_native_artifact_verification_receipt(
        &primary_lineage,
        &plan,
        &replay_observation,
        Some(&primary_lineage),
        id("verification-receipt:self-replay"),
    )
    .expect("self replay derives a failed check");
    assert_eq!(
        replay
            .checks
            .get(&NativeArtifactVerificationCheck::Reproducibility),
        Some(&NativeArtifactVerificationCheckDisposition::Failed)
    );
}

#[test]
fn lifecycle_machine_forms_refuse_unknown_fields() {
    let produced = produced_fixture(None);
    let lineage = produced.lineage();
    let plan = project_native_artifact_verification_plan(
        &lineage,
        id("verification-plan:strict-json"),
        independent_verifier(),
        BTreeSet::from([id("evidence:strict-json")]),
        false,
    )
    .expect("strict verification plan");

    let mut observation_json =
        serde_json::to_value(&produced.observation).expect("observation JSON");
    observation_json
        .as_object_mut()
        .expect("observation object")
        .insert("hidden_effect".to_owned(), serde_json::json!(true));
    assert!(serde_json::from_value::<NativeBuildObservation>(observation_json).is_err());

    let mut receipt_json = serde_json::to_value(&produced.receipt).expect("receipt JSON");
    receipt_json
        .as_object_mut()
        .expect("receipt object")
        .insert("admitted".to_owned(), serde_json::json!(true));
    assert!(serde_json::from_value::<NativeArtifactReceipt>(receipt_json).is_err());

    let mut plan_json = serde_json::to_value(&plan).expect("verification plan JSON");
    plan_json
        .as_object_mut()
        .expect("plan object")
        .insert("install_after_pass".to_owned(), serde_json::json!(true));
    assert!(serde_json::from_value::<NativeArtifactVerificationPlan>(plan_json).is_err());
}
