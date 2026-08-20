use std::collections::{BTreeMap, BTreeSet};

use cantor_core::{
    CANDIDATE_COMPILATION_PLAN_PROFILE, COMPILER_CAPABILITY_CEILING_PROFILE,
    COMPILER_CAPABILITY_RECEIPT_PROFILE, COMPILER_NON_AUTHORITY, CandidateCompilationPlan,
    CapabilityDisposition, CompilerBackendKind, CompilerCapability, CompilerCapabilityCeiling,
    CompilerCapabilityReceipt, CompilerSourceMapEntry, ContentDigest, SELF_ASSEMBLY_LEDGER_PROFILE,
    SOP_SEED_PROFILE, SelfAssemblyDisposition, SelfAssemblyEntry, SelfAssemblyLedger,
    SelfAssemblyStage, SemanticAddress, SemanticCompilerFormFaultKind, SemanticId, SemanticIrNode,
    SemanticIrNodeKind, SopSeed, SourceAnchor, TYPED_SOP_IR_PROFILE, TypedSopIr, UnitKind,
    candidate_compilation_plan_digest, compiler_capability_ceiling_digest,
    compiler_capability_receipt_digest, self_assembly_ledger_digest, sop_seed_digest,
    typed_sop_ir_digest, validate_candidate_compilation_plan, validate_compiler_capability_ceiling,
    validate_compiler_capability_receipt, validate_self_assembly_ledger, validate_sop_seed,
    validate_typed_sop_ir,
};

fn id(value: &str) -> SemanticId {
    SemanticId::new(value).expect("fixture identity")
}

fn digest(byte: char) -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: byte.to_string().repeat(64),
    }
}

fn address(unit: &str, kind: UnitKind, byte: char) -> SemanticAddress {
    let unit_id = id(unit);
    let package_id = id("package:compiler-fixture");
    SemanticAddress {
        unit_id: unit_id.clone(),
        unit_digest: digest(byte),
        package_id: package_id.clone(),
        package_digest: digest('a'),
        kind,
        context_id: id("context:compiler-fixture"),
        version: "0.1.0".to_owned(),
        source_anchors: vec![SourceAnchor {
            package_id,
            file_id: id("file:compiler-fixture"),
            unit_id,
            clause_id: id(&format!("clause:{unit}")),
            byte_start: 1,
            byte_end: 12,
            span_digest: digest('b'),
            display_line_start: 1,
            display_line_end: 1,
        }],
    }
}

fn ceiling() -> CompilerCapabilityCeiling {
    let mut value = CompilerCapabilityCeiling {
        profile: COMPILER_CAPABILITY_CEILING_PROFILE.to_owned(),
        ceiling_id: id("ceiling:seed-fixture"),
        capabilities: BTreeSet::from([
            CompilerCapability::SemanticRead,
            CompilerCapability::SourceRead,
            CompilerCapability::Build,
        ]),
        resource_scopes: BTreeSet::from(["fixture-only".to_owned()]),
        maximum_artifacts: 4,
        maximum_serialized_bytes: 1_048_576,
        ceiling_digest: digest('0'),
    };
    value.ceiling_digest =
        compiler_capability_ceiling_digest(&value).expect("ceiling digest computes");
    value
}

fn seed() -> SopSeed {
    let mut value = SopSeed {
        profile: SOP_SEED_PROFILE.to_owned(),
        seed_id: id("seed:compiler-fixture"),
        generation_id: id("generation:compiler-fixture:r1"),
        purpose: "assemble one verified Cantor candidate".to_owned(),
        honesty_trust_root_ref: id("trust:honesty"),
        security_trust_root_ref: id("trust:security"),
        authority_trust_root_ref: id("trust:authority"),
        compiler_trust_root_ref: id("trust:compiler"),
        dependency_roots: BTreeMap::from([
            (id("dependency:sop-core"), digest('c')),
            (id("dependency:anchor-catalogue"), digest('d')),
        ]),
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
        capability_ceiling: ceiling(),
        predecessor_generation_ref: Some(id("generation:compiler-fixture:r0")),
        successor_policy_ref: id("policy:external-successor-recognition"),
        seed_digest: digest('0'),
    };
    value.seed_digest = sop_seed_digest(&value).expect("seed digest computes");
    value
}

fn node(
    node_id: &str,
    kind: SemanticIrNodeKind,
    unit_kind: UnitKind,
    digest_byte: char,
    type_ref: Option<SemanticId>,
    dependency_refs: BTreeSet<SemanticId>,
) -> SemanticIrNode {
    SemanticIrNode {
        node_id: id(node_id),
        kind,
        semantic_address: address(&format!("unit:{node_id}"), unit_kind, digest_byte),
        type_ref,
        dependency_refs,
        generated_derivation_refs: BTreeSet::new(),
    }
}

fn ir() -> TypedSopIr {
    let type_id = id("node:type");
    let input_id = id("node:input");
    let output_id = id("node:output");
    let nodes = BTreeMap::from([
        (
            type_id.clone(),
            node(
                type_id.as_str(),
                SemanticIrNodeKind::Type,
                UnitKind::Term,
                'e',
                None,
                BTreeSet::new(),
            ),
        ),
        (
            input_id.clone(),
            node(
                input_id.as_str(),
                SemanticIrNodeKind::Input,
                UnitKind::Declaration,
                'f',
                Some(type_id.clone()),
                BTreeSet::from([type_id]),
            ),
        ),
        (
            output_id.clone(),
            node(
                output_id.as_str(),
                SemanticIrNodeKind::Output,
                UnitKind::Declaration,
                '1',
                Some(id("node:type")),
                BTreeSet::from([input_id]),
            ),
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
                    derivation_refs: node.generated_derivation_refs.clone(),
                },
            )
        })
        .collect();
    let mut value = TypedSopIr {
        profile: TYPED_SOP_IR_PROFILE.to_owned(),
        ir_id: id("ir:compiler-fixture"),
        source_manifest_digest: digest('2'),
        canonical_specification_ref: id("spec:seeded-compiler"),
        canonical_specification_digest: digest('3'),
        nodes,
        source_map,
        unresolved_account: BTreeSet::new(),
        non_authority: COMPILER_NON_AUTHORITY.to_owned(),
        ir_digest: digest('0'),
    };
    value.ir_digest = typed_sop_ir_digest(&value).expect("IR digest computes");
    value
}

fn plan(backend: CompilerBackendKind) -> CandidateCompilationPlan {
    let seed = seed();
    let ir = ir();
    let backend_profile = seed.backend_profiles[&backend].clone();
    let mut value = CandidateCompilationPlan {
        profile: CANDIDATE_COMPILATION_PLAN_PROFILE.to_owned(),
        plan_id: id(&format!("plan:{backend_profile}")),
        seed_ref: seed.seed_id.clone(),
        seed_digest: seed.seed_digest,
        ir_ref: ir.ir_id.clone(),
        ir_digest: ir.ir_digest,
        backend,
        backend_profile,
        purpose: seed.purpose,
        requested_capabilities: BTreeSet::from([
            CompilerCapability::SemanticRead,
            CompilerCapability::Build,
        ]),
        input_refs: BTreeSet::from([id("node:input")]),
        expected_output_refs: BTreeSet::from([id("node:output")]),
        verifier_refs: BTreeSet::from([id("verifier:compiler-fixture")]),
        rollback_ref: id("rollback:compiler-fixture"),
        unresolved_account: BTreeSet::new(),
        non_authority: COMPILER_NON_AUTHORITY.to_owned(),
        plan_digest: digest('0'),
    };
    value.plan_digest = candidate_compilation_plan_digest(&value).expect("plan digest computes");
    value
}

fn receipt(plan: &CandidateCompilationPlan) -> CompilerCapabilityReceipt {
    let seed = seed();
    let mut value = CompilerCapabilityReceipt {
        profile: COMPILER_CAPABILITY_RECEIPT_PROFILE.to_owned(),
        receipt_id: id("receipt:capability-fixture"),
        plan_ref: plan.plan_id.clone(),
        plan_digest: plan.plan_digest.clone(),
        backend: plan.backend.clone(),
        ceiling_ref: seed.capability_ceiling.ceiling_id.clone(),
        ceiling_digest: seed.capability_ceiling.ceiling_digest,
        requested_capabilities: plan.requested_capabilities.clone(),
        admitted_capabilities: plan.requested_capabilities.clone(),
        denied_capabilities: BTreeSet::new(),
        evidence_refs: BTreeSet::from([id("evidence:capability-check")]),
        disposition: CapabilityDisposition::WithinCeiling,
        non_authority: COMPILER_NON_AUTHORITY.to_owned(),
        receipt_digest: digest('0'),
    };
    value.receipt_digest =
        compiler_capability_receipt_digest(&value).expect("receipt digest computes");
    value
}

fn ledger() -> SelfAssemblyLedger {
    let seed = seed();
    let plan = plan(CompilerBackendKind::AttentionProcedure);
    let entries = vec![
        SelfAssemblyEntry {
            entry_id: id("ledger-entry:description"),
            stage: SelfAssemblyStage::SelfDescription,
            plan_ref: None,
            candidate_artifact_ref: None,
            honesty_receipt_ref: None,
            security_receipt_ref: None,
            external_recognition_ref: None,
            evidence_refs: BTreeSet::from([id("evidence:self-description")]),
            disposition: SelfAssemblyDisposition::Observed,
        },
        SelfAssemblyEntry {
            entry_id: id("ledger-entry:ordering"),
            stage: SelfAssemblyStage::SelfOrdering,
            plan_ref: Some(plan.plan_id.clone()),
            candidate_artifact_ref: None,
            honesty_receipt_ref: None,
            security_receipt_ref: None,
            external_recognition_ref: None,
            evidence_refs: BTreeSet::from([id("evidence:self-ordering")]),
            disposition: SelfAssemblyDisposition::Candidate,
        },
        SelfAssemblyEntry {
            entry_id: id("ledger-entry:hosting"),
            stage: SelfAssemblyStage::SelfHosting,
            plan_ref: Some(plan.plan_id.clone()),
            candidate_artifact_ref: Some(id("artifact:candidate-fixture")),
            honesty_receipt_ref: Some(id("receipt:honesty-candidate")),
            security_receipt_ref: Some(id("receipt:security-candidate")),
            external_recognition_ref: None,
            evidence_refs: BTreeSet::from([id("evidence:self-hosting")]),
            disposition: SelfAssemblyDisposition::VerifiedCandidate,
        },
        SelfAssemblyEntry {
            entry_id: id("ledger-entry:revision"),
            stage: SelfAssemblyStage::SelfRevision,
            plan_ref: Some(plan.plan_id),
            candidate_artifact_ref: Some(id("artifact:candidate-fixture")),
            honesty_receipt_ref: Some(id("receipt:honesty-successor")),
            security_receipt_ref: Some(id("receipt:security-successor")),
            external_recognition_ref: Some(id("recognition:external-authority")),
            evidence_refs: BTreeSet::from([id("evidence:self-revision")]),
            disposition: SelfAssemblyDisposition::RecognizedSuccessor,
        },
    ];
    let mut value = SelfAssemblyLedger {
        profile: SELF_ASSEMBLY_LEDGER_PROFILE.to_owned(),
        ledger_id: id("ledger:self-assembly-fixture"),
        seed_ref: seed.seed_id.clone(),
        seed_digest: seed.seed_digest,
        predecessor_generation_ref: seed.generation_id,
        successor_generation_ref: Some(id("generation:compiler-fixture:r2")),
        rollback_ref: id("rollback:generation-r1"),
        entries,
        non_authority: COMPILER_NON_AUTHORITY.to_owned(),
        ledger_digest: digest('0'),
    };
    value.ledger_digest = self_assembly_ledger_digest(&value).expect("ledger digest computes");
    value
}

#[test]
fn all_three_backend_plans_are_distinct_valid_and_deterministic() {
    let seed = seed();
    let ir = ir();
    validate_compiler_capability_ceiling(&seed.capability_ceiling).expect("ceiling validates");
    validate_sop_seed(&seed).expect("seed validates");
    validate_typed_sop_ir(&ir).expect("IR validates");

    let plans = [
        plan(CompilerBackendKind::AttentionProcedure),
        plan(CompilerBackendKind::InferenceHostIntegration),
        plan(CompilerBackendKind::NativeArtifact),
    ];
    for plan in &plans {
        validate_candidate_compilation_plan(&seed, &ir, plan).expect("plan validates");
        let encoded = serde_json::to_vec(plan).expect("plan serializes");
        assert_eq!(encoded, serde_json::to_vec(plan).expect("plan repeats"));
    }
    assert_eq!(
        plans
            .iter()
            .map(|plan| plan.plan_digest.value.clone())
            .collect::<BTreeSet<_>>()
            .len(),
        3
    );
}

#[test]
fn strict_forms_reject_unknown_fields_and_digest_mutation() {
    let seed = seed();
    let mut json = serde_json::to_value(&seed).expect("seed serializes");
    json["invented_authority"] = serde_json::json!(true);
    assert!(serde_json::from_value::<SopSeed>(json).is_err());

    let mut changed = seed;
    changed.purpose.push_str(" changed");
    assert_eq!(
        validate_sop_seed(&changed)
            .expect_err("unsealed mutation fails")
            .kind,
        SemanticCompilerFormFaultKind::DigestMismatch
    );
}

#[test]
fn source_map_gaps_dependency_cycles_and_address_substitution_fail() {
    let mut missing = ir();
    missing.source_map.remove(&id("node:input"));
    missing.ir_digest = typed_sop_ir_digest(&missing).expect("mutated IR reseals");
    assert_eq!(
        validate_typed_sop_ir(&missing)
            .expect_err("source map gap fails")
            .kind,
        SemanticCompilerFormFaultKind::MissingSourceMap
    );

    let mut cycle = ir();
    cycle
        .nodes
        .get_mut(&id("node:type"))
        .expect("type exists")
        .dependency_refs
        .insert(id("node:output"));
    cycle.ir_digest = typed_sop_ir_digest(&cycle).expect("cycle IR reseals");
    assert_eq!(
        validate_typed_sop_ir(&cycle)
            .expect_err("dependency cycle fails")
            .kind,
        SemanticCompilerFormFaultKind::DependencyCycle
    );

    let mut substituted = ir();
    substituted
        .source_map
        .get_mut(&id("node:input"))
        .expect("map exists")
        .semantic_address = address("unit:substitute", UnitKind::Declaration, '4');
    substituted.ir_digest = typed_sop_ir_digest(&substituted).expect("substitution reseals");
    assert_eq!(
        validate_typed_sop_ir(&substituted)
            .expect_err("address substitution fails")
            .kind,
        SemanticCompilerFormFaultKind::MissingSourceMap
    );

    let mut unknown_type = ir();
    unknown_type
        .nodes
        .get_mut(&id("node:input"))
        .expect("input exists")
        .type_ref = Some(id("node:unknown-type"));
    unknown_type.ir_digest = typed_sop_ir_digest(&unknown_type).expect("type mutation reseals");
    assert_eq!(
        validate_typed_sop_ir(&unknown_type)
            .expect_err("unknown type fails")
            .kind,
        SemanticCompilerFormFaultKind::InvalidReference
    );
}

#[test]
fn backend_substitution_and_capability_excess_fail_closed() {
    let seed = seed();
    let ir = ir();
    let mut wrong_backend = plan(CompilerBackendKind::AttentionProcedure);
    wrong_backend.backend = CompilerBackendKind::NativeArtifact;
    wrong_backend.plan_digest =
        candidate_compilation_plan_digest(&wrong_backend).expect("backend mutation reseals");
    assert_eq!(
        validate_candidate_compilation_plan(&seed, &ir, &wrong_backend)
            .expect_err("cross-backend profile fails")
            .kind,
        SemanticCompilerFormFaultKind::BackendMismatch
    );

    let mut excess = plan(CompilerBackendKind::NativeArtifact);
    excess
        .requested_capabilities
        .insert(CompilerCapability::Install);
    excess.plan_digest = candidate_compilation_plan_digest(&excess).expect("excess plan reseals");
    assert_eq!(
        validate_candidate_compilation_plan(&seed, &ir, &excess)
            .expect_err("capability excess fails")
            .kind,
        SemanticCompilerFormFaultKind::CapabilityExceeded
    );
}

#[test]
fn capability_receipt_partitions_the_request_without_authorizing_execution() {
    let seed = seed();
    let plan = plan(CompilerBackendKind::NativeArtifact);
    let valid = receipt(&plan);
    validate_compiler_capability_receipt(&seed, &plan, &valid).expect("receipt validates");
    assert_eq!(valid.non_authority, COMPILER_NON_AUTHORITY);

    let mut overlap = valid;
    overlap
        .denied_capabilities
        .insert(CompilerCapability::Build);
    overlap.receipt_digest =
        compiler_capability_receipt_digest(&overlap).expect("overlap receipt reseals");
    assert_eq!(
        validate_compiler_capability_receipt(&seed, &plan, &overlap)
            .expect_err("overlapping account fails")
            .kind,
        SemanticCompilerFormFaultKind::AccountingMismatch
    );
}

#[test]
fn self_assembly_requires_contiguous_stages_and_external_recognition() {
    let seed = seed();
    let valid = ledger();
    validate_self_assembly_ledger(&seed, &valid).expect("ledger validates");

    let mut skipped = valid.clone();
    skipped.entries.remove(1);
    skipped.ledger_digest = self_assembly_ledger_digest(&skipped).expect("skip reseals");
    assert_eq!(
        validate_self_assembly_ledger(&seed, &skipped)
            .expect_err("stage skip fails")
            .kind,
        SemanticCompilerFormFaultKind::StageOrder
    );

    let mut unsigned = valid;
    let revision = unsigned.entries.last_mut().expect("revision exists");
    revision.security_receipt_ref = None;
    unsigned.ledger_digest = self_assembly_ledger_digest(&unsigned).expect("ledger reseals");
    assert_eq!(
        validate_self_assembly_ledger(&seed, &unsigned)
            .expect_err("missing Security receipt fails")
            .kind,
        SemanticCompilerFormFaultKind::RecognitionBoundary
    );
}

#[test]
fn unresolved_receipt_and_candidate_ledger_prefix_remain_valid_non_authority() {
    let seed = seed();
    let plan = plan(CompilerBackendKind::InferenceHostIntegration);
    let mut unresolved = receipt(&plan);
    unresolved.evidence_refs.clear();
    unresolved.disposition = CapabilityDisposition::Unresolved;
    unresolved.receipt_digest =
        compiler_capability_receipt_digest(&unresolved).expect("unresolved receipt seals");
    validate_compiler_capability_receipt(&seed, &plan, &unresolved)
        .expect("unresolved capability account remains valid");

    let mut prefix = ledger();
    prefix.entries.truncate(2);
    prefix.successor_generation_ref = None;
    prefix.ledger_digest = self_assembly_ledger_digest(&prefix).expect("prefix ledger seals");
    validate_self_assembly_ledger(&seed, &prefix).expect("candidate prefix remains valid");
}
