use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::IR_VERSION;
use crate::evaluator::evaluate;
use crate::machine::{content_digest, from_machine_form, to_machine_form};
use crate::model::{
    AuthorityContext, BoundaryAccount, CantorQueryRequest, CantorQueryResult,
    CompiledPackageManifest, ConstraintRequirement, CoreMachineSchema, EffectAuthority,
    EvaluationFault, FaultKind, ImportFidelity, Instruction, OntologyImport, OntologyStandard,
    PackageLifecycle, ProofAssertion, ProofBundle, QueryBudget, RelationType, RelationshipPath,
    RelationshipStep, RequestedDetailKind, SearchMode, SemanticContext, SemanticId,
    SemanticProgram, SemanticRelation, SemanticState, SemanticTransition, SourceAnchor,
    StateStatus, TransitionTrace, UnitKind, UnitStatus,
};
use crate::review::{
    InferenceCapsule, ReviewReport, ReviewVerdict, build_capsule, no_match_history_review,
    review_capsule,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FixtureId {
    AliasesAndContext,
    InspectableInference,
    UnknownVersusInvalid,
    PureTransformation,
    EffectAuthority,
    YieldAndReentry,
    SurfaceEquivalence,
    OntologyImport,
}

impl FixtureId {
    pub const fn number(self) -> u8 {
        match self {
            Self::AliasesAndContext => 1,
            Self::InspectableInference => 2,
            Self::UnknownVersusInvalid => 3,
            Self::PureTransformation => 4,
            Self::EffectAuthority => 5,
            Self::YieldAndReentry => 6,
            Self::SurfaceEquivalence => 7,
            Self::OntologyImport => 8,
        }
    }

    pub const fn slug(self) -> &'static str {
        match self {
            Self::AliasesAndContext => "aliases_and_context",
            Self::InspectableInference => "inspectable_inference",
            Self::UnknownVersusInvalid => "unknown_versus_invalid",
            Self::PureTransformation => "pure_transformation",
            Self::EffectAuthority => "effect_authority",
            Self::YieldAndReentry => "yield_and_reentry",
            Self::SurfaceEquivalence => "surface_equivalence",
            Self::OntologyImport => "ontology_import",
        }
    }
}

impl fmt::Display for FixtureId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}", self.number(), self.slug())
    }
}

impl FromStr for FixtureId {
    type Err = EvaluationFault;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "1" | "aliases_and_context" => Ok(Self::AliasesAndContext),
            "2" | "inspectable_inference" => Ok(Self::InspectableInference),
            "3" | "unknown_versus_invalid" => Ok(Self::UnknownVersusInvalid),
            "4" | "pure_transformation" => Ok(Self::PureTransformation),
            "5" | "effect_authority" => Ok(Self::EffectAuthority),
            "6" | "yield_and_reentry" => Ok(Self::YieldAndReentry),
            "7" | "surface_equivalence" => Ok(Self::SurfaceEquivalence),
            "8" | "ontology_import" => Ok(Self::OntologyImport),
            _ => Err(EvaluationFault::new(
                FaultKind::UnsupportedSurface,
                format!("unknown fixture: {value}"),
            )),
        }
    }
}

pub const fn all_fixture_ids() -> [FixtureId; 8] {
    [
        FixtureId::AliasesAndContext,
        FixtureId::InspectableInference,
        FixtureId::UnknownVersusInvalid,
        FixtureId::PureTransformation,
        FixtureId::EffectAuthority,
        FixtureId::YieldAndReentry,
        FixtureId::SurfaceEquivalence,
        FixtureId::OntologyImport,
    ]
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixtureDecision {
    pub accepted: bool,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixtureReport {
    pub ir_version: String,
    pub fixture_id: FixtureId,
    pub before_state: SemanticState,
    pub transitions: Vec<SemanticTransition>,
    pub after_state: SemanticState,
    pub proof: Vec<ProofAssertion>,
    pub faults: Vec<EvaluationFault>,
    pub capsule: InferenceCapsule,
    pub review: ReviewReport,
    pub decision: FixtureDecision,
}

impl FixtureReport {
    pub fn is_accepted(&self) -> bool {
        self.decision.accepted
    }
}

pub fn run_fixture(fixture_id: FixtureId) -> Result<FixtureReport, EvaluationFault> {
    match fixture_id {
        FixtureId::AliasesAndContext => fixture_aliases_and_context(),
        FixtureId::InspectableInference => fixture_inspectable_inference(),
        FixtureId::UnknownVersusInvalid => fixture_unknown_versus_invalid(),
        FixtureId::PureTransformation => fixture_pure_transformation(),
        FixtureId::EffectAuthority => fixture_effect_authority(),
        FixtureId::YieldAndReentry => fixture_yield_and_reentry(),
        FixtureId::SurfaceEquivalence => fixture_surface_equivalence(),
        FixtureId::OntologyImport => fixture_ontology_import(),
    }
}

fn fixture_aliases_and_context() -> Result<FixtureReport, EvaluationFault> {
    let fixture = FixtureId::AliasesAndContext;
    let financial = unit(
        "unit:bank_financial",
        "bank",
        &["financial institution"],
        "an institution that receives deposits",
        "finance",
        UnitStatus::Asserted,
    )?;
    let river = unit(
        "unit:bank_river",
        "bank",
        &["riverbank"],
        "land alongside a river",
        "geography",
        UnitStatus::Asserted,
    )?;
    let instructions = vec![
        Instruction::Declare {
            unit: financial.clone(),
        },
        Instruction::Declare {
            unit: river.clone(),
        },
    ];
    let program = program(fixture, "preserve contextual identity", instructions)?;
    let entry = state(fixture, &program.purpose)?;
    let transitions = execute_program(fixture, &entry, &program.instructions)?;
    let exit = exit_state(&entry, &transitions);
    let finance_matches = exit.environment.resolve_label_in_scope("bank", "finance");
    let geography_matches = exit.environment.resolve_label_in_scope("bank", "geography");
    let schema = core_machine_schema(&financial, &river)?;
    let schema_machine_form = to_machine_form(&schema)?;
    let restored_schema: CoreMachineSchema = from_machine_form(&schema_machine_form)?;
    let proof = vec![
        proof(
            "shared label preserves two semantic identities",
            exit.environment.units.len() == 2
                && financial.unit_id != river.unit_id
                && exit.environment.labels["bank"].len() == 2,
            &["unit:bank_financial", "unit:bank_river"],
        ),
        proof(
            "context resolves the intended identity without global merging",
            finance_matches == vec![&financial] && geography_matches == vec![&river],
            &["scope:finance", "scope:geography"],
        ),
        proof(
            "CEB-002 core machine forms serialize and restore exactly",
            restored_schema == schema,
            &[
                "semantic_unit",
                "relation",
                "context",
                "anchor",
                "package",
                "query",
                "result",
                "proof",
                "trace",
                "fault",
            ],
        ),
    ];
    finalize(
        fixture,
        "term bank with financial and river contexts",
        program,
        entry,
        transitions,
        "two bank meanings remain distinct and context-addressable",
        proof,
    )
}

fn fixture_inspectable_inference() -> Result<FixtureReport, EvaluationFault> {
    let fixture = FixtureId::InspectableInference;
    let conclusion = unit(
        "judgment:socrates_mortal",
        "Socrates is mortal",
        &[],
        "Socrates is mortal",
        "classical_deduction",
        UnitStatus::Inferred,
    )?;
    let premises = vec![
        "Socrates is human".to_owned(),
        "Every human is mortal".to_owned(),
    ];
    let instructions = vec![Instruction::Infer {
        conclusion: conclusion.clone(),
        premises: premises.clone(),
        rule: "universal_instantiation_and_modus_ponens".to_owned(),
    }];
    let program = program(
        fixture,
        "derive a conclusion with named grounds",
        instructions,
    )?;
    let entry = state(fixture, &program.purpose)?;
    let transitions = execute_program(fixture, &entry, &program.instructions)?;
    let transition = &transitions[0];
    let proof = vec![proof(
        "inference exposes conclusion, premises, rule, and epistemic status",
        transition.judgments.len() == 1
            && transition.judgments[0].grounds.len() == 3
            && transition.judgments[0].claim == conclusion.meaning
            && transition.trace.reason.contains("named rule"),
        &[
            &premises[0],
            &premises[1],
            "rule:universal_instantiation_and_modus_ponens",
        ],
    )];
    finalize(
        fixture,
        "two premises and a named deductive rule",
        program,
        entry,
        transitions,
        "Socrates is mortal under the declared inference regime",
        proof,
    )
}

fn fixture_unknown_versus_invalid() -> Result<FixtureReport, EvaluationFault> {
    let fixture = FixtureId::UnknownVersusInvalid;
    let instructions = vec![
        Instruction::ValidateConstraint {
            name: "display_name_nonempty".to_owned(),
            observed: None,
            requirement: ConstraintRequirement::NonEmpty,
        },
        Instruction::ValidateConstraint {
            name: "display_name_nonempty".to_owned(),
            observed: Some(String::new()),
            requirement: ConstraintRequirement::NonEmpty,
        },
    ];
    let program = program(
        fixture,
        "distinguish missing knowledge from known invalidity",
        instructions,
    )?;
    let entry = state(fixture, &program.purpose)?;
    let transitions = execute_program(fixture, &entry, &program.instructions)?;
    let proof = vec![proof(
        "unknown and invalid produce distinct judgments and faults",
        transitions[0].faults[0].kind == FaultKind::UnknownKnowledge
            && transitions[1].faults[0].kind == FaultKind::ConstraintViolation
            && transitions[0].judgments[0].status != transitions[1].judgments[0].status,
        &["fault:UnknownKnowledge", "fault:ConstraintViolation"],
    )];
    finalize(
        fixture,
        "one absent value and one known empty value",
        program,
        entry,
        transitions,
        "absence remains unknown; known emptiness is invalid",
        proof,
    )
}

fn fixture_pure_transformation() -> Result<FixtureReport, EvaluationFault> {
    let fixture = FixtureId::PureTransformation;
    let instructions = vec![Instruction::TransformAdd {
        target: "sum".to_owned(),
        left: 2,
        right: 3,
    }];
    let program = program(fixture, "compute without an external effect", instructions)?;
    let entry = state(fixture, &program.purpose)?;
    let transitions = execute_program(fixture, &entry, &program.instructions)?;
    let exit = exit_state(&entry, &transitions);
    let proof = vec![proof(
        "pure transformation produces value five and no effect event",
        exit.values.get("sum") == Some(&5)
            && transitions[0].effect_events.is_empty()
            && exit.pending_effects.is_empty(),
        &["2 + 3", "sum = 5"],
    )];
    finalize(
        fixture,
        "add two fixture values",
        program,
        entry,
        transitions,
        "sum equals five with no external effect",
        proof,
    )
}

fn fixture_effect_authority() -> Result<FixtureReport, EvaluationFault> {
    let fixture = FixtureId::EffectAuthority;
    let instructions = vec![
        Instruction::ProposeEffect {
            effect_id: SemanticId::new("effect:denied_write")?,
            description: "write outside declared fixture scope".to_owned(),
            authority: EffectAuthority::Denied {
                reason: "caller has read-only authority".to_owned(),
            },
        },
        Instruction::ProposeEffect {
            effect_id: SemanticId::new("effect:authorized_fixture_write")?,
            description: "stage fixture-local proposed output".to_owned(),
            authority: EffectAuthority::Authorized {
                grant: "fixture-local proposal grant".to_owned(),
            },
        },
    ];
    let program = program(
        fixture,
        "separate denied, authorized, and committed effects",
        instructions,
    )?;
    let entry = state(fixture, &program.purpose)?;
    let transitions = execute_program(fixture, &entry, &program.instructions)?;
    let exit = exit_state(&entry, &transitions);
    let proof = vec![proof(
        "denied effect faults while authorized effect remains pending and uncommitted",
        transitions[0].faults[0].kind == FaultKind::UnauthorizedEffect
            && transitions[0].after_state.pending_effects.is_empty()
            && exit.pending_effects.len() == 1
            && transitions
                .iter()
                .flat_map(|transition| &transition.effect_events)
                .all(|event| !matches!(event.status, crate::model::EffectStatus::Proposed)),
        &[
            "fault:UnauthorizedEffect",
            "effect:authorized_fixture_write",
            "no committed effect status exists in Core v0.1",
        ],
    )];
    finalize(
        fixture,
        "one denied and one authorized effect proposal",
        program,
        entry,
        transitions,
        "authority gates proposals; Core v0.1 commits no external effect",
        proof,
    )
}

fn fixture_yield_and_reentry() -> Result<FixtureReport, EvaluationFault> {
    let fixture = FixtureId::YieldAndReentry;
    let entry = state(fixture, "yield, serialize, restore, and reenter exactly")?;
    let yield_instruction = Instruction::Yield;
    let yield_history = no_match_history_review(fixture.slug(), 0, &entry, "CONTROL")?;
    let yield_transition = evaluate(&entry, &yield_instruction, yield_history)?;
    let yielded = yield_transition.after_state.clone();
    let machine_form = to_machine_form(&yielded)?;
    let restored: SemanticState = from_machine_form(&machine_form)?;
    let exact_restore = restored == yielded;
    let reenter_instruction = Instruction::Reenter {
        restored_state: Box::new(restored.clone()),
    };
    let reentry_history = no_match_history_review(fixture.slug(), 1, &yielded, "CONTROL")?;
    let reentry_transition = evaluate(&yielded, &reenter_instruction, reentry_history)?;
    let program = program(
        fixture,
        "yield, serialize, restore, and reenter exactly",
        vec![yield_instruction, reenter_instruction],
    )?;
    let proof = vec![
        proof(
            "yielded state round-trips through its machine form exactly",
            exact_restore,
            &["serde_json deterministic machine form", "state equality"],
        ),
        proof(
            "reentry starts from the exact yielded state before consuming its transition",
            reentry_transition.before_state == yielded
                && restored == yielded
                && reentry_transition.after_state.status == StateStatus::Ready
                && reentry_transition.after_state.budget.transitions_remaining + 1
                    == yielded.budget.transitions_remaining,
            &["CONTROL:YIELD", "CONTROL:REENTER"],
        ),
    ];
    finalize(
        fixture,
        "one yielded semantic state",
        program,
        entry,
        vec![yield_transition, reentry_transition],
        "yielded state restored exactly before resuming",
        proof,
    )
}

fn fixture_surface_equivalence() -> Result<FixtureReport, EvaluationFault> {
    let fixture = FixtureId::SurfaceEquivalence;
    let verbose = "DECLARE term honesty MEANS accurate representation IN scope ethics";
    let condensed = "term honesty = accurate representation @ ethics";
    let verbose_program = compile_honesty_surface(verbose)?;
    let condensed_program = compile_honesty_surface(condensed)?;
    let mut verbose_semantics = verbose_program.clone();
    let mut condensed_semantics = condensed_program.clone();
    verbose_semantics.source_forms.clear();
    condensed_semantics.source_forms.clear();
    let verbose_digest = content_digest(&verbose_semantics)?;
    let condensed_digest = content_digest(&condensed_semantics)?;
    let entry = state(fixture, &verbose_program.purpose)?;
    let transitions = execute_program(fixture, &entry, &verbose_program.instructions)?;
    let proof = vec![proof(
        "verbose and condensed surfaces compile to equivalent semantic IR",
        verbose_semantics == condensed_semantics && verbose_digest == condensed_digest,
        &[verbose, condensed, &verbose_digest.value],
    )];
    finalize(
        fixture,
        &format!("verbose:{verbose}; condensed:{condensed}"),
        verbose_program,
        entry,
        transitions,
        "surface provenance differs while normalized semantic IR is equal",
        proof,
    )
}

fn fixture_ontology_import() -> Result<FixtureReport, EvaluationFault> {
    let fixture = FixtureId::OntologyImport;
    let animal = unit(
        "concept:animal",
        "animal",
        &[],
        "living organism that feeds on organic matter",
        "taxonomy",
        UnitStatus::Asserted,
    )?;
    let cat = unit(
        "concept:cat",
        "cat",
        &[],
        "domesticated feline",
        "taxonomy",
        UnitStatus::Asserted,
    )?;
    let relation = SemanticRelation {
        relation_id: SemanticId::new("relation:cat_broader_animal")?,
        source: cat.unit_id.clone(),
        relation_type: RelationType::Broader,
        target: animal.unit_id.clone(),
        source_ref: "fixture:skos_broader".to_owned(),
    };
    let import = OntologyImport {
        standard: OntologyStandard::Skos,
        source_construct: "ex:cat skos:broader ex:animal".to_owned(),
        relation: relation.clone(),
        fidelity: ImportFidelity::Exact,
    };
    let instructions = vec![
        Instruction::Declare { unit: animal },
        Instruction::Declare { unit: cat },
        Instruction::ImportOntology { import },
    ];
    let program = program(
        fixture,
        "import one SKOS relation with declared fidelity",
        instructions,
    )?;
    let entry = state(fixture, &program.purpose)?;
    let transitions = execute_program(fixture, &entry, &program.instructions)?;
    let exit = exit_state(&entry, &transitions);
    let proof = vec![proof(
        "SKOS broader relation imports with exact fidelity and source lineage",
        exit.environment.relations == vec![relation]
            && transitions[2].faults.is_empty()
            && transitions[2].trace.evidence == vec!["ex:cat skos:broader ex:animal"],
        &["skos:broader", "RelationType::Broader", "fidelity:Exact"],
    )];
    finalize(
        fixture,
        "one SKOS broader assertion",
        program,
        entry,
        transitions,
        "SKOS relation preserved with source and declared exact fidelity",
        proof,
    )
}

fn execute_program(
    fixture: FixtureId,
    entry: &SemanticState,
    instructions: &[Instruction],
) -> Result<Vec<SemanticTransition>, EvaluationFault> {
    let mut current = entry.clone();
    let mut transitions = Vec::with_capacity(instructions.len());
    for (sequence, instruction) in instructions.iter().enumerate() {
        let history =
            no_match_history_review(fixture.slug(), sequence, &current, instruction.family())?;
        let transition = evaluate(&current, instruction, history)?;
        current = transition.after_state.clone();
        transitions.push(transition);
    }
    Ok(transitions)
}

fn finalize(
    fixture_id: FixtureId,
    input_snapshot: &str,
    program: SemanticProgram,
    entry: SemanticState,
    transitions: Vec<SemanticTransition>,
    candidate_response: &str,
    proof: Vec<ProofAssertion>,
) -> Result<FixtureReport, EvaluationFault> {
    let after = exit_state(&entry, &transitions);
    let faults = transitions
        .iter()
        .flat_map(|transition| transition.faults.clone())
        .collect();
    let capsule = build_capsule(
        fixture_id.slug(),
        input_snapshot,
        program,
        entry.clone(),
        transitions.clone(),
        candidate_response.to_owned(),
        proof.clone(),
    )?;
    let review = review_capsule(&capsule)?;
    let accepted = proof.iter().all(|assertion| assertion.passed)
        && matches!(review.verdict, ReviewVerdict::Accept);
    let reason = if accepted {
        "all declared fixture proofs and review gates passed".to_owned()
    } else {
        "one or more fixture proofs or review gates failed".to_owned()
    };
    Ok(FixtureReport {
        ir_version: IR_VERSION.to_owned(),
        fixture_id,
        before_state: entry,
        transitions,
        after_state: after,
        proof,
        faults,
        capsule,
        review,
        decision: FixtureDecision { accepted, reason },
    })
}

fn exit_state(entry: &SemanticState, transitions: &[SemanticTransition]) -> SemanticState {
    transitions
        .last()
        .map(|transition| transition.after_state.clone())
        .unwrap_or_else(|| entry.clone())
}

fn state(fixture: FixtureId, purpose: &str) -> Result<SemanticState, EvaluationFault> {
    SemanticId::new(format!("state:{}", fixture.slug()))
        .map(|id| SemanticState::fixture(id, purpose))
}

fn program(
    fixture: FixtureId,
    purpose: &str,
    instructions: Vec<Instruction>,
) -> Result<SemanticProgram, EvaluationFault> {
    Ok(SemanticProgram {
        ir_version: IR_VERSION.to_owned(),
        program_id: SemanticId::new(format!("program:{}", fixture.slug()))?,
        purpose: purpose.to_owned(),
        instructions,
        source_forms: vec![format!("CoreAcceptance.fixture_{}", fixture.number())],
    })
}

fn unit(
    id: &str,
    expression: &str,
    aliases: &[&str],
    meaning: &str,
    scope: &str,
    status: UnitStatus,
) -> Result<crate::model::SemanticUnit, EvaluationFault> {
    Ok(crate::model::SemanticUnit {
        unit_id: SemanticId::new(id)?,
        kind: UnitKind::Term,
        expression: expression.to_owned(),
        aliases: aliases.iter().map(|alias| (*alias).to_owned()).collect(),
        meaning: meaning.to_owned(),
        context: SemanticContext::fixture(scope, "CoreAcceptance"),
        source_set: vec![format!("fixture:{id}")],
        status,
    })
}

fn proof(claim: &str, passed: bool, support: &[&str]) -> ProofAssertion {
    ProofAssertion {
        claim: claim.to_owned(),
        support: support.iter().map(|item| (*item).to_owned()).collect(),
        passed,
    }
}

fn compile_honesty_surface(surface: &str) -> Result<SemanticProgram, EvaluationFault> {
    const VERBOSE: &str = "DECLARE term honesty MEANS accurate representation IN scope ethics";
    const CONDENSED: &str = "term honesty = accurate representation @ ethics";
    if surface != VERBOSE && surface != CONDENSED {
        return Err(EvaluationFault::new(
            FaultKind::UnsupportedSurface,
            "Core v0.1 compiler accepts only the two fixture-seven surfaces",
        ));
    }
    let fixture = FixtureId::SurfaceEquivalence;
    let honesty = unit(
        "term:honesty",
        "honesty",
        &[],
        "accurate representation",
        "ethics",
        UnitStatus::Asserted,
    )?;
    let mut compiled = program(
        fixture,
        "compile equivalent surface forms",
        vec![Instruction::Declare { unit: honesty }],
    )?;
    compiled.source_forms = vec![surface.to_owned()];
    Ok(compiled)
}

fn core_machine_schema(
    financial: &crate::model::SemanticUnit,
    river: &crate::model::SemanticUnit,
) -> Result<CoreMachineSchema, EvaluationFault> {
    let relation = SemanticRelation {
        relation_id: SemanticId::new("relation:bank_meanings_distinct")?,
        source: financial.unit_id.clone(),
        relation_type: RelationType::DistinctFrom,
        target: river.unit_id.clone(),
        source_ref: "CoreAcceptance.fixture_1".to_owned(),
    };
    let fixture_digest = crate::model::ContentDigest {
        algorithm: "fnv1a64-fixture-only".to_owned(),
        value: "0000000000000000".to_owned(),
    };
    let anchor = SourceAnchor {
        package_id: SemanticId::new("package:core_schema_fixture")?,
        file_id: SemanticId::new("file:sop_core")?,
        unit_id: financial.unit_id.clone(),
        clause_id: SemanticId::new("clause:fixture_1")?,
        byte_start: 0,
        byte_end: 4,
        span_digest: fixture_digest.clone(),
        display_line_start: 147,
        display_line_end: 147,
    };
    let package = CompiledPackageManifest {
        manifest_version: "cantor-package/0.1-schema".to_owned(),
        package_id: anchor.package_id.clone(),
        semantic_unit_ids: vec![financial.unit_id.clone(), river.unit_id.clone()],
        relation_ids: vec![relation.relation_id.clone()],
        source_files: vec!["specifications/SOP_Core.sop".to_owned()],
        package_digest: fixture_digest.clone(),
        recognition_certificate: None,
        lifecycle: PackageLifecycle::SchemaOnly,
    };
    let query = CantorQueryRequest {
        protocol_version: "cantor-query/0.1-schema".to_owned(),
        request_id: SemanticId::new("request:core_schema_fixture")?,
        term_set: ["bank".to_owned()].into_iter().collect(),
        subject: Some("financial institution".to_owned()),
        purpose: "prove machine-form completeness".to_owned(),
        use_case_set: ["context resolution".to_owned()].into_iter().collect(),
        include_boundary_set: ["finance".to_owned()].into_iter().collect(),
        exclude_boundary_set: ["geography".to_owned()].into_iter().collect(),
        description_need: Some("resolve the intended bank meaning".to_owned()),
        requested_detail_kinds: [
            RequestedDetailKind::Term,
            RequestedDetailKind::Boundary,
            RequestedDetailKind::SourceSpan,
        ]
        .into_iter()
        .collect(),
        search_modes: [SearchMode::Exact, SearchMode::Contextual]
            .into_iter()
            .collect(),
        relation_types: [RelationType::DistinctFrom].into_iter().collect(),
        criteria: ["preserve identity".to_owned()].into_iter().collect(),
        source_scopes: ["core fixture".to_owned()].into_iter().collect(),
        perspectives: ["fixture".to_owned()].into_iter().collect(),
        known_units: [financial.unit_id.clone()].into_iter().collect(),
        authority_context: AuthorityContext {
            caller_id: SemanticId::new("caller:core_fixture")?,
            allowed_package_scopes: ["fixture".to_owned()].into_iter().collect(),
            operation: "schema_roundtrip".to_owned(),
            effect_boundary: "read_only".to_owned(),
        },
        budget: QueryBudget {
            maximum_records: 4,
            maximum_paths: 2,
            maximum_depth: 1,
            maximum_bytes: 4096,
            maximum_elapsed_milliseconds: 100,
        },
    };
    let proof_bundle = ProofBundle {
        package_proofs: Vec::new(),
        package_checks: vec!["schema_only".to_owned()],
        source_checks: vec!["anchor_shape_present".to_owned()],
        query_decisions: vec!["exact_before_contextual".to_owned()],
        relation_paths: vec![RelationshipPath {
            unit_path: vec![financial.unit_id.clone(), river.unit_id.clone()],
            steps: vec![RelationshipStep {
                package_id: SemanticId::new("package:schema_only")?,
                relation_id: relation.relation_id.clone(),
                relation_type: relation.relation_type.clone(),
                source: relation.source.clone(),
                target: relation.target.clone(),
                source_ref: relation.source_ref.clone(),
            }],
        }],
        exclusions: vec!["geography excluded by request".to_owned()],
        omissions: vec!["no query execution in slice 01".to_owned()],
        result_digest: fixture_digest.clone(),
    };
    let result = CantorQueryResult {
        protocol_version: query.protocol_version.clone(),
        request_id: query.request_id.clone(),
        resolved_subjects: vec![financial.unit_id.clone()],
        records: vec![financial.clone()],
        verified_quotes: Vec::new(),
        relationship_paths: proof_bundle.relation_paths.clone(),
        boundary_account: BoundaryAccount {
            admitted: vec![financial.unit_id.clone()],
            excluded: vec![river.unit_id.clone()],
            ambiguous: Vec::new(),
            contradictory: Vec::new(),
            unknown: Vec::new(),
            stale: Vec::new(),
            unauthorized: Vec::new(),
            budget_clipped: false,
        },
        deterministic_contributions: vec!["schema witness only".to_owned()],
        routed_contributions: Vec::new(),
        proof: proof_bundle.clone(),
        detail_accounts: Vec::new(),
        faults: Vec::new(),
        continuation: None,
        result_digest: fixture_digest.clone(),
    };
    Ok(CoreMachineSchema {
        semantic_unit: financial.clone(),
        relation,
        context: financial.context.clone(),
        anchor,
        package,
        query,
        result,
        proof: proof_bundle,
        trace: TransitionTrace {
            source: "CoreAcceptance.fixture_1".to_owned(),
            rule: "SCHEMA".to_owned(),
            reason: "prove CEB-002 machine forms".to_owned(),
            evidence: vec!["canonical build specification".to_owned()],
            authority: vec!["slice_01".to_owned()],
            uncertainty: vec!["behavior deferred to owning later slices".to_owned()],
        },
        fault: EvaluationFault::new(FaultKind::UnsupportedSurface, "schema witness fault form"),
    })
}
