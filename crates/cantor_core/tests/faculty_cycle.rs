use cantor_core::{
    CombinatoryProjection, FacultyActivation, FacultyCycle, FacultyCycleKind, FacultyKind,
    FacultyLedger, FacultyOmission, FacultyReturn, FacultyReturnStatus, FacultyStage,
    IdentityBoundary, IdentityBoundaryDomain, ObserverDisposition, ProjectionKind,
    ProjectionStatus, SemanticId,
};

fn id(value: &str) -> SemanticId {
    SemanticId::new(value).expect("fixture identity must be valid")
}

fn activation(ordinal: u32, faculty: FacultyKind, stage: FacultyStage) -> FacultyActivation {
    FacultyActivation {
        activation_id: id(&format!("activation:{ordinal}")),
        faculty,
        stage,
        ordinal,
        purpose: format!("perform {stage:?} as {faculty:?}"),
        input_refs: vec![id("state:before")],
        unavailable_refs: Vec::new(),
    }
}

fn faculty_return(activation: &FacultyActivation) -> FacultyReturn {
    FacultyReturn {
        activation_id: activation.activation_id.clone(),
        faculty: activation.faculty,
        status: FacultyReturnStatus::Accepted,
        output_refs: vec![id(&format!("output:{}", activation.ordinal))],
        objections: Vec::new(),
        uncertainty: Vec::new(),
        ledger: FacultyLedger {
            source_refs: vec!["fixture:source".to_owned()],
            grounds: vec!["fixture:ground".to_owned()],
            constraint_refs: vec!["CIFP".to_owned()],
            retained_boundaries: vec!["candidate != admitted".to_owned()],
            relation_refs: Vec::new(),
        },
    }
}

fn guarded_boundaries() -> Vec<IdentityBoundary> {
    vec![
        IdentityBoundary {
            boundary_id: id("boundary:epistemic"),
            domain: IdentityBoundaryDomain::Epistemic,
            guarded_by: FacultyKind::Honesty,
            subject_ref: id("state:before"),
            inside: vec!["supported claims".to_owned()],
            edge_conditions: vec!["claim kind or attribution changes".to_owned()],
            outside: vec!["unsupported certainty".to_owned()],
            uncertainty: Vec::new(),
        },
        IdentityBoundary {
            boundary_id: id("boundary:authority"),
            domain: IdentityBoundaryDomain::Authority,
            guarded_by: FacultyKind::Security,
            subject_ref: id("state:before"),
            inside: vec!["declared semantic operations".to_owned()],
            edge_conditions: vec!["resource or effect scope changes".to_owned()],
            outside: vec!["external effect commitment".to_owned()],
            uncertainty: Vec::new(),
        },
    ]
}

fn combinatory_projections() -> Vec<CombinatoryProjection> {
    vec![
        CombinatoryProjection {
            projection_id: id("projection:relational"),
            kind: ProjectionKind::Relational,
            projected_by: FacultyKind::Weaver,
            status: ProjectionStatus::Candidate,
            basis_refs: vec![id("state:before")],
            candidate_refs: vec![id("candidate:composite")],
            constraint_refs: vec!["preserve identity boundaries".to_owned()],
            residuals: Vec::new(),
        },
        CombinatoryProjection {
            projection_id: id("projection:temporal"),
            kind: ProjectionKind::Temporal,
            projected_by: FacultyKind::Planner,
            status: ProjectionStatus::Candidate,
            basis_refs: vec![id("candidate:composite")],
            candidate_refs: vec![id("candidate:path")],
            constraint_refs: vec!["verify each step".to_owned()],
            residuals: Vec::new(),
        },
    ]
}

fn cite_faculty_outputs(
    activations: &[FacultyActivation],
    returns: &mut [FacultyReturn],
    include_projections: bool,
) {
    for (activation, faculty_return) in activations.iter().zip(returns) {
        match (activation.faculty, activation.stage) {
            (FacultyKind::Honesty, FacultyStage::Bound) => {
                faculty_return.output_refs.push(id("boundary:epistemic"));
            }
            (FacultyKind::Security, FacultyStage::Bound) => {
                faculty_return.output_refs.push(id("boundary:authority"));
            }
            (FacultyKind::Weaver, FacultyStage::Project) if include_projections => {
                faculty_return.output_refs.push(id("projection:relational"));
            }
            (FacultyKind::Planner, FacultyStage::Project) if include_projections => {
                faculty_return.output_refs.push(id("projection:temporal"));
            }
            _ => {}
        }
    }
}

fn semantic_cycle() -> FacultyCycle {
    let activations = vec![
        activation(1, FacultyKind::Observer, FacultyStage::Observe),
        activation(2, FacultyKind::Scribe, FacultyStage::Anchor),
        activation(3, FacultyKind::Honesty, FacultyStage::Bound),
        activation(4, FacultyKind::Security, FacultyStage::Bound),
        activation(5, FacultyKind::Weaver, FacultyStage::Project),
        activation(6, FacultyKind::Planner, FacultyStage::Project),
        activation(7, FacultyKind::Refiner, FacultyStage::Refine),
        activation(8, FacultyKind::Honesty, FacultyStage::Gate),
        activation(9, FacultyKind::Security, FacultyStage::Gate),
        activation(10, FacultyKind::Observer, FacultyStage::Decide),
        activation(11, FacultyKind::Scribe, FacultyStage::Inscribe),
    ];
    let mut returns = activations.iter().map(faculty_return).collect::<Vec<_>>();
    cite_faculty_outputs(&activations, &mut returns, true);
    FacultyCycle {
        cycle_id: id("cycle:semantic"),
        kind: FacultyCycleKind::SemanticTransition,
        subject: "integrated faculty process".to_owned(),
        purpose: "form one governed semantic transition".to_owned(),
        before_state_ref: id("state:before"),
        identity_boundaries: guarded_boundaries(),
        projections: combinatory_projections(),
        activations,
        returns,
        omissions: Vec::new(),
        observer_disposition: ObserverDisposition::Admit,
        after_state_ref: id("state:after"),
        residuals: Vec::new(),
    }
}

fn preservation_cycle() -> FacultyCycle {
    let activations = vec![
        activation(1, FacultyKind::Observer, FacultyStage::Observe),
        activation(2, FacultyKind::Scribe, FacultyStage::Anchor),
        activation(3, FacultyKind::Honesty, FacultyStage::Bound),
        activation(4, FacultyKind::Security, FacultyStage::Bound),
        activation(5, FacultyKind::Refiner, FacultyStage::Refine),
        activation(6, FacultyKind::Honesty, FacultyStage::Gate),
        activation(7, FacultyKind::Security, FacultyStage::Gate),
        activation(8, FacultyKind::Observer, FacultyStage::Decide),
        activation(9, FacultyKind::Scribe, FacultyStage::Inscribe),
    ];
    let mut returns = activations.iter().map(faculty_return).collect::<Vec<_>>();
    cite_faculty_outputs(&activations, &mut returns, false);
    FacultyCycle {
        cycle_id: id("cycle:preservation"),
        kind: FacultyCycleKind::Preservation,
        subject: "exact source".to_owned(),
        purpose: "preserve without relational or temporal change".to_owned(),
        before_state_ref: id("state:before"),
        identity_boundaries: guarded_boundaries(),
        projections: Vec::new(),
        activations,
        returns,
        omissions: vec![
            FacultyOmission {
                faculty: FacultyKind::Planner,
                reason: "no state gap or ordered action exists".to_owned(),
                authority: "CIFP preservation omission".to_owned(),
                observer_accepted: true,
            },
            FacultyOmission {
                faculty: FacultyKind::Weaver,
                reason: "one already bounded source is preserved without composition".to_owned(),
                authority: "CIFP preservation omission".to_owned(),
                observer_accepted: true,
            },
        ],
        observer_disposition: ObserverDisposition::Admit,
        after_state_ref: id("state:after"),
        residuals: Vec::new(),
    }
}

#[test]
fn semantic_and_preservation_cycles_validate() {
    semantic_cycle()
        .validate()
        .expect("complete semantic cycle must validate");
    preservation_cycle()
        .validate()
        .expect("accountable preservation omissions must validate");
}

#[test]
fn every_faculty_must_be_activated_or_omitted() {
    let mut cycle = preservation_cycle();
    cycle
        .omissions
        .retain(|omission| omission.faculty != FacultyKind::Weaver);
    let fault = cycle.validate().expect_err("silent omission must fail");
    assert!(
        fault
            .message
            .contains("neither activated nor explicitly omitted")
    );
}

#[test]
fn semantic_transition_cannot_omit_planner_or_weaver() {
    let mut cycle = preservation_cycle();
    cycle.kind = FacultyCycleKind::SemanticTransition;
    let fault = cycle
        .validate()
        .expect_err("semantic transition requires Planner and Weaver");
    assert!(fault.message.contains("constitutionally required"));
}

#[test]
fn activation_and_omission_cannot_collide() {
    let mut cycle = semantic_cycle();
    cycle.omissions.push(FacultyOmission {
        faculty: FacultyKind::Planner,
        reason: "invalid collision fixture".to_owned(),
        authority: "fixture".to_owned(),
        observer_accepted: true,
    });
    let fault = cycle
        .validate()
        .expect_err("activation-omission collision must fail");
    assert!(fault.message.contains("both activated and omitted"));
}

#[test]
fn every_activation_requires_one_matching_return() {
    let mut missing = semantic_cycle();
    missing.returns.pop();
    let fault = missing
        .validate()
        .expect_err("missing faculty return must fail");
    assert!(fault.message.contains("exactly one return"));

    let mut mismatched = semantic_cycle();
    mismatched.returns[0].faculty = FacultyKind::Planner;
    let fault = mismatched
        .validate()
        .expect_err("mismatched faculty return must fail");
    assert!(fault.message.contains("does not match"));
}

#[test]
fn constitutional_stage_order_is_enforced() {
    let mut cycle = semantic_cycle();
    cycle.activations[6].stage = FacultyStage::Gate;
    cycle.activations[7].stage = FacultyStage::Refine;
    let fault = cycle
        .validate()
        .expect_err("gate before refinement must fail");
    assert!(
        fault.message.contains("missing required Refine")
            || fault.message.contains("violates anchor")
    );
}

#[test]
fn identity_boundaries_must_be_guarded_and_cited() {
    let mut missing = semantic_cycle();
    missing
        .identity_boundaries
        .retain(|boundary| boundary.guarded_by != FacultyKind::Security);
    let fault = missing
        .validate()
        .expect_err("both boundary guardians are required");
    assert!(
        fault
            .message
            .contains("Honesty-guarded and Security-guarded")
    );

    let mut mismatched = semantic_cycle();
    mismatched.identity_boundaries[0].guarded_by = FacultyKind::Security;
    let fault = mismatched
        .validate()
        .expect_err("boundary guardian must match its domain");
    assert!(fault.message.contains("wrong guardian"));

    let mut uncited = semantic_cycle();
    let honesty_bound = uncited
        .activations
        .iter()
        .find(|activation| {
            activation.faculty == FacultyKind::Honesty && activation.stage == FacultyStage::Bound
        })
        .expect("fixture has Honesty bound")
        .activation_id
        .clone();
    uncited
        .returns
        .iter_mut()
        .find(|faculty_return| faculty_return.activation_id == honesty_bound)
        .expect("fixture has Honesty bound return")
        .output_refs
        .retain(|output| output != &id("boundary:epistemic"));
    let fault = uncited
        .validate()
        .expect_err("bound return must cite its boundary");
    assert!(fault.message.contains("Honesty bound return"));
}

#[test]
fn combinatory_projections_must_match_projector_and_return() {
    let mut missing = semantic_cycle();
    missing
        .projections
        .retain(|projection| projection.kind != ProjectionKind::Temporal);
    let fault = missing
        .validate()
        .expect_err("active Planner must emit temporal potential");
    assert!(fault.message.contains("active Planner"));

    let mut mismatched = semantic_cycle();
    mismatched.projections[0].projected_by = FacultyKind::Planner;
    let fault = mismatched
        .validate()
        .expect_err("projection kind must match projector");
    assert!(
        fault
            .message
            .contains("relational projection requires Weaver")
    );
}

#[test]
fn machine_form_rejects_unknown_fields() {
    let cycle = semantic_cycle();
    let mut value = serde_json::to_value(cycle).expect("cycle must encode");
    value
        .as_object_mut()
        .expect("cycle must encode as an object")
        .insert("unrecognized".to_owned(), serde_json::Value::Bool(true));
    let fault = serde_json::from_value::<FacultyCycle>(value)
        .expect_err("unknown faculty-cycle fields must be rejected");
    assert!(fault.to_string().contains("unknown field"));
}
