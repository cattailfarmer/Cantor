use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{EvaluationFault, FaultKind, SemanticId};

pub const ALL_FACULTIES: [FacultyKind; 7] = [
    FacultyKind::Observer,
    FacultyKind::Honesty,
    FacultyKind::Security,
    FacultyKind::Scribe,
    FacultyKind::Refiner,
    FacultyKind::Planner,
    FacultyKind::Weaver,
];

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FacultyKind {
    Observer,
    Honesty,
    Security,
    Scribe,
    Refiner,
    Planner,
    Weaver,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub enum FacultyStage {
    Observe,
    Anchor,
    Bound,
    Project,
    Refine,
    Gate,
    Decide,
    Inscribe,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub enum FacultyCycleKind {
    Preservation,
    SemanticTransition,
    EffectProposal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub enum FacultyReturnStatus {
    Accepted,
    Qualified,
    Rejected,
    NoGain,
    Blocked,
    Unresolved,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub enum ObserverDisposition {
    Admit,
    Revise,
    Reroute,
    Decompose,
    Block,
    Escalate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub enum IdentityBoundaryDomain {
    Semantic,
    Epistemic,
    Authority,
    SubjectScope,
    Resource,
    Disclosure,
    Mutation,
    Effect,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub enum ProjectionKind {
    Relational,
    Temporal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub enum ProjectionStatus {
    Candidate,
    Incompatible,
    Unreachable,
    Blocked,
    Unresolved,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct IdentityBoundary {
    pub boundary_id: SemanticId,
    pub domain: IdentityBoundaryDomain,
    pub guarded_by: FacultyKind,
    pub subject_ref: SemanticId,
    pub inside: Vec<String>,
    pub edge_conditions: Vec<String>,
    pub outside: Vec<String>,
    pub uncertainty: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct CombinatoryProjection {
    pub projection_id: SemanticId,
    pub kind: ProjectionKind,
    pub projected_by: FacultyKind,
    pub status: ProjectionStatus,
    pub basis_refs: Vec<SemanticId>,
    pub candidate_refs: Vec<SemanticId>,
    pub constraint_refs: Vec<String>,
    pub residuals: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct FacultyLedger {
    pub source_refs: Vec<String>,
    pub grounds: Vec<String>,
    pub constraint_refs: Vec<String>,
    pub retained_boundaries: Vec<String>,
    pub relation_refs: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct FacultyActivation {
    pub activation_id: SemanticId,
    pub faculty: FacultyKind,
    pub stage: FacultyStage,
    pub ordinal: u32,
    pub purpose: String,
    pub input_refs: Vec<SemanticId>,
    pub unavailable_refs: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct FacultyReturn {
    pub activation_id: SemanticId,
    pub faculty: FacultyKind,
    pub status: FacultyReturnStatus,
    pub output_refs: Vec<SemanticId>,
    pub objections: Vec<String>,
    pub uncertainty: Vec<String>,
    pub ledger: FacultyLedger,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct FacultyOmission {
    pub faculty: FacultyKind,
    pub reason: String,
    pub authority: String,
    pub observer_accepted: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct FacultyCycle {
    pub cycle_id: SemanticId,
    pub kind: FacultyCycleKind,
    pub subject: String,
    pub purpose: String,
    pub before_state_ref: SemanticId,
    pub identity_boundaries: Vec<IdentityBoundary>,
    pub projections: Vec<CombinatoryProjection>,
    pub activations: Vec<FacultyActivation>,
    pub returns: Vec<FacultyReturn>,
    pub omissions: Vec<FacultyOmission>,
    pub observer_disposition: ObserverDisposition,
    pub after_state_ref: SemanticId,
    pub residuals: Vec<String>,
}

impl FacultyCycle {
    pub fn validate(&self) -> Result<(), EvaluationFault> {
        require_text("subject", &self.subject)?;
        require_text("purpose", &self.purpose)?;
        if self.activations.is_empty() {
            return Err(review_fault("faculty cycle has no activations"));
        }

        let mut activation_by_id = BTreeMap::new();
        let mut active_faculties = BTreeSet::new();
        let mut ordinals = BTreeSet::new();
        let mut previous_ordinal = None;
        for activation in &self.activations {
            require_text("activation purpose", &activation.purpose)?;
            if activation.ordinal == 0 {
                return Err(review_fault("faculty activation ordinal must be nonzero"));
            }
            if let Some(previous) = previous_ordinal
                && activation.ordinal <= previous
            {
                return Err(review_fault(
                    "faculty activations must be stored in strictly increasing ordinal order",
                ));
            }
            previous_ordinal = Some(activation.ordinal);
            if !ordinals.insert(activation.ordinal) {
                return Err(review_fault("faculty activation ordinal is duplicated"));
            }
            if activation_by_id
                .insert(activation.activation_id.clone(), activation.faculty)
                .is_some()
            {
                return Err(review_fault("faculty activation identity is duplicated"));
            }
            active_faculties.insert(activation.faculty);
        }

        let mut omitted_faculties = BTreeSet::new();
        for omission in &self.omissions {
            require_text("faculty omission reason", &omission.reason)?;
            require_text("faculty omission authority", &omission.authority)?;
            if !omission.observer_accepted {
                return Err(review_fault("faculty omission lacks Observer acceptance"));
            }
            if !omitted_faculties.insert(omission.faculty) {
                return Err(review_fault("faculty omission is duplicated"));
            }
            if active_faculties.contains(&omission.faculty) {
                return Err(review_fault(
                    "one faculty cannot be both activated and omitted",
                ));
            }
        }

        for faculty in ALL_FACULTIES {
            if !active_faculties.contains(&faculty) && !omitted_faculties.contains(&faculty) {
                return Err(review_fault(format!(
                    "faculty {faculty:?} is neither activated nor explicitly omitted"
                )));
            }
        }

        for faculty in [
            FacultyKind::Observer,
            FacultyKind::Honesty,
            FacultyKind::Security,
            FacultyKind::Scribe,
            FacultyKind::Refiner,
        ] {
            require_active(&active_faculties, faculty)?;
        }
        if matches!(
            self.kind,
            FacultyCycleKind::SemanticTransition | FacultyCycleKind::EffectProposal
        ) {
            require_active(&active_faculties, FacultyKind::Planner)?;
            require_active(&active_faculties, FacultyKind::Weaver)?;
        }

        let mut returns_by_id = BTreeMap::new();
        for faculty_return in &self.returns {
            if returns_by_id
                .insert(faculty_return.activation_id.clone(), faculty_return)
                .is_some()
            {
                return Err(review_fault("faculty activation has more than one return"));
            }
            let Some(expected_faculty) = activation_by_id.get(&faculty_return.activation_id) else {
                return Err(review_fault("faculty return has no matching activation"));
            };
            if *expected_faculty != faculty_return.faculty {
                return Err(review_fault(
                    "faculty return does not match its activation faculty",
                ));
            }
        }
        if returns_by_id.len() != activation_by_id.len()
            || activation_by_id
                .keys()
                .any(|activation_id| !returns_by_id.contains_key(activation_id))
        {
            return Err(review_fault(
                "every faculty activation must have exactly one return",
            ));
        }

        let observe = require_stage(self, FacultyKind::Observer, FacultyStage::Observe)?;
        let anchor = require_stage(self, FacultyKind::Scribe, FacultyStage::Anchor)?;
        let honesty_bound_activation =
            require_stage_activation(self, FacultyKind::Honesty, FacultyStage::Bound)?;
        let security_bound_activation =
            require_stage_activation(self, FacultyKind::Security, FacultyStage::Bound)?;
        let honesty_bound = honesty_bound_activation.ordinal;
        let security_bound = security_bound_activation.ordinal;
        let refine = require_stage(self, FacultyKind::Refiner, FacultyStage::Refine)?;
        let honesty_gate = require_stage(self, FacultyKind::Honesty, FacultyStage::Gate)?;
        let security_gate = require_stage(self, FacultyKind::Security, FacultyStage::Gate)?;
        let decide = require_stage(self, FacultyKind::Observer, FacultyStage::Decide)?;
        let inscribe = require_stage(self, FacultyKind::Scribe, FacultyStage::Inscribe)?;

        let mut boundary_ids = BTreeSet::new();
        let mut honesty_boundary_ids = BTreeSet::new();
        let mut security_boundary_ids = BTreeSet::new();
        for boundary in &self.identity_boundaries {
            if !boundary_ids.insert(boundary.boundary_id.clone()) {
                return Err(review_fault("identity boundary is duplicated"));
            }
            if boundary.inside.is_empty() || boundary.edge_conditions.is_empty() {
                return Err(review_fault(
                    "identity boundary requires inside material and edge conditions",
                ));
            }
            let expected_guardian = match boundary.domain {
                IdentityBoundaryDomain::Semantic | IdentityBoundaryDomain::Epistemic => {
                    FacultyKind::Honesty
                }
                IdentityBoundaryDomain::Authority
                | IdentityBoundaryDomain::SubjectScope
                | IdentityBoundaryDomain::Resource
                | IdentityBoundaryDomain::Disclosure
                | IdentityBoundaryDomain::Mutation
                | IdentityBoundaryDomain::Effect => FacultyKind::Security,
            };
            if boundary.guarded_by != expected_guardian {
                return Err(review_fault(
                    "identity boundary is assigned to the wrong guardian faculty",
                ));
            }
            match boundary.guarded_by {
                FacultyKind::Honesty => {
                    honesty_boundary_ids.insert(boundary.boundary_id.clone());
                }
                FacultyKind::Security => {
                    security_boundary_ids.insert(boundary.boundary_id.clone());
                }
                _ => {
                    return Err(review_fault(
                        "only Honesty or Security may guard an identity boundary",
                    ));
                }
            }
        }
        if honesty_boundary_ids.is_empty() || security_boundary_ids.is_empty() {
            return Err(review_fault(
                "faculty cycle requires Honesty-guarded and Security-guarded identity boundaries",
            ));
        }
        require_return_outputs(
            &returns_by_id,
            honesty_bound_activation,
            &honesty_boundary_ids,
            "Honesty bound return must cite every Honesty identity boundary",
        )?;
        require_return_outputs(
            &returns_by_id,
            security_bound_activation,
            &security_boundary_ids,
            "Security bound return must cite every Security identity boundary",
        )?;

        let first_specialist = self
            .activations
            .iter()
            .filter(|activation| {
                !(activation.faculty == FacultyKind::Observer
                    && activation.stage == FacultyStage::Observe)
            })
            .map(|activation| activation.ordinal)
            .min()
            .ok_or_else(|| review_fault("faculty cycle has no specialist activation"))?;
        if observe >= first_specialist {
            return Err(review_fault(
                "Observer observe must precede every specialist activation",
            ));
        }
        if !(observe < anchor
            && anchor < honesty_bound
            && anchor < security_bound
            && honesty_bound < refine
            && security_bound < refine
            && refine < honesty_gate
            && refine < security_gate
            && honesty_gate < decide
            && security_gate < decide
            && decide < inscribe)
        {
            return Err(review_fault(
                "faculty cycle violates anchor, boundary, refine, gate, decide, and inscribe order",
            ));
        }

        let mut projection_ids = BTreeSet::new();
        let mut relational_projection_ids = BTreeSet::new();
        let mut temporal_projection_ids = BTreeSet::new();
        for projection in &self.projections {
            if !projection_ids.insert(projection.projection_id.clone()) {
                return Err(review_fault("combinatory projection is duplicated"));
            }
            if projection.basis_refs.is_empty() {
                return Err(review_fault(
                    "combinatory projection requires at least one basis reference",
                ));
            }
            if projection.status == ProjectionStatus::Candidate
                && projection.candidate_refs.is_empty()
            {
                return Err(review_fault(
                    "candidate combinatory projection requires a candidate reference",
                ));
            }
            if projection.status != ProjectionStatus::Candidate && projection.residuals.is_empty() {
                return Err(review_fault(
                    "non-candidate combinatory projection requires an explanatory residual",
                ));
            }
            match (projection.kind, projection.projected_by) {
                (ProjectionKind::Relational, FacultyKind::Weaver) => {
                    relational_projection_ids.insert(projection.projection_id.clone());
                }
                (ProjectionKind::Temporal, FacultyKind::Planner) => {
                    temporal_projection_ids.insert(projection.projection_id.clone());
                }
                _ => {
                    return Err(review_fault(
                        "relational projection requires Weaver and temporal projection requires Planner",
                    ));
                }
            }
        }

        if active_faculties.contains(&FacultyKind::Weaver) {
            let projection_activation =
                require_stage_activation(self, FacultyKind::Weaver, FacultyStage::Project)?;
            let projection = projection_activation.ordinal;
            if !(honesty_bound < projection && security_bound < projection && projection < refine) {
                return Err(review_fault(
                    "Weaver projection must occur inside guarded boundaries and before refine",
                ));
            }
            if relational_projection_ids.is_empty() {
                return Err(review_fault(
                    "active Weaver must emit a relational combinatory projection",
                ));
            }
            require_return_outputs(
                &returns_by_id,
                projection_activation,
                &relational_projection_ids,
                "Weaver project return must cite every relational projection",
            )?;
        }
        if active_faculties.contains(&FacultyKind::Planner) {
            let projection_activation =
                require_stage_activation(self, FacultyKind::Planner, FacultyStage::Project)?;
            let projection = projection_activation.ordinal;
            if !(honesty_bound < projection && security_bound < projection && projection < refine) {
                return Err(review_fault(
                    "Planner projection must occur inside guarded boundaries and before refine",
                ));
            }
            if temporal_projection_ids.is_empty() {
                return Err(review_fault(
                    "active Planner must emit a temporal combinatory projection",
                ));
            }
            require_return_outputs(
                &returns_by_id,
                projection_activation,
                &temporal_projection_ids,
                "Planner project return must cite every temporal projection",
            )?;
        }
        if self
            .activations
            .iter()
            .any(|activation| activation.ordinal > inscribe)
        {
            return Err(review_fault(
                "Scribe inscription must be the final faculty activation",
            ));
        }

        Ok(())
    }
}

fn require_text(field: &str, value: &str) -> Result<(), EvaluationFault> {
    if value.trim().is_empty() {
        Err(review_fault(format!("{field} must not be empty")))
    } else {
        Ok(())
    }
}

fn require_active(
    active_faculties: &BTreeSet<FacultyKind>,
    faculty: FacultyKind,
) -> Result<(), EvaluationFault> {
    if active_faculties.contains(&faculty) {
        Ok(())
    } else {
        Err(review_fault(format!(
            "faculty {faculty:?} is constitutionally required for this cycle"
        )))
    }
}

fn require_stage(
    cycle: &FacultyCycle,
    faculty: FacultyKind,
    stage: FacultyStage,
) -> Result<u32, EvaluationFault> {
    Ok(require_stage_activation(cycle, faculty, stage)?.ordinal)
}

fn require_stage_activation(
    cycle: &FacultyCycle,
    faculty: FacultyKind,
    stage: FacultyStage,
) -> Result<&FacultyActivation, EvaluationFault> {
    let mut matching = cycle
        .activations
        .iter()
        .filter(|activation| activation.faculty == faculty && activation.stage == stage);
    let activation = matching.next().ok_or_else(|| {
        review_fault(format!(
            "faculty {faculty:?} is missing required {stage:?} stage"
        ))
    })?;
    if matching.next().is_some() {
        return Err(review_fault(format!(
            "faculty {faculty:?} repeats constitutional {stage:?} stage"
        )));
    }
    Ok(activation)
}

fn require_return_outputs(
    returns_by_id: &BTreeMap<SemanticId, &FacultyReturn>,
    activation: &FacultyActivation,
    required_outputs: &BTreeSet<SemanticId>,
    message: &str,
) -> Result<(), EvaluationFault> {
    let faculty_return = returns_by_id
        .get(&activation.activation_id)
        .ok_or_else(|| review_fault("faculty activation is missing its return"))?;
    if required_outputs
        .iter()
        .all(|required| faculty_return.output_refs.contains(required))
    {
        Ok(())
    } else {
        Err(review_fault(message))
    }
}

fn review_fault(message: impl Into<String>) -> EvaluationFault {
    EvaluationFault::new(FaultKind::ReviewFailure, message)
}
