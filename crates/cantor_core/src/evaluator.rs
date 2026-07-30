use crate::model::{
    ConstraintOutcome, ConstraintRequirement, EffectAuthority, EffectEvent, EffectStatus,
    EvaluationFault, FaultKind, ImportFidelity, Instruction, Judgment, JudgmentStatus,
    SemanticState, SemanticTransition, StateStatus, TransitionTrace,
};

/// Evaluate one observable instruction against an immutable input state.
///
/// Expected semantic non-success is represented inside the transition rather
/// than erased as a Rust error.
pub fn evaluate(
    before: &SemanticState,
    instruction: &Instruction,
    history_review: crate::model::HistoryReviewEvent,
) -> Result<SemanticTransition, EvaluationFault> {
    let transition_id = crate::model::SemanticId::new(format!(
        "transition:{}:{}:{}",
        before.state_id,
        before.budget.transitions_remaining,
        instruction.family().to_ascii_lowercase()
    ))?;
    let mut after = before.clone();
    let mut judgments = Vec::new();
    let mut effect_events = Vec::new();
    let mut faults = Vec::new();
    let mut evidence = Vec::new();
    let mut authority = Vec::new();
    let mut uncertainty = Vec::new();
    let reason;
    let rule = instruction.family().to_owned();

    if after.budget.transitions_remaining == 0 {
        after.status = StateStatus::Blocked;
        faults.push(EvaluationFault::new(
            FaultKind::BudgetExhausted,
            "no semantic transitions remain",
        ));
        reason = "transition blocked by the declared attention budget".to_owned();
    } else {
        after.budget.transitions_remaining -= 1;
        after.status = StateStatus::Running;

        match instruction {
            Instruction::Declare { unit } => {
                let id = unit.unit_id.clone();
                let mut labels = unit.aliases.clone();
                labels.insert(unit.expression.clone());
                for label in labels {
                    after
                        .environment
                        .labels
                        .entry(label.to_ascii_lowercase())
                        .or_default()
                        .insert(id.clone());
                }
                after.environment.units.insert(id.clone(), unit.clone());
                after.inside.insert(id);
                evidence.extend(unit.source_set.clone());
                judgments.push(Judgment {
                    status: JudgmentStatus::Asserted,
                    claim: format!("declared {}", unit.unit_id),
                    grounds: unit.source_set.clone(),
                });
                reason = "identity and meaning were declared without merging labels".to_owned();
            }
            Instruction::Infer {
                conclusion,
                premises,
                rule,
            } => {
                after
                    .environment
                    .units
                    .insert(conclusion.unit_id.clone(), conclusion.clone());
                after.inside.insert(conclusion.unit_id.clone());
                after.evidence.extend(premises.clone());
                evidence.extend(premises.clone());
                judgments.push(Judgment {
                    status: JudgmentStatus::Inferred,
                    claim: conclusion.meaning.clone(),
                    grounds: premises
                        .iter()
                        .cloned()
                        .chain(std::iter::once(format!("rule:{rule}")))
                        .collect(),
                });
                reason = format!("conclusion derived under named rule {rule}");
            }
            Instruction::ValidateConstraint {
                name,
                observed,
                requirement,
            } => {
                let outcome = validate_constraint(observed.as_deref(), requirement);
                match outcome {
                    ConstraintOutcome::Valid => {
                        judgments.push(Judgment {
                            status: JudgmentStatus::Validated,
                            claim: format!("constraint {name} satisfied"),
                            grounds: observed.iter().cloned().collect(),
                        });
                        reason = "known value satisfied the declared constraint".to_owned();
                    }
                    ConstraintOutcome::Unknown => {
                        let message = format!("constraint {name} cannot be decided: value unknown");
                        after.uncertainty.push(message.clone());
                        uncertainty.push(message.clone());
                        faults.push(EvaluationFault::new(
                            FaultKind::UnknownKnowledge,
                            message.clone(),
                        ));
                        judgments.push(Judgment {
                            status: JudgmentStatus::Unknown,
                            claim: message,
                            grounds: vec!["observed:none".to_owned()],
                        });
                        reason = "missing knowledge remained distinct from invalidity".to_owned();
                    }
                    ConstraintOutcome::Invalid => {
                        let message = format!("constraint {name} rejected known value");
                        faults.push(EvaluationFault::new(
                            FaultKind::ConstraintViolation,
                            message.clone(),
                        ));
                        judgments.push(Judgment {
                            status: JudgmentStatus::Invalid,
                            claim: message,
                            grounds: observed.iter().cloned().collect(),
                        });
                        reason = "known value violated the declared constraint".to_owned();
                    }
                }
            }
            Instruction::TransformAdd {
                target,
                left,
                right,
            } => {
                let result = left.checked_add(*right).ok_or_else(|| {
                    EvaluationFault::new(
                        FaultKind::ConstraintViolation,
                        "integer addition overflowed",
                    )
                })?;
                after.values.insert(target.clone(), result);
                judgments.push(Judgment {
                    status: JudgmentStatus::Validated,
                    claim: format!("{target} = {result}"),
                    grounds: vec![format!("{left} + {right}")],
                });
                reason = "pure transformation changed semantic state without an effect".to_owned();
            }
            Instruction::ProposeEffect {
                effect_id,
                description,
                authority: effect_authority,
            } => match effect_authority {
                EffectAuthority::Denied { reason: denial } => {
                    let event = EffectEvent {
                        effect_id: effect_id.clone(),
                        description: description.clone(),
                        status: EffectStatus::Denied,
                        authority: denial.clone(),
                    };
                    effect_events.push(event);
                    faults.push(EvaluationFault::new(
                        FaultKind::UnauthorizedEffect,
                        denial.clone(),
                    ));
                    judgments.push(Judgment {
                        status: JudgmentStatus::Denied,
                        claim: format!("effect {effect_id} denied"),
                        grounds: vec![denial.clone()],
                    });
                    authority.push(denial.clone());
                    reason = "effect remained uncommitted because authority was denied".to_owned();
                }
                EffectAuthority::Authorized { grant } => {
                    if after.budget.effects_remaining == 0 {
                        faults.push(EvaluationFault::new(
                            FaultKind::BudgetExhausted,
                            "no effect proposals remain",
                        ));
                        after.status = StateStatus::Blocked;
                        reason = "authorized effect was blocked by the effect budget".to_owned();
                    } else {
                        after.budget.effects_remaining -= 1;
                        let event = EffectEvent {
                            effect_id: effect_id.clone(),
                            description: description.clone(),
                            status: EffectStatus::Authorized,
                            authority: grant.clone(),
                        };
                        after.pending_effects.push(event.clone());
                        effect_events.push(event);
                        judgments.push(Judgment {
                            status: JudgmentStatus::Authorized,
                            claim: format!("effect {effect_id} authorized but not committed"),
                            grounds: vec![grant.clone()],
                        });
                        authority.push(grant.clone());
                        reason = "effect was authorized and queued without external commitment"
                            .to_owned();
                    }
                }
            },
            Instruction::Yield => {
                after.status = StateStatus::Yielded;
                judgments.push(Judgment {
                    status: JudgmentStatus::Validated,
                    claim: "state yielded at an explicit control boundary".to_owned(),
                    grounds: vec!["CONTROL:YIELD".to_owned()],
                });
                reason = "execution yielded with a serializable committed state".to_owned();
            }
            Instruction::Reenter { restored_state } => {
                if restored_state.status != StateStatus::Yielded
                    || restored_state.as_ref() != before
                {
                    faults.push(EvaluationFault::new(
                        FaultKind::InvalidReentry,
                        "reentry requires the exact current state committed at yield",
                    ));
                    after.status = StateStatus::Faulted;
                    reason = "reentry rejected a non-yielded or non-identical state".to_owned();
                } else {
                    after = restored_state.as_ref().clone();
                    after.budget.transitions_remaining -= 1;
                    after.status = StateStatus::Ready;
                    judgments.push(Judgment {
                        status: JudgmentStatus::Validated,
                        claim: "yielded state restored for exact reentry".to_owned(),
                        grounds: vec![restored_state.state_id.to_string()],
                    });
                    reason =
                        "serialized yielded state restored before execution resumed".to_owned();
                }
            }
            Instruction::ImportOntology { import } => {
                after.environment.relations.push(import.relation.clone());
                evidence.push(import.source_construct.clone());
                match &import.fidelity {
                    ImportFidelity::Exact => {
                        judgments.push(Judgment {
                            status: JudgmentStatus::Validated,
                            claim: format!(
                                "{:?} construct imported with exact declared relation fidelity",
                                import.standard
                            ),
                            grounds: vec![import.source_construct.clone()],
                        });
                        reason =
                            "formal source semantics and native relation stayed linked".to_owned();
                    }
                    ImportFidelity::Partial { loss_notes } => {
                        uncertainty.extend(loss_notes.clone());
                        faults.push(EvaluationFault::new(
                            FaultKind::SemanticLoss,
                            "ontology import contains declared semantic loss",
                        ));
                        reason = "partial import preserved its loss declaration".to_owned();
                    }
                    ImportFidelity::Rejected { reason: rejection } => {
                        faults.push(EvaluationFault::new(
                            FaultKind::SemanticLoss,
                            rejection.clone(),
                        ));
                        after.environment.relations.pop();
                        reason =
                            "ontology import was rejected instead of silently weakened".to_owned();
                    }
                }
            }
        }
    }

    if after.status == StateStatus::Running {
        after.status = StateStatus::Ready;
    }

    Ok(SemanticTransition {
        transition_id,
        before_state: before.clone(),
        history_review,
        instruction: instruction.clone(),
        judgments,
        after_state: after,
        effect_events,
        faults,
        trace: TransitionTrace {
            source: "SOP_Core.CoreAcceptance".to_owned(),
            rule,
            reason,
            evidence,
            authority,
            uncertainty,
        },
    })
}

fn validate_constraint(
    observed: Option<&str>,
    requirement: &ConstraintRequirement,
) -> ConstraintOutcome {
    let Some(observed) = observed else {
        return ConstraintOutcome::Unknown;
    };
    let valid = match requirement {
        ConstraintRequirement::Present => true,
        ConstraintRequirement::NonEmpty => !observed.is_empty(),
        ConstraintRequirement::Equals(expected) => observed == expected,
    };
    if valid {
        ConstraintOutcome::Valid
    } else {
        ConstraintOutcome::Invalid
    }
}
