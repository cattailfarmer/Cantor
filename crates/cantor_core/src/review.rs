use serde::{Deserialize, Serialize};

use crate::machine::content_digest;
use crate::model::{
    ContentDigest, EvaluationFault, FaultKind, HistoryDecision, HistoryReviewEvent, ProofAssertion,
    SemanticId, SemanticProgram, SemanticState, SemanticTransition,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceCapsule {
    pub capsule_id: SemanticId,
    pub input_snapshot: String,
    pub purpose_contract: String,
    pub program_snapshot: SemanticProgram,
    pub entry_state: SemanticState,
    pub execution_trace: Vec<SemanticTransition>,
    pub candidate_response: String,
    pub claim_ledger: Vec<ProofAssertion>,
    pub exit_state: SemanticState,
    pub provider_record: String,
    pub projection_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingSeverity {
    Note,
    Warning,
    Error,
    Blocking,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewFinding {
    pub location: String,
    pub severity: FindingSeverity,
    pub claim: String,
    pub support: Vec<String>,
    pub recommended_action: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReviewVerdict {
    Accept,
    ConditionalAccept,
    Revise,
    Reject,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewReport {
    pub review_program_version: String,
    pub capsule_digest: ContentDigest,
    pub findings: Vec<ReviewFinding>,
    pub surviving_claims: Vec<String>,
    pub unresolved: Vec<String>,
    pub verdict: ReviewVerdict,
    pub confidence_boundary: String,
}

pub fn no_match_history_review(
    fixture: &str,
    sequence: usize,
    state: &SemanticState,
    operation: &str,
) -> Result<HistoryReviewEvent, EvaluationFault> {
    let projection: Vec<String> = Vec::new();
    Ok(HistoryReviewEvent {
        review_id: SemanticId::new(format!("history:{fixture}:{sequence}"))?,
        current_subject: state
            .focus
            .as_ref()
            .map_or_else(|| fixture.to_owned(), ToString::to_string),
        current_purpose: state.purpose.clone(),
        current_operation: operation.to_owned(),
        candidate_count: 0,
        selected_records: projection.clone(),
        counterevidence_records: Vec::new(),
        excluded_summary: Vec::new(),
        coverage_statement: "fixture-local history searched; no pertinent prior record".to_owned(),
        projection_digest: content_digest(&projection)?,
        reconciliation: "no_pertinent_history; present input and purpose govern".to_owned(),
        transition_decision: HistoryDecision::Continue,
    })
}

pub fn build_capsule(
    fixture: &str,
    input_snapshot: &str,
    program: SemanticProgram,
    entry_state: SemanticState,
    transitions: Vec<SemanticTransition>,
    candidate_response: String,
    proof: Vec<ProofAssertion>,
) -> Result<InferenceCapsule, EvaluationFault> {
    let exit_state = transitions
        .last()
        .map(|transition| transition.after_state.clone())
        .unwrap_or_else(|| entry_state.clone());
    let projection_digest = content_digest(&transitions)?;
    Ok(InferenceCapsule {
        capsule_id: SemanticId::new(format!("capsule:{fixture}"))?,
        input_snapshot: input_snapshot.to_owned(),
        purpose_contract: program.purpose.clone(),
        program_snapshot: program,
        entry_state,
        execution_trace: transitions,
        candidate_response,
        claim_ledger: proof,
        exit_state,
        provider_record: "cantor_core deterministic evaluator; no model provider".to_owned(),
        projection_digest,
    })
}

pub fn review_capsule(capsule: &InferenceCapsule) -> Result<ReviewReport, EvaluationFault> {
    let mut findings = Vec::new();

    if capsule.execution_trace.is_empty() {
        findings.push(ReviewFinding {
            location: "execution_trace".to_owned(),
            severity: FindingSeverity::Blocking,
            claim: "capsule contains no observable transition".to_owned(),
            support: vec![capsule.capsule_id.to_string()],
            recommended_action: "revise".to_owned(),
        });
    }
    if capsule
        .execution_trace
        .iter()
        .any(|transition| transition.trace.reason.is_empty())
    {
        findings.push(ReviewFinding {
            location: "execution_trace".to_owned(),
            severity: FindingSeverity::Error,
            claim: "one or more transitions omit a decision reason".to_owned(),
            support: vec![capsule.capsule_id.to_string()],
            recommended_action: "revise".to_owned(),
        });
    }
    if capsule
        .execution_trace
        .iter()
        .any(|transition| transition.history_review.coverage_statement.is_empty())
    {
        findings.push(ReviewFinding {
            location: "attention_program".to_owned(),
            severity: FindingSeverity::Error,
            claim: "one or more material transitions omit history-review coverage".to_owned(),
            support: vec![capsule.capsule_id.to_string()],
            recommended_action: "revise".to_owned(),
        });
    }
    if capsule.claim_ledger.iter().any(|proof| !proof.passed) {
        findings.push(ReviewFinding {
            location: "candidate_response".to_owned(),
            severity: FindingSeverity::Blocking,
            claim: "one or more declared proof assertions failed".to_owned(),
            support: capsule
                .claim_ledger
                .iter()
                .filter(|proof| !proof.passed)
                .map(|proof| proof.claim.clone())
                .collect(),
            recommended_action: "reject".to_owned(),
        });
    }

    let verdict = if findings
        .iter()
        .any(|finding| finding.severity == FindingSeverity::Blocking)
    {
        ReviewVerdict::Reject
    } else if findings.is_empty() {
        ReviewVerdict::Accept
    } else {
        ReviewVerdict::Revise
    };
    let digest = content_digest(capsule)?;

    if matches!(verdict, ReviewVerdict::Reject) {
        return Ok(ReviewReport {
            review_program_version: "core-review/0.1".to_owned(),
            capsule_digest: digest,
            findings,
            surviving_claims: Vec::new(),
            unresolved: vec!["fixture requires correction before acceptance".to_owned()],
            verdict,
            confidence_boundary:
                "review rejection localizes a harness fault; it does not establish external truth"
                    .to_owned(),
        });
    }

    let surviving_claims = capsule
        .claim_ledger
        .iter()
        .filter(|proof| proof.passed)
        .map(|proof| proof.claim.clone())
        .collect();
    Ok(ReviewReport {
        review_program_version: "core-review/0.1".to_owned(),
        capsule_digest: digest,
        findings,
        surviving_claims,
        unresolved: Vec::new(),
        verdict,
        confidence_boundary:
            "passing deterministic review proves fixture conformance, not universal semantic truth"
                .to_owned(),
    })
}

pub fn review_fault(message: impl Into<String>) -> EvaluationFault {
    EvaluationFault::new(FaultKind::ReviewFailure, message)
}
