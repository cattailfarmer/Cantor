//! Pure seven-faculty Judgment gate for proposed accountable-object admission.
//!
//! This module validates supplied records. It does not run a model, establish
//! external truth, persist a journal, or authorize an effect.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{
    AccountableObject, IdentityLedger, SharedAttentionFault, SharedAttentionFaultCode,
    insert_admitted_accountable_object, validate_accountable_object, validate_identity_ledger,
};
use crate::procedure_runtime::empty_sha256;
use crate::{
    ALL_FACULTIES, ContentDigest, FacultyCycle, FacultyCycleKind, FacultyKind, FacultyReturnStatus,
    ObserverDisposition, SemanticId,
};

use super::runtime::digest;

pub const ACCOUNTABLE_OBJECT_ADMISSION_PROFILE: &str = "cantor-accountable-object-admission/0.1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountableObjectAdmission {
    pub profile: String,
    pub admission_id: SemanticId,
    pub expected_ledger_digest: ContentDigest,
    pub candidate: AccountableObject,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub faculty_cycle: FacultyCycle,
    pub admission_digest: ContentDigest,
}

pub fn finalize_accountable_object_admission(
    mut admission: AccountableObjectAdmission,
) -> Result<AccountableObjectAdmission, SharedAttentionFault> {
    admission.admission_digest = empty_sha256();
    validate_admission_body(&admission)?;
    admission.admission_digest = admission_digest(&admission)?;
    validate_accountable_object_admission(&admission)?;
    Ok(admission)
}

pub fn validate_accountable_object_admission(
    admission: &AccountableObjectAdmission,
) -> Result<(), SharedAttentionFault> {
    validate_admission_body(admission)?;
    if admission.admission_digest != admission_digest(admission)? {
        return Err(admission_fault(
            SharedAttentionFaultCode::InvalidDigest,
            "accountable object admission digest differs from canonical content",
            Some(admission.admission_id.clone()),
        ));
    }
    Ok(())
}

pub fn admit_accountable_object(
    ledger: &IdentityLedger,
    admission: &AccountableObjectAdmission,
) -> Result<IdentityLedger, SharedAttentionFault> {
    validate_identity_ledger(ledger)?;
    validate_accountable_object_admission(admission)?;
    if admission.expected_ledger_digest != ledger.ledger_digest {
        return Err(admission_fault(
            SharedAttentionFaultCode::StaleLedger,
            "accountable object admission is bound to a stale identity ledger",
            Some(admission.admission_id.clone()),
        ));
    }
    if ledger.objects.contains_key(&admission.candidate.handle) {
        return Err(admission_fault(
            SharedAttentionFaultCode::DuplicateIdentity,
            "accountable object admission proposes an existing exact handle",
            Some(admission.candidate.handle.clone()),
        ));
    }
    insert_admitted_accountable_object(ledger, admission.candidate.clone())
}

pub fn accounting_ledger_state_ref(
    ledger_digest: &ContentDigest,
) -> Result<SemanticId, SharedAttentionFault> {
    SemanticId::new(format!(
        "ledger:{}/{}",
        ledger_digest.algorithm, ledger_digest.value
    ))
    .map_err(|error| {
        admission_fault(
            SharedAttentionFaultCode::InvalidLedger,
            format!("ledger digest cannot form a semantic state reference: {error}"),
            None,
        )
    })
}

fn validate_admission_body(
    admission: &AccountableObjectAdmission,
) -> Result<(), SharedAttentionFault> {
    if admission.profile != ACCOUNTABLE_OBJECT_ADMISSION_PROFILE {
        return Err(admission_fault(
            SharedAttentionFaultCode::InvalidTransition,
            "accountable object admission profile is not supported",
            Some(admission.admission_id.clone()),
        ));
    }
    validate_accountable_object(&admission.candidate)?;
    if admission.candidate.version != 1 {
        return Err(admission_fault(
            SharedAttentionFaultCode::InvalidTransition,
            "new accountable object candidate must begin at version one",
            Some(admission.candidate.handle.clone()),
        ));
    }
    if admission.evidence_refs.is_empty()
        || admission.evidence_refs != admission.candidate.provenance_refs
    {
        return Err(admission_fault(
            SharedAttentionFaultCode::EpistemicBoundary,
            "admission evidence must be nonempty and exactly match candidate provenance",
            Some(admission.candidate.handle.clone()),
        ));
    }
    admission.faculty_cycle.validate().map_err(|error| {
        admission_fault(
            SharedAttentionFaultCode::InvalidTransition,
            format!("faculty cycle is invalid: {}", error.message),
            Some(admission.faculty_cycle.cycle_id.clone()),
        )
    })?;
    if admission.faculty_cycle.kind != FacultyCycleKind::SemanticTransition
        || !admission.faculty_cycle.omissions.is_empty()
    {
        return Err(admission_fault(
            SharedAttentionFaultCode::UnauthorizedFaculty,
            "identity admission requires a semantic transition with no faculty omission",
            Some(admission.faculty_cycle.cycle_id.clone()),
        ));
    }
    let active = admission
        .faculty_cycle
        .activations
        .iter()
        .map(|activation| activation.faculty)
        .collect::<BTreeSet<FacultyKind>>();
    if active != ALL_FACULTIES.into_iter().collect() {
        return Err(admission_fault(
            SharedAttentionFaultCode::UnauthorizedFaculty,
            "identity admission requires all seven faculties",
            Some(admission.faculty_cycle.cycle_id.clone()),
        ));
    }
    let expected_before = accounting_ledger_state_ref(&admission.expected_ledger_digest)?;
    if admission.faculty_cycle.subject != admission.candidate.handle.as_str()
        || admission.faculty_cycle.before_state_ref != expected_before
        || admission.faculty_cycle.after_state_ref != admission.candidate.handle
    {
        return Err(admission_fault(
            SharedAttentionFaultCode::InvalidTransition,
            "faculty cycle subject or state bindings differ from the admission candidate and ledger",
            Some(admission.admission_id.clone()),
        ));
    }
    if admission.faculty_cycle.observer_disposition != ObserverDisposition::Admit {
        return Err(admission_fault(
            SharedAttentionFaultCode::UnresolvedChallenge,
            "Observer disposition does not admit the candidate",
            Some(admission.admission_id.clone()),
        ));
    }
    if admission.faculty_cycle.returns.iter().any(|returned| {
        returned.status != FacultyReturnStatus::Accepted
            || !returned.objections.is_empty()
            || !returned.uncertainty.is_empty()
    }) || !admission.faculty_cycle.residuals.is_empty()
    {
        return Err(admission_fault(
            SharedAttentionFaultCode::UnresolvedChallenge,
            "identity admission requires accepted clear returns and no residual",
            Some(admission.admission_id.clone()),
        ));
    }
    Ok(())
}

fn admission_digest(
    admission: &AccountableObjectAdmission,
) -> Result<ContentDigest, SharedAttentionFault> {
    let mut body = admission.clone();
    body.admission_digest = empty_sha256();
    digest(&body, "accountable object admission")
}

fn admission_fault(
    code: SharedAttentionFaultCode,
    message: impl Into<String>,
    subject: Option<SemanticId>,
) -> SharedAttentionFault {
    let fault = SharedAttentionFault::new(code, message);
    match subject {
        Some(subject) => fault.with_subject(subject),
        None => fault,
    }
}
