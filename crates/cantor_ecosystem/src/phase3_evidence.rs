//! Pure machine forms shared by the future Phase 3 mutation, seal, test, and
//! review slices.
//!
//! This module deliberately owns no I/O. It validates caller-supplied values
//! and lifecycle edges, but cannot inspect or change a workspace, launch a
//! process, publish a capsule, execute a test, invoke a model, or promote code.

use std::fmt;

use serde::{Deserialize, Serialize, de::DeserializeOwned};

/// Version of the effect-free Phase 3 machine-form profile.
pub const PHASE3_MACHINE_FORMS_PROFILE: &str = "cantor-phase3-machine-forms/0.1";

const MAX_TEXT_BYTES: usize = 1_024;
const MAX_PROFILE_BYTES: usize = 128;
const MAX_PATH_BYTES: usize = 1_024;
const MAX_EVIDENCE_REFERENCES: usize = 64;

/// Closed validation-fault classes for the pure Phase 3 forms.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase3FormFaultCode {
    Json,
    Digest,
    Text,
    Path,
    Transition,
    Consequence,
    Change,
    Evidence,
}

/// Bounded, typed failure returned before a value becomes admissible.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Phase3FormFault {
    pub code: Phase3FormFaultCode,
    pub field: String,
    pub message: String,
}

impl Phase3FormFault {
    fn new(code: Phase3FormFaultCode, field: &str, message: &str) -> Self {
        Self {
            code,
            field: field.to_owned(),
            message: message.chars().take(MAX_TEXT_BYTES).collect(),
        }
    }
}

impl fmt::Display for Phase3FormFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl std::error::Error for Phase3FormFault {}

/// Semantic validation implemented by every admitted Phase 3 form.
pub trait ValidatePhase3 {
    fn validate(&self) -> Result<(), Phase3FormFault>;
}

/// Strictly decodes JSON and then applies semantic validation.
pub fn decode_phase3_json<T>(bytes: &[u8]) -> Result<T, Phase3FormFault>
where
    T: DeserializeOwned + ValidatePhase3,
{
    let value = serde_json::from_slice::<T>(bytes).map_err(|error| {
        Phase3FormFault::new(Phase3FormFaultCode::Json, "json", &error.to_string())
    })?;
    value.validate()?;
    Ok(value)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase3ArtifactKind {
    TopologyReceipt,
    MutationRun,
    CandidateCapsule,
    CaptureCertificate,
    SupervisorTest,
    IndependentReview,
}

impl ValidatePhase3 for Phase3ArtifactKind {
    fn validate(&self) -> Result<(), Phase3FormFault> {
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactReference {
    pub kind: Phase3ArtifactKind,
    pub profile: String,
    pub sha256: String,
}

impl ValidatePhase3 for ArtifactReference {
    fn validate(&self) -> Result<(), Phase3FormFault> {
        validate_text(
            &self.profile,
            "profile",
            MAX_PROFILE_BYTES,
            Phase3FormFaultCode::Text,
        )?;
        validate_digest(&self.sha256, "sha256")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationStage {
    Prepared,
    Revalidated,
    SandboxReady,
    TurnRunning,
    TurnTerminal,
    HandoffPendingSeal,
    Quarantined,
    Closed,
}

impl ValidatePhase3 for MutationStage {
    fn validate(&self) -> Result<(), Phase3FormFault> {
        Ok(())
    }
}

impl MutationStage {
    pub const ALL: [Self; 8] = [
        Self::Prepared,
        Self::Revalidated,
        Self::SandboxReady,
        Self::TurnRunning,
        Self::TurnTerminal,
        Self::HandoffPendingSeal,
        Self::Quarantined,
        Self::Closed,
    ];
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationTransition {
    pub from: MutationStage,
    pub to: MutationStage,
}

impl ValidatePhase3 for MutationTransition {
    fn validate(&self) -> Result<(), Phase3FormFault> {
        if is_valid_mutation_edge(self.from, self.to) {
            Ok(())
        } else {
            Err(Phase3FormFault::new(
                Phase3FormFaultCode::Transition,
                "mutation_transition",
                "transition is not a declared forward or quarantine edge",
            ))
        }
    }
}

fn is_valid_mutation_edge(from: MutationStage, to: MutationStage) -> bool {
    matches!(
        (from, to),
        (MutationStage::Prepared, MutationStage::Revalidated)
            | (MutationStage::Revalidated, MutationStage::SandboxReady)
            | (MutationStage::SandboxReady, MutationStage::TurnRunning)
            | (MutationStage::TurnRunning, MutationStage::TurnTerminal)
            | (
                MutationStage::TurnTerminal,
                MutationStage::HandoffPendingSeal
            )
            | (MutationStage::HandoffPendingSeal, MutationStage::Closed)
            | (MutationStage::Revalidated, MutationStage::Quarantined)
            | (MutationStage::SandboxReady, MutationStage::Quarantined)
            | (MutationStage::TurnRunning, MutationStage::Quarantined)
            | (MutationStage::TurnTerminal, MutationStage::Quarantined)
            | (
                MutationStage::HandoffPendingSeal,
                MutationStage::Quarantined
            )
            | (MutationStage::Quarantined, MutationStage::Closed)
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SealReviewStage {
    Admitted,
    Quiescing,
    Capturing,
    Publishing,
    Sealed,
    Reconstructing,
    Testing,
    Tested,
    Reviewing,
    Reviewed,
    Quarantined,
    Unresolved,
}

impl ValidatePhase3 for SealReviewStage {
    fn validate(&self) -> Result<(), Phase3FormFault> {
        Ok(())
    }
}

impl SealReviewStage {
    pub const ALL: [Self; 12] = [
        Self::Admitted,
        Self::Quiescing,
        Self::Capturing,
        Self::Publishing,
        Self::Sealed,
        Self::Reconstructing,
        Self::Testing,
        Self::Tested,
        Self::Reviewing,
        Self::Reviewed,
        Self::Quarantined,
        Self::Unresolved,
    ];
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealReviewTransition {
    pub from: SealReviewStage,
    pub to: SealReviewStage,
}

impl ValidatePhase3 for SealReviewTransition {
    fn validate(&self) -> Result<(), Phase3FormFault> {
        if is_valid_seal_review_edge(self.from, self.to) {
            Ok(())
        } else {
            Err(Phase3FormFault::new(
                Phase3FormFaultCode::Transition,
                "seal_review_transition",
                "transition is not a declared forward, quarantine, or unresolved edge",
            ))
        }
    }
}

fn is_valid_seal_review_edge(from: SealReviewStage, to: SealReviewStage) -> bool {
    matches!(
        (from, to),
        (SealReviewStage::Admitted, SealReviewStage::Quiescing)
            | (SealReviewStage::Quiescing, SealReviewStage::Capturing)
            | (SealReviewStage::Capturing, SealReviewStage::Publishing)
            | (SealReviewStage::Publishing, SealReviewStage::Sealed)
            | (SealReviewStage::Sealed, SealReviewStage::Reconstructing)
            | (SealReviewStage::Reconstructing, SealReviewStage::Testing)
            | (SealReviewStage::Testing, SealReviewStage::Tested)
            | (SealReviewStage::Tested, SealReviewStage::Reviewing)
            | (SealReviewStage::Reviewing, SealReviewStage::Reviewed)
            | (SealReviewStage::Quiescing, SealReviewStage::Quarantined)
            | (SealReviewStage::Capturing, SealReviewStage::Quarantined)
            | (SealReviewStage::Publishing, SealReviewStage::Quarantined)
            | (
                SealReviewStage::Reconstructing,
                SealReviewStage::Quarantined
            )
            | (SealReviewStage::Testing, SealReviewStage::Quarantined)
            | (SealReviewStage::Sealed, SealReviewStage::Unresolved)
            | (SealReviewStage::Tested, SealReviewStage::Unresolved)
            | (SealReviewStage::Reviewing, SealReviewStage::Unresolved)
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FaultConsequence {
    pub turn_started: bool,
    pub may_have_mutated: bool,
    pub quarantine_required: bool,
}

impl ValidatePhase3 for FaultConsequence {
    fn validate(&self) -> Result<(), Phase3FormFault> {
        if self.may_have_mutated == self.turn_started
            && self.quarantine_required == self.turn_started
        {
            Ok(())
        } else {
            Err(Phase3FormFault::new(
                Phase3FormFaultCode::Consequence,
                "fault_consequence",
                "post-start faults must preserve possible mutation and quarantine; pre-start faults must not claim mutation",
            ))
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsistencyClass {
    QuiescentDoubleInventory,
    OsSnapshotProven,
}

impl ValidatePhase3 for ConsistencyClass {
    fn validate(&self) -> Result<(), Phase3FormFault> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImmutabilityClass {
    ContentAddressedVerified,
    PlatformEnforced,
}

impl ValidatePhase3 for ImmutabilityClass {
    fn validate(&self) -> Result<(), Phase3FormFault> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateChangeKind {
    Add,
    Modify,
    Delete,
    ModeChange,
}

impl ValidatePhase3 for CandidateChangeKind {
    fn validate(&self) -> Result<(), Phase3FormFault> {
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegularFileEvidence {
    pub mode: String,
    pub length: u64,
    pub sha256: String,
}

impl ValidatePhase3 for RegularFileEvidence {
    fn validate(&self) -> Result<(), Phase3FormFault> {
        validate_text(
            &self.mode,
            "mode",
            MAX_PROFILE_BYTES,
            Phase3FormFaultCode::Text,
        )?;
        validate_digest(&self.sha256, "file_sha256")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidatePathRecord {
    pub relative_path: String,
    pub change_kind: CandidateChangeKind,
    pub base: Option<RegularFileEvidence>,
    pub current: Option<RegularFileEvidence>,
    pub blob_sha256: Option<String>,
}

impl ValidatePhase3 for CandidatePathRecord {
    fn validate(&self) -> Result<(), Phase3FormFault> {
        validate_relative_path(&self.relative_path)?;
        if let Some(base) = &self.base {
            base.validate()?;
        }
        if let Some(current) = &self.current {
            current.validate()?;
        }
        if let Some(blob) = &self.blob_sha256 {
            validate_digest(blob, "blob_sha256")?;
        }

        let shape_is_valid = match self.change_kind {
            CandidateChangeKind::Add => self.base.is_none() && self.current.is_some(),
            CandidateChangeKind::Modify | CandidateChangeKind::ModeChange => {
                self.base.is_some() && self.current.is_some()
            }
            CandidateChangeKind::Delete => self.base.is_some() && self.current.is_none(),
        };
        if !shape_is_valid {
            return Err(Phase3FormFault::new(
                Phase3FormFaultCode::Change,
                "change_kind",
                "base and current evidence do not match the declared change kind",
            ));
        }

        match (&self.current, &self.blob_sha256) {
            (Some(current), Some(blob)) if blob == &current.sha256 => {}
            (None, None) => {}
            _ => {
                return Err(Phase3FormFault::new(
                    Phase3FormFaultCode::Change,
                    "blob_sha256",
                    "blob digest must exist exactly with current content and equal its digest",
                ));
            }
        }

        if let (Some(base), Some(current)) = (&self.base, &self.current) {
            match self.change_kind {
                CandidateChangeKind::Modify
                    if base.length == current.length && base.sha256 == current.sha256 =>
                {
                    return Err(Phase3FormFault::new(
                        Phase3FormFaultCode::Change,
                        "change_kind",
                        "modify evidence does not contain a physical change",
                    ));
                }
                CandidateChangeKind::ModeChange
                    if base.mode == current.mode
                        || base.length != current.length
                        || base.sha256 != current.sha256 =>
                {
                    return Err(Phase3FormFault::new(
                        Phase3FormFaultCode::Change,
                        "change_kind",
                        "mode_change requires equal bytes and a different mode",
                    ));
                }
                _ => {}
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndependentCheckStatus {
    Pass,
    Fail,
    Unknown,
    NotApplicable,
}

impl ValidatePhase3 for IndependentCheckStatus {
    fn validate(&self) -> Result<(), Phase3FormFault> {
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndependentCheck {
    pub check_id: String,
    pub status: IndependentCheckStatus,
    pub evidence: Vec<ArtifactReference>,
    pub reason: String,
}

impl ValidatePhase3 for IndependentCheck {
    fn validate(&self) -> Result<(), Phase3FormFault> {
        validate_identifier(&self.check_id, "check_id")?;
        validate_text(
            &self.reason,
            "reason",
            MAX_TEXT_BYTES,
            Phase3FormFaultCode::Text,
        )?;
        if self.evidence.len() > MAX_EVIDENCE_REFERENCES
            || (self.evidence.is_empty() && self.status != IndependentCheckStatus::NotApplicable)
        {
            return Err(Phase3FormFault::new(
                Phase3FormFaultCode::Evidence,
                "evidence",
                "evidence is empty for an applicable check or exceeds its hard bound",
            ));
        }
        let mut prior = None;
        for reference in &self.evidence {
            reference.validate()?;
            if prior.is_some_and(|value: &ArtifactReference| value >= reference) {
                return Err(Phase3FormFault::new(
                    Phase3FormFaultCode::Evidence,
                    "evidence",
                    "evidence references are not sorted and unique",
                ));
            }
            prior = Some(reference);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase3ReviewDisposition {
    EligibleForPhase3dConsideration,
    ReviseInNewCandidate,
    Reject,
    Quarantine,
}

impl ValidatePhase3 for Phase3ReviewDisposition {
    fn validate(&self) -> Result<(), Phase3FormFault> {
        Ok(())
    }
}

fn validate_digest(value: &str, field: &str) -> Result<(), Phase3FormFault> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(Phase3FormFault::new(
            Phase3FormFaultCode::Digest,
            field,
            "digest is not canonical lowercase SHA-256",
        ))
    }
}

fn validate_text(
    value: &str,
    field: &str,
    maximum_bytes: usize,
    code: Phase3FormFaultCode,
) -> Result<(), Phase3FormFault> {
    if !value.trim().is_empty() && value.len() <= maximum_bytes && !value.contains('\0') {
        Ok(())
    } else {
        Err(Phase3FormFault::new(
            code,
            field,
            "text is empty, oversized, whitespace-only, or contains NUL",
        ))
    }
}

fn validate_identifier(value: &str, field: &str) -> Result<(), Phase3FormFault> {
    validate_text(value, field, MAX_PROFILE_BYTES, Phase3FormFaultCode::Text)?;
    if value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
    {
        Ok(())
    } else {
        Err(Phase3FormFault::new(
            Phase3FormFaultCode::Text,
            field,
            "identity contains a noncanonical character",
        ))
    }
}

fn validate_relative_path(value: &str) -> Result<(), Phase3FormFault> {
    let segments = value.split('/').collect::<Vec<_>>();
    let valid = !value.is_empty()
        && value.len() <= MAX_PATH_BYTES
        && !value.starts_with('/')
        && !value.ends_with('/')
        && !value.contains(['\\', '\0', ':'])
        && segments.iter().all(|segment| {
            !segment.is_empty()
                && !matches!(*segment, "." | "..")
                && !segment.eq_ignore_ascii_case(".git")
        });
    if valid {
        Ok(())
    } else {
        Err(Phase3FormFault::new(
            Phase3FormFaultCode::Path,
            "relative_path",
            "path is not a canonical safe relative path",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn artifact(hash: &str) -> ArtifactReference {
        ArtifactReference {
            kind: Phase3ArtifactKind::CandidateCapsule,
            profile: "candidate-capsule/0.1".to_owned(),
            sha256: hash.to_owned(),
        }
    }

    fn file(mode: &str, length: u64, hash: &str) -> RegularFileEvidence {
        RegularFileEvidence {
            mode: mode.to_owned(),
            length,
            sha256: hash.to_owned(),
        }
    }

    #[test]
    fn mutation_transition_matrix_is_exhaustive() {
        let expected = [
            (MutationStage::Prepared, MutationStage::Revalidated),
            (MutationStage::Revalidated, MutationStage::SandboxReady),
            (MutationStage::SandboxReady, MutationStage::TurnRunning),
            (MutationStage::TurnRunning, MutationStage::TurnTerminal),
            (
                MutationStage::TurnTerminal,
                MutationStage::HandoffPendingSeal,
            ),
            (MutationStage::HandoffPendingSeal, MutationStage::Closed),
            (MutationStage::Revalidated, MutationStage::Quarantined),
            (MutationStage::SandboxReady, MutationStage::Quarantined),
            (MutationStage::TurnRunning, MutationStage::Quarantined),
            (MutationStage::TurnTerminal, MutationStage::Quarantined),
            (
                MutationStage::HandoffPendingSeal,
                MutationStage::Quarantined,
            ),
            (MutationStage::Quarantined, MutationStage::Closed),
        ];
        for from in MutationStage::ALL {
            for to in MutationStage::ALL {
                assert_eq!(
                    MutationTransition { from, to }.validate().is_ok(),
                    expected.contains(&(from, to)),
                    "{from:?} -> {to:?}"
                );
            }
        }
    }

    #[test]
    fn seal_review_transition_matrix_is_exhaustive() {
        let expected = [
            (SealReviewStage::Admitted, SealReviewStage::Quiescing),
            (SealReviewStage::Quiescing, SealReviewStage::Capturing),
            (SealReviewStage::Capturing, SealReviewStage::Publishing),
            (SealReviewStage::Publishing, SealReviewStage::Sealed),
            (SealReviewStage::Sealed, SealReviewStage::Reconstructing),
            (SealReviewStage::Reconstructing, SealReviewStage::Testing),
            (SealReviewStage::Testing, SealReviewStage::Tested),
            (SealReviewStage::Tested, SealReviewStage::Reviewing),
            (SealReviewStage::Reviewing, SealReviewStage::Reviewed),
            (SealReviewStage::Quiescing, SealReviewStage::Quarantined),
            (SealReviewStage::Capturing, SealReviewStage::Quarantined),
            (SealReviewStage::Publishing, SealReviewStage::Quarantined),
            (
                SealReviewStage::Reconstructing,
                SealReviewStage::Quarantined,
            ),
            (SealReviewStage::Testing, SealReviewStage::Quarantined),
            (SealReviewStage::Sealed, SealReviewStage::Unresolved),
            (SealReviewStage::Tested, SealReviewStage::Unresolved),
            (SealReviewStage::Reviewing, SealReviewStage::Unresolved),
        ];
        for from in SealReviewStage::ALL {
            for to in SealReviewStage::ALL {
                assert_eq!(
                    SealReviewTransition { from, to }.validate().is_ok(),
                    expected.contains(&(from, to)),
                    "{from:?} -> {to:?}"
                );
            }
        }
    }

    #[test]
    fn consequence_never_denies_possible_post_start_mutation() {
        for turn_started in [false, true] {
            for may_have_mutated in [false, true] {
                for quarantine_required in [false, true] {
                    let value = FaultConsequence {
                        turn_started,
                        may_have_mutated,
                        quarantine_required,
                    };
                    assert_eq!(
                        value.validate().is_ok(),
                        may_have_mutated == turn_started && quarantine_required == turn_started
                    );
                }
            }
        }
    }

    #[test]
    fn path_change_shapes_are_coherent() {
        let added = CandidatePathRecord {
            relative_path: "src/new.rs".to_owned(),
            change_kind: CandidateChangeKind::Add,
            base: None,
            current: Some(file("100644", 1, A)),
            blob_sha256: Some(A.to_owned()),
        };
        assert!(added.validate().is_ok());

        let modified = CandidatePathRecord {
            relative_path: "src/lib.rs".to_owned(),
            change_kind: CandidateChangeKind::Modify,
            base: Some(file("100644", 1, A)),
            current: Some(file("100644", 2, B)),
            blob_sha256: Some(B.to_owned()),
        };
        assert!(modified.validate().is_ok());

        let deleted = CandidatePathRecord {
            relative_path: "old.txt".to_owned(),
            change_kind: CandidateChangeKind::Delete,
            base: Some(file("100644", 1, A)),
            current: None,
            blob_sha256: None,
        };
        assert!(deleted.validate().is_ok());

        let mode = CandidatePathRecord {
            relative_path: "tool".to_owned(),
            change_kind: CandidateChangeKind::ModeChange,
            base: Some(file("100644", 1, A)),
            current: Some(file("100755", 1, A)),
            blob_sha256: Some(A.to_owned()),
        };
        assert!(mode.validate().is_ok());

        let mut invalid = added.clone();
        invalid.relative_path = "src/../escape".to_owned();
        assert_eq!(
            invalid.validate().expect_err("path").code,
            Phase3FormFaultCode::Path
        );
        let mut invalid = modified.clone();
        invalid.current = invalid.base.clone();
        invalid.blob_sha256 = Some(A.to_owned());
        assert_eq!(
            invalid.validate().expect_err("unchanged").code,
            Phase3FormFaultCode::Change
        );
        let mut invalid = modified.clone();
        invalid.current = Some(file("100755", 1, A));
        invalid.blob_sha256 = Some(A.to_owned());
        assert_eq!(
            invalid.validate().expect_err("mode-only modify").code,
            Phase3FormFaultCode::Change
        );
        let mut invalid = mode;
        invalid.current = Some(file("100755", 2, B));
        invalid.blob_sha256 = Some(B.to_owned());
        assert_eq!(
            invalid.validate().expect_err("not mode-only").code,
            Phase3FormFaultCode::Change
        );
    }

    #[test]
    fn independent_checks_preserve_unknown_and_exact_evidence() {
        let check = IndependentCheck {
            check_id: "criterion:build".to_owned(),
            status: IndependentCheckStatus::Unknown,
            evidence: vec![artifact(A), artifact(B)],
            reason: "required environment was not observed".to_owned(),
        };
        assert!(check.validate().is_ok());
        let json = serde_json::to_vec(&check).expect("JSON");
        assert_eq!(
            decode_phase3_json::<IndependentCheck>(&json).expect("decode"),
            check
        );

        let mut duplicate = check.clone();
        duplicate.evidence = vec![artifact(A), artifact(A)];
        assert_eq!(
            duplicate.validate().expect_err("duplicate").code,
            Phase3FormFaultCode::Evidence
        );
        let empty = IndependentCheck {
            evidence: Vec::new(),
            ..check
        };
        assert_eq!(
            empty.validate().expect_err("empty").code,
            Phase3FormFaultCode::Evidence
        );
    }

    #[test]
    fn strict_json_rejects_unknown_fields_variants_and_invalid_scalars() {
        let valid = br#"{"kind":"candidate_capsule","profile":"candidate-capsule/0.1","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
        assert!(decode_phase3_json::<ArtifactReference>(valid).is_ok());

        let unknown_field = br#"{"kind":"candidate_capsule","profile":"candidate-capsule/0.1","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","promote":true}"#;
        assert_eq!(
            decode_phase3_json::<ArtifactReference>(unknown_field)
                .expect_err("unknown field")
                .code,
            Phase3FormFaultCode::Json
        );
        let unknown_variant = br#"{"kind":"promoted","profile":"x","sha256":"aaaaaaaa"}"#;
        assert_eq!(
            decode_phase3_json::<ArtifactReference>(unknown_variant)
                .expect_err("unknown variant")
                .code,
            Phase3FormFaultCode::Json
        );
        let invalid_digest =
            br#"{"kind":"candidate_capsule","profile":"x","sha256":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#;
        assert_eq!(
            decode_phase3_json::<ArtifactReference>(invalid_digest)
                .expect_err("digest")
                .code,
            Phase3FormFaultCode::Digest
        );
    }

    #[test]
    fn evidence_strength_and_dispositions_are_closed_json_vocabularies() {
        assert_eq!(
            serde_json::to_string(&ConsistencyClass::QuiescentDoubleInventory)
                .expect("consistency"),
            "\"quiescent_double_inventory\""
        );
        assert_eq!(
            serde_json::to_string(&ImmutabilityClass::ContentAddressedVerified)
                .expect("immutability"),
            "\"content_addressed_verified\""
        );
        let dispositions = [
            Phase3ReviewDisposition::EligibleForPhase3dConsideration,
            Phase3ReviewDisposition::ReviseInNewCandidate,
            Phase3ReviewDisposition::Reject,
            Phase3ReviewDisposition::Quarantine,
        ];
        let json = serde_json::to_string(&dispositions).expect("dispositions");
        for forbidden in ["commit", "merge", "push", "deploy", "activate", "cleanup"] {
            assert!(!json.contains(forbidden));
        }
        assert_eq!(
            decode_phase3_json::<Phase3ReviewDisposition>(
                br#""eligible_for_phase3d_consideration""#
            )
            .expect("closed disposition"),
            Phase3ReviewDisposition::EligibleForPhase3dConsideration
        );
        assert_eq!(
            decode_phase3_json::<Phase3ReviewDisposition>(br#""promote""#)
                .expect_err("unknown disposition")
                .code,
            Phase3FormFaultCode::Json
        );
    }

    #[test]
    fn module_profile_is_exact_and_stable() {
        assert_eq!(
            PHASE3_MACHINE_FORMS_PROFILE,
            "cantor-phase3-machine-forms/0.1"
        );
    }
}
