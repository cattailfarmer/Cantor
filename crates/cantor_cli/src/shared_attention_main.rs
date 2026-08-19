//! JSON transport shell for the pure shared-attention runtime.

use std::collections::BTreeSet;
use std::env;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use cantor_core::{
    AttentionCompaction, AttentionFrameDelta, DreamFrame, DreamFrameSeed, DreamReview,
    EpistemicStatus, FrameAttestation, ReconciliationDisposition, SemanticId, SharedAttentionFault,
    SharedAttentionFrame, compact_attention_frame, discard_dream_frame, fork_dream_frame,
    prepare_attention_candidate, project_dream_promotion, reconcile_attention_deltas,
    record_dream_evidence, review_dream_frame, settle_attention_candidate, validate_dream_frame,
    validate_shared_attention_frame,
};
use serde::{Deserialize, Serialize};

const CLI_PROFILE: &str = "cantor-shared-attention-cli/0.1";
const MAX_INPUT_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum CliRequest {
    ValidateFrame {
        frame: SharedAttentionFrame,
    },
    Reconcile {
        base: SharedAttentionFrame,
        deltas: Vec<AttentionFrameDelta>,
    },
    Compact {
        base: SharedAttentionFrame,
        compaction: AttentionCompaction,
    },
    Prepare {
        working: SharedAttentionFrame,
    },
    Settle {
        candidate: SharedAttentionFrame,
        attestations: Vec<FrameAttestation>,
    },
    ForkDream {
        parent: SharedAttentionFrame,
        seed: DreamFrameSeed,
    },
    ValidateDream {
        parent: SharedAttentionFrame,
        dream: DreamFrame,
    },
    RecordDreamEvidence {
        parent: SharedAttentionFrame,
        dream: DreamFrame,
        evidence_refs: BTreeSet<SemanticId>,
    },
    ReviewDream {
        parent: SharedAttentionFrame,
        dream: DreamFrame,
        reviews: Vec<DreamReview>,
    },
    DiscardDream {
        parent: SharedAttentionFrame,
        dream: DreamFrame,
        reason: String,
    },
    ProjectDreamPromotion {
        parent: SharedAttentionFrame,
        dream: DreamFrame,
        delta_id: SemanticId,
        author_ref: SemanticId,
        target_status: EpistemicStatus,
        logical_time: u64,
    },
}

impl CliRequest {
    fn name(&self) -> &'static str {
        match self {
            Self::ValidateFrame { .. } => "validate_frame",
            Self::Reconcile { .. } => "reconcile",
            Self::Compact { .. } => "compact",
            Self::Prepare { .. } => "prepare",
            Self::Settle { .. } => "settle",
            Self::ForkDream { .. } => "fork_dream",
            Self::ValidateDream { .. } => "validate_dream",
            Self::RecordDreamEvidence { .. } => "record_dream_evidence",
            Self::ReviewDream { .. } => "review_dream",
            Self::DiscardDream { .. } => "discard_dream",
            Self::ProjectDreamPromotion { .. } => "project_dream_promotion",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CliStatus {
    Succeeded,
    Buffered,
    Refused,
    InvalidRequest,
    InternalFault,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct CliFault {
    code: String,
    message: String,
    subject_refs: BTreeSet<SemanticId>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct CliResponse {
    profile: String,
    operation: String,
    status: CliStatus,
    result: Option<serde_json::Value>,
    fault: Option<CliFault>,
    nonclaims: Vec<String>,
}

impl CliResponse {
    fn success(operation: &str, result: serde_json::Value) -> Self {
        Self::new(operation, CliStatus::Succeeded, Some(result), None)
    }

    fn buffered(operation: &str, result: serde_json::Value) -> Self {
        Self::new(operation, CliStatus::Buffered, Some(result), None)
    }

    fn domain_fault(operation: &str, error: SharedAttentionFault) -> Self {
        Self::new(
            operation,
            CliStatus::Refused,
            None,
            Some(CliFault {
                code: error.code.as_str().to_owned(),
                message: error.message,
                subject_refs: error.subject_refs,
            }),
        )
    }

    fn transport_fault(status: CliStatus, code: &str, message: impl Into<String>) -> Self {
        Self::new(
            "unavailable",
            status,
            None,
            Some(CliFault {
                code: code.to_owned(),
                message: message.into(),
                subject_refs: BTreeSet::new(),
            }),
        )
    }

    fn new(
        operation: &str,
        status: CliStatus,
        result: Option<serde_json::Value>,
        fault: Option<CliFault>,
    ) -> Self {
        Self {
            profile: CLI_PROFILE.to_owned(),
            operation: operation.to_owned(),
            status,
            result,
            fault,
            nonclaims: vec![
                "no model hidden state or KV cache was shared".to_owned(),
                "no external effect was authorized or executed".to_owned(),
                "settlement is coordination and not proof of external truth".to_owned(),
            ],
        }
    }

    fn exit_code(&self) -> u8 {
        match self.status {
            CliStatus::Succeeded | CliStatus::Buffered => 0,
            CliStatus::InvalidRequest => 2,
            CliStatus::Refused => 3,
            CliStatus::InternalFault => 4,
        }
    }
}

fn main() -> ExitCode {
    let response = dispatch(env::args().skip(1).collect());
    if let Some(fault) = &response.fault {
        eprintln!("cantor-shared-attention: {}: {}", fault.code, fault.message);
    }
    let exit_code = response.exit_code();
    let stdout = io::stdout();
    let mut output = stdout.lock();
    if serde_json::to_writer(&mut output, &response).is_err() || writeln!(output).is_err() {
        eprintln!("cantor-shared-attention: response serialization failed");
        return ExitCode::from(4);
    }
    ExitCode::from(exit_code)
}

fn dispatch(arguments: Vec<String>) -> CliResponse {
    let input_path = match parse_arguments(&arguments) {
        Ok(path) => path,
        Err(message) => {
            return CliResponse::transport_fault(
                CliStatus::InvalidRequest,
                "invalid_arguments",
                message,
            );
        }
    };
    let bytes = match read_bounded_input(input_path.as_ref()) {
        Ok(bytes) => bytes,
        Err(message) => {
            return CliResponse::transport_fault(
                CliStatus::InvalidRequest,
                "input_read_failure",
                message,
            );
        }
    };
    let request: CliRequest = match serde_json::from_slice(&bytes) {
        Ok(request) => request,
        Err(error) => {
            return CliResponse::transport_fault(
                CliStatus::InvalidRequest,
                "malformed_request",
                format!("input is not a valid closed request: {error}"),
            );
        }
    };
    execute(request)
}

fn execute(request: CliRequest) -> CliResponse {
    let operation = request.name();
    let result = match request {
        CliRequest::ValidateFrame { frame } => validate_shared_attention_frame(&frame)
            .and_then(|_| json_value(&frame, "validated frame")),
        CliRequest::Reconcile { base, deltas } => {
            match reconcile_attention_deltas(&base, &deltas) {
                Ok(outcome) => {
                    let buffered = outcome.disposition == ReconciliationDisposition::Buffered;
                    return match json_value(&outcome, "reconciliation outcome") {
                        Ok(value) if buffered => CliResponse::buffered(operation, value),
                        Ok(value) => CliResponse::success(operation, value),
                        Err(error) => internal_domain_response(operation, error),
                    };
                }
                Err(error) => Err(error),
            }
        }
        CliRequest::Compact { base, compaction } => compact_attention_frame(&base, &compaction)
            .and_then(|value| json_value(&value, "attention compaction outcome")),
        CliRequest::Prepare { working } => prepare_attention_candidate(&working)
            .and_then(|value| json_value(&value, "prepared candidate")),
        CliRequest::Settle {
            candidate,
            attestations,
        } => settle_attention_candidate(&candidate, &attestations)
            .and_then(|value| json_value(&value, "settlement outcome")),
        CliRequest::ForkDream { parent, seed } => {
            fork_dream_frame(&parent, seed).and_then(|value| json_value(&value, "dream frame"))
        }
        CliRequest::ValidateDream { parent, dream } => validate_dream_frame(&parent, &dream)
            .and_then(|_| json_value(&dream, "validated dream")),
        CliRequest::RecordDreamEvidence {
            parent,
            dream,
            evidence_refs,
        } => record_dream_evidence(&parent, &dream, &evidence_refs)
            .and_then(|value| json_value(&value, "testing dream")),
        CliRequest::ReviewDream {
            parent,
            dream,
            reviews,
        } => review_dream_frame(&parent, &dream, &reviews)
            .and_then(|value| json_value(&value, "dream review outcome")),
        CliRequest::DiscardDream {
            parent,
            dream,
            reason,
        } => discard_dream_frame(&parent, &dream, reason).and_then(|(dream, receipt)| {
            json_value(
                &serde_json::json!({ "dream": dream, "receipt": receipt }),
                "dream discard outcome",
            )
        }),
        CliRequest::ProjectDreamPromotion {
            parent,
            dream,
            delta_id,
            author_ref,
            target_status,
            logical_time,
        } => project_dream_promotion(
            &parent,
            &dream,
            delta_id,
            author_ref,
            target_status,
            logical_time,
        )
        .and_then(|value| json_value(&value, "dream promotion delta")),
    };
    match result {
        Ok(value) => CliResponse::success(operation, value),
        Err(error) => CliResponse::domain_fault(operation, error),
    }
}

fn json_value<T: Serialize>(
    value: &T,
    label: &str,
) -> Result<serde_json::Value, SharedAttentionFault> {
    serde_json::to_value(value).map_err(|error| SharedAttentionFault {
        code: cantor_core::SharedAttentionFaultCode::MachineForm,
        message: format!("{label} serialization failed: {error}"),
        subject_refs: BTreeSet::new(),
    })
}

fn internal_domain_response(operation: &str, error: SharedAttentionFault) -> CliResponse {
    CliResponse::new(
        operation,
        CliStatus::InternalFault,
        None,
        Some(CliFault {
            code: "response_serialization_failed".to_owned(),
            message: error.message,
            subject_refs: error.subject_refs,
        }),
    )
}

fn parse_arguments(arguments: &[String]) -> Result<Option<PathBuf>, String> {
    match arguments {
        [] => Ok(None),
        [flag, path] if flag == "--input" && !path.is_empty() => Ok(Some(PathBuf::from(path))),
        [flag] if matches!(flag.as_str(), "help" | "--help" | "-h") => Err(
            "usage: cantor-shared-attention [--input <path>]; omit --input to read one request JSON object from stdin"
                .to_owned(),
        ),
        _ => Err("expected no arguments or exactly --input <path>".to_owned()),
    }
}

fn read_bounded_input(path: Option<&PathBuf>) -> Result<Vec<u8>, String> {
    let reader: Box<dyn Read> = match path {
        Some(path) => Box::new(
            File::open(path)
                .map_err(|error| format!("cannot open input {}: {error}", path.display()))?,
        ),
        None => Box::new(io::stdin().lock()),
    };
    let mut bytes = Vec::new();
    reader
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read input: {error}"))?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(format!("input exceeds {MAX_INPUT_BYTES} bytes"));
    }
    if bytes.is_empty() {
        return Err("input is empty".to_owned());
    }
    Ok(bytes)
}
