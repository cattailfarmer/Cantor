#![cfg(feature = "json-schema")]

use std::collections::BTreeSet;

use cantor_core::{
    AdmissionDecision, AdmissionDisposition, AuthorshipClass, AuthorshipLaneEvidence,
    AuthorshipLaneTemplate, AwaitedCondition, CantorProcessIr, CatalogueReceipt, CatalogueStatus,
    CompilationReceipt, CompiledProcedureIdentity, ConsumedBudget, ContentDigest, ControlRegion,
    ControllerEventKind, ControllerTranscriptEvent, CoordinationOutcome, CoordinationReplayReceipt,
    ExchangeOperation, FakeControllerOutcome, FakeControllerTranscript,
    FakeObserverAdmissionPolicy, InstructionOperand, InvocationBudget, InvocationDisposition,
    InvocationRequest, InvocationResult, LaterPassContext, NegotiatedFrame, NegotiationSession,
    NegotiationStatus, Participant, PhaseDisposition, ProcedureBounds, ProcedureCandidate,
    ProcedureCatalogueEntry, ProcedureCatalogueState, ProcedureEffectClass,
    ProcedureEffectDeclaration, ProcedureFault, ProcedureFaultCategory, ProcedureLifecycle,
    ProcedureMessage, ProcedureMessageKind, ProcedurePhase, ProcedureReadClass, ProcedureSchema,
    ProcedureSchemaSet, ProcedureType, ProcedureValue, ProcedureWriteClass, ProcessBudgetState,
    ProcessDefinition, ProcessInstanceState, ProcessInstruction, ProcessLifecycle,
    ProcessOperation, ProcessStep, ProhibitedProcedureOperation, ProviderNeutralToolResult,
    ProviderNeutralToolSchema, ReceiptEvidence, RevocationRecord, SchemaField, SchemaKind,
    SemanticId, SemanticTrace, SemanticTraceEvent, SensitivityClass, SerializedContinuation,
    SopAnchorBinding, SourceMapEntry, TaggedVariant, TokenRingPass, ToolCallProposal,
    ToolControllerFault, ToolResultDisposition, TraceEventKind, ValidationReceipt,
    VerificationReceipt,
};
use cantor_procedure_tool::{
    PrepareRequest, PreparedRunRequest, ProcedureToolFault, ProcedureToolResponse,
    ProcedureToolResponseStatus, ProcedureToolVerification, VerifyRequest,
};
use schemars::{JsonSchema, generate::SchemaSettings};
use serde_json::Value;

fn type_name<T: JsonSchema>() -> String {
    T::schema_name().into_owned()
}

fn root<T: JsonSchema>(serialize: bool) -> Value {
    let settings = if serialize {
        SchemaSettings::draft2020_12().for_serialize()
    } else {
        SchemaSettings::draft2020_12().for_deserialize()
    };
    serde_json::to_value(settings.into_generator().into_root_schema_for::<T>())
        .expect("generated schema is JSON")
}

#[test]
fn exact_reachable_inventory_has_stable_unique_names() {
    let actual = [
        type_name::<SemanticId>(),
        type_name::<ContentDigest>(),
        type_name::<AdmissionDecision>(),
        type_name::<AdmissionDisposition>(),
        type_name::<AwaitedCondition>(),
        type_name::<CantorProcessIr>(),
        type_name::<CatalogueReceipt>(),
        type_name::<CatalogueStatus>(),
        type_name::<CompilationReceipt>(),
        type_name::<CompiledProcedureIdentity>(),
        type_name::<ConsumedBudget>(),
        type_name::<ControlRegion>(),
        type_name::<InstructionOperand>(),
        type_name::<InvocationBudget>(),
        type_name::<InvocationDisposition>(),
        type_name::<InvocationRequest>(),
        type_name::<InvocationResult>(),
        type_name::<NegotiatedFrame>(),
        type_name::<NegotiationSession>(),
        type_name::<NegotiationStatus>(),
        type_name::<Participant>(),
        type_name::<PhaseDisposition>(),
        type_name::<ProcedureBounds>(),
        type_name::<ProcedureCandidate>(),
        type_name::<ProcedureCatalogueEntry>(),
        type_name::<ProcedureCatalogueState>(),
        type_name::<ProcedureEffectClass>(),
        type_name::<ProcedureEffectDeclaration>(),
        type_name::<ProcedureFault>(),
        type_name::<ProcedureFaultCategory>(),
        type_name::<ProcedureLifecycle>(),
        type_name::<ProcedureMessage>(),
        type_name::<ProcedureMessageKind>(),
        type_name::<ProcedurePhase>(),
        type_name::<ProcedureReadClass>(),
        type_name::<ProcedureSchema>(),
        type_name::<ProcedureSchemaSet>(),
        type_name::<ProcedureType>(),
        type_name::<ProcedureValue>(),
        type_name::<ProcedureWriteClass>(),
        type_name::<ProcessBudgetState>(),
        type_name::<ProcessDefinition>(),
        type_name::<ProcessInstanceState>(),
        type_name::<ProcessInstruction>(),
        type_name::<ProcessLifecycle>(),
        type_name::<ProcessOperation>(),
        type_name::<ProcessStep>(),
        type_name::<ProhibitedProcedureOperation>(),
        type_name::<ReceiptEvidence>(),
        type_name::<RevocationRecord>(),
        type_name::<SchemaField>(),
        type_name::<SchemaKind>(),
        type_name::<SemanticTrace>(),
        type_name::<SemanticTraceEvent>(),
        type_name::<SerializedContinuation>(),
        type_name::<SopAnchorBinding>(),
        type_name::<SourceMapEntry>(),
        type_name::<TaggedVariant>(),
        type_name::<TokenRingPass>(),
        type_name::<TraceEventKind>(),
        type_name::<ValidationReceipt>(),
        type_name::<VerificationReceipt>(),
        type_name::<AuthorshipClass>(),
        type_name::<AuthorshipLaneEvidence>(),
        type_name::<AuthorshipLaneTemplate>(),
        type_name::<CoordinationOutcome>(),
        type_name::<CoordinationReplayReceipt>(),
        type_name::<ControllerEventKind>(),
        type_name::<ControllerTranscriptEvent>(),
        type_name::<ExchangeOperation>(),
        type_name::<FakeControllerOutcome>(),
        type_name::<FakeControllerTranscript>(),
        type_name::<LaterPassContext>(),
        type_name::<ProviderNeutralToolResult>(),
        type_name::<ProviderNeutralToolSchema>(),
        type_name::<ToolCallProposal>(),
        type_name::<ToolControllerFault>(),
        type_name::<ToolResultDisposition>(),
        type_name::<FakeObserverAdmissionPolicy>(),
        type_name::<SensitivityClass>(),
        type_name::<PreparedRunRequest>(),
        type_name::<PrepareRequest>(),
        type_name::<ProcedureToolFault>(),
        type_name::<ProcedureToolResponse>(),
        type_name::<ProcedureToolResponseStatus>(),
        type_name::<ProcedureToolVerification>(),
        type_name::<VerifyRequest>(),
    ];
    let expected = [
        "SemanticId",
        "ContentDigest",
        "AdmissionDecision",
        "AdmissionDisposition",
        "AwaitedCondition",
        "CantorProcessIr",
        "CatalogueReceipt",
        "CatalogueStatus",
        "CompilationReceipt",
        "CompiledProcedureIdentity",
        "ConsumedBudget",
        "ControlRegion",
        "InstructionOperand",
        "InvocationBudget",
        "InvocationDisposition",
        "InvocationRequest",
        "InvocationResult",
        "NegotiatedFrame",
        "NegotiationSession",
        "NegotiationStatus",
        "Participant",
        "PhaseDisposition",
        "ProcedureBounds",
        "ProcedureCandidate",
        "ProcedureCatalogueEntry",
        "ProcedureCatalogueState",
        "ProcedureEffectClass",
        "ProcedureEffectDeclaration",
        "ProcedureFault",
        "ProcedureFaultCategory",
        "ProcedureLifecycle",
        "ProcedureMessage",
        "ProcedureMessageKind",
        "ProcedurePhase",
        "ProcedureReadClass",
        "ProcedureSchema",
        "ProcedureSchemaSet",
        "ProcedureType",
        "ProcedureValue",
        "ProcedureWriteClass",
        "ProcessBudgetState",
        "ProcessDefinition",
        "ProcessInstanceState",
        "ProcessInstruction",
        "ProcessLifecycle",
        "ProcessOperation",
        "ProcessStep",
        "ProhibitedProcedureOperation",
        "ReceiptEvidence",
        "RevocationRecord",
        "SchemaField",
        "SchemaKind",
        "SemanticTrace",
        "SemanticTraceEvent",
        "SerializedContinuation",
        "SopAnchorBinding",
        "SourceMapEntry",
        "TaggedVariant",
        "TokenRingPass",
        "TraceEventKind",
        "ValidationReceipt",
        "VerificationReceipt",
        "AuthorshipClass",
        "AuthorshipLaneEvidence",
        "AuthorshipLaneTemplate",
        "CoordinationOutcome",
        "CoordinationReplayReceipt",
        "ControllerEventKind",
        "ControllerTranscriptEvent",
        "ExchangeOperation",
        "FakeControllerOutcome",
        "FakeControllerTranscript",
        "LaterPassContext",
        "ProviderNeutralToolResult",
        "ProviderNeutralToolSchema",
        "ToolCallProposal",
        "ToolControllerFault",
        "ToolResultDisposition",
        "FakeObserverAdmissionPolicy",
        "SensitivityClass",
        "PreparedRunRequest",
        "PrepareRequest",
        "ProcedureToolFault",
        "ProcedureToolResponse",
        "ProcedureToolResponseStatus",
        "ProcedureToolVerification",
        "VerifyRequest",
    ];
    assert_eq!(actual.len(), 87);
    assert_eq!(actual.as_slice(), expected);
    assert_eq!(actual.iter().collect::<BTreeSet<_>>().len(), 87);
}

#[test]
fn directional_roots_and_recursive_definitions_compile() {
    let prepare_input = root::<PrepareRequest>(false);
    let run_input = root::<PreparedRunRequest>(false);
    let verify_input = root::<VerifyRequest>(false);
    let response_output = root::<ProcedureToolResponse>(true);
    let crossing_output = root::<PreparedRunRequest>(true);

    for document in [
        &prepare_input,
        &run_input,
        &verify_input,
        &response_output,
        &crossing_output,
    ] {
        assert_eq!(
            document.get("$schema").and_then(Value::as_str),
            Some("https://json-schema.org/draft/2020-12/schema")
        );
    }

    let prepare_text = serde_json::to_string(&prepare_input).expect("schema serializes");
    assert!(prepare_text.contains(r##""$ref":"#/$defs/ProcedureType""##));
    assert!(prepare_text.contains(r##""$ref":"#/$defs/ProcedureValue""##));

    let semantic_id = prepare_input
        .get("$defs")
        .and_then(|defs| defs.get("SemanticId"))
        .expect("SemanticId definition is reachable");
    assert_eq!(
        semantic_id.get("minLength").and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(
        semantic_id.get("maxLength").and_then(Value::as_u64),
        Some(512)
    );
    assert_eq!(
        semantic_id.get("pattern").and_then(Value::as_str),
        Some("^[A-Za-z0-9_.:/-]+$")
    );
}
