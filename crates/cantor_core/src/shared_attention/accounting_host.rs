//! Replayable custody and a strict inference-host protocol for identity accounting.
//!
//! This module is deliberately pure. It emits and restores canonical bytes but
//! leaves physical storage, model invocation, clocks, networks, and effects to
//! an explicit caller.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{
    AccountabilityInferenceWindow, AccountabilityManifestWindow, AccountableMaterialization,
    AccountableObject, AccountableObjectAdmission, AccountableObjectPatch, IdentityLedger,
    ManifestAttentionReceipt, ManifestAttentionReceiptSeed, ReferenceResolution,
    SharedAttentionFault, SharedAttentionFaultCode, SharedAttentionFrame, admit_accountable_object,
    apply_accountable_object_patch, compile_accountability_manifest_window,
    compile_accountability_window, finalize_manifest_attention_receipt, inspect_accountable_object,
    materialize_accountable_objects, resolve_accountability_reference,
    validate_accountability_manifest_window, validate_accountability_window,
    validate_accountable_materialization, validate_identity_ledger,
    validate_manifest_attention_receipt,
};
use crate::procedure_runtime::empty_sha256;
use crate::{ContentDigest, SemanticId};

use super::runtime::{derive, digest, fault};

pub const ACCOUNTING_JOURNAL_PROFILE: &str = "cantor-identity-accounting-journal/0.1";
pub const ACCOUNTING_JOURNAL_EVENT_PROFILE: &str = "cantor-identity-accounting-journal-event/0.1";
pub const ACCOUNTING_HOST_REQUEST_PROFILE: &str = "cantor-identity-accounting-host-request/0.1";
pub const ACCOUNTING_HOST_RESPONSE_PROFILE: &str = "cantor-identity-accounting-host-response/0.1";

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mutation", rename_all = "snake_case", deny_unknown_fields)]
pub enum AccountingJournalMutation {
    Genesis,
    PatchApplied {
        patch: Box<AccountableObjectPatch>,
    },
    AdmissionApplied {
        admission: Box<AccountableObjectAdmission>,
    },
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountingJournalEvent {
    pub profile: String,
    pub event_id: SemanticId,
    pub sequence: u64,
    pub request_id: SemanticId,
    pub request_digest: ContentDigest,
    pub predecessor_ledger_digest: Option<ContentDigest>,
    pub successor_ledger_digest: ContentDigest,
    pub touched_handle: Option<SemanticId>,
    pub mutation: AccountingJournalMutation,
    pub event_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountingJournal {
    pub profile: String,
    pub journal_id: SemanticId,
    pub basket_id: SemanticId,
    pub ledgers: BTreeMap<String, IdentityLedger>,
    pub events: Vec<AccountingJournalEvent>,
    pub head_ledger_digest: ContentDigest,
    pub journal_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountingHostOperationName {
    InspectJournal,
    Project,
    Resolve,
    InspectObject,
    ReadLedger,
    ReadEvent,
    ApplyPatch,
    AdmitObject,
    ProjectManifest,
    Materialize,
    AcknowledgeAttention,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum AccountingHostOperation {
    InspectJournal,
    Project {
        frame: Box<SharedAttentionFrame>,
        byte_budget: u64,
    },
    Resolve {
        query: String,
    },
    InspectObject {
        handle: SemanticId,
    },
    ReadLedger {
        ledger_digest: ContentDigest,
    },
    ReadEvent {
        event_id: SemanticId,
    },
    ApplyPatch {
        patch: Box<AccountableObjectPatch>,
    },
    AdmitObject {
        admission: Box<AccountableObjectAdmission>,
    },
    ProjectManifest {
        frame: Box<SharedAttentionFrame>,
        manifest_byte_budget: u64,
    },
    Materialize {
        frame: Box<SharedAttentionFrame>,
        manifest_byte_budget: u64,
        expected_window_digest: ContentDigest,
        handles: Vec<SemanticId>,
    },
    AcknowledgeAttention {
        frame: Box<SharedAttentionFrame>,
        manifest_byte_budget: u64,
        expected_window_digest: ContentDigest,
        materialized_handles: Vec<SemanticId>,
        receipt_seed: Box<ManifestAttentionReceiptSeed>,
    },
}

impl AccountingHostOperation {
    pub const fn name(&self) -> AccountingHostOperationName {
        match self {
            Self::InspectJournal => AccountingHostOperationName::InspectJournal,
            Self::Project { .. } => AccountingHostOperationName::Project,
            Self::Resolve { .. } => AccountingHostOperationName::Resolve,
            Self::InspectObject { .. } => AccountingHostOperationName::InspectObject,
            Self::ReadLedger { .. } => AccountingHostOperationName::ReadLedger,
            Self::ReadEvent { .. } => AccountingHostOperationName::ReadEvent,
            Self::ApplyPatch { .. } => AccountingHostOperationName::ApplyPatch,
            Self::AdmitObject { .. } => AccountingHostOperationName::AdmitObject,
            Self::ProjectManifest { .. } => AccountingHostOperationName::ProjectManifest,
            Self::Materialize { .. } => AccountingHostOperationName::Materialize,
            Self::AcknowledgeAttention { .. } => AccountingHostOperationName::AcknowledgeAttention,
        }
    }
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountingHostRequest {
    pub profile: String,
    pub request_id: SemanticId,
    pub expected_journal_digest: ContentDigest,
    pub operation: AccountingHostOperation,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum AccountingHostResult {
    JournalSummary {
        basket_id: SemanticId,
        generation: u64,
        event_count: u64,
    },
    Window {
        window: Box<AccountabilityInferenceWindow>,
    },
    Resolution {
        resolution: ReferenceResolution,
    },
    Object {
        object: Box<AccountableObject>,
    },
    Ledger {
        ledger: Box<IdentityLedger>,
    },
    Event {
        event: Box<AccountingJournalEvent>,
    },
    Applied {
        event: Box<AccountingJournalEvent>,
        ledger: Box<IdentityLedger>,
    },
    ManifestWindow {
        window: Box<AccountabilityManifestWindow>,
    },
    Materialization {
        materialization: Box<AccountableMaterialization>,
    },
    ManifestReceipt {
        receipt: Box<ManifestAttentionReceipt>,
    },
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountingHostResponse {
    pub profile: String,
    pub request_id: SemanticId,
    pub request_digest: ContentDigest,
    pub operation: AccountingHostOperationName,
    pub journal_id: SemanticId,
    pub journal_digest: ContentDigest,
    pub head_ledger_digest: ContentDigest,
    pub result: AccountingHostResult,
    pub response_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountingHostTransition {
    pub successor: Option<AccountingJournal>,
    pub response: AccountingHostResponse,
}

pub fn new_accounting_journal(
    journal_id: SemanticId,
    initial: IdentityLedger,
) -> Result<AccountingJournal, SharedAttentionFault> {
    validate_identity_ledger(&initial)?;
    let request_digest = digest(&initial, "accounting journal genesis request")?;
    let request_id = derive("accounting:genesis", &request_digest)?;
    let event = build_event(
        1,
        request_id,
        request_digest,
        None,
        initial.ledger_digest.clone(),
        None,
        AccountingJournalMutation::Genesis,
    )?;
    let mut journal = AccountingJournal {
        profile: ACCOUNTING_JOURNAL_PROFILE.to_owned(),
        journal_id,
        basket_id: initial.basket_id.clone(),
        ledgers: BTreeMap::from([(initial.ledger_digest.value.clone(), initial.clone())]),
        events: vec![event],
        head_ledger_digest: initial.ledger_digest,
        journal_digest: empty_sha256(),
    };
    refresh_journal_digest(&mut journal)?;
    validate_accounting_journal(&journal)?;
    Ok(journal)
}

pub fn validate_accounting_journal(
    journal: &AccountingJournal,
) -> Result<(), SharedAttentionFault> {
    if journal.profile != ACCOUNTING_JOURNAL_PROFILE || journal.events.is_empty() {
        return Err(journal_fault("unsupported or empty accounting journal"));
    }
    if journal.ledgers.len() != journal.events.len() {
        return Err(journal_fault(
            "accounting journal requires exactly one retained ledger per event",
        ));
    }
    if journal.journal_digest != compute_journal_digest(journal)? {
        return Err(fault(
            SharedAttentionFaultCode::InvalidDigest,
            "accounting journal digest differs from canonical content",
        ));
    }

    let mut seen_ledgers = BTreeSet::new();
    let mut current: Option<IdentityLedger> = None;
    for (index, event) in journal.events.iter().enumerate() {
        validate_event(event)?;
        if event.sequence != index as u64 + 1 {
            return Err(journal_fault(
                "accounting journal event sequence is discontinuous",
            ));
        }
        let retained = journal
            .ledgers
            .get(&event.successor_ledger_digest.value)
            .ok_or_else(|| journal_fault("event successor ledger snapshot is absent"))?;
        validate_identity_ledger(retained)?;
        if retained.basket_id != journal.basket_id
            || retained.ledger_digest != event.successor_ledger_digest
        {
            return Err(journal_fault(
                "retained ledger basket or digest differs from its event",
            ));
        }
        if !seen_ledgers.insert(event.successor_ledger_digest.value.clone()) {
            return Err(journal_fault(
                "one ledger snapshot is reached more than once",
            ));
        }

        match (&event.mutation, &current) {
            (AccountingJournalMutation::Genesis, None) => {
                if event.predecessor_ledger_digest.is_some() || event.touched_handle.is_some() {
                    return Err(journal_fault(
                        "genesis event has predecessor or touched handle",
                    ));
                }
            }
            (AccountingJournalMutation::PatchApplied { patch }, Some(predecessor)) => {
                if event.predecessor_ledger_digest.as_ref() != Some(&predecessor.ledger_digest)
                    || event.touched_handle.as_ref() != Some(&patch.handle)
                {
                    return Err(journal_fault(
                        "patch event predecessor or touched handle is discontinuous",
                    ));
                }
                let replayed = apply_accountable_object_patch(predecessor, (**patch).clone())?;
                if &replayed != retained {
                    return Err(journal_fault(
                        "patch event does not replay to the retained successor ledger",
                    ));
                }
            }
            (AccountingJournalMutation::AdmissionApplied { admission }, Some(predecessor)) => {
                if event.predecessor_ledger_digest.as_ref() != Some(&predecessor.ledger_digest)
                    || event.touched_handle.as_ref() != Some(&admission.candidate.handle)
                {
                    return Err(journal_fault(
                        "admission event predecessor or touched handle is discontinuous",
                    ));
                }
                let replayed = admit_accountable_object(predecessor, admission)?;
                if &replayed != retained {
                    return Err(journal_fault(
                        "admission event does not replay to the retained successor ledger",
                    ));
                }
            }
            _ => {
                return Err(journal_fault(
                    "journal requires one genesis followed only by patch or admission events",
                ));
            }
        }
        current = Some(retained.clone());
    }

    if seen_ledgers != journal.ledgers.keys().cloned().collect::<BTreeSet<_>>() {
        return Err(journal_fault(
            "accounting journal contains an orphan ledger snapshot",
        ));
    }
    if current.as_ref().map(|ledger| &ledger.ledger_digest) != Some(&journal.head_ledger_digest) {
        return Err(journal_fault(
            "accounting journal head differs from replayed history",
        ));
    }
    Ok(())
}

pub fn encode_accounting_journal(
    journal: &AccountingJournal,
) -> Result<Vec<u8>, SharedAttentionFault> {
    validate_accounting_journal(journal)?;
    serde_json::to_vec(journal).map_err(|error| {
        fault(
            SharedAttentionFaultCode::MachineForm,
            format!("accounting journal serialization failed: {error}"),
        )
    })
}

pub fn decode_accounting_journal(
    bytes: &[u8],
    maximum_bytes: u64,
) -> Result<AccountingJournal, SharedAttentionFault> {
    let length = u64::try_from(bytes.len()).map_err(|_| {
        fault(
            SharedAttentionFaultCode::CapacityOverflow,
            "accounting journal input length does not fit u64",
        )
    })?;
    if maximum_bytes == 0 || length > maximum_bytes {
        return Err(fault(
            SharedAttentionFaultCode::CapacityOverflow,
            "accounting journal input exceeds its declared byte bound",
        ));
    }
    let journal: AccountingJournal = serde_json::from_slice(bytes).map_err(|error| {
        fault(
            SharedAttentionFaultCode::MachineForm,
            format!("accounting journal machine form is invalid: {error}"),
        )
    })?;
    validate_accounting_journal(&journal)?;
    if serde_json::to_vec(&journal).map_err(|error| {
        fault(
            SharedAttentionFaultCode::MachineForm,
            format!("accounting journal canonical replay failed: {error}"),
        )
    })? != bytes
    {
        return Err(fault(
            SharedAttentionFaultCode::MachineForm,
            "accounting journal input is valid JSON but not canonical bytes",
        ));
    }
    Ok(journal)
}

pub fn execute_accounting_host_request(
    journal: &AccountingJournal,
    request: AccountingHostRequest,
) -> Result<AccountingHostTransition, SharedAttentionFault> {
    validate_accounting_journal(journal)?;
    validate_request(&request)?;
    if request.expected_journal_digest != journal.journal_digest {
        return Err(fault(
            SharedAttentionFaultCode::StaleLedger,
            "accounting host request expected journal digest is stale",
        ));
    }
    let request_digest = digest(&request, "accounting host request")?;
    let operation_name = request.operation.name();
    let head = head_ledger(journal)?;

    let (successor, result) = match &request.operation {
        AccountingHostOperation::InspectJournal => (
            None,
            AccountingHostResult::JournalSummary {
                basket_id: journal.basket_id.clone(),
                generation: head.generation,
                event_count: journal.events.len() as u64,
            },
        ),
        AccountingHostOperation::Project { frame, byte_budget } => (
            None,
            AccountingHostResult::Window {
                window: Box::new(compile_accountability_window(frame, head, *byte_budget)?),
            },
        ),
        AccountingHostOperation::ProjectManifest {
            frame,
            manifest_byte_budget,
        } => (
            None,
            AccountingHostResult::ManifestWindow {
                window: Box::new(compile_accountability_manifest_window(
                    frame,
                    head,
                    *manifest_byte_budget,
                )?),
            },
        ),
        AccountingHostOperation::Materialize {
            frame,
            manifest_byte_budget,
            expected_window_digest,
            handles,
        } => {
            let window =
                compile_accountability_manifest_window(frame, head, *manifest_byte_budget)?;
            if &window.window_digest != expected_window_digest {
                return Err(fault(
                    SharedAttentionFaultCode::StaleBase,
                    "materialize request expected manifest window digest is stale",
                ));
            }
            (
                None,
                AccountingHostResult::Materialization {
                    materialization: Box::new(materialize_accountable_objects(
                        &window,
                        head,
                        handles.clone(),
                    )?),
                },
            )
        }
        AccountingHostOperation::AcknowledgeAttention {
            frame,
            manifest_byte_budget,
            expected_window_digest,
            materialized_handles,
            receipt_seed,
        } => {
            let window =
                compile_accountability_manifest_window(frame, head, *manifest_byte_budget)?;
            if &window.window_digest != expected_window_digest {
                return Err(fault(
                    SharedAttentionFaultCode::StaleBase,
                    "acknowledge_attention request expected manifest window digest is stale",
                ));
            }
            let materialization =
                materialize_accountable_objects(&window, head, materialized_handles.clone())?;
            (
                None,
                AccountingHostResult::ManifestReceipt {
                    receipt: Box::new(finalize_manifest_attention_receipt(
                        &window,
                        head,
                        &materialization,
                        (**receipt_seed).clone(),
                    )?),
                },
            )
        }
        AccountingHostOperation::Resolve { query } => (
            None,
            AccountingHostResult::Resolution {
                resolution: resolve_accountability_reference(head, query)?,
            },
        ),
        AccountingHostOperation::InspectObject { handle } => (
            None,
            AccountingHostResult::Object {
                object: Box::new(inspect_accountable_object(head, handle)?.clone()),
            },
        ),
        AccountingHostOperation::ReadLedger { ledger_digest } => {
            let ledger = journal.ledgers.get(&ledger_digest.value).ok_or_else(|| {
                fault(
                    SharedAttentionFaultCode::UnknownReference,
                    "requested identity ledger digest is not retained",
                )
            })?;
            if &ledger.ledger_digest != ledger_digest {
                return Err(journal_fault("retained ledger key has digest collision"));
            }
            (
                None,
                AccountingHostResult::Ledger {
                    ledger: Box::new(ledger.clone()),
                },
            )
        }
        AccountingHostOperation::ReadEvent { event_id } => {
            let event = journal
                .events
                .iter()
                .find(|event| &event.event_id == event_id)
                .cloned()
                .ok_or_else(|| {
                    fault(
                        SharedAttentionFaultCode::UnknownEvent,
                        "requested accounting event is not retained",
                    )
                    .with_subject(event_id.clone())
                })?;
            (
                None,
                AccountingHostResult::Event {
                    event: Box::new(event),
                },
            )
        }
        AccountingHostOperation::ApplyPatch { patch } => {
            let next_ledger = apply_accountable_object_patch(head, (**patch).clone())?;
            let next_event = build_event(
                journal.events.len() as u64 + 1,
                request.request_id.clone(),
                request_digest.clone(),
                Some(head.ledger_digest.clone()),
                next_ledger.ledger_digest.clone(),
                Some(patch.handle.clone()),
                AccountingJournalMutation::PatchApplied {
                    patch: Box::new((**patch).clone()),
                },
            )?;
            let mut next_journal = journal.clone();
            if next_journal
                .ledgers
                .insert(next_ledger.ledger_digest.value.clone(), next_ledger.clone())
                .is_some()
            {
                return Err(fault(
                    SharedAttentionFaultCode::DigestCollision,
                    "patch successor ledger digest is already retained",
                ));
            }
            next_journal.events.push(next_event.clone());
            next_journal.head_ledger_digest = next_ledger.ledger_digest.clone();
            refresh_journal_digest(&mut next_journal)?;
            validate_accounting_journal(&next_journal)?;
            (
                Some(next_journal),
                AccountingHostResult::Applied {
                    event: Box::new(next_event),
                    ledger: Box::new(next_ledger),
                },
            )
        }
        AccountingHostOperation::AdmitObject { admission } => {
            let next_ledger = admit_accountable_object(head, admission)?;
            let next_event = build_event(
                journal.events.len() as u64 + 1,
                request.request_id.clone(),
                request_digest.clone(),
                Some(head.ledger_digest.clone()),
                next_ledger.ledger_digest.clone(),
                Some(admission.candidate.handle.clone()),
                AccountingJournalMutation::AdmissionApplied {
                    admission: Box::new((**admission).clone()),
                },
            )?;
            let mut next_journal = journal.clone();
            if next_journal
                .ledgers
                .insert(next_ledger.ledger_digest.value.clone(), next_ledger.clone())
                .is_some()
            {
                return Err(fault(
                    SharedAttentionFaultCode::DigestCollision,
                    "admission successor ledger digest is already retained",
                ));
            }
            next_journal.events.push(next_event.clone());
            next_journal.head_ledger_digest = next_ledger.ledger_digest.clone();
            refresh_journal_digest(&mut next_journal)?;
            validate_accounting_journal(&next_journal)?;
            (
                Some(next_journal),
                AccountingHostResult::Applied {
                    event: Box::new(next_event),
                    ledger: Box::new(next_ledger),
                },
            )
        }
    };

    let response_journal = successor.as_ref().unwrap_or(journal);
    let mut response = AccountingHostResponse {
        profile: ACCOUNTING_HOST_RESPONSE_PROFILE.to_owned(),
        request_id: request.request_id.clone(),
        request_digest,
        operation: operation_name,
        journal_id: response_journal.journal_id.clone(),
        journal_digest: response_journal.journal_digest.clone(),
        head_ledger_digest: response_journal.head_ledger_digest.clone(),
        result,
        response_digest: empty_sha256(),
    };
    response.response_digest = compute_response_digest(&response)?;
    validate_accounting_host_response(response_journal, &request, &response)?;
    Ok(AccountingHostTransition {
        successor,
        response,
    })
}

pub fn validate_accounting_host_response(
    journal: &AccountingJournal,
    request: &AccountingHostRequest,
    response: &AccountingHostResponse,
) -> Result<(), SharedAttentionFault> {
    validate_accounting_journal(journal)?;
    validate_request(request)?;
    if response.profile != ACCOUNTING_HOST_RESPONSE_PROFILE
        || response.request_id != request.request_id
        || response.request_digest != digest(request, "accounting host request")?
        || response.operation != request.operation.name()
        || response.journal_id != journal.journal_id
        || response.journal_digest != journal.journal_digest
        || response.head_ledger_digest != journal.head_ledger_digest
    {
        return Err(journal_fault(
            "accounting host response differs from its exact request or journal",
        ));
    }
    if response.response_digest != compute_response_digest(response)? {
        return Err(fault(
            SharedAttentionFaultCode::InvalidDigest,
            "accounting host response digest differs from canonical content",
        ));
    }
    let head = head_ledger(journal)?;
    match (&request.operation, &response.result) {
        (
            AccountingHostOperation::InspectJournal,
            AccountingHostResult::JournalSummary {
                basket_id,
                generation,
                event_count,
            },
        ) if basket_id == &journal.basket_id
            && generation == &head.generation
            && *event_count == journal.events.len() as u64 => {}
        (
            AccountingHostOperation::Project { frame, byte_budget },
            AccountingHostResult::Window { window },
        ) => {
            validate_accountability_window(window)?;
            if **window != compile_accountability_window(frame, head, *byte_budget)? {
                return Err(journal_fault(
                    "project response is not the exact requested window",
                ));
            }
        }
        (
            AccountingHostOperation::ProjectManifest {
                frame,
                manifest_byte_budget,
            },
            AccountingHostResult::ManifestWindow { window },
        ) => {
            validate_accountability_manifest_window(window)?;
            if **window
                != compile_accountability_manifest_window(frame, head, *manifest_byte_budget)?
            {
                return Err(journal_fault(
                    "project_manifest response is not the exact requested window",
                ));
            }
        }
        (
            AccountingHostOperation::Materialize {
                frame,
                manifest_byte_budget,
                expected_window_digest,
                handles,
            },
            AccountingHostResult::Materialization { materialization },
        ) => {
            let window =
                compile_accountability_manifest_window(frame, head, *manifest_byte_budget)?;
            if &window.window_digest != expected_window_digest {
                return Err(journal_fault(
                    "materialize response is bound to a stale expected window",
                ));
            }
            validate_accountable_materialization(&window, head, materialization)?;
            if **materialization != materialize_accountable_objects(&window, head, handles.clone())?
            {
                return Err(journal_fault(
                    "materialize response is not the exact requested object accounting",
                ));
            }
        }
        (
            AccountingHostOperation::AcknowledgeAttention {
                frame,
                manifest_byte_budget,
                expected_window_digest,
                materialized_handles,
                receipt_seed,
            },
            AccountingHostResult::ManifestReceipt { receipt },
        ) => {
            let window =
                compile_accountability_manifest_window(frame, head, *manifest_byte_budget)?;
            if &window.window_digest != expected_window_digest {
                return Err(journal_fault(
                    "manifest receipt response is bound to a stale expected window",
                ));
            }
            let materialization =
                materialize_accountable_objects(&window, head, materialized_handles.clone())?;
            validate_manifest_attention_receipt(&window, head, &materialization, receipt)?;
            if **receipt
                != finalize_manifest_attention_receipt(
                    &window,
                    head,
                    &materialization,
                    (**receipt_seed).clone(),
                )?
            {
                return Err(journal_fault(
                    "manifest receipt response is not the exact requested full-coverage receipt",
                ));
            }
        }
        (
            AccountingHostOperation::Resolve { query },
            AccountingHostResult::Resolution { resolution },
        ) if resolution == &resolve_accountability_reference(head, query)? => {}
        (
            AccountingHostOperation::InspectObject { handle },
            AccountingHostResult::Object { object },
        ) if object.as_ref() == inspect_accountable_object(head, handle)? => {}
        (
            AccountingHostOperation::ReadLedger { ledger_digest },
            AccountingHostResult::Ledger { ledger },
        ) if ledger.ledger_digest == *ledger_digest
            && journal.ledgers.get(&ledger_digest.value) == Some(ledger.as_ref()) => {}
        (
            AccountingHostOperation::ReadEvent { event_id },
            AccountingHostResult::Event { event },
        ) if event.event_id == *event_id
            && journal
                .events
                .iter()
                .any(|candidate| candidate == event.as_ref()) => {}
        (
            AccountingHostOperation::ApplyPatch { patch },
            AccountingHostResult::Applied { event, ledger },
        ) if ledger.ledger_digest == journal.head_ledger_digest
            && journal.ledgers.get(&ledger.ledger_digest.value) == Some(ledger.as_ref())
            && journal.events.last() == Some(event.as_ref())
            && event.request_id == request.request_id
            && event.request_digest == response.request_digest
            && event.mutation
                == AccountingJournalMutation::PatchApplied {
                    patch: Box::new((**patch).clone()),
                } => {}
        (
            AccountingHostOperation::AdmitObject { admission },
            AccountingHostResult::Applied { event, ledger },
        ) if ledger.ledger_digest == journal.head_ledger_digest
            && journal.ledgers.get(&ledger.ledger_digest.value) == Some(ledger.as_ref())
            && journal.events.last() == Some(event.as_ref())
            && event.request_id == request.request_id
            && event.request_digest == response.request_digest
            && event.mutation
                == AccountingJournalMutation::AdmissionApplied {
                    admission: Box::new((**admission).clone()),
                } => {}
        _ => {
            return Err(journal_fault(
                "accounting host result does not match the requested operation",
            ));
        }
    }
    Ok(())
}

fn validate_request(request: &AccountingHostRequest) -> Result<(), SharedAttentionFault> {
    if request.profile != ACCOUNTING_HOST_REQUEST_PROFILE {
        return Err(journal_fault("unsupported accounting host request profile"));
    }
    Ok(())
}

fn head_ledger(journal: &AccountingJournal) -> Result<&IdentityLedger, SharedAttentionFault> {
    journal
        .ledgers
        .get(&journal.head_ledger_digest.value)
        .filter(|ledger| ledger.ledger_digest == journal.head_ledger_digest)
        .ok_or_else(|| journal_fault("accounting journal head ledger is absent"))
}

#[allow(clippy::too_many_arguments)]
fn build_event(
    sequence: u64,
    request_id: SemanticId,
    request_digest: ContentDigest,
    predecessor_ledger_digest: Option<ContentDigest>,
    successor_ledger_digest: ContentDigest,
    touched_handle: Option<SemanticId>,
    mutation: AccountingJournalMutation,
) -> Result<AccountingJournalEvent, SharedAttentionFault> {
    let identity_digest = digest(
        &(
            sequence,
            &request_id,
            &request_digest,
            &predecessor_ledger_digest,
            &successor_ledger_digest,
            &touched_handle,
            &mutation,
        ),
        "accounting journal event identity",
    )?;
    let mut event = AccountingJournalEvent {
        profile: ACCOUNTING_JOURNAL_EVENT_PROFILE.to_owned(),
        event_id: derive("accounting:event", &identity_digest)?,
        sequence,
        request_id,
        request_digest,
        predecessor_ledger_digest,
        successor_ledger_digest,
        touched_handle,
        mutation,
        event_digest: empty_sha256(),
    };
    event.event_digest = compute_event_digest(&event)?;
    validate_event(&event)?;
    Ok(event)
}

fn validate_event(event: &AccountingJournalEvent) -> Result<(), SharedAttentionFault> {
    if event.profile != ACCOUNTING_JOURNAL_EVENT_PROFILE || event.sequence == 0 {
        return Err(journal_fault(
            "unsupported or zero-sequence accounting event",
        ));
    }
    let identity_digest = digest(
        &(
            event.sequence,
            &event.request_id,
            &event.request_digest,
            &event.predecessor_ledger_digest,
            &event.successor_ledger_digest,
            &event.touched_handle,
            &event.mutation,
        ),
        "accounting journal event identity",
    )?;
    if event.event_id != derive("accounting:event", &identity_digest)?
        || event.event_digest != compute_event_digest(event)?
    {
        return Err(fault(
            SharedAttentionFaultCode::InvalidDigest,
            "accounting journal event identity or digest differs from canonical content",
        ));
    }
    Ok(())
}

fn refresh_journal_digest(journal: &mut AccountingJournal) -> Result<(), SharedAttentionFault> {
    journal.journal_digest = compute_journal_digest(journal)?;
    Ok(())
}

fn compute_event_digest(
    event: &AccountingJournalEvent,
) -> Result<ContentDigest, SharedAttentionFault> {
    let mut body = event.clone();
    body.event_digest = empty_sha256();
    digest(&body, "accounting journal event")
}

fn compute_journal_digest(
    journal: &AccountingJournal,
) -> Result<ContentDigest, SharedAttentionFault> {
    let mut body = journal.clone();
    body.journal_digest = empty_sha256();
    digest(&body, "accounting journal")
}

fn compute_response_digest(
    response: &AccountingHostResponse,
) -> Result<ContentDigest, SharedAttentionFault> {
    let mut body = response.clone();
    body.response_digest = empty_sha256();
    digest(&body, "accounting host response")
}

fn journal_fault(message: impl Into<String>) -> SharedAttentionFault {
    fault(SharedAttentionFaultCode::InvalidLedger, message)
}
