//! Deterministic identity accounting projected into one shared-attention frame.
//!
//! The model-facing handle is stable and readable. SHA-256 digests remain
//! integrity and compare-and-set evidence; they never replace object identity.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{
    SharedAttentionFault, SharedAttentionFaultCode, SharedAttentionFrame,
    validate_shared_attention_frame,
};
use crate::procedure_runtime::empty_sha256;
use crate::{ContentDigest, SemanticId};

use super::runtime::{digest, fault, require_text};

pub const IDENTITY_LEDGER_PROFILE: &str = "cantor-identity-ledger/0.1";
pub const ACCOUNTABLE_OBJECT_PROFILE: &str = "cantor-accountable-object/0.1";
pub const ACCOUNTABILITY_REGISTER_PROFILE: &str = "cantor-accountability-register/0.1";
pub const ACCOUNTABILITY_WINDOW_PROFILE: &str = "cantor-accountability-inference-window/0.1";
pub const ATTENTION_RECEIPT_PROFILE: &str = "cantor-accountability-attention-receipt/0.1";

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountableObject {
    pub profile: String,
    pub handle: SemanticId,
    pub object_type: SemanticId,
    pub labels: BTreeSet<String>,
    pub differentiators: BTreeMap<String, String>,
    pub state: BTreeMap<String, String>,
    pub roles: BTreeSet<SemanticId>,
    pub purposes: BTreeSet<SemanticId>,
    pub obligations: BTreeSet<SemanticId>,
    pub provenance_refs: BTreeSet<SemanticId>,
    pub version: u64,
    pub record_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityLedger {
    pub profile: String,
    pub basket_id: SemanticId,
    pub generation: u64,
    pub objects: BTreeMap<SemanticId, AccountableObject>,
    pub ledger_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountabilityRegister {
    pub profile: String,
    pub basket_id: SemanticId,
    pub ledger_generation: u64,
    pub ledger_digest: ContentDigest,
    pub member_count: u64,
    pub entries: Vec<AccountableObject>,
    pub register_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountabilityInferenceWindow {
    pub profile: String,
    pub frame_id: SemanticId,
    pub frame_digest: ContentDigest,
    pub frame_purpose: String,
    pub ledger_digest: ContentDigest,
    pub register: AccountabilityRegister,
    pub rendered_register: String,
    pub window_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "resolution", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReferenceResolution {
    Resolved { handle: SemanticId },
    Ambiguous { candidates: BTreeSet<SemanticId> },
    Unknown { query: String },
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountableObjectPatch {
    pub expected_ledger_digest: ContentDigest,
    pub handle: SemanticId,
    pub expected_version: u64,
    pub labels: Option<BTreeSet<String>>,
    pub differentiators: Option<BTreeMap<String, String>>,
    pub state: Option<BTreeMap<String, String>>,
    pub roles: Option<BTreeSet<SemanticId>>,
    pub purposes: Option<BTreeSet<SemanticId>>,
    pub obligations: Option<BTreeSet<SemanticId>>,
    pub provenance_refs: Option<BTreeSet<SemanticId>>,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttentionMemberDisposition {
    Relevant,
    NotApplicable,
    Unresolved,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttentionMemberReceipt {
    pub handle: SemanticId,
    pub disposition: AttentionMemberDisposition,
    pub rationale: String,
    pub evidence_refs: BTreeSet<SemanticId>,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttentionReceiptStatus {
    Complete,
    Held,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttentionReceiptSeed {
    pub receipt_id: SemanticId,
    pub window_digest: ContentDigest,
    pub ledger_digest: ContentDigest,
    pub register_digest: ContentDigest,
    pub member_receipts: BTreeMap<SemanticId, AttentionMemberReceipt>,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttentionReceipt {
    pub profile: String,
    pub receipt_id: SemanticId,
    pub window_digest: ContentDigest,
    pub ledger_digest: ContentDigest,
    pub register_digest: ContentDigest,
    pub member_receipts: BTreeMap<SemanticId, AttentionMemberReceipt>,
    pub status: AttentionReceiptStatus,
    pub receipt_digest: ContentDigest,
}

pub fn finalize_accountable_object(
    mut object: AccountableObject,
) -> Result<AccountableObject, SharedAttentionFault> {
    object.record_digest = empty_sha256();
    validate_object_body(&object)?;
    object.record_digest = object_digest(&object)?;
    validate_accountable_object(&object)?;
    Ok(object)
}

pub fn validate_accountable_object(object: &AccountableObject) -> Result<(), SharedAttentionFault> {
    validate_object_body(object)?;
    if object.record_digest != object_digest(object)? {
        return Err(accounting_fault(
            SharedAttentionFaultCode::InvalidDigest,
            "accountable object digest differs from canonical content",
        )
        .with_subject(object.handle.clone()));
    }
    Ok(())
}

pub fn new_identity_ledger(
    basket_id: SemanticId,
    objects: Vec<AccountableObject>,
) -> Result<IdentityLedger, SharedAttentionFault> {
    let mut by_handle = BTreeMap::new();
    for object in objects {
        validate_accountable_object(&object)?;
        let handle = object.handle.clone();
        if by_handle.insert(handle.clone(), object).is_some() {
            return Err(accounting_fault(
                SharedAttentionFaultCode::DuplicateIdentity,
                "identity ledger contains a duplicate object handle",
            )
            .with_subject(handle));
        }
    }
    if by_handle.is_empty() {
        return Err(accounting_fault(
            SharedAttentionFaultCode::InvalidLedger,
            "identity ledger requires at least one accountable object",
        ));
    }
    let mut ledger = IdentityLedger {
        profile: IDENTITY_LEDGER_PROFILE.to_owned(),
        basket_id,
        generation: 1,
        objects: by_handle,
        ledger_digest: empty_sha256(),
    };
    refresh_ledger_digest(&mut ledger)?;
    validate_identity_ledger(&ledger)?;
    Ok(ledger)
}

pub fn validate_identity_ledger(ledger: &IdentityLedger) -> Result<(), SharedAttentionFault> {
    if ledger.profile != IDENTITY_LEDGER_PROFILE || ledger.generation == 0 {
        return Err(accounting_fault(
            SharedAttentionFaultCode::InvalidLedger,
            "identity ledger profile or generation is invalid",
        ));
    }
    if ledger.objects.is_empty() {
        return Err(accounting_fault(
            SharedAttentionFaultCode::InvalidLedger,
            "identity ledger requires at least one accountable object",
        ));
    }
    for (handle, object) in &ledger.objects {
        validate_accountable_object(object)?;
        if handle != &object.handle {
            return Err(accounting_fault(
                SharedAttentionFaultCode::InvalidLedger,
                "identity ledger map key differs from object handle",
            )
            .with_subject(handle.clone()));
        }
    }
    if ledger.ledger_digest != ledger_digest(ledger)? {
        return Err(accounting_fault(
            SharedAttentionFaultCode::InvalidDigest,
            "identity ledger digest differs from canonical content",
        ));
    }
    Ok(())
}

pub fn compile_accountability_window(
    frame: &SharedAttentionFrame,
    ledger: &IdentityLedger,
    byte_budget: u64,
) -> Result<AccountabilityInferenceWindow, SharedAttentionFault> {
    validate_shared_attention_frame(frame)?;
    validate_identity_ledger(ledger)?;
    let register = project_register(ledger)?;
    let rendered_register = render_register(&register)?;
    let rendered_bytes = u64::try_from(rendered_register.len()).map_err(|_| {
        accounting_fault(
            SharedAttentionFaultCode::CapacityOverflow,
            "accountability register byte length does not fit u64",
        )
    })?;
    if rendered_bytes > byte_budget {
        return Err(accounting_fault(
            SharedAttentionFaultCode::CapacityOverflow,
            format!(
                "complete accountability register requires {rendered_bytes} bytes but budget is {byte_budget}; refusing truncation"
            ),
        ));
    }
    let mut window = AccountabilityInferenceWindow {
        profile: ACCOUNTABILITY_WINDOW_PROFILE.to_owned(),
        frame_id: frame.frame_id.clone(),
        frame_digest: frame.frame_digest.clone(),
        frame_purpose: frame.purpose.clone(),
        ledger_digest: ledger.ledger_digest.clone(),
        register,
        rendered_register,
        window_digest: empty_sha256(),
    };
    window.window_digest = window_digest(&window)?;
    validate_accountability_window(&window)?;
    Ok(window)
}

pub fn validate_accountability_window(
    window: &AccountabilityInferenceWindow,
) -> Result<(), SharedAttentionFault> {
    if window.profile != ACCOUNTABILITY_WINDOW_PROFILE {
        return Err(accounting_fault(
            SharedAttentionFaultCode::InvalidFrame,
            "accountability inference window profile is not supported",
        ));
    }
    require_text(&window.frame_purpose, "accountability frame purpose")?;
    validate_register(&window.register)?;
    if window.ledger_digest != window.register.ledger_digest
        || window.rendered_register != render_register(&window.register)?
    {
        return Err(accounting_fault(
            SharedAttentionFaultCode::InvalidFrame,
            "accountability window differs from its exact ledger or rendered register",
        ));
    }
    if window.window_digest != window_digest(window)? {
        return Err(accounting_fault(
            SharedAttentionFaultCode::InvalidDigest,
            "accountability window digest differs from canonical content",
        ));
    }
    Ok(())
}

pub fn resolve_accountability_reference(
    ledger: &IdentityLedger,
    query: &str,
) -> Result<ReferenceResolution, SharedAttentionFault> {
    validate_identity_ledger(ledger)?;
    let trimmed = query.trim();
    let handle_text = trimmed.strip_prefix('@').unwrap_or(trimmed);
    if let Ok(handle) = SemanticId::new(handle_text.to_owned())
        && ledger.objects.contains_key(&handle)
    {
        return Ok(ReferenceResolution::Resolved { handle });
    }
    let normalized = normalize_label(trimmed);
    if normalized.is_empty() {
        return Ok(ReferenceResolution::Unknown {
            query: query.to_owned(),
        });
    }
    let candidates = ledger
        .objects
        .values()
        .filter(|object| {
            object
                .labels
                .iter()
                .any(|label| normalize_label(label) == normalized)
        })
        .map(|object| object.handle.clone())
        .collect::<BTreeSet<_>>();
    Ok(match candidates.len() {
        0 => ReferenceResolution::Unknown {
            query: query.to_owned(),
        },
        1 => ReferenceResolution::Resolved {
            handle: candidates.into_iter().next().expect("one candidate exists"),
        },
        _ => ReferenceResolution::Ambiguous { candidates },
    })
}

pub fn inspect_accountable_object<'ledger>(
    ledger: &'ledger IdentityLedger,
    handle: &SemanticId,
) -> Result<&'ledger AccountableObject, SharedAttentionFault> {
    validate_identity_ledger(ledger)?;
    ledger.objects.get(handle).ok_or_else(|| {
        accounting_fault(
            SharedAttentionFaultCode::UnknownReference,
            "exact accountable object handle is absent from the identity ledger",
        )
        .with_subject(handle.clone())
    })
}

pub fn apply_accountable_object_patch(
    ledger: &IdentityLedger,
    patch: AccountableObjectPatch,
) -> Result<IdentityLedger, SharedAttentionFault> {
    validate_identity_ledger(ledger)?;
    if patch.expected_ledger_digest != ledger.ledger_digest {
        return Err(accounting_fault(
            SharedAttentionFaultCode::StaleLedger,
            "accountable object patch is bound to a stale identity ledger",
        ));
    }
    if patch.labels.is_none()
        && patch.differentiators.is_none()
        && patch.state.is_none()
        && patch.roles.is_none()
        && patch.purposes.is_none()
        && patch.obligations.is_none()
        && patch.provenance_refs.is_none()
    {
        return Err(accounting_fault(
            SharedAttentionFaultCode::InvalidTransition,
            "accountable object patch contains no mutation",
        ));
    }
    let mut successor = ledger.clone();
    let object = successor.objects.get_mut(&patch.handle).ok_or_else(|| {
        accounting_fault(
            SharedAttentionFaultCode::UnknownReference,
            "accountable object patch names an unknown exact handle",
        )
        .with_subject(patch.handle.clone())
    })?;
    if object.version != patch.expected_version {
        return Err(accounting_fault(
            SharedAttentionFaultCode::StaleBase,
            "accountable object patch is bound to a stale object version",
        )
        .with_subject(patch.handle));
    }
    if let Some(value) = patch.labels {
        object.labels = value;
    }
    if let Some(value) = patch.differentiators {
        object.differentiators = value;
    }
    if let Some(value) = patch.state {
        object.state = value;
    }
    if let Some(value) = patch.roles {
        object.roles = value;
    }
    if let Some(value) = patch.purposes {
        object.purposes = value;
    }
    if let Some(value) = patch.obligations {
        object.obligations = value;
    }
    if let Some(value) = patch.provenance_refs {
        object.provenance_refs = value;
    }
    object.version = object.version.checked_add(1).ok_or_else(|| {
        accounting_fault(
            SharedAttentionFaultCode::InvalidTransition,
            "accountable object version overflowed",
        )
    })?;
    *object = finalize_accountable_object(object.clone())?;
    let before_handles = ledger.objects.keys().cloned().collect::<BTreeSet<_>>();
    let after_handles = successor.objects.keys().cloned().collect::<BTreeSet<_>>();
    if before_handles != after_handles || ledger.objects.len() != successor.objects.len() {
        return Err(accounting_fault(
            SharedAttentionFaultCode::ConflictingMutation,
            "accountable object patch violated basket membership conservation",
        ));
    }
    successor.generation = successor.generation.checked_add(1).ok_or_else(|| {
        accounting_fault(
            SharedAttentionFaultCode::InvalidTransition,
            "identity ledger generation overflowed",
        )
    })?;
    refresh_ledger_digest(&mut successor)?;
    validate_identity_ledger(&successor)?;
    Ok(successor)
}

pub(super) fn insert_admitted_accountable_object(
    ledger: &IdentityLedger,
    candidate: AccountableObject,
) -> Result<IdentityLedger, SharedAttentionFault> {
    validate_identity_ledger(ledger)?;
    validate_accountable_object(&candidate)?;
    if candidate.version != 1 {
        return Err(accounting_fault(
            SharedAttentionFaultCode::InvalidTransition,
            "newly admitted accountable object must begin at version one",
        )
        .with_subject(candidate.handle));
    }
    let mut successor = ledger.clone();
    let handle = candidate.handle.clone();
    if successor
        .objects
        .insert(handle.clone(), candidate)
        .is_some()
    {
        return Err(accounting_fault(
            SharedAttentionFaultCode::DuplicateIdentity,
            "identity ledger already contains the proposed accountable object handle",
        )
        .with_subject(handle));
    }
    successor.generation = successor.generation.checked_add(1).ok_or_else(|| {
        accounting_fault(
            SharedAttentionFaultCode::InvalidTransition,
            "identity ledger generation overflowed during admission",
        )
    })?;
    refresh_ledger_digest(&mut successor)?;
    validate_identity_ledger(&successor)?;
    Ok(successor)
}

pub fn finalize_attention_receipt(
    window: &AccountabilityInferenceWindow,
    seed: AttentionReceiptSeed,
) -> Result<AttentionReceipt, SharedAttentionFault> {
    validate_accountability_window(window)?;
    if seed.window_digest != window.window_digest
        || seed.ledger_digest != window.ledger_digest
        || seed.register_digest != window.register.register_digest
    {
        return Err(accounting_fault(
            SharedAttentionFaultCode::StaleBase,
            "attention receipt seed differs from its exact inference window",
        ));
    }
    let expected = window
        .register
        .entries
        .iter()
        .map(|entry| entry.handle.clone())
        .collect::<BTreeSet<_>>();
    let supplied = seed
        .member_receipts
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    if supplied != expected {
        return Err(accounting_fault(
            SharedAttentionFaultCode::MissingAttestation,
            "attention receipt must dispose every register member exactly once and no foreign member",
        ));
    }
    for (handle, member) in &seed.member_receipts {
        if handle != &member.handle {
            return Err(accounting_fault(
                SharedAttentionFaultCode::InvalidFrame,
                "attention receipt map key differs from member handle",
            )
            .with_subject(handle.clone()));
        }
        require_text(&member.rationale, "attention member rationale")?;
    }
    let status = if seed
        .member_receipts
        .values()
        .any(|item| item.disposition == AttentionMemberDisposition::Unresolved)
    {
        AttentionReceiptStatus::Held
    } else {
        AttentionReceiptStatus::Complete
    };
    let mut receipt = AttentionReceipt {
        profile: ATTENTION_RECEIPT_PROFILE.to_owned(),
        receipt_id: seed.receipt_id,
        window_digest: seed.window_digest,
        ledger_digest: seed.ledger_digest,
        register_digest: seed.register_digest,
        member_receipts: seed.member_receipts,
        status,
        receipt_digest: empty_sha256(),
    };
    receipt.receipt_digest = receipt_digest(&receipt)?;
    validate_attention_receipt(window, &receipt)?;
    Ok(receipt)
}

pub fn validate_attention_receipt(
    window: &AccountabilityInferenceWindow,
    receipt: &AttentionReceipt,
) -> Result<(), SharedAttentionFault> {
    if receipt.profile != ATTENTION_RECEIPT_PROFILE {
        return Err(accounting_fault(
            SharedAttentionFaultCode::InvalidFrame,
            "attention receipt profile is not supported",
        ));
    }
    let rebuilt = finalize_attention_receipt_body(window, receipt)?;
    if rebuilt.status != receipt.status || rebuilt.receipt_digest != receipt.receipt_digest {
        return Err(accounting_fault(
            SharedAttentionFaultCode::InvalidDigest,
            "attention receipt differs from exact coverage or canonical digest",
        ));
    }
    Ok(())
}

fn finalize_attention_receipt_body(
    window: &AccountabilityInferenceWindow,
    receipt: &AttentionReceipt,
) -> Result<AttentionReceipt, SharedAttentionFault> {
    validate_accountability_window(window)?;
    if receipt.window_digest != window.window_digest
        || receipt.ledger_digest != window.ledger_digest
        || receipt.register_digest != window.register.register_digest
    {
        return Err(accounting_fault(
            SharedAttentionFaultCode::StaleBase,
            "attention receipt differs from its exact inference window",
        ));
    }
    let expected = window
        .register
        .entries
        .iter()
        .map(|entry| entry.handle.clone())
        .collect::<BTreeSet<_>>();
    if receipt
        .member_receipts
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>()
        != expected
    {
        return Err(accounting_fault(
            SharedAttentionFaultCode::MissingAttestation,
            "attention receipt coverage differs from complete register membership",
        ));
    }
    for (handle, member) in &receipt.member_receipts {
        if handle != &member.handle {
            return Err(accounting_fault(
                SharedAttentionFaultCode::InvalidFrame,
                "attention receipt map key differs from member handle",
            ));
        }
        require_text(&member.rationale, "attention member rationale")?;
    }
    let mut rebuilt = receipt.clone();
    rebuilt.status = if rebuilt
        .member_receipts
        .values()
        .any(|item| item.disposition == AttentionMemberDisposition::Unresolved)
    {
        AttentionReceiptStatus::Held
    } else {
        AttentionReceiptStatus::Complete
    };
    rebuilt.receipt_digest = empty_sha256();
    rebuilt.receipt_digest = receipt_digest(&rebuilt)?;
    Ok(rebuilt)
}

fn project_register(
    ledger: &IdentityLedger,
) -> Result<AccountabilityRegister, SharedAttentionFault> {
    let member_count = u64::try_from(ledger.objects.len()).map_err(|_| {
        accounting_fault(
            SharedAttentionFaultCode::CapacityOverflow,
            "accountability register member count does not fit u64",
        )
    })?;
    let mut register = AccountabilityRegister {
        profile: ACCOUNTABILITY_REGISTER_PROFILE.to_owned(),
        basket_id: ledger.basket_id.clone(),
        ledger_generation: ledger.generation,
        ledger_digest: ledger.ledger_digest.clone(),
        member_count,
        entries: ledger.objects.values().cloned().collect(),
        register_digest: empty_sha256(),
    };
    register.register_digest = register_digest(&register)?;
    validate_register(&register)?;
    Ok(register)
}

fn validate_register(register: &AccountabilityRegister) -> Result<(), SharedAttentionFault> {
    if register.profile != ACCOUNTABILITY_REGISTER_PROFILE
        || register.member_count != register.entries.len() as u64
        || register.entries.is_empty()
    {
        return Err(accounting_fault(
            SharedAttentionFaultCode::InvalidLedger,
            "accountability register profile count or membership is invalid",
        ));
    }
    let mut objects = BTreeMap::new();
    let mut previous: Option<&SemanticId> = None;
    for entry in &register.entries {
        validate_accountable_object(entry)?;
        if previous.is_some_and(|prior| prior >= &entry.handle) {
            return Err(accounting_fault(
                SharedAttentionFaultCode::InvalidLedger,
                "accountability register entries are not in strict handle order",
            ));
        }
        previous = Some(&entry.handle);
        objects.insert(entry.handle.clone(), entry.clone());
    }
    let ledger = IdentityLedger {
        profile: IDENTITY_LEDGER_PROFILE.to_owned(),
        basket_id: register.basket_id.clone(),
        generation: register.ledger_generation,
        objects,
        ledger_digest: register.ledger_digest.clone(),
    };
    validate_identity_ledger(&ledger)?;
    if register.register_digest != register_digest(register)? {
        return Err(accounting_fault(
            SharedAttentionFaultCode::InvalidDigest,
            "accountability register digest differs from canonical content",
        ));
    }
    Ok(())
}

fn render_register(register: &AccountabilityRegister) -> Result<String, SharedAttentionFault> {
    let mut rendered = format!(
        "[ACCOUNTABILITY_REGISTER basket={} generation={} members={} ledger={} register={}]\n",
        register.basket_id,
        register.ledger_generation,
        register.member_count,
        register.ledger_digest.value,
        register.register_digest.value
    );
    for entry in &register.entries {
        let json = serde_json::to_string(entry).map_err(|error| {
            accounting_fault(
                SharedAttentionFaultCode::MachineForm,
                format!("accountability register entry serialization failed: {error}"),
            )
        })?;
        rendered.push('@');
        rendered.push_str(entry.handle.as_str());
        rendered.push(' ');
        rendered.push_str(&json);
        rendered.push('\n');
    }
    rendered.push_str("[/ACCOUNTABILITY_REGISTER]");
    Ok(rendered)
}

fn validate_object_body(object: &AccountableObject) -> Result<(), SharedAttentionFault> {
    if object.profile != ACCOUNTABLE_OBJECT_PROFILE || object.version == 0 {
        return Err(accounting_fault(
            SharedAttentionFaultCode::InvalidLedger,
            "accountable object profile or version is invalid",
        )
        .with_subject(object.handle.clone()));
    }
    let object_type = object.object_type.as_str();
    if object_type.contains('/') {
        return Err(accounting_fault(
            SharedAttentionFaultCode::InvalidLedger,
            "accountable object type must not contain a slash",
        )
        .with_subject(object.handle.clone()));
    }
    let prefix = format!("object:{object_type}/");
    let Some(local_id) = object.handle.as_str().strip_prefix(&prefix) else {
        return Err(accounting_fault(
            SharedAttentionFaultCode::InvalidLedger,
            "accountable object handle must be shaped object:{type}/{local_id}",
        )
        .with_subject(object.handle.clone()));
    };
    if local_id.is_empty() || local_id.contains('/') {
        return Err(accounting_fault(
            SharedAttentionFaultCode::InvalidLedger,
            "accountable object local identity must be one nonempty path segment",
        )
        .with_subject(object.handle.clone()));
    }
    for label in &object.labels {
        require_text(label, "accountable object label")?;
    }
    for (key, value) in object.differentiators.iter().chain(object.state.iter()) {
        require_text(key, "accountable object field key")?;
        require_text(value, "accountable object field value")?;
    }
    Ok(())
}

fn refresh_ledger_digest(ledger: &mut IdentityLedger) -> Result<(), SharedAttentionFault> {
    ledger.ledger_digest = ledger_digest(ledger)?;
    Ok(())
}

fn object_digest(object: &AccountableObject) -> Result<ContentDigest, SharedAttentionFault> {
    let mut body = object.clone();
    body.record_digest = empty_sha256();
    digest(&body, "accountable object")
}

fn ledger_digest(ledger: &IdentityLedger) -> Result<ContentDigest, SharedAttentionFault> {
    let mut body = ledger.clone();
    body.ledger_digest = empty_sha256();
    digest(&body, "identity ledger")
}

fn register_digest(
    register: &AccountabilityRegister,
) -> Result<ContentDigest, SharedAttentionFault> {
    let mut body = register.clone();
    body.register_digest = empty_sha256();
    digest(&body, "accountability register")
}

fn window_digest(
    window: &AccountabilityInferenceWindow,
) -> Result<ContentDigest, SharedAttentionFault> {
    let mut body = window.clone();
    body.window_digest = empty_sha256();
    digest(&body, "accountability inference window")
}

fn receipt_digest(receipt: &AttentionReceipt) -> Result<ContentDigest, SharedAttentionFault> {
    let mut body = receipt.clone();
    body.receipt_digest = empty_sha256();
    digest(&body, "accountability attention receipt")
}

fn normalize_label(value: &str) -> String {
    value.trim().to_lowercase()
}

fn accounting_fault(
    code: SharedAttentionFaultCode,
    message: impl Into<String>,
) -> SharedAttentionFault {
    fault(code, message)
}
