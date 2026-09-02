//! Compact complete identity projection and exact, read-only attention accounting.
//!
//! These forms keep every admitted handle visible without copying mutable object
//! bodies into the inference window. Exact bodies are materialized separately,
//! and a receipt accounts for every manifest member without claiming hidden model
//! attention, external truth, or effect authority.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::runtime::{digest, fault, require_text};
use super::{
    AccountableObject, AttentionMemberReceipt, AttentionMemberDisposition, AttentionReceiptStatus,
    IdentityLedger, SharedAttentionFault, SharedAttentionFaultCode, SharedAttentionFrame,
    validate_accountable_object, validate_identity_ledger, validate_shared_attention_frame,
};
use crate::procedure_runtime::empty_sha256;
use crate::{ContentDigest, SemanticId};

pub const ACCOUNTABILITY_MANIFEST_PROFILE: &str = "cantor-accountability-manifest/0.1";
pub const ACCOUNTABILITY_MANIFEST_WINDOW_PROFILE: &str =
    "cantor-accountability-manifest-window/0.1";
pub const ACCOUNTABLE_MATERIALIZATION_PROFILE: &str =
    "cantor-accountable-materialization/0.1";
pub const MANIFEST_ATTENTION_RECEIPT_PROFILE: &str =
    "cantor-manifest-attention-receipt/0.1";
pub const MAX_MATERIALIZED_HANDLES: usize = 32;

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountabilityManifestEntry {
    pub handle: SemanticId,
    pub object_type: SemanticId,
    pub display_label: String,
    pub version: u64,
    pub record_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountabilityManifest {
    pub profile: String,
    pub basket_id: SemanticId,
    pub ledger_generation: u64,
    pub ledger_digest: ContentDigest,
    pub member_count: u64,
    pub entries: Vec<AccountabilityManifestEntry>,
    pub manifest_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountabilityManifestWindow {
    pub profile: String,
    pub frame_id: SemanticId,
    pub frame_digest: ContentDigest,
    pub frame_purpose: String,
    pub ledger_digest: ContentDigest,
    pub manifest: AccountabilityManifest,
    pub rendered_manifest: String,
    pub window_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountableMaterialization {
    pub profile: String,
    pub window_digest: ContentDigest,
    pub ledger_digest: ContentDigest,
    pub requested_handles: Vec<SemanticId>,
    pub objects: Vec<AccountableObject>,
    pub materialization_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestAttentionReceiptSeed {
    pub receipt_id: SemanticId,
    pub window_digest: ContentDigest,
    pub ledger_digest: ContentDigest,
    pub manifest_digest: ContentDigest,
    pub materialization_digest: ContentDigest,
    pub member_receipts: BTreeMap<SemanticId, AttentionMemberReceipt>,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestAttentionReceipt {
    pub profile: String,
    pub receipt_id: SemanticId,
    pub window_digest: ContentDigest,
    pub ledger_digest: ContentDigest,
    pub manifest_digest: ContentDigest,
    pub materialization_digest: ContentDigest,
    pub member_receipts: BTreeMap<SemanticId, AttentionMemberReceipt>,
    pub status: AttentionReceiptStatus,
    pub receipt_digest: ContentDigest,
}

pub fn compile_accountability_manifest_window(
    frame: &SharedAttentionFrame,
    ledger: &IdentityLedger,
    byte_budget: u64,
) -> Result<AccountabilityManifestWindow, SharedAttentionFault> {
    validate_shared_attention_frame(frame)?;
    let manifest = project_accountability_manifest(ledger)?;
    let rendered_manifest = render_manifest(&manifest)?;
    let rendered_bytes = u64::try_from(rendered_manifest.len()).map_err(|_| {
        manifest_fault(
            SharedAttentionFaultCode::CapacityOverflow,
            "accountability manifest byte length does not fit u64",
        )
    })?;
    if byte_budget == 0 || rendered_bytes > byte_budget {
        return Err(manifest_fault(
            SharedAttentionFaultCode::CapacityOverflow,
            format!(
                "complete accountability manifest requires {rendered_bytes} bytes but budget is {byte_budget}; refusing truncation"
            ),
        ));
    }
    let mut window = AccountabilityManifestWindow {
        profile: ACCOUNTABILITY_MANIFEST_WINDOW_PROFILE.to_owned(),
        frame_id: frame.frame_id.clone(),
        frame_digest: frame.frame_digest.clone(),
        frame_purpose: frame.purpose.clone(),
        ledger_digest: ledger.ledger_digest.clone(),
        manifest,
        rendered_manifest,
        window_digest: empty_sha256(),
    };
    window.window_digest = manifest_window_digest(&window)?;
    validate_accountability_manifest_window(&window)?;
    Ok(window)
}

pub fn project_accountability_manifest(
    ledger: &IdentityLedger,
) -> Result<AccountabilityManifest, SharedAttentionFault> {
    validate_identity_ledger(ledger)?;
    let entries = ledger
        .objects
        .values()
        .map(|object| AccountabilityManifestEntry {
            handle: object.handle.clone(),
            object_type: object.object_type.clone(),
            display_label: object
                .labels
                .first()
                .cloned()
                .unwrap_or_else(|| format!("@{}", object.handle)),
            version: object.version,
            record_digest: object.record_digest.clone(),
        })
        .collect::<Vec<_>>();
    let member_count = u64::try_from(entries.len()).map_err(|_| {
        manifest_fault(
            SharedAttentionFaultCode::CapacityOverflow,
            "accountability manifest member count does not fit u64",
        )
    })?;
    let mut manifest = AccountabilityManifest {
        profile: ACCOUNTABILITY_MANIFEST_PROFILE.to_owned(),
        basket_id: ledger.basket_id.clone(),
        ledger_generation: ledger.generation,
        ledger_digest: ledger.ledger_digest.clone(),
        member_count,
        entries,
        manifest_digest: empty_sha256(),
    };
    manifest.manifest_digest = manifest_digest(&manifest)?;
    validate_accountability_manifest(&manifest)?;
    Ok(manifest)
}

pub fn validate_accountability_manifest(
    manifest: &AccountabilityManifest,
) -> Result<(), SharedAttentionFault> {
    if manifest.profile != ACCOUNTABILITY_MANIFEST_PROFILE
        || manifest.entries.is_empty()
        || manifest.member_count != manifest.entries.len() as u64
        || manifest.ledger_generation == 0
    {
        return Err(manifest_fault(
            SharedAttentionFaultCode::InvalidLedger,
            "accountability manifest profile count generation or membership is invalid",
        ));
    }
    let mut previous: Option<&SemanticId> = None;
    for entry in &manifest.entries {
        require_text(&entry.display_label, "accountability manifest display label")?;
        if entry.version == 0 || previous.is_some_and(|prior| prior >= &entry.handle) {
            return Err(manifest_fault(
                SharedAttentionFaultCode::InvalidLedger,
                "accountability manifest entries are invalid or not in strict handle order",
            ));
        }
        previous = Some(&entry.handle);
    }
    if manifest.manifest_digest != manifest_digest(manifest)? {
        return Err(manifest_fault(
            SharedAttentionFaultCode::InvalidDigest,
            "accountability manifest digest differs from canonical content",
        ));
    }
    Ok(())
}

pub fn validate_accountability_manifest_window(
    window: &AccountabilityManifestWindow,
) -> Result<(), SharedAttentionFault> {
    if window.profile != ACCOUNTABILITY_MANIFEST_WINDOW_PROFILE {
        return Err(manifest_fault(
            SharedAttentionFaultCode::InvalidFrame,
            "accountability manifest window profile is not supported",
        ));
    }
    require_text(&window.frame_purpose, "accountability manifest frame purpose")?;
    validate_accountability_manifest(&window.manifest)?;
    if window.ledger_digest != window.manifest.ledger_digest
        || window.rendered_manifest != render_manifest(&window.manifest)?
        || window.window_digest != manifest_window_digest(window)?
    {
        return Err(manifest_fault(
            SharedAttentionFaultCode::InvalidDigest,
            "accountability manifest window differs from its exact bindings or canonical digest",
        ));
    }
    Ok(())
}

pub fn materialize_accountable_objects(
    window: &AccountabilityManifestWindow,
    ledger: &IdentityLedger,
    requested_handles: Vec<SemanticId>,
) -> Result<AccountableMaterialization, SharedAttentionFault> {
    validate_accountability_manifest_window(window)?;
    validate_identity_ledger(ledger)?;
    if window.manifest != project_accountability_manifest(ledger)? {
        return Err(manifest_fault(
            SharedAttentionFaultCode::StaleLedger,
            "accountability materialization window is stale for the current ledger",
        ));
    }
    if requested_handles.is_empty() || requested_handles.len() > MAX_MATERIALIZED_HANDLES {
        return Err(manifest_fault(
            SharedAttentionFaultCode::CapacityOverflow,
            format!(
                "materialization requires one through {MAX_MATERIALIZED_HANDLES} exact handles"
            ),
        ));
    }
    let mut canonical = requested_handles;
    canonical.sort();
    if canonical.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(manifest_fault(
            SharedAttentionFaultCode::DuplicateIdentity,
            "materialization request contains a duplicate exact handle",
        ));
    }
    let objects = canonical
        .iter()
        .map(|handle| {
            ledger.objects.get(handle).cloned().ok_or_else(|| {
                manifest_fault(
                    SharedAttentionFaultCode::UnknownReference,
                    "materialization request names an unknown exact handle",
                )
                .with_subject(handle.clone())
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut materialization = AccountableMaterialization {
        profile: ACCOUNTABLE_MATERIALIZATION_PROFILE.to_owned(),
        window_digest: window.window_digest.clone(),
        ledger_digest: ledger.ledger_digest.clone(),
        requested_handles: canonical,
        objects,
        materialization_digest: empty_sha256(),
    };
    materialization.materialization_digest = materialization_digest(&materialization)?;
    validate_accountable_materialization(window, ledger, &materialization)?;
    Ok(materialization)
}

pub fn validate_accountable_materialization(
    window: &AccountabilityManifestWindow,
    ledger: &IdentityLedger,
    materialization: &AccountableMaterialization,
) -> Result<(), SharedAttentionFault> {
    if materialization.profile != ACCOUNTABLE_MATERIALIZATION_PROFILE
        || materialization.window_digest != window.window_digest
        || materialization.ledger_digest != ledger.ledger_digest
        || materialization.requested_handles.is_empty()
        || materialization.requested_handles.len() > MAX_MATERIALIZED_HANDLES
        || materialization.requested_handles.len() != materialization.objects.len()
    {
        return Err(manifest_fault(
            SharedAttentionFaultCode::InvalidFrame,
            "accountable materialization profile binding count or capacity is invalid",
        ));
    }
    validate_accountability_manifest_window(window)?;
    validate_identity_ledger(ledger)?;
    if window.manifest != project_accountability_manifest(ledger)? {
        return Err(manifest_fault(
            SharedAttentionFaultCode::StaleLedger,
            "accountable materialization is stale for the current ledger",
        ));
    }
    let mut previous: Option<&SemanticId> = None;
    for (handle, object) in materialization
        .requested_handles
        .iter()
        .zip(&materialization.objects)
    {
        if previous.is_some_and(|prior| prior >= handle) || &object.handle != handle {
            return Err(manifest_fault(
                SharedAttentionFaultCode::InvalidFrame,
                "materialized handles and objects are not one exact canonical accounting",
            ));
        }
        validate_accountable_object(object)?;
        if ledger.objects.get(handle) != Some(object) {
            return Err(manifest_fault(
                SharedAttentionFaultCode::ConflictingMutation,
                "materialized object differs from the current exact ledger record",
            ));
        }
        previous = Some(handle);
    }
    if materialization.materialization_digest != materialization_digest(materialization)? {
        return Err(manifest_fault(
            SharedAttentionFaultCode::InvalidDigest,
            "accountable materialization digest differs from canonical content",
        ));
    }
    Ok(())
}

pub fn finalize_manifest_attention_receipt(
    window: &AccountabilityManifestWindow,
    ledger: &IdentityLedger,
    materialization: &AccountableMaterialization,
    seed: ManifestAttentionReceiptSeed,
) -> Result<ManifestAttentionReceipt, SharedAttentionFault> {
    validate_accountable_materialization(window, ledger, materialization)?;
    if seed.window_digest != window.window_digest
        || seed.ledger_digest != ledger.ledger_digest
        || seed.manifest_digest != window.manifest.manifest_digest
        || seed.materialization_digest != materialization.materialization_digest
    {
        return Err(manifest_fault(
            SharedAttentionFaultCode::StaleBase,
            "manifest attention receipt seed differs from its exact window or materialization",
        ));
    }
    let expected = window
        .manifest
        .entries
        .iter()
        .map(|entry| entry.handle.clone())
        .collect::<BTreeSet<_>>();
    let supplied = seed.member_receipts.keys().cloned().collect::<BTreeSet<_>>();
    if supplied != expected {
        return Err(manifest_fault(
            SharedAttentionFaultCode::MissingAttestation,
            "manifest receipt must dispose every member exactly once and no foreign member",
        ));
    }
    let materialized = materialization
        .requested_handles
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    for (handle, member) in &seed.member_receipts {
        if handle != &member.handle {
            return Err(manifest_fault(
                SharedAttentionFaultCode::InvalidFrame,
                "manifest receipt map key differs from member handle",
            ));
        }
        require_text(&member.rationale, "manifest attention member rationale")?;
        if member.disposition == AttentionMemberDisposition::Relevant
            && !materialized.contains(handle)
        {
            return Err(manifest_fault(
                SharedAttentionFaultCode::MissingAttestation,
                "every Relevant manifest member must have an exact materialized record",
            )
            .with_subject(handle.clone()));
        }
    }
    let status = if seed
        .member_receipts
        .values()
        .any(|member| member.disposition == AttentionMemberDisposition::Unresolved)
    {
        AttentionReceiptStatus::Held
    } else {
        AttentionReceiptStatus::Complete
    };
    let mut receipt = ManifestAttentionReceipt {
        profile: MANIFEST_ATTENTION_RECEIPT_PROFILE.to_owned(),
        receipt_id: seed.receipt_id,
        window_digest: seed.window_digest,
        ledger_digest: seed.ledger_digest,
        manifest_digest: seed.manifest_digest,
        materialization_digest: seed.materialization_digest,
        member_receipts: seed.member_receipts,
        status,
        receipt_digest: empty_sha256(),
    };
    receipt.receipt_digest = manifest_receipt_digest(&receipt)?;
    validate_manifest_attention_receipt(window, ledger, materialization, &receipt)?;
    Ok(receipt)
}

pub fn validate_manifest_attention_receipt(
    window: &AccountabilityManifestWindow,
    ledger: &IdentityLedger,
    materialization: &AccountableMaterialization,
    receipt: &ManifestAttentionReceipt,
) -> Result<(), SharedAttentionFault> {
    if receipt.profile != MANIFEST_ATTENTION_RECEIPT_PROFILE {
        return Err(manifest_fault(
            SharedAttentionFaultCode::InvalidFrame,
            "manifest attention receipt profile is not supported",
        ));
    }
    let rebuilt = finalize_manifest_attention_receipt_body(window, ledger, materialization, receipt)?;
    if rebuilt.status != receipt.status || rebuilt.receipt_digest != receipt.receipt_digest {
        return Err(manifest_fault(
            SharedAttentionFaultCode::InvalidDigest,
            "manifest attention receipt differs from exact coverage or canonical digest",
        ));
    }
    Ok(())
}

fn finalize_manifest_attention_receipt_body(
    window: &AccountabilityManifestWindow,
    ledger: &IdentityLedger,
    materialization: &AccountableMaterialization,
    receipt: &ManifestAttentionReceipt,
) -> Result<ManifestAttentionReceipt, SharedAttentionFault> {
    let seed = ManifestAttentionReceiptSeed {
        receipt_id: receipt.receipt_id.clone(),
        window_digest: receipt.window_digest.clone(),
        ledger_digest: receipt.ledger_digest.clone(),
        manifest_digest: receipt.manifest_digest.clone(),
        materialization_digest: receipt.materialization_digest.clone(),
        member_receipts: receipt.member_receipts.clone(),
    };
    let mut rebuilt = finalize_manifest_attention_receipt_unchecked(
        window,
        ledger,
        materialization,
        seed,
    )?;
    rebuilt.receipt_digest = manifest_receipt_digest(&rebuilt)?;
    Ok(rebuilt)
}

fn finalize_manifest_attention_receipt_unchecked(
    window: &AccountabilityManifestWindow,
    ledger: &IdentityLedger,
    materialization: &AccountableMaterialization,
    seed: ManifestAttentionReceiptSeed,
) -> Result<ManifestAttentionReceipt, SharedAttentionFault> {
    validate_accountable_materialization(window, ledger, materialization)?;
    if seed.window_digest != window.window_digest
        || seed.ledger_digest != ledger.ledger_digest
        || seed.manifest_digest != window.manifest.manifest_digest
        || seed.materialization_digest != materialization.materialization_digest
    {
        return Err(manifest_fault(SharedAttentionFaultCode::StaleBase, "manifest receipt binding is stale"));
    }
    let expected = window.manifest.entries.iter().map(|entry| entry.handle.clone()).collect::<BTreeSet<_>>();
    if seed.member_receipts.keys().cloned().collect::<BTreeSet<_>>() != expected {
        return Err(manifest_fault(SharedAttentionFaultCode::MissingAttestation, "manifest receipt coverage is incomplete"));
    }
    let materialized = materialization.requested_handles.iter().cloned().collect::<BTreeSet<_>>();
    for (handle, member) in &seed.member_receipts {
        if handle != &member.handle {
            return Err(manifest_fault(SharedAttentionFaultCode::InvalidFrame, "manifest receipt handle accounting is invalid"));
        }
        require_text(&member.rationale, "manifest attention member rationale")?;
        if member.disposition == AttentionMemberDisposition::Relevant && !materialized.contains(handle) {
            return Err(manifest_fault(SharedAttentionFaultCode::MissingAttestation, "Relevant member lacks materialization"));
        }
    }
    let status = if seed.member_receipts.values().any(|member| member.disposition == AttentionMemberDisposition::Unresolved) {
        AttentionReceiptStatus::Held
    } else {
        AttentionReceiptStatus::Complete
    };
    Ok(ManifestAttentionReceipt {
        profile: MANIFEST_ATTENTION_RECEIPT_PROFILE.to_owned(),
        receipt_id: seed.receipt_id,
        window_digest: seed.window_digest,
        ledger_digest: seed.ledger_digest,
        manifest_digest: seed.manifest_digest,
        materialization_digest: seed.materialization_digest,
        member_receipts: seed.member_receipts,
        status,
        receipt_digest: empty_sha256(),
    })
}

fn render_manifest(manifest: &AccountabilityManifest) -> Result<String, SharedAttentionFault> {
    let mut rendered = format!(
        "[ACCOUNTABILITY_MANIFEST basket={} generation={} members={} ledger={} manifest={}]\n",
        manifest.basket_id,
        manifest.ledger_generation,
        manifest.member_count,
        manifest.ledger_digest.value,
        manifest.manifest_digest.value
    );
    for entry in &manifest.entries {
        let json = serde_json::to_string(entry).map_err(|error| {
            manifest_fault(
                SharedAttentionFaultCode::MachineForm,
                format!("accountability manifest entry serialization failed: {error}"),
            )
        })?;
        rendered.push_str(&json);
        rendered.push('\n');
    }
    rendered.push_str("[/ACCOUNTABILITY_MANIFEST]");
    Ok(rendered)
}

fn manifest_digest(manifest: &AccountabilityManifest) -> Result<ContentDigest, SharedAttentionFault> {
    let mut canonical = manifest.clone();
    canonical.manifest_digest = empty_sha256();
    digest(&canonical, "accountability manifest")
}

fn manifest_window_digest(window: &AccountabilityManifestWindow) -> Result<ContentDigest, SharedAttentionFault> {
    let mut canonical = window.clone();
    canonical.window_digest = empty_sha256();
    digest(&canonical, "accountability manifest window")
}

fn materialization_digest(materialization: &AccountableMaterialization) -> Result<ContentDigest, SharedAttentionFault> {
    let mut canonical = materialization.clone();
    canonical.materialization_digest = empty_sha256();
    digest(&canonical, "accountable materialization")
}

fn manifest_receipt_digest(receipt: &ManifestAttentionReceipt) -> Result<ContentDigest, SharedAttentionFault> {
    let mut canonical = receipt.clone();
    canonical.receipt_digest = empty_sha256();
    digest(&canonical, "manifest attention receipt")
}

fn manifest_fault(code: SharedAttentionFaultCode, message: impl Into<String>) -> SharedAttentionFault {
    fault(code, message)
}
