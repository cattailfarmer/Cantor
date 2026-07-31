//! Pure stability reconciliation for two caller-supplied Windows entry reads.
//!
//! The labels `pre_read` and `post_read` designate comparison roles only. A
//! successful result does not prove physical time, ordering, handle continuity,
//! object identity, path identity, freshness, or Windows provenance.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::windows_supplied_entry_observation::{
    WindowsSuppliedEntryAssemblyFault, WindowsSuppliedEntryAssemblyInput,
    WindowsSuppliedEntryObservation, assemble_windows_supplied_entry_observation,
};

/// Closed profile implemented by this pure reconciler.
pub const WINDOWS_SUPPLIED_ENTRY_STABILITY_PROFILE: &str =
    "cantor-windows-supplied-entry-stability/0.1";

/// Strict input retaining two independently assembled supplied-record bundles.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsSuppliedEntryStabilityInput {
    pub profile: String,
    pub reconciliation_identity: u64,
    pub pre_read: WindowsSuppliedEntryAssemblyInput,
    pub post_read: WindowsSuppliedEntryAssemblyInput,
}

/// Canonical comparison order. The first differing field terminates admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsSuppliedEntryStabilityComparedField {
    Kind,
    PolicyDecision,
    ReparseTag,
    StrongIdentity,
    AllocationSize,
    EndOfFile,
    NumberOfLinks,
    SuppliedStreamRecords,
}

/// Exact closed comparison vocabulary in evaluation order.
pub const WINDOWS_SUPPLIED_ENTRY_STABILITY_COMPARED_FIELDS:
    [WindowsSuppliedEntryStabilityComparedField; 8] = [
    WindowsSuppliedEntryStabilityComparedField::Kind,
    WindowsSuppliedEntryStabilityComparedField::PolicyDecision,
    WindowsSuppliedEntryStabilityComparedField::ReparseTag,
    WindowsSuppliedEntryStabilityComparedField::StrongIdentity,
    WindowsSuppliedEntryStabilityComparedField::AllocationSize,
    WindowsSuppliedEntryStabilityComparedField::EndOfFile,
    WindowsSuppliedEntryStabilityComparedField::NumberOfLinks,
    WindowsSuppliedEntryStabilityComparedField::SuppliedStreamRecords,
];

/// Successfully reconciled pair. Both assembled reads remain inspectable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsSuppliedEntryStablePair {
    pub profile: String,
    pub reconciliation_identity: u64,
    pub entry_reference_identity: u64,
    pub pre_batch_identity: u64,
    pub post_batch_identity: u64,
    pub compared_fields: [WindowsSuppliedEntryStabilityComparedField; 8],
    pub pre_read: WindowsSuppliedEntryObservation,
    pub post_read: WindowsSuppliedEntryObservation,
}

/// Identifies which independent assembly rejected its supplied records.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsSuppliedEntryStabilitySide {
    PreRead,
    PostRead,
}

/// Closed stability-reconciliation failure vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsSuppliedEntryStabilityFaultCode {
    Profile,
    ReconciliationIdentity,
    PreRead,
    PostRead,
    EntryReference,
    BatchIdentity,
    Difference,
    Resource,
    Json,
}

/// Deterministic failure released without a partially admitted stable pair.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsSuppliedEntryStabilityFault {
    pub code: WindowsSuppliedEntryStabilityFaultCode,
    pub nested_side: Option<WindowsSuppliedEntryStabilitySide>,
    pub nested_fault: Option<WindowsSuppliedEntryAssemblyFault>,
    pub difference_field: Option<WindowsSuppliedEntryStabilityComparedField>,
    pub field: String,
    pub message: String,
}

impl WindowsSuppliedEntryStabilityFault {
    fn simple(code: WindowsSuppliedEntryStabilityFaultCode, field: &str, message: &str) -> Self {
        Self {
            code,
            nested_side: None,
            nested_fault: None,
            difference_field: None,
            field: field.to_owned(),
            message: message.chars().take(256).collect(),
        }
    }

    fn nested(
        side: WindowsSuppliedEntryStabilitySide,
        fault: WindowsSuppliedEntryAssemblyFault,
    ) -> Self {
        let (code, field) = match side {
            WindowsSuppliedEntryStabilitySide::PreRead => (
                WindowsSuppliedEntryStabilityFaultCode::PreRead,
                format!("pre_read.{}", fault.field),
            ),
            WindowsSuppliedEntryStabilitySide::PostRead => (
                WindowsSuppliedEntryStabilityFaultCode::PostRead,
                format!("post_read.{}", fault.field),
            ),
        };
        let message = format!("supplied-entry assembly rejected: {}", fault.message);
        Self {
            code,
            nested_side: Some(side),
            nested_fault: Some(fault),
            difference_field: None,
            field,
            message: message.chars().take(256).collect(),
        }
    }

    fn difference(field: WindowsSuppliedEntryStabilityComparedField, field_name: &str) -> Self {
        Self {
            code: WindowsSuppliedEntryStabilityFaultCode::Difference,
            nested_side: None,
            nested_fault: None,
            difference_field: Some(field),
            field: field_name.to_owned(),
            message: "independently assembled supplied reads differ at the first canonical field"
                .to_owned(),
        }
    }
}

impl fmt::Display for WindowsSuppliedEntryStabilityFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl std::error::Error for WindowsSuppliedEntryStabilityFault {}

/// Strictly decodes one stability input and applies the pure profile.
pub fn decode_and_reconcile_windows_supplied_entry_stability(
    bytes: &[u8],
) -> Result<WindowsSuppliedEntryStablePair, WindowsSuppliedEntryStabilityFault> {
    let input = serde_json::from_slice(bytes).map_err(|error| {
        WindowsSuppliedEntryStabilityFault::simple(
            WindowsSuppliedEntryStabilityFaultCode::Json,
            "json",
            &error.to_string(),
        )
    })?;
    reconcile_windows_supplied_entry_stability(input)
}

/// Independently assembles two supplied reads and reconciles their exact facts.
pub fn reconcile_windows_supplied_entry_stability(
    input: WindowsSuppliedEntryStabilityInput,
) -> Result<WindowsSuppliedEntryStablePair, WindowsSuppliedEntryStabilityFault> {
    if input.profile != WINDOWS_SUPPLIED_ENTRY_STABILITY_PROFILE {
        return Err(WindowsSuppliedEntryStabilityFault::simple(
            WindowsSuppliedEntryStabilityFaultCode::Profile,
            "profile",
            "profile is not the exact supported supplied-entry stability profile",
        ));
    }
    if input.reconciliation_identity == 0 {
        return Err(WindowsSuppliedEntryStabilityFault::simple(
            WindowsSuppliedEntryStabilityFaultCode::ReconciliationIdentity,
            "reconciliation_identity",
            "reconciliation identity must be nonzero",
        ));
    }

    let pre_read =
        assemble_windows_supplied_entry_observation(input.pre_read).map_err(|fault| {
            WindowsSuppliedEntryStabilityFault::nested(
                WindowsSuppliedEntryStabilitySide::PreRead,
                fault,
            )
        })?;
    let post_read =
        assemble_windows_supplied_entry_observation(input.post_read).map_err(|fault| {
            WindowsSuppliedEntryStabilityFault::nested(
                WindowsSuppliedEntryStabilitySide::PostRead,
                fault,
            )
        })?;

    if pre_read.entry_reference_identity == 0
        || pre_read.entry_reference_identity != post_read.entry_reference_identity
    {
        return Err(WindowsSuppliedEntryStabilityFault::simple(
            WindowsSuppliedEntryStabilityFaultCode::EntryReference,
            "entry_reference_identity",
            "assembled entry-reference identities must be equal and nonzero",
        ));
    }
    if pre_read.batch_identity == 0
        || post_read.batch_identity == 0
        || pre_read.batch_identity == post_read.batch_identity
    {
        return Err(WindowsSuppliedEntryStabilityFault::simple(
            WindowsSuppliedEntryStabilityFaultCode::BatchIdentity,
            "batch_identity",
            "assembled batch identities must be nonzero and distinct",
        ));
    }

    compare(
        pre_read.policy_decision.kind == post_read.policy_decision.kind,
        WindowsSuppliedEntryStabilityComparedField::Kind,
        "policy_decision.kind",
    )?;
    compare(
        pre_read.policy_decision == post_read.policy_decision,
        WindowsSuppliedEntryStabilityComparedField::PolicyDecision,
        "policy_decision",
    )?;
    compare(
        pre_read.reparse_tag == post_read.reparse_tag,
        WindowsSuppliedEntryStabilityComparedField::ReparseTag,
        "reparse_tag",
    )?;
    compare(
        pre_read.identity == post_read.identity,
        WindowsSuppliedEntryStabilityComparedField::StrongIdentity,
        "identity",
    )?;
    compare(
        pre_read.allocation_size == post_read.allocation_size,
        WindowsSuppliedEntryStabilityComparedField::AllocationSize,
        "allocation_size",
    )?;
    compare(
        pre_read.end_of_file == post_read.end_of_file,
        WindowsSuppliedEntryStabilityComparedField::EndOfFile,
        "end_of_file",
    )?;
    compare(
        pre_read.number_of_links == post_read.number_of_links,
        WindowsSuppliedEntryStabilityComparedField::NumberOfLinks,
        "number_of_links",
    )?;
    compare(
        pre_read.supplied_stream_records == post_read.supplied_stream_records,
        WindowsSuppliedEntryStabilityComparedField::SuppliedStreamRecords,
        "supplied_stream_records",
    )?;

    Ok(WindowsSuppliedEntryStablePair {
        profile: input.profile,
        reconciliation_identity: input.reconciliation_identity,
        entry_reference_identity: pre_read.entry_reference_identity,
        pre_batch_identity: pre_read.batch_identity,
        post_batch_identity: post_read.batch_identity,
        compared_fields: WINDOWS_SUPPLIED_ENTRY_STABILITY_COMPARED_FIELDS,
        pre_read,
        post_read,
    })
}

fn compare(
    equal: bool,
    field: WindowsSuppliedEntryStabilityComparedField,
    field_name: &str,
) -> Result<(), WindowsSuppliedEntryStabilityFault> {
    if equal {
        Ok(())
    } else {
        Err(WindowsSuppliedEntryStabilityFault::difference(
            field, field_name,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::windows_supplied_entry_observation::{
        WINDOWS_SUPPLIED_ENTRY_OBSERVATION_PROFILE, WindowsSuppliedAttributeTagRecord,
        WindowsSuppliedCaseSensitivityRecord, WindowsSuppliedFileIdentityRecord,
        WindowsSuppliedOrderedStreamRecords, WindowsSuppliedRecordCorrelation,
        WindowsSuppliedStandardInformationRecord, WindowsSuppliedStreamSet,
    };
    use crate::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, WindowsEntryPolicyKind,
        WindowsRawStreamRecord,
    };

    fn correlation(
        batch_identity: u64,
        entry_reference_identity: u64,
    ) -> WindowsSuppliedRecordCorrelation {
        WindowsSuppliedRecordCorrelation {
            batch_identity,
            entry_reference_identity,
        }
    }

    fn assembly_input(batch_identity: u64) -> WindowsSuppliedEntryAssemblyInput {
        let correlation = correlation(batch_identity, 11);
        WindowsSuppliedEntryAssemblyInput {
            profile: WINDOWS_SUPPLIED_ENTRY_OBSERVATION_PROFILE.to_owned(),
            kind: WindowsEntryPolicyKind::RegularFile,
            component: "entry.txt".to_owned(),
            maximum_component_utf16_units: 255,
            attribute_tag: WindowsSuppliedAttributeTagRecord {
                correlation,
                attributes: FILE_ATTRIBUTE_NORMAL,
                reparse_tag: 0x1234,
            },
            file_identity: WindowsSuppliedFileIdentityRecord {
                correlation,
                volume_serial: 19,
                file_id_bytes: (0_u8..16).collect(),
            },
            standard: WindowsSuppliedStandardInformationRecord {
                correlation,
                allocation_size: 16,
                end_of_file: 9,
                number_of_links: 1,
                delete_pending: false,
                directory: false,
            },
            case_sensitivity: WindowsSuppliedCaseSensitivityRecord::NotApplicable(correlation),
            streams: WindowsSuppliedStreamSet::ExplicitEmpty(correlation),
        }
    }

    fn input() -> WindowsSuppliedEntryStabilityInput {
        WindowsSuppliedEntryStabilityInput {
            profile: WINDOWS_SUPPLIED_ENTRY_STABILITY_PROFILE.to_owned(),
            reconciliation_identity: 31,
            pre_read: assembly_input(7),
            post_read: assembly_input(8),
        }
    }

    fn replace_correlation(
        input: &mut WindowsSuppliedEntryAssemblyInput,
        correlation: WindowsSuppliedRecordCorrelation,
    ) {
        input.attribute_tag.correlation = correlation;
        input.file_identity.correlation = correlation;
        input.standard.correlation = correlation;
        input.case_sensitivity = WindowsSuppliedCaseSensitivityRecord::NotApplicable(correlation);
        input.streams = WindowsSuppliedStreamSet::ExplicitEmpty(correlation);
    }

    fn assert_difference(
        input: WindowsSuppliedEntryStabilityInput,
        expected: WindowsSuppliedEntryStabilityComparedField,
    ) {
        let fault = reconcile_windows_supplied_entry_stability(input).expect_err("difference");
        assert_eq!(
            fault.code,
            WindowsSuppliedEntryStabilityFaultCode::Difference
        );
        assert_eq!(fault.difference_field, Some(expected));
        assert_eq!(fault.nested_side, None);
        assert_eq!(fault.nested_fault, None);
    }

    #[test]
    fn stable_pair_preserves_both_assemblies_and_fixed_comparison_order() {
        let expected_pre = assemble_windows_supplied_entry_observation(assembly_input(7)).unwrap();
        let expected_post = assemble_windows_supplied_entry_observation(assembly_input(8)).unwrap();
        let stable = reconcile_windows_supplied_entry_stability(input()).expect("stable");
        assert_eq!(stable.profile, WINDOWS_SUPPLIED_ENTRY_STABILITY_PROFILE);
        assert_eq!(stable.reconciliation_identity, 31);
        assert_eq!(stable.entry_reference_identity, 11);
        assert_eq!(
            (stable.pre_batch_identity, stable.post_batch_identity),
            (7, 8)
        );
        assert_eq!(
            stable.compared_fields,
            WINDOWS_SUPPLIED_ENTRY_STABILITY_COMPARED_FIELDS
        );
        assert_eq!(stable.pre_read, expected_pre);
        assert_eq!(stable.post_read, expected_post);
    }

    #[test]
    fn outer_profile_and_reconciliation_identity_reject_before_nested_assembly() {
        let mut profile = input();
        profile.profile = "cantor-windows-supplied-entry-stability/0.0".to_owned();
        profile.pre_read.profile = "invalid".to_owned();
        assert_eq!(
            reconcile_windows_supplied_entry_stability(profile)
                .unwrap_err()
                .code,
            WindowsSuppliedEntryStabilityFaultCode::Profile
        );

        let mut identity = input();
        identity.reconciliation_identity = 0;
        identity.pre_read.profile = "invalid".to_owned();
        assert_eq!(
            reconcile_windows_supplied_entry_stability(identity)
                .unwrap_err()
                .code,
            WindowsSuppliedEntryStabilityFaultCode::ReconciliationIdentity
        );
    }

    #[test]
    fn pre_read_rejects_first_and_preserves_nested_fault() {
        let mut value = input();
        value.pre_read.profile = "invalid-pre".to_owned();
        value.post_read.profile = "invalid-post".to_owned();
        let fault = reconcile_windows_supplied_entry_stability(value).unwrap_err();
        assert_eq!(fault.code, WindowsSuppliedEntryStabilityFaultCode::PreRead);
        assert_eq!(
            fault.nested_side,
            Some(WindowsSuppliedEntryStabilitySide::PreRead)
        );
        assert_eq!(fault.nested_fault.unwrap().field, "profile");
    }

    #[test]
    fn post_read_rejection_is_side_qualified() {
        let mut value = input();
        value.post_read.standard.number_of_links = 0;
        let fault = reconcile_windows_supplied_entry_stability(value).unwrap_err();
        assert_eq!(fault.code, WindowsSuppliedEntryStabilityFaultCode::PostRead);
        assert_eq!(
            fault.nested_side,
            Some(WindowsSuppliedEntryStabilitySide::PostRead)
        );
        assert_eq!(
            fault.nested_fault.unwrap().field,
            "standard.number_of_links"
        );
    }

    #[test]
    fn entry_reference_must_match_and_batches_must_be_distinct() {
        let mut reference = input();
        replace_correlation(&mut reference.post_read, correlation(8, 12));
        assert_eq!(
            reconcile_windows_supplied_entry_stability(reference)
                .unwrap_err()
                .code,
            WindowsSuppliedEntryStabilityFaultCode::EntryReference
        );

        let mut batch = input();
        replace_correlation(&mut batch.post_read, correlation(7, 11));
        assert_eq!(
            reconcile_windows_supplied_entry_stability(batch)
                .unwrap_err()
                .code,
            WindowsSuppliedEntryStabilityFaultCode::BatchIdentity
        );
    }

    #[test]
    fn kind_is_the_first_canonical_difference() {
        let mut value = input();
        value.post_read.kind = WindowsEntryPolicyKind::Directory;
        value.post_read.attribute_tag.attributes = FILE_ATTRIBUTE_DIRECTORY;
        value.post_read.standard.directory = true;
        value.post_read.case_sensitivity = WindowsSuppliedCaseSensitivityRecord::DirectoryFlags(
            crate::windows_supplied_entry_observation::WindowsSuppliedDirectoryCaseFlags {
                correlation: correlation(8, 11),
                flags: 0,
            },
        );
        assert_difference(value, WindowsSuppliedEntryStabilityComparedField::Kind);
    }

    #[test]
    fn policy_decision_is_compared_before_later_differences() {
        let mut value = input();
        value.post_read.component = "different.txt".to_owned();
        value.post_read.attribute_tag.reparse_tag = 0x9999;
        assert_difference(
            value,
            WindowsSuppliedEntryStabilityComparedField::PolicyDecision,
        );
    }

    #[test]
    fn reparse_identity_and_sizes_report_their_exact_first_difference() {
        let mut reparse = input();
        reparse.post_read.attribute_tag.reparse_tag = 0x9999;
        assert_difference(
            reparse,
            WindowsSuppliedEntryStabilityComparedField::ReparseTag,
        );

        let mut identity = input();
        identity.post_read.file_identity.volume_serial = 20;
        identity.post_read.standard.allocation_size = 17;
        assert_difference(
            identity,
            WindowsSuppliedEntryStabilityComparedField::StrongIdentity,
        );

        let mut allocation = input();
        allocation.post_read.standard.allocation_size = 17;
        allocation.post_read.standard.end_of_file = 10;
        assert_difference(
            allocation,
            WindowsSuppliedEntryStabilityComparedField::AllocationSize,
        );

        let mut end = input();
        end.post_read.standard.end_of_file = 10;
        assert_difference(end, WindowsSuppliedEntryStabilityComparedField::EndOfFile);
    }

    #[test]
    fn link_and_stream_differences_complete_the_canonical_order() {
        let mut links = input();
        links.post_read.standard.number_of_links = 2;
        assert_difference(
            links,
            WindowsSuppliedEntryStabilityComparedField::NumberOfLinks,
        );

        let mut streams = input();
        streams.post_read.streams =
            WindowsSuppliedStreamSet::OrderedRecords(WindowsSuppliedOrderedStreamRecords {
                correlation: correlation(8, 11),
                records: vec![WindowsRawStreamRecord {
                    name: "::$DATA".to_owned(),
                    stream_size: 9,
                    allocation_size: 16,
                    source_offset: 0,
                }],
            });
        assert_difference(
            streams,
            WindowsSuppliedEntryStabilityComparedField::SuppliedStreamRecords,
        );
    }

    #[test]
    fn strict_json_rejects_outer_and_nested_shape_drift() {
        let bytes = serde_json::to_vec(&input()).unwrap();
        assert!(decode_and_reconcile_windows_supplied_entry_stability(&bytes).is_ok());

        let text = String::from_utf8(bytes.clone()).unwrap();
        let outer_unknown = text.replacen('{', "{\"trusted\":true,", 1);
        assert_eq!(
            decode_and_reconcile_windows_supplied_entry_stability(outer_unknown.as_bytes())
                .unwrap_err()
                .code,
            WindowsSuppliedEntryStabilityFaultCode::Json
        );
        let nested_unknown = text.replacen(
            "\"pre_read\":{",
            "\"pre_read\":{\"physically_observed\":true,",
            1,
        );
        assert_eq!(
            decode_and_reconcile_windows_supplied_entry_stability(nested_unknown.as_bytes())
                .unwrap_err()
                .code,
            WindowsSuppliedEntryStabilityFaultCode::Json
        );
        let missing = serde_json::json!({
            "profile": WINDOWS_SUPPLIED_ENTRY_STABILITY_PROFILE,
            "reconciliation_identity": 31,
            "pre_read": assembly_input(7)
        });
        assert_eq!(
            decode_and_reconcile_windows_supplied_entry_stability(
                &serde_json::to_vec(&missing).unwrap()
            )
            .unwrap_err()
            .code,
            WindowsSuppliedEntryStabilityFaultCode::Json
        );
    }

    #[test]
    fn repeated_input_has_identical_result_and_bounded_fault_messages() {
        let value = input();
        let first = reconcile_windows_supplied_entry_stability(value.clone()).unwrap();
        let second = reconcile_windows_supplied_entry_stability(value).unwrap();
        assert_eq!(first, second);

        let mut invalid = input();
        invalid.pre_read.component = "x".repeat(300);
        invalid.pre_read.maximum_component_utf16_units = 1;
        let fault = reconcile_windows_supplied_entry_stability(invalid).unwrap_err();
        assert!(fault.message.chars().count() <= 256);
    }
}
