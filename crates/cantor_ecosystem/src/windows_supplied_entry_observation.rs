//! Pure assembly of caller-supplied Windows entry metadata.
//!
//! A successful value proves only structural coherence under this profile.
//! Correlation identifiers are equality syntax, not evidence of a shared
//! handle, object, query, epoch, path, or physical observation.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};

use crate::{
    StrongFileIdentity, TopologyEntryKind, TopologyStreamFact, TopologyStreamKind,
    WINDOWS_ENTRY_POLICY_PROFILE, WindowsEntryPolicyDecision, WindowsEntryPolicyInput,
    WindowsEntryPolicyKind, WindowsRawStreamRecord, evaluate_windows_entry_policy,
};

/// Closed profile implemented by this pure assembler.
pub const WINDOWS_SUPPLIED_ENTRY_OBSERVATION_PROFILE: &str =
    "cantor-windows-supplied-entry-observation/0.1";

const MAXIMUM_STREAMS: usize = 1_024;
const MAXIMUM_STREAM_NAME_UTF16_UNITS: usize = 32_767;

/// Caller-owned equality syntax repeated by every supplied record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsSuppliedRecordCorrelation {
    pub batch_identity: u64,
    pub entry_reference_identity: u64,
}

/// Exact caller-supplied attribute and diagnostic-tag values.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsSuppliedAttributeTagRecord {
    pub correlation: WindowsSuppliedRecordCorrelation,
    pub attributes: u32,
    pub reparse_tag: u32,
}

/// Exact caller-supplied volume serial and sixteen-byte file identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsSuppliedFileIdentityRecord {
    pub correlation: WindowsSuppliedRecordCorrelation,
    pub volume_serial: u64,
    pub file_id_bytes: Vec<u8>,
}

/// Caller-supplied fixed standard-information values before checked conversion.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsSuppliedStandardInformationRecord {
    pub correlation: WindowsSuppliedRecordCorrelation,
    pub allocation_size: i64,
    pub end_of_file: i64,
    pub number_of_links: u32,
    pub delete_pending: bool,
    pub directory: bool,
}

/// Explicit directory case-flags record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsSuppliedDirectoryCaseFlags {
    pub correlation: WindowsSuppliedRecordCorrelation,
    pub flags: u32,
}

/// Conditional case information without an optional or defaulted record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsSuppliedCaseSensitivityRecord {
    DirectoryFlags(WindowsSuppliedDirectoryCaseFlags),
    NotApplicable(WindowsSuppliedRecordCorrelation),
}

impl WindowsSuppliedCaseSensitivityRecord {
    fn correlation(&self) -> WindowsSuppliedRecordCorrelation {
        match self {
            Self::DirectoryFlags(record) => record.correlation,
            Self::NotApplicable(correlation) => *correlation,
        }
    }
}

/// Explicit nonempty ordered stream-record collection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsSuppliedOrderedStreamRecords {
    pub correlation: WindowsSuppliedRecordCorrelation,
    pub records: Vec<WindowsRawStreamRecord>,
}

/// Supplied stream syntax. Neither variant proves physical enumeration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsSuppliedStreamSet {
    ExplicitEmpty(WindowsSuppliedRecordCorrelation),
    OrderedRecords(WindowsSuppliedOrderedStreamRecords),
}

impl WindowsSuppliedStreamSet {
    fn correlation(&self) -> WindowsSuppliedRecordCorrelation {
        match self {
            Self::ExplicitEmpty(correlation) => *correlation,
            Self::OrderedRecords(record) => record.correlation,
        }
    }
}

/// Strict input containing every required caller-supplied record class.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsSuppliedEntryAssemblyInput {
    pub profile: String,
    pub kind: WindowsEntryPolicyKind,
    pub component: String,
    pub maximum_component_utf16_units: u32,
    pub attribute_tag: WindowsSuppliedAttributeTagRecord,
    pub file_identity: WindowsSuppliedFileIdentityRecord,
    pub standard: WindowsSuppliedStandardInformationRecord,
    pub case_sensitivity: WindowsSuppliedCaseSensitivityRecord,
    pub streams: WindowsSuppliedStreamSet,
}

/// Structurally coherent supplied values with no physical-provenance claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsSuppliedEntryObservation {
    pub profile: String,
    pub batch_identity: u64,
    pub entry_reference_identity: u64,
    pub policy_decision: WindowsEntryPolicyDecision,
    pub reparse_tag: u32,
    pub identity: StrongFileIdentity,
    pub allocation_size: u64,
    pub end_of_file: u64,
    pub number_of_links: u32,
    pub supplied_stream_records: Vec<WindowsRawStreamRecord>,
}

/// Deliberately incomplete projection toward the M2A topology vocabulary.
///
/// The type cannot hold a relative path, mode class, content digest, or
/// observation ordinal, so callers must separately supply and validate those
/// facts before constructing a `TopologyEntryObservation`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsTopologyEntryProjectionSeed {
    pub kind: TopologyEntryKind,
    pub attributes: u32,
    pub identity: StrongFileIdentity,
    pub number_of_links: u32,
    pub streams: Vec<TopologyStreamFact>,
    pub length: Option<u64>,
}

impl WindowsSuppliedEntryObservation {
    /// Derives only the subset of M2A fields justified by this supplied value.
    pub fn topology_projection_seed(&self) -> WindowsTopologyEntryProjectionSeed {
        let mut streams = self
            .supplied_stream_records
            .iter()
            .map(|record| TopologyStreamFact {
                name: record.name.clone(),
                size: record.stream_size,
                kind: if record.name == "::$DATA" {
                    TopologyStreamKind::UnnamedDefault
                } else {
                    TopologyStreamKind::NamedData
                },
            })
            .collect::<Vec<_>>();
        streams.sort_by(|left, right| left.name.cmp(&right.name));

        let (kind, length) = match self.policy_decision.kind {
            WindowsEntryPolicyKind::Directory => (TopologyEntryKind::Directory, None),
            WindowsEntryPolicyKind::RegularFile => {
                (TopologyEntryKind::RegularFile, Some(self.end_of_file))
            }
        };
        WindowsTopologyEntryProjectionSeed {
            kind,
            attributes: self.policy_decision.attributes,
            identity: self.identity.clone(),
            number_of_links: self.number_of_links,
            streams,
            length,
        }
    }
}

/// Closed assembly failure vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsSuppliedEntryAssemblyFaultCode {
    Profile,
    Correlation,
    Identity,
    Size,
    Link,
    DeletePending,
    Kind,
    CaseSensitivity,
    Stream,
    Policy,
    Resource,
    Json,
}

/// Deterministic failure released without a partial accepted observation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsSuppliedEntryAssemblyFault {
    pub code: WindowsSuppliedEntryAssemblyFaultCode,
    pub field: String,
    pub message: String,
}

impl WindowsSuppliedEntryAssemblyFault {
    fn new(code: WindowsSuppliedEntryAssemblyFaultCode, field: &str, message: &str) -> Self {
        Self {
            code,
            field: field.to_owned(),
            message: message.chars().take(256).collect(),
        }
    }
}

impl fmt::Display for WindowsSuppliedEntryAssemblyFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl std::error::Error for WindowsSuppliedEntryAssemblyFault {}

/// Strictly decodes one supplied input and applies the pure assembly profile.
pub fn decode_and_assemble_windows_supplied_entry_observation(
    bytes: &[u8],
) -> Result<WindowsSuppliedEntryObservation, WindowsSuppliedEntryAssemblyFault> {
    let input = serde_json::from_slice(bytes).map_err(|error| {
        WindowsSuppliedEntryAssemblyFault::new(
            WindowsSuppliedEntryAssemblyFaultCode::Json,
            "json",
            &error.to_string(),
        )
    })?;
    assemble_windows_supplied_entry_observation(input)
}

/// Correlates and validates already supplied values without observing anything.
pub fn assemble_windows_supplied_entry_observation(
    input: WindowsSuppliedEntryAssemblyInput,
) -> Result<WindowsSuppliedEntryObservation, WindowsSuppliedEntryAssemblyFault> {
    if input.profile != WINDOWS_SUPPLIED_ENTRY_OBSERVATION_PROFILE {
        return Err(WindowsSuppliedEntryAssemblyFault::new(
            WindowsSuppliedEntryAssemblyFaultCode::Profile,
            "profile",
            "profile is not the exact supported supplied-entry observation profile",
        ));
    }

    let expected = input.attribute_tag.correlation;
    validate_correlations(
        expected,
        [
            input.file_identity.correlation,
            input.standard.correlation,
            input.case_sensitivity.correlation(),
            input.streams.correlation(),
        ],
    )?;

    let file_id_bytes: [u8; 16] = input
        .file_identity
        .file_id_bytes
        .as_slice()
        .try_into()
        .map_err(|_| {
            WindowsSuppliedEntryAssemblyFault::new(
                WindowsSuppliedEntryAssemblyFaultCode::Identity,
                "file_identity.file_id_bytes",
                "file identity must contain exactly sixteen bytes",
            )
        })?;
    let identity = StrongFileIdentity {
        volume_serial: input.file_identity.volume_serial,
        file_id_hex: file_id_bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    };

    if input.standard.allocation_size < 0 || input.standard.end_of_file < 0 {
        return Err(WindowsSuppliedEntryAssemblyFault::new(
            WindowsSuppliedEntryAssemblyFaultCode::Size,
            "standard",
            "allocation size and end-of-file must both be nonnegative",
        ));
    }
    if input.standard.number_of_links == 0 {
        return Err(WindowsSuppliedEntryAssemblyFault::new(
            WindowsSuppliedEntryAssemblyFaultCode::Link,
            "standard.number_of_links",
            "link count must be nonzero",
        ));
    }
    if input.standard.delete_pending {
        return Err(WindowsSuppliedEntryAssemblyFault::new(
            WindowsSuppliedEntryAssemblyFaultCode::DeletePending,
            "standard.delete_pending",
            "delete-pending entries are never structurally admitted",
        ));
    }
    let requested_directory = input.kind == WindowsEntryPolicyKind::Directory;
    if input.standard.directory != requested_directory {
        return Err(WindowsSuppliedEntryAssemblyFault::new(
            WindowsSuppliedEntryAssemblyFaultCode::Kind,
            "standard.directory",
            "standard-information directory flag disagrees with requested kind",
        ));
    }

    let directory_case_sensitive_flags = match (&input.kind, &input.case_sensitivity) {
        (
            WindowsEntryPolicyKind::Directory,
            WindowsSuppliedCaseSensitivityRecord::DirectoryFlags(record),
        ) if record.flags == 0 => Some(0),
        (
            WindowsEntryPolicyKind::RegularFile,
            WindowsSuppliedCaseSensitivityRecord::NotApplicable(_),
        ) => None,
        _ => {
            return Err(WindowsSuppliedEntryAssemblyFault::new(
                WindowsSuppliedEntryAssemblyFaultCode::CaseSensitivity,
                "case_sensitivity",
                "directory requires exact zero flags and regular file requires not_applicable",
            ));
        }
    };

    let supplied_stream_records = validate_and_copy_streams(&input.streams)?;
    let policy_decision = evaluate_windows_entry_policy(WindowsEntryPolicyInput {
        profile: WINDOWS_ENTRY_POLICY_PROFILE.to_owned(),
        kind: input.kind,
        attributes: input.attribute_tag.attributes,
        directory_case_sensitive_flags,
        component: input.component,
        maximum_component_utf16_units: input.maximum_component_utf16_units,
    })
    .map_err(|fault| {
        WindowsSuppliedEntryAssemblyFault::new(
            WindowsSuppliedEntryAssemblyFaultCode::Policy,
            &format!("policy.{}", fault.field),
            &fault.message,
        )
    })?;

    Ok(WindowsSuppliedEntryObservation {
        profile: input.profile,
        batch_identity: expected.batch_identity,
        entry_reference_identity: expected.entry_reference_identity,
        policy_decision,
        reparse_tag: input.attribute_tag.reparse_tag,
        identity,
        allocation_size: input.standard.allocation_size as u64,
        end_of_file: input.standard.end_of_file as u64,
        number_of_links: input.standard.number_of_links,
        supplied_stream_records,
    })
}

fn validate_correlations(
    expected: WindowsSuppliedRecordCorrelation,
    remaining: [WindowsSuppliedRecordCorrelation; 4],
) -> Result<(), WindowsSuppliedEntryAssemblyFault> {
    if expected.batch_identity == 0 || expected.entry_reference_identity == 0 {
        return Err(WindowsSuppliedEntryAssemblyFault::new(
            WindowsSuppliedEntryAssemblyFaultCode::Correlation,
            "attribute_tag.correlation",
            "both correlation identities must be nonzero",
        ));
    }
    for (index, value) in remaining.into_iter().enumerate() {
        if value.batch_identity == 0 || value.entry_reference_identity == 0 {
            return Err(WindowsSuppliedEntryAssemblyFault::new(
                WindowsSuppliedEntryAssemblyFaultCode::Correlation,
                "correlation",
                &format!("record correlation at index {index} contains a zero identity"),
            ));
        }
        if value != expected {
            return Err(WindowsSuppliedEntryAssemblyFault::new(
                WindowsSuppliedEntryAssemblyFaultCode::Correlation,
                "correlation",
                &format!("record correlation at index {index} does not match"),
            ));
        }
    }
    Ok(())
}

fn validate_and_copy_streams(
    streams: &WindowsSuppliedStreamSet,
) -> Result<Vec<WindowsRawStreamRecord>, WindowsSuppliedEntryAssemblyFault> {
    let WindowsSuppliedStreamSet::OrderedRecords(supplied) = streams else {
        return Ok(Vec::new());
    };
    if supplied.records.is_empty() || supplied.records.len() > MAXIMUM_STREAMS {
        return Err(WindowsSuppliedEntryAssemblyFault::new(
            WindowsSuppliedEntryAssemblyFaultCode::Stream,
            "streams.records",
            "ordered records must contain one through 1024 entries",
        ));
    }

    let mut names = BTreeSet::new();
    let mut previous_offset = None;
    for record in &supplied.records {
        let name_units = record.name.encode_utf16().count();
        if !(1..=MAXIMUM_STREAM_NAME_UTF16_UNITS).contains(&name_units)
            || !is_exact_data_stream_name(&record.name)
        {
            return Err(WindowsSuppliedEntryAssemblyFault::new(
                WindowsSuppliedEntryAssemblyFaultCode::Stream,
                "streams.records.name",
                "stream name violates exact DATA-stream grammar or UTF-16 bound",
            ));
        }
        if !names.insert(record.name.as_str()) {
            return Err(WindowsSuppliedEntryAssemblyFault::new(
                WindowsSuppliedEntryAssemblyFaultCode::Stream,
                "streams.records.name",
                "stream names must be exactly unique",
            ));
        }
        if previous_offset.is_some_and(|previous| previous >= record.source_offset) {
            return Err(WindowsSuppliedEntryAssemblyFault::new(
                WindowsSuppliedEntryAssemblyFaultCode::Stream,
                "streams.records.source_offset",
                "source offsets must increase strictly in supplied order",
            ));
        }
        previous_offset = Some(record.source_offset);
    }
    Ok(supplied.records.clone())
}

fn is_exact_data_stream_name(name: &str) -> bool {
    name == "::$DATA"
        || name
            .strip_prefix(':')
            .and_then(|value| value.strip_suffix(":$DATA"))
            .is_some_and(|inner| !inner.is_empty() && !inner.contains([':', '\0']))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL};

    fn correlation() -> WindowsSuppliedRecordCorrelation {
        WindowsSuppliedRecordCorrelation {
            batch_identity: 7,
            entry_reference_identity: 11,
        }
    }

    fn regular_input() -> WindowsSuppliedEntryAssemblyInput {
        let correlation = correlation();
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

    #[test]
    fn profile_json_and_required_fields_are_strict() {
        let valid = regular_input();
        let bytes = serde_json::to_vec(&valid).expect("serialize");
        assert_eq!(
            decode_and_assemble_windows_supplied_entry_observation(&bytes)
                .expect("valid")
                .end_of_file,
            9
        );

        let mut wrong_profile = valid;
        wrong_profile.profile = "cantor-windows-supplied-entry-observation/0.0".to_owned();
        assert_eq!(
            assemble_windows_supplied_entry_observation(wrong_profile)
                .expect_err("profile")
                .code,
            WindowsSuppliedEntryAssemblyFaultCode::Profile
        );

        let unknown =
            String::from_utf8(bytes)
                .expect("UTF-8")
                .replacen('{', "{\"trusted\":true,", 1);
        assert_eq!(
            decode_and_assemble_windows_supplied_entry_observation(unknown.as_bytes())
                .expect_err("unknown field")
                .code,
            WindowsSuppliedEntryAssemblyFaultCode::Json
        );
    }

    #[test]
    fn correlations_must_all_be_nonzero_and_equal() {
        let mut zero = regular_input();
        zero.attribute_tag.correlation.batch_identity = 0;
        assert_eq!(
            assemble_windows_supplied_entry_observation(zero)
                .expect_err("zero")
                .code,
            WindowsSuppliedEntryAssemblyFaultCode::Correlation
        );

        let mut records = regular_input();
        records.file_identity.correlation.batch_identity = 8;
        assert_eq!(
            assemble_windows_supplied_entry_observation(records)
                .expect_err("identity record")
                .code,
            WindowsSuppliedEntryAssemblyFaultCode::Correlation
        );
        let mut records = regular_input();
        records.standard.correlation.entry_reference_identity = 12;
        assert_eq!(
            assemble_windows_supplied_entry_observation(records)
                .expect_err("standard record")
                .code,
            WindowsSuppliedEntryAssemblyFaultCode::Correlation
        );
        let mut records = regular_input();
        records.case_sensitivity =
            WindowsSuppliedCaseSensitivityRecord::NotApplicable(WindowsSuppliedRecordCorrelation {
                batch_identity: 7,
                entry_reference_identity: 12,
            });
        assert_eq!(
            assemble_windows_supplied_entry_observation(records)
                .expect_err("case record")
                .code,
            WindowsSuppliedEntryAssemblyFaultCode::Correlation
        );
        let mut records = regular_input();
        records.streams =
            WindowsSuppliedStreamSet::ExplicitEmpty(WindowsSuppliedRecordCorrelation {
                batch_identity: 8,
                entry_reference_identity: 11,
            });
        assert_eq!(
            assemble_windows_supplied_entry_observation(records)
                .expect_err("stream record")
                .code,
            WindowsSuppliedEntryAssemblyFaultCode::Correlation
        );
    }

    #[test]
    fn file_identity_is_exact_and_lowercase_byte_order_preserving() {
        let observation =
            assemble_windows_supplied_entry_observation(regular_input()).expect("valid");
        assert_eq!(observation.identity.volume_serial, 19);
        assert_eq!(
            observation.identity.file_id_hex,
            "000102030405060708090a0b0c0d0e0f"
        );

        for length in [0, 15, 17] {
            let mut input = regular_input();
            input.file_identity.file_id_bytes = vec![0; length];
            assert_eq!(
                assemble_windows_supplied_entry_observation(input)
                    .expect_err("identity")
                    .code,
                WindowsSuppliedEntryAssemblyFaultCode::Identity
            );
        }
    }

    #[test]
    fn signed_sizes_reject_before_conversion() {
        for (allocation_size, end_of_file) in [(-1, 0), (0, -1), (i64::MIN, i64::MIN)] {
            let mut input = regular_input();
            input.standard.allocation_size = allocation_size;
            input.standard.end_of_file = end_of_file;
            assert_eq!(
                assemble_windows_supplied_entry_observation(input)
                    .expect_err("size")
                    .code,
                WindowsSuppliedEntryAssemblyFaultCode::Size
            );
        }
        let mut input = regular_input();
        input.standard.allocation_size = i64::MAX;
        input.standard.end_of_file = i64::MAX;
        let observation = assemble_windows_supplied_entry_observation(input).expect("maximum");
        assert_eq!(observation.allocation_size, i64::MAX as u64);
        assert_eq!(observation.end_of_file, i64::MAX as u64);
    }

    #[test]
    fn zero_links_and_delete_pending_always_reject() {
        let mut links = regular_input();
        links.standard.number_of_links = 0;
        assert_eq!(
            assemble_windows_supplied_entry_observation(links)
                .expect_err("links")
                .code,
            WindowsSuppliedEntryAssemblyFaultCode::Link
        );

        let mut deleting = regular_input();
        deleting.standard.delete_pending = true;
        assert_eq!(
            assemble_windows_supplied_entry_observation(deleting)
                .expect_err("delete")
                .code,
            WindowsSuppliedEntryAssemblyFaultCode::DeletePending
        );
    }

    #[test]
    fn kind_directory_flag_attributes_and_case_variant_must_agree() {
        let mut directory = regular_input();
        directory.kind = WindowsEntryPolicyKind::Directory;
        directory.attribute_tag.attributes = FILE_ATTRIBUTE_DIRECTORY;
        directory.standard.directory = true;
        directory.case_sensitivity = WindowsSuppliedCaseSensitivityRecord::DirectoryFlags(
            WindowsSuppliedDirectoryCaseFlags {
                correlation: correlation(),
                flags: 0,
            },
        );
        let observation =
            assemble_windows_supplied_entry_observation(directory).expect("directory");
        assert_eq!(
            observation.policy_decision.kind,
            WindowsEntryPolicyKind::Directory
        );
        assert_eq!(observation.topology_projection_seed().length, None);

        let mut kind = regular_input();
        kind.standard.directory = true;
        assert_eq!(
            assemble_windows_supplied_entry_observation(kind)
                .expect_err("kind")
                .code,
            WindowsSuppliedEntryAssemblyFaultCode::Kind
        );

        let mut case = regular_input();
        case.case_sensitivity = WindowsSuppliedCaseSensitivityRecord::DirectoryFlags(
            WindowsSuppliedDirectoryCaseFlags {
                correlation: correlation(),
                flags: 0,
            },
        );
        assert_eq!(
            assemble_windows_supplied_entry_observation(case)
                .expect_err("case")
                .code,
            WindowsSuppliedEntryAssemblyFaultCode::CaseSensitivity
        );

        let mut attributes = regular_input();
        attributes.attribute_tag.attributes = FILE_ATTRIBUTE_DIRECTORY;
        assert_eq!(
            assemble_windows_supplied_entry_observation(attributes)
                .expect_err("policy")
                .code,
            WindowsSuppliedEntryAssemblyFaultCode::Policy
        );
    }

    #[test]
    fn policy_receives_exact_component_bound_and_diagnostic_tag() {
        let mut input = regular_input();
        input.component = "Ångström😀.rs".to_owned();
        input.maximum_component_utf16_units = 13;
        input.attribute_tag.reparse_tag = u32::MAX;
        let observation =
            assemble_windows_supplied_entry_observation(input.clone()).expect("Unicode");
        assert_eq!(observation.policy_decision.component, input.component);
        assert_eq!(observation.reparse_tag, u32::MAX);

        input.maximum_component_utf16_units = 12;
        assert_eq!(
            assemble_windows_supplied_entry_observation(input)
                .expect_err("bound")
                .code,
            WindowsSuppliedEntryAssemblyFaultCode::Policy
        );
    }

    #[test]
    fn raw_stream_order_and_sizes_are_preserved_while_projection_is_sorted() {
        let mut input = regular_input();
        let supplied = vec![
            WindowsRawStreamRecord {
                name: ":z:$DATA".to_owned(),
                stream_size: 3,
                allocation_size: 8,
                source_offset: 0,
            },
            WindowsRawStreamRecord {
                name: "::$DATA".to_owned(),
                stream_size: 9,
                allocation_size: 16,
                source_offset: 48,
            },
            WindowsRawStreamRecord {
                name: ":a:$DATA".to_owned(),
                stream_size: 5,
                allocation_size: 8,
                source_offset: 96,
            },
        ];
        input.streams =
            WindowsSuppliedStreamSet::OrderedRecords(WindowsSuppliedOrderedStreamRecords {
                correlation: correlation(),
                records: supplied.clone(),
            });
        let observation =
            assemble_windows_supplied_entry_observation(input).expect("ordered records");
        assert_eq!(observation.supplied_stream_records, supplied);
        let projection = observation.topology_projection_seed();
        assert_eq!(
            projection
                .streams
                .iter()
                .map(|stream| stream.name.as_str())
                .collect::<Vec<_>>(),
            vec!["::$DATA", ":a:$DATA", ":z:$DATA"]
        );
        assert_eq!(projection.length, Some(9));
        assert_eq!(projection.streams[1].size, 5);
    }

    #[test]
    fn stream_variants_cardinality_grammar_uniqueness_and_order_are_closed() {
        let mut empty_records = regular_input();
        empty_records.streams =
            WindowsSuppliedStreamSet::OrderedRecords(WindowsSuppliedOrderedStreamRecords {
                correlation: correlation(),
                records: Vec::new(),
            });
        assert_eq!(
            assemble_windows_supplied_entry_observation(empty_records)
                .expect_err("use explicit empty")
                .code,
            WindowsSuppliedEntryAssemblyFaultCode::Stream
        );

        let record = WindowsRawStreamRecord {
            name: ":a:$DATA".to_owned(),
            stream_size: 1,
            allocation_size: 2,
            source_offset: 8,
        };
        for records in [
            vec![
                record.clone(),
                WindowsRawStreamRecord {
                    source_offset: 16,
                    ..record.clone()
                },
            ],
            vec![
                record.clone(),
                WindowsRawStreamRecord {
                    name: ":b:$DATA".to_owned(),
                    source_offset: 8,
                    ..record.clone()
                },
            ],
            vec![WindowsRawStreamRecord {
                name: ":a:b:$DATA".to_owned(),
                ..record.clone()
            }],
            vec![WindowsRawStreamRecord {
                name: format!(":{}:$DATA", "x".repeat(32_768)),
                ..record.clone()
            }],
        ] {
            let mut input = regular_input();
            input.streams =
                WindowsSuppliedStreamSet::OrderedRecords(WindowsSuppliedOrderedStreamRecords {
                    correlation: correlation(),
                    records,
                });
            assert_eq!(
                assemble_windows_supplied_entry_observation(input)
                    .expect_err("stream")
                    .code,
                WindowsSuppliedEntryAssemblyFaultCode::Stream
            );
        }

        let mut over_bound = regular_input();
        over_bound.streams =
            WindowsSuppliedStreamSet::OrderedRecords(WindowsSuppliedOrderedStreamRecords {
                correlation: correlation(),
                records: (0..1_025)
                    .map(|index| WindowsRawStreamRecord {
                        name: format!(":s{index}:$DATA"),
                        stream_size: 0,
                        allocation_size: 0,
                        source_offset: index,
                    })
                    .collect(),
            });
        assert_eq!(
            assemble_windows_supplied_entry_observation(over_bound)
                .expect_err("bound")
                .code,
            WindowsSuppliedEntryAssemblyFaultCode::Stream
        );
    }

    #[test]
    fn explicit_empty_is_preserved_as_empty_syntax_only() {
        let observation =
            assemble_windows_supplied_entry_observation(regular_input()).expect("empty");
        assert!(observation.supplied_stream_records.is_empty());
        assert!(observation.topology_projection_seed().streams.is_empty());
    }

    #[test]
    fn profile_is_exact() {
        assert_eq!(
            WINDOWS_SUPPLIED_ENTRY_OBSERVATION_PROFILE,
            "cantor-windows-supplied-entry-observation/0.1"
        );
    }
}
