//! Effect-free machine forms for the future Phase 3 Windows topology scanner.
//!
//! These types validate caller-supplied values. They do not inspect a path,
//! enforce topology policy, keep a receipt-consumption ledger, or grant any
//! filesystem, process, network, model, mutation, or promotion authority.

use std::fmt;

use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::ConsistencyClass;

/// Version of this pure machine-form vocabulary.
pub const TOPOLOGY_FORMS_PROFILE: &str = "cantor-phase3-topology-forms/0.1";
/// Scanner profile represented by a topology receipt.
pub const WINDOWS_TOPOLOGY_PROFILE: &str = "cantor-windows-candidate-topology/0.1";

const MAX_TEXT_BYTES: usize = 1_024;
const MAX_PROFILE_BYTES: usize = 128;
const MAX_PATH_BYTES: usize = 32_768;
const MAX_NONCE_BYTES: usize = 256;
const MAX_ENTRIES: u64 = 1_000_000;
const MAX_DEPTH: u32 = 256;
const MAX_FILE_BYTES: u64 = 1_099_511_627_776;
const MAX_TOTAL_BYTES: u64 = 4_398_046_511_104;
const MAX_STREAMS_PER_ENTRY: u32 = 1_024;

/// Closed validation failures for topology machine forms.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TopologyFormFaultCode {
    Json,
    Text,
    Digest,
    Limit,
    Identity,
    Stream,
    Entry,
    Receipt,
    Consumption,
    RuntimeFault,
}

/// Bounded failure produced before a topology value is admitted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopologyFormFault {
    pub code: TopologyFormFaultCode,
    pub field: String,
    pub message: String,
}

impl TopologyFormFault {
    fn new(code: TopologyFormFaultCode, field: &str, message: &str) -> Self {
        Self {
            code,
            field: field.to_owned(),
            message: message.chars().take(MAX_TEXT_BYTES).collect(),
        }
    }
}

impl fmt::Display for TopologyFormFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl std::error::Error for TopologyFormFault {}

/// Semantic validation implemented by every admitted topology form.
pub trait ValidateTopologyForm {
    fn validate(&self) -> Result<(), TopologyFormFault>;
}

/// Strictly decodes JSON and then applies semantic validation.
pub fn decode_topology_json<T>(bytes: &[u8]) -> Result<T, TopologyFormFault>
where
    T: DeserializeOwned + ValidateTopologyForm,
{
    let value = serde_json::from_slice::<T>(bytes).map_err(|error| {
        TopologyFormFault::new(TopologyFormFaultCode::Json, "json", &error.to_string())
    })?;
    value.validate()?;
    Ok(value)
}

/// Hard resource limits supplied to one future scan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopologyScanLimits {
    pub maximum_entries: u64,
    pub maximum_depth: u32,
    pub maximum_path_bytes: u32,
    pub maximum_file_bytes: u64,
    pub maximum_total_bytes: u64,
    pub maximum_streams_per_entry: u32,
    pub deadline_tick: u64,
}

impl ValidateTopologyForm for TopologyScanLimits {
    fn validate(&self) -> Result<(), TopologyFormFault> {
        check_range(self.maximum_entries, 1, MAX_ENTRIES, "maximum_entries")?;
        check_range(
            u64::from(self.maximum_depth),
            1,
            u64::from(MAX_DEPTH),
            "maximum_depth",
        )?;
        check_range(
            u64::from(self.maximum_path_bytes),
            1,
            MAX_PATH_BYTES as u64,
            "maximum_path_bytes",
        )?;
        check_range(
            self.maximum_file_bytes,
            1,
            MAX_FILE_BYTES,
            "maximum_file_bytes",
        )?;
        check_range(
            self.maximum_total_bytes,
            1,
            MAX_TOTAL_BYTES,
            "maximum_total_bytes",
        )?;
        check_range(
            u64::from(self.maximum_streams_per_entry),
            1,
            u64::from(MAX_STREAMS_PER_ENTRY),
            "maximum_streams_per_entry",
        )?;
        if self.maximum_file_bytes > self.maximum_total_bytes {
            return Err(TopologyFormFault::new(
                TopologyFormFaultCode::Limit,
                "maximum_file_bytes",
                "per-file bound cannot exceed total-byte bound",
            ));
        }
        if self.deadline_tick == 0 {
            return Err(TopologyFormFault::new(
                TopologyFormFaultCode::Limit,
                "deadline_tick",
                "deadline tick must be nonzero",
            ));
        }
        Ok(())
    }
}

/// Strong scan-local Windows file identity.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrongFileIdentity {
    pub volume_serial: u64,
    pub file_id_hex: String,
}

impl ValidateTopologyForm for StrongFileIdentity {
    fn validate(&self) -> Result<(), TopologyFormFault> {
        validate_lower_hex(
            &self.file_id_hex,
            32,
            "file_id_hex",
            TopologyFormFaultCode::Identity,
        )
    }
}

/// Entry kinds admitted by the initial evidence vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TopologyEntryKind {
    RootDirectory,
    Directory,
    RegularFile,
}

/// Closed platform-to-Git mode classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TopologyModeClass {
    Directory,
    RegularNonExecutable,
    RegularExecutable,
}

/// Data-stream classification without platform-policy interpretation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TopologyStreamKind {
    UnnamedDefault,
    NamedData,
}

/// One caller-observed Windows data stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopologyStreamFact {
    pub name: String,
    pub size: u64,
    pub kind: TopologyStreamKind,
}

impl ValidateTopologyForm for TopologyStreamFact {
    fn validate(&self) -> Result<(), TopologyFormFault> {
        validate_text(&self.name, "stream.name", MAX_TEXT_BYTES)?;
        match self.kind {
            TopologyStreamKind::UnnamedDefault if self.name != "::$DATA" => {
                Err(TopologyFormFault::new(
                    TopologyFormFaultCode::Stream,
                    "stream.name",
                    "unnamed default stream must be named ::$DATA",
                ))
            }
            TopologyStreamKind::NamedData if self.name == "::$DATA" => Err(TopologyFormFault::new(
                TopologyFormFaultCode::Stream,
                "stream.kind",
                "::$DATA must be classified as unnamed_default",
            )),
            _ => Ok(()),
        }
    }
}

/// One structurally coherent caller-supplied entry observation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopologyEntryObservation {
    pub relative_path: Option<String>,
    pub kind: TopologyEntryKind,
    pub mode_class: TopologyModeClass,
    pub attributes: u32,
    pub identity: StrongFileIdentity,
    pub number_of_links: u32,
    pub streams: Vec<TopologyStreamFact>,
    pub length: Option<u64>,
    pub content_sha256: Option<String>,
    pub observation_ordinal: u64,
}

impl ValidateTopologyForm for TopologyEntryObservation {
    fn validate(&self) -> Result<(), TopologyFormFault> {
        self.identity.validate()?;
        if self.number_of_links == 0 {
            return Err(TopologyFormFault::new(
                TopologyFormFaultCode::Entry,
                "number_of_links",
                "link count must be nonzero",
            ));
        }
        if self.observation_ordinal == 0 {
            return Err(TopologyFormFault::new(
                TopologyFormFaultCode::Entry,
                "observation_ordinal",
                "observation ordinal must be nonzero",
            ));
        }
        validate_streams(&self.streams)?;

        match self.kind {
            TopologyEntryKind::RootDirectory => {
                require_root_path(&self.relative_path)?;
                require_directory_shape(self.mode_class, self.length, &self.content_sha256)
            }
            TopologyEntryKind::Directory => {
                require_descendant_path(&self.relative_path)?;
                require_directory_shape(self.mode_class, self.length, &self.content_sha256)
            }
            TopologyEntryKind::RegularFile => {
                require_descendant_path(&self.relative_path)?;
                if !matches!(
                    self.mode_class,
                    TopologyModeClass::RegularNonExecutable | TopologyModeClass::RegularExecutable
                ) {
                    return Err(TopologyFormFault::new(
                        TopologyFormFaultCode::Entry,
                        "mode_class",
                        "regular file requires a regular mode class",
                    ));
                }
                if self.length.is_none() {
                    return Err(TopologyFormFault::new(
                        TopologyFormFaultCode::Entry,
                        "length",
                        "regular file requires length",
                    ));
                }
                match &self.content_sha256 {
                    Some(digest) => validate_digest(digest, "content_sha256"),
                    None => Err(TopologyFormFault::new(
                        TopologyFormFaultCode::Entry,
                        "content_sha256",
                        "regular file requires content digest",
                    )),
                }
            }
        }
    }
}

/// Fresh content-addressed evidence from a future successful topology scan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopologyReceipt {
    pub profile: String,
    pub candidate_root: String,
    pub admission_profile: String,
    pub admission_receipt_sha256: String,
    pub policy_sha256: String,
    pub scan_nonce: String,
    pub ordered_inventory_sha256: String,
    pub limits: TopologyScanLimits,
    pub entry_count: u64,
    pub total_file_bytes: u64,
    pub consistency: ConsistencyClass,
    pub issued_tick: u64,
    pub expires_tick: u64,
}

impl ValidateTopologyForm for TopologyReceipt {
    fn validate(&self) -> Result<(), TopologyFormFault> {
        if self.profile != WINDOWS_TOPOLOGY_PROFILE {
            return Err(TopologyFormFault::new(
                TopologyFormFaultCode::Receipt,
                "profile",
                "unknown topology scanner profile",
            ));
        }
        validate_text(&self.candidate_root, "candidate_root", MAX_PATH_BYTES)?;
        validate_text(
            &self.admission_profile,
            "admission_profile",
            MAX_PROFILE_BYTES,
        )?;
        validate_digest(&self.admission_receipt_sha256, "admission_receipt_sha256")?;
        validate_digest(&self.policy_sha256, "policy_sha256")?;
        validate_text(&self.scan_nonce, "scan_nonce", MAX_NONCE_BYTES)?;
        validate_digest(&self.ordered_inventory_sha256, "ordered_inventory_sha256")?;
        self.limits.validate()?;
        if self.entry_count == 0 || self.entry_count > self.limits.maximum_entries {
            return Err(TopologyFormFault::new(
                TopologyFormFaultCode::Receipt,
                "entry_count",
                "entry count must be nonzero and within scan limits",
            ));
        }
        if self.total_file_bytes > self.limits.maximum_total_bytes {
            return Err(TopologyFormFault::new(
                TopologyFormFaultCode::Receipt,
                "total_file_bytes",
                "total file bytes exceed scan limits",
            ));
        }
        if self.consistency != ConsistencyClass::QuiescentDoubleInventory {
            return Err(TopologyFormFault::new(
                TopologyFormFaultCode::Receipt,
                "consistency",
                "M2A receipt permits only quiescent_double_inventory",
            ));
        }
        if self.issued_tick >= self.expires_tick {
            return Err(TopologyFormFault::new(
                TopologyFormFaultCode::Receipt,
                "expires_tick",
                "receipt expiry must be greater than issue tick",
            ));
        }
        if self.expires_tick > self.limits.deadline_tick {
            return Err(TopologyFormFault::new(
                TopologyFormFaultCode::Receipt,
                "expires_tick",
                "receipt expiry cannot exceed the bound scan deadline",
            ));
        }
        Ok(())
    }
}

/// Immutable evidence that a future supervisor consumed a receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopologyReceiptConsumption {
    pub topology_receipt_sha256: String,
    pub mutation_work_packet_sha256: String,
    pub issued_tick: u64,
    pub consumed_tick: u64,
    pub expires_tick: u64,
}

impl ValidateTopologyForm for TopologyReceiptConsumption {
    fn validate(&self) -> Result<(), TopologyFormFault> {
        validate_digest(&self.topology_receipt_sha256, "topology_receipt_sha256")?;
        validate_digest(
            &self.mutation_work_packet_sha256,
            "mutation_work_packet_sha256",
        )?;
        if self.issued_tick > self.consumed_tick || self.consumed_tick >= self.expires_tick {
            return Err(TopologyFormFault::new(
                TopologyFormFaultCode::Consumption,
                "consumed_tick",
                "consumption must be at or after issue and strictly before expiry",
            ));
        }
        Ok(())
    }
}

/// Closed future scanner operations used in fault evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TopologyOperation {
    ValidateRequest,
    EnumerateDirectory,
    OpenEntry,
    QueryAttributes,
    QueryIdentity,
    QueryLinks,
    EnumerateStreams,
    ReadContent,
    RepeatInventory,
    IssueReceipt,
}

/// Closed future scanner runtime-fault classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TopologyRuntimeFaultClass {
    InvalidRequest,
    Limit,
    Path,
    Reparse,
    HardLink,
    DuplicateIdentity,
    Stream,
    Attribute,
    SpecialEntry,
    GitTopology,
    UnsupportedPlatform,
    Access,
    NotFound,
    ChangedDuringScan,
    OtherOs,
}

/// Admission consequence of a future runtime fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TopologyFaultDisposition {
    DenyLaunch,
    QuarantineCandidate,
}

/// Honest, bounded report of one future scanner runtime failure.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopologyRuntimeFault {
    pub operation: TopologyOperation,
    pub class: TopologyRuntimeFaultClass,
    pub relative_path: Option<String>,
    pub os_error: Option<i32>,
    pub may_have_changed: bool,
    pub disposition: TopologyFaultDisposition,
}

impl ValidateTopologyForm for TopologyRuntimeFault {
    fn validate(&self) -> Result<(), TopologyFormFault> {
        if let Some(path) = &self.relative_path {
            validate_relative_path(path)?;
        }
        if self.may_have_changed
            && self.disposition != TopologyFaultDisposition::QuarantineCandidate
        {
            return Err(TopologyFormFault::new(
                TopologyFormFaultCode::RuntimeFault,
                "disposition",
                "possible candidate change requires quarantine",
            ));
        }
        if self.disposition == TopologyFaultDisposition::DenyLaunch && self.may_have_changed {
            return Err(TopologyFormFault::new(
                TopologyFormFaultCode::RuntimeFault,
                "may_have_changed",
                "deny_launch is valid only before possible change",
            ));
        }
        if self.class == TopologyRuntimeFaultClass::ChangedDuringScan
            && (!self.may_have_changed
                || self.disposition != TopologyFaultDisposition::QuarantineCandidate)
        {
            return Err(TopologyFormFault::new(
                TopologyFormFaultCode::RuntimeFault,
                "changed_during_scan",
                "changed_during_scan requires possible change and quarantine",
            ));
        }
        Ok(())
    }
}

fn check_range(
    value: u64,
    minimum: u64,
    maximum: u64,
    field: &str,
) -> Result<(), TopologyFormFault> {
    if (minimum..=maximum).contains(&value) {
        Ok(())
    } else {
        Err(TopologyFormFault::new(
            TopologyFormFaultCode::Limit,
            field,
            "value is outside the closed profile bound",
        ))
    }
}

fn validate_text(value: &str, field: &str, maximum: usize) -> Result<(), TopologyFormFault> {
    if value.is_empty() || value.len() > maximum || value.contains('\0') {
        return Err(TopologyFormFault::new(
            TopologyFormFaultCode::Text,
            field,
            "text must be nonempty, NUL-free, and within its byte bound",
        ));
    }
    Ok(())
}

fn validate_lower_hex(
    value: &str,
    length: usize,
    field: &str,
    code: TopologyFormFaultCode,
) -> Result<(), TopologyFormFault> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(TopologyFormFault::new(
            code,
            field,
            "value must have exact length and canonical lowercase hexadecimal form",
        ));
    }
    Ok(())
}

fn validate_digest(value: &str, field: &str) -> Result<(), TopologyFormFault> {
    validate_lower_hex(value, 64, field, TopologyFormFaultCode::Digest)
}

fn validate_relative_path(path: &str) -> Result<(), TopologyFormFault> {
    if path.len() > MAX_PATH_BYTES
        || path.is_empty()
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains('\\')
        || path.contains(':')
        || path.contains('\0')
    {
        return Err(TopologyFormFault::new(
            TopologyFormFaultCode::Entry,
            "relative_path",
            "path is not a bounded canonical relative path",
        ));
    }
    for segment in path.split('/') {
        if segment.is_empty()
            || segment == "."
            || segment == ".."
            || segment.eq_ignore_ascii_case(".git")
        {
            return Err(TopologyFormFault::new(
                TopologyFormFaultCode::Entry,
                "relative_path",
                "path contains a forbidden segment",
            ));
        }
    }
    Ok(())
}

fn require_root_path(path: &Option<String>) -> Result<(), TopologyFormFault> {
    if path.is_none() {
        Ok(())
    } else {
        Err(TopologyFormFault::new(
            TopologyFormFaultCode::Entry,
            "relative_path",
            "root_directory must not have a relative path",
        ))
    }
}

fn require_descendant_path(path: &Option<String>) -> Result<(), TopologyFormFault> {
    match path {
        Some(path) => validate_relative_path(path),
        None => Err(TopologyFormFault::new(
            TopologyFormFaultCode::Entry,
            "relative_path",
            "non-root entry requires a relative path",
        )),
    }
}

fn require_directory_shape(
    mode: TopologyModeClass,
    length: Option<u64>,
    digest: &Option<String>,
) -> Result<(), TopologyFormFault> {
    if mode != TopologyModeClass::Directory || length.is_some() || digest.is_some() {
        return Err(TopologyFormFault::new(
            TopologyFormFaultCode::Entry,
            "entry",
            "directory requires directory mode and no content fields",
        ));
    }
    Ok(())
}

fn validate_streams(streams: &[TopologyStreamFact]) -> Result<(), TopologyFormFault> {
    if streams.len() > MAX_STREAMS_PER_ENTRY as usize {
        return Err(TopologyFormFault::new(
            TopologyFormFaultCode::Stream,
            "streams",
            "stream collection exceeds profile bound",
        ));
    }
    let mut previous: Option<&str> = None;
    let mut default_count = 0_u8;
    for stream in streams {
        stream.validate()?;
        if let Some(previous) = previous
            && previous >= stream.name.as_str()
        {
            return Err(TopologyFormFault::new(
                TopologyFormFaultCode::Stream,
                "streams",
                "streams must be strictly sorted by unique name",
            ));
        }
        if stream.kind == TopologyStreamKind::UnnamedDefault {
            default_count += 1;
            if default_count > 1 {
                return Err(TopologyFormFault::new(
                    TopologyFormFaultCode::Stream,
                    "streams",
                    "at most one unnamed default stream is permitted",
                ));
            }
        }
        previous = Some(&stream.name);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(character: char) -> String {
        std::iter::repeat_n(character, 64).collect()
    }

    fn identity() -> StrongFileIdentity {
        StrongFileIdentity {
            volume_serial: 7,
            file_id_hex: "0123456789abcdef0123456789abcdef".to_owned(),
        }
    }

    fn limits() -> TopologyScanLimits {
        TopologyScanLimits {
            maximum_entries: 100,
            maximum_depth: 20,
            maximum_path_bytes: 1_024,
            maximum_file_bytes: 1_000_000,
            maximum_total_bytes: 2_000_000,
            maximum_streams_per_entry: 8,
            deadline_tick: 250,
        }
    }

    fn receipt() -> TopologyReceipt {
        TopologyReceipt {
            profile: WINDOWS_TOPOLOGY_PROFILE.to_owned(),
            candidate_root: r"C:\candidate".to_owned(),
            admission_profile: "cantor-candidate-workspace-admission/0.1".to_owned(),
            admission_receipt_sha256: digest('a'),
            policy_sha256: digest('b'),
            scan_nonce: "scan-1".to_owned(),
            ordered_inventory_sha256: digest('c'),
            limits: limits(),
            entry_count: 3,
            total_file_bytes: 42,
            consistency: ConsistencyClass::QuiescentDoubleInventory,
            issued_tick: 100,
            expires_tick: 200,
        }
    }

    #[test]
    fn strict_json_rejects_unknown_and_malformed_input() {
        let valid = serde_json::to_vec(&limits()).expect("serialize");
        assert_eq!(
            decode_topology_json::<TopologyScanLimits>(&valid).expect("valid"),
            limits()
        );
        let unknown = br#"{"maximum_entries":1,"maximum_depth":1,"maximum_path_bytes":1,"maximum_file_bytes":1,"maximum_total_bytes":1,"maximum_streams_per_entry":1,"deadline_tick":1,"extra":true}"#;
        assert_eq!(
            decode_topology_json::<TopologyScanLimits>(unknown)
                .expect_err("unknown field")
                .code,
            TopologyFormFaultCode::Json
        );
        assert_eq!(
            decode_topology_json::<TopologyScanLimits>(b"{")
                .expect_err("malformed")
                .code,
            TopologyFormFaultCode::Json
        );
    }

    #[test]
    fn scan_limits_enforce_every_bound_and_cross_field_relation() {
        assert!(limits().validate().is_ok());
        let mut invalid = limits();
        invalid.maximum_entries = 0;
        assert!(invalid.validate().is_err());
        invalid = limits();
        invalid.maximum_depth = MAX_DEPTH + 1;
        assert!(invalid.validate().is_err());
        invalid = limits();
        invalid.maximum_path_bytes = MAX_PATH_BYTES as u32 + 1;
        assert!(invalid.validate().is_err());
        invalid = limits();
        invalid.maximum_file_bytes = invalid.maximum_total_bytes + 1;
        assert!(invalid.validate().is_err());
        invalid = limits();
        invalid.maximum_streams_per_entry = 0;
        assert!(invalid.validate().is_err());
        invalid = limits();
        invalid.deadline_tick = 0;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn strong_identity_is_exact_lowercase_128_bit_hex() {
        assert!(identity().validate().is_ok());
        for value in [
            "0123",
            "0123456789ABCDEF0123456789ABCDEF",
            "g123456789abcdef0123456789abcdef",
        ] {
            let mut invalid = identity();
            invalid.file_id_hex = value.to_owned();
            assert!(invalid.validate().is_err(), "{value}");
        }
    }

    #[test]
    fn streams_are_coherent_sorted_unique_and_bounded() {
        let default = TopologyStreamFact {
            name: "::$DATA".to_owned(),
            size: 10,
            kind: TopologyStreamKind::UnnamedDefault,
        };
        assert!(default.validate().is_ok());
        let mut invalid_default = default.clone();
        invalid_default.name = ":named:$DATA".to_owned();
        assert!(invalid_default.validate().is_err());
        let named = TopologyStreamFact {
            name: ":named:$DATA".to_owned(),
            size: 1,
            kind: TopologyStreamKind::NamedData,
        };
        assert!(validate_streams(&[default.clone(), named.clone()]).is_ok());
        assert!(validate_streams(&[named, default.clone()]).is_err());
        assert!(validate_streams(&[default.clone(), default]).is_err());
    }

    #[test]
    fn entry_shape_table_and_paths_are_exact() {
        let root = TopologyEntryObservation {
            relative_path: None,
            kind: TopologyEntryKind::RootDirectory,
            mode_class: TopologyModeClass::Directory,
            attributes: 16,
            identity: identity(),
            number_of_links: 1,
            streams: Vec::new(),
            length: None,
            content_sha256: None,
            observation_ordinal: 1,
        };
        assert!(root.validate().is_ok());
        let mut directory = root.clone();
        directory.kind = TopologyEntryKind::Directory;
        directory.relative_path = Some("src".to_owned());
        directory.observation_ordinal = 2;
        assert!(directory.validate().is_ok());
        let mut regular = directory.clone();
        regular.kind = TopologyEntryKind::RegularFile;
        regular.relative_path = Some("src/lib.rs".to_owned());
        regular.mode_class = TopologyModeClass::RegularNonExecutable;
        regular.length = Some(12);
        regular.content_sha256 = Some(digest('d'));
        assert!(regular.validate().is_ok());
        for path in ["", "/root", "a\\b", "a/../b", ".git/config", "a:x"] {
            regular.relative_path = Some(path.to_owned());
            assert!(regular.validate().is_err(), "{path}");
        }
        regular.relative_path = Some("src/lib.rs".to_owned());
        regular.content_sha256 = None;
        assert!(regular.validate().is_err());
        directory.length = Some(0);
        assert!(directory.validate().is_err());
    }

    #[test]
    fn receipt_binds_limits_strength_and_freshness() {
        assert!(receipt().validate().is_ok());
        let mut invalid = receipt();
        invalid.consistency = ConsistencyClass::OsSnapshotProven;
        assert!(invalid.validate().is_err());
        invalid = receipt();
        invalid.entry_count = invalid.limits.maximum_entries + 1;
        assert!(invalid.validate().is_err());
        invalid = receipt();
        invalid.total_file_bytes = invalid.limits.maximum_total_bytes + 1;
        assert!(invalid.validate().is_err());
        invalid = receipt();
        invalid.expires_tick = invalid.issued_tick;
        assert!(invalid.validate().is_err());
        invalid = receipt();
        invalid.expires_tick = invalid.limits.deadline_tick + 1;
        assert!(invalid.validate().is_err());
        invalid = receipt();
        invalid.profile = TOPOLOGY_FORMS_PROFILE.to_owned();
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn consumption_uses_a_half_open_freshness_interval() {
        let mut value = TopologyReceiptConsumption {
            topology_receipt_sha256: digest('a'),
            mutation_work_packet_sha256: digest('b'),
            issued_tick: 100,
            consumed_tick: 100,
            expires_tick: 200,
        };
        assert!(value.validate().is_ok());
        value.consumed_tick = 199;
        assert!(value.validate().is_ok());
        value.consumed_tick = 200;
        assert!(value.validate().is_err());
        value.consumed_tick = 99;
        assert!(value.validate().is_err());
    }

    #[test]
    fn runtime_fault_never_denies_possible_change() {
        for may_have_changed in [false, true] {
            for disposition in [
                TopologyFaultDisposition::DenyLaunch,
                TopologyFaultDisposition::QuarantineCandidate,
            ] {
                let value = TopologyRuntimeFault {
                    operation: TopologyOperation::ReadContent,
                    class: TopologyRuntimeFaultClass::Access,
                    relative_path: Some("src/lib.rs".to_owned()),
                    os_error: Some(5),
                    may_have_changed,
                    disposition,
                };
                let expected = !may_have_changed
                    || disposition == TopologyFaultDisposition::QuarantineCandidate;
                assert_eq!(value.validate().is_ok(), expected);
            }
        }
        let changed = TopologyRuntimeFault {
            operation: TopologyOperation::RepeatInventory,
            class: TopologyRuntimeFaultClass::ChangedDuringScan,
            relative_path: None,
            os_error: None,
            may_have_changed: false,
            disposition: TopologyFaultDisposition::DenyLaunch,
        };
        assert!(changed.validate().is_err());
    }
}
