//! Pure SHA-256 derivation over caller-supplied byte chunks.
//!
//! A successful observation proves only the digest of the exact chunks accepted
//! by this in-memory accumulator. Even when that observation is structurally
//! bound to revalidated supplied metadata, it does not prove file origin,
//! physical read order, handle continuity, freshness, or content stability.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    WindowsEntryPolicyKind,
    windows_supplied_entry_stability::{
        WindowsSuppliedEntryStabilityFault, WindowsSuppliedEntryStabilityInput,
        WindowsSuppliedEntryStablePair, reconcile_windows_supplied_entry_stability,
    },
};

/// Closed profile implemented by this pure supplied-byte transform.
pub const WINDOWS_SUPPLIED_CONTENT_DIGEST_PROFILE: &str =
    "cantor-windows-supplied-content-digest/0.1";
/// Maximum accepted encoded plan size before JSON decoding.
pub const WINDOWS_SUPPLIED_CONTENT_DIGEST_PLAN_MAX_BYTES: usize = 4_096;
/// Maximum caller-declared content budget accepted by this profile.
pub const WINDOWS_SUPPLIED_CONTENT_DIGEST_MAX_CONTENT_BYTES: u64 = 1_099_511_627_776;
/// Maximum caller-declared chunk budget accepted by this profile.
pub const WINDOWS_SUPPLIED_CONTENT_DIGEST_MAX_CHUNKS: u32 = 1_048_576;

/// Strict source plan for one caller-supplied streaming digest derivation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsSuppliedContentDigestPlan {
    pub profile: String,
    pub content_read_identity: u64,
    pub entry_reference_identity: u64,
    pub expected_content_length: u64,
    pub maximum_content_bytes: u64,
    pub maximum_chunks: u32,
}

/// Closed supplied-content failure vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsSuppliedContentDigestFaultCode {
    Json,
    Profile,
    ContentReadIdentity,
    EntryReferenceIdentity,
    Limit,
    Chunk,
    Length,
    Stability,
    Kind,
    EntryReference,
    MetadataLength,
    Resource,
}

/// Deterministic bounded fault released without partial success state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsSuppliedContentDigestFault {
    pub code: WindowsSuppliedContentDigestFaultCode,
    pub nested_stability_fault: Option<Box<WindowsSuppliedEntryStabilityFault>>,
    pub field: String,
    pub message: String,
}

impl WindowsSuppliedContentDigestFault {
    fn simple(code: WindowsSuppliedContentDigestFaultCode, field: &str, message: &str) -> Self {
        Self {
            code,
            nested_stability_fault: None,
            field: bounded(field, 64),
            message: bounded(message, 256),
        }
    }

    fn stability(fault: WindowsSuppliedEntryStabilityFault) -> Self {
        let message = format!("supplied-entry stability rejected: {fault}");
        Self {
            code: WindowsSuppliedContentDigestFaultCode::Stability,
            nested_stability_fault: Some(Box::new(fault)),
            field: "stability_input".to_owned(),
            message: bounded(&message, 256),
        }
    }
}

impl fmt::Display for WindowsSuppliedContentDigestFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl std::error::Error for WindowsSuppliedContentDigestFault {}

/// Private constant-size state for one validated supplied-byte derivation.
pub struct WindowsSuppliedContentDigestAccumulator {
    plan: WindowsSuppliedContentDigestPlan,
    hasher: Sha256,
    observed_length: u64,
    observed_chunks: u32,
}

impl fmt::Debug for WindowsSuppliedContentDigestAccumulator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsSuppliedContentDigestAccumulator")
            .field("plan", &self.plan)
            .field("observed_length", &self.observed_length)
            .field("observed_chunks", &self.observed_chunks)
            .finish_non_exhaustive()
    }
}

impl WindowsSuppliedContentDigestAccumulator {
    /// Returns the validated caller plan without allowing mutation.
    pub fn plan(&self) -> &WindowsSuppliedContentDigestPlan {
        &self.plan
    }

    /// Returns the number of bytes accepted so far.
    pub fn observed_length(&self) -> u64 {
        self.observed_length
    }

    /// Returns the number of nonempty chunks accepted so far.
    pub fn observed_chunks(&self) -> u32 {
        self.observed_chunks
    }

    /// Consumes this state and admits one exact nonempty caller-supplied chunk.
    ///
    /// Every counter and limit is checked before the hash state changes. A
    /// rejection returns no accumulator, so the rejected derivation cannot be
    /// resumed through this API.
    pub fn push_chunk(mut self, chunk: &[u8]) -> Result<Self, WindowsSuppliedContentDigestFault> {
        if chunk.is_empty() {
            return Err(WindowsSuppliedContentDigestFault::simple(
                WindowsSuppliedContentDigestFaultCode::Chunk,
                "chunk",
                "supplied chunk must be nonempty",
            ));
        }

        let chunk_length = u64::try_from(chunk.len()).map_err(|_| {
            WindowsSuppliedContentDigestFault::simple(
                WindowsSuppliedContentDigestFaultCode::Resource,
                "chunk_length",
                "supplied chunk length cannot be represented as u64",
            )
        })?;
        let next_chunks = self.observed_chunks.checked_add(1).ok_or_else(|| {
            WindowsSuppliedContentDigestFault::simple(
                WindowsSuppliedContentDigestFaultCode::Resource,
                "observed_chunks",
                "supplied chunk count overflowed u32",
            )
        })?;
        if next_chunks > self.plan.maximum_chunks {
            return Err(WindowsSuppliedContentDigestFault::simple(
                WindowsSuppliedContentDigestFaultCode::Limit,
                "maximum_chunks",
                "supplied chunk count exceeds the validated maximum",
            ));
        }

        let next_length = self
            .observed_length
            .checked_add(chunk_length)
            .ok_or_else(|| {
                WindowsSuppliedContentDigestFault::simple(
                    WindowsSuppliedContentDigestFaultCode::Resource,
                    "observed_length",
                    "supplied content length overflowed u64",
                )
            })?;
        if next_length > self.plan.maximum_content_bytes {
            return Err(WindowsSuppliedContentDigestFault::simple(
                WindowsSuppliedContentDigestFaultCode::Limit,
                "maximum_content_bytes",
                "supplied content exceeds the validated byte budget",
            ));
        }
        if next_length > self.plan.expected_content_length {
            return Err(WindowsSuppliedContentDigestFault::simple(
                WindowsSuppliedContentDigestFaultCode::Length,
                "expected_content_length",
                "supplied content exceeds the exact expected length",
            ));
        }

        self.hasher.update(chunk);
        self.observed_chunks = next_chunks;
        self.observed_length = next_length;
        Ok(self)
    }

    /// Consumes this state and releases one output-only successful observation.
    pub fn finish(
        self,
    ) -> Result<WindowsSuppliedContentDigestObservation, WindowsSuppliedContentDigestFault> {
        if self.observed_length != self.plan.expected_content_length {
            return Err(WindowsSuppliedContentDigestFault::simple(
                WindowsSuppliedContentDigestFaultCode::Length,
                "observed_length",
                "observed content length does not equal the exact expected length",
            ));
        }

        let digest_bytes = self.hasher.finalize();
        let mut digest = String::with_capacity(64);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in digest_bytes {
            digest.push(char::from(HEX[usize::from(byte >> 4)]));
            digest.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        Ok(WindowsSuppliedContentDigestObservation {
            profile: self.plan.profile,
            content_read_identity: self.plan.content_read_identity,
            entry_reference_identity: self.plan.entry_reference_identity,
            expected_content_length: self.plan.expected_content_length,
            observed_content_length: self.observed_length,
            maximum_content_bytes: self.plan.maximum_content_bytes,
            maximum_chunks: self.plan.maximum_chunks,
            observed_chunks: self.observed_chunks,
            derived_sha256: digest,
        })
    }
}

/// Successful evidence about exact caller-supplied bytes only.
///
/// Private fields and the absence of `Deserialize` and public constructors keep
/// successful values on the validated accumulator path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WindowsSuppliedContentDigestObservation {
    profile: String,
    content_read_identity: u64,
    entry_reference_identity: u64,
    expected_content_length: u64,
    observed_content_length: u64,
    maximum_content_bytes: u64,
    maximum_chunks: u32,
    observed_chunks: u32,
    derived_sha256: String,
}

impl WindowsSuppliedContentDigestObservation {
    pub fn profile(&self) -> &str {
        &self.profile
    }

    pub fn content_read_identity(&self) -> u64 {
        self.content_read_identity
    }

    pub fn entry_reference_identity(&self) -> u64 {
        self.entry_reference_identity
    }

    pub fn expected_content_length(&self) -> u64 {
        self.expected_content_length
    }

    pub fn observed_content_length(&self) -> u64 {
        self.observed_content_length
    }

    pub fn maximum_content_bytes(&self) -> u64 {
        self.maximum_content_bytes
    }

    pub fn maximum_chunks(&self) -> u32 {
        self.maximum_chunks
    }

    pub fn observed_chunks(&self) -> u32 {
        self.observed_chunks
    }

    pub fn derived_sha256(&self) -> &str {
        &self.derived_sha256
    }
}

/// Output-only structural association with a newly reconciled stable pair.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WindowsSuppliedContentStableBinding {
    profile: String,
    content_observation: WindowsSuppliedContentDigestObservation,
    stable_pair: WindowsSuppliedEntryStablePair,
}

impl WindowsSuppliedContentStableBinding {
    pub fn profile(&self) -> &str {
        &self.profile
    }

    pub fn content_observation(&self) -> &WindowsSuppliedContentDigestObservation {
        &self.content_observation
    }

    pub fn stable_pair(&self) -> &WindowsSuppliedEntryStablePair {
        &self.stable_pair
    }
}

/// Strictly decodes a bounded plan and constructs one private accumulator.
pub fn decode_and_begin_windows_supplied_content_digest(
    bytes: &[u8],
) -> Result<WindowsSuppliedContentDigestAccumulator, WindowsSuppliedContentDigestFault> {
    if bytes.len() > WINDOWS_SUPPLIED_CONTENT_DIGEST_PLAN_MAX_BYTES {
        return Err(WindowsSuppliedContentDigestFault::simple(
            WindowsSuppliedContentDigestFaultCode::Resource,
            "json",
            "encoded supplied-content digest plan exceeds 4096 bytes",
        ));
    }
    let plan = serde_json::from_slice(bytes).map_err(|error| {
        WindowsSuppliedContentDigestFault::simple(
            WindowsSuppliedContentDigestFaultCode::Json,
            "json",
            &error.to_string(),
        )
    })?;
    begin_windows_supplied_content_digest(plan)
}

/// Validates one plan and constructs a private zero-count accumulator.
pub fn begin_windows_supplied_content_digest(
    plan: WindowsSuppliedContentDigestPlan,
) -> Result<WindowsSuppliedContentDigestAccumulator, WindowsSuppliedContentDigestFault> {
    validate_plan(&plan)?;
    Ok(WindowsSuppliedContentDigestAccumulator {
        plan,
        hasher: Sha256::new(),
        observed_length: 0,
        observed_chunks: 0,
    })
}

/// Revalidates supplied stability input and applies exact structural join gates.
pub fn bind_windows_supplied_content_digest(
    observation: WindowsSuppliedContentDigestObservation,
    stability_input: WindowsSuppliedEntryStabilityInput,
) -> Result<WindowsSuppliedContentStableBinding, WindowsSuppliedContentDigestFault> {
    let stable_pair = reconcile_windows_supplied_entry_stability(stability_input)
        .map_err(WindowsSuppliedContentDigestFault::stability)?;

    if stable_pair.pre_read.policy_decision.kind != WindowsEntryPolicyKind::RegularFile {
        return Err(WindowsSuppliedContentDigestFault::simple(
            WindowsSuppliedContentDigestFaultCode::Kind,
            "stable_pair.kind",
            "supplied-content binding requires a stable regular file",
        ));
    }
    if observation.entry_reference_identity != stable_pair.entry_reference_identity {
        return Err(WindowsSuppliedContentDigestFault::simple(
            WindowsSuppliedContentDigestFaultCode::EntryReference,
            "entry_reference_identity",
            "content and stable-pair entry-reference identities differ",
        ));
    }
    let pre_length = stable_pair.pre_read.end_of_file;
    let post_length = stable_pair.post_read.end_of_file;
    if pre_length != observation.expected_content_length
        || post_length != observation.expected_content_length
        || pre_length != observation.observed_content_length
        || post_length != observation.observed_content_length
    {
        return Err(WindowsSuppliedContentDigestFault::simple(
            WindowsSuppliedContentDigestFaultCode::MetadataLength,
            "stable_pair.end_of_file",
            "both stable EOF values must equal expected and observed supplied-content lengths",
        ));
    }

    Ok(WindowsSuppliedContentStableBinding {
        profile: WINDOWS_SUPPLIED_CONTENT_DIGEST_PROFILE.to_owned(),
        content_observation: observation,
        stable_pair,
    })
}

fn validate_plan(
    plan: &WindowsSuppliedContentDigestPlan,
) -> Result<(), WindowsSuppliedContentDigestFault> {
    if plan.profile != WINDOWS_SUPPLIED_CONTENT_DIGEST_PROFILE {
        return Err(WindowsSuppliedContentDigestFault::simple(
            WindowsSuppliedContentDigestFaultCode::Profile,
            "profile",
            "profile is not the exact supported supplied-content digest profile",
        ));
    }
    if plan.content_read_identity == 0 {
        return Err(WindowsSuppliedContentDigestFault::simple(
            WindowsSuppliedContentDigestFaultCode::ContentReadIdentity,
            "content_read_identity",
            "content-read identity must be nonzero caller syntax",
        ));
    }
    if plan.entry_reference_identity == 0 {
        return Err(WindowsSuppliedContentDigestFault::simple(
            WindowsSuppliedContentDigestFaultCode::EntryReferenceIdentity,
            "entry_reference_identity",
            "entry-reference identity must be nonzero caller syntax",
        ));
    }
    if plan.maximum_content_bytes == 0
        || plan.maximum_content_bytes > WINDOWS_SUPPLIED_CONTENT_DIGEST_MAX_CONTENT_BYTES
    {
        return Err(WindowsSuppliedContentDigestFault::simple(
            WindowsSuppliedContentDigestFaultCode::Limit,
            "maximum_content_bytes",
            "maximum content bytes must be positive and no greater than 1099511627776",
        ));
    }
    if plan.maximum_chunks == 0 || plan.maximum_chunks > WINDOWS_SUPPLIED_CONTENT_DIGEST_MAX_CHUNKS
    {
        return Err(WindowsSuppliedContentDigestFault::simple(
            WindowsSuppliedContentDigestFaultCode::Limit,
            "maximum_chunks",
            "maximum chunks must be positive and no greater than 1048576",
        ));
    }
    if plan.expected_content_length > plan.maximum_content_bytes {
        return Err(WindowsSuppliedContentDigestFault::simple(
            WindowsSuppliedContentDigestFaultCode::Limit,
            "expected_content_length",
            "expected content length exceeds the declared maximum content bytes",
        ));
    }
    Ok(())
}

fn bounded(value: &str, maximum_scalars: usize) -> String {
    value.chars().take(maximum_scalars).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
        windows_supplied_entry_observation::{
            WINDOWS_SUPPLIED_ENTRY_OBSERVATION_PROFILE, WindowsSuppliedAttributeTagRecord,
            WindowsSuppliedCaseSensitivityRecord, WindowsSuppliedDirectoryCaseFlags,
            WindowsSuppliedFileIdentityRecord, WindowsSuppliedRecordCorrelation,
            WindowsSuppliedStandardInformationRecord, WindowsSuppliedStreamSet,
        },
        windows_supplied_entry_stability::{
            WINDOWS_SUPPLIED_ENTRY_STABILITY_PROFILE, WindowsSuppliedEntryStabilityFaultCode,
        },
    };

    fn plan(expected: u64) -> WindowsSuppliedContentDigestPlan {
        WindowsSuppliedContentDigestPlan {
            profile: WINDOWS_SUPPLIED_CONTENT_DIGEST_PROFILE.to_owned(),
            content_read_identity: 41,
            entry_reference_identity: 11,
            expected_content_length: expected,
            maximum_content_bytes: expected.max(1),
            maximum_chunks: 8,
        }
    }

    fn correlation(
        batch_identity: u64,
        entry_reference_identity: u64,
    ) -> WindowsSuppliedRecordCorrelation {
        WindowsSuppliedRecordCorrelation {
            batch_identity,
            entry_reference_identity,
        }
    }

    fn assembly_input(
        batch_identity: u64,
        entry_reference_identity: u64,
        length: u64,
        directory: bool,
    ) -> crate::WindowsSuppliedEntryAssemblyInput {
        let correlation = correlation(batch_identity, entry_reference_identity);
        crate::WindowsSuppliedEntryAssemblyInput {
            profile: WINDOWS_SUPPLIED_ENTRY_OBSERVATION_PROFILE.to_owned(),
            kind: if directory {
                WindowsEntryPolicyKind::Directory
            } else {
                WindowsEntryPolicyKind::RegularFile
            },
            component: "entry.txt".to_owned(),
            maximum_component_utf16_units: 255,
            attribute_tag: WindowsSuppliedAttributeTagRecord {
                correlation,
                attributes: if directory {
                    FILE_ATTRIBUTE_DIRECTORY
                } else {
                    FILE_ATTRIBUTE_NORMAL
                },
                reparse_tag: 0,
            },
            file_identity: WindowsSuppliedFileIdentityRecord {
                correlation,
                volume_serial: 19,
                file_id_bytes: (0_u8..16).collect(),
            },
            standard: WindowsSuppliedStandardInformationRecord {
                correlation,
                allocation_size: i64::try_from(length).unwrap(),
                end_of_file: i64::try_from(length).unwrap(),
                number_of_links: 1,
                delete_pending: false,
                directory,
            },
            case_sensitivity: if directory {
                WindowsSuppliedCaseSensitivityRecord::DirectoryFlags(
                    WindowsSuppliedDirectoryCaseFlags {
                        correlation,
                        flags: 0,
                    },
                )
            } else {
                WindowsSuppliedCaseSensitivityRecord::NotApplicable(correlation)
            },
            streams: WindowsSuppliedStreamSet::ExplicitEmpty(correlation),
        }
    }

    fn stability_input(
        entry_reference_identity: u64,
        length: u64,
        directory: bool,
    ) -> WindowsSuppliedEntryStabilityInput {
        WindowsSuppliedEntryStabilityInput {
            profile: WINDOWS_SUPPLIED_ENTRY_STABILITY_PROFILE.to_owned(),
            reconciliation_identity: 31,
            pre_read: assembly_input(7, entry_reference_identity, length, directory),
            post_read: assembly_input(8, entry_reference_identity, length, directory),
        }
    }

    fn observation(
        bytes: &[u8],
        entry_reference_identity: u64,
    ) -> WindowsSuppliedContentDigestObservation {
        let mut value = plan(u64::try_from(bytes.len()).unwrap());
        value.entry_reference_identity = entry_reference_identity;
        begin_windows_supplied_content_digest(value)
            .unwrap()
            .push_chunk(bytes)
            .unwrap()
            .finish()
            .unwrap()
    }

    #[test]
    fn strict_decode_enforces_size_shape_profile_and_identities() {
        let encoded = serde_json::to_vec(&plan(3)).unwrap();
        assert!(decode_and_begin_windows_supplied_content_digest(&encoded).is_ok());

        let text = String::from_utf8(encoded).unwrap();
        let unknown = text.replacen('{', "{\"trusted\":true,", 1);
        assert_eq!(
            decode_and_begin_windows_supplied_content_digest(unknown.as_bytes())
                .unwrap_err()
                .code,
            WindowsSuppliedContentDigestFaultCode::Json
        );
        assert_eq!(
            decode_and_begin_windows_supplied_content_digest(&vec![b' '; 4097])
                .unwrap_err()
                .code,
            WindowsSuppliedContentDigestFaultCode::Resource
        );
        assert_eq!(
            decode_and_begin_windows_supplied_content_digest(&vec![b' '; 4096])
                .unwrap_err()
                .code,
            WindowsSuppliedContentDigestFaultCode::Json
        );
        let missing = serde_json::json!({
            "profile": WINDOWS_SUPPLIED_CONTENT_DIGEST_PROFILE,
            "content_read_identity": 41,
            "entry_reference_identity": 11,
            "expected_content_length": 3,
            "maximum_content_bytes": 3
        });
        assert_eq!(
            decode_and_begin_windows_supplied_content_digest(
                &serde_json::to_vec(&missing).unwrap()
            )
            .unwrap_err()
            .code,
            WindowsSuppliedContentDigestFaultCode::Json
        );

        let mut invalid = plan(3);
        invalid.profile = "other".to_owned();
        assert_eq!(
            begin_windows_supplied_content_digest(invalid)
                .unwrap_err()
                .code,
            WindowsSuppliedContentDigestFaultCode::Profile
        );
        let mut invalid = plan(3);
        invalid.content_read_identity = 0;
        assert_eq!(
            begin_windows_supplied_content_digest(invalid)
                .unwrap_err()
                .code,
            WindowsSuppliedContentDigestFaultCode::ContentReadIdentity
        );
        let mut invalid = plan(3);
        invalid.entry_reference_identity = 0;
        assert_eq!(
            begin_windows_supplied_content_digest(invalid)
                .unwrap_err()
                .code,
            WindowsSuppliedContentDigestFaultCode::EntryReferenceIdentity
        );
    }

    #[test]
    fn plan_limits_are_exact() {
        let mut invalid = plan(3);
        invalid.maximum_content_bytes = 0;
        assert_eq!(
            begin_windows_supplied_content_digest(invalid)
                .unwrap_err()
                .field,
            "maximum_content_bytes"
        );
        let mut invalid = plan(3);
        invalid.maximum_chunks = 0;
        assert_eq!(
            begin_windows_supplied_content_digest(invalid)
                .unwrap_err()
                .field,
            "maximum_chunks"
        );
        let mut invalid = plan(3);
        invalid.maximum_content_bytes = WINDOWS_SUPPLIED_CONTENT_DIGEST_MAX_CONTENT_BYTES + 1;
        assert_eq!(
            begin_windows_supplied_content_digest(invalid)
                .unwrap_err()
                .field,
            "maximum_content_bytes"
        );
        let mut invalid = plan(3);
        invalid.maximum_chunks = WINDOWS_SUPPLIED_CONTENT_DIGEST_MAX_CHUNKS + 1;
        assert_eq!(
            begin_windows_supplied_content_digest(invalid)
                .unwrap_err()
                .field,
            "maximum_chunks"
        );
        let mut invalid = plan(3);
        invalid.maximum_content_bytes = 2;
        assert_eq!(
            begin_windows_supplied_content_digest(invalid)
                .unwrap_err()
                .field,
            "expected_content_length"
        );
    }

    #[test]
    fn empty_and_abc_vectors_are_exact() {
        let empty = begin_windows_supplied_content_digest(plan(0))
            .unwrap()
            .finish()
            .unwrap();
        assert_eq!(
            empty.derived_sha256(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(empty.observed_chunks(), 0);

        let abc = observation(b"abc", 11);
        assert_eq!(
            abc.derived_sha256(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(abc.observed_content_length(), 3);
    }

    #[test]
    fn equal_concatenations_have_equal_digest_and_exact_chunk_counts() {
        let one = observation(b"abcdefgh", 11);
        let many = begin_windows_supplied_content_digest(plan(8))
            .unwrap()
            .push_chunk(b"ab")
            .unwrap()
            .push_chunk(b"cde")
            .unwrap()
            .push_chunk(b"fgh")
            .unwrap()
            .finish()
            .unwrap();
        assert_eq!(one.derived_sha256(), many.derived_sha256());
        assert_eq!((one.observed_chunks(), many.observed_chunks()), (1, 3));

        let phrase = begin_windows_supplied_content_digest(plan(43))
            .unwrap()
            .push_chunk(b"The quick brown ")
            .unwrap()
            .push_chunk(b"fox jumps over ")
            .unwrap()
            .push_chunk(b"the lazy dog")
            .unwrap()
            .finish()
            .unwrap();
        assert_eq!(
            phrase.derived_sha256(),
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
        );
    }

    #[test]
    fn chunk_transition_rejects_empty_chunk_count_and_byte_budget() {
        assert_eq!(
            begin_windows_supplied_content_digest(plan(1))
                .unwrap()
                .push_chunk(b"")
                .unwrap_err()
                .code,
            WindowsSuppliedContentDigestFaultCode::Chunk
        );

        let mut chunk_limited = plan(2);
        chunk_limited.maximum_chunks = 1;
        assert_eq!(
            begin_windows_supplied_content_digest(chunk_limited)
                .unwrap()
                .push_chunk(b"a")
                .unwrap()
                .push_chunk(b"b")
                .unwrap_err()
                .field,
            "maximum_chunks"
        );

        let mut byte_limited = plan(3);
        byte_limited.maximum_content_bytes = 3;
        assert_eq!(
            begin_windows_supplied_content_digest(byte_limited)
                .unwrap()
                .push_chunk(b"abcd")
                .unwrap_err()
                .field,
            "maximum_content_bytes"
        );
    }

    #[test]
    fn transition_and_finalization_enforce_exact_length() {
        let mut exact_length = plan(3);
        exact_length.maximum_content_bytes = 4;
        assert_eq!(
            begin_windows_supplied_content_digest(exact_length)
                .unwrap()
                .push_chunk(b"abcd")
                .unwrap_err()
                .code,
            WindowsSuppliedContentDigestFaultCode::Length
        );
        assert_eq!(
            begin_windows_supplied_content_digest(plan(3))
                .unwrap()
                .push_chunk(b"ab")
                .unwrap()
                .finish()
                .unwrap_err()
                .code,
            WindowsSuppliedContentDigestFaultCode::Length
        );
    }

    #[test]
    fn observation_is_inspectable_and_serializable() {
        let value = observation(b"abc", 11);
        assert_eq!(value.profile(), WINDOWS_SUPPLIED_CONTENT_DIGEST_PROFILE);
        assert_eq!(value.content_read_identity(), 41);
        assert_eq!(value.entry_reference_identity(), 11);
        assert_eq!(value.expected_content_length(), 3);
        assert_eq!(value.maximum_content_bytes(), 3);
        assert_eq!(value.maximum_chunks(), 8);
        let encoded = serde_json::to_value(&value).unwrap();
        assert_eq!(encoded["derived_sha256"], value.derived_sha256());
    }

    #[test]
    fn binding_revalidates_and_preserves_complete_success_records() {
        let binding = bind_windows_supplied_content_digest(
            observation(b"abc", 11),
            stability_input(11, 3, false),
        )
        .unwrap();
        assert_eq!(binding.profile(), WINDOWS_SUPPLIED_CONTENT_DIGEST_PROFILE);
        assert_eq!(
            binding.content_observation().derived_sha256(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(binding.stable_pair().entry_reference_identity, 11);
        assert_eq!(binding.stable_pair().pre_batch_identity, 7);
        assert_eq!(binding.stable_pair().post_batch_identity, 8);
    }

    #[test]
    fn binding_preserves_exact_nested_stability_fault() {
        let mut invalid = stability_input(11, 3, false);
        invalid.profile = "invalid".to_owned();
        let fault =
            bind_windows_supplied_content_digest(observation(b"abc", 11), invalid).unwrap_err();
        assert_eq!(fault.code, WindowsSuppliedContentDigestFaultCode::Stability);
        assert_eq!(
            fault.nested_stability_fault.unwrap().code,
            WindowsSuppliedEntryStabilityFaultCode::Profile
        );
    }

    #[test]
    fn binding_rejects_directory_reference_and_metadata_length() {
        assert_eq!(
            bind_windows_supplied_content_digest(
                observation(b"abc", 11),
                stability_input(11, 3, true),
            )
            .unwrap_err()
            .code,
            WindowsSuppliedContentDigestFaultCode::Kind
        );
        assert_eq!(
            bind_windows_supplied_content_digest(
                observation(b"abc", 12),
                stability_input(11, 3, false),
            )
            .unwrap_err()
            .code,
            WindowsSuppliedContentDigestFaultCode::EntryReference
        );
        assert_eq!(
            bind_windows_supplied_content_digest(
                observation(b"abc", 11),
                stability_input(11, 4, false),
            )
            .unwrap_err()
            .code,
            WindowsSuppliedContentDigestFaultCode::MetadataLength
        );
    }

    #[test]
    fn faults_are_bounded_and_success_is_repeatable() {
        let bytes = serde_json::to_vec(&plan(3)).unwrap();
        let first = decode_and_begin_windows_supplied_content_digest(&bytes)
            .unwrap()
            .push_chunk(b"abc")
            .unwrap()
            .finish()
            .unwrap();
        let second = decode_and_begin_windows_supplied_content_digest(&bytes)
            .unwrap()
            .push_chunk(b"abc")
            .unwrap()
            .finish()
            .unwrap();
        assert_eq!(first, second);

        let fault = decode_and_begin_windows_supplied_content_digest(b"{").unwrap_err();
        assert!(fault.field.chars().count() <= 64);
        assert!(fault.message.chars().count() <= 256);
    }
}
