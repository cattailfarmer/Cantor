//! Pure canonical commitment over one completed supplied topology inventory.
//!
//! Success proves only that the retained supplied assembly was current-form
//! revalidated, encoded under the exact declared profile, and hashed in its
//! existing order. It does not prove physical origin, enumeration completeness,
//! freshness, temporal equality, receipt validity, admission, or any effect.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    TopologyEntryKind, TopologyEntryObservation, TopologyFormFault, TopologyModeClass,
    TopologyStreamFact, TopologyStreamKind, ValidateTopologyForm,
    windows_supplied_topology_inventory_assembly::{
        WINDOWS_SUPPLIED_TOPOLOGY_INVENTORY_ASSEMBLY_PROFILE,
        WindowsSuppliedTopologyInventoryAssembly,
    },
};

/// Exact pure transform profile.
pub const WINDOWS_SUPPLIED_ORDERED_TOPOLOGY_INVENTORY_DIGEST_PROFILE: &str =
    "cantor-windows-supplied-ordered-topology-inventory-digest/0.1";
/// Exact architecture-independent byte grammar profile and hash domain.
pub const ORDERED_TOPOLOGY_OBSERVATION_ENCODING_PROFILE: &str =
    "cantor-ordered-topology-observation-encoding/0.1";
/// Maximum accepted encoded plan size before JSON decoding.
pub const WINDOWS_SUPPLIED_ORDERED_TOPOLOGY_INVENTORY_DIGEST_PLAN_MAX_BYTES: usize = 4_096;

const ENTRY_START: u8 = 0x01;
const FIELD_RELATIVE_PATH: u8 = 0x10;
const FIELD_KIND: u8 = 0x11;
const FIELD_MODE_CLASS: u8 = 0x12;
const FIELD_ATTRIBUTES: u8 = 0x13;
const FIELD_VOLUME_SERIAL: u8 = 0x14;
const FIELD_FILE_ID: u8 = 0x15;
const FIELD_NUMBER_OF_LINKS: u8 = 0x16;
const FIELD_STREAMS: u8 = 0x17;
const FIELD_LENGTH: u8 = 0x18;
const FIELD_CONTENT_SHA256: u8 = 0x19;
const FIELD_OBSERVATION_ORDINAL: u8 = 0x1a;
const STREAM_START: u8 = 0x20;
const STREAM_FIELD_NAME: u8 = 0x21;
const STREAM_FIELD_SIZE: u8 = 0x22;
const STREAM_FIELD_KIND: u8 = 0x23;
const OPTION_ABSENT: u8 = 0x00;
const OPTION_PRESENT: u8 = 0x01;

/// Strict plan for one supplied ordered-inventory commitment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsSuppliedOrderedTopologyInventoryDigestPlan {
    profile: String,
    commitment_identity: u64,
    encoding_profile: String,
}

impl WindowsSuppliedOrderedTopologyInventoryDigestPlan {
    pub fn profile(&self) -> &str {
        &self.profile
    }

    pub fn commitment_identity(&self) -> u64 {
        self.commitment_identity
    }

    pub fn encoding_profile(&self) -> &str {
        &self.encoding_profile
    }
}

/// Closed supplied ordered-inventory commitment failure vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsSuppliedOrderedTopologyInventoryDigestFaultCode {
    Json,
    Profile,
    CommitmentIdentity,
    EncodingProfile,
    TopologyForm,
    Assembly,
    Count,
    Ordinal,
    Accounting,
    Hex,
    Arithmetic,
    Resource,
    Internal,
}

/// Bounded failure released without a digest result or canonical byte state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsSuppliedOrderedTopologyInventoryDigestFault {
    pub code: WindowsSuppliedOrderedTopologyInventoryDigestFaultCode,
    pub nested_topology_fault: Option<Box<TopologyFormFault>>,
    pub field: String,
    pub message: String,
}

impl WindowsSuppliedOrderedTopologyInventoryDigestFault {
    fn simple(
        code: WindowsSuppliedOrderedTopologyInventoryDigestFaultCode,
        field: &str,
        message: &str,
    ) -> Self {
        Self {
            code,
            nested_topology_fault: None,
            field: bounded(field, 64),
            message: bounded(message, 256),
        }
    }

    fn topology(field: &str, fault: TopologyFormFault) -> Self {
        let message = format!("topology form rejected: {fault}");
        Self {
            code: WindowsSuppliedOrderedTopologyInventoryDigestFaultCode::TopologyForm,
            nested_topology_fault: Some(Box::new(fault)),
            field: bounded(field, 64),
            message: bounded(&message, 256),
        }
    }
}

impl fmt::Display for WindowsSuppliedOrderedTopologyInventoryDigestFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl std::error::Error for WindowsSuppliedOrderedTopologyInventoryDigestFault {}

/// Output-only commitment retaining the complete supplied assembly lineage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WindowsSuppliedOrderedTopologyInventoryDigest {
    profile: String,
    encoding_profile: String,
    plan: WindowsSuppliedOrderedTopologyInventoryDigestPlan,
    assembly: WindowsSuppliedTopologyInventoryAssembly,
    ordered_inventory_sha256: String,
}

impl WindowsSuppliedOrderedTopologyInventoryDigest {
    pub fn profile(&self) -> &str {
        &self.profile
    }

    pub fn encoding_profile(&self) -> &str {
        &self.encoding_profile
    }

    pub fn plan(&self) -> &WindowsSuppliedOrderedTopologyInventoryDigestPlan {
        &self.plan
    }

    pub fn assembly(&self) -> &WindowsSuppliedTopologyInventoryAssembly {
        &self.assembly
    }

    pub fn ordered_inventory_sha256(&self) -> &str {
        &self.ordered_inventory_sha256
    }
}

/// Strictly decodes and validates one bounded commitment plan.
pub fn decode_windows_supplied_ordered_topology_inventory_digest_plan(
    bytes: &[u8],
) -> Result<
    WindowsSuppliedOrderedTopologyInventoryDigestPlan,
    WindowsSuppliedOrderedTopologyInventoryDigestFault,
> {
    if bytes.len() > WINDOWS_SUPPLIED_ORDERED_TOPOLOGY_INVENTORY_DIGEST_PLAN_MAX_BYTES {
        return Err(WindowsSuppliedOrderedTopologyInventoryDigestFault::simple(
            WindowsSuppliedOrderedTopologyInventoryDigestFaultCode::Resource,
            "json",
            "encoded supplied ordered topology inventory digest plan exceeds 4096 bytes",
        ));
    }
    let plan = serde_json::from_slice(bytes).map_err(|error| {
        WindowsSuppliedOrderedTopologyInventoryDigestFault::simple(
            WindowsSuppliedOrderedTopologyInventoryDigestFaultCode::Json,
            "json",
            &error.to_string(),
        )
    })?;
    validate_plan(&plan)?;
    Ok(plan)
}

/// Decodes one plan and derives one commitment from a complete supplied assembly.
pub fn decode_and_derive_windows_supplied_ordered_topology_inventory_digest(
    bytes: &[u8],
    assembly: WindowsSuppliedTopologyInventoryAssembly,
) -> Result<
    WindowsSuppliedOrderedTopologyInventoryDigest,
    WindowsSuppliedOrderedTopologyInventoryDigestFault,
> {
    let plan = decode_windows_supplied_ordered_topology_inventory_digest_plan(bytes)?;
    derive_windows_supplied_ordered_topology_inventory_digest(plan, assembly)
}

/// Revalidates, canonically encodes, and commits one complete supplied assembly.
pub fn derive_windows_supplied_ordered_topology_inventory_digest(
    plan: WindowsSuppliedOrderedTopologyInventoryDigestPlan,
    assembly: WindowsSuppliedTopologyInventoryAssembly,
) -> Result<
    WindowsSuppliedOrderedTopologyInventoryDigest,
    WindowsSuppliedOrderedTopologyInventoryDigestFault,
> {
    validate_plan(&plan)?;
    let entry_count = validate_assembly(&assembly)?;

    let mut writer = CanonicalWriter::new();
    writer.update(ORDERED_TOPOLOGY_OBSERVATION_ENCODING_PROFILE.as_bytes());
    writer.write_byte(0);
    writer.write_u64(entry_count);
    for member in assembly.ordered_members() {
        writer.write_observation(member.topology_observation())?;
    }
    let ordered_inventory_sha256 = writer.finish();

    Ok(WindowsSuppliedOrderedTopologyInventoryDigest {
        profile: WINDOWS_SUPPLIED_ORDERED_TOPOLOGY_INVENTORY_DIGEST_PROFILE.to_owned(),
        encoding_profile: ORDERED_TOPOLOGY_OBSERVATION_ENCODING_PROFILE.to_owned(),
        plan,
        assembly,
        ordered_inventory_sha256,
    })
}

fn validate_plan(
    plan: &WindowsSuppliedOrderedTopologyInventoryDigestPlan,
) -> Result<(), WindowsSuppliedOrderedTopologyInventoryDigestFault> {
    if plan.profile != WINDOWS_SUPPLIED_ORDERED_TOPOLOGY_INVENTORY_DIGEST_PROFILE {
        return Err(WindowsSuppliedOrderedTopologyInventoryDigestFault::simple(
            WindowsSuppliedOrderedTopologyInventoryDigestFaultCode::Profile,
            "profile",
            "profile is not the exact supported supplied ordered inventory digest profile",
        ));
    }
    if plan.commitment_identity == 0 {
        return Err(WindowsSuppliedOrderedTopologyInventoryDigestFault::simple(
            WindowsSuppliedOrderedTopologyInventoryDigestFaultCode::CommitmentIdentity,
            "commitment_identity",
            "commitment identity must be nonzero caller correlation syntax",
        ));
    }
    if plan.encoding_profile != ORDERED_TOPOLOGY_OBSERVATION_ENCODING_PROFILE {
        return Err(WindowsSuppliedOrderedTopologyInventoryDigestFault::simple(
            WindowsSuppliedOrderedTopologyInventoryDigestFaultCode::EncodingProfile,
            "encoding_profile",
            "encoding profile is not the exact supported canonical byte grammar",
        ));
    }
    Ok(())
}

fn validate_assembly(
    assembly: &WindowsSuppliedTopologyInventoryAssembly,
) -> Result<u64, WindowsSuppliedOrderedTopologyInventoryDigestFault> {
    if assembly.profile() != WINDOWS_SUPPLIED_TOPOLOGY_INVENTORY_ASSEMBLY_PROFILE {
        return Err(WindowsSuppliedOrderedTopologyInventoryDigestFault::simple(
            WindowsSuppliedOrderedTopologyInventoryDigestFaultCode::Assembly,
            "assembly.profile",
            "assembly profile is not the exact completed supplied inventory profile",
        ));
    }
    let entry_count = u64::try_from(assembly.ordered_members().len()).map_err(|_| {
        WindowsSuppliedOrderedTopologyInventoryDigestFault::simple(
            WindowsSuppliedOrderedTopologyInventoryDigestFaultCode::Arithmetic,
            "assembly.ordered_members",
            "ordered member count cannot be represented as u64",
        )
    })?;
    if entry_count == 0 || entry_count != assembly.entry_count() {
        return Err(WindowsSuppliedOrderedTopologyInventoryDigestFault::simple(
            WindowsSuppliedOrderedTopologyInventoryDigestFaultCode::Count,
            "assembly.entry_count",
            "ordered member count must be nonzero and equal assembly entry_count",
        ));
    }

    let mut total_file_bytes = 0_u64;
    for (position, member) in assembly.ordered_members().iter().enumerate() {
        let observation = member.topology_observation();
        observation.validate().map_err(|fault| {
            WindowsSuppliedOrderedTopologyInventoryDigestFault::topology(
                "assembly.ordered_members",
                fault,
            )
        })?;
        if position == 0 {
            if observation.kind != TopologyEntryKind::RootDirectory
                || observation.relative_path.is_some()
            {
                return Err(WindowsSuppliedOrderedTopologyInventoryDigestFault::simple(
                    WindowsSuppliedOrderedTopologyInventoryDigestFaultCode::Assembly,
                    "assembly.ordered_members[0]",
                    "first ordered observation must remain a root directory with absent path",
                ));
            }
        } else if observation.kind == TopologyEntryKind::RootDirectory
            || observation.relative_path.is_none()
        {
            return Err(WindowsSuppliedOrderedTopologyInventoryDigestFault::simple(
                WindowsSuppliedOrderedTopologyInventoryDigestFaultCode::Assembly,
                "assembly.ordered_members",
                "non-root ordered observations must remain descendants",
            ));
        }

        let expected_ordinal = u64::try_from(position)
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| {
                WindowsSuppliedOrderedTopologyInventoryDigestFault::simple(
                    WindowsSuppliedOrderedTopologyInventoryDigestFaultCode::Arithmetic,
                    "observation_ordinal",
                    "ordered position cannot form a one-based ordinal",
                )
            })?;
        if observation.observation_ordinal != expected_ordinal {
            return Err(WindowsSuppliedOrderedTopologyInventoryDigestFault::simple(
                WindowsSuppliedOrderedTopologyInventoryDigestFaultCode::Ordinal,
                "observation_ordinal",
                "observation ordinal must equal its one-based ordered position",
            ));
        }

        if observation.kind == TopologyEntryKind::RegularFile {
            let length = observation.length.ok_or_else(|| {
                WindowsSuppliedOrderedTopologyInventoryDigestFault::simple(
                    WindowsSuppliedOrderedTopologyInventoryDigestFaultCode::Accounting,
                    "length",
                    "validated regular-file observation lacks length",
                )
            })?;
            total_file_bytes = total_file_bytes.checked_add(length).ok_or_else(|| {
                WindowsSuppliedOrderedTopologyInventoryDigestFault::simple(
                    WindowsSuppliedOrderedTopologyInventoryDigestFaultCode::Arithmetic,
                    "assembly.total_file_bytes",
                    "regular-file byte total overflowed u64",
                )
            })?;
        }
    }
    if total_file_bytes != assembly.total_file_bytes() {
        return Err(WindowsSuppliedOrderedTopologyInventoryDigestFault::simple(
            WindowsSuppliedOrderedTopologyInventoryDigestFaultCode::Accounting,
            "assembly.total_file_bytes",
            "recomputed regular-file byte total differs from assembly total_file_bytes",
        ));
    }
    Ok(entry_count)
}

struct CanonicalWriter {
    hasher: Sha256,
}

impl CanonicalWriter {
    fn new() -> Self {
        Self {
            hasher: Sha256::new(),
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        self.hasher.update(bytes);
    }

    fn write_byte(&mut self, value: u8) {
        self.update(&[value]);
    }

    fn write_u32(&mut self, value: u32) {
        self.update(&value.to_be_bytes());
    }

    fn write_u64(&mut self, value: u64) {
        self.update(&value.to_be_bytes());
    }

    fn write_text(
        &mut self,
        value: &str,
    ) -> Result<(), WindowsSuppliedOrderedTopologyInventoryDigestFault> {
        let length = u64::try_from(value.len()).map_err(|_| {
            WindowsSuppliedOrderedTopologyInventoryDigestFault::simple(
                WindowsSuppliedOrderedTopologyInventoryDigestFaultCode::Resource,
                "text",
                "UTF-8 text length cannot be represented as u64",
            )
        })?;
        self.write_u64(length);
        self.update(value.as_bytes());
        Ok(())
    }

    fn write_optional_text(
        &mut self,
        value: Option<&str>,
    ) -> Result<(), WindowsSuppliedOrderedTopologyInventoryDigestFault> {
        match value {
            None => self.write_byte(OPTION_ABSENT),
            Some(value) => {
                self.write_byte(OPTION_PRESENT);
                self.write_text(value)?;
            }
        }
        Ok(())
    }

    fn write_optional_u64(&mut self, value: Option<u64>) {
        match value {
            None => self.write_byte(OPTION_ABSENT),
            Some(value) => {
                self.write_byte(OPTION_PRESENT);
                self.write_u64(value);
            }
        }
    }

    fn write_optional_digest(
        &mut self,
        value: Option<&str>,
    ) -> Result<(), WindowsSuppliedOrderedTopologyInventoryDigestFault> {
        match value {
            None => self.write_byte(OPTION_ABSENT),
            Some(value) => {
                self.write_byte(OPTION_PRESENT);
                self.update(&decode_lower_hex::<32>(value, "content_sha256")?);
            }
        }
        Ok(())
    }

    fn write_stream(
        &mut self,
        stream: &TopologyStreamFact,
    ) -> Result<(), WindowsSuppliedOrderedTopologyInventoryDigestFault> {
        self.write_byte(STREAM_START);
        self.write_byte(STREAM_FIELD_NAME);
        self.write_text(&stream.name)?;
        self.write_byte(STREAM_FIELD_SIZE);
        self.write_u64(stream.size);
        self.write_byte(STREAM_FIELD_KIND);
        self.write_byte(stream_kind_tag(stream.kind));
        Ok(())
    }

    fn write_observation(
        &mut self,
        observation: &TopologyEntryObservation,
    ) -> Result<(), WindowsSuppliedOrderedTopologyInventoryDigestFault> {
        self.write_byte(ENTRY_START);
        self.write_byte(FIELD_RELATIVE_PATH);
        self.write_optional_text(observation.relative_path.as_deref())?;
        self.write_byte(FIELD_KIND);
        self.write_byte(entry_kind_tag(observation.kind));
        self.write_byte(FIELD_MODE_CLASS);
        self.write_byte(mode_class_tag(observation.mode_class));
        self.write_byte(FIELD_ATTRIBUTES);
        self.write_u32(observation.attributes);
        self.write_byte(FIELD_VOLUME_SERIAL);
        self.write_u64(observation.identity.volume_serial);
        self.write_byte(FIELD_FILE_ID);
        self.update(&decode_lower_hex::<16>(
            &observation.identity.file_id_hex,
            "identity.file_id_hex",
        )?);
        self.write_byte(FIELD_NUMBER_OF_LINKS);
        self.write_u32(observation.number_of_links);
        self.write_byte(FIELD_STREAMS);
        let stream_count = u64::try_from(observation.streams.len()).map_err(|_| {
            WindowsSuppliedOrderedTopologyInventoryDigestFault::simple(
                WindowsSuppliedOrderedTopologyInventoryDigestFaultCode::Resource,
                "streams",
                "stream count cannot be represented as u64",
            )
        })?;
        self.write_u64(stream_count);
        for stream in &observation.streams {
            self.write_stream(stream)?;
        }
        self.write_byte(FIELD_LENGTH);
        self.write_optional_u64(observation.length);
        self.write_byte(FIELD_CONTENT_SHA256);
        self.write_optional_digest(observation.content_sha256.as_deref())?;
        self.write_byte(FIELD_OBSERVATION_ORDINAL);
        self.write_u64(observation.observation_ordinal);
        Ok(())
    }

    fn finish(self) -> String {
        lower_hex(&self.hasher.finalize())
    }
}

fn entry_kind_tag(kind: TopologyEntryKind) -> u8 {
    match kind {
        TopologyEntryKind::RootDirectory => 0x01,
        TopologyEntryKind::Directory => 0x02,
        TopologyEntryKind::RegularFile => 0x03,
    }
}

fn mode_class_tag(mode: TopologyModeClass) -> u8 {
    match mode {
        TopologyModeClass::Directory => 0x01,
        TopologyModeClass::RegularNonExecutable => 0x02,
        TopologyModeClass::RegularExecutable => 0x03,
    }
}

fn stream_kind_tag(kind: TopologyStreamKind) -> u8 {
    match kind {
        TopologyStreamKind::UnnamedDefault => 0x01,
        TopologyStreamKind::NamedData => 0x02,
    }
}

fn decode_lower_hex<const N: usize>(
    value: &str,
    field: &str,
) -> Result<[u8; N], WindowsSuppliedOrderedTopologyInventoryDigestFault> {
    if value.len() != N * 2 {
        return Err(hex_fault(field, "hex value has the wrong fixed width"));
    }
    let mut decoded = [0_u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = lower_hex_nibble(pair[0])
            .ok_or_else(|| hex_fault(field, "hex value must use lowercase hexadecimal"))?;
        let low = lower_hex_nibble(pair[1])
            .ok_or_else(|| hex_fault(field, "hex value must use lowercase hexadecimal"))?;
        decoded[index] = (high << 4) | low;
    }
    Ok(decoded)
}

fn lower_hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(char::from(HEX[usize::from(byte >> 4)]));
        value.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    value
}

fn hex_fault(field: &str, message: &str) -> WindowsSuppliedOrderedTopologyInventoryDigestFault {
    WindowsSuppliedOrderedTopologyInventoryDigestFault::simple(
        WindowsSuppliedOrderedTopologyInventoryDigestFaultCode::Hex,
        field,
        message,
    )
}

fn bounded(value: &str, maximum_scalars: usize) -> String {
    value.chars().take(maximum_scalars).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, PlatformPreflightDisposition,
        StrongFileIdentity, TopologyScanLimits, WINDOWS_PLATFORM_PREFLIGHT_PROFILE,
        WINDOWS_PLATFORM_PREFLIGHT_TARGET, WindowsEntryPolicyKind, WindowsPlatformPreflightRecord,
        WindowsVolumeInformation,
        windows_supplied_content_digest::{
            WINDOWS_SUPPLIED_CONTENT_DIGEST_PROFILE, WindowsSuppliedContentDigestPlan,
            begin_windows_supplied_content_digest, bind_windows_supplied_content_digest,
        },
        windows_supplied_directory_topology_projection::{
            WINDOWS_SUPPLIED_DIRECTORY_TOPOLOGY_PROJECTION_PROFILE,
            WindowsSuppliedDirectoryTopologyProjectionPlan,
            project_windows_supplied_directory_topology,
        },
        windows_supplied_entry_observation::{
            WINDOWS_SUPPLIED_ENTRY_OBSERVATION_PROFILE, WindowsSuppliedAttributeTagRecord,
            WindowsSuppliedCaseSensitivityRecord, WindowsSuppliedDirectoryCaseFlags,
            WindowsSuppliedEntryAssemblyInput, WindowsSuppliedFileIdentityRecord,
            WindowsSuppliedRecordCorrelation, WindowsSuppliedStandardInformationRecord,
            WindowsSuppliedStreamSet,
        },
        windows_supplied_entry_stability::{
            WINDOWS_SUPPLIED_ENTRY_STABILITY_PROFILE, WindowsSuppliedEntryStabilityInput,
        },
        windows_supplied_regular_file_topology_projection::{
            WINDOWS_SUPPLIED_REGULAR_FILE_TOPOLOGY_PROJECTION_PROFILE,
            WindowsSuppliedRegularFileTopologyProjectionPlan,
            project_windows_supplied_regular_file_topology,
        },
        windows_supplied_root_topology_projection::{
            WINDOWS_SUPPLIED_ROOT_TOPOLOGY_PROJECTION_PROFILE,
            WindowsSuppliedRootTopologyProjectionPlan, project_windows_supplied_root_topology,
        },
        windows_supplied_topology_inventory_assembly::{
            WindowsSuppliedTopologyInventoryAssemblyPlan,
            assemble_windows_supplied_topology_inventory,
        },
    };

    const GUID_ROOT: &str = r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\";
    const ROOT_ONLY_SHA256: &str =
        "89bd2d81e81799a838f9f4028076f14f1b3c3c9ca75fe78ebcbccd9015508f6a";
    const MIXED_SHA256: &str = "fa6e4153f4ec5e25d6aebae3323698ef917c4ae0a12205e926ef2a14823e92bd";

    fn digest_plan(commitment_identity: u64) -> WindowsSuppliedOrderedTopologyInventoryDigestPlan {
        WindowsSuppliedOrderedTopologyInventoryDigestPlan {
            profile: WINDOWS_SUPPLIED_ORDERED_TOPOLOGY_INVENTORY_DIGEST_PROFILE.to_owned(),
            commitment_identity,
            encoding_profile: ORDERED_TOPOLOGY_OBSERVATION_ENCODING_PROFILE.to_owned(),
        }
    }

    fn limits() -> TopologyScanLimits {
        TopologyScanLimits {
            maximum_entries: 64,
            maximum_depth: 16,
            maximum_path_bytes: 1_024,
            maximum_file_bytes: 1_024,
            maximum_total_bytes: 4_096,
            maximum_streams_per_entry: 16,
            deadline_tick: 1,
        }
    }

    fn assembly_plan(assembly_identity: u64) -> WindowsSuppliedTopologyInventoryAssemblyPlan {
        WindowsSuppliedTopologyInventoryAssemblyPlan {
            profile: WINDOWS_SUPPLIED_TOPOLOGY_INVENTORY_ASSEMBLY_PROFILE.to_owned(),
            assembly_identity,
            limits: limits(),
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

    fn identity(volume_serial: u64, seed: u8) -> StrongFileIdentity {
        StrongFileIdentity {
            volume_serial,
            file_id_hex: (seed..seed + 16)
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        }
    }

    fn assembly_input(
        batch_identity: u64,
        entry_reference_identity: u64,
        component: &str,
        kind: WindowsEntryPolicyKind,
        volume_serial: u64,
        seed: u8,
        length: u64,
    ) -> WindowsSuppliedEntryAssemblyInput {
        let correlation = correlation(batch_identity, entry_reference_identity);
        let directory = kind == WindowsEntryPolicyKind::Directory;
        WindowsSuppliedEntryAssemblyInput {
            profile: WINDOWS_SUPPLIED_ENTRY_OBSERVATION_PROFILE.to_owned(),
            kind,
            component: component.to_owned(),
            maximum_component_utf16_units: 32_767,
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
                volume_serial,
                file_id_bytes: (seed..seed + 16).collect(),
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
        component: &str,
        kind: WindowsEntryPolicyKind,
        volume_serial: u64,
        seed: u8,
        length: u64,
    ) -> WindowsSuppliedEntryStabilityInput {
        WindowsSuppliedEntryStabilityInput {
            profile: WINDOWS_SUPPLIED_ENTRY_STABILITY_PROFILE.to_owned(),
            reconciliation_identity: entry_reference_identity + 1_000,
            pre_read: assembly_input(
                entry_reference_identity + 100,
                entry_reference_identity,
                component,
                kind,
                volume_serial,
                seed,
                length,
            ),
            post_read: assembly_input(
                entry_reference_identity + 200,
                entry_reference_identity,
                component,
                kind,
                volume_serial,
                seed,
                length,
            ),
        }
    }

    fn root(
        projection_identity: u64,
        entry_reference_identity: u64,
        volume_serial: u64,
        seed: u8,
    ) -> crate::windows_supplied_root_topology_projection::WindowsSuppliedRootTopologyProjection
    {
        let preflight = WindowsPlatformPreflightRecord::CompleteLocal {
            profile: WINDOWS_PLATFORM_PREFLIGHT_PROFILE.to_owned(),
            target_triple: WINDOWS_PLATFORM_PREFLIGHT_TARGET.to_owned(),
            input_root: r"\\?\C:\Cantor".to_owned(),
            root_identity: identity(volume_serial, seed),
            root_volume_guid_path: format!("{GUID_ROOT}Cantor"),
            volume: WindowsVolumeInformation {
                volume_name: "Work".to_owned(),
                volume_serial_number: 42,
                maximum_component_length: 255,
                file_system_flags: 0,
                file_system_name: "NTFS".to_owned(),
            },
            disposition: PlatformPreflightDisposition::EligibleLocalNtfs,
        };
        project_windows_supplied_root_topology(
            WindowsSuppliedRootTopologyProjectionPlan {
                profile: WINDOWS_SUPPLIED_ROOT_TOPOLOGY_PROJECTION_PROFILE.to_owned(),
                projection_identity,
                entry_reference_identity,
            },
            preflight,
            stability_input(
                entry_reference_identity,
                "Cantor",
                WindowsEntryPolicyKind::Directory,
                volume_serial,
                seed,
                0,
            ),
        )
        .unwrap()
    }

    fn directory(
        path: &str,
        ordinal: u64,
        projection_identity: u64,
        entry_reference_identity: u64,
        volume_serial: u64,
        seed: u8,
    ) -> crate::windows_supplied_directory_topology_projection::WindowsSuppliedDirectoryTopologyProjection
    {
        let component = path.rsplit('/').next().unwrap();
        project_windows_supplied_directory_topology(
            WindowsSuppliedDirectoryTopologyProjectionPlan {
                profile: WINDOWS_SUPPLIED_DIRECTORY_TOPOLOGY_PROJECTION_PROFILE.to_owned(),
                projection_identity,
                entry_reference_identity,
                relative_path: path.to_owned(),
                observation_ordinal: ordinal,
            },
            stability_input(
                entry_reference_identity,
                component,
                WindowsEntryPolicyKind::Directory,
                volume_serial,
                seed,
                0,
            ),
        )
        .unwrap()
    }

    fn regular_file(
        path: &str,
        ordinal: u64,
        projection_identity: u64,
        entry_reference_identity: u64,
        volume_serial: u64,
        seed: u8,
        bytes: &[u8],
    ) -> crate::windows_supplied_regular_file_topology_projection::WindowsSuppliedRegularFileTopologyProjection
    {
        let component = path.rsplit('/').next().unwrap();
        let digest_plan = WindowsSuppliedContentDigestPlan {
            profile: WINDOWS_SUPPLIED_CONTENT_DIGEST_PROFILE.to_owned(),
            content_read_identity: entry_reference_identity + 2_000,
            entry_reference_identity,
            expected_content_length: u64::try_from(bytes.len()).unwrap(),
            maximum_content_bytes: u64::try_from(bytes.len()).unwrap().max(1),
            maximum_chunks: 8,
        };
        let accumulator = begin_windows_supplied_content_digest(digest_plan).unwrap();
        let digest = if bytes.is_empty() {
            accumulator.finish().unwrap()
        } else {
            accumulator.push_chunk(bytes).unwrap().finish().unwrap()
        };
        let binding = bind_windows_supplied_content_digest(
            digest,
            stability_input(
                entry_reference_identity,
                component,
                WindowsEntryPolicyKind::RegularFile,
                volume_serial,
                seed,
                u64::try_from(bytes.len()).unwrap(),
            ),
        )
        .unwrap();
        project_windows_supplied_regular_file_topology(
            WindowsSuppliedRegularFileTopologyProjectionPlan {
                profile: WINDOWS_SUPPLIED_REGULAR_FILE_TOPOLOGY_PROJECTION_PROFILE.to_owned(),
                projection_identity,
                entry_reference_identity,
                relative_path: path.to_owned(),
                mode_class: TopologyModeClass::RegularNonExecutable,
                observation_ordinal: ordinal,
            },
            binding,
        )
        .unwrap()
    }

    fn root_only_assembly(
        assembly_identity: u64,
        projection_identity: u64,
        entry_reference_identity: u64,
    ) -> WindowsSuppliedTopologyInventoryAssembly {
        assemble_windows_supplied_topology_inventory(
            assembly_plan(assembly_identity),
            root(projection_identity, entry_reference_identity, 19, 0),
            vec![],
            vec![],
        )
        .unwrap()
    }

    fn mixed_assembly() -> WindowsSuppliedTopologyInventoryAssembly {
        assemble_windows_supplied_topology_inventory(
            assembly_plan(91),
            root(1, 11, 19, 0),
            vec![directory("src", 2, 2, 12, 19, 16)],
            vec![regular_file("src/a.txt", 3, 3, 13, 19, 32, b"abc")],
        )
        .unwrap()
    }

    fn reference_push_u32(bytes: &mut Vec<u8>, value: u32) {
        bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn reference_push_u64(bytes: &mut Vec<u8>, value: u64) {
        bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn reference_push_text(bytes: &mut Vec<u8>, value: &str) {
        reference_push_u64(bytes, u64::try_from(value.len()).unwrap());
        bytes.extend_from_slice(value.as_bytes());
    }

    fn reference_decode_hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let text = std::str::from_utf8(pair).unwrap();
                u8::from_str_radix(text, 16).unwrap()
            })
            .collect()
    }

    fn reference_observation(bytes: &mut Vec<u8>, observation: &TopologyEntryObservation) {
        bytes.push(0x01);
        bytes.push(0x10);
        match &observation.relative_path {
            None => bytes.push(0x00),
            Some(path) => {
                bytes.push(0x01);
                reference_push_text(bytes, path);
            }
        }
        bytes.extend_from_slice(&[0x11, entry_kind_tag(observation.kind)]);
        bytes.extend_from_slice(&[0x12, mode_class_tag(observation.mode_class)]);
        bytes.push(0x13);
        reference_push_u32(bytes, observation.attributes);
        bytes.push(0x14);
        reference_push_u64(bytes, observation.identity.volume_serial);
        bytes.push(0x15);
        bytes.extend(reference_decode_hex(&observation.identity.file_id_hex));
        bytes.push(0x16);
        reference_push_u32(bytes, observation.number_of_links);
        bytes.push(0x17);
        reference_push_u64(bytes, u64::try_from(observation.streams.len()).unwrap());
        for stream in &observation.streams {
            bytes.extend_from_slice(&[0x20, 0x21]);
            reference_push_text(bytes, &stream.name);
            bytes.push(0x22);
            reference_push_u64(bytes, stream.size);
            bytes.extend_from_slice(&[0x23, stream_kind_tag(stream.kind)]);
        }
        bytes.push(0x18);
        match observation.length {
            None => bytes.push(0x00),
            Some(length) => {
                bytes.push(0x01);
                reference_push_u64(bytes, length);
            }
        }
        bytes.push(0x19);
        match &observation.content_sha256 {
            None => bytes.push(0x00),
            Some(digest) => {
                bytes.push(0x01);
                bytes.extend(reference_decode_hex(digest));
            }
        }
        bytes.push(0x1a);
        reference_push_u64(bytes, observation.observation_ordinal);
    }

    fn reference_bytes(assembly: &WindowsSuppliedTopologyInventoryAssembly) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(ORDERED_TOPOLOGY_OBSERVATION_ENCODING_PROFILE.as_bytes());
        bytes.push(0);
        reference_push_u64(&mut bytes, assembly.entry_count());
        for member in assembly.ordered_members() {
            reference_observation(&mut bytes, member.topology_observation());
        }
        bytes
    }

    fn digest_observation(observation: &TopologyEntryObservation) -> String {
        let mut writer = CanonicalWriter::new();
        writer.update(ORDERED_TOPOLOGY_OBSERVATION_ENCODING_PROFILE.as_bytes());
        writer.write_byte(0);
        writer.write_u64(1);
        writer.write_observation(observation).unwrap();
        writer.finish()
    }

    fn regular_observation() -> TopologyEntryObservation {
        TopologyEntryObservation {
            relative_path: Some("a.txt".to_owned()),
            kind: TopologyEntryKind::RegularFile,
            mode_class: TopologyModeClass::RegularNonExecutable,
            attributes: FILE_ATTRIBUTE_NORMAL,
            identity: identity(19, 32),
            number_of_links: 1,
            streams: vec![TopologyStreamFact {
                name: "::$DATA".to_owned(),
                size: 3,
                kind: TopologyStreamKind::UnnamedDefault,
            }],
            length: Some(3),
            content_sha256: Some(
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".to_owned(),
            ),
            observation_ordinal: 2,
        }
    }

    #[test]
    fn strict_plan_decode_profiles_identity_and_resource_bound_are_exact() {
        let encoded = serde_json::to_vec(&digest_plan(7)).unwrap();
        let decoded =
            decode_windows_supplied_ordered_topology_inventory_digest_plan(&encoded).unwrap();
        assert_eq!(
            decoded.profile(),
            WINDOWS_SUPPLIED_ORDERED_TOPOLOGY_INVENTORY_DIGEST_PROFILE
        );
        assert_eq!(decoded.commitment_identity(), 7);
        assert_eq!(
            decoded.encoding_profile(),
            ORDERED_TOPOLOGY_OBSERVATION_ENCODING_PROFILE
        );

        let text = String::from_utf8(encoded).unwrap();
        let unknown = text.replacen('{', "{\"trusted\":true,", 1);
        assert_eq!(
            decode_windows_supplied_ordered_topology_inventory_digest_plan(unknown.as_bytes())
                .unwrap_err()
                .code,
            WindowsSuppliedOrderedTopologyInventoryDigestFaultCode::Json
        );
        assert_eq!(
            decode_windows_supplied_ordered_topology_inventory_digest_plan(&vec![
                b' ';
                WINDOWS_SUPPLIED_ORDERED_TOPOLOGY_INVENTORY_DIGEST_PLAN_MAX_BYTES
                    + 1
            ])
            .unwrap_err()
            .code,
            WindowsSuppliedOrderedTopologyInventoryDigestFaultCode::Resource
        );

        let mut invalid = digest_plan(0);
        assert_eq!(
            validate_plan(&invalid).unwrap_err().code,
            WindowsSuppliedOrderedTopologyInventoryDigestFaultCode::CommitmentIdentity
        );
        invalid.commitment_identity = 1;
        invalid.encoding_profile = "other".to_owned();
        assert_eq!(
            validate_plan(&invalid).unwrap_err().code,
            WindowsSuppliedOrderedTopologyInventoryDigestFaultCode::EncodingProfile
        );
        invalid.encoding_profile = ORDERED_TOPOLOGY_OBSERVATION_ENCODING_PROFILE.to_owned();
        invalid.profile = "other".to_owned();
        assert_eq!(
            validate_plan(&invalid).unwrap_err().code,
            WindowsSuppliedOrderedTopologyInventoryDigestFaultCode::Profile
        );
    }

    #[test]
    fn root_only_known_vector_retains_exact_plan_and_assembly() {
        let assembly = root_only_assembly(91, 1, 11);
        let expected_assembly = assembly.clone();
        let result =
            derive_windows_supplied_ordered_topology_inventory_digest(digest_plan(7), assembly)
                .unwrap();
        assert_eq!(result.ordered_inventory_sha256(), ROOT_ONLY_SHA256);
        assert_eq!(result.assembly(), &expected_assembly);
        assert_eq!(result.plan().commitment_identity(), 7);
        assert_eq!(
            result.profile(),
            WINDOWS_SUPPLIED_ORDERED_TOPOLOGY_INVENTORY_DIGEST_PROFILE
        );
        assert_eq!(
            result.encoding_profile(),
            ORDERED_TOPOLOGY_OBSERVATION_ENCODING_PROFILE
        );
    }

    #[test]
    fn mixed_known_vector_matches_independent_reference_bytes() {
        let assembly = mixed_assembly();
        let reference = reference_bytes(&assembly);
        let expected = lower_hex(&Sha256::digest(&reference));
        let result =
            derive_windows_supplied_ordered_topology_inventory_digest(digest_plan(8), assembly)
                .unwrap();
        assert_eq!(expected, MIXED_SHA256);
        assert_eq!(result.ordered_inventory_sha256(), MIXED_SHA256);
    }

    #[test]
    fn every_observation_and_stream_field_class_changes_the_subject() {
        let base = regular_observation();
        base.validate().unwrap();
        let baseline = digest_observation(&base);
        let mut variants = Vec::new();

        let mut value = base.clone();
        value.relative_path = Some("b.txt".to_owned());
        variants.push(value);
        let mut value = base.clone();
        value.kind = TopologyEntryKind::Directory;
        value.mode_class = TopologyModeClass::Directory;
        value.length = None;
        value.content_sha256 = None;
        value.streams.clear();
        variants.push(value);
        let mut value = base.clone();
        value.mode_class = TopologyModeClass::RegularExecutable;
        variants.push(value);
        let mut value = base.clone();
        value.attributes += 1;
        variants.push(value);
        let mut value = base.clone();
        value.identity.volume_serial += 1;
        variants.push(value);
        let mut value = base.clone();
        value.identity.file_id_hex = "ff".repeat(16);
        variants.push(value);
        let mut value = base.clone();
        value.number_of_links += 1;
        variants.push(value);
        let mut value = base.clone();
        value.streams.clear();
        variants.push(value);
        let mut value = base.clone();
        value.streams[0].name = ":meta:$DATA".to_owned();
        value.streams[0].kind = TopologyStreamKind::NamedData;
        variants.push(value);
        let mut value = base.clone();
        value.streams[0].size += 1;
        variants.push(value);
        let mut value = base.clone();
        value.length = Some(4);
        variants.push(value);
        let mut value = base.clone();
        value.content_sha256 = Some("00".repeat(32));
        variants.push(value);
        let mut value = base.clone();
        value.observation_ordinal += 1;
        variants.push(value);

        for (index, variant) in variants.iter().enumerate() {
            variant.validate().unwrap();
            assert_ne!(digest_observation(variant), baseline, "variant {index}");
        }
    }

    #[test]
    fn plan_and_carrier_only_lineage_are_excluded_while_results_retain_them() {
        let assembly_a = root_only_assembly(91, 1, 11);
        let assembly_b = root_only_assembly(92, 2, 12);
        assert_eq!(
            assembly_a.ordered_members()[0].topology_observation(),
            assembly_b.ordered_members()[0].topology_observation()
        );
        assert_ne!(assembly_a, assembly_b);

        let result_a =
            derive_windows_supplied_ordered_topology_inventory_digest(digest_plan(7), assembly_a)
                .unwrap();
        let result_b =
            derive_windows_supplied_ordered_topology_inventory_digest(digest_plan(8), assembly_b)
                .unwrap();
        assert_eq!(
            result_a.ordered_inventory_sha256(),
            result_b.ordered_inventory_sha256()
        );
        assert_ne!(result_a.plan(), result_b.plan());
        assert_ne!(result_a.assembly(), result_b.assembly());
    }

    #[test]
    fn member_order_and_entry_count_are_committed() {
        let assembly = mixed_assembly();
        let baseline = reference_bytes(&assembly);
        let mut different_count = baseline.clone();
        let count_start = ORDERED_TOPOLOGY_OBSERVATION_ENCODING_PROFILE.len() + 1;
        different_count[count_start + 7] ^= 1;
        assert_ne!(Sha256::digest(&baseline), Sha256::digest(&different_count));

        let observations: Vec<_> = assembly
            .ordered_members()
            .iter()
            .map(|member| member.topology_observation())
            .collect();
        let mut forward = CanonicalWriter::new();
        let mut reversed = CanonicalWriter::new();
        for writer in [&mut forward, &mut reversed] {
            writer.update(ORDERED_TOPOLOGY_OBSERVATION_ENCODING_PROFILE.as_bytes());
            writer.write_byte(0);
            writer.write_u64(assembly.entry_count());
        }
        for observation in &observations {
            forward.write_observation(observation).unwrap();
        }
        for observation in observations.iter().rev() {
            reversed.write_observation(observation).unwrap();
        }
        assert_ne!(forward.finish(), reversed.finish());
    }

    #[test]
    fn fixed_width_hex_decoder_rejects_width_case_and_alphabet_drift() {
        assert_eq!(
            decode_lower_hex::<16>("00", "identity.file_id_hex")
                .unwrap_err()
                .code,
            WindowsSuppliedOrderedTopologyInventoryDigestFaultCode::Hex
        );
        assert_eq!(
            decode_lower_hex::<16>(&"AA".repeat(16), "identity.file_id_hex")
                .unwrap_err()
                .code,
            WindowsSuppliedOrderedTopologyInventoryDigestFaultCode::Hex
        );
        assert_eq!(
            decode_lower_hex::<32>(&"gg".repeat(32), "content_sha256")
                .unwrap_err()
                .code,
            WindowsSuppliedOrderedTopologyInventoryDigestFaultCode::Hex
        );
    }

    #[test]
    fn closed_tag_namespaces_match_the_signed_table() {
        assert_eq!(
            [
                FIELD_RELATIVE_PATH,
                FIELD_KIND,
                FIELD_MODE_CLASS,
                FIELD_ATTRIBUTES,
                FIELD_VOLUME_SERIAL,
                FIELD_FILE_ID,
                FIELD_NUMBER_OF_LINKS,
                FIELD_STREAMS,
                FIELD_LENGTH,
                FIELD_CONTENT_SHA256,
                FIELD_OBSERVATION_ORDINAL,
            ],
            [
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a
            ]
        );
        assert_eq!(
            [
                STREAM_START,
                STREAM_FIELD_NAME,
                STREAM_FIELD_SIZE,
                STREAM_FIELD_KIND
            ],
            [0x20, 0x21, 0x22, 0x23]
        );
        assert_eq!(
            [
                entry_kind_tag(TopologyEntryKind::RootDirectory),
                entry_kind_tag(TopologyEntryKind::Directory),
                entry_kind_tag(TopologyEntryKind::RegularFile),
            ],
            [0x01, 0x02, 0x03]
        );
        assert_eq!(
            [
                mode_class_tag(TopologyModeClass::Directory),
                mode_class_tag(TopologyModeClass::RegularNonExecutable),
                mode_class_tag(TopologyModeClass::RegularExecutable),
            ],
            [0x01, 0x02, 0x03]
        );
        assert_eq!(
            [
                stream_kind_tag(TopologyStreamKind::UnnamedDefault),
                stream_kind_tag(TopologyStreamKind::NamedData),
            ],
            [0x01, 0x02]
        );
    }

    #[test]
    fn faults_are_bounded_and_topology_nesting_is_role_specific() {
        let fault = WindowsSuppliedOrderedTopologyInventoryDigestFault::simple(
            WindowsSuppliedOrderedTopologyInventoryDigestFaultCode::Internal,
            &"f".repeat(100),
            &"m".repeat(400),
        );
        assert_eq!(fault.field.chars().count(), 64);
        assert_eq!(fault.message.chars().count(), 256);
        assert!(fault.nested_topology_fault.is_none());

        let topology_fault = TopologyEntryObservation {
            relative_path: None,
            ..regular_observation()
        }
        .validate()
        .unwrap_err();
        let nested = WindowsSuppliedOrderedTopologyInventoryDigestFault::topology(
            "assembly.ordered_members",
            topology_fault.clone(),
        );
        assert_eq!(
            nested.code,
            WindowsSuppliedOrderedTopologyInventoryDigestFaultCode::TopologyForm
        );
        assert_eq!(
            nested.nested_topology_fault.as_deref(),
            Some(&topology_fault)
        );
    }

    #[test]
    fn digest_representation_is_exact_lowercase_sha256() {
        let result = derive_windows_supplied_ordered_topology_inventory_digest(
            digest_plan(9),
            root_only_assembly(91, 1, 11),
        )
        .unwrap();
        assert_eq!(result.ordered_inventory_sha256().len(), 64);
        assert!(
            result
                .ordered_inventory_sha256()
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
    }
}
