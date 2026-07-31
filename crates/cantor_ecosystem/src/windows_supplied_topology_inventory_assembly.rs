//! Pure assembly of complete supplied topology projection carriers.
//!
//! Successful output proves only current M2A form validity and exact structural
//! relations within the supplied member set. It does not prove runtime origin,
//! physical membership, enumeration, inventory completeness, traversal, Git
//! truth, canonical encoding, aggregate digest, double inventory, receipt,
//! admission, mutation safety, or promotion authority.

use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{Deserialize, Serialize};

use crate::{
    StrongFileIdentity, TopologyEntryKind, TopologyEntryObservation, TopologyFormFault,
    TopologyScanLimits, ValidateTopologyForm,
    windows_supplied_directory_topology_projection::WindowsSuppliedDirectoryTopologyProjection,
    windows_supplied_regular_file_topology_projection::WindowsSuppliedRegularFileTopologyProjection,
    windows_supplied_root_topology_projection::WindowsSuppliedRootTopologyProjection,
};

pub const WINDOWS_SUPPLIED_TOPOLOGY_INVENTORY_ASSEMBLY_PROFILE: &str =
    "cantor-windows-supplied-topology-inventory-assembly/0.1";
pub const WINDOWS_SUPPLIED_TOPOLOGY_INVENTORY_ASSEMBLY_PLAN_MAX_BYTES: usize = 16_384;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsSuppliedTopologyInventoryAssemblyPlan {
    pub profile: String,
    pub assembly_identity: u64,
    pub limits: TopologyScanLimits,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsSuppliedTopologyInventoryAssemblyFaultCode {
    Json,
    Profile,
    AssemblyIdentity,
    TopologyForm,
    Cardinality,
    RootShape,
    CarrierKind,
    ProjectionIdentity,
    EntryReference,
    Volume,
    StrongIdentity,
    RelativePath,
    Ordinal,
    Limit,
    Parent,
    Order,
    Arithmetic,
    Resource,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsSuppliedTopologyInventoryAssemblyFault {
    pub code: WindowsSuppliedTopologyInventoryAssemblyFaultCode,
    pub nested_topology_fault: Option<Box<TopologyFormFault>>,
    pub field: String,
    pub message: String,
}

impl WindowsSuppliedTopologyInventoryAssemblyFault {
    fn simple(
        code: WindowsSuppliedTopologyInventoryAssemblyFaultCode,
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
            code: WindowsSuppliedTopologyInventoryAssemblyFaultCode::TopologyForm,
            nested_topology_fault: Some(Box::new(fault)),
            field: bounded(field, 64),
            message: bounded(&message, 256),
        }
    }
}

impl fmt::Display for WindowsSuppliedTopologyInventoryAssemblyFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl std::error::Error for WindowsSuppliedTopologyInventoryAssemblyFault {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "carrier_kind", content = "carrier")]
pub enum WindowsSuppliedTopologyInventoryMember {
    Root(WindowsSuppliedRootTopologyProjection),
    Directory(WindowsSuppliedDirectoryTopologyProjection),
    RegularFile(WindowsSuppliedRegularFileTopologyProjection),
}

impl WindowsSuppliedTopologyInventoryMember {
    pub fn topology_observation(&self) -> &TopologyEntryObservation {
        match self {
            Self::Root(carrier) => carrier.topology_observation(),
            Self::Directory(carrier) => carrier.topology_observation(),
            Self::RegularFile(carrier) => carrier.topology_observation(),
        }
    }

    pub fn projection_identity(&self) -> u64 {
        match self {
            Self::Root(carrier) => carrier.plan().projection_identity,
            Self::Directory(carrier) => carrier.plan().projection_identity,
            Self::RegularFile(carrier) => carrier.plan().projection_identity,
        }
    }

    pub fn entry_reference_identity(&self) -> u64 {
        match self {
            Self::Root(carrier) => carrier.stable_pair().entry_reference_identity,
            Self::Directory(carrier) => carrier.stable_pair().entry_reference_identity,
            Self::RegularFile(carrier) => {
                carrier
                    .content_binding()
                    .stable_pair()
                    .entry_reference_identity
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WindowsSuppliedTopologyInventoryAssembly {
    profile: String,
    plan: WindowsSuppliedTopologyInventoryAssemblyPlan,
    ordered_members: Vec<WindowsSuppliedTopologyInventoryMember>,
    entry_count: u64,
    total_file_bytes: u64,
}

impl WindowsSuppliedTopologyInventoryAssembly {
    pub fn profile(&self) -> &str {
        &self.profile
    }
    pub fn plan(&self) -> &WindowsSuppliedTopologyInventoryAssemblyPlan {
        &self.plan
    }
    pub fn ordered_members(&self) -> &[WindowsSuppliedTopologyInventoryMember] {
        &self.ordered_members
    }
    pub fn entry_count(&self) -> u64 {
        self.entry_count
    }
    pub fn total_file_bytes(&self) -> u64 {
        self.total_file_bytes
    }
}

pub fn decode_windows_supplied_topology_inventory_assembly_plan(
    bytes: &[u8],
) -> Result<
    WindowsSuppliedTopologyInventoryAssemblyPlan,
    WindowsSuppliedTopologyInventoryAssemblyFault,
> {
    if bytes.len() > WINDOWS_SUPPLIED_TOPOLOGY_INVENTORY_ASSEMBLY_PLAN_MAX_BYTES {
        return Err(WindowsSuppliedTopologyInventoryAssemblyFault::simple(
            WindowsSuppliedTopologyInventoryAssemblyFaultCode::Resource,
            "json",
            "encoded supplied topology inventory assembly plan exceeds 16384 bytes",
        ));
    }
    let plan: WindowsSuppliedTopologyInventoryAssemblyPlan = serde_json::from_slice(bytes)
        .map_err(|error| {
            WindowsSuppliedTopologyInventoryAssemblyFault::simple(
                WindowsSuppliedTopologyInventoryAssemblyFaultCode::Json,
                "json",
                &error.to_string(),
            )
        })?;
    validate_plan(&plan)?;
    Ok(plan)
}

pub fn decode_and_assemble_windows_supplied_topology_inventory(
    bytes: &[u8],
    root: WindowsSuppliedRootTopologyProjection,
    directories: Vec<WindowsSuppliedDirectoryTopologyProjection>,
    regular_files: Vec<WindowsSuppliedRegularFileTopologyProjection>,
) -> Result<WindowsSuppliedTopologyInventoryAssembly, WindowsSuppliedTopologyInventoryAssemblyFault>
{
    let plan = decode_windows_supplied_topology_inventory_assembly_plan(bytes)?;
    assemble_windows_supplied_topology_inventory(plan, root, directories, regular_files)
}

pub fn assemble_windows_supplied_topology_inventory(
    plan: WindowsSuppliedTopologyInventoryAssemblyPlan,
    root: WindowsSuppliedRootTopologyProjection,
    directories: Vec<WindowsSuppliedDirectoryTopologyProjection>,
    regular_files: Vec<WindowsSuppliedRegularFileTopologyProjection>,
) -> Result<WindowsSuppliedTopologyInventoryAssembly, WindowsSuppliedTopologyInventoryAssemblyFault>
{
    validate_plan(&plan)?;
    let descendant_count = directories
        .len()
        .checked_add(regular_files.len())
        .ok_or_else(|| arithmetic_fault("input cardinality overflow"))?;
    let member_count = descendant_count
        .checked_add(1)
        .ok_or_else(|| arithmetic_fault("root-inclusive cardinality overflow"))?;
    let entry_count = u64::try_from(member_count)
        .map_err(|_| arithmetic_fault("member count cannot be represented as u64"))?;
    if entry_count > plan.limits.maximum_entries {
        return Err(WindowsSuppliedTopologyInventoryAssemblyFault::simple(
            WindowsSuppliedTopologyInventoryAssemblyFaultCode::Cardinality,
            "limits.maximum_entries",
            "supplied member count exceeds maximum_entries",
        ));
    }

    let root_member = WindowsSuppliedTopologyInventoryMember::Root(root);
    root_member
        .topology_observation()
        .validate()
        .map_err(|fault| WindowsSuppliedTopologyInventoryAssemblyFault::topology("root", fault))?;
    let root_observation = root_member.topology_observation();
    if root_observation.kind != TopologyEntryKind::RootDirectory
        || root_observation.relative_path.is_some()
        || root_observation.observation_ordinal != 1
    {
        return Err(WindowsSuppliedTopologyInventoryAssemblyFault::simple(
            WindowsSuppliedTopologyInventoryAssemblyFaultCode::RootShape,
            "root",
            "root carrier must remain RootDirectory with absent path and ordinal one",
        ));
    }
    let root_volume_serial = root_observation.identity.volume_serial;

    let mut descendants = Vec::with_capacity(descendant_count);
    for carrier in directories {
        let member = WindowsSuppliedTopologyInventoryMember::Directory(carrier);
        validate_descendant_member(&member, TopologyEntryKind::Directory, "directories")?;
        let path = member
            .topology_observation()
            .relative_path
            .as_ref()
            .ok_or_else(|| order_fault("directory carrier lacks a descendant path"))?
            .clone();
        descendants.push((path, member));
    }
    for carrier in regular_files {
        let member = WindowsSuppliedTopologyInventoryMember::RegularFile(carrier);
        validate_descendant_member(&member, TopologyEntryKind::RegularFile, "regular_files")?;
        let path = member
            .topology_observation()
            .relative_path
            .as_ref()
            .ok_or_else(|| order_fault("regular-file carrier lacks a descendant path"))?
            .clone();
        descendants.push((path, member));
    }

    for member in std::iter::once(&root_member).chain(descendants.iter().map(|(_, member)| member))
    {
        if member.topology_observation().identity.volume_serial != root_volume_serial {
            return Err(WindowsSuppliedTopologyInventoryAssemblyFault::simple(
                WindowsSuppliedTopologyInventoryAssemblyFaultCode::Volume,
                "identity.volume_serial",
                "every supplied member volume serial must equal the root volume serial",
            ));
        }
    }
    reject_duplicate_projection_identities(&root_member, &descendants)?;
    reject_duplicate_entry_references(&root_member, &descendants)?;
    reject_duplicate_strong_identities(&root_member, &descendants)?;
    let path_kinds = collect_unique_path_kinds(&descendants)?;
    reject_duplicate_ordinals(&root_member, &descendants)?;

    let total_file_bytes = enforce_limits_and_total(&plan.limits, &root_member, &descendants)?;
    enforce_parent_closure(&path_kinds)?;
    descendants.sort_by(|(left, _), (right, _)| compare_structural_paths(left, right));
    enforce_ordinals(&descendants)?;

    let mut ordered_members = Vec::with_capacity(member_count);
    ordered_members.push(root_member);
    ordered_members.extend(descendants.into_iter().map(|(_, member)| member));

    Ok(WindowsSuppliedTopologyInventoryAssembly {
        profile: WINDOWS_SUPPLIED_TOPOLOGY_INVENTORY_ASSEMBLY_PROFILE.to_owned(),
        plan,
        ordered_members,
        entry_count,
        total_file_bytes,
    })
}

fn validate_plan(
    plan: &WindowsSuppliedTopologyInventoryAssemblyPlan,
) -> Result<(), WindowsSuppliedTopologyInventoryAssemblyFault> {
    if plan.profile != WINDOWS_SUPPLIED_TOPOLOGY_INVENTORY_ASSEMBLY_PROFILE {
        return Err(WindowsSuppliedTopologyInventoryAssemblyFault::simple(
            WindowsSuppliedTopologyInventoryAssemblyFaultCode::Profile,
            "profile",
            "profile is not the exact supported supplied inventory assembly profile",
        ));
    }
    if plan.assembly_identity == 0 {
        return Err(WindowsSuppliedTopologyInventoryAssemblyFault::simple(
            WindowsSuppliedTopologyInventoryAssemblyFaultCode::AssemblyIdentity,
            "assembly_identity",
            "assembly identity must be nonzero caller syntax",
        ));
    }
    plan.limits
        .validate()
        .map_err(|fault| WindowsSuppliedTopologyInventoryAssemblyFault::topology("limits", fault))
}

fn validate_descendant_member(
    member: &WindowsSuppliedTopologyInventoryMember,
    required_kind: TopologyEntryKind,
    field: &str,
) -> Result<(), WindowsSuppliedTopologyInventoryAssemblyFault> {
    member
        .topology_observation()
        .validate()
        .map_err(|fault| WindowsSuppliedTopologyInventoryAssemblyFault::topology(field, fault))?;
    if member.topology_observation().kind != required_kind {
        return Err(WindowsSuppliedTopologyInventoryAssemblyFault::simple(
            WindowsSuppliedTopologyInventoryAssemblyFaultCode::CarrierKind,
            field,
            "carrier variant and projected topology kind differ",
        ));
    }
    Ok(())
}

fn members<'a>(
    root: &'a WindowsSuppliedTopologyInventoryMember,
    descendants: &'a [(String, WindowsSuppliedTopologyInventoryMember)],
) -> impl Iterator<Item = &'a WindowsSuppliedTopologyInventoryMember> {
    std::iter::once(root).chain(descendants.iter().map(|(_, member)| member))
}

fn reject_duplicate_projection_identities(
    root: &WindowsSuppliedTopologyInventoryMember,
    descendants: &[(String, WindowsSuppliedTopologyInventoryMember)],
) -> Result<(), WindowsSuppliedTopologyInventoryAssemblyFault> {
    let mut seen = BTreeSet::new();
    for member in members(root, descendants) {
        if !seen.insert(member.projection_identity()) {
            return Err(WindowsSuppliedTopologyInventoryAssemblyFault::simple(
                WindowsSuppliedTopologyInventoryAssemblyFaultCode::ProjectionIdentity,
                "projection_identity",
                "duplicate projection identity in supplied member set",
            ));
        }
    }
    Ok(())
}

fn reject_duplicate_entry_references(
    root: &WindowsSuppliedTopologyInventoryMember,
    descendants: &[(String, WindowsSuppliedTopologyInventoryMember)],
) -> Result<(), WindowsSuppliedTopologyInventoryAssemblyFault> {
    let mut seen = BTreeSet::new();
    for member in members(root, descendants) {
        if !seen.insert(member.entry_reference_identity()) {
            return Err(WindowsSuppliedTopologyInventoryAssemblyFault::simple(
                WindowsSuppliedTopologyInventoryAssemblyFaultCode::EntryReference,
                "entry_reference_identity",
                "duplicate entry-reference identity in supplied member set",
            ));
        }
    }
    Ok(())
}

fn reject_duplicate_strong_identities(
    root: &WindowsSuppliedTopologyInventoryMember,
    descendants: &[(String, WindowsSuppliedTopologyInventoryMember)],
) -> Result<(), WindowsSuppliedTopologyInventoryAssemblyFault> {
    let mut seen: BTreeSet<StrongFileIdentity> = BTreeSet::new();
    for member in members(root, descendants) {
        if !seen.insert(member.topology_observation().identity.clone()) {
            return Err(WindowsSuppliedTopologyInventoryAssemblyFault::simple(
                WindowsSuppliedTopologyInventoryAssemblyFaultCode::StrongIdentity,
                "identity",
                "duplicate complete strong identity in supplied member set",
            ));
        }
    }
    Ok(())
}

fn collect_unique_path_kinds(
    descendants: &[(String, WindowsSuppliedTopologyInventoryMember)],
) -> Result<BTreeMap<String, TopologyEntryKind>, WindowsSuppliedTopologyInventoryAssemblyFault> {
    let mut paths = BTreeMap::new();
    for (path, member) in descendants {
        if paths
            .insert(path.clone(), member.topology_observation().kind)
            .is_some()
        {
            return Err(WindowsSuppliedTopologyInventoryAssemblyFault::simple(
                WindowsSuppliedTopologyInventoryAssemblyFaultCode::RelativePath,
                "relative_path",
                "duplicate exact descendant path in supplied member set",
            ));
        }
    }
    Ok(paths)
}

fn reject_duplicate_ordinals(
    root: &WindowsSuppliedTopologyInventoryMember,
    descendants: &[(String, WindowsSuppliedTopologyInventoryMember)],
) -> Result<(), WindowsSuppliedTopologyInventoryAssemblyFault> {
    let mut seen = BTreeSet::new();
    for member in members(root, descendants) {
        if !seen.insert(member.topology_observation().observation_ordinal) {
            return Err(WindowsSuppliedTopologyInventoryAssemblyFault::simple(
                WindowsSuppliedTopologyInventoryAssemblyFaultCode::Ordinal,
                "observation_ordinal",
                "duplicate observation ordinal in supplied member set",
            ));
        }
    }
    Ok(())
}

fn enforce_limits_and_total(
    limits: &TopologyScanLimits,
    root: &WindowsSuppliedTopologyInventoryMember,
    descendants: &[(String, WindowsSuppliedTopologyInventoryMember)],
) -> Result<u64, WindowsSuppliedTopologyInventoryAssemblyFault> {
    let mut total_file_bytes = 0_u64;
    for member in members(root, descendants) {
        let observation = member.topology_observation();
        let stream_count = u32::try_from(observation.streams.len())
            .map_err(|_| arithmetic_fault("stream count cannot be represented as u32"))?;
        if stream_count > limits.maximum_streams_per_entry {
            return Err(limit_fault(
                "limits.maximum_streams_per_entry",
                "entry stream count exceeds maximum_streams_per_entry",
            ));
        }
        if let Some(path) = &observation.relative_path {
            if path.len() > limits.maximum_path_bytes as usize {
                return Err(limit_fault(
                    "limits.maximum_path_bytes",
                    "descendant path exceeds maximum_path_bytes",
                ));
            }
            let depth = u32::try_from(path.split('/').count())
                .map_err(|_| arithmetic_fault("path depth cannot be represented as u32"))?;
            if depth > limits.maximum_depth {
                return Err(limit_fault(
                    "limits.maximum_depth",
                    "descendant path depth exceeds maximum_depth",
                ));
            }
        }
        if observation.kind == TopologyEntryKind::RegularFile {
            let length = observation.length.ok_or_else(|| {
                WindowsSuppliedTopologyInventoryAssemblyFault::simple(
                    WindowsSuppliedTopologyInventoryAssemblyFaultCode::CarrierKind,
                    "length",
                    "regular-file carrier lacks its validated length",
                )
            })?;
            if length > limits.maximum_file_bytes {
                return Err(limit_fault(
                    "limits.maximum_file_bytes",
                    "regular-file length exceeds maximum_file_bytes",
                ));
            }
            total_file_bytes = total_file_bytes
                .checked_add(length)
                .ok_or_else(|| arithmetic_fault("total file-byte count overflow"))?;
            if total_file_bytes > limits.maximum_total_bytes {
                return Err(limit_fault(
                    "limits.maximum_total_bytes",
                    "total regular-file bytes exceed maximum_total_bytes",
                ));
            }
        }
    }
    Ok(total_file_bytes)
}

fn enforce_parent_closure(
    path_kinds: &BTreeMap<String, TopologyEntryKind>,
) -> Result<(), WindowsSuppliedTopologyInventoryAssemblyFault> {
    for path in path_kinds.keys() {
        let components: Vec<&str> = path.split('/').collect();
        for prefix_length in 1..components.len() {
            let prefix = components[..prefix_length].join("/");
            match path_kinds.get(&prefix) {
                Some(TopologyEntryKind::Directory) => {}
                Some(_) => {
                    return Err(WindowsSuppliedTopologyInventoryAssemblyFault::simple(
                        WindowsSuppliedTopologyInventoryAssemblyFaultCode::Parent,
                        "relative_path",
                        "required supplied parent exists but is not a directory",
                    ));
                }
                None => {
                    return Err(WindowsSuppliedTopologyInventoryAssemblyFault::simple(
                        WindowsSuppliedTopologyInventoryAssemblyFaultCode::Parent,
                        "relative_path",
                        "required supplied parent directory is absent",
                    ));
                }
            }
        }
    }
    Ok(())
}

fn compare_structural_paths(left: &str, right: &str) -> Ordering {
    left.split('/')
        .map(str::as_bytes)
        .cmp(right.split('/').map(str::as_bytes))
}

fn enforce_ordinals(
    descendants: &[(String, WindowsSuppliedTopologyInventoryMember)],
) -> Result<(), WindowsSuppliedTopologyInventoryAssemblyFault> {
    for (position, (_, member)) in descendants.iter().enumerate() {
        let expected = u64::try_from(position)
            .ok()
            .and_then(|value| value.checked_add(2))
            .ok_or_else(|| arithmetic_fault("structural position cannot form an ordinal"))?;
        if member.topology_observation().observation_ordinal != expected {
            return Err(WindowsSuppliedTopologyInventoryAssemblyFault::simple(
                WindowsSuppliedTopologyInventoryAssemblyFaultCode::Ordinal,
                "observation_ordinal",
                "declared ordinal does not equal root-first structural position",
            ));
        }
    }
    Ok(())
}

fn limit_fault(field: &str, message: &str) -> WindowsSuppliedTopologyInventoryAssemblyFault {
    WindowsSuppliedTopologyInventoryAssemblyFault::simple(
        WindowsSuppliedTopologyInventoryAssemblyFaultCode::Limit,
        field,
        message,
    )
}

fn arithmetic_fault(message: &str) -> WindowsSuppliedTopologyInventoryAssemblyFault {
    WindowsSuppliedTopologyInventoryAssemblyFault::simple(
        WindowsSuppliedTopologyInventoryAssemblyFaultCode::Arithmetic,
        "arithmetic",
        message,
    )
}

fn order_fault(message: &str) -> WindowsSuppliedTopologyInventoryAssemblyFault {
    WindowsSuppliedTopologyInventoryAssemblyFault::simple(
        WindowsSuppliedTopologyInventoryAssemblyFaultCode::Order,
        "relative_path",
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
        TopologyModeClass, WINDOWS_PLATFORM_PREFLIGHT_PROFILE, WINDOWS_PLATFORM_PREFLIGHT_TARGET,
        WindowsEntryPolicyKind, WindowsPlatformPreflightRecord, WindowsVolumeInformation,
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
    };

    const GUID_ROOT: &str = r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\";

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

    fn plan() -> WindowsSuppliedTopologyInventoryAssemblyPlan {
        WindowsSuppliedTopologyInventoryAssemblyPlan {
            profile: WINDOWS_SUPPLIED_TOPOLOGY_INVENTORY_ASSEMBLY_PROFILE.to_owned(),
            assembly_identity: 91,
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
    ) -> WindowsSuppliedRootTopologyProjection {
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
    ) -> WindowsSuppliedDirectoryTopologyProjection {
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
    ) -> WindowsSuppliedRegularFileTopologyProjection {
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

    #[test]
    fn strict_plan_decode_and_current_limit_validation_are_exact() {
        let encoded = serde_json::to_vec(&plan()).unwrap();
        assert_eq!(
            decode_windows_supplied_topology_inventory_assembly_plan(&encoded).unwrap(),
            plan()
        );
        let text = String::from_utf8(encoded).unwrap();
        let unknown = text.replacen('{', "{\"trusted\":true,", 1);
        assert_eq!(
            decode_windows_supplied_topology_inventory_assembly_plan(unknown.as_bytes())
                .unwrap_err()
                .code,
            WindowsSuppliedTopologyInventoryAssemblyFaultCode::Json
        );
        assert_eq!(
            decode_windows_supplied_topology_inventory_assembly_plan(&vec![
                b' ';
                WINDOWS_SUPPLIED_TOPOLOGY_INVENTORY_ASSEMBLY_PLAN_MAX_BYTES
                    + 1
            ])
            .unwrap_err()
            .code,
            WindowsSuppliedTopologyInventoryAssemblyFaultCode::Resource
        );
        let mut invalid = plan();
        invalid.assembly_identity = 0;
        assert_eq!(
            assemble_windows_supplied_topology_inventory(
                invalid,
                root(1, 11, 19, 0),
                vec![],
                vec![]
            )
            .unwrap_err()
            .code,
            WindowsSuppliedTopologyInventoryAssemblyFaultCode::AssemblyIdentity
        );
        let mut invalid = plan();
        invalid.limits.maximum_entries = 0;
        let fault = assemble_windows_supplied_topology_inventory(
            invalid,
            root(1, 11, 19, 0),
            vec![],
            vec![],
        )
        .unwrap_err();
        assert_eq!(
            fault.code,
            WindowsSuppliedTopologyInventoryAssemblyFaultCode::TopologyForm
        );
        assert!(fault.nested_topology_fault.is_some());
    }

    #[test]
    fn root_only_set_is_valid_and_preserves_complete_carrier() {
        let output = assemble_windows_supplied_topology_inventory(
            plan(),
            root(1, 11, 19, 0),
            vec![],
            vec![],
        )
        .unwrap();
        assert_eq!(output.entry_count(), 1);
        assert_eq!(output.total_file_bytes(), 0);
        assert_eq!(output.ordered_members().len(), 1);
        assert!(matches!(
            output.ordered_members()[0],
            WindowsSuppliedTopologyInventoryMember::Root(_)
        ));
        assert_eq!(output.ordered_members()[0].projection_identity(), 1);
    }

    #[test]
    fn mixed_set_sorts_whole_carriers_and_derives_exact_totals() {
        let output = assemble_windows_supplied_topology_inventory(
            plan(),
            root(1, 11, 19, 0),
            vec![
                directory("z", 4, 4, 14, 19, 48),
                directory("src", 2, 2, 12, 19, 16),
            ],
            vec![regular_file("src/lib.rs", 3, 3, 13, 19, 32, b"abc")],
        )
        .unwrap();
        let paths: Vec<Option<&str>> = output
            .ordered_members()
            .iter()
            .map(|member| member.topology_observation().relative_path.as_deref())
            .collect();
        assert_eq!(
            paths,
            vec![None, Some("src"), Some("src/lib.rs"), Some("z")]
        );
        assert_eq!(output.entry_count(), 4);
        assert_eq!(output.total_file_bytes(), 3);
        assert_eq!(output.ordered_members()[2].entry_reference_identity(), 13);
    }

    #[test]
    fn projection_and_entry_reference_duplicates_are_distinct() {
        let fault = assemble_windows_supplied_topology_inventory(
            plan(),
            root(1, 11, 19, 0),
            vec![directory("src", 2, 1, 12, 19, 16)],
            vec![],
        )
        .unwrap_err();
        assert_eq!(
            fault.code,
            WindowsSuppliedTopologyInventoryAssemblyFaultCode::ProjectionIdentity
        );

        let fault = assemble_windows_supplied_topology_inventory(
            plan(),
            root(1, 11, 19, 0),
            vec![directory("src", 2, 2, 11, 19, 16)],
            vec![],
        )
        .unwrap_err();
        assert_eq!(
            fault.code,
            WindowsSuppliedTopologyInventoryAssemblyFaultCode::EntryReference
        );
    }

    #[test]
    fn strong_identity_path_and_ordinal_duplicates_are_distinct() {
        let fault = assemble_windows_supplied_topology_inventory(
            plan(),
            root(1, 11, 19, 0),
            vec![directory("src", 2, 2, 12, 19, 0)],
            vec![],
        )
        .unwrap_err();
        assert_eq!(
            fault.code,
            WindowsSuppliedTopologyInventoryAssemblyFaultCode::StrongIdentity
        );

        let fault = assemble_windows_supplied_topology_inventory(
            plan(),
            root(1, 11, 19, 0),
            vec![directory("dup", 2, 2, 12, 19, 16)],
            vec![regular_file("dup", 3, 3, 13, 19, 32, b"x")],
        )
        .unwrap_err();
        assert_eq!(
            fault.code,
            WindowsSuppliedTopologyInventoryAssemblyFaultCode::RelativePath
        );

        let fault = assemble_windows_supplied_topology_inventory(
            plan(),
            root(1, 11, 19, 0),
            vec![directory("a", 2, 2, 12, 19, 16)],
            vec![regular_file("b", 2, 3, 13, 19, 32, b"x")],
        )
        .unwrap_err();
        assert_eq!(
            fault.code,
            WindowsSuppliedTopologyInventoryAssemblyFaultCode::Ordinal
        );
    }

    #[test]
    fn common_volume_is_exact() {
        let fault = assemble_windows_supplied_topology_inventory(
            plan(),
            root(1, 11, 19, 0),
            vec![directory("src", 2, 2, 12, 20, 16)],
            vec![],
        )
        .unwrap_err();
        assert_eq!(
            fault.code,
            WindowsSuppliedTopologyInventoryAssemblyFaultCode::Volume
        );
    }

    #[test]
    fn cardinality_path_depth_file_and_total_limits_are_enforced() {
        let mut bounded = plan();
        bounded.limits.maximum_entries = 1;
        assert_eq!(
            assemble_windows_supplied_topology_inventory(
                bounded,
                root(1, 11, 19, 0),
                vec![directory("src", 2, 2, 12, 19, 16)],
                vec![],
            )
            .unwrap_err()
            .code,
            WindowsSuppliedTopologyInventoryAssemblyFaultCode::Cardinality
        );

        let mut bounded = plan();
        bounded.limits.maximum_path_bytes = 3;
        assert_eq!(
            assemble_windows_supplied_topology_inventory(
                bounded,
                root(1, 11, 19, 0),
                vec![directory("long", 2, 2, 12, 19, 16)],
                vec![],
            )
            .unwrap_err()
            .code,
            WindowsSuppliedTopologyInventoryAssemblyFaultCode::Limit
        );

        let mut bounded = plan();
        bounded.limits.maximum_depth = 1;
        assert_eq!(
            assemble_windows_supplied_topology_inventory(
                bounded,
                root(1, 11, 19, 0),
                vec![directory("src", 2, 2, 12, 19, 16)],
                vec![regular_file("src/lib", 3, 3, 13, 19, 32, b"x")],
            )
            .unwrap_err()
            .code,
            WindowsSuppliedTopologyInventoryAssemblyFaultCode::Limit
        );

        let mut bounded = plan();
        bounded.limits.maximum_file_bytes = 2;
        assert_eq!(
            assemble_windows_supplied_topology_inventory(
                bounded,
                root(1, 11, 19, 0),
                vec![],
                vec![regular_file("a", 2, 2, 12, 19, 16, b"abc")],
            )
            .unwrap_err()
            .code,
            WindowsSuppliedTopologyInventoryAssemblyFaultCode::Limit
        );

        let mut bounded = plan();
        bounded.limits.maximum_file_bytes = 3;
        bounded.limits.maximum_total_bytes = 4;
        assert_eq!(
            assemble_windows_supplied_topology_inventory(
                bounded,
                root(1, 11, 19, 0),
                vec![],
                vec![
                    regular_file("a", 2, 2, 12, 19, 16, b"abc"),
                    regular_file("b", 3, 3, 13, 19, 32, b"def"),
                ],
            )
            .unwrap_err()
            .code,
            WindowsSuppliedTopologyInventoryAssemblyFaultCode::Limit
        );
    }

    #[test]
    fn missing_and_nondirectory_parents_reject_distinctly_from_success() {
        let fault = assemble_windows_supplied_topology_inventory(
            plan(),
            root(1, 11, 19, 0),
            vec![],
            vec![regular_file("src/lib", 2, 2, 12, 19, 16, b"x")],
        )
        .unwrap_err();
        assert_eq!(
            fault.code,
            WindowsSuppliedTopologyInventoryAssemblyFaultCode::Parent
        );

        let fault = assemble_windows_supplied_topology_inventory(
            plan(),
            root(1, 11, 19, 0),
            vec![],
            vec![
                regular_file("src", 2, 2, 12, 19, 16, b"x"),
                regular_file("src/lib", 3, 3, 13, 19, 32, b"y"),
            ],
        )
        .unwrap_err();
        assert_eq!(
            fault.code,
            WindowsSuppliedTopologyInventoryAssemblyFaultCode::Parent
        );
    }

    #[test]
    fn structural_order_is_component_aware_and_ordinals_are_not_repaired() {
        assert_eq!(compare_structural_paths("a/z", "b"), Ordering::Less);
        assert_eq!(compare_structural_paths("a", "a/z"), Ordering::Less);
        assert_eq!(compare_structural_paths("Z", "a"), Ordering::Less);
        let fault = assemble_windows_supplied_topology_inventory(
            plan(),
            root(1, 11, 19, 0),
            vec![directory("z", 2, 2, 12, 19, 16)],
            vec![regular_file("a", 3, 3, 13, 19, 32, b"x")],
        )
        .unwrap_err();
        assert_eq!(
            fault.code,
            WindowsSuppliedTopologyInventoryAssemblyFaultCode::Ordinal
        );
    }

    #[test]
    fn decode_output_serialization_and_diagnostics_remain_bounded() {
        let encoded = serde_json::to_vec(&plan()).unwrap();
        let output = decode_and_assemble_windows_supplied_topology_inventory(
            &encoded,
            root(1, 11, 19, 0),
            vec![],
            vec![],
        )
        .unwrap();
        let value = serde_json::to_value(output).unwrap();
        assert_eq!(
            value["profile"],
            WINDOWS_SUPPLIED_TOPOLOGY_INVENTORY_ASSEMBLY_PROFILE
        );
        assert_eq!(value["ordered_members"][0]["carrier_kind"], "root");
        let long = "x".repeat(400);
        let fault = WindowsSuppliedTopologyInventoryAssemblyFault::simple(
            WindowsSuppliedTopologyInventoryAssemblyFaultCode::Resource,
            &long,
            &long,
        );
        assert_eq!(fault.field.chars().count(), 64);
        assert_eq!(fault.message.chars().count(), 256);
    }
}
