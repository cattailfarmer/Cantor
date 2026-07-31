//! Pure reconciliation of two complete supplied ordered-inventory digests.
//!
//! Success proves only current pure rederivation, exact supplied comparison
//! scope, and an equal-or-different relation between canonical sequence
//! commitments. Left and right are positional roles, not acquisition time. No
//! physical, temporal, stability, double-inventory, quiescence, receipt, or
//! admission claim is made here.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    TopologyEntryKind, TopologyScanLimits,
    windows_supplied_ordered_topology_inventory_digest::{
        ORDERED_TOPOLOGY_OBSERVATION_ENCODING_PROFILE,
        WINDOWS_SUPPLIED_ORDERED_TOPOLOGY_INVENTORY_DIGEST_PROFILE,
        WindowsSuppliedOrderedTopologyInventoryDigest,
        WindowsSuppliedOrderedTopologyInventoryDigestFault,
        derive_windows_supplied_ordered_topology_inventory_digest,
    },
    windows_supplied_topology_inventory_assembly::WINDOWS_SUPPLIED_TOPOLOGY_INVENTORY_ASSEMBLY_PROFILE,
};

/// Exact pure reconciliation profile.
pub const WINDOWS_SUPPLIED_ORDERED_TOPOLOGY_INVENTORY_DIGEST_RECONCILIATION_PROFILE: &str =
    "cantor-windows-supplied-ordered-topology-inventory-digest-reconciliation/0.1";
/// Maximum accepted encoded plan size before strict JSON decoding.
pub const WINDOWS_SUPPLIED_ORDERED_TOPOLOGY_INVENTORY_DIGEST_RECONCILIATION_PLAN_MAX_BYTES: usize =
    4_096;

/// Strict plan for one supplied digest-pair reconciliation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsSuppliedOrderedTopologyInventoryDigestReconciliationPlan {
    profile: String,
    reconciliation_identity: u64,
}

impl WindowsSuppliedOrderedTopologyInventoryDigestReconciliationPlan {
    pub fn profile(&self) -> &str {
        &self.profile
    }

    pub fn reconciliation_identity(&self) -> u64 {
        self.reconciliation_identity
    }
}

/// Closed positional operand role. It carries no temporal meaning.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsSuppliedOrderedTopologyInventoryDigestReconciliationSide {
    Left,
    Right,
}

/// Closed successful pair relation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsSuppliedOrderedTopologyInventoryDigestReconciliationDisposition {
    Equal,
    Different,
}

/// Closed pure reconciliation failure vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsSuppliedOrderedTopologyInventoryDigestReconciliationFaultCode {
    Json,
    Profile,
    ReconciliationIdentity,
    LeftDigest,
    RightDigest,
    ScopeProfile,
    Limits,
    RootScope,
    Resource,
    Internal,
}

/// Bounded failure released without operands, scope, or disposition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsSuppliedOrderedTopologyInventoryDigestReconciliationFault {
    pub code: WindowsSuppliedOrderedTopologyInventoryDigestReconciliationFaultCode,
    pub side: Option<WindowsSuppliedOrderedTopologyInventoryDigestReconciliationSide>,
    pub nested_digest_fault: Option<Box<WindowsSuppliedOrderedTopologyInventoryDigestFault>>,
    pub field: String,
    pub message: String,
}

impl WindowsSuppliedOrderedTopologyInventoryDigestReconciliationFault {
    fn simple(
        code: WindowsSuppliedOrderedTopologyInventoryDigestReconciliationFaultCode,
        field: &str,
        message: &str,
    ) -> Self {
        Self {
            code,
            side: None,
            nested_digest_fault: None,
            field: bounded(field, 64),
            message: bounded(message, 256),
        }
    }

    fn digest(
        side: WindowsSuppliedOrderedTopologyInventoryDigestReconciliationSide,
        fault: WindowsSuppliedOrderedTopologyInventoryDigestFault,
    ) -> Self {
        let (code, field) = match side {
            WindowsSuppliedOrderedTopologyInventoryDigestReconciliationSide::Left => (
                WindowsSuppliedOrderedTopologyInventoryDigestReconciliationFaultCode::LeftDigest,
                "left",
            ),
            WindowsSuppliedOrderedTopologyInventoryDigestReconciliationSide::Right => (
                WindowsSuppliedOrderedTopologyInventoryDigestReconciliationFaultCode::RightDigest,
                "right",
            ),
        };
        let message = format!("current supplied digest rederivation rejected: {fault}");
        Self {
            code,
            side: Some(side),
            nested_digest_fault: Some(Box::new(fault)),
            field: field.to_owned(),
            message: bounded(&message, 256),
        }
    }

    fn contradiction(
        side: WindowsSuppliedOrderedTopologyInventoryDigestReconciliationSide,
    ) -> Self {
        let field = match side {
            WindowsSuppliedOrderedTopologyInventoryDigestReconciliationSide::Left => "left",
            WindowsSuppliedOrderedTopologyInventoryDigestReconciliationSide::Right => "right",
        };
        Self {
            code: WindowsSuppliedOrderedTopologyInventoryDigestReconciliationFaultCode::Internal,
            side: Some(side),
            nested_digest_fault: None,
            field: field.to_owned(),
            message: "current supplied digest rederivation contradicted its complete operand"
                .to_owned(),
        }
    }
}

impl fmt::Display for WindowsSuppliedOrderedTopologyInventoryDigestReconciliationFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl std::error::Error for WindowsSuppliedOrderedTopologyInventoryDigestReconciliationFault {}

/// Exact common supplied comparison scope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WindowsSuppliedOrderedTopologyInventoryDigestReconciliationScope {
    encoding_profile: String,
    limits: TopologyScanLimits,
    root_relative_path: Option<String>,
    root_kind: TopologyEntryKind,
    root_volume_serial: u64,
    root_file_id: String,
}

impl WindowsSuppliedOrderedTopologyInventoryDigestReconciliationScope {
    pub fn encoding_profile(&self) -> &str {
        &self.encoding_profile
    }

    pub fn limits(&self) -> &TopologyScanLimits {
        &self.limits
    }

    pub fn root_relative_path(&self) -> Option<&str> {
        self.root_relative_path.as_deref()
    }

    pub fn root_kind(&self) -> TopologyEntryKind {
        self.root_kind
    }

    pub fn root_volume_serial(&self) -> u64 {
        self.root_volume_serial
    }

    pub fn root_file_id(&self) -> &str {
        &self.root_file_id
    }
}

/// Output-only pair relation retaining both complete supplied lineages.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WindowsSuppliedOrderedTopologyInventoryDigestReconciliation {
    profile: String,
    plan: WindowsSuppliedOrderedTopologyInventoryDigestReconciliationPlan,
    left: WindowsSuppliedOrderedTopologyInventoryDigest,
    right: WindowsSuppliedOrderedTopologyInventoryDigest,
    common_scope: WindowsSuppliedOrderedTopologyInventoryDigestReconciliationScope,
    disposition: WindowsSuppliedOrderedTopologyInventoryDigestReconciliationDisposition,
}

impl WindowsSuppliedOrderedTopologyInventoryDigestReconciliation {
    pub fn profile(&self) -> &str {
        &self.profile
    }

    pub fn plan(&self) -> &WindowsSuppliedOrderedTopologyInventoryDigestReconciliationPlan {
        &self.plan
    }

    pub fn left(&self) -> &WindowsSuppliedOrderedTopologyInventoryDigest {
        &self.left
    }

    pub fn right(&self) -> &WindowsSuppliedOrderedTopologyInventoryDigest {
        &self.right
    }

    pub fn common_scope(
        &self,
    ) -> &WindowsSuppliedOrderedTopologyInventoryDigestReconciliationScope {
        &self.common_scope
    }

    pub fn disposition(
        &self,
    ) -> WindowsSuppliedOrderedTopologyInventoryDigestReconciliationDisposition {
        self.disposition
    }
}

/// Strictly decodes and validates one bounded reconciliation plan.
pub fn decode_windows_supplied_ordered_topology_inventory_digest_reconciliation_plan(
    bytes: &[u8],
) -> Result<
    WindowsSuppliedOrderedTopologyInventoryDigestReconciliationPlan,
    WindowsSuppliedOrderedTopologyInventoryDigestReconciliationFault,
> {
    if bytes.len()
        > WINDOWS_SUPPLIED_ORDERED_TOPOLOGY_INVENTORY_DIGEST_RECONCILIATION_PLAN_MAX_BYTES
    {
        return Err(
            WindowsSuppliedOrderedTopologyInventoryDigestReconciliationFault::simple(
                WindowsSuppliedOrderedTopologyInventoryDigestReconciliationFaultCode::Resource,
                "json",
                "encoded supplied digest reconciliation plan exceeds 4096 bytes",
            ),
        );
    }
    let plan: WindowsSuppliedOrderedTopologyInventoryDigestReconciliationPlan =
        serde_json::from_slice(bytes).map_err(|error| {
            WindowsSuppliedOrderedTopologyInventoryDigestReconciliationFault::simple(
                WindowsSuppliedOrderedTopologyInventoryDigestReconciliationFaultCode::Json,
                "json",
                &error.to_string(),
            )
        })?;
    validate_plan(&plan)?;
    Ok(plan)
}

/// Decodes a plan and reconciles exactly two complete supplied digest carriers.
pub fn decode_and_reconcile_windows_supplied_ordered_topology_inventory_digests(
    plan_bytes: &[u8],
    left: WindowsSuppliedOrderedTopologyInventoryDigest,
    right: WindowsSuppliedOrderedTopologyInventoryDigest,
) -> Result<
    WindowsSuppliedOrderedTopologyInventoryDigestReconciliation,
    WindowsSuppliedOrderedTopologyInventoryDigestReconciliationFault,
> {
    let plan =
        decode_windows_supplied_ordered_topology_inventory_digest_reconciliation_plan(plan_bytes)?;
    reconcile_windows_supplied_ordered_topology_inventory_digests(plan, left, right)
}

/// Reconciles two output-only supplied digest carriers without effects.
pub fn reconcile_windows_supplied_ordered_topology_inventory_digests(
    plan: WindowsSuppliedOrderedTopologyInventoryDigestReconciliationPlan,
    left: WindowsSuppliedOrderedTopologyInventoryDigest,
    right: WindowsSuppliedOrderedTopologyInventoryDigest,
) -> Result<
    WindowsSuppliedOrderedTopologyInventoryDigestReconciliation,
    WindowsSuppliedOrderedTopologyInventoryDigestReconciliationFault,
> {
    validate_plan(&plan)?;
    rederive(
        WindowsSuppliedOrderedTopologyInventoryDigestReconciliationSide::Left,
        &left,
    )?;
    rederive(
        WindowsSuppliedOrderedTopologyInventoryDigestReconciliationSide::Right,
        &right,
    )?;
    validate_profiles(&left, &right)?;
    let common_scope = validate_and_build_scope(&left, &right)?;
    let disposition = if left.ordered_inventory_sha256() == right.ordered_inventory_sha256() {
        WindowsSuppliedOrderedTopologyInventoryDigestReconciliationDisposition::Equal
    } else {
        WindowsSuppliedOrderedTopologyInventoryDigestReconciliationDisposition::Different
    };
    Ok(
        WindowsSuppliedOrderedTopologyInventoryDigestReconciliation {
            profile: WINDOWS_SUPPLIED_ORDERED_TOPOLOGY_INVENTORY_DIGEST_RECONCILIATION_PROFILE
                .to_owned(),
            plan,
            left,
            right,
            common_scope,
            disposition,
        },
    )
}

fn validate_plan(
    plan: &WindowsSuppliedOrderedTopologyInventoryDigestReconciliationPlan,
) -> Result<(), WindowsSuppliedOrderedTopologyInventoryDigestReconciliationFault> {
    if plan.profile != WINDOWS_SUPPLIED_ORDERED_TOPOLOGY_INVENTORY_DIGEST_RECONCILIATION_PROFILE {
        return Err(
            WindowsSuppliedOrderedTopologyInventoryDigestReconciliationFault::simple(
                WindowsSuppliedOrderedTopologyInventoryDigestReconciliationFaultCode::Profile,
                "profile",
                "unsupported supplied digest reconciliation profile",
            ),
        );
    }
    if plan.reconciliation_identity == 0 {
        return Err(
            WindowsSuppliedOrderedTopologyInventoryDigestReconciliationFault::simple(
                WindowsSuppliedOrderedTopologyInventoryDigestReconciliationFaultCode::ReconciliationIdentity,
                "reconciliation_identity",
                "reconciliation identity must be nonzero",
            ),
        );
    }
    Ok(())
}

fn rederive(
    side: WindowsSuppliedOrderedTopologyInventoryDigestReconciliationSide,
    supplied: &WindowsSuppliedOrderedTopologyInventoryDigest,
) -> Result<(), WindowsSuppliedOrderedTopologyInventoryDigestReconciliationFault> {
    let rederived = derive_windows_supplied_ordered_topology_inventory_digest(
        supplied.plan().clone(),
        supplied.assembly().clone(),
    )
    .map_err(|fault| {
        WindowsSuppliedOrderedTopologyInventoryDigestReconciliationFault::digest(side, fault)
    })?;
    if rederived != *supplied {
        return Err(
            WindowsSuppliedOrderedTopologyInventoryDigestReconciliationFault::contradiction(side),
        );
    }
    Ok(())
}

fn validate_profiles(
    left: &WindowsSuppliedOrderedTopologyInventoryDigest,
    right: &WindowsSuppliedOrderedTopologyInventoryDigest,
) -> Result<(), WindowsSuppliedOrderedTopologyInventoryDigestReconciliationFault> {
    for (field, actual, expected) in [
        (
            "left.profile",
            left.profile(),
            WINDOWS_SUPPLIED_ORDERED_TOPOLOGY_INVENTORY_DIGEST_PROFILE,
        ),
        (
            "right.profile",
            right.profile(),
            WINDOWS_SUPPLIED_ORDERED_TOPOLOGY_INVENTORY_DIGEST_PROFILE,
        ),
        (
            "left.encoding_profile",
            left.encoding_profile(),
            ORDERED_TOPOLOGY_OBSERVATION_ENCODING_PROFILE,
        ),
        (
            "right.encoding_profile",
            right.encoding_profile(),
            ORDERED_TOPOLOGY_OBSERVATION_ENCODING_PROFILE,
        ),
        (
            "left.plan.profile",
            left.plan().profile(),
            WINDOWS_SUPPLIED_ORDERED_TOPOLOGY_INVENTORY_DIGEST_PROFILE,
        ),
        (
            "right.plan.profile",
            right.plan().profile(),
            WINDOWS_SUPPLIED_ORDERED_TOPOLOGY_INVENTORY_DIGEST_PROFILE,
        ),
        (
            "left.plan.encoding_profile",
            left.plan().encoding_profile(),
            ORDERED_TOPOLOGY_OBSERVATION_ENCODING_PROFILE,
        ),
        (
            "right.plan.encoding_profile",
            right.plan().encoding_profile(),
            ORDERED_TOPOLOGY_OBSERVATION_ENCODING_PROFILE,
        ),
        (
            "left.assembly.profile",
            left.assembly().profile(),
            WINDOWS_SUPPLIED_TOPOLOGY_INVENTORY_ASSEMBLY_PROFILE,
        ),
        (
            "right.assembly.profile",
            right.assembly().profile(),
            WINDOWS_SUPPLIED_TOPOLOGY_INVENTORY_ASSEMBLY_PROFILE,
        ),
    ] {
        if actual != expected {
            return Err(
                WindowsSuppliedOrderedTopologyInventoryDigestReconciliationFault::simple(
                    WindowsSuppliedOrderedTopologyInventoryDigestReconciliationFaultCode::ScopeProfile,
                    field,
                    "supplied digest comparison profile is not current and exact",
                ),
            );
        }
    }
    Ok(())
}

fn validate_and_build_scope(
    left: &WindowsSuppliedOrderedTopologyInventoryDigest,
    right: &WindowsSuppliedOrderedTopologyInventoryDigest,
) -> Result<
    WindowsSuppliedOrderedTopologyInventoryDigestReconciliationScope,
    WindowsSuppliedOrderedTopologyInventoryDigestReconciliationFault,
> {
    let left_limits = &left.assembly().plan().limits;
    let right_limits = &right.assembly().plan().limits;
    if left_limits != right_limits {
        return Err(
            WindowsSuppliedOrderedTopologyInventoryDigestReconciliationFault::simple(
                WindowsSuppliedOrderedTopologyInventoryDigestReconciliationFaultCode::Limits,
                "limits",
                "supplied digest operands have unequal complete scan limits",
            ),
        );
    }

    let left_root = left
        .assembly()
        .ordered_members()
        .first()
        .ok_or_else(|| root_fault("left.root", "left assembly has no root member"))?
        .topology_observation();
    let right_root = right
        .assembly()
        .ordered_members()
        .first()
        .ok_or_else(|| root_fault("right.root", "right assembly has no root member"))?
        .topology_observation();

    if left_root.relative_path.is_some() || right_root.relative_path.is_some() {
        return Err(root_fault(
            "root.relative_path",
            "both supplied roots must have absent relative paths",
        ));
    }
    if left_root.kind != TopologyEntryKind::RootDirectory
        || right_root.kind != TopologyEntryKind::RootDirectory
    {
        return Err(root_fault(
            "root.kind",
            "both supplied roots must use the exact root_directory kind",
        ));
    }
    if left_root.identity.volume_serial != right_root.identity.volume_serial {
        return Err(root_fault(
            "root.volume_serial",
            "supplied roots have unequal volume serial identities",
        ));
    }
    if left_root.identity.file_id_hex != right_root.identity.file_id_hex {
        return Err(root_fault(
            "root.file_id",
            "supplied roots have unequal file identities",
        ));
    }

    Ok(
        WindowsSuppliedOrderedTopologyInventoryDigestReconciliationScope {
            encoding_profile: ORDERED_TOPOLOGY_OBSERVATION_ENCODING_PROFILE.to_owned(),
            limits: left_limits.clone(),
            root_relative_path: None,
            root_kind: TopologyEntryKind::RootDirectory,
            root_volume_serial: left_root.identity.volume_serial,
            root_file_id: left_root.identity.file_id_hex.clone(),
        },
    )
}

fn root_fault(
    field: &str,
    message: &str,
) -> WindowsSuppliedOrderedTopologyInventoryDigestReconciliationFault {
    WindowsSuppliedOrderedTopologyInventoryDigestReconciliationFault::simple(
        WindowsSuppliedOrderedTopologyInventoryDigestReconciliationFaultCode::RootScope,
        field,
        message,
    )
}

fn bounded(value: &str, maximum_chars: usize) -> String {
    value.chars().take(maximum_chars).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, PlatformPreflightDisposition,
        StrongFileIdentity, TopologyModeClass, WINDOWS_PLATFORM_PREFLIGHT_PROFILE,
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
        windows_supplied_ordered_topology_inventory_digest::{
            WindowsSuppliedOrderedTopologyInventoryDigestFaultCode,
            decode_windows_supplied_ordered_topology_inventory_digest_plan,
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
            WindowsSuppliedTopologyInventoryAssembly, WindowsSuppliedTopologyInventoryAssemblyPlan,
            assemble_windows_supplied_topology_inventory,
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

    fn plan(identity: u64) -> WindowsSuppliedOrderedTopologyInventoryDigestReconciliationPlan {
        WindowsSuppliedOrderedTopologyInventoryDigestReconciliationPlan {
            profile: WINDOWS_SUPPLIED_ORDERED_TOPOLOGY_INVENTORY_DIGEST_RECONCILIATION_PROFILE
                .to_owned(),
            reconciliation_identity: identity,
        }
    }

    fn digest_plan(
        identity: u64,
    ) -> crate::windows_supplied_ordered_topology_inventory_digest::WindowsSuppliedOrderedTopologyInventoryDigestPlan
    {
        let bytes = serde_json::to_vec(&serde_json::json!({
            "profile": WINDOWS_SUPPLIED_ORDERED_TOPOLOGY_INVENTORY_DIGEST_PROFILE,
            "commitment_identity": identity,
            "encoding_profile": ORDERED_TOPOLOGY_OBSERVATION_ENCODING_PROFILE,
        }))
        .unwrap();
        decode_windows_supplied_ordered_topology_inventory_digest_plan(&bytes).unwrap()
    }

    fn correlation(batch: u64, entry: u64) -> WindowsSuppliedRecordCorrelation {
        WindowsSuppliedRecordCorrelation {
            batch_identity: batch,
            entry_reference_identity: entry,
        }
    }

    fn identity(volume: u64, seed: u8) -> StrongFileIdentity {
        StrongFileIdentity {
            volume_serial: volume,
            file_id_hex: (seed..seed + 16)
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        }
    }

    fn assembly_input(
        batch: u64,
        entry: u64,
        component: &str,
        kind: WindowsEntryPolicyKind,
        volume: u64,
        seed: u8,
        length: u64,
    ) -> WindowsSuppliedEntryAssemblyInput {
        let correlation = correlation(batch, entry);
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
                volume_serial: volume,
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
        entry: u64,
        component: &str,
        kind: WindowsEntryPolicyKind,
        volume: u64,
        seed: u8,
        length: u64,
    ) -> WindowsSuppliedEntryStabilityInput {
        WindowsSuppliedEntryStabilityInput {
            profile: WINDOWS_SUPPLIED_ENTRY_STABILITY_PROFILE.to_owned(),
            reconciliation_identity: entry + 1_000,
            pre_read: assembly_input(entry + 100, entry, component, kind, volume, seed, length),
            post_read: assembly_input(entry + 200, entry, component, kind, volume, seed, length),
        }
    }

    fn root(
        projection: u64,
        entry: u64,
        volume: u64,
        seed: u8,
    ) -> crate::windows_supplied_root_topology_projection::WindowsSuppliedRootTopologyProjection
    {
        let preflight = WindowsPlatformPreflightRecord::CompleteLocal {
            profile: WINDOWS_PLATFORM_PREFLIGHT_PROFILE.to_owned(),
            target_triple: WINDOWS_PLATFORM_PREFLIGHT_TARGET.to_owned(),
            input_root: r"\\?\C:\Cantor".to_owned(),
            root_identity: identity(volume, seed),
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
                projection_identity: projection,
                entry_reference_identity: entry,
            },
            preflight,
            stability_input(
                entry,
                "Cantor",
                WindowsEntryPolicyKind::Directory,
                volume,
                seed,
                0,
            ),
        )
        .unwrap()
    }

    fn directory(
        projection: u64,
        entry: u64,
    ) -> crate::windows_supplied_directory_topology_projection::WindowsSuppliedDirectoryTopologyProjection
    {
        project_windows_supplied_directory_topology(
            WindowsSuppliedDirectoryTopologyProjectionPlan {
                profile: WINDOWS_SUPPLIED_DIRECTORY_TOPOLOGY_PROJECTION_PROFILE.to_owned(),
                projection_identity: projection,
                entry_reference_identity: entry,
                relative_path: "src".to_owned(),
                observation_ordinal: 2,
            },
            stability_input(entry, "src", WindowsEntryPolicyKind::Directory, 19, 16, 0),
        )
        .unwrap()
    }

    fn regular_file(
        projection: u64,
        entry: u64,
        bytes: &[u8],
    ) -> crate::windows_supplied_regular_file_topology_projection::WindowsSuppliedRegularFileTopologyProjection
    {
        let digest_plan = WindowsSuppliedContentDigestPlan {
            profile: WINDOWS_SUPPLIED_CONTENT_DIGEST_PROFILE.to_owned(),
            content_read_identity: entry + 2_000,
            entry_reference_identity: entry,
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
                entry,
                "a.txt",
                WindowsEntryPolicyKind::RegularFile,
                19,
                32,
                u64::try_from(bytes.len()).unwrap(),
            ),
        )
        .unwrap();
        project_windows_supplied_regular_file_topology(
            WindowsSuppliedRegularFileTopologyProjectionPlan {
                profile: WINDOWS_SUPPLIED_REGULAR_FILE_TOPOLOGY_PROJECTION_PROFILE.to_owned(),
                projection_identity: projection,
                entry_reference_identity: entry,
                relative_path: "src/a.txt".to_owned(),
                mode_class: TopologyModeClass::RegularNonExecutable,
                observation_ordinal: 3,
            },
            binding,
        )
        .unwrap()
    }

    fn assembly(
        lineage: u64,
        scan_limits: TopologyScanLimits,
        root_volume: u64,
        root_seed: u8,
        content: Option<&[u8]>,
    ) -> WindowsSuppliedTopologyInventoryAssembly {
        let base = lineage * 100;
        let (directories, files) = match content {
            Some(bytes) => (
                vec![directory(base + 2, base + 12)],
                vec![regular_file(base + 3, base + 13, bytes)],
            ),
            None => (vec![], vec![]),
        };
        assemble_windows_supplied_topology_inventory(
            WindowsSuppliedTopologyInventoryAssemblyPlan {
                profile: WINDOWS_SUPPLIED_TOPOLOGY_INVENTORY_ASSEMBLY_PROFILE.to_owned(),
                assembly_identity: base + 91,
                limits: scan_limits,
            },
            root(base + 1, base + 11, root_volume, root_seed),
            directories,
            files,
        )
        .unwrap()
    }

    fn digest(
        commitment: u64,
        assembly: WindowsSuppliedTopologyInventoryAssembly,
    ) -> WindowsSuppliedOrderedTopologyInventoryDigest {
        derive_windows_supplied_ordered_topology_inventory_digest(digest_plan(commitment), assembly)
            .unwrap()
    }

    #[test]
    fn plan_decode_is_strict_bounded_and_exact() {
        let bytes = serde_json::to_vec(&plan(7)).unwrap();
        let decoded =
            decode_windows_supplied_ordered_topology_inventory_digest_reconciliation_plan(&bytes)
                .unwrap();
        assert_eq!(
            decoded.profile(),
            WINDOWS_SUPPLIED_ORDERED_TOPOLOGY_INVENTORY_DIGEST_RECONCILIATION_PROFILE
        );
        assert_eq!(decoded.reconciliation_identity(), 7);

        for (bytes, code) in [
            (
                br#"{"profile":"wrong","reconciliation_identity":7}"#.as_slice(),
                WindowsSuppliedOrderedTopologyInventoryDigestReconciliationFaultCode::Profile,
            ),
            (
                br#"{"profile":"cantor-windows-supplied-ordered-topology-inventory-digest-reconciliation/0.1","reconciliation_identity":0}"#.as_slice(),
                WindowsSuppliedOrderedTopologyInventoryDigestReconciliationFaultCode::ReconciliationIdentity,
            ),
            (
                br#"{"profile":"cantor-windows-supplied-ordered-topology-inventory-digest-reconciliation/0.1","reconciliation_identity":7,"extra":true}"#.as_slice(),
                WindowsSuppliedOrderedTopologyInventoryDigestReconciliationFaultCode::Json,
            ),
        ] {
            assert_eq!(
                decode_windows_supplied_ordered_topology_inventory_digest_reconciliation_plan(
                    bytes
                )
                .unwrap_err()
                .code,
                code
            );
        }

        let oversized = vec![
            b' ';
            WINDOWS_SUPPLIED_ORDERED_TOPOLOGY_INVENTORY_DIGEST_RECONCILIATION_PLAN_MAX_BYTES
                + 1
        ];
        assert_eq!(
            decode_windows_supplied_ordered_topology_inventory_digest_reconciliation_plan(
                &oversized
            )
            .unwrap_err()
            .code,
            WindowsSuppliedOrderedTopologyInventoryDigestReconciliationFaultCode::Resource
        );
    }

    #[test]
    fn equal_operands_rederive_and_retain_complete_positional_lineage() {
        let left = digest(701, assembly(1, limits(), 19, 0, Some(b"abc")));
        let right = digest(702, assembly(2, limits(), 19, 0, Some(b"abc")));
        let result = reconcile_windows_supplied_ordered_topology_inventory_digests(
            plan(801),
            left.clone(),
            right.clone(),
        )
        .unwrap();

        assert_eq!(
            result.disposition(),
            WindowsSuppliedOrderedTopologyInventoryDigestReconciliationDisposition::Equal
        );
        assert_eq!(result.left(), &left);
        assert_eq!(result.right(), &right);
        assert_ne!(
            result.left().plan().commitment_identity(),
            result.right().plan().commitment_identity()
        );
        assert_ne!(
            result.left().assembly().plan().assembly_identity,
            result.right().assembly().plan().assembly_identity
        );
        assert_eq!(result.plan().reconciliation_identity(), 801);
        assert_eq!(result.common_scope().root_relative_path(), None);
        assert_eq!(
            result.common_scope().root_kind(),
            TopologyEntryKind::RootDirectory
        );
        assert_eq!(result.common_scope().root_volume_serial(), 19);
        assert_eq!(
            result.common_scope().root_file_id(),
            identity(19, 0).file_id_hex
        );
    }

    #[test]
    fn semantic_change_is_different_with_the_same_scope() {
        let left = digest(701, assembly(1, limits(), 19, 0, Some(b"abc")));
        let right = digest(702, assembly(2, limits(), 19, 0, Some(b"abd")));
        let result =
            reconcile_windows_supplied_ordered_topology_inventory_digests(plan(802), left, right)
                .unwrap();
        assert_eq!(
            result.disposition(),
            WindowsSuppliedOrderedTopologyInventoryDigestReconciliationDisposition::Different
        );
        assert_ne!(
            result.left().ordered_inventory_sha256(),
            result.right().ordered_inventory_sha256()
        );
    }

    #[test]
    fn member_count_change_is_different_not_a_scope_failure() {
        let left = digest(701, assembly(1, limits(), 19, 0, None));
        let right = digest(702, assembly(2, limits(), 19, 0, Some(b"abc")));
        let result =
            reconcile_windows_supplied_ordered_topology_inventory_digests(plan(803), left, right)
                .unwrap();
        assert_eq!(result.left().assembly().entry_count(), 1);
        assert_eq!(result.right().assembly().entry_count(), 3);
        assert_eq!(
            result.disposition(),
            WindowsSuppliedOrderedTopologyInventoryDigestReconciliationDisposition::Different
        );
    }

    #[test]
    fn unequal_complete_limits_fail_before_a_relation_is_released() {
        let left_limits = limits();
        let mut right_limits = limits();
        right_limits.maximum_depth += 1;
        let fault = reconcile_windows_supplied_ordered_topology_inventory_digests(
            plan(804),
            digest(701, assembly(1, left_limits, 19, 0, None)),
            digest(702, assembly(2, right_limits, 19, 0, None)),
        )
        .unwrap_err();
        assert_eq!(
            fault.code,
            WindowsSuppliedOrderedTopologyInventoryDigestReconciliationFaultCode::Limits
        );
        assert_eq!(fault.field, "limits");
        assert!(fault.side.is_none());
        assert!(fault.nested_digest_fault.is_none());
    }

    #[test]
    fn unequal_root_strong_identity_is_rejected_as_scope() {
        for (right_volume, right_seed, field) in
            [(20, 0, "root.volume_serial"), (19, 1, "root.file_id")]
        {
            let fault = reconcile_windows_supplied_ordered_topology_inventory_digests(
                plan(805),
                digest(701, assembly(1, limits(), 19, 0, None)),
                digest(702, assembly(2, limits(), right_volume, right_seed, None)),
            )
            .unwrap_err();
            assert_eq!(
                fault.code,
                WindowsSuppliedOrderedTopologyInventoryDigestReconciliationFaultCode::RootScope
            );
            assert_eq!(fault.field, field);
        }
    }

    #[test]
    fn operand_swap_preserves_position_without_temporal_reinterpretation() {
        let first = digest(701, assembly(1, limits(), 19, 0, None));
        let second = digest(702, assembly(2, limits(), 19, 0, Some(b"abc")));
        let forward = reconcile_windows_supplied_ordered_topology_inventory_digests(
            plan(806),
            first.clone(),
            second.clone(),
        )
        .unwrap();
        let reverse = reconcile_windows_supplied_ordered_topology_inventory_digests(
            plan(807),
            second.clone(),
            first.clone(),
        )
        .unwrap();

        assert_eq!(forward.left(), &first);
        assert_eq!(forward.right(), &second);
        assert_eq!(reverse.left(), &second);
        assert_eq!(reverse.right(), &first);
        assert_eq!(forward.disposition(), reverse.disposition());
    }

    #[test]
    fn decode_and_reconcile_matches_the_typed_entry_point() {
        let left = digest(701, assembly(1, limits(), 19, 0, None));
        let right = digest(702, assembly(2, limits(), 19, 0, None));
        let expected = reconcile_windows_supplied_ordered_topology_inventory_digests(
            plan(808),
            left.clone(),
            right.clone(),
        )
        .unwrap();
        let bytes = serde_json::to_vec(&plan(808)).unwrap();
        let decoded = decode_and_reconcile_windows_supplied_ordered_topology_inventory_digests(
            &bytes, left, right,
        )
        .unwrap();
        assert_eq!(decoded, expected);
    }

    #[test]
    fn serialization_is_complete_repeatable_and_output_only() {
        let result = reconcile_windows_supplied_ordered_topology_inventory_digests(
            plan(809),
            digest(701, assembly(1, limits(), 19, 0, None)),
            digest(702, assembly(2, limits(), 19, 0, None)),
        )
        .unwrap();
        let first = serde_json::to_vec(&result).unwrap();
        let second = serde_json::to_vec(&result).unwrap();
        assert_eq!(first, second);
        let value: serde_json::Value = serde_json::from_slice(&first).unwrap();
        assert_eq!(
            value["profile"],
            WINDOWS_SUPPLIED_ORDERED_TOPOLOGY_INVENTORY_DIGEST_RECONCILIATION_PROFILE
        );
        assert_eq!(value["disposition"], "equal");
        assert_eq!(value["common_scope"]["root_kind"], "root_directory");
        assert_eq!(value["left"]["plan"]["commitment_identity"], 701);
        assert_eq!(value["right"]["plan"]["commitment_identity"], 702);
    }

    #[test]
    fn faults_are_bounded_and_nested_digest_failures_are_exact() {
        let simple = WindowsSuppliedOrderedTopologyInventoryDigestReconciliationFault::simple(
            WindowsSuppliedOrderedTopologyInventoryDigestReconciliationFaultCode::Internal,
            &"f".repeat(100),
            &"m".repeat(300),
        );
        assert_eq!(simple.field.chars().count(), 64);
        assert_eq!(simple.message.chars().count(), 256);
        assert!(simple.side.is_none());

        let nested = WindowsSuppliedOrderedTopologyInventoryDigestFault {
            code: WindowsSuppliedOrderedTopologyInventoryDigestFaultCode::Internal,
            nested_topology_fault: None,
            field: "digest".to_owned(),
            message: "synthetic current-rederivation failure".to_owned(),
        };
        let wrapped = WindowsSuppliedOrderedTopologyInventoryDigestReconciliationFault::digest(
            WindowsSuppliedOrderedTopologyInventoryDigestReconciliationSide::Left,
            nested.clone(),
        );
        assert_eq!(
            wrapped.code,
            WindowsSuppliedOrderedTopologyInventoryDigestReconciliationFaultCode::LeftDigest
        );
        assert_eq!(
            wrapped.side,
            Some(WindowsSuppliedOrderedTopologyInventoryDigestReconciliationSide::Left)
        );
        assert_eq!(wrapped.nested_digest_fault.as_deref(), Some(&nested));
    }
}
