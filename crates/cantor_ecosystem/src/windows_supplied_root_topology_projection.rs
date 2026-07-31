//! Pure structural projection of one revalidated supplied root correlation.
//!
//! Successful output proves only that current pure preflight, stability, and
//! M2A validators accepted complete caller-supplied values and that exact
//! reference, identity, and component joins passed. It does not prove runtime
//! origin, a physical root or path, handle continuity, enumeration, traversal,
//! inventory completeness, receipt, admission, or mutation safety.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    PlatformPreflightDisposition, PlatformPreflightFormFault, TopologyEntryKind,
    TopologyEntryObservation, TopologyFormFault, TopologyModeClass, ValidatePlatformPreflightForm,
    ValidateTopologyForm, WindowsPlatformPreflightRecord,
    windows_supplied_entry_stability::{
        WindowsSuppliedEntryStabilityFault, WindowsSuppliedEntryStabilityInput,
        WindowsSuppliedEntryStablePair, reconcile_windows_supplied_entry_stability,
    },
};

pub const WINDOWS_SUPPLIED_ROOT_TOPOLOGY_PROJECTION_PROFILE: &str =
    "cantor-windows-supplied-root-topology-projection/0.1";
pub const WINDOWS_SUPPLIED_ROOT_TOPOLOGY_PROJECTION_PLAN_MAX_BYTES: usize = 4_096;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsSuppliedRootTopologyProjectionPlan {
    pub profile: String,
    pub projection_identity: u64,
    pub entry_reference_identity: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsSuppliedRootTopologyProjectionFaultCode {
    Json,
    Profile,
    ProjectionIdentity,
    EntryReferenceIdentity,
    Preflight,
    PreflightDisposition,
    Stability,
    EntryReference,
    Kind,
    Identity,
    InputRootComponent,
    FinalPathComponent,
    Component,
    TopologyForm,
    Resource,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsSuppliedRootTopologyProjectionFault {
    pub code: WindowsSuppliedRootTopologyProjectionFaultCode,
    pub nested_preflight_fault: Option<Box<PlatformPreflightFormFault>>,
    pub nested_stability_fault: Option<Box<WindowsSuppliedEntryStabilityFault>>,
    pub nested_topology_fault: Option<Box<TopologyFormFault>>,
    pub field: String,
    pub message: String,
}

impl WindowsSuppliedRootTopologyProjectionFault {
    fn simple(
        code: WindowsSuppliedRootTopologyProjectionFaultCode,
        field: &str,
        message: &str,
    ) -> Self {
        Self {
            code,
            nested_preflight_fault: None,
            nested_stability_fault: None,
            nested_topology_fault: None,
            field: bounded(field, 64),
            message: bounded(message, 256),
        }
    }

    fn preflight(fault: PlatformPreflightFormFault) -> Self {
        let message = format!("platform preflight form rejected: {fault}");
        Self {
            code: WindowsSuppliedRootTopologyProjectionFaultCode::Preflight,
            nested_preflight_fault: Some(Box::new(fault)),
            nested_stability_fault: None,
            nested_topology_fault: None,
            field: "preflight_record".to_owned(),
            message: bounded(&message, 256),
        }
    }

    fn stability(fault: WindowsSuppliedEntryStabilityFault) -> Self {
        let message = format!("supplied-entry stability rejected: {fault}");
        Self {
            code: WindowsSuppliedRootTopologyProjectionFaultCode::Stability,
            nested_preflight_fault: None,
            nested_stability_fault: Some(Box::new(fault)),
            nested_topology_fault: None,
            field: "stability_input".to_owned(),
            message: bounded(&message, 256),
        }
    }

    fn topology(fault: TopologyFormFault) -> Self {
        let message = format!("topology form rejected: {fault}");
        Self {
            code: WindowsSuppliedRootTopologyProjectionFaultCode::TopologyForm,
            nested_preflight_fault: None,
            nested_stability_fault: None,
            nested_topology_fault: Some(Box::new(fault)),
            field: "topology_observation".to_owned(),
            message: bounded(&message, 256),
        }
    }
}

impl fmt::Display for WindowsSuppliedRootTopologyProjectionFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl std::error::Error for WindowsSuppliedRootTopologyProjectionFault {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WindowsSuppliedRootTopologyProjection {
    profile: String,
    plan: WindowsSuppliedRootTopologyProjectionPlan,
    preflight_record: WindowsPlatformPreflightRecord,
    stable_pair: WindowsSuppliedEntryStablePair,
    topology_observation: TopologyEntryObservation,
}

impl WindowsSuppliedRootTopologyProjection {
    pub fn profile(&self) -> &str {
        &self.profile
    }
    pub fn plan(&self) -> &WindowsSuppliedRootTopologyProjectionPlan {
        &self.plan
    }
    pub fn preflight_record(&self) -> &WindowsPlatformPreflightRecord {
        &self.preflight_record
    }
    pub fn stable_pair(&self) -> &WindowsSuppliedEntryStablePair {
        &self.stable_pair
    }
    pub fn topology_observation(&self) -> &TopologyEntryObservation {
        &self.topology_observation
    }
}

pub fn decode_windows_supplied_root_topology_projection_plan(
    bytes: &[u8],
) -> Result<WindowsSuppliedRootTopologyProjectionPlan, WindowsSuppliedRootTopologyProjectionFault> {
    if bytes.len() > WINDOWS_SUPPLIED_ROOT_TOPOLOGY_PROJECTION_PLAN_MAX_BYTES {
        return Err(WindowsSuppliedRootTopologyProjectionFault::simple(
            WindowsSuppliedRootTopologyProjectionFaultCode::Resource,
            "json",
            "encoded supplied root projection plan exceeds 4096 bytes",
        ));
    }
    let plan: WindowsSuppliedRootTopologyProjectionPlan =
        serde_json::from_slice(bytes).map_err(|error| {
            WindowsSuppliedRootTopologyProjectionFault::simple(
                WindowsSuppliedRootTopologyProjectionFaultCode::Json,
                "json",
                &error.to_string(),
            )
        })?;
    validate_plan(&plan)?;
    Ok(plan)
}

pub fn decode_and_project_windows_supplied_root_topology(
    bytes: &[u8],
    preflight_record: WindowsPlatformPreflightRecord,
    stability_input: WindowsSuppliedEntryStabilityInput,
) -> Result<WindowsSuppliedRootTopologyProjection, WindowsSuppliedRootTopologyProjectionFault> {
    let plan = decode_windows_supplied_root_topology_projection_plan(bytes)?;
    project_windows_supplied_root_topology(plan, preflight_record, stability_input)
}

pub fn project_windows_supplied_root_topology(
    plan: WindowsSuppliedRootTopologyProjectionPlan,
    preflight_record: WindowsPlatformPreflightRecord,
    stability_input: WindowsSuppliedEntryStabilityInput,
) -> Result<WindowsSuppliedRootTopologyProjection, WindowsSuppliedRootTopologyProjectionFault> {
    validate_plan(&plan)?;
    preflight_record
        .validate()
        .map_err(WindowsSuppliedRootTopologyProjectionFault::preflight)?;

    let (input_root, root_identity, root_volume_guid_path) = match &preflight_record {
        WindowsPlatformPreflightRecord::CompleteLocal {
            input_root,
            root_identity,
            root_volume_guid_path,
            disposition: PlatformPreflightDisposition::EligibleLocalNtfs,
            ..
        } => (
            input_root.clone(),
            root_identity.clone(),
            root_volume_guid_path.clone(),
        ),
        _ => {
            return Err(WindowsSuppliedRootTopologyProjectionFault::simple(
                WindowsSuppliedRootTopologyProjectionFaultCode::PreflightDisposition,
                "preflight_record",
                "supplied root projection requires exact eligible CompleteLocal preflight",
            ));
        }
    };

    let stable_pair = reconcile_windows_supplied_entry_stability(stability_input)
        .map_err(WindowsSuppliedRootTopologyProjectionFault::stability)?;
    if plan.entry_reference_identity != stable_pair.entry_reference_identity {
        return Err(WindowsSuppliedRootTopologyProjectionFault::simple(
            WindowsSuppliedRootTopologyProjectionFaultCode::EntryReference,
            "entry_reference_identity",
            "projection plan and revalidated stable-pair entry references differ",
        ));
    }

    let seed = stable_pair.pre_read.topology_projection_seed();
    if seed.kind != TopologyEntryKind::Directory {
        return Err(WindowsSuppliedRootTopologyProjectionFault::simple(
            WindowsSuppliedRootTopologyProjectionFaultCode::Kind,
            "stable_pair.pre_read.kind",
            "supplied root projection requires a directory seed",
        ));
    }
    if seed.identity != root_identity {
        return Err(WindowsSuppliedRootTopologyProjectionFault::simple(
            WindowsSuppliedRootTopologyProjectionFaultCode::Identity,
            "root_identity",
            "preflight root identity and stable directory identity differ",
        ));
    }

    let input_component = final_component(
        &input_root,
        WindowsSuppliedRootTopologyProjectionFaultCode::InputRootComponent,
        "preflight_record.input_root",
        "validated input root does not name a non-drive-root final component",
    )?;
    let final_path_component = final_component(
        &root_volume_guid_path,
        WindowsSuppliedRootTopologyProjectionFaultCode::FinalPathComponent,
        "preflight_record.root_volume_guid_path",
        "validated volume-GUID path does not name a nonempty final component",
    )?;
    let stable_component = stable_pair.pre_read.policy_decision.component.as_str();
    if input_component != stable_component || final_path_component != stable_component {
        return Err(WindowsSuppliedRootTopologyProjectionFault::simple(
            WindowsSuppliedRootTopologyProjectionFaultCode::Component,
            "root_component",
            "input-root and volume-GUID final components must both equal the stable policy component",
        ));
    }

    let topology_observation = TopologyEntryObservation {
        relative_path: None,
        kind: TopologyEntryKind::RootDirectory,
        mode_class: TopologyModeClass::Directory,
        attributes: seed.attributes,
        identity: seed.identity,
        number_of_links: seed.number_of_links,
        streams: seed.streams,
        length: None,
        content_sha256: None,
        observation_ordinal: 1,
    };
    topology_observation
        .validate()
        .map_err(WindowsSuppliedRootTopologyProjectionFault::topology)?;

    Ok(WindowsSuppliedRootTopologyProjection {
        profile: WINDOWS_SUPPLIED_ROOT_TOPOLOGY_PROJECTION_PROFILE.to_owned(),
        plan,
        preflight_record,
        stable_pair,
        topology_observation,
    })
}

fn validate_plan(
    plan: &WindowsSuppliedRootTopologyProjectionPlan,
) -> Result<(), WindowsSuppliedRootTopologyProjectionFault> {
    if plan.profile != WINDOWS_SUPPLIED_ROOT_TOPOLOGY_PROJECTION_PROFILE {
        return Err(WindowsSuppliedRootTopologyProjectionFault::simple(
            WindowsSuppliedRootTopologyProjectionFaultCode::Profile,
            "profile",
            "profile is not the exact supported supplied root projection profile",
        ));
    }
    if plan.projection_identity == 0 {
        return Err(WindowsSuppliedRootTopologyProjectionFault::simple(
            WindowsSuppliedRootTopologyProjectionFaultCode::ProjectionIdentity,
            "projection_identity",
            "projection identity must be nonzero caller syntax",
        ));
    }
    if plan.entry_reference_identity == 0 {
        return Err(WindowsSuppliedRootTopologyProjectionFault::simple(
            WindowsSuppliedRootTopologyProjectionFaultCode::EntryReferenceIdentity,
            "entry_reference_identity",
            "entry-reference identity must be nonzero caller syntax",
        ));
    }
    Ok(())
}

fn final_component<'a>(
    path: &'a str,
    code: WindowsSuppliedRootTopologyProjectionFaultCode,
    field: &str,
    message: &str,
) -> Result<&'a str, WindowsSuppliedRootTopologyProjectionFault> {
    path.rsplit('\\')
        .next()
        .filter(|component| !component.is_empty())
        .ok_or_else(|| WindowsSuppliedRootTopologyProjectionFault::simple(code, field, message))
}

fn bounded(value: &str, maximum_scalars: usize) -> String {
    value.chars().take(maximum_scalars).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, PlatformPreflightFormFaultCode,
        TopologyFormFaultCode, WINDOWS_PLATFORM_PREFLIGHT_PROFILE,
        WINDOWS_PLATFORM_PREFLIGHT_TARGET, WindowsEntryPolicyKind, WindowsRawStreamRecord,
        WindowsVolumeInformation,
        windows_supplied_entry_observation::{
            WINDOWS_SUPPLIED_ENTRY_OBSERVATION_PROFILE, WindowsSuppliedAttributeTagRecord,
            WindowsSuppliedCaseSensitivityRecord, WindowsSuppliedDirectoryCaseFlags,
            WindowsSuppliedEntryAssemblyInput, WindowsSuppliedFileIdentityRecord,
            WindowsSuppliedOrderedStreamRecords, WindowsSuppliedRecordCorrelation,
            WindowsSuppliedStandardInformationRecord, WindowsSuppliedStreamSet,
        },
        windows_supplied_entry_stability::{
            WINDOWS_SUPPLIED_ENTRY_STABILITY_PROFILE, WindowsSuppliedEntryStabilityFaultCode,
        },
    };

    const GUID_ROOT: &str = r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\";

    fn plan() -> WindowsSuppliedRootTopologyProjectionPlan {
        WindowsSuppliedRootTopologyProjectionPlan {
            profile: WINDOWS_SUPPLIED_ROOT_TOPOLOGY_PROJECTION_PROFILE.to_owned(),
            projection_identity: 53,
            entry_reference_identity: 11,
        }
    }

    fn correlation(batch_identity: u64) -> WindowsSuppliedRecordCorrelation {
        WindowsSuppliedRecordCorrelation {
            batch_identity,
            entry_reference_identity: 11,
        }
    }

    fn identity() -> crate::StrongFileIdentity {
        crate::StrongFileIdentity {
            volume_serial: 19,
            file_id_hex: "000102030405060708090a0b0c0d0e0f".to_owned(),
        }
    }

    fn assembly_input(
        batch_identity: u64,
        kind: WindowsEntryPolicyKind,
        long_stream: bool,
    ) -> WindowsSuppliedEntryAssemblyInput {
        let correlation = correlation(batch_identity);
        let directory = kind == WindowsEntryPolicyKind::Directory;
        let streams = if long_stream {
            WindowsSuppliedStreamSet::OrderedRecords(WindowsSuppliedOrderedStreamRecords {
                correlation,
                records: vec![WindowsRawStreamRecord {
                    name: format!(":{}:$DATA", "a".repeat(1_024)),
                    stream_size: 0,
                    allocation_size: 0,
                    source_offset: 0,
                }],
            })
        } else {
            WindowsSuppliedStreamSet::ExplicitEmpty(correlation)
        };
        WindowsSuppliedEntryAssemblyInput {
            profile: WINDOWS_SUPPLIED_ENTRY_OBSERVATION_PROFILE.to_owned(),
            kind,
            component: "Cantor".to_owned(),
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
                volume_serial: 19,
                file_id_bytes: (0_u8..16).collect(),
            },
            standard: WindowsSuppliedStandardInformationRecord {
                correlation,
                allocation_size: 0,
                end_of_file: 0,
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
            streams,
        }
    }

    fn stability_input(
        kind: WindowsEntryPolicyKind,
        long_stream: bool,
    ) -> WindowsSuppliedEntryStabilityInput {
        WindowsSuppliedEntryStabilityInput {
            profile: WINDOWS_SUPPLIED_ENTRY_STABILITY_PROFILE.to_owned(),
            reconciliation_identity: 31,
            pre_read: assembly_input(7, kind, long_stream),
            post_read: assembly_input(8, kind, long_stream),
        }
    }

    fn preflight(
        input_root: &str,
        final_path: &str,
        file_system: &str,
        disposition: PlatformPreflightDisposition,
    ) -> WindowsPlatformPreflightRecord {
        WindowsPlatformPreflightRecord::CompleteLocal {
            profile: WINDOWS_PLATFORM_PREFLIGHT_PROFILE.to_owned(),
            target_triple: WINDOWS_PLATFORM_PREFLIGHT_TARGET.to_owned(),
            input_root: input_root.to_owned(),
            root_identity: identity(),
            root_volume_guid_path: final_path.to_owned(),
            volume: WindowsVolumeInformation {
                volume_name: "Work".to_owned(),
                volume_serial_number: 42,
                maximum_component_length: 255,
                file_system_flags: 0,
                file_system_name: file_system.to_owned(),
            },
            disposition,
        }
    }

    fn valid_preflight() -> WindowsPlatformPreflightRecord {
        preflight(
            r"\\?\C:\Project\Cantor",
            &format!("{GUID_ROOT}Project\\Cantor"),
            "NTFS",
            PlatformPreflightDisposition::EligibleLocalNtfs,
        )
    }

    #[test]
    fn strict_plan_decode_and_identity_gates_are_exact() {
        let encoded = serde_json::to_vec(&plan()).unwrap();
        assert_eq!(
            decode_windows_supplied_root_topology_projection_plan(&encoded).unwrap(),
            plan()
        );
        let unknown = String::from_utf8(encoded)
            .unwrap()
            .replacen('{', "{\"extra\":true,", 1);
        assert_eq!(
            decode_windows_supplied_root_topology_projection_plan(unknown.as_bytes())
                .unwrap_err()
                .code,
            WindowsSuppliedRootTopologyProjectionFaultCode::Json
        );
        assert_eq!(
            decode_windows_supplied_root_topology_projection_plan(&vec![b' '; 4_097])
                .unwrap_err()
                .code,
            WindowsSuppliedRootTopologyProjectionFaultCode::Resource
        );
        let mut wrong = plan();
        wrong.profile = "other".to_owned();
        assert_eq!(
            project_windows_supplied_root_topology(
                wrong,
                valid_preflight(),
                stability_input(WindowsEntryPolicyKind::Directory, false)
            )
            .unwrap_err()
            .code,
            WindowsSuppliedRootTopologyProjectionFaultCode::Profile
        );
        let mut zero = plan();
        zero.projection_identity = 0;
        assert_eq!(
            project_windows_supplied_root_topology(
                zero,
                valid_preflight(),
                stability_input(WindowsEntryPolicyKind::Directory, false)
            )
            .unwrap_err()
            .code,
            WindowsSuppliedRootTopologyProjectionFaultCode::ProjectionIdentity
        );
        let mut zero = plan();
        zero.entry_reference_identity = 0;
        assert_eq!(
            project_windows_supplied_root_topology(
                zero,
                valid_preflight(),
                stability_input(WindowsEntryPolicyKind::Directory, false)
            )
            .unwrap_err()
            .code,
            WindowsSuppliedRootTopologyProjectionFaultCode::EntryReferenceIdentity
        );
    }

    #[test]
    fn current_preflight_fault_is_preserved() {
        let mut invalid = valid_preflight();
        if let WindowsPlatformPreflightRecord::CompleteLocal { profile, .. } = &mut invalid {
            *profile = "bad".to_owned();
        }
        let fault = project_windows_supplied_root_topology(
            plan(),
            invalid,
            stability_input(WindowsEntryPolicyKind::Directory, false),
        )
        .unwrap_err();
        assert_eq!(
            fault.code,
            WindowsSuppliedRootTopologyProjectionFaultCode::Preflight
        );
        assert_eq!(
            fault.nested_preflight_fault.unwrap().code,
            PlatformPreflightFormFaultCode::Profile
        );
    }

    #[test]
    fn valid_but_ineligible_or_noncomplete_preflight_rejects() {
        let unsupported = preflight(
            r"\\?\C:\Project\Cantor",
            &format!("{GUID_ROOT}Project\\Cantor"),
            "ReFS",
            PlatformPreflightDisposition::RejectUnsupportedFileSystem,
        );
        assert_eq!(
            project_windows_supplied_root_topology(
                plan(),
                unsupported,
                stability_input(WindowsEntryPolicyKind::Directory, false)
            )
            .unwrap_err()
            .code,
            WindowsSuppliedRootTopologyProjectionFaultCode::PreflightDisposition
        );
        let fault = WindowsPlatformPreflightRecord::OpenFault {
            profile: WINDOWS_PLATFORM_PREFLIGHT_PROFILE.to_owned(),
            target_triple: WINDOWS_PLATFORM_PREFLIGHT_TARGET.to_owned(),
            input_root: r"\\?\C:\Project\Cantor".to_owned(),
            error_code: 5,
        };
        assert_eq!(
            project_windows_supplied_root_topology(
                plan(),
                fault,
                stability_input(WindowsEntryPolicyKind::Directory, false)
            )
            .unwrap_err()
            .code,
            WindowsSuppliedRootTopologyProjectionFaultCode::PreflightDisposition
        );
    }

    #[test]
    fn current_stability_fault_is_preserved() {
        let mut invalid = stability_input(WindowsEntryPolicyKind::Directory, false);
        invalid.pre_read.profile = "bad".to_owned();
        let fault =
            project_windows_supplied_root_topology(plan(), valid_preflight(), invalid).unwrap_err();
        assert_eq!(
            fault.code,
            WindowsSuppliedRootTopologyProjectionFaultCode::Stability
        );
        assert_eq!(
            fault.nested_stability_fault.unwrap().code,
            WindowsSuppliedEntryStabilityFaultCode::PreRead
        );
    }

    #[test]
    fn reference_and_directory_kind_are_separate_gates() {
        let mut mismatch = plan();
        mismatch.entry_reference_identity = 12;
        assert_eq!(
            project_windows_supplied_root_topology(
                mismatch,
                valid_preflight(),
                stability_input(WindowsEntryPolicyKind::Directory, false)
            )
            .unwrap_err()
            .code,
            WindowsSuppliedRootTopologyProjectionFaultCode::EntryReference
        );
        assert_eq!(
            project_windows_supplied_root_topology(
                plan(),
                valid_preflight(),
                stability_input(WindowsEntryPolicyKind::RegularFile, false)
            )
            .unwrap_err()
            .code,
            WindowsSuppliedRootTopologyProjectionFaultCode::Kind
        );
    }

    #[test]
    fn complete_strong_identity_must_match() {
        let mut mismatch = valid_preflight();
        if let WindowsPlatformPreflightRecord::CompleteLocal { root_identity, .. } = &mut mismatch {
            root_identity.volume_serial = 20;
        }
        assert_eq!(
            project_windows_supplied_root_topology(
                plan(),
                mismatch,
                stability_input(WindowsEntryPolicyKind::Directory, false)
            )
            .unwrap_err()
            .code,
            WindowsSuppliedRootTopologyProjectionFaultCode::Identity
        );
    }

    #[test]
    fn drive_root_and_volume_root_components_reject_distinctly() {
        let drive = preflight(
            r"\\?\C:\",
            &format!("{GUID_ROOT}Cantor"),
            "NTFS",
            PlatformPreflightDisposition::EligibleLocalNtfs,
        );
        assert_eq!(
            project_windows_supplied_root_topology(
                plan(),
                drive,
                stability_input(WindowsEntryPolicyKind::Directory, false)
            )
            .unwrap_err()
            .code,
            WindowsSuppliedRootTopologyProjectionFaultCode::InputRootComponent
        );
        let volume = preflight(
            r"\\?\C:\Cantor",
            GUID_ROOT,
            "NTFS",
            PlatformPreflightDisposition::EligibleLocalNtfs,
        );
        assert_eq!(
            project_windows_supplied_root_topology(
                plan(),
                volume,
                stability_input(WindowsEntryPolicyKind::Directory, false)
            )
            .unwrap_err()
            .code,
            WindowsSuppliedRootTopologyProjectionFaultCode::FinalPathComponent
        );
    }

    #[test]
    fn both_components_must_match_exactly() {
        let mismatch = preflight(
            r"\\?\C:\Project\Other",
            &format!("{GUID_ROOT}Project\\Other"),
            "NTFS",
            PlatformPreflightDisposition::EligibleLocalNtfs,
        );
        assert_eq!(
            project_windows_supplied_root_topology(
                plan(),
                mismatch,
                stability_input(WindowsEntryPolicyKind::Directory, false)
            )
            .unwrap_err()
            .code,
            WindowsSuppliedRootTopologyProjectionFaultCode::Component
        );
    }

    #[test]
    fn current_m2a_validation_fault_is_preserved() {
        let fault = project_windows_supplied_root_topology(
            plan(),
            valid_preflight(),
            stability_input(WindowsEntryPolicyKind::Directory, true),
        )
        .unwrap_err();
        assert_eq!(
            fault.code,
            WindowsSuppliedRootTopologyProjectionFaultCode::TopologyForm
        );
        assert_eq!(
            fault.nested_topology_fault.unwrap().code,
            TopologyFormFaultCode::Text
        );
    }

    #[test]
    fn valid_projection_maps_fixed_root_shape_and_preserves_lineage() {
        let preflight = valid_preflight();
        let projected = project_windows_supplied_root_topology(
            plan(),
            preflight.clone(),
            stability_input(WindowsEntryPolicyKind::Directory, false),
        )
        .unwrap();
        assert_eq!(
            projected.profile(),
            WINDOWS_SUPPLIED_ROOT_TOPOLOGY_PROJECTION_PROFILE
        );
        assert_eq!(projected.plan(), &plan());
        assert_eq!(projected.preflight_record(), &preflight);
        assert_eq!(projected.stable_pair().entry_reference_identity, 11);
        let root = projected.topology_observation();
        assert_eq!(root.relative_path, None);
        assert_eq!(root.kind, TopologyEntryKind::RootDirectory);
        assert_eq!(root.mode_class, TopologyModeClass::Directory);
        assert_eq!(root.attributes, FILE_ATTRIBUTE_DIRECTORY);
        assert_eq!(root.identity, identity());
        assert_eq!(root.number_of_links, 1);
        assert!(root.streams.is_empty());
        assert_eq!(root.length, None);
        assert_eq!(root.content_sha256, None);
        assert_eq!(root.observation_ordinal, 1);
    }

    #[test]
    fn decode_projection_serializes_complete_inputs_and_bounds_faults() {
        let projected = decode_and_project_windows_supplied_root_topology(
            &serde_json::to_vec(&plan()).unwrap(),
            valid_preflight(),
            stability_input(WindowsEntryPolicyKind::Directory, false),
        )
        .unwrap();
        let value = serde_json::to_value(projected).unwrap();
        assert_eq!(value["preflight_record"]["outcome"], "complete_local");
        assert_eq!(value["stable_pair"]["entry_reference_identity"], 11);
        assert_eq!(value["topology_observation"]["kind"], "root_directory");
        let long = "x".repeat(400);
        let fault = WindowsSuppliedRootTopologyProjectionFault::simple(
            WindowsSuppliedRootTopologyProjectionFaultCode::Resource,
            &long,
            &long,
        );
        assert_eq!(fault.field.chars().count(), 64);
        assert_eq!(fault.message.chars().count(), 256);
    }
}
