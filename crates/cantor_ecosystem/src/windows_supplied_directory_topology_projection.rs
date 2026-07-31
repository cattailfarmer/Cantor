//! Pure structural placement of one revalidated supplied directory pair.
//!
//! A successful value proves that current supplied-entry assembly and stability
//! rules accepted the caller's values and that the resulting directory seed,
//! caller placement, and current M2A form agree structurally. It does not prove
//! a physical directory, path, handle, time order, enumeration, traversal,
//! inventory, stream completeness, receipt, admission, or mutation safety.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    TopologyEntryKind, TopologyEntryObservation, TopologyFormFault, TopologyModeClass,
    ValidateTopologyForm,
    windows_supplied_entry_stability::{
        WindowsSuppliedEntryStabilityFault, WindowsSuppliedEntryStabilityInput,
        WindowsSuppliedEntryStablePair, reconcile_windows_supplied_entry_stability,
    },
};

/// Closed profile implemented by this pure supplied-value projection.
pub const WINDOWS_SUPPLIED_DIRECTORY_TOPOLOGY_PROJECTION_PROFILE: &str =
    "cantor-windows-supplied-directory-topology-projection/0.1";
/// Maximum accepted encoded placement plan size before JSON decoding.
pub const WINDOWS_SUPPLIED_DIRECTORY_TOPOLOGY_PROJECTION_PLAN_MAX_BYTES: usize = 262_144;

/// Strict caller-declared placement syntax for one supplied directory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsSuppliedDirectoryTopologyProjectionPlan {
    pub profile: String,
    pub projection_identity: u64,
    pub entry_reference_identity: u64,
    pub relative_path: String,
    pub observation_ordinal: u64,
}

/// Closed supplied-directory projection failure vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsSuppliedDirectoryTopologyProjectionFaultCode {
    Json,
    Profile,
    ProjectionIdentity,
    EntryReferenceIdentity,
    Stability,
    EntryReference,
    Kind,
    TopologyForm,
    Component,
    Ordinal,
    Resource,
}

/// Deterministic bounded fault released without partial successful projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsSuppliedDirectoryTopologyProjectionFault {
    pub code: WindowsSuppliedDirectoryTopologyProjectionFaultCode,
    pub nested_stability_fault: Option<Box<WindowsSuppliedEntryStabilityFault>>,
    pub nested_topology_fault: Option<Box<TopologyFormFault>>,
    pub field: String,
    pub message: String,
}

impl WindowsSuppliedDirectoryTopologyProjectionFault {
    fn simple(
        code: WindowsSuppliedDirectoryTopologyProjectionFaultCode,
        field: &str,
        message: &str,
    ) -> Self {
        Self {
            code,
            nested_stability_fault: None,
            nested_topology_fault: None,
            field: bounded(field, 64),
            message: bounded(message, 256),
        }
    }

    fn stability(fault: WindowsSuppliedEntryStabilityFault) -> Self {
        let message = format!("supplied-entry stability rejected: {fault}");
        Self {
            code: WindowsSuppliedDirectoryTopologyProjectionFaultCode::Stability,
            nested_stability_fault: Some(Box::new(fault)),
            nested_topology_fault: None,
            field: "stability_input".to_owned(),
            message: bounded(&message, 256),
        }
    }

    fn topology(fault: TopologyFormFault) -> Self {
        let message = format!("topology form rejected: {fault}");
        Self {
            code: WindowsSuppliedDirectoryTopologyProjectionFaultCode::TopologyForm,
            nested_stability_fault: None,
            nested_topology_fault: Some(Box::new(fault)),
            field: "topology_observation".to_owned(),
            message: bounded(&message, 256),
        }
    }
}

impl fmt::Display for WindowsSuppliedDirectoryTopologyProjectionFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl std::error::Error for WindowsSuppliedDirectoryTopologyProjectionFault {}

/// Output-only complete structural projection retaining its exact lineage.
///
/// Private fields and the absence of `Deserialize`, `Default`, public
/// constructors, and downgrade conversions keep success on the validated path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WindowsSuppliedDirectoryTopologyProjection {
    profile: String,
    plan: WindowsSuppliedDirectoryTopologyProjectionPlan,
    stable_pair: WindowsSuppliedEntryStablePair,
    topology_observation: TopologyEntryObservation,
}

impl WindowsSuppliedDirectoryTopologyProjection {
    pub fn profile(&self) -> &str {
        &self.profile
    }

    pub fn plan(&self) -> &WindowsSuppliedDirectoryTopologyProjectionPlan {
        &self.plan
    }

    pub fn stable_pair(&self) -> &WindowsSuppliedEntryStablePair {
        &self.stable_pair
    }

    pub fn topology_observation(&self) -> &TopologyEntryObservation {
        &self.topology_observation
    }
}

/// Strictly decodes and validates one bounded caller placement plan.
pub fn decode_windows_supplied_directory_topology_projection_plan(
    bytes: &[u8],
) -> Result<
    WindowsSuppliedDirectoryTopologyProjectionPlan,
    WindowsSuppliedDirectoryTopologyProjectionFault,
> {
    if bytes.len() > WINDOWS_SUPPLIED_DIRECTORY_TOPOLOGY_PROJECTION_PLAN_MAX_BYTES {
        return Err(WindowsSuppliedDirectoryTopologyProjectionFault::simple(
            WindowsSuppliedDirectoryTopologyProjectionFaultCode::Resource,
            "json",
            "encoded supplied directory placement plan exceeds 262144 bytes",
        ));
    }
    let plan: WindowsSuppliedDirectoryTopologyProjectionPlan = serde_json::from_slice(bytes)
        .map_err(|error| {
            WindowsSuppliedDirectoryTopologyProjectionFault::simple(
                WindowsSuppliedDirectoryTopologyProjectionFaultCode::Json,
                "json",
                &error.to_string(),
            )
        })?;
    validate_plan(&plan)?;
    Ok(plan)
}

/// Decodes a placement plan and applies the pure projection in one call.
pub fn decode_and_project_windows_supplied_directory_topology(
    bytes: &[u8],
    stability_input: WindowsSuppliedEntryStabilityInput,
) -> Result<
    WindowsSuppliedDirectoryTopologyProjection,
    WindowsSuppliedDirectoryTopologyProjectionFault,
> {
    let plan = decode_windows_supplied_directory_topology_projection_plan(bytes)?;
    project_windows_supplied_directory_topology(plan, stability_input)
}

/// Revalidates supplied metadata, applies exact joins, and constructs one M2A form.
pub fn project_windows_supplied_directory_topology(
    plan: WindowsSuppliedDirectoryTopologyProjectionPlan,
    stability_input: WindowsSuppliedEntryStabilityInput,
) -> Result<
    WindowsSuppliedDirectoryTopologyProjection,
    WindowsSuppliedDirectoryTopologyProjectionFault,
> {
    validate_plan(&plan)?;

    let stable_pair = reconcile_windows_supplied_entry_stability(stability_input)
        .map_err(WindowsSuppliedDirectoryTopologyProjectionFault::stability)?;

    if plan.entry_reference_identity != stable_pair.entry_reference_identity {
        return Err(WindowsSuppliedDirectoryTopologyProjectionFault::simple(
            WindowsSuppliedDirectoryTopologyProjectionFaultCode::EntryReference,
            "entry_reference_identity",
            "placement plan and revalidated stable-pair entry references differ",
        ));
    }

    let seed = stable_pair.pre_read.topology_projection_seed();
    if seed.kind != TopologyEntryKind::Directory {
        return Err(WindowsSuppliedDirectoryTopologyProjectionFault::simple(
            WindowsSuppliedDirectoryTopologyProjectionFaultCode::Kind,
            "stable_pair.pre_read.kind",
            "supplied directory projection requires a directory seed",
        ));
    }

    let topology_observation = TopologyEntryObservation {
        relative_path: Some(plan.relative_path.clone()),
        kind: seed.kind,
        mode_class: TopologyModeClass::Directory,
        attributes: seed.attributes,
        identity: seed.identity,
        number_of_links: seed.number_of_links,
        streams: seed.streams,
        length: None,
        content_sha256: None,
        observation_ordinal: plan.observation_ordinal,
    };
    topology_observation
        .validate()
        .map_err(WindowsSuppliedDirectoryTopologyProjectionFault::topology)?;

    let final_component = topology_observation
        .relative_path
        .as_deref()
        .and_then(|path| path.rsplit('/').next())
        .ok_or_else(|| {
            WindowsSuppliedDirectoryTopologyProjectionFault::simple(
                WindowsSuppliedDirectoryTopologyProjectionFaultCode::Resource,
                "relative_path",
                "validated descendant path did not expose a final component",
            )
        })?;
    if final_component != stable_pair.pre_read.policy_decision.component {
        return Err(WindowsSuppliedDirectoryTopologyProjectionFault::simple(
            WindowsSuppliedDirectoryTopologyProjectionFaultCode::Component,
            "relative_path",
            "final relative-path component differs from the stable policy component",
        ));
    }

    Ok(WindowsSuppliedDirectoryTopologyProjection {
        profile: WINDOWS_SUPPLIED_DIRECTORY_TOPOLOGY_PROJECTION_PROFILE.to_owned(),
        plan,
        stable_pair,
        topology_observation,
    })
}

fn validate_plan(
    plan: &WindowsSuppliedDirectoryTopologyProjectionPlan,
) -> Result<(), WindowsSuppliedDirectoryTopologyProjectionFault> {
    if plan.profile != WINDOWS_SUPPLIED_DIRECTORY_TOPOLOGY_PROJECTION_PROFILE {
        return Err(WindowsSuppliedDirectoryTopologyProjectionFault::simple(
            WindowsSuppliedDirectoryTopologyProjectionFaultCode::Profile,
            "profile",
            "profile is not the exact supported supplied directory projection profile",
        ));
    }
    if plan.projection_identity == 0 {
        return Err(WindowsSuppliedDirectoryTopologyProjectionFault::simple(
            WindowsSuppliedDirectoryTopologyProjectionFaultCode::ProjectionIdentity,
            "projection_identity",
            "projection identity must be nonzero caller syntax",
        ));
    }
    if plan.entry_reference_identity == 0 {
        return Err(WindowsSuppliedDirectoryTopologyProjectionFault::simple(
            WindowsSuppliedDirectoryTopologyProjectionFaultCode::EntryReferenceIdentity,
            "entry_reference_identity",
            "entry-reference identity must be nonzero caller syntax",
        ));
    }
    if plan.observation_ordinal == 0 {
        return Err(WindowsSuppliedDirectoryTopologyProjectionFault::simple(
            WindowsSuppliedDirectoryTopologyProjectionFaultCode::Ordinal,
            "observation_ordinal",
            "observation ordinal must be nonzero caller syntax",
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
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, TopologyFormFaultCode,
        WindowsEntryPolicyKind,
        windows_supplied_entry_observation::{
            WINDOWS_SUPPLIED_ENTRY_OBSERVATION_PROFILE, WindowsSuppliedAttributeTagRecord,
            WindowsSuppliedCaseSensitivityRecord, WindowsSuppliedDirectoryCaseFlags,
            WindowsSuppliedEntryAssemblyInput, WindowsSuppliedFileIdentityRecord,
            WindowsSuppliedRecordCorrelation, WindowsSuppliedStandardInformationRecord,
            WindowsSuppliedStreamSet,
        },
        windows_supplied_entry_stability::{
            WINDOWS_SUPPLIED_ENTRY_STABILITY_PROFILE, WindowsSuppliedEntryStabilityFaultCode,
        },
    };

    fn plan() -> WindowsSuppliedDirectoryTopologyProjectionPlan {
        WindowsSuppliedDirectoryTopologyProjectionPlan {
            profile: WINDOWS_SUPPLIED_DIRECTORY_TOPOLOGY_PROJECTION_PROFILE.to_owned(),
            projection_identity: 53,
            entry_reference_identity: 11,
            relative_path: "src/entry".to_owned(),
            observation_ordinal: 3,
        }
    }

    fn correlation(batch_identity: u64) -> WindowsSuppliedRecordCorrelation {
        WindowsSuppliedRecordCorrelation {
            batch_identity,
            entry_reference_identity: 11,
        }
    }

    fn assembly_input(
        batch_identity: u64,
        component: &str,
        kind: WindowsEntryPolicyKind,
    ) -> WindowsSuppliedEntryAssemblyInput {
        let correlation = correlation(batch_identity);
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
            streams: WindowsSuppliedStreamSet::ExplicitEmpty(correlation),
        }
    }

    fn stability_input(
        component: &str,
        kind: WindowsEntryPolicyKind,
    ) -> WindowsSuppliedEntryStabilityInput {
        WindowsSuppliedEntryStabilityInput {
            profile: WINDOWS_SUPPLIED_ENTRY_STABILITY_PROFILE.to_owned(),
            reconciliation_identity: 31,
            pre_read: assembly_input(7, component, kind),
            post_read: assembly_input(8, component, kind),
        }
    }

    #[test]
    fn strict_decode_enforces_size_shape_and_profile() {
        let encoded = serde_json::to_vec(&plan()).unwrap();
        assert_eq!(
            decode_windows_supplied_directory_topology_projection_plan(&encoded).unwrap(),
            plan()
        );
        let text = String::from_utf8(encoded).unwrap();
        let unknown = text.replacen('{', "{\"trusted\":true,", 1);
        assert_eq!(
            decode_windows_supplied_directory_topology_projection_plan(unknown.as_bytes())
                .unwrap_err()
                .code,
            WindowsSuppliedDirectoryTopologyProjectionFaultCode::Json
        );
        assert_eq!(
            decode_windows_supplied_directory_topology_projection_plan(&vec![
                b' ';
                WINDOWS_SUPPLIED_DIRECTORY_TOPOLOGY_PROJECTION_PLAN_MAX_BYTES
                    + 1
            ])
            .unwrap_err()
            .code,
            WindowsSuppliedDirectoryTopologyProjectionFaultCode::Resource
        );
        let mut invalid = plan();
        invalid.profile = "other".to_owned();
        assert_eq!(
            project_windows_supplied_directory_topology(
                invalid,
                stability_input("entry", WindowsEntryPolicyKind::Directory)
            )
            .unwrap_err()
            .code,
            WindowsSuppliedDirectoryTopologyProjectionFaultCode::Profile
        );
    }

    #[test]
    fn identities_and_ordinal_are_distinct_gates() {
        for (field, expected) in [
            (
                "projection",
                WindowsSuppliedDirectoryTopologyProjectionFaultCode::ProjectionIdentity,
            ),
            (
                "reference",
                WindowsSuppliedDirectoryTopologyProjectionFaultCode::EntryReferenceIdentity,
            ),
            (
                "ordinal",
                WindowsSuppliedDirectoryTopologyProjectionFaultCode::Ordinal,
            ),
        ] {
            let mut invalid = plan();
            match field {
                "projection" => invalid.projection_identity = 0,
                "reference" => invalid.entry_reference_identity = 0,
                "ordinal" => invalid.observation_ordinal = 0,
                _ => unreachable!(),
            }
            assert_eq!(
                project_windows_supplied_directory_topology(
                    invalid,
                    stability_input("entry", WindowsEntryPolicyKind::Directory)
                )
                .unwrap_err()
                .code,
                expected
            );
        }
    }

    #[test]
    fn current_stability_reconciliation_runs_and_preserves_exact_fault() {
        let mut invalid = stability_input("entry", WindowsEntryPolicyKind::Directory);
        invalid.pre_read.profile = "invalid".to_owned();
        let fault = project_windows_supplied_directory_topology(plan(), invalid).unwrap_err();
        assert_eq!(
            fault.code,
            WindowsSuppliedDirectoryTopologyProjectionFaultCode::Stability
        );
        assert!(fault.nested_topology_fault.is_none());
        assert_eq!(
            fault.nested_stability_fault.unwrap().code,
            WindowsSuppliedEntryStabilityFaultCode::PreRead
        );
    }

    #[test]
    fn reference_mismatch_rejects_before_projection() {
        let mut invalid = plan();
        invalid.entry_reference_identity = 12;
        let fault = project_windows_supplied_directory_topology(
            invalid,
            stability_input("entry", WindowsEntryPolicyKind::Directory),
        )
        .unwrap_err();
        assert_eq!(
            fault.code,
            WindowsSuppliedDirectoryTopologyProjectionFaultCode::EntryReference
        );
        assert!(fault.nested_stability_fault.is_none());
        assert!(fault.nested_topology_fault.is_none());
    }

    #[test]
    fn regular_file_pair_rejects_at_directory_kind_gate() {
        let fault = project_windows_supplied_directory_topology(
            plan(),
            stability_input("entry", WindowsEntryPolicyKind::RegularFile),
        )
        .unwrap_err();
        assert_eq!(
            fault.code,
            WindowsSuppliedDirectoryTopologyProjectionFaultCode::Kind
        );
    }

    #[test]
    fn malformed_path_preserves_exact_current_m2a_fault() {
        let mut invalid = plan();
        invalid.relative_path = "src/../entry".to_owned();
        let fault = project_windows_supplied_directory_topology(
            invalid,
            stability_input("entry", WindowsEntryPolicyKind::Directory),
        )
        .unwrap_err();
        assert_eq!(
            fault.code,
            WindowsSuppliedDirectoryTopologyProjectionFaultCode::TopologyForm
        );
        assert!(fault.nested_stability_fault.is_none());
        let nested = fault.nested_topology_fault.unwrap();
        assert_eq!(nested.code, TopologyFormFaultCode::Entry);
        assert_eq!(nested.field, "relative_path");
    }

    #[test]
    fn component_join_is_exact_after_path_validation() {
        let mut invalid = plan();
        invalid.relative_path = "src/Entry".to_owned();
        let fault = project_windows_supplied_directory_topology(
            invalid,
            stability_input("entry", WindowsEntryPolicyKind::Directory),
        )
        .unwrap_err();
        assert_eq!(
            fault.code,
            WindowsSuppliedDirectoryTopologyProjectionFaultCode::Component
        );
        assert!(fault.nested_stability_fault.is_none());
        assert!(fault.nested_topology_fault.is_none());
    }

    #[test]
    fn directory_projection_maps_every_field_without_digest_or_length() {
        let projected = project_windows_supplied_directory_topology(
            plan(),
            stability_input("entry", WindowsEntryPolicyKind::Directory),
        )
        .unwrap();
        assert_eq!(
            projected.profile(),
            WINDOWS_SUPPLIED_DIRECTORY_TOPOLOGY_PROJECTION_PROFILE
        );
        assert_eq!(projected.plan(), &plan());
        assert_eq!(projected.stable_pair().entry_reference_identity, 11);
        assert_eq!(
            (
                projected.stable_pair().pre_batch_identity,
                projected.stable_pair().post_batch_identity
            ),
            (7, 8)
        );
        let entry = projected.topology_observation();
        assert_eq!(entry.relative_path.as_deref(), Some("src/entry"));
        assert_eq!(entry.kind, TopologyEntryKind::Directory);
        assert_eq!(entry.mode_class, TopologyModeClass::Directory);
        assert_eq!(entry.attributes, FILE_ATTRIBUTE_DIRECTORY);
        assert_eq!(entry.identity.volume_serial, 19);
        assert_eq!(entry.number_of_links, 1);
        assert!(entry.streams.is_empty());
        assert_eq!(entry.length, None);
        assert_eq!(entry.content_sha256, None);
        assert_eq!(entry.observation_ordinal, 3);
    }

    #[test]
    fn one_and_many_component_paths_preserve_exact_declared_syntax() {
        let mut one = plan();
        one.relative_path = "entry".to_owned();
        let one = project_windows_supplied_directory_topology(
            one,
            stability_input("entry", WindowsEntryPolicyKind::Directory),
        )
        .unwrap();
        assert_eq!(
            one.topology_observation().relative_path.as_deref(),
            Some("entry")
        );

        let mut many = plan();
        many.relative_path = "one/two/entry".to_owned();
        let many = project_windows_supplied_directory_topology(
            many,
            stability_input("entry", WindowsEntryPolicyKind::Directory),
        )
        .unwrap();
        assert_eq!(
            many.topology_observation().relative_path.as_deref(),
            Some("one/two/entry")
        );
    }

    #[test]
    fn decode_and_project_serializes_complete_revalidated_lineage() {
        let encoded = serde_json::to_vec(&plan()).unwrap();
        let projected = decode_and_project_windows_supplied_directory_topology(
            &encoded,
            stability_input("entry", WindowsEntryPolicyKind::Directory),
        )
        .unwrap();
        let value = serde_json::to_value(&projected).unwrap();
        assert_eq!(
            value["profile"],
            WINDOWS_SUPPLIED_DIRECTORY_TOPOLOGY_PROJECTION_PROFILE
        );
        assert_eq!(value["plan"]["relative_path"], "src/entry");
        assert_eq!(value["stable_pair"]["entry_reference_identity"], 11);
        assert_eq!(value["stable_pair"]["pre_batch_identity"], 7);
        assert_eq!(value["topology_observation"]["mode_class"], "directory");
        assert!(value["topology_observation"]["length"].is_null());
        assert!(value["topology_observation"]["content_sha256"].is_null());
    }

    #[test]
    fn diagnostics_are_bounded_and_nested_classes_are_exclusive() {
        let oversized = "x".repeat(400);
        let fault = WindowsSuppliedDirectoryTopologyProjectionFault::simple(
            WindowsSuppliedDirectoryTopologyProjectionFaultCode::Resource,
            &oversized,
            &oversized,
        );
        assert_eq!(fault.field.chars().count(), 64);
        assert_eq!(fault.message.chars().count(), 256);
        assert!(fault.nested_stability_fault.is_none());
        assert!(fault.nested_topology_fault.is_none());
    }
}
