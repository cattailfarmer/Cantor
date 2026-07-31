//! Pure structural placement of one supplied regular-file content binding.
//!
//! A successful value preserves derived supplied metadata and digest evidence
//! beside caller-declared path, mode, and ordinal syntax. It does not prove a
//! physical path, Git mode, traversal position, stream completeness, file
//! origin, scanner observation, receipt, admission, or mutation safety.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    TopologyEntryKind, TopologyEntryObservation, TopologyFormFault, TopologyModeClass,
    ValidateTopologyForm, windows_supplied_content_digest::WindowsSuppliedContentStableBinding,
};

/// Closed profile implemented by this pure supplied-value projection.
pub const WINDOWS_SUPPLIED_REGULAR_FILE_TOPOLOGY_PROJECTION_PROFILE: &str =
    "cantor-windows-supplied-regular-file-topology-projection/0.1";
/// Maximum accepted encoded placement plan size before JSON decoding.
pub const WINDOWS_SUPPLIED_REGULAR_FILE_TOPOLOGY_PROJECTION_PLAN_MAX_BYTES: usize = 262_144;

/// Strict caller-declared placement syntax for one supplied regular file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsSuppliedRegularFileTopologyProjectionPlan {
    pub profile: String,
    pub projection_identity: u64,
    pub entry_reference_identity: u64,
    pub relative_path: String,
    pub mode_class: TopologyModeClass,
    pub observation_ordinal: u64,
}

/// Closed supplied-projection failure vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsSuppliedRegularFileTopologyProjectionFaultCode {
    Json,
    Profile,
    ProjectionIdentity,
    EntryReferenceIdentity,
    EntryReference,
    Component,
    Mode,
    Ordinal,
    Kind,
    TopologyForm,
    Resource,
}

/// Deterministic bounded fault released without partial successful projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsSuppliedRegularFileTopologyProjectionFault {
    pub code: WindowsSuppliedRegularFileTopologyProjectionFaultCode,
    pub nested_topology_fault: Option<Box<TopologyFormFault>>,
    pub field: String,
    pub message: String,
}

impl WindowsSuppliedRegularFileTopologyProjectionFault {
    fn simple(
        code: WindowsSuppliedRegularFileTopologyProjectionFaultCode,
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

    fn topology(fault: TopologyFormFault) -> Self {
        let message = format!("topology form rejected: {fault}");
        Self {
            code: WindowsSuppliedRegularFileTopologyProjectionFaultCode::TopologyForm,
            nested_topology_fault: Some(Box::new(fault)),
            field: "topology_observation".to_owned(),
            message: bounded(&message, 256),
        }
    }
}

impl fmt::Display for WindowsSuppliedRegularFileTopologyProjectionFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl std::error::Error for WindowsSuppliedRegularFileTopologyProjectionFault {}

/// Output-only complete structural projection retaining its exact lineage.
///
/// Private fields and the absence of `Deserialize`, `Default`, public
/// constructors, and downgrade conversions keep success on the validated path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WindowsSuppliedRegularFileTopologyProjection {
    profile: String,
    plan: WindowsSuppliedRegularFileTopologyProjectionPlan,
    content_binding: WindowsSuppliedContentStableBinding,
    topology_observation: TopologyEntryObservation,
}

impl WindowsSuppliedRegularFileTopologyProjection {
    pub fn profile(&self) -> &str {
        &self.profile
    }

    pub fn plan(&self) -> &WindowsSuppliedRegularFileTopologyProjectionPlan {
        &self.plan
    }

    pub fn content_binding(&self) -> &WindowsSuppliedContentStableBinding {
        &self.content_binding
    }

    pub fn topology_observation(&self) -> &TopologyEntryObservation {
        &self.topology_observation
    }
}

/// Strictly decodes and validates one bounded caller placement plan.
pub fn decode_windows_supplied_regular_file_topology_projection_plan(
    bytes: &[u8],
) -> Result<
    WindowsSuppliedRegularFileTopologyProjectionPlan,
    WindowsSuppliedRegularFileTopologyProjectionFault,
> {
    if bytes.len() > WINDOWS_SUPPLIED_REGULAR_FILE_TOPOLOGY_PROJECTION_PLAN_MAX_BYTES {
        return Err(WindowsSuppliedRegularFileTopologyProjectionFault::simple(
            WindowsSuppliedRegularFileTopologyProjectionFaultCode::Resource,
            "json",
            "encoded supplied topology placement plan exceeds 262144 bytes",
        ));
    }
    let plan = serde_json::from_slice(bytes).map_err(|error| {
        WindowsSuppliedRegularFileTopologyProjectionFault::simple(
            WindowsSuppliedRegularFileTopologyProjectionFaultCode::Json,
            "json",
            &error.to_string(),
        )
    })?;
    validate_plan(&plan)?;
    Ok(plan)
}

/// Decodes a placement plan and applies the pure projection in one call.
pub fn decode_and_project_windows_supplied_regular_file_topology(
    bytes: &[u8],
    content_binding: WindowsSuppliedContentStableBinding,
) -> Result<
    WindowsSuppliedRegularFileTopologyProjection,
    WindowsSuppliedRegularFileTopologyProjectionFault,
> {
    let plan = decode_windows_supplied_regular_file_topology_projection_plan(bytes)?;
    project_windows_supplied_regular_file_topology(plan, content_binding)
}

/// Applies exact supplied-value joins and constructs one validated M2A form.
pub fn project_windows_supplied_regular_file_topology(
    plan: WindowsSuppliedRegularFileTopologyProjectionPlan,
    content_binding: WindowsSuppliedContentStableBinding,
) -> Result<
    WindowsSuppliedRegularFileTopologyProjection,
    WindowsSuppliedRegularFileTopologyProjectionFault,
> {
    validate_plan(&plan)?;

    if plan.entry_reference_identity
        != content_binding
            .content_observation()
            .entry_reference_identity()
    {
        return Err(WindowsSuppliedRegularFileTopologyProjectionFault::simple(
            WindowsSuppliedRegularFileTopologyProjectionFaultCode::EntryReference,
            "entry_reference_identity",
            "placement plan and supplied-content binding entry references differ",
        ));
    }

    let seed = content_binding
        .stable_pair()
        .pre_read
        .topology_projection_seed();
    if seed.kind != TopologyEntryKind::RegularFile {
        return Err(WindowsSuppliedRegularFileTopologyProjectionFault::simple(
            WindowsSuppliedRegularFileTopologyProjectionFaultCode::Kind,
            "content_binding.stable_pair.kind",
            "supplied topology projection requires a regular-file seed",
        ));
    }

    let topology_observation = TopologyEntryObservation {
        relative_path: Some(plan.relative_path.clone()),
        kind: seed.kind,
        mode_class: plan.mode_class,
        attributes: seed.attributes,
        identity: seed.identity,
        number_of_links: seed.number_of_links,
        streams: seed.streams,
        length: seed.length,
        content_sha256: Some(
            content_binding
                .content_observation()
                .derived_sha256()
                .to_owned(),
        ),
        observation_ordinal: plan.observation_ordinal,
    };
    topology_observation
        .validate()
        .map_err(WindowsSuppliedRegularFileTopologyProjectionFault::topology)?;

    let final_component = topology_observation
        .relative_path
        .as_deref()
        .and_then(|path| path.rsplit('/').next())
        .ok_or_else(|| {
            WindowsSuppliedRegularFileTopologyProjectionFault::simple(
                WindowsSuppliedRegularFileTopologyProjectionFaultCode::Resource,
                "relative_path",
                "validated descendant path did not expose a final component",
            )
        })?;
    if final_component
        != content_binding
            .stable_pair()
            .pre_read
            .policy_decision
            .component
    {
        return Err(WindowsSuppliedRegularFileTopologyProjectionFault::simple(
            WindowsSuppliedRegularFileTopologyProjectionFaultCode::Component,
            "relative_path",
            "final relative-path component differs from the stable policy component",
        ));
    }

    Ok(WindowsSuppliedRegularFileTopologyProjection {
        profile: WINDOWS_SUPPLIED_REGULAR_FILE_TOPOLOGY_PROJECTION_PROFILE.to_owned(),
        plan,
        content_binding,
        topology_observation,
    })
}

fn validate_plan(
    plan: &WindowsSuppliedRegularFileTopologyProjectionPlan,
) -> Result<(), WindowsSuppliedRegularFileTopologyProjectionFault> {
    if plan.profile != WINDOWS_SUPPLIED_REGULAR_FILE_TOPOLOGY_PROJECTION_PROFILE {
        return Err(WindowsSuppliedRegularFileTopologyProjectionFault::simple(
            WindowsSuppliedRegularFileTopologyProjectionFaultCode::Profile,
            "profile",
            "profile is not the exact supported supplied topology projection profile",
        ));
    }
    if plan.projection_identity == 0 {
        return Err(WindowsSuppliedRegularFileTopologyProjectionFault::simple(
            WindowsSuppliedRegularFileTopologyProjectionFaultCode::ProjectionIdentity,
            "projection_identity",
            "projection identity must be nonzero caller syntax",
        ));
    }
    if plan.entry_reference_identity == 0 {
        return Err(WindowsSuppliedRegularFileTopologyProjectionFault::simple(
            WindowsSuppliedRegularFileTopologyProjectionFaultCode::EntryReferenceIdentity,
            "entry_reference_identity",
            "entry-reference identity must be nonzero caller syntax",
        ));
    }
    if !matches!(
        plan.mode_class,
        TopologyModeClass::RegularNonExecutable | TopologyModeClass::RegularExecutable
    ) {
        return Err(WindowsSuppliedRegularFileTopologyProjectionFault::simple(
            WindowsSuppliedRegularFileTopologyProjectionFaultCode::Mode,
            "mode_class",
            "supplied regular-file projection requires a regular mode class",
        ));
    }
    if plan.observation_ordinal == 0 {
        return Err(WindowsSuppliedRegularFileTopologyProjectionFault::simple(
            WindowsSuppliedRegularFileTopologyProjectionFaultCode::Ordinal,
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
        FILE_ATTRIBUTE_NORMAL, TopologyFormFaultCode, TopologyStreamKind, WindowsEntryPolicyKind,
        WindowsRawStreamRecord,
        windows_supplied_content_digest::{
            WINDOWS_SUPPLIED_CONTENT_DIGEST_PROFILE, WindowsSuppliedContentDigestPlan,
            begin_windows_supplied_content_digest, bind_windows_supplied_content_digest,
        },
        windows_supplied_entry_observation::{
            WINDOWS_SUPPLIED_ENTRY_OBSERVATION_PROFILE, WindowsSuppliedAttributeTagRecord,
            WindowsSuppliedCaseSensitivityRecord, WindowsSuppliedEntryAssemblyInput,
            WindowsSuppliedFileIdentityRecord, WindowsSuppliedOrderedStreamRecords,
            WindowsSuppliedRecordCorrelation, WindowsSuppliedStandardInformationRecord,
            WindowsSuppliedStreamSet,
        },
        windows_supplied_entry_stability::{
            WINDOWS_SUPPLIED_ENTRY_STABILITY_PROFILE, WindowsSuppliedEntryStabilityInput,
        },
    };

    fn plan() -> WindowsSuppliedRegularFileTopologyProjectionPlan {
        WindowsSuppliedRegularFileTopologyProjectionPlan {
            profile: WINDOWS_SUPPLIED_REGULAR_FILE_TOPOLOGY_PROJECTION_PROFILE.to_owned(),
            projection_identity: 53,
            entry_reference_identity: 11,
            relative_path: "src/entry.txt".to_owned(),
            mode_class: TopologyModeClass::RegularNonExecutable,
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
        length: u64,
        streams: WindowsSuppliedStreamSet,
    ) -> WindowsSuppliedEntryAssemblyInput {
        let correlation = correlation(batch_identity);
        WindowsSuppliedEntryAssemblyInput {
            profile: WINDOWS_SUPPLIED_ENTRY_OBSERVATION_PROFILE.to_owned(),
            kind: WindowsEntryPolicyKind::RegularFile,
            component: component.to_owned(),
            maximum_component_utf16_units: 32_767,
            attribute_tag: WindowsSuppliedAttributeTagRecord {
                correlation,
                attributes: FILE_ATTRIBUTE_NORMAL,
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
                directory: false,
            },
            case_sensitivity: WindowsSuppliedCaseSensitivityRecord::NotApplicable(correlation),
            streams,
        }
    }

    fn stable_input(
        component: &str,
        length: u64,
        stream_name: Option<&str>,
    ) -> WindowsSuppliedEntryStabilityInput {
        let make_streams = |batch_identity| {
            let correlation = correlation(batch_identity);
            match stream_name {
                Some(name) => {
                    WindowsSuppliedStreamSet::OrderedRecords(WindowsSuppliedOrderedStreamRecords {
                        correlation,
                        records: vec![WindowsRawStreamRecord {
                            name: name.to_owned(),
                            stream_size: length,
                            allocation_size: length,
                            source_offset: 0,
                        }],
                    })
                }
                None => WindowsSuppliedStreamSet::ExplicitEmpty(correlation),
            }
        };
        WindowsSuppliedEntryStabilityInput {
            profile: WINDOWS_SUPPLIED_ENTRY_STABILITY_PROFILE.to_owned(),
            reconciliation_identity: 31,
            pre_read: assembly_input(7, component, length, make_streams(7)),
            post_read: assembly_input(8, component, length, make_streams(8)),
        }
    }

    fn binding(
        bytes: &[u8],
        component: &str,
        stream_name: Option<&str>,
    ) -> WindowsSuppliedContentStableBinding {
        let content_plan = WindowsSuppliedContentDigestPlan {
            profile: WINDOWS_SUPPLIED_CONTENT_DIGEST_PROFILE.to_owned(),
            content_read_identity: 41,
            entry_reference_identity: 11,
            expected_content_length: u64::try_from(bytes.len()).unwrap(),
            maximum_content_bytes: u64::try_from(bytes.len()).unwrap().max(1),
            maximum_chunks: 8,
        };
        let accumulator = begin_windows_supplied_content_digest(content_plan).unwrap();
        let observation = if bytes.is_empty() {
            accumulator.finish().unwrap()
        } else {
            accumulator.push_chunk(bytes).unwrap().finish().unwrap()
        };
        bind_windows_supplied_content_digest(
            observation,
            stable_input(component, u64::try_from(bytes.len()).unwrap(), stream_name),
        )
        .unwrap()
    }

    #[test]
    fn strict_decode_enforces_size_shape_and_profile() {
        let encoded = serde_json::to_vec(&plan()).unwrap();
        assert_eq!(
            decode_windows_supplied_regular_file_topology_projection_plan(&encoded).unwrap(),
            plan()
        );

        let text = String::from_utf8(encoded).unwrap();
        let unknown = text.replacen('{', "{\"trusted\":true,", 1);
        assert_eq!(
            decode_windows_supplied_regular_file_topology_projection_plan(unknown.as_bytes())
                .unwrap_err()
                .code,
            WindowsSuppliedRegularFileTopologyProjectionFaultCode::Json
        );
        assert_eq!(
            decode_windows_supplied_regular_file_topology_projection_plan(&vec![
                b' ';
                WINDOWS_SUPPLIED_REGULAR_FILE_TOPOLOGY_PROJECTION_PLAN_MAX_BYTES
                    + 1
            ])
            .unwrap_err()
            .code,
            WindowsSuppliedRegularFileTopologyProjectionFaultCode::Resource
        );

        let mut invalid = plan();
        invalid.profile = "other".to_owned();
        assert_eq!(
            project_windows_supplied_regular_file_topology(
                invalid,
                binding(b"abc", "entry.txt", None)
            )
            .unwrap_err()
            .code,
            WindowsSuppliedRegularFileTopologyProjectionFaultCode::Profile
        );
    }

    #[test]
    fn identities_mode_and_ordinal_are_distinct_gates() {
        let mut invalid = plan();
        invalid.projection_identity = 0;
        assert_eq!(
            project_windows_supplied_regular_file_topology(
                invalid,
                binding(b"abc", "entry.txt", None)
            )
            .unwrap_err()
            .code,
            WindowsSuppliedRegularFileTopologyProjectionFaultCode::ProjectionIdentity
        );

        let mut invalid = plan();
        invalid.entry_reference_identity = 0;
        assert_eq!(
            project_windows_supplied_regular_file_topology(
                invalid,
                binding(b"abc", "entry.txt", None)
            )
            .unwrap_err()
            .code,
            WindowsSuppliedRegularFileTopologyProjectionFaultCode::EntryReferenceIdentity
        );

        let mut invalid = plan();
        invalid.mode_class = TopologyModeClass::Directory;
        assert_eq!(
            project_windows_supplied_regular_file_topology(
                invalid,
                binding(b"abc", "entry.txt", None)
            )
            .unwrap_err()
            .code,
            WindowsSuppliedRegularFileTopologyProjectionFaultCode::Mode
        );

        let mut invalid = plan();
        invalid.observation_ordinal = 0;
        assert_eq!(
            project_windows_supplied_regular_file_topology(
                invalid,
                binding(b"abc", "entry.txt", None)
            )
            .unwrap_err()
            .code,
            WindowsSuppliedRegularFileTopologyProjectionFaultCode::Ordinal
        );
    }

    #[test]
    fn entry_reference_mismatch_rejects_before_projection() {
        let mut invalid = plan();
        invalid.entry_reference_identity = 12;
        let fault = project_windows_supplied_regular_file_topology(
            invalid,
            binding(b"abc", "entry.txt", None),
        )
        .unwrap_err();
        assert_eq!(
            fault.code,
            WindowsSuppliedRegularFileTopologyProjectionFaultCode::EntryReference
        );
        assert!(fault.nested_topology_fault.is_none());
    }

    #[test]
    fn malformed_path_preserves_exact_nested_topology_fault() {
        let mut invalid = plan();
        invalid.relative_path = "src/../entry.txt".to_owned();
        let fault = project_windows_supplied_regular_file_topology(
            invalid,
            binding(b"abc", "entry.txt", None),
        )
        .unwrap_err();
        assert_eq!(
            fault.code,
            WindowsSuppliedRegularFileTopologyProjectionFaultCode::TopologyForm
        );
        let nested = fault.nested_topology_fault.unwrap();
        assert_eq!(nested.code, TopologyFormFaultCode::Entry);
        assert_eq!(nested.field, "relative_path");
    }

    #[test]
    fn component_join_is_exact_after_path_validation() {
        let mut invalid = plan();
        invalid.relative_path = "src/Entry.txt".to_owned();
        let fault = project_windows_supplied_regular_file_topology(
            invalid,
            binding(b"abc", "entry.txt", None),
        )
        .unwrap_err();
        assert_eq!(
            fault.code,
            WindowsSuppliedRegularFileTopologyProjectionFaultCode::Component
        );
        assert!(fault.nested_topology_fault.is_none());
    }

    #[test]
    fn non_executable_projection_maps_every_field_exactly() {
        let binding = binding(b"abc", "entry.txt", Some("::$DATA"));
        let expected_digest = binding.content_observation().derived_sha256().to_owned();
        let expected_pair = binding.stable_pair().clone();
        let projected = project_windows_supplied_regular_file_topology(plan(), binding).unwrap();

        assert_eq!(
            projected.profile(),
            WINDOWS_SUPPLIED_REGULAR_FILE_TOPOLOGY_PROJECTION_PROFILE
        );
        assert_eq!(projected.plan(), &plan());
        assert_eq!(projected.content_binding().stable_pair(), &expected_pair);
        let entry = projected.topology_observation();
        assert_eq!(entry.relative_path.as_deref(), Some("src/entry.txt"));
        assert_eq!(entry.kind, TopologyEntryKind::RegularFile);
        assert_eq!(entry.mode_class, TopologyModeClass::RegularNonExecutable);
        assert_eq!(entry.attributes, FILE_ATTRIBUTE_NORMAL);
        assert_eq!(entry.identity.volume_serial, 19);
        assert_eq!(entry.number_of_links, 1);
        assert_eq!(entry.length, Some(3));
        assert_eq!(
            entry.content_sha256.as_deref(),
            Some(expected_digest.as_str())
        );
        assert_eq!(entry.observation_ordinal, 3);
        assert_eq!(entry.streams.len(), 1);
        assert_eq!(entry.streams[0].name, "::$DATA");
        assert_eq!(entry.streams[0].size, 3);
        assert_eq!(entry.streams[0].kind, TopologyStreamKind::UnnamedDefault);
    }

    #[test]
    fn executable_mode_is_preserved_without_inference() {
        let mut executable = plan();
        executable.mode_class = TopologyModeClass::RegularExecutable;
        let projected = project_windows_supplied_regular_file_topology(
            executable,
            binding(b"abc", "entry.txt", None),
        )
        .unwrap();
        assert_eq!(
            projected.topology_observation().mode_class,
            TopologyModeClass::RegularExecutable
        );
    }

    #[test]
    fn multi_segment_path_uses_only_exact_final_component() {
        let mut nested = plan();
        nested.relative_path = "one/two/three/entry.txt".to_owned();
        let projected = project_windows_supplied_regular_file_topology(
            nested,
            binding(b"abc", "entry.txt", None),
        )
        .unwrap();
        assert_eq!(
            projected.topology_observation().relative_path.as_deref(),
            Some("one/two/three/entry.txt")
        );
    }

    #[test]
    fn current_m2a_stream_bound_is_reapplied() {
        let long_name = format!(":{}:$DATA", "a".repeat(1_024));
        let fault = project_windows_supplied_regular_file_topology(
            plan(),
            binding(b"abc", "entry.txt", Some(&long_name)),
        )
        .unwrap_err();
        assert_eq!(
            fault.code,
            WindowsSuppliedRegularFileTopologyProjectionFaultCode::TopologyForm
        );
        let nested = fault.nested_topology_fault.unwrap();
        assert_eq!(nested.code, TopologyFormFaultCode::Text);
        assert_eq!(nested.field, "stream.name");
    }

    #[test]
    fn decode_and_project_preserves_serializable_lineage() {
        let encoded = serde_json::to_vec(&plan()).unwrap();
        let projected = decode_and_project_windows_supplied_regular_file_topology(
            &encoded,
            binding(b"abc", "entry.txt", None),
        )
        .unwrap();
        let value = serde_json::to_value(&projected).unwrap();
        assert_eq!(
            value["profile"],
            WINDOWS_SUPPLIED_REGULAR_FILE_TOPOLOGY_PROJECTION_PROFILE
        );
        assert_eq!(value["plan"]["relative_path"], "src/entry.txt");
        assert_eq!(
            value["topology_observation"]["content_sha256"],
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            value["content_binding"]["stable_pair"]["entry_reference_identity"],
            11
        );
    }

    #[test]
    fn diagnostics_are_bounded_and_nested_fault_is_class_exact() {
        let oversized_scalar = "x".repeat(400);
        let fault = WindowsSuppliedRegularFileTopologyProjectionFault::simple(
            WindowsSuppliedRegularFileTopologyProjectionFaultCode::Resource,
            &oversized_scalar,
            &oversized_scalar,
        );
        assert_eq!(fault.field.chars().count(), 64);
        assert_eq!(fault.message.chars().count(), 256);
        assert!(fault.nested_topology_fault.is_none());

        let encoded = vec![b'['; 4_096];
        let fault =
            decode_windows_supplied_regular_file_topology_projection_plan(&encoded).unwrap_err();
        assert_eq!(
            fault.code,
            WindowsSuppliedRegularFileTopologyProjectionFaultCode::Json
        );
        assert!(fault.message.chars().count() <= 256);
    }
}
