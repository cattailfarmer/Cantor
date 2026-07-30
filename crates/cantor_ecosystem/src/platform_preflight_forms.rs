//! Effect-free machine forms for a future Windows platform preflight.
//!
//! These types validate caller-supplied records. They do not inspect a path,
//! invoke an operating-system function, or grant topology-scanner authority.

use std::fmt;

use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::topology_forms::{StrongFileIdentity, ValidateTopologyForm, validate_volume_guid_path};

/// Version of the pure platform-preflight vocabulary.
pub const WINDOWS_PLATFORM_PREFLIGHT_PROFILE: &str = "cantor-windows-platform-preflight/0.2";
/// Version of a request validated before a future platform observation.
pub const WINDOWS_PLATFORM_PREFLIGHT_REQUEST_PROFILE: &str =
    "cantor-windows-platform-preflight-request/0.1";
/// Initial compilation target admitted by this vocabulary.
pub const WINDOWS_PLATFORM_PREFLIGHT_TARGET: &str = "x86_64-pc-windows-msvc";

const MAX_INPUT_ROOT_BYTES: usize = 32_768;
const MAX_VOLUME_NAME_BYTES: usize = 1_024;
const MAX_FILE_SYSTEM_NAME_BYTES: usize = 64;
const REMOTE_PROTOCOL_STRUCTURE_SIZE: u16 = 116;

/// Closed validation failures for platform-preflight forms.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformPreflightFormFaultCode {
    Json,
    Profile,
    Target,
    Path,
    Fault,
    Identity,
    Volume,
    RemoteProtocol,
    Disposition,
}

/// Bounded failure produced before a supplied platform-preflight record is admitted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformPreflightFormFault {
    pub code: PlatformPreflightFormFaultCode,
    pub field: String,
    pub message: String,
}

impl PlatformPreflightFormFault {
    fn new(code: PlatformPreflightFormFaultCode, field: &str, message: &str) -> Self {
        Self {
            code,
            field: field.to_owned(),
            message: message.chars().take(1_024).collect(),
        }
    }
}

impl fmt::Display for PlatformPreflightFormFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl std::error::Error for PlatformPreflightFormFault {}

/// Semantic validation for one supplied platform-preflight value.
pub trait ValidatePlatformPreflightForm {
    fn validate(&self) -> Result<(), PlatformPreflightFormFault>;
}

/// Strictly decodes JSON and then applies semantic validation.
pub fn decode_platform_preflight_json<T>(bytes: &[u8]) -> Result<T, PlatformPreflightFormFault>
where
    T: DeserializeOwned + ValidatePlatformPreflightForm,
{
    let value = serde_json::from_slice::<T>(bytes).map_err(|error| {
        PlatformPreflightFormFault::new(
            PlatformPreflightFormFaultCode::Json,
            "json",
            &error.to_string(),
        )
    })?;
    value.validate()?;
    Ok(value)
}

/// Strict effect-free input to a future platform observer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsPlatformPreflightRequest {
    pub request_profile: String,
    pub result_profile: String,
    pub target_triple: String,
    pub input_root: String,
}

impl ValidatePlatformPreflightForm for WindowsPlatformPreflightRequest {
    fn validate(&self) -> Result<(), PlatformPreflightFormFault> {
        if self.request_profile != WINDOWS_PLATFORM_PREFLIGHT_REQUEST_PROFILE {
            return Err(PlatformPreflightFormFault::new(
                PlatformPreflightFormFaultCode::Profile,
                "request_profile",
                "unknown platform-preflight request profile",
            ));
        }
        validate_common(&self.result_profile, &self.target_triple, &self.input_root)
    }
}

/// Closed query stage at which a complete observation may fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformPreflightQueryStage {
    FileIdInfo,
    FinalVolumeGuidPath,
    VolumeInformation,
    RemoteProtocolInformation,
}

/// Complete bounded volume information supplied by a future observer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsVolumeInformation {
    pub volume_name: String,
    pub volume_serial_number: u32,
    pub maximum_component_length: u32,
    pub file_system_flags: u32,
    pub file_system_name: String,
}

impl ValidatePlatformPreflightForm for WindowsVolumeInformation {
    fn validate(&self) -> Result<(), PlatformPreflightFormFault> {
        validate_optional_text(
            &self.volume_name,
            "volume.volume_name",
            MAX_VOLUME_NAME_BYTES,
        )?;
        if !(1..=32_767).contains(&self.maximum_component_length) {
            return Err(PlatformPreflightFormFault::new(
                PlatformPreflightFormFaultCode::Volume,
                "volume.maximum_component_length",
                "maximum component length must be in the closed range 1 through 32767",
            ));
        }
        validate_file_system_name(&self.file_system_name)
    }
}

/// Bounded, non-reserved fields from one remote-protocol information record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsRemoteProtocolInformation {
    pub structure_version: u16,
    pub structure_size: u16,
    pub protocol: u32,
    pub protocol_major_version: u16,
    pub protocol_minor_version: u16,
    pub protocol_revision: u16,
    pub flags: u32,
}

impl ValidatePlatformPreflightForm for WindowsRemoteProtocolInformation {
    fn validate(&self) -> Result<(), PlatformPreflightFormFault> {
        if !matches!(self.structure_version, 1 | 2) {
            return Err(PlatformPreflightFormFault::new(
                PlatformPreflightFormFaultCode::RemoteProtocol,
                "remote_protocol.structure_version",
                "structure version must be 1 or 2",
            ));
        }
        if self.structure_size != REMOTE_PROTOCOL_STRUCTURE_SIZE {
            return Err(PlatformPreflightFormFault::new(
                PlatformPreflightFormFaultCode::RemoteProtocol,
                "remote_protocol.structure_size",
                "structure size must be 116",
            ));
        }
        Ok(())
    }
}

/// Exact policy consequence of complete supplied evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformPreflightDisposition {
    EligibleLocalNtfs,
    RejectRemoteProtocol,
    RejectUnsupportedFileSystem,
}

/// Closed local processing failures after a platform query reports success.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformPreflightObservationFaultClass {
    ReturnedLengthLimit,
    InvalidUtf16,
    InvalidObservation,
}

/// One closed platform-preflight result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum WindowsPlatformPreflightRecord {
    OpenFault {
        profile: String,
        target_triple: String,
        input_root: String,
        error_code: u32,
    },
    QueryFault {
        profile: String,
        target_triple: String,
        input_root: String,
        stage: PlatformPreflightQueryStage,
        error_code: u32,
    },
    ObservationFault {
        profile: String,
        target_triple: String,
        input_root: String,
        stage: PlatformPreflightQueryStage,
        class: PlatformPreflightObservationFaultClass,
    },
    Complete {
        profile: String,
        target_triple: String,
        input_root: String,
        root_identity: StrongFileIdentity,
        root_volume_guid_path: String,
        volume: WindowsVolumeInformation,
        remote_protocol: WindowsRemoteProtocolInformation,
        disposition: PlatformPreflightDisposition,
    },
}

impl ValidatePlatformPreflightForm for WindowsPlatformPreflightRecord {
    fn validate(&self) -> Result<(), PlatformPreflightFormFault> {
        match self {
            Self::OpenFault {
                profile,
                target_triple,
                input_root,
                error_code,
            } => {
                validate_common(profile, target_triple, input_root)?;
                validate_error_code(*error_code)
            }
            Self::QueryFault {
                profile,
                target_triple,
                input_root,
                stage: _,
                error_code,
            } => {
                validate_common(profile, target_triple, input_root)?;
                validate_error_code(*error_code)
            }
            Self::ObservationFault {
                profile,
                target_triple,
                input_root,
                stage: _,
                class: _,
            } => validate_common(profile, target_triple, input_root),
            Self::Complete {
                profile,
                target_triple,
                input_root,
                root_identity,
                root_volume_guid_path,
                volume,
                remote_protocol,
                disposition,
            } => {
                validate_common(profile, target_triple, input_root)?;
                root_identity.validate().map_err(|fault| {
                    PlatformPreflightFormFault::new(
                        PlatformPreflightFormFaultCode::Identity,
                        "root_identity",
                        &fault.to_string(),
                    )
                })?;
                validate_volume_guid_path(root_volume_guid_path).map_err(|fault| {
                    PlatformPreflightFormFault::new(
                        PlatformPreflightFormFaultCode::Path,
                        "root_volume_guid_path",
                        &fault.to_string(),
                    )
                })?;
                volume.validate()?;
                remote_protocol.validate()?;
                validate_disposition(volume, remote_protocol, *disposition)
            }
        }
    }
}

fn validate_common(
    profile: &str,
    target_triple: &str,
    input_root: &str,
) -> Result<(), PlatformPreflightFormFault> {
    if profile != WINDOWS_PLATFORM_PREFLIGHT_PROFILE {
        return Err(PlatformPreflightFormFault::new(
            PlatformPreflightFormFaultCode::Profile,
            "profile",
            "unknown platform-preflight profile",
        ));
    }
    if target_triple != WINDOWS_PLATFORM_PREFLIGHT_TARGET {
        return Err(PlatformPreflightFormFault::new(
            PlatformPreflightFormFaultCode::Target,
            "target_triple",
            "unsupported platform-preflight target",
        ));
    }
    validate_extended_dos_drive_root(input_root)
}

fn validate_error_code(error_code: u32) -> Result<(), PlatformPreflightFormFault> {
    if error_code == 0 {
        return Err(PlatformPreflightFormFault::new(
            PlatformPreflightFormFaultCode::Fault,
            "error_code",
            "fault error code must be nonzero",
        ));
    }
    Ok(())
}

fn validate_extended_dos_drive_root(path: &str) -> Result<(), PlatformPreflightFormFault> {
    if path.is_empty()
        || path.len() > MAX_INPUT_ROOT_BYTES
        || path.contains('\0')
        || path.contains('/')
    {
        return Err(PlatformPreflightFormFault::new(
            PlatformPreflightFormFaultCode::Path,
            "input_root",
            "input root must be nonempty, NUL-free, backslash-only, and within its byte bound",
        ));
    }

    let Some(drive_path) = path.strip_prefix(r"\\?\") else {
        return Err(PlatformPreflightFormFault::new(
            PlatformPreflightFormFaultCode::Path,
            "input_root",
            "input root must use the extended-DOS prefix",
        ));
    };
    let bytes = drive_path.as_bytes();
    if bytes.len() < 3 || !bytes[0].is_ascii_uppercase() || bytes[1] != b':' || bytes[2] != b'\\' {
        return Err(PlatformPreflightFormFault::new(
            PlatformPreflightFormFaultCode::Path,
            "input_root",
            "input root must begin with an uppercase drive and root separator",
        ));
    }

    let tail = &drive_path[3..];
    if tail.is_empty() {
        return Ok(());
    }
    for component in tail.split('\\') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(PlatformPreflightFormFault::new(
                PlatformPreflightFormFaultCode::Path,
                "input_root",
                "input root contains a noncanonical component",
            ));
        }
    }
    Ok(())
}

fn validate_optional_text(
    value: &str,
    field: &str,
    maximum: usize,
) -> Result<(), PlatformPreflightFormFault> {
    if value.len() > maximum || value.contains('\0') {
        return Err(PlatformPreflightFormFault::new(
            PlatformPreflightFormFaultCode::Volume,
            field,
            "text must be NUL-free and within its byte bound",
        ));
    }
    Ok(())
}

fn validate_file_system_name(value: &str) -> Result<(), PlatformPreflightFormFault> {
    if value.is_empty()
        || value.len() > MAX_FILE_SYSTEM_NAME_BYTES
        || !value.is_ascii()
        || value.contains('\0')
        || value.trim().is_empty()
    {
        return Err(PlatformPreflightFormFault::new(
            PlatformPreflightFormFaultCode::Volume,
            "volume.file_system_name",
            "file-system name must be nonblank, NUL-free ASCII within 64 bytes",
        ));
    }
    Ok(())
}

fn validate_disposition(
    volume: &WindowsVolumeInformation,
    remote_protocol: &WindowsRemoteProtocolInformation,
    disposition: PlatformPreflightDisposition,
) -> Result<(), PlatformPreflightFormFault> {
    let expected = if remote_protocol.protocol != 0 {
        PlatformPreflightDisposition::RejectRemoteProtocol
    } else if volume.file_system_name == "NTFS" {
        PlatformPreflightDisposition::EligibleLocalNtfs
    } else {
        PlatformPreflightDisposition::RejectUnsupportedFileSystem
    };

    if disposition != expected {
        return Err(PlatformPreflightFormFault::new(
            PlatformPreflightFormFaultCode::Disposition,
            "disposition",
            "disposition is inconsistent with protocol and file-system evidence",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> StrongFileIdentity {
        StrongFileIdentity {
            volume_serial: 7,
            file_id_hex: "0123456789abcdef0123456789abcdef".to_owned(),
        }
    }

    fn volume(file_system_name: &str) -> WindowsVolumeInformation {
        WindowsVolumeInformation {
            volume_name: "Work".to_owned(),
            volume_serial_number: 42,
            maximum_component_length: 255,
            file_system_flags: 0x0004_0000,
            file_system_name: file_system_name.to_owned(),
        }
    }

    fn remote(protocol: u32) -> WindowsRemoteProtocolInformation {
        WindowsRemoteProtocolInformation {
            structure_version: 2,
            structure_size: 116,
            protocol,
            protocol_major_version: 3,
            protocol_minor_version: 1,
            protocol_revision: 1,
            flags: 0,
        }
    }

    fn request() -> WindowsPlatformPreflightRequest {
        WindowsPlatformPreflightRequest {
            request_profile: WINDOWS_PLATFORM_PREFLIGHT_REQUEST_PROFILE.to_owned(),
            result_profile: WINDOWS_PLATFORM_PREFLIGHT_PROFILE.to_owned(),
            target_triple: WINDOWS_PLATFORM_PREFLIGHT_TARGET.to_owned(),
            input_root: r"\\?\C:\Project\Cantor".to_owned(),
        }
    }

    fn complete(
        file_system_name: &str,
        protocol: u32,
        disposition: PlatformPreflightDisposition,
    ) -> WindowsPlatformPreflightRecord {
        WindowsPlatformPreflightRecord::Complete {
            profile: WINDOWS_PLATFORM_PREFLIGHT_PROFILE.to_owned(),
            target_triple: WINDOWS_PLATFORM_PREFLIGHT_TARGET.to_owned(),
            input_root: r"\\?\C:\Project\Cantor".to_owned(),
            root_identity: identity(),
            root_volume_guid_path:
                r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\Project\Cantor".to_owned(),
            volume: volume(file_system_name),
            remote_protocol: remote(protocol),
            disposition,
        }
    }

    #[test]
    fn every_closed_outcome_round_trips_and_validates() {
        let values = [
            WindowsPlatformPreflightRecord::OpenFault {
                profile: WINDOWS_PLATFORM_PREFLIGHT_PROFILE.to_owned(),
                target_triple: WINDOWS_PLATFORM_PREFLIGHT_TARGET.to_owned(),
                input_root: r"\\?\C:\".to_owned(),
                error_code: 5,
            },
            WindowsPlatformPreflightRecord::QueryFault {
                profile: WINDOWS_PLATFORM_PREFLIGHT_PROFILE.to_owned(),
                target_triple: WINDOWS_PLATFORM_PREFLIGHT_TARGET.to_owned(),
                input_root: r"\\?\C:\Project\Cantor".to_owned(),
                stage: PlatformPreflightQueryStage::FileIdInfo,
                error_code: 87,
            },
            WindowsPlatformPreflightRecord::ObservationFault {
                profile: WINDOWS_PLATFORM_PREFLIGHT_PROFILE.to_owned(),
                target_triple: WINDOWS_PLATFORM_PREFLIGHT_TARGET.to_owned(),
                input_root: r"\\?\C:\Project\Cantor".to_owned(),
                stage: PlatformPreflightQueryStage::FinalVolumeGuidPath,
                class: PlatformPreflightObservationFaultClass::ReturnedLengthLimit,
            },
            complete("NTFS", 0, PlatformPreflightDisposition::EligibleLocalNtfs),
        ];

        for value in values {
            let bytes = serde_json::to_vec(&value).expect("serialize");
            assert_eq!(
                decode_platform_preflight_json::<WindowsPlatformPreflightRecord>(&bytes)
                    .expect("strict decode"),
                value
            );
        }
    }

    #[test]
    fn request_validates_every_pre_effect_identity_field() {
        let value = request();
        let bytes = serde_json::to_vec(&value).expect("serialize");
        assert_eq!(
            decode_platform_preflight_json::<WindowsPlatformPreflightRequest>(&bytes)
                .expect("valid request"),
            value
        );
        let mut unknown = serde_json::to_value(&value).expect("serialize request");
        unknown
            .as_object_mut()
            .expect("request object")
            .insert("extra".to_owned(), serde_json::json!(true));
        assert_eq!(
            decode_platform_preflight_json::<WindowsPlatformPreflightRequest>(
                &serde_json::to_vec(&unknown).expect("serialize unknown request")
            )
            .expect_err("unknown request field")
            .code,
            PlatformPreflightFormFaultCode::Json
        );

        let mut invalid = request();
        invalid.request_profile = "other".to_owned();
        assert_eq!(
            invalid.validate().expect_err("request profile").code,
            PlatformPreflightFormFaultCode::Profile
        );
        invalid = request();
        invalid.result_profile = "cantor-windows-platform-preflight/0.1".to_owned();
        assert_eq!(
            invalid.validate().expect_err("result profile").code,
            PlatformPreflightFormFaultCode::Profile
        );
        invalid = request();
        invalid.target_triple = "aarch64-pc-windows-msvc".to_owned();
        assert_eq!(
            invalid.validate().expect_err("target").code,
            PlatformPreflightFormFaultCode::Target
        );
        invalid = request();
        invalid.input_root = r"C:\Project\Cantor".to_owned();
        assert_eq!(
            invalid.validate().expect_err("input root").code,
            PlatformPreflightFormFaultCode::Path
        );
    }

    #[test]
    fn profile_and_target_are_exact() {
        let mut value = complete("NTFS", 0, PlatformPreflightDisposition::EligibleLocalNtfs);
        if let WindowsPlatformPreflightRecord::Complete { profile, .. } = &mut value {
            *profile = "other".to_owned();
        }
        assert_eq!(
            value.validate().expect_err("profile").code,
            PlatformPreflightFormFaultCode::Profile
        );
        if let WindowsPlatformPreflightRecord::Complete {
            profile,
            target_triple,
            ..
        } = &mut value
        {
            *profile = WINDOWS_PLATFORM_PREFLIGHT_PROFILE.to_owned();
            *target_triple = "aarch64-pc-windows-msvc".to_owned();
        }
        assert_eq!(
            value.validate().expect_err("target").code,
            PlatformPreflightFormFaultCode::Target
        );
    }

    #[test]
    fn extended_dos_drive_roots_are_lexically_closed() {
        for path in [r"\\?\C:\", r"\\?\Z:\Project", r"\\?\C:\Project\Ångström"] {
            assert!(validate_extended_dos_drive_root(path).is_ok(), "{path:?}");
        }
        for path in [
            "",
            r"C:\Project",
            r"\\?\c:\Project",
            r"\\?\C:Project",
            r"\\?\UNC\server\share",
            r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\",
            r"\\?\C:\Project\",
            r"\\?\C:\Project\\Cantor",
            r"\\?\C:\.",
            r"\\?\C:\..",
            r"\\?\C:\a/b",
        ] {
            assert!(validate_extended_dos_drive_root(path).is_err(), "{path:?}");
        }
        assert!(validate_extended_dos_drive_root("\\\\?\\C:\\bad\0tail").is_err());
        assert!(
            validate_extended_dos_drive_root(&format!(
                r"\\?\C:\{}",
                "é".repeat(MAX_INPUT_ROOT_BYTES)
            ))
            .is_err()
        );
    }

    #[test]
    fn fault_codes_are_nonzero_and_fault_shapes_reject_partial_evidence() {
        let mut value = WindowsPlatformPreflightRecord::OpenFault {
            profile: WINDOWS_PLATFORM_PREFLIGHT_PROFILE.to_owned(),
            target_triple: WINDOWS_PLATFORM_PREFLIGHT_TARGET.to_owned(),
            input_root: r"\\?\C:\".to_owned(),
            error_code: 0,
        };
        assert_eq!(
            value.validate().expect_err("zero error").code,
            PlatformPreflightFormFaultCode::Fault
        );
        let WindowsPlatformPreflightRecord::OpenFault { error_code, .. } = &mut value else {
            unreachable!()
        };
        *error_code = 5;
        let mut json = serde_json::to_value(value).expect("serialize");
        json.as_object_mut()
            .expect("object")
            .insert("volume".to_owned(), serde_json::json!({}));
        assert_eq!(
            decode_platform_preflight_json::<WindowsPlatformPreflightRecord>(
                &serde_json::to_vec(&json).expect("serialize JSON")
            )
            .expect_err("partial evidence")
            .code,
            PlatformPreflightFormFaultCode::Json
        );
    }

    #[test]
    fn observation_fault_classes_round_trip_without_os_error_or_partial_evidence() {
        for class in [
            PlatformPreflightObservationFaultClass::ReturnedLengthLimit,
            PlatformPreflightObservationFaultClass::InvalidUtf16,
            PlatformPreflightObservationFaultClass::InvalidObservation,
        ] {
            let value = WindowsPlatformPreflightRecord::ObservationFault {
                profile: WINDOWS_PLATFORM_PREFLIGHT_PROFILE.to_owned(),
                target_triple: WINDOWS_PLATFORM_PREFLIGHT_TARGET.to_owned(),
                input_root: r"\\?\C:\Project\Cantor".to_owned(),
                stage: PlatformPreflightQueryStage::VolumeInformation,
                class,
            };
            let bytes = serde_json::to_vec(&value).expect("serialize");
            assert_eq!(
                decode_platform_preflight_json::<WindowsPlatformPreflightRecord>(&bytes)
                    .expect("valid observation fault"),
                value
            );

            let mut json = serde_json::to_value(&value).expect("serialize JSON");
            json.as_object_mut()
                .expect("object")
                .insert("error_code".to_owned(), serde_json::json!(13));
            assert_eq!(
                decode_platform_preflight_json::<WindowsPlatformPreflightRecord>(
                    &serde_json::to_vec(&json).expect("serialize invalid JSON")
                )
                .expect_err("observation fault OS error")
                .code,
                PlatformPreflightFormFaultCode::Json
            );

            let mut json = serde_json::to_value(&value).expect("serialize JSON");
            json.as_object_mut()
                .expect("object")
                .insert("volume".to_owned(), serde_json::json!({}));
            assert_eq!(
                decode_platform_preflight_json::<WindowsPlatformPreflightRecord>(
                    &serde_json::to_vec(&json).expect("serialize invalid JSON")
                )
                .expect_err("observation fault partial evidence")
                .code,
                PlatformPreflightFormFaultCode::Json
            );
        }

        let unknown_class = br#"{"outcome":"observation_fault","profile":"cantor-windows-platform-preflight/0.2","target_triple":"x86_64-pc-windows-msvc","input_root":"\\\\?\\C:\\","stage":"volume_information","class":"other"}"#;
        assert_eq!(
            decode_platform_preflight_json::<WindowsPlatformPreflightRecord>(unknown_class)
                .expect_err("unknown observation fault class")
                .code,
            PlatformPreflightFormFaultCode::Json
        );
    }

    #[test]
    fn legacy_result_profile_is_rejected_for_every_compatible_shape() {
        let values = [
            WindowsPlatformPreflightRecord::OpenFault {
                profile: WINDOWS_PLATFORM_PREFLIGHT_PROFILE.to_owned(),
                target_triple: WINDOWS_PLATFORM_PREFLIGHT_TARGET.to_owned(),
                input_root: r"\\?\C:\".to_owned(),
                error_code: 5,
            },
            WindowsPlatformPreflightRecord::QueryFault {
                profile: WINDOWS_PLATFORM_PREFLIGHT_PROFILE.to_owned(),
                target_triple: WINDOWS_PLATFORM_PREFLIGHT_TARGET.to_owned(),
                input_root: r"\\?\C:\".to_owned(),
                stage: PlatformPreflightQueryStage::FileIdInfo,
                error_code: 87,
            },
            complete("NTFS", 0, PlatformPreflightDisposition::EligibleLocalNtfs),
        ];
        for value in values {
            let mut json = serde_json::to_value(value).expect("serialize");
            json.as_object_mut().expect("object").insert(
                "profile".to_owned(),
                serde_json::json!("cantor-windows-platform-preflight/0.1"),
            );
            let bytes = serde_json::to_vec(&json).expect("serialize JSON");
            assert_eq!(
                decode_platform_preflight_json::<WindowsPlatformPreflightRecord>(&bytes)
                    .expect_err("legacy result profile")
                    .code,
                PlatformPreflightFormFaultCode::Profile
            );
        }
    }

    #[test]
    fn volume_information_enforces_text_and_scalar_bounds() {
        assert!(volume("NTFS").validate().is_ok());
        let mut value = volume("NTFS");
        value.volume_name.clear();
        assert!(value.validate().is_ok());
        value.maximum_component_length = 0;
        assert!(value.validate().is_err());
        value = volume("NTFS");
        value.maximum_component_length = 32_768;
        assert!(value.validate().is_err());
        value = volume(" ");
        assert!(value.validate().is_err());
        value = volume("NÉFS");
        assert!(value.validate().is_err());
        value = volume(&"N".repeat(MAX_FILE_SYSTEM_NAME_BYTES + 1));
        assert!(value.validate().is_err());
        value = volume("NTFS");
        value.volume_name = "x\0y".to_owned();
        assert!(value.validate().is_err());
        value.volume_name = "é".repeat((MAX_VOLUME_NAME_BYTES / 2) + 1);
        assert!(value.validate().is_err());
    }

    #[test]
    fn remote_protocol_header_is_exact_and_reserved_fields_reject() {
        assert!(remote(0).validate().is_ok());
        for version in [0, 3] {
            let mut value = remote(0);
            value.structure_version = version;
            assert!(value.validate().is_err());
        }
        let mut value = remote(0);
        value.structure_size = 115;
        assert!(value.validate().is_err());

        let record = complete("NTFS", 0, PlatformPreflightDisposition::EligibleLocalNtfs);
        let mut json = serde_json::to_value(record).expect("serialize");
        json.get_mut("remote_protocol")
            .and_then(serde_json::Value::as_object_mut)
            .expect("remote object")
            .insert("reserved".to_owned(), serde_json::json!([0, 0]));
        assert_eq!(
            decode_platform_preflight_json::<WindowsPlatformPreflightRecord>(
                &serde_json::to_vec(&json).expect("serialize JSON")
            )
            .expect_err("reserved fields")
            .code,
            PlatformPreflightFormFaultCode::Json
        );
    }

    #[test]
    fn disposition_truth_table_is_exhaustive() {
        for (file_system, protocol, expected) in [
            ("NTFS", 0, PlatformPreflightDisposition::EligibleLocalNtfs),
            (
                "ReFS",
                0,
                PlatformPreflightDisposition::RejectUnsupportedFileSystem,
            ),
            (
                "NTFS",
                0x0002_0000,
                PlatformPreflightDisposition::RejectRemoteProtocol,
            ),
            (
                "ReFS",
                0x0002_0000,
                PlatformPreflightDisposition::RejectRemoteProtocol,
            ),
        ] {
            for disposition in [
                PlatformPreflightDisposition::EligibleLocalNtfs,
                PlatformPreflightDisposition::RejectRemoteProtocol,
                PlatformPreflightDisposition::RejectUnsupportedFileSystem,
            ] {
                assert_eq!(
                    complete(file_system, protocol, disposition)
                        .validate()
                        .is_ok(),
                    disposition == expected,
                    "{file_system} {protocol:#x} {disposition:?}"
                );
            }
        }
    }

    #[test]
    fn shared_identity_and_volume_guid_grammar_are_enforced() {
        let mut value = complete("NTFS", 0, PlatformPreflightDisposition::EligibleLocalNtfs);
        if let WindowsPlatformPreflightRecord::Complete { root_identity, .. } = &mut value {
            root_identity.file_id_hex = "ABCDEF".repeat(6);
        }
        assert_eq!(
            value.validate().expect_err("identity").code,
            PlatformPreflightFormFaultCode::Identity
        );
        if let WindowsPlatformPreflightRecord::Complete {
            root_identity,
            root_volume_guid_path,
            ..
        } = &mut value
        {
            *root_identity = identity();
            *root_volume_guid_path =
                r"\\?\Volume{01234567-89AB-cdef-0123-456789abcdef}\Project".to_owned();
        }
        assert_eq!(
            value.validate().expect_err("volume GUID").code,
            PlatformPreflightFormFaultCode::Path
        );
    }

    #[test]
    fn strict_json_rejects_unknown_fields_variants_and_missing_values() {
        let valid = serde_json::to_vec(&complete(
            "NTFS",
            0,
            PlatformPreflightDisposition::EligibleLocalNtfs,
        ))
        .expect("serialize");
        let mut unknown = serde_json::from_slice::<serde_json::Value>(&valid).expect("parse");
        unknown
            .as_object_mut()
            .expect("object")
            .insert("extra".to_owned(), serde_json::json!(true));
        let unknown = serde_json::to_vec(&unknown).expect("serialize");
        for bytes in [
            unknown,
            br#"{"outcome":"unknown"}"#.to_vec(),
            br#"{"outcome":"query_fault","profile":"cantor-windows-platform-preflight/0.1","target_triple":"x86_64-pc-windows-msvc","input_root":"\\\\?\\C:\\","error_code":5}"#.to_vec(),
            b"{".to_vec(),
        ] {
            assert_eq!(
                decode_platform_preflight_json::<WindowsPlatformPreflightRecord>(&bytes)
                    .expect_err("strict JSON")
                    .code,
                PlatformPreflightFormFaultCode::Json
            );
        }
    }
}
