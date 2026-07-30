//! Isolated, root-only Windows platform preflight.
//!
//! The public boundary is safe and consumes only the already proven request
//! form. The Windows FFI and ownership seam is confined to one private module.

#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

use cantor_ecosystem::{
    PlatformPreflightFormFault, PlatformPreflightQueryStage, ValidatePlatformPreflightForm,
    WindowsPlatformPreflightRecord, WindowsPlatformPreflightRequest,
};
use serde::{Deserialize, Serialize};

/// Version of the isolated runtime behavior.
pub const WINDOWS_PLATFORM_PREFLIGHT_RUNTIME_PROFILE: &str =
    "cantor-windows-platform-preflight-runtime/0.2";

/// Exact operation whose immediate operating-system error was unavailable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum WindowsPlatformPreflightRuntimeOperation {
    Open,
    Query { stage: PlatformPreflightQueryStage },
}

/// Closed runtime-layer faults that cannot honestly inhabit the result form.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "fault", rename_all = "snake_case", deny_unknown_fields)]
pub enum WindowsPlatformPreflightRuntimeFault {
    InvalidRequest {
        detail: PlatformPreflightFormFault,
    },
    UnsupportedTarget,
    OperatingSystemErrorUnavailable {
        operation: WindowsPlatformPreflightRuntimeOperation,
    },
}

/// Validates one request before dispatching to the target-specific observer.
pub fn observe_platform_preflight(
    request: &WindowsPlatformPreflightRequest,
) -> Result<WindowsPlatformPreflightRecord, WindowsPlatformPreflightRuntimeFault> {
    request
        .validate()
        .map_err(|detail| WindowsPlatformPreflightRuntimeFault::InvalidRequest { detail })?;

    #[cfg(windows)]
    {
        windows_runtime::observe(request)
    }

    #[cfg(not(windows))]
    {
        Err(WindowsPlatformPreflightRuntimeFault::UnsupportedTarget)
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod windows_runtime {
    use std::{
        ffi::c_void,
        mem::{MaybeUninit, size_of},
        os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
        ptr,
    };

    use cantor_ecosystem::{
        PlatformPreflightDisposition, PlatformPreflightObservationFaultClass,
        PlatformPreflightQueryStage, StrongFileIdentity, ValidatePlatformPreflightForm,
        WINDOWS_PLATFORM_PREFLIGHT_PROFILE, WindowsPlatformPreflightRecord,
        WindowsPlatformPreflightRequest, WindowsRemoteProtocolInformation,
        WindowsVolumeInformation,
    };
    use windows_sys::Win32::{
        Foundation::{GetLastError, HANDLE, INVALID_HANDLE_VALUE},
        Storage::FileSystem::{
            CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO,
            FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES, FILE_REMOTE_PROTOCOL_INFO,
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FileIdInfo,
            FileRemoteProtocolInfo, GetFileInformationByHandleEx, GetFinalPathNameByHandleW,
            GetVolumeInformationByHandleW, OPEN_EXISTING, VOLUME_NAME_GUID,
        },
    };

    use super::{WindowsPlatformPreflightRuntimeFault, WindowsPlatformPreflightRuntimeOperation};

    const FINAL_PATH_CAPACITY: usize = 32_768;
    const VOLUME_TEXT_CAPACITY: usize = 261;

    #[derive(Clone, Copy)]
    struct RemoteFields {
        structure_version: u16,
        structure_size: u16,
        protocol: u32,
        protocol_major_version: u16,
        protocol_minor_version: u16,
        protocol_revision: u16,
        flags: u32,
        reserved_are_zero: bool,
    }

    pub(super) fn observe(
        request: &WindowsPlatformPreflightRequest,
    ) -> Result<WindowsPlatformPreflightRecord, WindowsPlatformPreflightRuntimeFault> {
        let wide_root = nul_terminated_utf16(&request.input_root);

        // SAFETY: wide_root is an owned, NUL-terminated UTF-16 allocation alive for the call;
        // all access, share, creation, flag, security, and template arguments are closed constants.
        let (raw_handle, open_error) = unsafe {
            let handle = CreateFileW(
                wide_root.as_ptr(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                ptr::null_mut(),
            );
            let error = if handle == INVALID_HANDLE_VALUE {
                GetLastError()
            } else {
                0
            };
            (handle, error)
        };
        if raw_handle == INVALID_HANDLE_VALUE {
            return operating_system_fault(request, None, open_error);
        }

        // SAFETY: CreateFileW returned a live, owned, CloseHandle-compatible handle; this is
        // the sole transfer, INVALID_HANDLE_VALUE was rejected, and no other owner is retained.
        let handle = unsafe { OwnedHandle::from_raw_handle(raw_handle) };
        let borrowed_handle = handle.as_raw_handle() as HANDLE;

        // SAFETY: output is correctly aligned and sized for FILE_ID_INFO, its pointer and u32
        // size remain valid for the call, and assume_init runs only on the documented success path.
        let (file_id, file_id_error) = unsafe {
            let mut output = MaybeUninit::<FILE_ID_INFO>::uninit();
            let success = GetFileInformationByHandleEx(
                borrowed_handle,
                FileIdInfo,
                output.as_mut_ptr().cast::<c_void>(),
                u32::try_from(size_of::<FILE_ID_INFO>()).expect("FILE_ID_INFO fits u32"),
            );
            if success == 0 {
                (None, GetLastError())
            } else {
                (Some(output.assume_init()), 0)
            }
        };
        let Some(file_id) = file_id else {
            return operating_system_fault(
                request,
                Some(PlatformPreflightQueryStage::FileIdInfo),
                file_id_error,
            );
        };
        let root_identity = StrongFileIdentity {
            volume_serial: file_id.VolumeSerialNumber,
            file_id_hex: encode_identity(file_id.FileId.Identifier),
        };

        let mut final_path_buffer = [0u16; FINAL_PATH_CAPACITY];
        // SAFETY: final_path_buffer is initialized, writable, and alive for the call; its exact
        // element count fits u32, and the live owned handle is only borrowed for this query.
        let (final_path_length, final_path_error) = unsafe {
            let length = GetFinalPathNameByHandleW(
                borrowed_handle,
                final_path_buffer.as_mut_ptr(),
                u32::try_from(final_path_buffer.len()).expect("final path capacity fits u32"),
                FILE_NAME_NORMALIZED | VOLUME_NAME_GUID,
            );
            let error = if length == 0 { GetLastError() } else { 0 };
            (length, error)
        };
        if final_path_length == 0 && final_path_error == 0 {
            return operating_system_fault(
                request,
                Some(PlatformPreflightQueryStage::FinalVolumeGuidPath),
                final_path_error,
            );
        }
        if final_path_length != 0 {
            let final_path_length = usize::try_from(final_path_length)
                .expect("u32 length fits usize on supported target");
            if final_path_length >= final_path_buffer.len() {
                return Ok(observation_fault(
                    request,
                    PlatformPreflightQueryStage::FinalVolumeGuidPath,
                    PlatformPreflightObservationFaultClass::ReturnedLengthLimit,
                ));
            }
            let root_volume_guid_path =
                match String::from_utf16(&final_path_buffer[..final_path_length]) {
                    Ok(path) => canonicalize_volume_guid(path),
                    Err(_) => {
                        return Ok(observation_fault(
                            request,
                            PlatformPreflightQueryStage::FinalVolumeGuidPath,
                            PlatformPreflightObservationFaultClass::InvalidUtf16,
                        ));
                    }
                };

            let mut volume_name_buffer = [0u16; VOLUME_TEXT_CAPACITY];
            let mut file_system_name_buffer = [0u16; VOLUME_TEXT_CAPACITY];
            let mut volume_serial_number = 0u32;
            let mut maximum_component_length = 0u32;
            let mut file_system_flags = 0u32;
            // SAFETY: both initialized WCHAR buffers and all scalar outputs are writable, aligned,
            // correctly sized, alive for the call, and consumed only after complete API success.
            let (volume_success, volume_error) = unsafe {
                let success = GetVolumeInformationByHandleW(
                    borrowed_handle,
                    volume_name_buffer.as_mut_ptr(),
                    u32::try_from(volume_name_buffer.len()).expect("volume buffer fits u32"),
                    &mut volume_serial_number,
                    &mut maximum_component_length,
                    &mut file_system_flags,
                    file_system_name_buffer.as_mut_ptr(),
                    u32::try_from(file_system_name_buffer.len())
                        .expect("file-system buffer fits u32"),
                );
                let error = if success == 0 { GetLastError() } else { 0 };
                (success, error)
            };
            if volume_success == 0 {
                return operating_system_fault(
                    request,
                    Some(PlatformPreflightQueryStage::VolumeInformation),
                    volume_error,
                );
            }
            let volume_name = match decode_nul_terminated(&volume_name_buffer) {
                Ok(value) => value,
                Err(class) => {
                    return Ok(observation_fault(
                        request,
                        PlatformPreflightQueryStage::VolumeInformation,
                        class,
                    ));
                }
            };
            let file_system_name = match decode_nul_terminated(&file_system_name_buffer) {
                Ok(value) => value,
                Err(class) => {
                    return Ok(observation_fault(
                        request,
                        PlatformPreflightQueryStage::VolumeInformation,
                        class,
                    ));
                }
            };
            let volume = WindowsVolumeInformation {
                volume_name,
                volume_serial_number,
                maximum_component_length,
                file_system_flags,
                file_system_name,
            };
            let disposition = local_disposition(&volume.file_system_name);
            let complete = WindowsPlatformPreflightRecord::CompleteLocal {
                profile: WINDOWS_PLATFORM_PREFLIGHT_PROFILE.to_owned(),
                target_triple: request.target_triple.clone(),
                input_root: request.input_root.clone(),
                root_identity,
                root_volume_guid_path,
                volume,
                disposition,
            };
            return release_complete(request, complete);
        }

        // SAFETY: output is correctly aligned and sized for FILE_REMOTE_PROTOCOL_INFO; the live
        // handle is borrowed, initialization is assumed only on success, and union reserved bytes
        // are copied inside this block before the backing value leaves the unsafe boundary.
        let (remote, remote_error) = unsafe {
            let mut output = MaybeUninit::<FILE_REMOTE_PROTOCOL_INFO>::uninit();
            let success = GetFileInformationByHandleEx(
                borrowed_handle,
                FileRemoteProtocolInfo,
                output.as_mut_ptr().cast::<c_void>(),
                u32::try_from(size_of::<FILE_REMOTE_PROTOCOL_INFO>())
                    .expect("FILE_REMOTE_PROTOCOL_INFO fits u32"),
            );
            if success == 0 {
                (None, GetLastError())
            } else {
                let output = output.assume_init();
                let protocol_reserved = output.ProtocolSpecific.Reserved;
                (
                    Some(RemoteFields {
                        structure_version: output.StructureVersion,
                        structure_size: output.StructureSize,
                        protocol: output.Protocol,
                        protocol_major_version: output.ProtocolMajorVersion,
                        protocol_minor_version: output.ProtocolMinorVersion,
                        protocol_revision: output.ProtocolRevision,
                        flags: output.Flags,
                        reserved_are_zero: output.Reserved == 0
                            && output
                                .GenericReserved
                                .Reserved
                                .iter()
                                .all(|value| *value == 0)
                            && protocol_reserved.iter().all(|value| *value == 0),
                    }),
                    0,
                )
            }
        };
        let Some(remote) = remote else {
            return operating_system_fault(
                request,
                Some(PlatformPreflightQueryStage::RemoteProtocolInformation),
                remote_error,
            );
        };
        if !remote.reserved_are_zero {
            return Ok(observation_fault(
                request,
                PlatformPreflightQueryStage::RemoteProtocolInformation,
                PlatformPreflightObservationFaultClass::InvalidObservation,
            ));
        }
        let remote_protocol = WindowsRemoteProtocolInformation {
            structure_version: remote.structure_version,
            structure_size: remote.structure_size,
            protocol: remote.protocol,
            protocol_major_version: remote.protocol_major_version,
            protocol_minor_version: remote.protocol_minor_version,
            protocol_revision: remote.protocol_revision,
            flags: remote.flags,
        };
        if remote_protocol.protocol == 0 {
            return Ok(observation_fault(
                request,
                PlatformPreflightQueryStage::RemoteProtocolInformation,
                PlatformPreflightObservationFaultClass::InvalidObservation,
            ));
        }
        let complete = WindowsPlatformPreflightRecord::CompleteRemote {
            profile: WINDOWS_PLATFORM_PREFLIGHT_PROFILE.to_owned(),
            target_triple: request.target_triple.clone(),
            input_root: request.input_root.clone(),
            root_identity,
            remote_protocol,
            disposition: PlatformPreflightDisposition::RejectRemoteProtocol,
        };
        release_complete(request, complete)
    }

    fn release_complete(
        request: &WindowsPlatformPreflightRequest,
        complete: WindowsPlatformPreflightRecord,
    ) -> Result<WindowsPlatformPreflightRecord, WindowsPlatformPreflightRuntimeFault> {
        match complete.validate() {
            Ok(()) => Ok(complete),
            Err(fault) => Ok(observation_fault(
                request,
                stage_for_form_fault(&fault.field),
                PlatformPreflightObservationFaultClass::InvalidObservation,
            )),
        }
    }

    fn nul_terminated_utf16(value: &str) -> Vec<u16> {
        value.encode_utf16().chain([0]).collect()
    }

    fn encode_identity(identifier: [u8; 16]) -> String {
        use std::fmt::Write as _;

        let mut encoded = String::with_capacity(32);
        for byte in identifier {
            write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
        }
        encoded
    }

    fn canonicalize_volume_guid(path: String) -> String {
        const PREFIX: &str = r"\\?\Volume{";
        let Some(rest) = path.strip_prefix(PREFIX) else {
            return path;
        };
        let Some((guid, tail)) = rest.split_once(r"}\") else {
            return path;
        };
        format!("{PREFIX}{}}}\\{tail}", guid.to_ascii_lowercase())
    }

    fn decode_nul_terminated(
        buffer: &[u16],
    ) -> Result<String, PlatformPreflightObservationFaultClass> {
        let Some(length) = buffer.iter().position(|value| *value == 0) else {
            return Err(PlatformPreflightObservationFaultClass::InvalidObservation);
        };
        String::from_utf16(&buffer[..length])
            .map_err(|_| PlatformPreflightObservationFaultClass::InvalidUtf16)
    }

    fn local_disposition(file_system_name: &str) -> PlatformPreflightDisposition {
        if file_system_name == "NTFS" {
            PlatformPreflightDisposition::EligibleLocalNtfs
        } else {
            PlatformPreflightDisposition::RejectUnsupportedFileSystem
        }
    }

    fn operating_system_fault(
        request: &WindowsPlatformPreflightRequest,
        stage: Option<PlatformPreflightQueryStage>,
        error_code: u32,
    ) -> Result<WindowsPlatformPreflightRecord, WindowsPlatformPreflightRuntimeFault> {
        if error_code == 0 {
            let operation = match stage {
                Some(stage) => WindowsPlatformPreflightRuntimeOperation::Query { stage },
                None => WindowsPlatformPreflightRuntimeOperation::Open,
            };
            return Err(
                WindowsPlatformPreflightRuntimeFault::OperatingSystemErrorUnavailable { operation },
            );
        }
        Ok(match stage {
            Some(stage) => WindowsPlatformPreflightRecord::QueryFault {
                profile: WINDOWS_PLATFORM_PREFLIGHT_PROFILE.to_owned(),
                target_triple: request.target_triple.clone(),
                input_root: request.input_root.clone(),
                stage,
                error_code,
            },
            None => WindowsPlatformPreflightRecord::OpenFault {
                profile: WINDOWS_PLATFORM_PREFLIGHT_PROFILE.to_owned(),
                target_triple: request.target_triple.clone(),
                input_root: request.input_root.clone(),
                error_code,
            },
        })
    }

    fn observation_fault(
        request: &WindowsPlatformPreflightRequest,
        stage: PlatformPreflightQueryStage,
        class: PlatformPreflightObservationFaultClass,
    ) -> WindowsPlatformPreflightRecord {
        WindowsPlatformPreflightRecord::ObservationFault {
            profile: WINDOWS_PLATFORM_PREFLIGHT_PROFILE.to_owned(),
            target_triple: request.target_triple.clone(),
            input_root: request.input_root.clone(),
            stage,
            class,
        }
    }

    fn stage_for_form_fault(field: &str) -> PlatformPreflightQueryStage {
        if field.starts_with("root_identity") {
            PlatformPreflightQueryStage::FileIdInfo
        } else if field.starts_with("root_volume_guid_path") {
            PlatformPreflightQueryStage::FinalVolumeGuidPath
        } else if field.starts_with("volume.") {
            PlatformPreflightQueryStage::VolumeInformation
        } else {
            PlatformPreflightQueryStage::RemoteProtocolInformation
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn identity_encoding_is_lowercase_and_byte_order_preserving() {
            assert_eq!(
                encode_identity([
                    0x00, 0x01, 0x0a, 0x10, 0x7f, 0x80, 0xaa, 0xff, 1, 2, 3, 4, 5, 6, 7, 8,
                ]),
                "00010a107f80aaff0102030405060708"
            );
        }

        #[test]
        fn strict_utf16_and_terminator_fail_closed() {
            assert_eq!(decode_nul_terminated(&[b'N' as u16, 0]), Ok("N".to_owned()));
            assert_eq!(
                decode_nul_terminated(&[0xd800, 0]),
                Err(PlatformPreflightObservationFaultClass::InvalidUtf16)
            );
            assert_eq!(
                decode_nul_terminated(&[1, 2]),
                Err(PlatformPreflightObservationFaultClass::InvalidObservation)
            );
        }

        #[test]
        fn disposition_is_exact() {
            assert_eq!(
                local_disposition("NTFS"),
                PlatformPreflightDisposition::EligibleLocalNtfs
            );
            assert_eq!(
                local_disposition("ReFS"),
                PlatformPreflightDisposition::RejectUnsupportedFileSystem
            );
        }

        #[test]
        fn volume_guid_canonicalization_changes_only_guid_hex_case() {
            assert_eq!(
                canonicalize_volume_guid(
                    r"\\?\Volume{ABCDEFAB-1234-ABCD-9876-ABCDEFABCDEF}\Case".to_owned()
                ),
                r"\\?\Volume{abcdefab-1234-abcd-9876-abcdefabcdef}\Case"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cantor_ecosystem::{
        WINDOWS_PLATFORM_PREFLIGHT_PROFILE, WINDOWS_PLATFORM_PREFLIGHT_REQUEST_PROFILE,
        WINDOWS_PLATFORM_PREFLIGHT_TARGET,
    };

    fn request() -> WindowsPlatformPreflightRequest {
        WindowsPlatformPreflightRequest {
            request_profile: WINDOWS_PLATFORM_PREFLIGHT_REQUEST_PROFILE.to_owned(),
            result_profile: WINDOWS_PLATFORM_PREFLIGHT_PROFILE.to_owned(),
            target_triple: WINDOWS_PLATFORM_PREFLIGHT_TARGET.to_owned(),
            input_root: r"\\?\C:\definitely-absent-cantor-invalid-request-test".to_owned(),
        }
    }

    #[test]
    fn invalid_request_fails_before_target_dispatch() {
        let mut invalid = request();
        invalid.request_profile = "wrong".to_owned();
        assert!(matches!(
            observe_platform_preflight(&invalid),
            Err(WindowsPlatformPreflightRuntimeFault::InvalidRequest { .. })
        ));
    }

    #[test]
    fn runtime_profile_is_exact() {
        assert_eq!(
            WINDOWS_PLATFORM_PREFLIGHT_RUNTIME_PROFILE,
            "cantor-windows-platform-preflight-runtime/0.2"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn valid_request_is_explicitly_unsupported_off_windows() {
        assert_eq!(
            observe_platform_preflight(&request()),
            Err(WindowsPlatformPreflightRuntimeFault::UnsupportedTarget)
        );
    }
}
