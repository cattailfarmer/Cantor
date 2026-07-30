#![cfg(windows)]

use serde::Serialize;
use std::mem::{align_of, size_of};
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_SPARSE_FILE,
    FILE_ATTRIBUTE_TAG_INFO, FILE_CASE_SENSITIVE_INFO, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_ID_INFO, FILE_NAME_NORMALIZED,
    FILE_READ_ATTRIBUTES, FILE_REMOTE_PROTOCOL_INFO, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_STANDARD_INFO, FILE_STREAM_INFO, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA,
    FileAttributeTagInfo, FileCaseSensitiveInfo, FileIdInfo, FileRemoteProtocolInfo,
    FileStandardInfo, FileStreamInfo, GetFileInformationByHandleEx, GetFinalPathNameByHandleW,
    GetVolumeInformationByHandleW, OPEN_EXISTING, VOLUME_NAME_GUID,
};

const PROFILE: &str = "cantor-windows-topology-abi-probe/0.2";

#[derive(Serialize)]
struct Layout {
    name: &'static str,
    size: usize,
    align: usize,
}

#[derive(Serialize)]
struct AbiFingerprint {
    profile: &'static str,
    function_items: [&'static str; 5],
    layouts: [Layout; 6],
    information_classes: [i32; 6],
    policy_constants: [u32; 14],
}

#[test]
fn generated_function_items_are_available_without_calls() {
    let _ = CreateFileW;
    let _ = GetFileInformationByHandleEx;
    let _ = GetFinalPathNameByHandleW;
    let _ = GetVolumeInformationByHandleW;
    let _ = GetLastError;
}

#[test]
fn generated_information_classes_are_exact() {
    assert_eq!(FileStandardInfo, 1);
    assert_eq!(FileStreamInfo, 7);
    assert_eq!(FileAttributeTagInfo, 9);
    assert_eq!(FileRemoteProtocolInfo, 13);
    assert_eq!(FileIdInfo, 18);
    assert_eq!(FileCaseSensitiveInfo, 23);
}

#[test]
fn observation_policy_constants_are_exact_and_read_only() {
    assert_eq!(OPEN_EXISTING, 3);
    assert_eq!(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 7);
    assert_eq!(FILE_FLAG_BACKUP_SEMANTICS, 33_554_432);
    assert_eq!(FILE_FLAG_OPEN_REPARSE_POINT, 2_097_152);
    assert_eq!(FILE_ATTRIBUTE_NORMAL, 128);
    assert_eq!(FILE_ATTRIBUTE_SPARSE_FILE, 512);
    assert_eq!(FILE_ATTRIBUTE_REPARSE_POINT, 1_024);
    assert_eq!(FILE_READ_ATTRIBUTES, 128);
    assert_eq!(FILE_GENERIC_READ, 1_179_785);
    assert_eq!(
        FILE_GENERIC_READ & (FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES),
        0
    );
    assert_eq!(FILE_NAME_NORMALIZED, 0);
    assert_eq!(VOLUME_NAME_GUID, 1);
}

#[test]
fn generated_abi_fingerprint_is_exact() {
    let fingerprint = AbiFingerprint {
        profile: PROFILE,
        function_items: [
            "CreateFileW",
            "GetFileInformationByHandleEx",
            "GetFinalPathNameByHandleW",
            "GetVolumeInformationByHandleW",
            "GetLastError",
        ],
        layouts: [
            Layout {
                name: "FILE_ATTRIBUTE_TAG_INFO",
                size: size_of::<FILE_ATTRIBUTE_TAG_INFO>(),
                align: align_of::<FILE_ATTRIBUTE_TAG_INFO>(),
            },
            Layout {
                name: "FILE_CASE_SENSITIVE_INFO",
                size: size_of::<FILE_CASE_SENSITIVE_INFO>(),
                align: align_of::<FILE_CASE_SENSITIVE_INFO>(),
            },
            Layout {
                name: "FILE_ID_INFO",
                size: size_of::<FILE_ID_INFO>(),
                align: align_of::<FILE_ID_INFO>(),
            },
            Layout {
                name: "FILE_STANDARD_INFO",
                size: size_of::<FILE_STANDARD_INFO>(),
                align: align_of::<FILE_STANDARD_INFO>(),
            },
            Layout {
                name: "FILE_STREAM_INFO",
                size: size_of::<FILE_STREAM_INFO>(),
                align: align_of::<FILE_STREAM_INFO>(),
            },
            Layout {
                name: "FILE_REMOTE_PROTOCOL_INFO",
                size: size_of::<FILE_REMOTE_PROTOCOL_INFO>(),
                align: align_of::<FILE_REMOTE_PROTOCOL_INFO>(),
            },
        ],
        information_classes: [
            FileStandardInfo,
            FileStreamInfo,
            FileAttributeTagInfo,
            FileRemoteProtocolInfo,
            FileIdInfo,
            FileCaseSensitiveInfo,
        ],
        policy_constants: [
            OPEN_EXISTING,
            FILE_SHARE_READ,
            FILE_SHARE_WRITE,
            FILE_SHARE_DELETE,
            FILE_FLAG_BACKUP_SEMANTICS,
            FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_ATTRIBUTE_NORMAL,
            FILE_ATTRIBUTE_SPARSE_FILE,
            FILE_ATTRIBUTE_REPARSE_POINT,
            FILE_READ_ATTRIBUTES,
            FILE_GENERIC_READ,
            FILE_NAME_NORMALIZED,
            VOLUME_NAME_GUID,
            FILE_GENERIC_READ & (FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES),
        ],
    };

    let actual = serde_json::to_string(&fingerprint).expect("ABI fingerprint must serialize");
    let expected = concat!(
        r#"{"profile":"cantor-windows-topology-abi-probe/0.2","#,
        r#""function_items":["CreateFileW","GetFileInformationByHandleEx","#,
        r#""GetFinalPathNameByHandleW","GetVolumeInformationByHandleW","GetLastError"],"#,
        r#""layouts":[{"name":"FILE_ATTRIBUTE_TAG_INFO","size":8,"align":4},"#,
        r#"{"name":"FILE_CASE_SENSITIVE_INFO","size":4,"align":4},"#,
        r#"{"name":"FILE_ID_INFO","size":24,"align":8},"#,
        r#"{"name":"FILE_STANDARD_INFO","size":24,"align":8},"#,
        r#"{"name":"FILE_STREAM_INFO","size":32,"align":8},"#,
        r#"{"name":"FILE_REMOTE_PROTOCOL_INFO","size":116,"align":4}],"#,
        r#""information_classes":[1,7,9,13,18,23],"#,
        r#""policy_constants":[3,1,2,4,33554432,2097152,128,512,1024,128,1179785,0,1,0]}"#
    );

    assert_eq!(actual, expected);
}
