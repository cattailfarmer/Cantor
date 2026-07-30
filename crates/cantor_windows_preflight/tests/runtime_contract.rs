use std::{fs, path::Path};

use cantor_ecosystem::{
    PlatformPreflightDisposition, ValidatePlatformPreflightForm,
    WINDOWS_PLATFORM_PREFLIGHT_PROFILE, WINDOWS_PLATFORM_PREFLIGHT_REQUEST_PROFILE,
    WINDOWS_PLATFORM_PREFLIGHT_TARGET, WindowsPlatformPreflightRecord,
    WindowsPlatformPreflightRequest,
};
use cantor_windows_preflight::observe_platform_preflight;

const EXACT_FIXTURE_ROOT: &str = r"\\?\C:\Project\Cantor\.local\m2b-platform-preflight-fixture";

#[test]
fn source_has_exact_six_block_private_seam_and_closed_calls() {
    let source = include_str!("../src/lib.rs");
    let seam = source
        .split_once("    #[cfg(test)]\n    mod tests")
        .expect("private seam test boundary")
        .0;
    assert_eq!(seam.matches("unsafe {").count(), 6);
    assert_eq!(seam.matches("// SAFETY:").count(), 6);
    assert!(seam.contains("#[allow(unsafe_code)]\nmod windows_runtime"));
    for required in [
        "CreateFileW(",
        "GetFileInformationByHandleEx(",
        "GetFinalPathNameByHandleW(",
        "GetVolumeInformationByHandleW(",
        "GetLastError()",
        "OwnedHandle::from_raw_handle(",
        "FILE_READ_ATTRIBUTES",
        "FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE",
        "FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS",
    ] {
        assert!(
            seam.contains(required),
            "missing required seam token {required}"
        );
    }
    for forbidden in [
        "CloseHandle(",
        "ReadFile(",
        "WriteFile(",
        "DeleteFile",
        "MoveFile",
        "GENERIC_WRITE",
        "FILE_WRITE_DATA",
    ] {
        assert!(
            !seam.contains(forbidden),
            "forbidden seam token present: {forbidden}"
        );
    }
}

#[cfg(windows)]
#[test]
#[ignore = "requires the governed exact-root Windows fixture runner"]
fn exact_windows_fixture_emits_one_complete_local_ntfs_observation() {
    let request_path = std::env::var_os("CANTOR_WINDOWS_PREFLIGHT_REQUEST_PATH")
        .expect("governed runner supplies request path");
    let request: WindowsPlatformPreflightRequest = serde_json::from_slice(
        &fs::read(Path::new(&request_path)).expect("governed request file must read"),
    )
    .expect("governed request JSON");
    request.validate().expect("governed request validates");
    assert_eq!(
        request.request_profile,
        WINDOWS_PLATFORM_PREFLIGHT_REQUEST_PROFILE
    );
    assert_eq!(request.result_profile, WINDOWS_PLATFORM_PREFLIGHT_PROFILE);
    assert_eq!(request.target_triple, WINDOWS_PLATFORM_PREFLIGHT_TARGET);
    assert_eq!(request.input_root, EXACT_FIXTURE_ROOT);

    let result = observe_platform_preflight(&request).expect("runtime-layer fault");
    result.validate().expect("released record validates");
    println!(
        "CANTOR_WINDOWS_PREFLIGHT_RESULT={}",
        serde_json::to_string(&result).expect("result JSON")
    );
    match &result {
        WindowsPlatformPreflightRecord::CompleteLocal {
            volume,
            disposition,
            ..
        } => {
            assert_eq!(volume.file_system_name, "NTFS");
            assert_eq!(
                *disposition,
                PlatformPreflightDisposition::EligibleLocalNtfs
            );
        }
        other => panic!("expected complete_local NTFS preflight, got {other:?}"),
    }
}
