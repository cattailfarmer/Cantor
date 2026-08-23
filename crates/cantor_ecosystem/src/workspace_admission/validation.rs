use std::{
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

use super::*;

pub(super) fn validate_request(
    request: &CandidateWorkspaceRequest,
) -> Result<ValidatedRequest, AdmissionFault> {
    validate_request_claims(request)?;
    let account = empty_account(request.budget.timeout_millis);
    let git_executable = validate_regular_file(
        &request.git_executable,
        &request.git_executable_sha256,
        "git_executable",
        account.clone(),
    )?;
    let principal_workspace = validate_directory(
        &request.principal_workspace,
        "principal_workspace",
        account.clone(),
    )?;
    let candidate_workspace = validate_directory(
        &request.candidate_workspace,
        "candidate_workspace",
        account.clone(),
    )?;
    let repository_common_dir = validate_directory(
        &request.expected_repository_common_dir,
        "expected_repository_common_dir",
        account.clone(),
    )?;
    if overlaps(&principal_workspace, &candidate_workspace) {
        return Err(fault(
            AdmissionFaultCode::Isolation,
            "workspace_separation",
            "principal and candidate workspaces overlap",
            account,
        ));
    }
    Ok(ValidatedRequest {
        source: request.clone(),
        git_executable,
        principal_workspace,
        candidate_workspace,
        repository_common_dir,
    })
}

pub(super) fn validate_request_claims(
    request: &CandidateWorkspaceRequest,
) -> Result<(), AdmissionFault> {
    let account = empty_account(request.budget.timeout_millis);
    if request.profile != CANDIDATE_WORKSPACE_ADMISSION_PROFILE {
        return Err(fault(
            AdmissionFaultCode::Request,
            "request",
            "unsupported candidate workspace admission profile",
            account,
        ));
    }
    validate_uuid(&request.candidate_uuid, "candidate_uuid", account.clone())?;
    validate_uuid(
        &request.correlation_uuid,
        "correlation_uuid",
        account.clone(),
    )?;
    validate_nonce(&request.admission_nonce, account.clone())?;
    validate_digest(
        &request.git_executable_sha256,
        "git_executable_sha256",
        account.clone(),
    )?;
    validate_text(&request.git_version, "git_version", account.clone())?;
    validate_object_id(
        &request.expected_base_commit,
        "expected_base_commit",
        account.clone(),
    )?;
    validate_branch_ref(
        &request.expected_branch_ref,
        "expected_branch_ref",
        account.clone(),
    )?;
    validate_budget(request.budget)?;
    validate_sorted_unique_refs(
        &request.protected_branch_refs,
        &request.expected_branch_ref,
        account.clone(),
    )?;
    validate_allowed_paths(&request.allowed_relative_paths, account.clone())?;
    Ok(())
}

fn validate_budget(budget: AdmissionBudget) -> Result<(), AdmissionFault> {
    let account = empty_account(budget.timeout_millis);
    if budget.maximum_command_bytes == 0
        || budget.maximum_command_bytes > HARD_MAX_COMMAND_BYTES
        || budget.maximum_total_bytes < budget.maximum_command_bytes
        || budget.maximum_total_bytes > HARD_MAX_TOTAL_BYTES
        || budget.maximum_processes < MINIMUM_PROCESS_COUNT
        || budget.maximum_processes > HARD_MAX_PROCESSES
        || budget.timeout_millis == 0
        || budget.timeout_millis > HARD_MAX_TIMEOUT_MILLIS
    {
        return Err(fault(
            AdmissionFaultCode::Budget,
            "request_budget",
            "admission budget is zero, insufficient, inconsistent, or above a hard limit",
            account,
        ));
    }
    Ok(())
}

fn validate_uuid(
    value: &str,
    operation: &str,
    account: AdmissionResourceAccount,
) -> Result<(), AdmissionFault> {
    let valid = value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        });
    if valid {
        Ok(())
    } else {
        Err(fault(
            AdmissionFaultCode::Request,
            operation,
            "identity is not a canonical lowercase UUID",
            account,
        ))
    }
}

fn validate_nonce(value: &str, account: AdmissionResourceAccount) -> Result<(), AdmissionFault> {
    if !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'.'))
    {
        Ok(())
    } else {
        Err(fault(
            AdmissionFaultCode::Request,
            "admission_nonce",
            "admission nonce is empty, oversized, or noncanonical",
            account,
        ))
    }
}

fn validate_text(
    value: &str,
    operation: &str,
    account: AdmissionResourceAccount,
) -> Result<(), AdmissionFault> {
    if !value.trim().is_empty() && value.len() <= MAX_TEXT_BYTES && !value.contains('\0') {
        Ok(())
    } else {
        Err(fault(
            AdmissionFaultCode::Request,
            operation,
            "text is empty, oversized, or contains NUL",
            account,
        ))
    }
}

fn validate_digest(
    value: &str,
    operation: &str,
    account: AdmissionResourceAccount,
) -> Result<(), AdmissionFault> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(fault(
            AdmissionFaultCode::Request,
            operation,
            "digest is not canonical lowercase SHA-256",
            account,
        ))
    }
}

pub(super) fn validate_object_id(
    value: &str,
    operation: &str,
    account: AdmissionResourceAccount,
) -> Result<(), AdmissionFault> {
    if matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(fault(
            AdmissionFaultCode::Branch,
            operation,
            "Git object ID is not a canonical full lowercase hash",
            account,
        ))
    }
}

pub(super) fn validate_branch_ref(
    value: &str,
    operation: &str,
    account: AdmissionResourceAccount,
) -> Result<(), AdmissionFault> {
    let valid = value.strip_prefix("refs/heads/").is_some_and(|suffix| {
        let components_are_safe = suffix
            .split('/')
            .all(|component| !component.starts_with('.') && !component.ends_with('.'));
        !suffix.is_empty()
            && components_are_safe
            && !suffix.starts_with('/')
            && !suffix.ends_with('/')
            && !suffix.ends_with('.')
            && !suffix.ends_with(".lock")
            && !suffix.contains("..")
            && !suffix.contains("//")
            && !suffix.contains("@{")
            && suffix.bytes().all(|byte| {
                byte > b' '
                    && byte != 0x7f
                    && !matches!(byte, b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
            })
    });
    if valid {
        Ok(())
    } else {
        Err(fault(
            AdmissionFaultCode::Branch,
            operation,
            "branch is not a safe full local branch ref",
            account,
        ))
    }
}

fn validate_sorted_unique_refs(
    values: &[String],
    expected: &str,
    account: AdmissionResourceAccount,
) -> Result<(), AdmissionFault> {
    if values.is_empty() || values.len() > MAX_SET_ITEMS {
        return Err(fault(
            AdmissionFaultCode::Request,
            "protected_branch_refs",
            "protected branch set is empty or oversized",
            account,
        ));
    }
    let mut prior: Option<&str> = None;
    for value in values {
        validate_branch_ref(value, "protected_branch_refs", account.clone())?;
        if prior.is_some_and(|prior| prior >= value.as_str()) {
            return Err(fault(
                AdmissionFaultCode::Request,
                "protected_branch_refs",
                "protected branch refs are not strictly sorted and unique",
                account,
            ));
        }
        prior = Some(value);
    }
    if values
        .binary_search_by(|value| value.as_str().cmp(expected))
        .is_ok()
    {
        return Err(fault(
            AdmissionFaultCode::Branch,
            "protected_branch_refs",
            "expected candidate branch is protected",
            account,
        ));
    }
    Ok(())
}

fn validate_allowed_paths(
    values: &[String],
    account: AdmissionResourceAccount,
) -> Result<(), AdmissionFault> {
    if values.is_empty() || values.len() > MAX_SET_ITEMS {
        return Err(fault(
            AdmissionFaultCode::Path,
            "allowed_relative_paths",
            "allowed path set is empty or oversized",
            account,
        ));
    }
    let mut prior: Option<&str> = None;
    for value in values {
        let segments = value.split('/').collect::<Vec<_>>();
        let valid = !value.is_empty()
            && !value.starts_with('/')
            && !value.ends_with('/')
            && !value.contains(['\\', '\0', ':'])
            && segments.iter().all(|segment| {
                !segment.is_empty()
                    && !matches!(*segment, "." | "..")
                    && !segment.eq_ignore_ascii_case(".git")
            });
        if !valid {
            return Err(fault(
                AdmissionFaultCode::Path,
                "allowed_relative_paths",
                "allowed path is not a canonical safe relative path",
                account,
            ));
        }
        if let Some(prior) = prior
            && (prior >= value.as_str()
                || value
                    .strip_prefix(prior)
                    .is_some_and(|suffix| suffix.starts_with('/')))
        {
            return Err(fault(
                AdmissionFaultCode::Path,
                "allowed_relative_paths",
                "allowed paths are not sorted, unique, and nonoverlapping",
                account,
            ));
        }
        prior = Some(value);
    }
    Ok(())
}

fn validate_regular_file(
    path: &Path,
    expected_hash: &str,
    operation: &str,
    account: AdmissionResourceAccount,
) -> Result<PathBuf, AdmissionFault> {
    if !path.is_absolute() {
        return Err(fault(
            AdmissionFaultCode::Path,
            operation,
            "path is not absolute",
            account,
        ));
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        fault(
            AdmissionFaultCode::Path,
            operation,
            error.to_string(),
            account.clone(),
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(fault(
            AdmissionFaultCode::Path,
            operation,
            "path is not a nonsymlink regular file",
            account,
        ));
    }
    let canonical = fs::canonicalize(path).map_err(|error| {
        fault(
            AdmissionFaultCode::Path,
            operation,
            error.to_string(),
            account.clone(),
        )
    })?;
    if canonical != path {
        return Err(fault(
            AdmissionFaultCode::Path,
            operation,
            "path is not already canonical",
            account,
        ));
    }
    if hash_file(&canonical, operation, account.clone())? != expected_hash {
        return Err(fault(
            AdmissionFaultCode::Executable,
            operation,
            "file digest differs from the pin",
            account,
        ));
    }
    Ok(canonical)
}

fn validate_directory(
    path: &Path,
    operation: &str,
    account: AdmissionResourceAccount,
) -> Result<PathBuf, AdmissionFault> {
    if !path.is_absolute() {
        return Err(fault(
            AdmissionFaultCode::Path,
            operation,
            "path is not absolute",
            account,
        ));
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        fault(
            AdmissionFaultCode::Path,
            operation,
            error.to_string(),
            account.clone(),
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(fault(
            AdmissionFaultCode::Path,
            operation,
            "path is not a nonsymlink directory",
            account,
        ));
    }
    let canonical = fs::canonicalize(path).map_err(|error| {
        fault(
            AdmissionFaultCode::Path,
            operation,
            error.to_string(),
            account.clone(),
        )
    })?;
    if canonical != path {
        return Err(fault(
            AdmissionFaultCode::Path,
            operation,
            "path is not already canonical",
            account,
        ));
    }
    Ok(canonical)
}

pub(super) fn hash_file(
    path: &Path,
    operation: &str,
    account: AdmissionResourceAccount,
) -> Result<String, AdmissionFault> {
    let mut file = File::open(path).map_err(|error| {
        fault(
            AdmissionFaultCode::Executable,
            operation,
            error.to_string(),
            account.clone(),
        )
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(|error| {
            fault(
                AdmissionFaultCode::Executable,
                operation,
                error.to_string(),
                account.clone(),
            )
        })?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn overlaps(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

pub(super) fn path_text<'path>(
    path: &'path Path,
    operation: &str,
) -> Result<&'path str, AdmissionFault> {
    path.to_str().ok_or_else(|| {
        fault(
            AdmissionFaultCode::Path,
            operation,
            "path is not UTF-8",
            empty_account(0),
        )
    })
}

pub(super) fn one_line(
    bytes: &[u8],
    operation: &str,
    account: &AdmissionResourceAccount,
) -> Result<String, AdmissionFault> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        fault(
            AdmissionFaultCode::Protocol,
            operation,
            "observation is not UTF-8",
            account.clone(),
        )
    })?;
    let text = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(text);
    if text.is_empty()
        || text
            .chars()
            .any(|character| matches!(character, '\r' | '\n' | '\0'))
    {
        return Err(fault(
            AdmissionFaultCode::Protocol,
            operation,
            "observation is not exactly one nonempty line",
            account.clone(),
        ));
    }
    Ok(text.to_owned())
}

pub(super) fn observed_path(
    bytes: &[u8],
    operation: &str,
    account: &AdmissionResourceAccount,
) -> Result<PathBuf, AdmissionFault> {
    let path = PathBuf::from(one_line(bytes, operation, account)?);
    if !path.is_absolute() {
        return Err(fault(
            AdmissionFaultCode::Repository,
            operation,
            "Git returned a nonabsolute path",
            account.clone(),
        ));
    }
    fs::canonicalize(&path).map_err(|error| {
        fault(
            AdmissionFaultCode::Repository,
            operation,
            error.to_string(),
            account.clone(),
        )
    })
}

pub(super) fn reconcile_path(
    actual: &Path,
    expected: &Path,
    operation: &str,
    account: &AdmissionResourceAccount,
) -> Result<(), AdmissionFault> {
    if actual == expected {
        Ok(())
    } else {
        Err(fault(
            AdmissionFaultCode::Repository,
            operation,
            "observed path differs from the admitted path",
            account.clone(),
        ))
    }
}
