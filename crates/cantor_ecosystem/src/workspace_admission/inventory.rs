use std::{fs, path::PathBuf};

use super::*;

#[derive(Clone, Debug, Default)]
pub(super) struct WorktreeEntry {
    worktree: Option<PathBuf>,
    head: Option<String>,
    branch: Option<String>,
    disqualifier: Option<String>,
}

pub(super) fn parse_worktree_inventory(
    bytes: &[u8],
    account: &AdmissionResourceAccount,
) -> Result<Vec<WorktreeEntry>, AdmissionFault> {
    if bytes.is_empty() || !bytes.ends_with(&[0, 0]) {
        return Err(fault(
            AdmissionFaultCode::Protocol,
            "worktree_inventory",
            "worktree inventory lacks its exact double-NUL terminator",
            account.clone(),
        ));
    }
    let fields = bytes[..bytes.len() - 2]
        .split(|byte| *byte == 0)
        .collect::<Vec<_>>();
    let mut entries = Vec::new();
    for record in fields.split(|field| field.is_empty()) {
        if record.is_empty() {
            continue;
        }
        let mut entry = WorktreeEntry::default();
        for field in record {
            let text = std::str::from_utf8(field).map_err(|_| {
                fault(
                    AdmissionFaultCode::Protocol,
                    "worktree_inventory",
                    "worktree inventory is not UTF-8",
                    account.clone(),
                )
            })?;
            if let Some(value) = text.strip_prefix("worktree ") {
                set_once_path(&mut entry.worktree, value, "worktree", account)?;
            } else if let Some(value) = text.strip_prefix("HEAD ") {
                set_once(&mut entry.head, value, "HEAD", account)?;
            } else if let Some(value) = text.strip_prefix("branch ") {
                set_once(&mut entry.branch, value, "branch", account)?;
            } else if matches!(text, "bare" | "detached")
                || text.starts_with("locked")
                || text.starts_with("prunable")
            {
                set_once(&mut entry.disqualifier, text, "disqualifier", account)?;
            } else {
                return Err(fault(
                    AdmissionFaultCode::Protocol,
                    "worktree_inventory",
                    "worktree inventory contains an unknown field",
                    account.clone(),
                ));
            }
        }
        if entry.worktree.is_none() || entry.head.is_none() {
            return Err(fault(
                AdmissionFaultCode::Protocol,
                "worktree_inventory",
                "worktree inventory entry is incomplete",
                account.clone(),
            ));
        }
        entries.push(entry);
    }
    if entries.is_empty() {
        return Err(fault(
            AdmissionFaultCode::Protocol,
            "worktree_inventory",
            "worktree inventory is empty",
            account.clone(),
        ));
    }
    Ok(entries)
}

pub(super) fn reconcile_inventory(
    entries: &[WorktreeEntry],
    request: &ValidatedRequest,
    candidate_head: &str,
    candidate_branch: &str,
    account: &AdmissionResourceAccount,
) -> Result<(), AdmissionFault> {
    let mut matches = 0_u8;
    for entry in entries {
        let Some(worktree) = entry.worktree.as_ref() else {
            continue;
        };
        let canonical = fs::canonicalize(worktree).map_err(|error| {
            fault(
                AdmissionFaultCode::Repository,
                "worktree_inventory",
                error.to_string(),
                account.clone(),
            )
        })?;
        if canonical == request.candidate_workspace {
            matches = matches.saturating_add(1);
            if entry.head.as_deref() != Some(candidate_head)
                || entry.branch.as_deref() != Some(candidate_branch)
                || entry.disqualifier.is_some()
            {
                return Err(fault(
                    AdmissionFaultCode::Isolation,
                    "worktree_inventory",
                    "candidate inventory entry differs or is disqualified",
                    account.clone(),
                ));
            }
        }
    }
    if matches == 1 {
        Ok(())
    } else {
        Err(fault(
            AdmissionFaultCode::Isolation,
            "worktree_inventory",
            "candidate workspace does not have exactly one inventory entry",
            account.clone(),
        ))
    }
}

fn set_once(
    slot: &mut Option<String>,
    value: &str,
    label: &str,
    account: &AdmissionResourceAccount,
) -> Result<(), AdmissionFault> {
    if slot.replace(value.to_owned()).is_some() {
        Err(fault(
            AdmissionFaultCode::Protocol,
            "worktree_inventory",
            format!("duplicate {label} field"),
            account.clone(),
        ))
    } else {
        Ok(())
    }
}

fn set_once_path(
    slot: &mut Option<PathBuf>,
    value: &str,
    label: &str,
    account: &AdmissionResourceAccount,
) -> Result<(), AdmissionFault> {
    if slot.replace(PathBuf::from(value)).is_some() {
        Err(fault(
            AdmissionFaultCode::Protocol,
            "worktree_inventory",
            format!("duplicate {label} field"),
            account.clone(),
        ))
    } else {
        Ok(())
    }
}
