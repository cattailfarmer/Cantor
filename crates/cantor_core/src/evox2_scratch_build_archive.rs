//! Bounded USTAR/PAX archive admission and absent-root materialization.
//!
//! The parser accepts only regular files, directories, and narrowly scoped PAX
//! metadata. Links, devices, traversal, case collisions, base-256 numerics, and
//! trailing nonzero bytes are refused before extraction.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::Path;

use crate::evox2_scratch_build_executor::{
    EVOX2_SCRATCH_BUILD_SOURCE_ARCHIVE_SHA256, fixed_evox2_scratch_build_bounds,
};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evox2ScratchBuildArchiveVerification {
    pub profile: String,
    pub status: String,
    pub archive_bytes: u64,
    pub archive_sha256: String,
    pub member_count: u32,
    pub regular_file_count: u32,
    pub directory_count: u32,
    pub effects: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Member {
    path: String,
    kind: MemberKind,
    size: u64,
    data_offset: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MemberKind {
    File,
    Directory,
}

pub fn verify_evox2_scratch_build_source_archive(
    archive: &Path,
) -> Result<Evox2ScratchBuildArchiveVerification, String> {
    let (bytes, digest, members) = scan_archive(archive)?;
    if digest != EVOX2_SCRATCH_BUILD_SOURCE_ARCHIVE_SHA256 {
        return Err("source archive digest differs".to_owned());
    }
    let regular_file_count = members
        .iter()
        .filter(|member| member.kind == MemberKind::File)
        .count() as u32;
    let directory_count = members.len() as u32 - regular_file_count;
    Ok(Evox2ScratchBuildArchiveVerification {
        profile: "cantor-evox2-scratch-build-archive-verification/0.1".to_owned(),
        status: "passed".to_owned(),
        archive_bytes: bytes,
        archive_sha256: digest,
        member_count: members.len() as u32,
        regular_file_count,
        directory_count,
        effects: 0,
    })
}

pub fn materialize_evox2_scratch_build_source_archive(
    archive: &Path,
    stage: &Path,
    destination: &Path,
) -> Result<Evox2ScratchBuildArchiveVerification, String> {
    if stage.exists() || destination.exists() || stage.parent() != destination.parent() {
        return Err("absent sibling materialization roots required".to_owned());
    }
    let (bytes, digest, members) = scan_archive(archive)?;
    if digest != EVOX2_SCRATCH_BUILD_SOURCE_ARCHIVE_SHA256 {
        return Err("source archive digest differs".to_owned());
    }
    fs::create_dir(stage).map_err(|error| format!("stage creation failed: {error}"))?;
    extract_members(archive, stage, &members)?;
    fs::rename(stage, destination)
        .map_err(|error| format!("atomic workspace establishment failed: {error}"))?;
    let regular_file_count = members
        .iter()
        .filter(|member| member.kind == MemberKind::File)
        .count() as u32;
    Ok(Evox2ScratchBuildArchiveVerification {
        profile: "cantor-evox2-scratch-build-archive-materialization/0.1".to_owned(),
        status: "passed".to_owned(),
        archive_bytes: bytes,
        archive_sha256: digest,
        member_count: members.len() as u32,
        regular_file_count,
        directory_count: members.len() as u32 - regular_file_count,
        effects: 1,
    })
}

fn scan_archive(archive: &Path) -> Result<(u64, String, Vec<Member>), String> {
    let metadata = fs::symlink_metadata(archive)
        .map_err(|error| format!("source archive unavailable: {error}"))?;
    let bounds = fixed_evox2_scratch_build_bounds();
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > bounds.maximum_archive_bytes
        || metadata.len() % 512 != 0
    {
        return Err("source archive file boundary refused".to_owned());
    }
    let digest = file_digest(archive, metadata.len())?;
    let mut file = File::open(archive).map_err(|error| format!("archive open failed: {error}"))?;
    let mut offset = 0_u64;
    let mut zero_blocks = 0_u32;
    let mut members = Vec::new();
    let mut seen = BTreeSet::new();
    let mut pending_pax_path = None;
    let mut header = [0_u8; 512];
    while offset < metadata.len() {
        file.read_exact(&mut header)
            .map_err(|error| format!("archive header read failed: {error}"))?;
        offset += 512;
        if header.iter().all(|byte| *byte == 0) {
            zero_blocks += 1;
            if zero_blocks >= 2 {
                let mut tail = Vec::new();
                file.read_to_end(&mut tail)
                    .map_err(|error| format!("archive tail read failed: {error}"))?;
                if tail.iter().any(|byte| *byte != 0) {
                    return Err("archive trailing content refused".to_owned());
                }
                if pending_pax_path.is_some() {
                    return Err("orphan PAX path refused".to_owned());
                }
                return Ok((metadata.len(), digest, members));
            }
            continue;
        }
        if zero_blocks != 0 {
            return Err("archive partial terminator refused".to_owned());
        }
        validate_checksum(&header)?;
        let size = parse_octal(&header[124..136])?;
        let typeflag = header[156];
        let raw_path = ustar_path(&header)?;
        let data_offset = offset;
        let padded = size
            .checked_add(511)
            .map(|value| value / 512 * 512)
            .ok_or_else(|| "archive member size overflow".to_owned())?;
        if offset
            .checked_add(padded)
            .is_none_or(|end| end > metadata.len())
        {
            return Err("archive member exceeds file".to_owned());
        }
        match typeflag {
            b'x' | b'g' => {
                if size > 65_536 {
                    return Err("PAX payload exceeds bound".to_owned());
                }
                let mut payload = vec![0_u8; size as usize];
                file.read_exact(&mut payload)
                    .map_err(|error| format!("PAX read failed: {error}"))?;
                let padding = padded - size;
                if padding != 0 {
                    let mut discard = vec![0_u8; padding as usize];
                    file.read_exact(&mut discard)
                        .map_err(|error| format!("PAX padding read failed: {error}"))?;
                    if discard.iter().any(|byte| *byte != 0) {
                        return Err("PAX padding differs".to_owned());
                    }
                }
                offset += padded;
                let path = parse_pax(&payload, typeflag == b'g')?;
                if typeflag == b'x' {
                    if pending_pax_path.is_some() {
                        return Err("stacked PAX path refused".to_owned());
                    }
                    pending_pax_path = path;
                } else if path.is_some() {
                    return Err("global PAX path refused".to_owned());
                }
                continue;
            }
            b'0' | 0 | b'5' => {}
            _ => return Err("archive special member refused".to_owned()),
        }
        let mut path = pending_pax_path.take().unwrap_or(raw_path);
        if typeflag == b'5' {
            path = path
                .strip_suffix('/')
                .ok_or_else(|| "archive directory terminator differs".to_owned())?
                .to_owned();
        }
        validate_member_path(&path)?;
        let coordinate = path.to_ascii_lowercase();
        if !seen.insert(coordinate) {
            return Err("archive duplicate case-folded coordinate refused".to_owned());
        }
        let kind = if typeflag == b'5' {
            if size != 0 {
                return Err("archive directory payload refused".to_owned());
            }
            MemberKind::Directory
        } else {
            MemberKind::File
        };
        members.push(Member {
            path,
            kind,
            size,
            data_offset,
        });
        if members.len() > bounds.maximum_files as usize {
            return Err("archive member count exceeds bound".to_owned());
        }
        file.seek_relative(size as i64)
            .map_err(|error| format!("archive member seek failed: {error}"))?;
        let padding = padded - size;
        if padding != 0 {
            let mut discard = vec![0_u8; padding as usize];
            file.read_exact(&mut discard)
                .map_err(|error| format!("archive padding read failed: {error}"))?;
            if discard.iter().any(|byte| *byte != 0) {
                return Err("archive member padding differs".to_owned());
            }
        }
        offset += padded;
    }
    Err("archive terminator missing".to_owned())
}

fn extract_members(archive: &Path, stage: &Path, members: &[Member]) -> Result<(), String> {
    let mut archive_file =
        File::open(archive).map_err(|error| format!("archive open failed: {error}"))?;
    for member in members {
        let relative = member.path.replace('/', std::path::MAIN_SEPARATOR_STR);
        let destination = stage.join(relative);
        if !destination.starts_with(stage) {
            return Err("archive materialization escaped stage".to_owned());
        }
        match member.kind {
            MemberKind::Directory => {
                fs::create_dir_all(&destination)
                    .map_err(|error| format!("archive directory creation failed: {error}"))?;
            }
            MemberKind::File => {
                let parent = destination
                    .parent()
                    .ok_or_else(|| "archive file parent unavailable".to_owned())?;
                fs::create_dir_all(parent)
                    .map_err(|error| format!("archive parent creation failed: {error}"))?;
                let mut output = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&destination)
                    .map_err(|error| format!("archive file creation failed: {error}"))?;
                archive_file
                    .seek(std::io::SeekFrom::Start(member.data_offset))
                    .map_err(|error| format!("archive seek failed: {error}"))?;
                let mut bounded = (&mut archive_file).take(member.size);
                let copied = std::io::copy(&mut bounded, &mut output)
                    .map_err(|error| format!("archive copy failed: {error}"))?;
                if copied != member.size {
                    return Err("archive file copy truncated".to_owned());
                }
                output
                    .flush()
                    .map_err(|error| format!("archive file flush failed: {error}"))?;
            }
        }
    }
    Ok(())
}

fn file_digest(path: &Path, expected: u64) -> Result<String, String> {
    let mut file = File::open(path).map_err(|error| format!("archive open failed: {error}"))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 65_536];
    let mut observed = 0_u64;
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("archive hash read failed: {error}"))?;
        if count == 0 {
            break;
        }
        observed = observed
            .checked_add(count as u64)
            .ok_or_else(|| "archive hash byte overflow".to_owned())?;
        if observed > expected {
            return Err("archive changed during hash".to_owned());
        }
        digest.update(&buffer[..count]);
    }
    if observed != expected {
        return Err("archive changed during hash".to_owned());
    }
    Ok(digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn validate_checksum(header: &[u8; 512]) -> Result<(), String> {
    let expected = parse_octal(&header[148..156])?;
    let observed = header
        .iter()
        .enumerate()
        .map(|(index, byte)| {
            if (148..156).contains(&index) {
                u64::from(b' ')
            } else {
                u64::from(*byte)
            }
        })
        .sum::<u64>();
    if expected != observed {
        return Err("archive header checksum differs".to_owned());
    }
    Ok(())
}

fn parse_octal(field: &[u8]) -> Result<u64, String> {
    if field.first().is_some_and(|byte| byte & 0x80 != 0) {
        return Err("archive base-256 numeric refused".to_owned());
    }
    let start = field
        .iter()
        .position(|byte| *byte != 0 && *byte != b' ')
        .unwrap_or(field.len());
    let end = field[start..]
        .iter()
        .position(|byte| *byte == 0 || *byte == b' ')
        .map(|index| start + index)
        .unwrap_or(field.len());
    if field[end..].iter().any(|byte| *byte != 0 && *byte != b' ') {
        return Err("archive octal suffix refused".to_owned());
    }
    let text = &field[start..end];
    if text.is_empty() {
        return Ok(0);
    }
    if text.iter().any(|byte| !(b'0'..=b'7').contains(byte)) {
        return Err("archive octal field refused".to_owned());
    }
    text.iter().copied().try_fold(0_u64, |value, byte| {
        value
            .checked_mul(8)
            .and_then(|value| value.checked_add(u64::from(byte - b'0')))
            .ok_or_else(|| "archive octal overflow".to_owned())
    })
}

fn ustar_path(header: &[u8; 512]) -> Result<String, String> {
    let name = text_field(&header[0..100])?;
    let prefix = text_field(&header[345..500])?;
    if prefix.is_empty() {
        Ok(name)
    } else {
        Ok(format!("{prefix}/{name}"))
    }
}

fn text_field(field: &[u8]) -> Result<String, String> {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    if field[end..].iter().any(|byte| *byte != 0) {
        return Err("archive text field padding differs".to_owned());
    }
    std::str::from_utf8(&field[..end])
        .map(str::to_owned)
        .map_err(|_| "archive path UTF-8 refused".to_owned())
}

fn parse_pax(payload: &[u8], global: bool) -> Result<Option<String>, String> {
    if payload.iter().any(|byte| !byte.is_ascii()) {
        return Err("PAX non-ASCII content refused".to_owned());
    }
    let text = std::str::from_utf8(payload).map_err(|_| "PAX UTF-8 refused".to_owned())?;
    let mut offset = 0_usize;
    let mut path = None;
    while offset < text.len() {
        let space = text[offset..]
            .find(' ')
            .map(|index| offset + index)
            .ok_or_else(|| "PAX length refused".to_owned())?;
        let length = text[offset..space]
            .parse::<usize>()
            .map_err(|_| "PAX length refused".to_owned())?;
        if length == 0 || offset + length > text.len() {
            return Err("PAX record boundary refused".to_owned());
        }
        let record = &text[space + 1..offset + length];
        if !record.ends_with('\n') {
            return Err("PAX record terminator refused".to_owned());
        }
        let content = &record[..record.len() - 1];
        let (key, value) = content
            .split_once('=')
            .ok_or_else(|| "PAX assignment refused".to_owned())?;
        match key {
            "path" if !global && path.is_none() => path = Some(value.to_owned()),
            "comment" if global => {}
            _ => return Err("PAX key refused".to_owned()),
        }
        offset += length;
    }
    Ok(path)
}

fn validate_member_path(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 4_096
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains('\\')
        || value.contains(':')
        || value.chars().any(|character| {
            !character.is_ascii()
                || character.is_control()
                || matches!(character, '*' | '?' | '"' | '<' | '>' | '|')
        })
        || value.split('/').any(|segment| {
            segment.is_empty()
                || segment == "."
                || segment == ".."
                || segment.ends_with('.')
                || segment.ends_with(' ')
        })
    {
        return Err("archive member path refused".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn regular_ustar_scans_and_extracts_inside_absent_stage() {
        let root = test_root("regular");
        fs::create_dir(&root).unwrap();
        let archive = root.join("fixture.tar");
        fs::write(
            &archive,
            tar(&[("src/", b'5', b""), ("src/lib.rs", b'0', b"safe")]),
        )
        .unwrap();
        let (_, _, members) = scan_archive(&archive).unwrap();
        let stage = root.join("stage");
        fs::create_dir(&stage).unwrap();
        extract_members(&archive, &stage, &members).unwrap();
        assert_eq!(fs::read(stage.join("src/lib.rs")).unwrap(), b"safe");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn traversal_link_and_case_duplicate_members_refuse() {
        for (label, entries) in [
            ("traversal", vec![("../escape", b'0', b"x".as_slice())]),
            ("link", vec![("link", b'2', b"".as_slice())]),
            (
                "duplicate",
                vec![("Path", b'0', b"a".as_slice()), ("path", b'0', b"b")],
            ),
        ] {
            let root = test_root(label);
            fs::create_dir(&root).unwrap();
            let archive = root.join("fixture.tar");
            fs::write(&archive, tar(&entries)).unwrap();
            assert!(scan_archive(&archive).is_err());
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn nonzero_padding_checksum_and_trailing_content_refuse() {
        let root = test_root("framing");
        fs::create_dir(&root).unwrap();
        let archive = root.join("fixture.tar");
        let canonical = tar(&[("file", b'0', b"x")]);

        let mut changed = canonical.clone();
        changed[513] = 1;
        fs::write(&archive, changed).unwrap();
        assert!(scan_archive(&archive).is_err());

        let mut changed = canonical.clone();
        changed[0] = b'X';
        fs::write(&archive, changed).unwrap();
        assert!(scan_archive(&archive).is_err());

        let mut changed = canonical;
        *changed.last_mut().unwrap() = 1;
        fs::write(&archive, changed).unwrap();
        assert!(scan_archive(&archive).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    fn test_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "cantor-evox2-archive-{label}-{}",
            std::process::id()
        ))
    }

    fn tar(entries: &[(&str, u8, &[u8])]) -> Vec<u8> {
        let mut output = Vec::new();
        for (path, kind, content) in entries {
            let mut header = [0_u8; 512];
            header[..path.len()].copy_from_slice(path.as_bytes());
            write_octal(&mut header[100..108], 0o644);
            write_octal(&mut header[108..116], 0);
            write_octal(&mut header[116..124], 0);
            write_octal(&mut header[124..136], content.len() as u64);
            write_octal(&mut header[136..148], 0);
            header[148..156].fill(b' ');
            header[156] = *kind;
            header[257..263].copy_from_slice(b"ustar\0");
            header[263..265].copy_from_slice(b"00");
            let checksum = header.iter().map(|byte| u64::from(*byte)).sum::<u64>();
            let encoded = format!("{checksum:06o}\0 ");
            header[148..156].copy_from_slice(encoded.as_bytes());
            output.extend_from_slice(&header);
            output.extend_from_slice(content);
            output.resize(output.len().next_multiple_of(512), 0);
        }
        output.resize(output.len() + 1024, 0);
        output
    }

    fn write_octal(field: &mut [u8], value: u64) {
        let encoded = format!("{:0width$o}\0", value, width = field.len() - 1);
        field.copy_from_slice(encoded.as_bytes());
    }
}
