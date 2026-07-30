//! Pure checked parser for an exact caller-supplied `FILE_STREAM_INFO` region.
//!
//! Parse success proves only that the bytes satisfy this structural profile.
//! It does not prove that Windows produced the bytes or enumerated all streams.

use std::fmt;

use serde::{Deserialize, Serialize};

pub const WINDOWS_STREAM_INFO_PARSER_PROFILE: &str = "cantor-windows-stream-info-parser/0.1";
const STREAM_INFO_HEADER_BYTES: usize = 24;
const MAXIMUM_ENTRIES_PROFILE_BOUND: u32 = 1_024;
const MAXIMUM_NAME_UNITS_PROFILE_BOUND: u32 = 32_767;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsStreamInfoParseLimits {
    pub maximum_entries: u32,
    pub maximum_name_utf16_units: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsRawStreamRecord {
    pub name: String,
    pub stream_size: u64,
    pub allocation_size: u64,
    pub source_offset: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsStreamInfoParseFaultCode {
    Limit,
    Header,
    Offset,
    Alignment,
    Length,
    Size,
    Utf16,
    Name,
    Terminal,
    Resource,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsStreamInfoParseFault {
    pub code: WindowsStreamInfoParseFaultCode,
    pub field: String,
    pub message: String,
}

impl WindowsStreamInfoParseFault {
    fn new(code: WindowsStreamInfoParseFaultCode, field: &str, message: &str) -> Self {
        Self {
            code,
            field: field.to_owned(),
            message: message.chars().take(256).collect(),
        }
    }
}

impl fmt::Display for WindowsStreamInfoParseFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl std::error::Error for WindowsStreamInfoParseFault {}

pub fn parse_windows_stream_info(
    bytes: &[u8],
    limits: WindowsStreamInfoParseLimits,
) -> Result<Vec<WindowsRawStreamRecord>, WindowsStreamInfoParseFault> {
    validate_limits(limits)?;
    if bytes.len() < STREAM_INFO_HEADER_BYTES + 2 {
        return Err(WindowsStreamInfoParseFault::new(
            WindowsStreamInfoParseFaultCode::Resource,
            "bytes",
            "region cannot contain one complete header and UTF-16 code unit",
        ));
    }

    let mut records = Vec::new();
    let mut offset = 0_usize;
    loop {
        if records.len() >= limits.maximum_entries as usize {
            return Err(WindowsStreamInfoParseFault::new(
                WindowsStreamInfoParseFaultCode::Limit,
                "maximum_entries",
                "entry chain exceeds the supplied bound",
            ));
        }
        let header_end = offset
            .checked_add(STREAM_INFO_HEADER_BYTES)
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| {
                WindowsStreamInfoParseFault::new(
                    WindowsStreamInfoParseFaultCode::Header,
                    "header",
                    "entry header is truncated or overflows the region",
                )
            })?;

        let next_offset = read_u32(bytes, offset, "next_entry_offset")?;
        let name_bytes = read_u32(bytes, offset + 4, "stream_name_length")?;
        let stream_size = read_i64(bytes, offset + 8, "stream_size")?;
        let allocation_size = read_i64(bytes, offset + 16, "allocation_size")?;
        if stream_size < 0 || allocation_size < 0 {
            return Err(WindowsStreamInfoParseFault::new(
                WindowsStreamInfoParseFaultCode::Size,
                "stream_size",
                "stream and allocation sizes must both be nonnegative",
            ));
        }
        if name_bytes == 0 || name_bytes % 2 != 0 {
            return Err(WindowsStreamInfoParseFault::new(
                WindowsStreamInfoParseFaultCode::Length,
                "stream_name_length",
                "stream name byte length must be positive and even",
            ));
        }
        let name_units = name_bytes / 2;
        if name_units > limits.maximum_name_utf16_units {
            return Err(WindowsStreamInfoParseFault::new(
                WindowsStreamInfoParseFaultCode::Limit,
                "maximum_name_utf16_units",
                "stream name exceeds the supplied UTF-16-unit bound",
            ));
        }
        let name_end = header_end
            .checked_add(name_bytes as usize)
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| {
                WindowsStreamInfoParseFault::new(
                    WindowsStreamInfoParseFaultCode::Length,
                    "stream_name_length",
                    "stream name extends outside the supplied region",
                )
            })?;
        let name = decode_utf16le(&bytes[header_end..name_end])?;
        validate_stream_name(&name)?;
        let source_offset = u32::try_from(offset).map_err(|_| {
            WindowsStreamInfoParseFault::new(
                WindowsStreamInfoParseFaultCode::Resource,
                "source_offset",
                "source offset exceeds the released record representation",
            )
        })?;
        records.push(WindowsRawStreamRecord {
            name,
            stream_size: stream_size as u64,
            allocation_size: allocation_size as u64,
            source_offset,
        });

        if next_offset == 0 {
            if name_end != bytes.len() {
                return Err(WindowsStreamInfoParseFault::new(
                    WindowsStreamInfoParseFaultCode::Terminal,
                    "next_entry_offset",
                    "terminal entry does not exhaust the exact supplied region",
                ));
            }
            return Ok(records);
        }

        let next = next_offset as usize;
        let minimum_next = STREAM_INFO_HEADER_BYTES
            .checked_add(name_bytes as usize)
            .ok_or_else(|| {
                WindowsStreamInfoParseFault::new(
                    WindowsStreamInfoParseFaultCode::Offset,
                    "next_entry_offset",
                    "minimum next offset overflowed",
                )
            })?;
        if !next.is_multiple_of(8) {
            return Err(WindowsStreamInfoParseFault::new(
                WindowsStreamInfoParseFaultCode::Alignment,
                "next_entry_offset",
                "nonterminal next offset is not eight-byte aligned",
            ));
        }
        if next < minimum_next {
            return Err(WindowsStreamInfoParseFault::new(
                WindowsStreamInfoParseFaultCode::Offset,
                "next_entry_offset",
                "next offset overlaps the current header or name",
            ));
        }
        offset = offset
            .checked_add(next)
            .filter(|next_start| *next_start < bytes.len())
            .ok_or_else(|| {
                WindowsStreamInfoParseFault::new(
                    WindowsStreamInfoParseFaultCode::Offset,
                    "next_entry_offset",
                    "next offset does not advance to an in-region entry",
                )
            })?;
    }
}

fn validate_limits(
    limits: WindowsStreamInfoParseLimits,
) -> Result<(), WindowsStreamInfoParseFault> {
    if !(1..=MAXIMUM_ENTRIES_PROFILE_BOUND).contains(&limits.maximum_entries)
        || !(1..=MAXIMUM_NAME_UNITS_PROFILE_BOUND).contains(&limits.maximum_name_utf16_units)
    {
        return Err(WindowsStreamInfoParseFault::new(
            WindowsStreamInfoParseFaultCode::Limit,
            "limits",
            "parse limits are zero or exceed the closed profile bounds",
        ));
    }
    Ok(())
}

fn read_u32(bytes: &[u8], start: usize, field: &str) -> Result<u32, WindowsStreamInfoParseFault> {
    let value = bytes
        .get(start..start + 4)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| {
            WindowsStreamInfoParseFault::new(
                WindowsStreamInfoParseFaultCode::Header,
                field,
                "u32 field is truncated",
            )
        })?;
    Ok(u32::from_le_bytes(value))
}

fn read_i64(bytes: &[u8], start: usize, field: &str) -> Result<i64, WindowsStreamInfoParseFault> {
    let value = bytes
        .get(start..start + 8)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| {
            WindowsStreamInfoParseFault::new(
                WindowsStreamInfoParseFaultCode::Header,
                field,
                "i64 field is truncated",
            )
        })?;
    Ok(i64::from_le_bytes(value))
}

fn decode_utf16le(bytes: &[u8]) -> Result<String, WindowsStreamInfoParseFault> {
    let units = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    String::from_utf16(&units).map_err(|_| {
        WindowsStreamInfoParseFault::new(
            WindowsStreamInfoParseFaultCode::Utf16,
            "stream_name",
            "stream name is not strict UTF-16LE",
        )
    })
}

fn validate_stream_name(name: &str) -> Result<(), WindowsStreamInfoParseFault> {
    let valid = name == "::$DATA"
        || name
            .strip_prefix(':')
            .and_then(|value| value.strip_suffix(":$DATA"))
            .is_some_and(|inner| !inner.is_empty() && !inner.contains([':', '\0']));
    if valid {
        Ok(())
    } else {
        Err(WindowsStreamInfoParseFault::new(
            WindowsStreamInfoParseFaultCode::Name,
            "stream_name",
            "stream name is not exact default or named DATA-stream grammar",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> WindowsStreamInfoParseLimits {
        WindowsStreamInfoParseLimits {
            maximum_entries: 8,
            maximum_name_utf16_units: 64,
        }
    }

    fn entry(next: u32, name: &str, size: i64, allocation: i64) -> Vec<u8> {
        let name_bytes = name
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&next.to_le_bytes());
        bytes.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&size.to_le_bytes());
        bytes.extend_from_slice(&allocation.to_le_bytes());
        bytes.extend_from_slice(&name_bytes);
        bytes
    }

    #[test]
    fn default_and_named_records_preserve_exact_values() {
        let default = entry(0, "::$DATA", 7, 8);
        assert_eq!(
            parse_windows_stream_info(&default, limits()).expect("default"),
            vec![WindowsRawStreamRecord {
                name: "::$DATA".to_owned(),
                stream_size: 7,
                allocation_size: 8,
                source_offset: 0,
            }]
        );
        let named = entry(0, ":Authors:$DATA", 9, 16);
        assert_eq!(
            parse_windows_stream_info(&named, limits())
                .expect("named")
                .first()
                .expect("record")
                .name,
            ":Authors:$DATA"
        );
    }

    #[test]
    fn aligned_chain_ignores_padding_and_preserves_source_order() {
        let first_name = ":A:$DATA";
        let mut first = entry(48, first_name, 1, 2);
        first.resize(48, 0xa5);
        let second = entry(0, "::$DATA", 3, 4);
        first.extend_from_slice(&second);
        let records = parse_windows_stream_info(&first, limits()).expect("chain");
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].name, first_name);
        assert_eq!(records[1].source_offset, 48);
    }

    #[test]
    fn limits_and_empty_or_truncated_regions_reject() {
        for invalid in [
            WindowsStreamInfoParseLimits {
                maximum_entries: 0,
                ..limits()
            },
            WindowsStreamInfoParseLimits {
                maximum_entries: 1_025,
                ..limits()
            },
            WindowsStreamInfoParseLimits {
                maximum_name_utf16_units: 0,
                ..limits()
            },
            WindowsStreamInfoParseLimits {
                maximum_name_utf16_units: 32_768,
                ..limits()
            },
        ] {
            assert_eq!(
                parse_windows_stream_info(&entry(0, "::$DATA", 0, 0), invalid)
                    .expect_err("limits")
                    .code,
                WindowsStreamInfoParseFaultCode::Limit
            );
        }
        for bytes in [&[][..], &[0; 24][..], &[0; 25][..]] {
            assert!(parse_windows_stream_info(bytes, limits()).is_err());
        }
    }

    #[test]
    fn offsets_must_advance_align_and_contain_the_next_entry() {
        for next in [1, 32, 4_096] {
            let mut bytes = entry(next, ":A:$DATA", 0, 0);
            bytes.resize(80, 0);
            let fault = parse_windows_stream_info(&bytes, limits()).expect_err("offset");
            assert!(
                matches!(
                    fault.code,
                    WindowsStreamInfoParseFaultCode::Alignment
                        | WindowsStreamInfoParseFaultCode::Offset
                ),
                "{next}: {fault:?}"
            );
        }
    }

    #[test]
    fn name_length_must_be_positive_even_bounded_and_in_region() {
        let mut zero = entry(0, "::$DATA", 0, 0);
        zero[4..8].copy_from_slice(&0_u32.to_le_bytes());
        assert_eq!(
            parse_windows_stream_info(&zero, limits())
                .expect_err("zero")
                .code,
            WindowsStreamInfoParseFaultCode::Length
        );
        let mut odd = entry(0, "::$DATA", 0, 0);
        odd[4..8].copy_from_slice(&13_u32.to_le_bytes());
        assert_eq!(
            parse_windows_stream_info(&odd, limits())
                .expect_err("odd")
                .code,
            WindowsStreamInfoParseFaultCode::Length
        );
        let mut outside = entry(0, "::$DATA", 0, 0);
        outside[4..8].copy_from_slice(&1_000_u32.to_le_bytes());
        assert_eq!(
            parse_windows_stream_info(&outside, limits())
                .expect_err("outside")
                .code,
            WindowsStreamInfoParseFaultCode::Limit
        );
    }

    #[test]
    fn negative_sizes_invalid_utf16_and_bad_grammar_reject() {
        for (size, allocation) in [(-1, 0), (0, -1)] {
            assert_eq!(
                parse_windows_stream_info(&entry(0, "::$DATA", size, allocation), limits())
                    .expect_err("size")
                    .code,
                WindowsStreamInfoParseFaultCode::Size
            );
        }
        let mut utf16 = entry(0, "::$DATA", 0, 0);
        utf16[24..26].copy_from_slice(&0xd800_u16.to_le_bytes());
        assert_eq!(
            parse_windows_stream_info(&utf16, limits())
                .expect_err("UTF-16")
                .code,
            WindowsStreamInfoParseFaultCode::Utf16
        );
        for name in ["", "$DATA", ":$DATA", ":A", ":A:B:$DATA", "::OTHER"] {
            assert_eq!(
                parse_windows_stream_info(&entry(0, name, 0, 0), limits())
                    .expect_err("name")
                    .code,
                if name.is_empty() {
                    WindowsStreamInfoParseFaultCode::Resource
                } else {
                    WindowsStreamInfoParseFaultCode::Name
                },
                "{name:?}"
            );
        }
    }

    #[test]
    fn terminal_tail_and_entry_budget_reject_without_partial_release() {
        let mut trailing = entry(0, "::$DATA", 0, 0);
        trailing.push(0);
        assert_eq!(
            parse_windows_stream_info(&trailing, limits())
                .expect_err("tail")
                .code,
            WindowsStreamInfoParseFaultCode::Terminal
        );

        let mut first = entry(48, ":A:$DATA", 0, 0);
        first.resize(48, 0);
        first.extend_from_slice(&entry(0, "::$DATA", 0, 0));
        let one = WindowsStreamInfoParseLimits {
            maximum_entries: 1,
            ..limits()
        };
        assert_eq!(
            parse_windows_stream_info(&first, one)
                .expect_err("entry budget")
                .code,
            WindowsStreamInfoParseFaultCode::Limit
        );
    }

    #[test]
    fn parser_profile_is_exact() {
        assert_eq!(
            WINDOWS_STREAM_INFO_PARSER_PROFILE,
            "cantor-windows-stream-info-parser/0.1"
        );
    }
}
