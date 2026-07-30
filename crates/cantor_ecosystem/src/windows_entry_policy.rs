//! Pure admission policy for already-observed Windows entry metadata.
//!
//! This module does not observe an entry. It only classifies caller-supplied
//! values under the closed `cantor-windows-entry-policy/0.1` profile.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Closed profile implemented by this pure evaluator.
pub const WINDOWS_ENTRY_POLICY_PROFILE: &str = "cantor-windows-entry-policy/0.1";

pub const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
pub const FILE_ATTRIBUTE_HIDDEN: u32 = 0x0000_0002;
pub const FILE_ATTRIBUTE_SYSTEM: u32 = 0x0000_0004;
pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
pub const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x0000_0020;
pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
pub const FILE_ATTRIBUTE_NOT_CONTENT_INDEXED: u32 = 0x0000_2000;

/// Every attribute bit admitted in combination by profile 0.1.
pub const WINDOWS_ENTRY_BENIGN_ATTRIBUTE_MASK: u32 = FILE_ATTRIBUTE_READONLY
    | FILE_ATTRIBUTE_HIDDEN
    | FILE_ATTRIBUTE_SYSTEM
    | FILE_ATTRIBUTE_ARCHIVE
    | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;

/// Exact directory mask: DIRECTORY plus any benign combination.
pub const WINDOWS_ENTRY_DIRECTORY_ALLOWED_MASK: u32 =
    FILE_ATTRIBUTE_DIRECTORY | WINDOWS_ENTRY_BENIGN_ATTRIBUTE_MASK;

/// Entry shape supplied by a later observation seam.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsEntryPolicyKind {
    Directory,
    RegularFile,
}

/// Strict, effect-free policy input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsEntryPolicyInput {
    pub profile: String,
    pub kind: WindowsEntryPolicyKind,
    pub attributes: u32,
    pub directory_case_sensitive_flags: Option<u32>,
    pub component: String,
    pub maximum_component_utf16_units: u32,
}

/// Inspectable admitted result. Every value derives solely from the input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsEntryPolicyDecision {
    pub profile: String,
    pub kind: WindowsEntryPolicyKind,
    pub attributes: u32,
    pub directory_case_sensitive_flags: Option<u32>,
    pub component: String,
    pub order_key_hex: String,
}

/// Closed policy failure vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsEntryPolicyFaultCode {
    Profile,
    Attribute,
    CaseSensitivity,
    Component,
    ReservedDevice,
    Resource,
    Json,
}

/// Deterministic failure released without partial admission evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsEntryPolicyFault {
    pub code: WindowsEntryPolicyFaultCode,
    pub field: String,
    pub message: String,
}

impl WindowsEntryPolicyFault {
    fn new(code: WindowsEntryPolicyFaultCode, field: &str, message: &str) -> Self {
        Self {
            code,
            field: field.to_owned(),
            message: message.chars().take(256).collect(),
        }
    }
}

impl fmt::Display for WindowsEntryPolicyFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl std::error::Error for WindowsEntryPolicyFault {}

/// Strictly decodes one input and evaluates the pure policy.
pub fn decode_and_evaluate_windows_entry_policy(
    bytes: &[u8],
) -> Result<WindowsEntryPolicyDecision, WindowsEntryPolicyFault> {
    let input = serde_json::from_slice(bytes).map_err(|error| {
        WindowsEntryPolicyFault::new(
            WindowsEntryPolicyFaultCode::Json,
            "json",
            &error.to_string(),
        )
    })?;
    evaluate_windows_entry_policy(input)
}

/// Evaluates one already-observed entry without performing any observation.
pub fn evaluate_windows_entry_policy(
    input: WindowsEntryPolicyInput,
) -> Result<WindowsEntryPolicyDecision, WindowsEntryPolicyFault> {
    if input.profile != WINDOWS_ENTRY_POLICY_PROFILE {
        return Err(WindowsEntryPolicyFault::new(
            WindowsEntryPolicyFaultCode::Profile,
            "profile",
            "profile is not the exact supported Windows entry policy profile",
        ));
    }
    validate_attributes_and_case(
        input.kind,
        input.attributes,
        input.directory_case_sensitive_flags,
    )?;
    validate_component(&input.component, input.maximum_component_utf16_units)?;
    let order_key_hex = input
        .component
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok(WindowsEntryPolicyDecision {
        profile: input.profile,
        kind: input.kind,
        attributes: input.attributes,
        directory_case_sensitive_flags: input.directory_case_sensitive_flags,
        component: input.component,
        order_key_hex,
    })
}

fn validate_attributes_and_case(
    kind: WindowsEntryPolicyKind,
    attributes: u32,
    directory_case_sensitive_flags: Option<u32>,
) -> Result<(), WindowsEntryPolicyFault> {
    let attributes_valid = match kind {
        WindowsEntryPolicyKind::Directory => {
            attributes & FILE_ATTRIBUTE_DIRECTORY != 0
                && attributes & !WINDOWS_ENTRY_DIRECTORY_ALLOWED_MASK == 0
        }
        WindowsEntryPolicyKind::RegularFile => {
            attributes == FILE_ATTRIBUTE_NORMAL
                || (attributes != 0 && attributes & !WINDOWS_ENTRY_BENIGN_ATTRIBUTE_MASK == 0)
        }
    };
    if !attributes_valid {
        return Err(WindowsEntryPolicyFault::new(
            WindowsEntryPolicyFaultCode::Attribute,
            "attributes",
            "attribute shape is outside the closed kind-specific profile",
        ));
    }

    let case_valid = match kind {
        WindowsEntryPolicyKind::Directory => directory_case_sensitive_flags == Some(0),
        WindowsEntryPolicyKind::RegularFile => directory_case_sensitive_flags.is_none(),
    };
    if !case_valid {
        return Err(WindowsEntryPolicyFault::new(
            WindowsEntryPolicyFaultCode::CaseSensitivity,
            "directory_case_sensitive_flags",
            "directory requires exact zero flags and regular file requires absence",
        ));
    }
    Ok(())
}

fn validate_component(
    component: &str,
    maximum_component_utf16_units: u32,
) -> Result<(), WindowsEntryPolicyFault> {
    if !(1..=32_767).contains(&maximum_component_utf16_units) {
        return Err(WindowsEntryPolicyFault::new(
            WindowsEntryPolicyFaultCode::Resource,
            "maximum_component_utf16_units",
            "component bound must be within 1 through 32767",
        ));
    }
    let units = component.encode_utf16().count();
    if component.is_empty()
        || units > usize::try_from(maximum_component_utf16_units).unwrap_or(usize::MAX)
    {
        return Err(WindowsEntryPolicyFault::new(
            WindowsEntryPolicyFaultCode::Resource,
            "component",
            "component is empty or exceeds the supplied UTF-16-unit bound",
        ));
    }
    if component == "."
        || component == ".."
        || component.eq_ignore_ascii_case(".git")
        || component
            .chars()
            .any(|value| is_forbidden_component_scalar(value as u32))
        || component.ends_with([' ', '.'])
    {
        return Err(WindowsEntryPolicyFault::new(
            WindowsEntryPolicyFaultCode::Component,
            "component",
            "component contains a navigation, Git, character, or terminal hazard",
        ));
    }
    let stem = component.split('.').next().unwrap_or(component);
    if is_reserved_device_stem(stem) {
        return Err(WindowsEntryPolicyFault::new(
            WindowsEntryPolicyFaultCode::ReservedDevice,
            "component",
            "component stem is a reserved Windows device name",
        ));
    }
    Ok(())
}

fn is_forbidden_component_scalar(value: u32) -> bool {
    value == 0
        || (1..=31).contains(&value)
        || matches!(
            value,
            0x22 | 0x2a | 0x2f | 0x3a | 0x3c | 0x3e | 0x3f | 0x5c | 0x7c
        )
}

fn is_reserved_device_stem(stem: &str) -> bool {
    if ["CON", "PRN", "AUX", "NUL"]
        .iter()
        .any(|value| stem.eq_ignore_ascii_case(value))
    {
        return true;
    }
    for prefix in ["COM", "LPT"] {
        let Some(suffix) = stem.get(prefix.len()..) else {
            continue;
        };
        if stem
            .get(..prefix.len())
            .is_some_and(|value| value.eq_ignore_ascii_case(prefix))
            && (matches!(suffix.as_bytes(), [b'1'..=b'9'])
                || matches!(suffix, "\u{00b9}" | "\u{00b2}" | "\u{00b3}"))
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(kind: WindowsEntryPolicyKind, attributes: u32) -> WindowsEntryPolicyInput {
        WindowsEntryPolicyInput {
            profile: WINDOWS_ENTRY_POLICY_PROFILE.to_owned(),
            kind,
            attributes,
            directory_case_sensitive_flags: match kind {
                WindowsEntryPolicyKind::Directory => Some(0),
                WindowsEntryPolicyKind::RegularFile => None,
            },
            component: "entry.txt".to_owned(),
            maximum_component_utf16_units: 255,
        }
    }

    #[test]
    fn profile_and_json_are_strict() {
        let valid = input(WindowsEntryPolicyKind::RegularFile, FILE_ATTRIBUTE_NORMAL);
        let bytes = serde_json::to_vec(&valid).expect("serialize");
        assert_eq!(
            decode_and_evaluate_windows_entry_policy(&bytes)
                .expect("valid")
                .component,
            "entry.txt"
        );
        let mut wrong = valid;
        wrong.profile = "cantor-windows-entry-policy/0.0".to_owned();
        assert_eq!(
            evaluate_windows_entry_policy(wrong)
                .expect_err("profile")
                .code,
            WindowsEntryPolicyFaultCode::Profile
        );
        let unknown = br#"{"profile":"cantor-windows-entry-policy/0.1","kind":"regular_file","attributes":128,"directory_case_sensitive_flags":null,"component":"entry.txt","maximum_component_utf16_units":255,"observe":true}"#;
        assert_eq!(
            decode_and_evaluate_windows_entry_policy(unknown)
                .expect_err("unknown field")
                .code,
            WindowsEntryPolicyFaultCode::Json
        );
    }

    #[test]
    fn all_benign_subsets_have_exact_kind_relations() {
        for subset in 0..=WINDOWS_ENTRY_BENIGN_ATTRIBUTE_MASK {
            if subset & !WINDOWS_ENTRY_BENIGN_ATTRIBUTE_MASK != 0 {
                continue;
            }
            let directory = input(
                WindowsEntryPolicyKind::Directory,
                FILE_ATTRIBUTE_DIRECTORY | subset,
            );
            assert!(
                evaluate_windows_entry_policy(directory).is_ok(),
                "{subset:#x}"
            );

            let regular = input(WindowsEntryPolicyKind::RegularFile, subset);
            assert_eq!(
                evaluate_windows_entry_policy(regular).is_ok(),
                subset != 0,
                "{subset:#x}"
            );
        }
        assert!(
            evaluate_windows_entry_policy(input(
                WindowsEntryPolicyKind::RegularFile,
                FILE_ATTRIBUTE_NORMAL
            ))
            .is_ok()
        );
    }

    #[test]
    fn every_single_bit_outside_the_masks_rejects() {
        for bit in 0..32 {
            let value = 1_u32 << bit;
            let directory_expected = value == FILE_ATTRIBUTE_DIRECTORY
                || value & WINDOWS_ENTRY_BENIGN_ATTRIBUTE_MASK != 0;
            let regular_expected =
                value == FILE_ATTRIBUTE_NORMAL || value & WINDOWS_ENTRY_BENIGN_ATTRIBUTE_MASK != 0;
            assert_eq!(
                evaluate_windows_entry_policy(input(
                    WindowsEntryPolicyKind::Directory,
                    FILE_ATTRIBUTE_DIRECTORY | value
                ))
                .is_ok(),
                directory_expected,
                "directory bit {bit}"
            );
            assert_eq!(
                evaluate_windows_entry_policy(input(WindowsEntryPolicyKind::RegularFile, value))
                    .is_ok(),
                regular_expected,
                "regular bit {bit}"
            );
        }
    }

    #[test]
    fn normal_cannot_combine_and_kinds_cannot_cross() {
        for value in [
            FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_ARCHIVE,
            FILE_ATTRIBUTE_DIRECTORY,
            FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_ARCHIVE,
            0,
        ] {
            assert!(
                evaluate_windows_entry_policy(input(WindowsEntryPolicyKind::RegularFile, value))
                    .is_err(),
                "{value:#x}"
            );
        }
        for value in [0, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_ARCHIVE] {
            assert!(
                evaluate_windows_entry_policy(input(WindowsEntryPolicyKind::Directory, value))
                    .is_err(),
                "{value:#x}"
            );
        }
    }

    #[test]
    fn case_field_relation_is_exact() {
        let mut directory = input(WindowsEntryPolicyKind::Directory, FILE_ATTRIBUTE_DIRECTORY);
        for flags in [None, Some(1), Some(u32::MAX)] {
            directory.directory_case_sensitive_flags = flags;
            assert_eq!(
                evaluate_windows_entry_policy(directory.clone())
                    .expect_err("directory flags")
                    .code,
                WindowsEntryPolicyFaultCode::CaseSensitivity
            );
        }
        let mut regular = input(WindowsEntryPolicyKind::RegularFile, FILE_ATTRIBUTE_NORMAL);
        regular.directory_case_sensitive_flags = Some(0);
        assert_eq!(
            evaluate_windows_entry_policy(regular)
                .expect_err("regular flags")
                .code,
            WindowsEntryPolicyFaultCode::CaseSensitivity
        );
    }

    #[test]
    fn forbidden_characters_navigation_git_and_terminal_reject() {
        for component in [
            ".", "..", ".git", ".GIT", "trail ", "trail.", "a\0b", "a\u{1f}b", "a<b", "a>b", "a:b",
            "a\"b", "a/b", "a\\b", "a|b", "a?b", "a*b",
        ] {
            let mut value = input(WindowsEntryPolicyKind::RegularFile, FILE_ATTRIBUTE_NORMAL);
            value.component = component.to_owned();
            assert_eq!(
                evaluate_windows_entry_policy(value)
                    .expect_err("component")
                    .code,
                WindowsEntryPolicyFaultCode::Component,
                "{component:?}"
            );
        }
    }

    #[test]
    fn every_reserved_device_stem_rejects_case_and_extension() {
        let mut names = vec!["CON", "PRN", "AUX", "NUL"];
        for prefix in ["COM", "LPT"] {
            for suffix in ["1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³"] {
                names.push(Box::leak(format!("{prefix}{suffix}").into_boxed_str()));
            }
        }
        for name in names {
            for component in [
                name.to_owned(),
                format!("{}.txt", name.to_ascii_lowercase()),
            ] {
                let mut value = input(WindowsEntryPolicyKind::RegularFile, FILE_ATTRIBUTE_NORMAL);
                value.component = component;
                assert_eq!(
                    evaluate_windows_entry_policy(value)
                        .expect_err("reserved")
                        .code,
                    WindowsEntryPolicyFaultCode::ReservedDevice,
                    "{name}"
                );
            }
        }
        for admitted in [
            "COM0",
            "COM10",
            "LPT0",
            "LPT10",
            "CONsole",
            "NULl",
            "auxiliary",
        ] {
            let mut value = input(WindowsEntryPolicyKind::RegularFile, FILE_ATTRIBUTE_NORMAL);
            value.component = admitted.to_owned();
            assert!(evaluate_windows_entry_policy(value).is_ok(), "{admitted}");
        }
    }

    #[test]
    fn utf16_bound_unicode_preservation_and_order_key_are_exact() {
        let mut value = input(WindowsEntryPolicyKind::RegularFile, FILE_ATTRIBUTE_NORMAL);
        value.component = "Ångström😀.rs".to_owned();
        value.maximum_component_utf16_units = 13;
        let decision = evaluate_windows_entry_policy(value.clone()).expect("Unicode");
        assert_eq!(decision.component, value.component);
        assert_eq!(
            decision.order_key_hex,
            value
                .component
                .as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        value.maximum_component_utf16_units = 12;
        assert_eq!(
            evaluate_windows_entry_policy(value)
                .expect_err("UTF-16 bound")
                .code,
            WindowsEntryPolicyFaultCode::Resource
        );
    }

    #[test]
    fn component_bound_itself_is_closed() {
        for bound in [0, 32_768, u32::MAX] {
            let mut value = input(WindowsEntryPolicyKind::RegularFile, FILE_ATTRIBUTE_NORMAL);
            value.maximum_component_utf16_units = bound;
            assert_eq!(
                evaluate_windows_entry_policy(value)
                    .expect_err("bound")
                    .code,
                WindowsEntryPolicyFaultCode::Resource
            );
        }
    }
}
