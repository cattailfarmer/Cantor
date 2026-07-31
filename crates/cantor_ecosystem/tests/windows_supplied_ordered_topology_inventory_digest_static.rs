#[test]
fn supplied_ordered_inventory_digest_surface_is_pure_closed_and_lineage_retaining() {
    let source = include_str!("../src/windows_supplied_ordered_topology_inventory_digest.rs");
    let production = source.split_once("#[cfg(test)]").expect("test boundary").0;

    for forbidden in [
        "windows_sys",
        "unsafe {",
        "std::fs",
        "std::path",
        "std::process",
        "std::env",
        "std::net",
        "SystemTime",
        "Instant",
        "File::",
        "Command::",
        "TopologyReceipt",
        "serde_json::to_vec",
        "Vec<u8>",
        "Vec<TopologyEntryObservation>",
        "impl From<",
        "impl Into<",
        "pub fn new(",
        "pub fn from_",
    ] {
        assert!(
            !production.contains(forbidden),
            "forbidden production token: {forbidden}"
        );
    }

    for required in [
        "WINDOWS_SUPPLIED_ORDERED_TOPOLOGY_INVENTORY_DIGEST_PROFILE",
        "ORDERED_TOPOLOGY_OBSERVATION_ENCODING_PROFILE",
        "WINDOWS_SUPPLIED_ORDERED_TOPOLOGY_INVENTORY_DIGEST_PLAN_MAX_BYTES",
        "assembly: WindowsSuppliedTopologyInventoryAssembly",
        "observation.validate()",
        "assembly.entry_count()",
        "assembly.total_file_bytes()",
        "checked_add",
        "to_be_bytes()",
        "Sha256::new()",
        "write_optional_text",
        "write_optional_digest",
        "decode_lower_hex::<16>",
        "decode_lower_hex::<32>",
        "does not prove physical origin",
    ] {
        assert!(production.contains(required), "missing token: {required}");
    }

    for tag in [
        "const ENTRY_START: u8 = 0x01;",
        "const FIELD_RELATIVE_PATH: u8 = 0x10;",
        "const FIELD_KIND: u8 = 0x11;",
        "const FIELD_MODE_CLASS: u8 = 0x12;",
        "const FIELD_ATTRIBUTES: u8 = 0x13;",
        "const FIELD_VOLUME_SERIAL: u8 = 0x14;",
        "const FIELD_FILE_ID: u8 = 0x15;",
        "const FIELD_NUMBER_OF_LINKS: u8 = 0x16;",
        "const FIELD_STREAMS: u8 = 0x17;",
        "const FIELD_LENGTH: u8 = 0x18;",
        "const FIELD_CONTENT_SHA256: u8 = 0x19;",
        "const FIELD_OBSERVATION_ORDINAL: u8 = 0x1a;",
        "const STREAM_START: u8 = 0x20;",
        "const STREAM_FIELD_NAME: u8 = 0x21;",
        "const STREAM_FIELD_SIZE: u8 = 0x22;",
        "const STREAM_FIELD_KIND: u8 = 0x23;",
    ] {
        assert!(production.contains(tag), "missing exact tag: {tag}");
    }

    let output = "pub struct WindowsSuppliedOrderedTopologyInventoryDigest {";
    let position = production.find(output).expect("output declaration");
    let prefix = &production[..position];
    let derive = &production[prefix.rfind("#[derive(").expect("output derive")..position];
    assert!(derive.contains("Serialize"));
    assert!(!derive.contains("Deserialize"));
    assert!(!derive.contains("Default"));
    let body = production
        .split_once(output)
        .expect("output declaration")
        .1
        .split_once('}')
        .expect("output body")
        .0;
    assert!(!body.contains("pub "), "output fields must remain private");
    for field in [
        "profile:",
        "encoding_profile:",
        "plan:",
        "assembly:",
        "ordered_inventory_sha256:",
    ] {
        assert!(body.contains(field), "missing output field: {field}");
    }

    let plan = "pub struct WindowsSuppliedOrderedTopologyInventoryDigestPlan {";
    let plan_body = production
        .split_once(plan)
        .expect("plan declaration")
        .1
        .split_once('}')
        .expect("plan body")
        .0;
    assert!(
        !plan_body.contains("pub "),
        "plan fields must remain private"
    );

    let cargo = include_str!("../../../Cargo.toml");
    let crate_cargo = include_str!("../Cargo.toml");
    assert!(cargo.contains("sha2"));
    assert!(crate_cargo.contains("sha2.workspace = true"));
}
