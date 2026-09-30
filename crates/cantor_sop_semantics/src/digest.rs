use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{Result, SnapshotInput};

pub fn bytes(bytes: &[u8]) -> String {
    let hash = Sha256::digest(bytes);
    hex(&hash)
}

pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut result = String::with_capacity(64);
    for byte in bytes {
        write!(result, "{byte:02x}").expect("writing to a String cannot fail");
    }
    result
}

/// Domain-separated JSON with recursively sorted object keys and integer-only
/// numbers. Arrays preserve order; logical record ordering is normalized first.
pub fn value<T: Serialize>(domain: &str, value: &T) -> Result<String> {
    let mut payload = domain.as_bytes().to_vec();
    payload.push(0);
    canonical(&serde_json::to_value(value)?, &mut payload)?;
    Ok(bytes(&payload))
}

fn canonical(value: &serde_json::Value, out: &mut Vec<u8>) -> Result<()> {
    use serde_json::Value;

    match value {
        Value::Object(map) => {
            out.push(b'{');
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index != 0 {
                    out.push(b',');
                }
                out.extend(serde_json::to_vec(key)?);
                out.push(b':');
                canonical(value, out)?;
            }
            out.push(b'}');
        }
        Value::Array(values) => {
            out.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    out.push(b',');
                }
                canonical(value, out)?;
            }
            out.push(b']');
        }
        Value::Number(number) if number.is_f64() => {
            return Err(crate::Fault::new(
                "noncanonical_number",
                "floating point values are outside the exact logical encoding",
            ));
        }
        _ => out.extend(serde_json::to_vec(value)?),
    }
    Ok(())
}

pub fn normalize(input: &SnapshotInput) -> SnapshotInput {
    let mut input = input.clone();
    input.packages.sort_by(|a, b| a.id.cmp(&b.id));
    input.sources.sort_by(|a, b| a.id.cmp(&b.id));
    input.kinds.sort_by(|a, b| a.id.cmp(&b.id));
    input.contexts.sort_by(|a, b| a.id.cmp(&b.id));
    input.units.sort_by(|a, b| a.id.cmp(&b.id));
    input.relation_types.sort_by(|a, b| a.id.cmp(&b.id));
    input.relations.sort_by(|a, b| a.id.cmp(&b.id));
    input.rules.sort_by(|a, b| a.id.cmp(&b.id));
    input.views.sort_by(|a, b| a.id.cmp(&b.id));
    for relation_type in &mut input.relation_types {
        relation_type.roles.sort_by(|a, b| a.name.cmp(&b.name));
    }
    for relation in &mut input.relations {
        relation.participants.sort();
    }
    input
}

pub fn generation(input: &SnapshotInput) -> Result<String> {
    value("cantor-sop-semantic-snapshot/0.1", &normalize(input))
}

/// Labels use Unicode lowercase; spelling and source bytes remain untouched.
/// This is lexical matching, not Unicode normalization or semantic equivalence.
pub fn label_key(label: &str) -> String {
    label.to_lowercase()
}
