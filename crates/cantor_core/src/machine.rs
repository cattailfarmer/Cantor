use serde::{Serialize, de::DeserializeOwned};

use crate::model::{ContentDigest, EvaluationFault, FaultKind};

/// Serialize a machine form. BTree-based collections in the IR preserve
/// deterministic key order.
pub fn to_machine_form<T: Serialize>(value: &T) -> Result<String, EvaluationFault> {
    serde_json::to_string(value).map_err(|error| {
        EvaluationFault::new(
            FaultKind::MachineForm,
            format!("machine-form serialization failed: {error}"),
        )
    })
}

/// Restore a previously serialized machine form.
pub fn from_machine_form<T: DeserializeOwned>(value: &str) -> Result<T, EvaluationFault> {
    serde_json::from_str(value).map_err(|error| {
        EvaluationFault::new(
            FaultKind::MachineForm,
            format!("machine-form restoration failed: {error}"),
        )
    })
}

/// Produce a deterministic, non-cryptographic content identity for Core v0.1.
///
/// Trusted-package work will replace this proof-fixture digest with the
/// cryptographic profile owned by CEB Slice 02.
pub fn content_digest<T: Serialize>(value: &T) -> Result<ContentDigest, EvaluationFault> {
    let bytes = serde_json::to_vec(value).map_err(|error| {
        EvaluationFault::new(
            FaultKind::MachineForm,
            format!("digest serialization failed: {error}"),
        )
    })?;
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    Ok(ContentDigest {
        algorithm: "fnv1a64-fixture-only".to_owned(),
        value: format!("{hash:016x}"),
    })
}
