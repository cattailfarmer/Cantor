use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::model::{ContentDigest, SemanticId};

use super::types::{AuthorityScope, PackageContent, TrustFault, TrustFaultKind};

pub fn sha256_bytes(bytes: &[u8]) -> ContentDigest {
    let digest = Sha256::digest(bytes);
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: encode_hex(&digest),
    }
}

pub fn sha256_digest<T: Serialize>(value: &T) -> Result<ContentDigest, TrustFault> {
    let bytes = serde_json::to_vec(value).map_err(|error| {
        TrustFault::new(
            TrustFaultKind::MachineForm,
            "canonical_serialization",
            error.to_string(),
        )
    })?;
    Ok(sha256_bytes(&bytes))
}

pub fn derive_package_id(digest: &ContentDigest) -> Result<SemanticId, TrustFault> {
    SemanticId::new(format!("package:{}:{}", digest.algorithm, digest.value)).map_err(|error| {
        TrustFault::new(
            TrustFaultKind::InvalidPackageIdentity,
            "package_identity",
            error.to_string(),
        )
    })
}

#[allow(clippy::too_many_arguments)]
pub fn derive_certificate_id(
    package_digest: &ContentDigest,
    semantic_root_digest: &ContentDigest,
    source_root_digest: &ContentDigest,
    authority_signer_id: &SemanticId,
    compiler_signer_id: &SemanticId,
    signature_profile: &str,
    issued_at_epoch_seconds: u64,
    not_before_epoch_seconds: u64,
    not_after_epoch_seconds: u64,
    authority_scope: &AuthorityScope,
) -> Result<SemanticId, TrustFault> {
    let certificate_digest = sha256_digest(&(
        package_digest,
        semantic_root_digest,
        source_root_digest,
        authority_signer_id,
        compiler_signer_id,
        signature_profile,
        issued_at_epoch_seconds,
        not_before_epoch_seconds,
        not_after_epoch_seconds,
        authority_scope,
    ))?;
    SemanticId::new(format!(
        "certificate:{}:{}",
        certificate_digest.algorithm, certificate_digest.value
    ))
    .map_err(|error| {
        TrustFault::new(
            TrustFaultKind::InvalidPackageIdentity,
            "certificate_identity",
            error.to_string(),
        )
    })
}

pub fn package_content_digest(content: &PackageContent) -> Result<ContentDigest, TrustFault> {
    let normalized = normalized_content(content)?;
    sha256_digest(&normalized)
}

pub fn semantic_root_digest(content: &PackageContent) -> Result<ContentDigest, TrustFault> {
    sha256_digest(&(&content.semantic_units, &content.relations))
}

pub fn source_root_digest(content: &PackageContent) -> Result<ContentDigest, TrustFault> {
    let normalized = normalized_content(content)?;
    sha256_digest(&(
        &normalized.sources,
        &normalized.source_anchors,
        &normalized.quotes,
    ))
}

pub(super) fn sign_value<T: Serialize>(
    signing_key: &SigningKey,
    value: &T,
) -> Result<Vec<u8>, TrustFault> {
    let bytes = serde_json::to_vec(value).map_err(|error| {
        TrustFault::new(
            TrustFaultKind::MachineForm,
            "signature_payload",
            error.to_string(),
        )
    })?;
    Ok(signing_key.sign(&bytes).to_bytes().to_vec())
}

pub(super) fn verify_value<T: Serialize>(
    verifying_key_bytes: &[u8],
    signature_bytes: &[u8],
    value: &T,
) -> Result<(), TrustFault> {
    let key_bytes: [u8; 32] = verifying_key_bytes.try_into().map_err(|_| {
        TrustFault::new(
            TrustFaultKind::InvalidSignature,
            "signature_verification",
            "Ed25519 verifying key must contain exactly 32 bytes",
        )
    })?;
    let verifying_key = VerifyingKey::from_bytes(&key_bytes).map_err(|error| {
        TrustFault::new(
            TrustFaultKind::InvalidSignature,
            "signature_verification",
            error.to_string(),
        )
    })?;
    let signature = Signature::try_from(signature_bytes).map_err(|error| {
        TrustFault::new(
            TrustFaultKind::InvalidSignature,
            "signature_verification",
            error.to_string(),
        )
    })?;
    let payload = serde_json::to_vec(value).map_err(|error| {
        TrustFault::new(
            TrustFaultKind::MachineForm,
            "signature_payload",
            error.to_string(),
        )
    })?;
    verifying_key
        .verify_strict(&payload, &signature)
        .map_err(|error| {
            TrustFault::new(
                TrustFaultKind::InvalidSignature,
                "signature_verification",
                error.to_string(),
            )
        })
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn normalized_content(content: &PackageContent) -> Result<PackageContent, TrustFault> {
    let mut normalized = content.clone();
    let pending = SemanticId::new("package:pending").map_err(|error| {
        TrustFault::new(
            TrustFaultKind::InvalidPackageIdentity,
            "package_canonicalization",
            error.to_string(),
        )
    })?;
    for anchor in &mut normalized.source_anchors {
        anchor.package_id = pending.clone();
    }
    for quote in &mut normalized.quotes {
        quote.anchor.package_id = pending.clone();
    }
    Ok(normalized)
}
