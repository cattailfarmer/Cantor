use std::collections::{BTreeMap, BTreeSet};

use crate::model::{SemanticId, SourceAnchor};

use super::compiler::build_exact_indexes;
use super::crypto::{
    derive_certificate_id, derive_package_id, package_content_digest, semantic_root_digest,
    sha256_bytes, source_root_digest, verify_value,
};
use super::types::{
    AdmittedPackage, AuthorityScope, AuthorityStatement, CompiledSourcePackage, CompilerStatement,
    PACKAGE_FORMAT_VERSION, RECOGNITION_PROFILE, SignerRole, TrustFault, TrustFaultKind,
    TrustStore,
};

pub fn admit_package(
    package: &CompiledSourcePackage,
    trust_store: &TrustStore,
    requested_scope: &AuthorityScope,
    now_epoch_seconds: u64,
) -> Result<AdmittedPackage, TrustFault> {
    let certificate = package.certificate.as_ref().ok_or_else(|| {
        TrustFault::new(
            TrustFaultKind::UnsignedPackage,
            "certificate_presence",
            "compiled package contains no Cantor Recognition Certificate",
        )
    })?;
    if certificate.signature_algorithm_profile != trust_store.approved_signature_profile
        || certificate.signature_algorithm_profile != RECOGNITION_PROFILE
    {
        return Err(TrustFault::new(
            TrustFaultKind::SignatureProfileRejected,
            "signature_profile",
            "certificate signature profile is not approved",
        ));
    }

    let package_digest = package_content_digest(&package.content)?;
    if package_digest != certificate.package_digest {
        return Err(TrustFault::new(
            TrustFaultKind::PackageDigestMismatch,
            "package_digest",
            "package content does not match the signed package digest",
        ));
    }
    let expected_package_id = derive_package_id(&package_digest)?;
    if package.package_id != expected_package_id {
        return Err(TrustFault::new(
            TrustFaultKind::InvalidPackageIdentity,
            "package_identity",
            "package identity is not derived from its canonical content digest",
        ));
    }
    let semantic_root = semantic_root_digest(&package.content)?;
    if semantic_root != certificate.semantic_root_digest {
        return Err(TrustFault::new(
            TrustFaultKind::SemanticRootMismatch,
            "semantic_root",
            "semantic units or relations differ from the certificate",
        ));
    }
    let source_root = source_root_digest(&package.content)?;
    if source_root != certificate.source_root_digest {
        return Err(TrustFault::new(
            TrustFaultKind::SourceRootMismatch,
            "source_root",
            "source snapshots, anchors, or quotes differ from the certificate",
        ));
    }
    let expected_certificate_id = derive_certificate_id(
        &package_digest,
        &semantic_root,
        &source_root,
        &certificate.authority_signer_id,
        &certificate.compiler_signer_id,
        &certificate.signature_algorithm_profile,
        certificate.issued_at_epoch_seconds,
        certificate.not_before_epoch_seconds,
        certificate.not_after_epoch_seconds,
        &certificate.authority_scope,
    )?;
    if certificate.certificate_id != expected_certificate_id
        || certificate.revocation_locator
            != format!("trust-store://certificate/{}", certificate.certificate_id)
    {
        return Err(TrustFault::new(
            TrustFaultKind::InvalidPackageIdentity,
            "certificate_identity",
            "certificate identity or revocation locator is not canonical",
        ));
    }
    if certificate.not_before_epoch_seconds > certificate.issued_at_epoch_seconds
        || certificate.issued_at_epoch_seconds > certificate.not_after_epoch_seconds
    {
        return Err(TrustFault::new(
            TrustFaultKind::InvalidValidityInterval,
            "validity",
            "certificate validity interval is malformed",
        ));
    }

    if trust_store.revoked_packages.contains(&package.package_id)
        || trust_store
            .revoked_certificates
            .contains(&certificate.certificate_id)
    {
        return Err(TrustFault::new(
            TrustFaultKind::Revoked,
            "revocation",
            "package or certificate is revoked",
        ));
    }
    if trust_store.stale_packages.contains(&package.package_id) {
        return Err(TrustFault::new(
            TrustFaultKind::Stale,
            "freshness",
            "package is marked stale",
        ));
    }
    if now_epoch_seconds < certificate.not_before_epoch_seconds {
        return Err(TrustFault::new(
            TrustFaultKind::NotYetValid,
            "validity",
            "certificate is not yet valid",
        ));
    }
    if now_epoch_seconds > certificate.not_after_epoch_seconds {
        return Err(TrustFault::new(
            TrustFaultKind::Expired,
            "validity",
            "certificate has expired",
        ));
    }

    let authority_signer = trust_store
        .signers
        .get(&certificate.authority_signer_id)
        .ok_or_else(|| {
            TrustFault::new(
                TrustFaultKind::UnknownSigner,
                "authority_signer",
                "authority signer is not recognized",
            )
        })?;
    let compiler_signer = trust_store
        .signers
        .get(&certificate.compiler_signer_id)
        .ok_or_else(|| {
            TrustFault::new(
                TrustFaultKind::UnknownSigner,
                "compiler_signer",
                "compiler signer is not recognized",
            )
        })?;
    if authority_signer.signer_id != certificate.authority_signer_id
        || compiler_signer.signer_id != certificate.compiler_signer_id
    {
        return Err(TrustFault::new(
            TrustFaultKind::SignerIdentityMismatch,
            "signer_identity",
            "trust-store key and embedded signer identity must match",
        ));
    }
    if authority_signer.role != SignerRole::Authority
        || compiler_signer.role != SignerRole::Compiler
    {
        return Err(TrustFault::new(
            TrustFaultKind::SignerRoleMismatch,
            "signer_role",
            "authority and compiler signer roles must remain distinct",
        ));
    }
    if certificate.authority_signer_id == certificate.compiler_signer_id
        || authority_signer.verifying_key == compiler_signer.verifying_key
    {
        return Err(TrustFault::new(
            TrustFaultKind::SignerSeparationViolation,
            "signer_separation",
            "authority and compiler attestations require distinct identities and keys",
        ));
    }
    if !compiler_signer
        .authorized_compiler_ids
        .contains(&package.content.compiler_id)
    {
        return Err(TrustFault::new(
            TrustFaultKind::CompilerVersionRejected,
            "compiler_signer_scope",
            "compiler signer is not authorized for the declared compiler identity",
        ));
    }
    if package.content.declared_scope != certificate.authority_scope
        || !authority_signer
            .authority_scope
            .contains(&certificate.authority_scope)
        || !certificate.authority_scope.contains(requested_scope)
    {
        return Err(TrustFault::new(
            TrustFaultKind::ScopeViolation,
            "authority_scope",
            "declared, signer, certificate, or requested scope is incompatible",
        ));
    }

    let allowed_versions = trust_store
        .allowed_compiler_versions
        .get(&package.content.compiler_id)
        .ok_or_else(|| {
            TrustFault::new(
                TrustFaultKind::CompilerVersionRejected,
                "compiler_version",
                "compiler identity is not recognized",
            )
        })?;
    if !allowed_versions.contains(&package.content.compiler_version) {
        return Err(TrustFault::new(
            TrustFaultKind::CompilerVersionRejected,
            "compiler_version",
            "compiler version is not admitted by trust policy",
        ));
    }
    if package.content.dependency_lock != trust_store.required_dependency_lock {
        return Err(TrustFault::new(
            TrustFaultKind::DependencyLockMismatch,
            "dependency_lock",
            "package dependency lock differs from trust policy",
        ));
    }

    let authority_statement = AuthorityStatement {
        domain: "cantor-authority-v1".to_owned(),
        certificate_id: certificate.certificate_id.clone(),
        package_digest: package_digest.clone(),
        semantic_root_digest: semantic_root,
        source_root_digest: source_root,
        authority_signer_id: certificate.authority_signer_id.clone(),
        signature_algorithm_profile: certificate.signature_algorithm_profile.clone(),
        issued_at_epoch_seconds: certificate.issued_at_epoch_seconds,
        not_before_epoch_seconds: certificate.not_before_epoch_seconds,
        not_after_epoch_seconds: certificate.not_after_epoch_seconds,
        authority_scope: certificate.authority_scope.clone(),
        revocation_locator: certificate.revocation_locator.clone(),
    };
    verify_value(
        &authority_signer.verifying_key,
        &certificate.authority_signature,
        &authority_statement,
    )?;
    let compiler_statement = CompilerStatement {
        domain: "cantor-compiler-v1".to_owned(),
        certificate_id: certificate.certificate_id.clone(),
        package_digest,
        compiler_signer_id: certificate.compiler_signer_id.clone(),
        compiler_id: package.content.compiler_id.clone(),
        compiler_version: package.content.compiler_version.clone(),
        dependency_lock: package.content.dependency_lock.clone(),
        proof_ids: package.content.proof_ids.clone(),
    };
    verify_value(
        &compiler_signer.verifying_key,
        &certificate.compiler_signature,
        &compiler_statement,
    )?;
    validate_package_structure(package)?;

    Ok(AdmittedPackage {
        package: package.clone(),
        certificate_id: certificate.certificate_id.clone(),
        admitted_at_epoch_seconds: now_epoch_seconds,
    })
}

pub fn validate_package_structure(package: &CompiledSourcePackage) -> Result<(), TrustFault> {
    let content = &package.content;
    if content.format_version != PACKAGE_FORMAT_VERSION {
        return Err(TrustFault::new(
            TrustFaultKind::DependencyLockMismatch,
            "package_format",
            "package format version is unsupported",
        ));
    }
    if content.compiler_version.trim().is_empty() {
        return Err(TrustFault::new(
            TrustFaultKind::MachineForm,
            "compiler_identity",
            "compiler version must contain non-whitespace text",
        ));
    }
    if content
        .dependency_lock
        .iter()
        .any(|(name, version)| name.trim().is_empty() || version.trim().is_empty())
    {
        return Err(TrustFault::new(
            TrustFaultKind::MachineForm,
            "dependency_lock",
            "dependency identities and versions cannot be blank",
        ));
    }
    if (content.declared_scope.projects.is_empty() && content.declared_scope.namespaces.is_empty())
        || content
            .declared_scope
            .projects
            .iter()
            .chain(content.declared_scope.namespaces.iter())
            .chain(content.declared_scope.perspectives.iter())
            .chain(content.declared_scope.instruction_capabilities.iter())
            .any(|value| value.trim().is_empty())
    {
        return Err(TrustFault::new(
            TrustFaultKind::ScopeViolation,
            "authority_scope_structure",
            "authority scope requires a nonblank project or namespace and no blank selectors",
        ));
    }
    if content.sources.is_empty() || content.semantic_units.is_empty() {
        return Err(TrustFault::new(
            TrustFaultKind::EmptyPackage,
            "package_structure",
            "admitted package cannot be empty",
        ));
    }
    if !content
        .sources
        .windows(2)
        .all(|pair| pair[0].file_id < pair[1].file_id)
        || !content
            .semantic_units
            .windows(2)
            .all(|pair| pair[0].unit_id < pair[1].unit_id)
        || !content
            .relations
            .windows(2)
            .all(|pair| pair[0].relation_id < pair[1].relation_id)
        || !content
            .source_anchors
            .windows(2)
            .all(|pair| pair[0].unit_id < pair[1].unit_id)
        || !content
            .quotes
            .windows(2)
            .all(|pair| pair[0].unit_id < pair[1].unit_id)
        || !content.proof_ids.windows(2).all(|pair| pair[0] < pair[1])
    {
        return Err(TrustFault::new(
            TrustFaultKind::MachineForm,
            "canonical_order",
            "package collections must use strict canonical identity order",
        ));
    }
    reject_duplicate_ids(
        content.sources.iter().map(|source| &source.file_id),
        "source_identity",
    )?;
    let unique_paths = content
        .sources
        .iter()
        .map(|source| source.path.as_str())
        .collect::<BTreeSet<_>>();
    if unique_paths.len() != content.sources.len() {
        return Err(TrustFault::new(
            TrustFaultKind::DuplicateIdentity,
            "source_path",
            "source paths must be unique inside one compiled package",
        ));
    }
    reject_duplicate_ids(
        content.semantic_units.iter().map(|unit| &unit.unit_id),
        "semantic_identity",
    )?;
    reject_duplicate_ids(
        content
            .relations
            .iter()
            .map(|relation| &relation.relation_id),
        "relation_identity",
    )?;
    for source in &content.sources {
        if source.path.trim().is_empty() {
            return Err(TrustFault::new(
                TrustFaultKind::MachineForm,
                "source_path",
                format!("source {} requires a human-readable path", source.file_id),
            ));
        }
        if std::str::from_utf8(&source.bytes).is_err() {
            return Err(TrustFault::new(
                TrustFaultKind::InvalidSourceEncoding,
                "source_encoding",
                format!("source {} is not valid UTF-8 SOP text", source.file_id),
            ));
        }
        if sha256_bytes(&source.bytes) != source.document_digest {
            return Err(TrustFault::new(
                TrustFaultKind::SourceRootMismatch,
                "source_digest",
                format!("source {} digest does not match bytes", source.file_id),
            ));
        }
    }
    for unit in &content.semantic_units {
        if unit.expression.trim().is_empty()
            || unit.meaning.trim().is_empty()
            || unit.context.scope.trim().is_empty()
            || unit.context.purpose.trim().is_empty()
            || unit.context.perspective.trim().is_empty()
            || unit.context.world.trim().is_empty()
            || unit.aliases.iter().any(|alias| alias.trim().is_empty())
            || unit.source_set.is_empty()
            || unit
                .source_set
                .iter()
                .any(|source| source.trim().is_empty())
        {
            return Err(TrustFault::new(
                TrustFaultKind::MachineForm,
                "semantic_unit",
                format!(
                    "semantic unit {} requires expression and complete context identity",
                    unit.unit_id
                ),
            ));
        }
        if !content.declared_scope.semantic_kinds.contains(&unit.kind)
            || !content
                .declared_scope
                .perspectives
                .contains(&unit.context.perspective)
        {
            return Err(TrustFault::new(
                TrustFaultKind::ScopeViolation,
                "authority_scope_content",
                format!(
                    "semantic unit {} exceeds the package's declared kind or perspective scope",
                    unit.unit_id
                ),
            ));
        }
    }
    let rebuilt_indexes = build_exact_indexes(&content.semantic_units, &content.relations)?;
    if rebuilt_indexes != content.exact_indexes {
        return Err(TrustFault::new(
            TrustFaultKind::IndexCorruption,
            "exact_indexes",
            "signed exact indexes do not match authoritative units and relations",
        ));
    }
    let unit_ids = content
        .semantic_units
        .iter()
        .map(|unit| unit.unit_id.clone())
        .collect::<BTreeSet<_>>();
    for relation in &content.relations {
        if !unit_ids.contains(&relation.source) || !unit_ids.contains(&relation.target) {
            return Err(TrustFault::new(
                TrustFaultKind::ReferentialIntegrity,
                "semantic_graph",
                format!("relation {} has an unknown endpoint", relation.relation_id),
            ));
        }
        if relation.source_ref.trim().is_empty() {
            return Err(TrustFault::new(
                TrustFaultKind::MachineForm,
                "relation_source",
                format!(
                    "relation {} requires a source reference",
                    relation.relation_id
                ),
            ));
        }
    }
    if content
        .proof_ids
        .iter()
        .any(|proof_id| proof_id.trim().is_empty())
    {
        return Err(TrustFault::new(
            TrustFaultKind::MachineForm,
            "proof_identity",
            "proof identifiers cannot be blank",
        ));
    }

    let anchors = content
        .source_anchors
        .iter()
        .map(|anchor| (anchor.unit_id.clone(), anchor))
        .collect::<BTreeMap<_, _>>();
    if anchors.len() != content.source_anchors.len() {
        return Err(TrustFault::new(
            TrustFaultKind::DuplicateIdentity,
            "source_anchor",
            "more than one source anchor exists for a semantic unit",
        ));
    }
    if anchors.keys().cloned().collect::<BTreeSet<_>>() != unit_ids {
        return Err(TrustFault::new(
            TrustFaultKind::ReferentialIntegrity,
            "source_anchor",
            "every semantic unit must have exactly one source anchor",
        ));
    }
    let quotes = content
        .quotes
        .iter()
        .map(|quote| (quote.unit_id.clone(), quote))
        .collect::<BTreeMap<_, _>>();
    if quotes.len() != content.quotes.len()
        || quotes.keys().cloned().collect::<BTreeSet<_>>() != unit_ids
    {
        return Err(TrustFault::new(
            TrustFaultKind::ReferentialIntegrity,
            "quote_store",
            "every semantic unit must have exactly one quote record",
        ));
    }
    for unit_id in &unit_ids {
        let anchor = anchors[unit_id];
        let quote = quotes[unit_id];
        validate_quote(package, anchor, quote)?;
    }
    Ok(())
}

fn validate_quote(
    package: &CompiledSourcePackage,
    anchor: &SourceAnchor,
    quote: &super::types::QuoteRecord,
) -> Result<(), TrustFault> {
    if anchor.package_id != package.package_id || quote.anchor != *anchor {
        return Err(TrustFault::new(
            TrustFaultKind::ReferentialIntegrity,
            "quote_anchor",
            "quote and source anchor are not bound to the admitted package",
        ));
    }
    let source = package
        .content
        .sources
        .iter()
        .find(|source| source.file_id == anchor.file_id)
        .ok_or_else(|| {
            TrustFault::new(
                TrustFaultKind::ReferentialIntegrity,
                "quote_source",
                "quote references an unknown source file",
            )
        })?;
    let start = usize::try_from(anchor.byte_start).map_err(|error| {
        TrustFault::new(
            TrustFaultKind::InvalidSourceSpan,
            "quote_source",
            error.to_string(),
        )
    })?;
    let end = usize::try_from(anchor.byte_end).map_err(|error| {
        TrustFault::new(
            TrustFaultKind::InvalidSourceSpan,
            "quote_source",
            error.to_string(),
        )
    })?;
    if start >= end || end > source.bytes.len() {
        return Err(TrustFault::new(
            TrustFaultKind::InvalidSourceSpan,
            "quote_source",
            "quote source span is outside the signed source snapshot",
        ));
    }
    let source_text = std::str::from_utf8(&source.bytes).map_err(|error| {
        TrustFault::new(
            TrustFaultKind::InvalidSourceEncoding,
            "quote_source",
            error.to_string(),
        )
    })?;
    if !source_text.is_char_boundary(start) || !source_text.is_char_boundary(end) {
        return Err(TrustFault::new(
            TrustFaultKind::InvalidSourceSpan,
            "quote_source",
            "quote span does not preserve UTF-8 character boundaries",
        ));
    }
    if source.bytes[start..end] != quote.bytes {
        return Err(TrustFault::new(
            TrustFaultKind::QuoteSubstitution,
            "quote_source",
            "quote bytes differ from the signed source snapshot",
        ));
    }
    if sha256_bytes(&quote.bytes) != anchor.span_digest {
        return Err(TrustFault::new(
            TrustFaultKind::QuoteDigestMismatch,
            "quote_digest",
            "quote bytes differ from the signed span digest",
        ));
    }
    Ok(())
}

fn reject_duplicate_ids<'a>(
    values: impl Iterator<Item = &'a SemanticId>,
    gate: &str,
) -> Result<(), TrustFault> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(TrustFault::new(
                TrustFaultKind::DuplicateIdentity,
                gate,
                format!("duplicate identity {value}"),
            ));
        }
    }
    Ok(())
}
