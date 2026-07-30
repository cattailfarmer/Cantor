use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::SigningKey;

use crate::model::{SemanticId, SemanticRelation, SemanticUnit, SourceAnchor};

use super::admission::validate_package_structure;
use super::crypto::{
    derive_certificate_id, derive_package_id, package_content_digest, semantic_root_digest,
    sha256_bytes, sign_value, source_root_digest,
};
use super::types::{
    AuthorityStatement, CantorRecognitionCertificate, CompiledSourcePackage, CompilerStatement,
    ExactIndexArtifact, PACKAGE_FORMAT_VERSION, PackageCompilationInput, PackageCompiler,
    PackageContent, QuoteRecord, RECOGNITION_PROFILE, SourceSnapshot, TrustFault, TrustFaultKind,
    UnitCompilationInput,
};

impl PackageCompiler {
    pub fn new(
        compiler_id: SemanticId,
        compiler_version: impl Into<String>,
        authority_signer_id: SemanticId,
        compiler_signer_id: SemanticId,
        authority_signing_key: SigningKey,
        compiler_signing_key: SigningKey,
    ) -> Self {
        Self {
            compiler_id,
            compiler_version: compiler_version.into(),
            authority_signer_id,
            compiler_signer_id,
            authority_signing_key,
            compiler_signing_key,
        }
    }

    pub fn authority_verifying_key_bytes(&self) -> Vec<u8> {
        self.authority_signing_key
            .verifying_key()
            .to_bytes()
            .to_vec()
    }

    pub fn compiler_verifying_key_bytes(&self) -> Vec<u8> {
        self.compiler_signing_key
            .verifying_key()
            .to_bytes()
            .to_vec()
    }

    pub fn compile(
        &self,
        input: PackageCompilationInput,
    ) -> Result<CompiledSourcePackage, TrustFault> {
        if self.authority_signer_id == self.compiler_signer_id
            || self.authority_signing_key.verifying_key()
                == self.compiler_signing_key.verifying_key()
        {
            return Err(TrustFault::new(
                TrustFaultKind::SignerSeparationViolation,
                "signer_separation",
                "authority and compiler attestations require distinct identities and keys",
            ));
        }
        if input.sources.is_empty() || input.units.is_empty() {
            return Err(TrustFault::new(
                TrustFaultKind::EmptyPackage,
                "compile_input",
                "a package requires at least one source and one semantic unit",
            ));
        }
        if input.not_before_epoch_seconds > input.issued_at_epoch_seconds
            || input.issued_at_epoch_seconds > input.not_after_epoch_seconds
        {
            return Err(TrustFault::new(
                TrustFaultKind::InvalidValidityInterval,
                "certificate_validity",
                "not_before <= issued_at <= not_after is required",
            ));
        }

        let mut sources = input
            .sources
            .into_iter()
            .map(|source| SourceSnapshot {
                file_id: source.file_id,
                path: source.path,
                document_digest: sha256_bytes(&source.bytes),
                bytes: source.bytes,
            })
            .collect::<Vec<_>>();
        sources.sort_by(|left, right| left.file_id.cmp(&right.file_id));
        reject_duplicate_ids(
            sources.iter().map(|source| &source.file_id),
            "source_identity",
        )?;

        let mut units = input.units;
        units.sort_by(|left, right| left.unit.unit_id.cmp(&right.unit.unit_id));
        reject_duplicate_ids(
            units.iter().map(|unit| &unit.unit.unit_id),
            "semantic_identity",
        )?;

        let mut semantic_units = Vec::with_capacity(units.len());
        let mut source_anchors = Vec::with_capacity(units.len());
        let mut quotes = Vec::with_capacity(units.len());
        for unit_input in units {
            let (unit, anchor, quote) = compile_unit(&sources, unit_input)?;
            semantic_units.push(unit);
            source_anchors.push(anchor);
            quotes.push(quote);
        }
        source_anchors.sort_by(|left, right| left.unit_id.cmp(&right.unit_id));
        quotes.sort_by(|left, right| left.unit_id.cmp(&right.unit_id));

        let mut relations = input.relations;
        relations.sort_by(|left, right| left.relation_id.cmp(&right.relation_id));
        reject_duplicate_ids(
            relations.iter().map(|relation| &relation.relation_id),
            "relation_identity",
        )?;
        validate_relation_endpoints(&semantic_units, &relations)?;
        let exact_indexes = build_exact_indexes(&semantic_units, &relations)?;

        let mut proof_ids = input.proof_ids;
        proof_ids.sort();
        proof_ids.dedup();
        let mut content = PackageContent {
            format_version: PACKAGE_FORMAT_VERSION.to_owned(),
            compiler_id: self.compiler_id.clone(),
            compiler_version: self.compiler_version.clone(),
            dependency_lock: input.dependency_lock,
            declared_scope: input.authority_scope.clone(),
            sources,
            semantic_units,
            relations,
            source_anchors,
            quotes,
            exact_indexes,
            proof_ids,
        };
        let package_digest = package_content_digest(&content)?;
        let semantic_root_digest = semantic_root_digest(&content)?;
        let source_root_digest = source_root_digest(&content)?;
        let package_id = derive_package_id(&package_digest)?;
        for anchor in &mut content.source_anchors {
            anchor.package_id = package_id.clone();
        }
        for quote in &mut content.quotes {
            quote.anchor.package_id = package_id.clone();
        }

        let certificate_id = derive_certificate_id(
            &package_digest,
            &semantic_root_digest,
            &source_root_digest,
            &self.authority_signer_id,
            &self.compiler_signer_id,
            RECOGNITION_PROFILE,
            input.issued_at_epoch_seconds,
            input.not_before_epoch_seconds,
            input.not_after_epoch_seconds,
            &input.authority_scope,
        )?;
        let revocation_locator = format!("trust-store://certificate/{certificate_id}");
        let authority_statement = AuthorityStatement {
            domain: "cantor-authority-v1".to_owned(),
            certificate_id: certificate_id.clone(),
            package_digest: package_digest.clone(),
            semantic_root_digest: semantic_root_digest.clone(),
            source_root_digest: source_root_digest.clone(),
            authority_signer_id: self.authority_signer_id.clone(),
            signature_algorithm_profile: RECOGNITION_PROFILE.to_owned(),
            issued_at_epoch_seconds: input.issued_at_epoch_seconds,
            not_before_epoch_seconds: input.not_before_epoch_seconds,
            not_after_epoch_seconds: input.not_after_epoch_seconds,
            authority_scope: input.authority_scope.clone(),
            revocation_locator: revocation_locator.clone(),
        };
        let compiler_statement = CompilerStatement {
            domain: "cantor-compiler-v1".to_owned(),
            certificate_id: certificate_id.clone(),
            package_digest: package_digest.clone(),
            compiler_signer_id: self.compiler_signer_id.clone(),
            compiler_id: self.compiler_id.clone(),
            compiler_version: self.compiler_version.clone(),
            dependency_lock: content.dependency_lock.clone(),
            proof_ids: content.proof_ids.clone(),
        };
        let authority_signature = sign_value(&self.authority_signing_key, &authority_statement)?;
        let compiler_signature = sign_value(&self.compiler_signing_key, &compiler_statement)?;
        let certificate = CantorRecognitionCertificate {
            certificate_id: certificate_id.clone(),
            package_digest,
            semantic_root_digest,
            source_root_digest,
            authority_signer_id: self.authority_signer_id.clone(),
            compiler_signer_id: self.compiler_signer_id.clone(),
            signature_algorithm_profile: RECOGNITION_PROFILE.to_owned(),
            authority_signature,
            compiler_signature,
            issued_at_epoch_seconds: input.issued_at_epoch_seconds,
            not_before_epoch_seconds: input.not_before_epoch_seconds,
            not_after_epoch_seconds: input.not_after_epoch_seconds,
            authority_scope: input.authority_scope,
            revocation_locator,
        };
        let package = CompiledSourcePackage {
            package_id,
            content,
            certificate: Some(certificate),
        };
        validate_package_structure(&package)?;
        Ok(package)
    }
}

pub fn build_exact_indexes(
    units: &[SemanticUnit],
    relations: &[SemanticRelation],
) -> Result<ExactIndexArtifact, TrustFault> {
    let mut unit_positions = BTreeMap::new();
    let mut labels: BTreeMap<String, BTreeSet<SemanticId>> = BTreeMap::new();
    for (position, unit) in units.iter().enumerate() {
        if unit_positions
            .insert(unit.unit_id.clone(), position)
            .is_some()
        {
            return Err(TrustFault::new(
                TrustFaultKind::DuplicateIdentity,
                "exact_index",
                format!("duplicate semantic unit {}", unit.unit_id),
            ));
        }
        labels
            .entry(unit.expression.trim().to_ascii_lowercase())
            .or_default()
            .insert(unit.unit_id.clone());
        for alias in &unit.aliases {
            labels
                .entry(alias.trim().to_ascii_lowercase())
                .or_default()
                .insert(unit.unit_id.clone());
        }
    }
    let mut relation_positions = BTreeMap::new();
    for (position, relation) in relations.iter().enumerate() {
        if relation_positions
            .insert(relation.relation_id.clone(), position)
            .is_some()
        {
            return Err(TrustFault::new(
                TrustFaultKind::DuplicateIdentity,
                "exact_index",
                format!("duplicate relation {}", relation.relation_id),
            ));
        }
    }
    Ok(ExactIndexArtifact {
        unit_positions,
        relation_positions,
        labels,
    })
}

fn compile_unit(
    sources: &[SourceSnapshot],
    input: UnitCompilationInput,
) -> Result<(SemanticUnit, SourceAnchor, QuoteRecord), TrustFault> {
    let source = sources
        .iter()
        .find(|source| source.file_id == input.file_id)
        .ok_or_else(|| {
            TrustFault::new(
                TrustFaultKind::ReferentialIntegrity,
                "source_anchor",
                format!("unknown source file {}", input.file_id),
            )
        })?;
    if input.byte_start >= input.byte_end || input.byte_end > source.bytes.len() {
        return Err(TrustFault::new(
            TrustFaultKind::InvalidSourceSpan,
            "source_anchor",
            format!(
                "invalid byte range {}..{} for {} bytes",
                input.byte_start,
                input.byte_end,
                source.bytes.len()
            ),
        ));
    }
    let source_text = std::str::from_utf8(&source.bytes).map_err(|error| {
        TrustFault::new(
            TrustFaultKind::InvalidSourceEncoding,
            "source_anchor",
            error.to_string(),
        )
    })?;
    if !source_text.is_char_boundary(input.byte_start)
        || !source_text.is_char_boundary(input.byte_end)
    {
        return Err(TrustFault::new(
            TrustFaultKind::InvalidSourceSpan,
            "source_anchor",
            "source span must begin and end on UTF-8 character boundaries",
        ));
    }
    let quote_bytes = source.bytes[input.byte_start..input.byte_end].to_vec();
    let span_digest = sha256_bytes(&quote_bytes);
    let line_start = line_at_offset(&source.bytes, input.byte_start);
    let line_end = line_at_offset(&source.bytes, input.byte_end.saturating_sub(1));
    let anchor = SourceAnchor {
        package_id: SemanticId::new("package:pending").map_err(|error| {
            TrustFault::new(
                TrustFaultKind::InvalidPackageIdentity,
                "source_anchor",
                error.to_string(),
            )
        })?,
        file_id: input.file_id,
        unit_id: input.unit.unit_id.clone(),
        clause_id: input.clause_id,
        byte_start: u64::try_from(input.byte_start).map_err(|error| {
            TrustFault::new(
                TrustFaultKind::InvalidSourceSpan,
                "source_anchor",
                error.to_string(),
            )
        })?,
        byte_end: u64::try_from(input.byte_end).map_err(|error| {
            TrustFault::new(
                TrustFaultKind::InvalidSourceSpan,
                "source_anchor",
                error.to_string(),
            )
        })?,
        span_digest,
        display_line_start: line_start,
        display_line_end: line_end,
    };
    let quote = QuoteRecord {
        unit_id: input.unit.unit_id.clone(),
        anchor: anchor.clone(),
        bytes: quote_bytes,
    };
    Ok((input.unit, anchor, quote))
}

fn validate_relation_endpoints(
    units: &[SemanticUnit],
    relations: &[SemanticRelation],
) -> Result<(), TrustFault> {
    let unit_ids = units
        .iter()
        .map(|unit| &unit.unit_id)
        .collect::<BTreeSet<_>>();
    for relation in relations {
        if !unit_ids.contains(&relation.source) || !unit_ids.contains(&relation.target) {
            return Err(TrustFault::new(
                TrustFaultKind::ReferentialIntegrity,
                "semantic_graph",
                format!("relation {} has an unknown endpoint", relation.relation_id),
            ));
        }
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

fn line_at_offset(bytes: &[u8], offset: usize) -> u32 {
    let line = 1_usize
        + bytes[..offset]
            .iter()
            .filter(|byte| **byte == b'\n')
            .count();
    u32::try_from(line).unwrap_or(u32::MAX)
}
