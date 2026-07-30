use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

use crate::model::{
    ContentDigest, SemanticId, SemanticRelation, SemanticUnit, SourceAnchor, UnitKind,
};

pub const RECOGNITION_PROFILE: &str = "Ed25519+SHA-256/Cantor-CRC-v1";
pub const PACKAGE_FORMAT_VERSION: &str = "cantor-package/0.1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityScope {
    pub projects: BTreeSet<String>,
    pub namespaces: BTreeSet<String>,
    pub semantic_kinds: BTreeSet<UnitKind>,
    pub perspectives: BTreeSet<String>,
    pub instruction_capabilities: BTreeSet<String>,
}

impl AuthorityScope {
    pub fn contains(&self, requested: &Self) -> bool {
        requested.projects.is_subset(&self.projects)
            && requested.namespaces.is_subset(&self.namespaces)
            && requested.semantic_kinds.is_subset(&self.semantic_kinds)
            && requested.perspectives.is_subset(&self.perspectives)
            && requested
                .instruction_capabilities
                .is_subset(&self.instruction_capabilities)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceSnapshot {
    pub file_id: SemanticId,
    pub path: String,
    pub bytes: Vec<u8>,
    pub document_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuoteRecord {
    pub unit_id: SemanticId,
    pub anchor: SourceAnchor,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactIndexArtifact {
    pub unit_positions: BTreeMap<SemanticId, usize>,
    pub relation_positions: BTreeMap<SemanticId, usize>,
    pub labels: BTreeMap<String, BTreeSet<SemanticId>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageContent {
    pub format_version: String,
    pub compiler_id: SemanticId,
    pub compiler_version: String,
    pub dependency_lock: BTreeMap<String, String>,
    pub declared_scope: AuthorityScope,
    pub sources: Vec<SourceSnapshot>,
    pub semantic_units: Vec<SemanticUnit>,
    pub relations: Vec<SemanticRelation>,
    pub source_anchors: Vec<SourceAnchor>,
    pub quotes: Vec<QuoteRecord>,
    pub exact_indexes: ExactIndexArtifact,
    pub proof_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityStatement {
    pub domain: String,
    pub certificate_id: SemanticId,
    pub package_digest: ContentDigest,
    pub semantic_root_digest: ContentDigest,
    pub source_root_digest: ContentDigest,
    pub authority_signer_id: SemanticId,
    pub signature_algorithm_profile: String,
    pub issued_at_epoch_seconds: u64,
    pub not_before_epoch_seconds: u64,
    pub not_after_epoch_seconds: u64,
    pub authority_scope: AuthorityScope,
    pub revocation_locator: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompilerStatement {
    pub domain: String,
    pub certificate_id: SemanticId,
    pub package_digest: ContentDigest,
    pub compiler_signer_id: SemanticId,
    pub compiler_id: SemanticId,
    pub compiler_version: String,
    pub dependency_lock: BTreeMap<String, String>,
    pub proof_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CantorRecognitionCertificate {
    pub certificate_id: SemanticId,
    pub package_digest: ContentDigest,
    pub semantic_root_digest: ContentDigest,
    pub source_root_digest: ContentDigest,
    pub authority_signer_id: SemanticId,
    pub compiler_signer_id: SemanticId,
    pub signature_algorithm_profile: String,
    pub authority_signature: Vec<u8>,
    pub compiler_signature: Vec<u8>,
    pub issued_at_epoch_seconds: u64,
    pub not_before_epoch_seconds: u64,
    pub not_after_epoch_seconds: u64,
    pub authority_scope: AuthorityScope,
    pub revocation_locator: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledSourcePackage {
    pub package_id: SemanticId,
    pub content: PackageContent,
    pub certificate: Option<CantorRecognitionCertificate>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceDocumentInput {
    pub file_id: SemanticId,
    pub path: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnitCompilationInput {
    pub unit: SemanticUnit,
    pub file_id: SemanticId,
    pub clause_id: SemanticId,
    pub byte_start: usize,
    pub byte_end: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageCompilationInput {
    pub sources: Vec<SourceDocumentInput>,
    pub units: Vec<UnitCompilationInput>,
    pub relations: Vec<SemanticRelation>,
    pub dependency_lock: BTreeMap<String, String>,
    pub authority_scope: AuthorityScope,
    pub proof_ids: Vec<String>,
    pub issued_at_epoch_seconds: u64,
    pub not_before_epoch_seconds: u64,
    pub not_after_epoch_seconds: u64,
}

pub struct PackageCompiler {
    pub compiler_id: SemanticId,
    pub compiler_version: String,
    pub authority_signer_id: SemanticId,
    pub compiler_signer_id: SemanticId,
    pub(crate) authority_signing_key: SigningKey,
    pub(crate) compiler_signing_key: SigningKey,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignerRole {
    Authority,
    Compiler,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedSignerRecord {
    pub signer_id: SemanticId,
    pub role: SignerRole,
    pub verifying_key: Vec<u8>,
    pub authority_scope: AuthorityScope,
    pub authorized_compiler_ids: BTreeSet<SemanticId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustStore {
    pub approved_signature_profile: String,
    pub signers: BTreeMap<SemanticId, TrustedSignerRecord>,
    pub allowed_compiler_versions: BTreeMap<SemanticId, BTreeSet<String>>,
    pub required_dependency_lock: BTreeMap<String, String>,
    pub revoked_certificates: BTreeSet<SemanticId>,
    pub revoked_packages: BTreeSet<SemanticId>,
    pub stale_packages: BTreeSet<SemanticId>,
}

impl TrustStore {
    pub fn empty(required_dependency_lock: BTreeMap<String, String>) -> Self {
        Self {
            approved_signature_profile: RECOGNITION_PROFILE.to_owned(),
            signers: BTreeMap::new(),
            allowed_compiler_versions: BTreeMap::new(),
            required_dependency_lock,
            revoked_certificates: BTreeSet::new(),
            revoked_packages: BTreeSet::new(),
            stale_packages: BTreeSet::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmittedPackage {
    pub(crate) package: CompiledSourcePackage,
    pub(crate) certificate_id: SemanticId,
    pub(crate) admitted_at_epoch_seconds: u64,
}

impl AdmittedPackage {
    pub fn package(&self) -> &CompiledSourcePackage {
        &self.package
    }

    pub fn content(&self) -> &PackageContent {
        &self.package.content
    }

    pub fn certificate_id(&self) -> &SemanticId {
        &self.certificate_id
    }

    pub const fn admitted_at_epoch_seconds(&self) -> u64 {
        self.admitted_at_epoch_seconds
    }

    pub fn semantic_unit(&self, id: &SemanticId) -> Option<&SemanticUnit> {
        let position = self.package.content.exact_indexes.unit_positions.get(id)?;
        self.package.content.semantic_units.get(*position)
    }

    pub fn source_anchor(&self, id: &SemanticId) -> Option<&SourceAnchor> {
        self.package
            .content
            .source_anchors
            .iter()
            .find(|anchor| &anchor.unit_id == id)
    }

    pub fn quote(&self, id: &SemanticId) -> Option<&QuoteRecord> {
        self.package
            .content
            .quotes
            .iter()
            .find(|quote| &quote.unit_id == id)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustFaultKind {
    UnsignedPackage,
    InvalidPackageIdentity,
    PackageDigestMismatch,
    SemanticRootMismatch,
    SourceRootMismatch,
    UnknownSigner,
    SignerIdentityMismatch,
    SignerRoleMismatch,
    SignerSeparationViolation,
    SignatureProfileRejected,
    InvalidSignature,
    NotYetValid,
    Expired,
    Revoked,
    Stale,
    CompilerVersionRejected,
    DependencyLockMismatch,
    ScopeViolation,
    InvalidSourceSpan,
    InvalidSourceEncoding,
    QuoteDigestMismatch,
    QuoteSubstitution,
    IndexCorruption,
    ReferentialIntegrity,
    DuplicateIdentity,
    EmptyPackage,
    InvalidValidityInterval,
    MachineForm,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustFault {
    pub kind: TrustFaultKind,
    pub message: String,
    pub gate: String,
}

impl TrustFault {
    pub fn new(kind: TrustFaultKind, gate: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            kind,
            gate: gate.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for TrustFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{:?} at {}: {}",
            self.kind, self.gate, self.message
        )
    }
}

impl std::error::Error for TrustFault {}
