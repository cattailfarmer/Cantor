use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

use crate::{
    AuthorityContext, AuthorityScope, CantorQueryRequest, CompiledSourcePackage,
    EMBEDDED_ENVIRONMENT_VERSION, EmbeddedRuntimeEnvironment, ExpectedPackage, InspectRequest,
    PROTOCOL_VERSION, PackageCompilationInput, PackageCompiler, ProtocolCallerContext,
    ProtocolOperation, ProtocolRequest, QUERY_PROTOCOL_VERSION, QueryBudget, RelationType,
    RequestedDetailKind, SearchMode, SemanticContext, SemanticId, SemanticRelation, SemanticUnit,
    SignerRole, SourceDocumentInput, TrustStore, TrustedSignerRecord, UnitCompilationInput,
    UnitKind, UnitStatus, admit_package, embedded_environment_digest, execute_protocol_request,
    sha256_bytes, verify_protocol_response_against_environment,
};

pub const SOP_SOURCE_PROFILE: &str = "cantor-sop-source/0.1";
pub const SOP_LOWERING_PROFILE: &str = "cantor-sop-lowering/0.1";
pub const SOP_CORPUS_PROFILE: &str = "cantor-sop-corpus/0.1";

pub const MAX_DOCUMENTS: usize = 256;
pub const MAX_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_CORPUS_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_LINES_PER_DOCUMENT: usize = 200_000;
pub const MAX_NODES: usize = 1_000_000;
pub const MAX_RELATIONS: usize = 1_000_000;
pub const MAX_DEPTH: usize = 128;
pub const MAX_NAME_BYTES: usize = 512;
pub const MAX_BODY_BYTES: usize = 65_536;
pub const MAX_QUERY_TEMPLATES: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SopCorpusContext {
    pub project: String,
    pub namespace: String,
    pub source_scope: String,
    pub purpose: String,
    pub perspective: String,
    pub world: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SopCompilerIdentity {
    pub compiler_id: SemanticId,
    pub compiler_version: String,
    pub authority_signer_id: SemanticId,
    pub compiler_signer_id: SemanticId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SopDocumentManifest {
    pub document_id: String,
    pub path: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SopQueryTemplate {
    pub name: String,
    pub terms: BTreeSet<String>,
    pub subject: Option<String>,
    pub requested_detail_kinds: BTreeSet<RequestedDetailKind>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SopCorpusManifest {
    pub corpus_version: String,
    pub source_root: String,
    pub context: SopCorpusContext,
    pub compiler: SopCompilerIdentity,
    pub dependency_lock: BTreeMap<String, String>,
    pub proof_ids: Vec<String>,
    pub issued_at_epoch_seconds: u64,
    pub not_before_epoch_seconds: u64,
    pub not_after_epoch_seconds: u64,
    pub documents: Vec<SopDocumentManifest>,
    pub queries: Vec<SopQueryTemplate>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SopDocumentInput {
    pub document_id: String,
    pub path: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoweredSopCorpus {
    pub package_input: PackageCompilationInput,
    pub source_count: usize,
    pub unit_count: usize,
    pub relation_count: usize,
}

pub struct SopSigningKeys {
    pub authority: SigningKey,
    pub compiler: SigningKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamedProtocolRequest {
    pub name: String,
    pub request: ProtocolRequest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuiltSopCorpus {
    pub package: CompiledSourcePackage,
    pub environment: EmbeddedRuntimeEnvironment,
    pub requests: Vec<NamedProtocolRequest>,
    pub source_count: usize,
    pub unit_count: usize,
    pub relation_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SopFaultKind {
    InvalidManifest,
    Io,
    ResourceLimit,
    InvalidEncoding,
    InvalidSyntax,
    InvalidIndentation,
    DuplicateIdentity,
    Signing,
    Trust,
    ArtifactConflict,
    ArtifactWrite,
    Verification,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SopFault {
    pub kind: SopFaultKind,
    pub document_id: Option<String>,
    pub path: Option<String>,
    pub line: Option<u32>,
    pub byte_start: Option<u64>,
    pub byte_end: Option<u64>,
    pub message: String,
}

impl SopFault {
    pub fn manifest(message: impl Into<String>) -> Self {
        Self {
            kind: SopFaultKind::InvalidManifest,
            document_id: None,
            path: None,
            line: None,
            byte_start: None,
            byte_end: None,
            message: message.into(),
        }
    }

    pub fn external(kind: SopFaultKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            document_id: None,
            path: None,
            line: None,
            byte_start: None,
            byte_end: None,
            message: message.into(),
        }
    }

    fn document(
        kind: SopFaultKind,
        input: &SopDocumentInput,
        line: Option<usize>,
        byte_start: Option<usize>,
        byte_end: Option<usize>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            document_id: Some(input.document_id.clone()),
            path: Some(input.path.clone()),
            line: line.and_then(|value| u32::try_from(value).ok()),
            byte_start: byte_start.and_then(|value| u64::try_from(value).ok()),
            byte_end: byte_end.and_then(|value| u64::try_from(value).ok()),
            message: message.into(),
        }
    }
}

impl fmt::Display for SopFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.kind, self.message)?;
        if let Some(document_id) = &self.document_id {
            write!(formatter, " [document={document_id}")?;
            if let Some(line) = self.line {
                write!(formatter, ", line={line}")?;
            }
            write!(formatter, "]")?;
        }
        Ok(())
    }
}

impl std::error::Error for SopFault {}

pub fn lower_sop_corpus(
    manifest: &SopCorpusManifest,
    documents: Vec<SopDocumentInput>,
) -> Result<LoweredSopCorpus, Vec<SopFault>> {
    let mut faults = validate_manifest(manifest);
    if documents.len() != manifest.documents.len() {
        faults.push(SopFault::manifest(format!(
            "received {} source documents for {} manifest entries",
            documents.len(),
            manifest.documents.len()
        )));
    }

    let mut input_by_id = BTreeMap::new();
    for input in documents {
        let id = input.document_id.clone();
        if input_by_id.insert(id.clone(), input).is_some() {
            faults.push(SopFault::external(
                SopFaultKind::DuplicateIdentity,
                format!("duplicate source input document_id {id:?}"),
            ));
        }
    }

    let mut total_bytes = 0_usize;
    let mut ordered_inputs = Vec::new();
    for declared in &manifest.documents {
        match input_by_id.remove(&declared.document_id) {
            Some(input) if input.path == declared.path => {
                total_bytes = total_bytes.saturating_add(input.bytes.len());
                ordered_inputs.push(input);
            }
            Some(input) => faults.push(SopFault::document(
                SopFaultKind::InvalidManifest,
                &input,
                None,
                None,
                None,
                format!(
                    "resolved path {:?} differs from manifest path {:?}",
                    input.path, declared.path
                ),
            )),
            None => faults.push(SopFault::manifest(format!(
                "missing source input for document_id {:?}",
                declared.document_id
            ))),
        }
    }
    for unexpected in input_by_id.into_values() {
        faults.push(SopFault::document(
            SopFaultKind::InvalidManifest,
            &unexpected,
            None,
            None,
            None,
            "source input is not declared by the manifest",
        ));
    }
    if total_bytes > MAX_CORPUS_BYTES {
        faults.push(SopFault::external(
            SopFaultKind::ResourceLimit,
            format!("corpus source bytes {total_bytes} exceed the {MAX_CORPUS_BYTES}-byte limit"),
        ));
    }
    if !faults.is_empty() {
        sort_faults(&mut faults);
        return Err(faults);
    }

    let mut sources = Vec::new();
    let mut units = Vec::new();
    let mut relations = Vec::new();
    let mut file_ids = BTreeSet::new();
    let mut unit_ids = BTreeSet::new();
    let mut clause_ids = BTreeSet::new();
    let mut relation_ids = BTreeSet::new();

    for input in &ordered_inputs {
        match parse_document(manifest, input) {
            Ok(parsed) => {
                if !file_ids.insert(parsed.source.file_id.clone()) {
                    faults.push(SopFault::document(
                        SopFaultKind::DuplicateIdentity,
                        input,
                        None,
                        None,
                        None,
                        format!("derived duplicate file identity {}", parsed.source.file_id),
                    ));
                }
                for unit in &parsed.units {
                    if !unit_ids.insert(unit.unit.unit_id.clone()) {
                        faults.push(SopFault::document(
                            SopFaultKind::DuplicateIdentity,
                            input,
                            None,
                            Some(unit.byte_start),
                            Some(unit.byte_end),
                            format!("derived duplicate unit identity {}", unit.unit.unit_id),
                        ));
                    }
                    if !clause_ids.insert(unit.clause_id.clone()) {
                        faults.push(SopFault::document(
                            SopFaultKind::DuplicateIdentity,
                            input,
                            None,
                            Some(unit.byte_start),
                            Some(unit.byte_end),
                            format!("derived duplicate clause identity {}", unit.clause_id),
                        ));
                    }
                }
                for relation in &parsed.relations {
                    if !relation_ids.insert(relation.relation_id.clone()) {
                        faults.push(SopFault::document(
                            SopFaultKind::DuplicateIdentity,
                            input,
                            None,
                            None,
                            None,
                            format!(
                                "derived duplicate relation identity {}",
                                relation.relation_id
                            ),
                        ));
                    }
                }
                sources.push(parsed.source);
                units.extend(parsed.units);
                relations.extend(parsed.relations);
            }
            Err(mut document_faults) => faults.append(&mut document_faults),
        }
    }

    if units.len() > MAX_NODES {
        faults.push(SopFault::external(
            SopFaultKind::ResourceLimit,
            format!(
                "lowered units {} exceed the {MAX_NODES}-unit limit",
                units.len()
            ),
        ));
    }
    if relations.len() > MAX_RELATIONS {
        faults.push(SopFault::external(
            SopFaultKind::ResourceLimit,
            format!(
                "lowered relations {} exceed the {MAX_RELATIONS}-relation limit",
                relations.len()
            ),
        ));
    }
    if !faults.is_empty() {
        sort_faults(&mut faults);
        return Err(faults);
    }

    let semantic_kinds = units
        .iter()
        .map(|unit| unit.unit.kind.clone())
        .collect::<BTreeSet<_>>();
    let authority_scope = AuthorityScope {
        projects: [manifest.context.project.clone()].into_iter().collect(),
        namespaces: [manifest.context.namespace.clone()].into_iter().collect(),
        semantic_kinds,
        perspectives: [manifest.context.perspective.clone()].into_iter().collect(),
        instruction_capabilities: ["read".to_owned()].into_iter().collect(),
    };
    let source_count = sources.len();
    let unit_count = units.len();
    let relation_count = relations.len();
    Ok(LoweredSopCorpus {
        package_input: PackageCompilationInput {
            sources,
            units,
            relations,
            dependency_lock: manifest.dependency_lock.clone(),
            authority_scope,
            proof_ids: manifest.proof_ids.clone(),
            issued_at_epoch_seconds: manifest.issued_at_epoch_seconds,
            not_before_epoch_seconds: manifest.not_before_epoch_seconds,
            not_after_epoch_seconds: manifest.not_after_epoch_seconds,
        },
        source_count,
        unit_count,
        relation_count,
    })
}

pub fn build_sop_corpus(
    manifest: &SopCorpusManifest,
    documents: Vec<SopDocumentInput>,
    keys: SopSigningKeys,
) -> Result<BuiltSopCorpus, Vec<SopFault>> {
    if keys.authority.to_bytes() == keys.compiler.to_bytes() {
        return Err(vec![SopFault::external(
            SopFaultKind::Signing,
            "authority and compiler signing seeds must differ",
        )]);
    }
    let lowered = lower_sop_corpus(manifest, documents)?;
    let authority_scope = lowered.package_input.authority_scope.clone();
    let compiler = PackageCompiler::new(
        manifest.compiler.compiler_id.clone(),
        manifest.compiler.compiler_version.clone(),
        manifest.compiler.authority_signer_id.clone(),
        manifest.compiler.compiler_signer_id.clone(),
        keys.authority,
        keys.compiler,
    );
    let package = compiler
        .compile(lowered.package_input)
        .map_err(|fault| vec![SopFault::external(SopFaultKind::Signing, fault.to_string())])?;
    let mut trust_store = TrustStore::empty(manifest.dependency_lock.clone());
    trust_store.signers.insert(
        manifest.compiler.authority_signer_id.clone(),
        TrustedSignerRecord {
            signer_id: manifest.compiler.authority_signer_id.clone(),
            role: SignerRole::Authority,
            verifying_key: compiler.authority_verifying_key_bytes(),
            authority_scope: authority_scope.clone(),
            authorized_compiler_ids: BTreeSet::new(),
        },
    );
    trust_store.signers.insert(
        manifest.compiler.compiler_signer_id.clone(),
        TrustedSignerRecord {
            signer_id: manifest.compiler.compiler_signer_id.clone(),
            role: SignerRole::Compiler,
            verifying_key: compiler.compiler_verifying_key_bytes(),
            authority_scope: authority_scope.clone(),
            authorized_compiler_ids: [manifest.compiler.compiler_id.clone()]
                .into_iter()
                .collect(),
        },
    );
    trust_store.allowed_compiler_versions.insert(
        manifest.compiler.compiler_id.clone(),
        [manifest.compiler.compiler_version.clone()]
            .into_iter()
            .collect(),
    );
    admit_package(
        &package,
        &trust_store,
        &authority_scope,
        manifest.issued_at_epoch_seconds,
    )
    .map_err(|fault| vec![SopFault::external(SopFaultKind::Trust, fault.to_string())])?;

    let environment = EmbeddedRuntimeEnvironment {
        environment_version: EMBEDDED_ENVIRONMENT_VERSION.to_owned(),
        now_epoch_seconds: manifest.issued_at_epoch_seconds,
        trust_store,
        packages: vec![package.clone()],
    };
    let environment_digest = embedded_environment_digest(&environment).map_err(|fault| {
        vec![SopFault::external(
            SopFaultKind::Verification,
            fault.to_string(),
        )]
    })?;
    let certificate = package.certificate.as_ref().ok_or_else(|| {
        vec![SopFault::external(
            SopFaultKind::Signing,
            "compiled package has no recognition certificate",
        )]
    })?;
    let expected_packages = vec![ExpectedPackage {
        package_id: package.package_id.clone(),
        package_digest: certificate.package_digest.clone(),
    }];
    let mut requests = Vec::with_capacity(manifest.queries.len() + 1);
    requests.push(NamedProtocolRequest {
        name: "inspect-fabric".to_owned(),
        request: build_protocol_request(
            manifest,
            &authority_scope,
            &environment_digest,
            &expected_packages,
            "inspect-fabric",
            ProtocolOperation::Inspect {
                inspect: InspectRequest::Fabric,
            },
        )?,
    });
    for template in &manifest.queries {
        let request_id = semantic_id_from_digest("request:sop:", &template.name);
        let query = CantorQueryRequest {
            protocol_version: QUERY_PROTOCOL_VERSION.to_owned(),
            request_id: request_id.clone(),
            term_set: template.terms.clone(),
            subject: template.subject.clone(),
            purpose: manifest.context.purpose.clone(),
            use_case_set: BTreeSet::new(),
            include_boundary_set: BTreeSet::new(),
            exclude_boundary_set: BTreeSet::new(),
            description_need: None,
            requested_detail_kinds: template.requested_detail_kinds.clone(),
            search_modes: [
                SearchMode::Exact,
                SearchMode::Contextual,
                SearchMode::Relational,
            ]
            .into_iter()
            .collect(),
            relation_types: [RelationType::Narrower].into_iter().collect(),
            criteria: BTreeSet::new(),
            source_scopes: [manifest.context.source_scope.clone()]
                .into_iter()
                .collect(),
            perspectives: [manifest.context.perspective.clone()].into_iter().collect(),
            known_units: BTreeSet::new(),
            authority_context: AuthorityContext {
                caller_id: semantic_id_from_digest("caller:sop:", &manifest.context.project),
                allowed_package_scopes: [manifest.context.project.clone()].into_iter().collect(),
                operation: "semantic_read".to_owned(),
                effect_boundary: "read_only".to_owned(),
            },
            budget: QueryBudget {
                maximum_records: 256,
                maximum_paths: 256,
                maximum_depth: 16,
                maximum_bytes: 4 * 1024 * 1024,
                maximum_elapsed_milliseconds: 5_000,
            },
        };
        requests.push(NamedProtocolRequest {
            name: format!("query-{}", template.name),
            request: build_protocol_request(
                manifest,
                &authority_scope,
                &environment_digest,
                &expected_packages,
                &template.name,
                ProtocolOperation::Query {
                    query: Box::new(query),
                },
            )?,
        });
    }

    for named in &requests {
        let response = execute_protocol_request(&environment, named.request.clone());
        verify_protocol_response_against_environment(&environment, &named.request, &response)
            .map_err(|fault| {
                vec![SopFault::external(
                    SopFaultKind::Verification,
                    format!(
                        "{} preflight verification failed: {}: {}",
                        named.name, fault.code, fault.message
                    ),
                )]
            })?;
        if response.exit_class.code() != 0 {
            return Err(vec![SopFault::external(
                SopFaultKind::Verification,
                format!(
                    "{} preflight returned {:?}: {:?}",
                    named.name, response.exit_class, response.faults
                ),
            )]);
        }
    }

    Ok(BuiltSopCorpus {
        package,
        environment,
        requests,
        source_count: lowered.source_count,
        unit_count: lowered.unit_count,
        relation_count: lowered.relation_count,
    })
}

fn validate_manifest(manifest: &SopCorpusManifest) -> Vec<SopFault> {
    let mut faults = Vec::new();
    if manifest.corpus_version != SOP_CORPUS_PROFILE {
        faults.push(SopFault::manifest(format!(
            "unsupported corpus version {:?}; expected {SOP_CORPUS_PROFILE:?}",
            manifest.corpus_version
        )));
    }
    if manifest.source_root.trim().is_empty() {
        faults.push(SopFault::manifest("source_root must be nonempty"));
    }
    for (label, value) in [
        ("project", &manifest.context.project),
        ("namespace", &manifest.context.namespace),
        ("source_scope", &manifest.context.source_scope),
        ("purpose", &manifest.context.purpose),
        ("perspective", &manifest.context.perspective),
        ("world", &manifest.context.world),
        ("compiler_version", &manifest.compiler.compiler_version),
    ] {
        if value.trim().is_empty() {
            faults.push(SopFault::manifest(format!("{label} must be nonempty")));
        }
    }
    if manifest.compiler.authority_signer_id == manifest.compiler.compiler_signer_id {
        faults.push(SopFault::manifest(
            "authority_signer_id and compiler_signer_id must differ",
        ));
    }
    if manifest.not_before_epoch_seconds > manifest.issued_at_epoch_seconds
        || manifest.issued_at_epoch_seconds > manifest.not_after_epoch_seconds
    {
        faults.push(SopFault::manifest(
            "validity requires not_before <= issued_at <= not_after",
        ));
    }
    if manifest.documents.is_empty() || manifest.documents.len() > MAX_DOCUMENTS {
        faults.push(SopFault::manifest(format!(
            "document count must be 1..={MAX_DOCUMENTS}"
        )));
    }
    if manifest.queries.is_empty() || manifest.queries.len() > MAX_QUERY_TEMPLATES {
        faults.push(SopFault::manifest(format!(
            "query template count must be 1..={MAX_QUERY_TEMPLATES}"
        )));
    }
    if manifest.dependency_lock.is_empty()
        || manifest
            .dependency_lock
            .iter()
            .any(|(name, version)| name.trim().is_empty() || version.trim().is_empty())
    {
        faults.push(SopFault::manifest(
            "dependency_lock requires nonempty names and versions",
        ));
    }
    if manifest.proof_ids.is_empty()
        || manifest
            .proof_ids
            .iter()
            .any(|value| value.trim().is_empty())
    {
        faults.push(SopFault::manifest(
            "proof_ids requires at least one nonempty proof identity",
        ));
    }

    let mut document_ids = BTreeSet::new();
    let mut document_paths = BTreeSet::new();
    for document in &manifest.documents {
        if !valid_portable_name(&document.document_id) {
            faults.push(SopFault::manifest(format!(
                "document_id {:?} is not a portable name",
                document.document_id
            )));
        }
        if !document_ids.insert(document.document_id.clone()) {
            faults.push(SopFault::manifest(format!(
                "duplicate document_id {:?}",
                document.document_id
            )));
        }
        if document.path.trim().is_empty() {
            faults.push(SopFault::manifest(format!(
                "document {:?} has an empty path",
                document.document_id
            )));
        }
        if !document_paths.insert(document.path.clone()) {
            faults.push(SopFault::manifest(format!(
                "duplicate document path {:?}",
                document.path
            )));
        }
    }
    let mut query_names = BTreeSet::new();
    for query in &manifest.queries {
        if !valid_portable_name(&query.name) {
            faults.push(SopFault::manifest(format!(
                "query name {:?} is not a portable name",
                query.name
            )));
        }
        if !query_names.insert(query.name.clone()) {
            faults.push(SopFault::manifest(format!(
                "duplicate query name {:?}",
                query.name
            )));
        }
        if query.terms.is_empty() || query.terms.iter().any(|term| term.trim().is_empty()) {
            faults.push(SopFault::manifest(format!(
                "query {:?} requires nonempty terms",
                query.name
            )));
        }
        if query.requested_detail_kinds.is_empty() {
            faults.push(SopFault::manifest(format!(
                "query {:?} requires requested_detail_kinds",
                query.name
            )));
        }
        if query
            .subject
            .as_ref()
            .is_some_and(|subject| subject.trim().is_empty())
        {
            faults.push(SopFault::manifest(format!(
                "query {:?} has a blank subject",
                query.name
            )));
        }
    }
    sort_faults(&mut faults);
    faults
}

struct ParsedDocument {
    source: SourceDocumentInput,
    units: Vec<UnitCompilationInput>,
    relations: Vec<SemanticRelation>,
}

#[derive(Clone, Copy)]
enum SopMarker {
    Subject,
    Member,
    Reference,
    Claim,
    Directive,
    Constraint,
}

impl SopMarker {
    const fn tag(self) -> &'static str {
        match self {
            Self::Subject => "subject",
            Self::Member => "member",
            Self::Reference => "reference",
            Self::Claim => "claim",
            Self::Directive => "directive",
            Self::Constraint => "constraint",
        }
    }

    const fn kind(self) -> UnitKind {
        match self {
            Self::Subject => UnitKind::Term,
            Self::Member => UnitKind::Declaration,
            Self::Reference => UnitKind::Relation,
            Self::Claim => UnitKind::Judgment,
            Self::Directive => UnitKind::Operation,
            Self::Constraint => UnitKind::Contract,
        }
    }
}

struct ParsedNode {
    unit_id: SemanticId,
    node_key: String,
}

fn parse_document(
    manifest: &SopCorpusManifest,
    input: &SopDocumentInput,
) -> Result<ParsedDocument, Vec<SopFault>> {
    let mut faults = Vec::new();
    if input.bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(vec![SopFault::document(
            SopFaultKind::ResourceLimit,
            input,
            None,
            None,
            None,
            format!(
                "document bytes {} exceed the {MAX_DOCUMENT_BYTES}-byte limit",
                input.bytes.len()
            ),
        )]);
    }
    let text = match std::str::from_utf8(&input.bytes) {
        Ok(text) => text,
        Err(error) => {
            return Err(vec![SopFault::document(
                SopFaultKind::InvalidEncoding,
                input,
                None,
                Some(error.valid_up_to()),
                Some(error.valid_up_to().saturating_add(1)),
                "document is not valid UTF-8",
            )]);
        }
    };
    let document_key = canonical_parts(&[
        &normalize(&manifest.context.project),
        &normalize(&manifest.context.namespace),
        &normalize(&input.document_id),
    ]);
    let file_digest = sha256_bytes(document_key.as_bytes()).value;
    let file_id = semantic_id_checked(
        format!("file:sop:{}", &file_digest[..32]),
        input,
        None,
        None,
        None,
        &mut faults,
    );
    let Some(file_id) = file_id else {
        return Err(faults);
    };

    let mut subject_seen = false;
    let mut description_seen = false;
    let mut semantic_seen = false;
    let mut line_count = 0_usize;
    let mut offset = 0_usize;
    let mut units = Vec::new();
    let mut relations = Vec::new();
    let mut stack: Vec<ParsedNode> = Vec::new();
    let mut node_keys = BTreeSet::new();

    while offset < input.bytes.len() {
        line_count = line_count.saturating_add(1);
        if line_count > MAX_LINES_PER_DOCUMENT {
            faults.push(SopFault::document(
                SopFaultKind::ResourceLimit,
                input,
                Some(line_count),
                Some(offset),
                Some(offset),
                format!("line count exceeds the {MAX_LINES_PER_DOCUMENT}-line limit"),
            ));
            break;
        }
        let remaining = &input.bytes[offset..];
        let newline_relative = remaining.iter().position(|byte| *byte == b'\n');
        let next_offset = newline_relative
            .map(|position| offset + position + 1)
            .unwrap_or(input.bytes.len());
        let mut content_end = newline_relative
            .map(|position| offset + position)
            .unwrap_or(input.bytes.len());
        if content_end > offset && input.bytes[content_end - 1] == b'\r' {
            content_end -= 1;
        }
        let raw_line = &text[offset..content_end];
        if raw_line.contains('\r') {
            faults.push(line_fault(
                SopFaultKind::InvalidSyntax,
                input,
                line_count,
                offset,
                content_end,
                raw_line,
                "carriage return is allowed only as part of CRLF",
            ));
            offset = next_offset;
            continue;
        }
        if raw_line.contains('\t') {
            faults.push(line_fault(
                SopFaultKind::InvalidIndentation,
                input,
                line_count,
                offset,
                content_end,
                raw_line,
                "tabs are not allowed in the bounded SOP source profile",
            ));
            offset = next_offset;
            continue;
        }
        let indent = raw_line.bytes().take_while(|byte| *byte == b' ').count();
        let content = &raw_line[indent..];
        if content.is_empty() || content.starts_with('#') {
            offset = next_offset;
            continue;
        }
        if indent % 2 != 0 {
            faults.push(line_fault(
                SopFaultKind::InvalidIndentation,
                input,
                line_count,
                offset,
                content_end,
                raw_line,
                "indentation must use exact two-space levels",
            ));
            offset = next_offset;
            continue;
        }
        let depth = indent / 2;
        if depth > MAX_DEPTH {
            faults.push(line_fault(
                SopFaultKind::ResourceLimit,
                input,
                line_count,
                offset,
                content_end,
                raw_line,
                format!("indentation depth exceeds the {MAX_DEPTH}-level limit"),
            ));
            offset = next_offset;
            continue;
        }
        if let Some(value) = content.strip_prefix("Subject:") {
            let body = value.trim();
            if indent != 0 || body.is_empty() || subject_seen || semantic_seen {
                faults.push(line_fault(
                    SopFaultKind::InvalidSyntax,
                    input,
                    line_count,
                    offset,
                    content_end,
                    raw_line,
                    "Subject metadata must occur once, unindented, before semantic lines, with nonempty text",
                ));
            } else {
                subject_seen = true;
            }
            offset = next_offset;
            continue;
        }
        if let Some(value) = content.strip_prefix("Description:") {
            let body = value.trim();
            if indent != 0 || body.is_empty() || !subject_seen || description_seen || semantic_seen
            {
                faults.push(line_fault(
                    SopFaultKind::InvalidSyntax,
                    input,
                    line_count,
                    offset,
                    content_end,
                    raw_line,
                    "Description metadata may occur once, unindented, after Subject and before semantic lines",
                ));
            } else {
                description_seen = true;
            }
            offset = next_offset;
            continue;
        }
        if !subject_seen {
            faults.push(line_fault(
                SopFaultKind::InvalidSyntax,
                input,
                line_count,
                offset,
                content_end,
                raw_line,
                "semantic content requires preceding Subject metadata",
            ));
            offset = next_offset;
            continue;
        }
        semantic_seen = true;
        let (marker, name, body) = match parse_semantic_line(content) {
            Ok(parsed) => parsed,
            Err(message) => {
                faults.push(line_fault(
                    SopFaultKind::InvalidSyntax,
                    input,
                    line_count,
                    offset,
                    content_end,
                    raw_line,
                    message,
                ));
                offset = next_offset;
                continue;
            }
        };
        if name
            .as_ref()
            .is_some_and(|value| value.len() > MAX_NAME_BYTES)
        {
            faults.push(line_fault(
                SopFaultKind::ResourceLimit,
                input,
                line_count,
                offset,
                content_end,
                raw_line,
                format!("name exceeds the {MAX_NAME_BYTES}-byte limit"),
            ));
            offset = next_offset;
            continue;
        }
        if body.len() > MAX_BODY_BYTES {
            faults.push(line_fault(
                SopFaultKind::ResourceLimit,
                input,
                line_count,
                offset,
                content_end,
                raw_line,
                format!("body exceeds the {MAX_BODY_BYTES}-byte limit"),
            ));
            offset = next_offset;
            continue;
        }
        if depth > stack.len() {
            faults.push(line_fault(
                SopFaultKind::InvalidIndentation,
                input,
                line_count,
                offset,
                content_end,
                raw_line,
                "indented semantic line has no parent exactly one level shallower",
            ));
            offset = next_offset;
            continue;
        }
        stack.truncate(depth);
        let parent = stack.last();
        let parent_key = parent.map_or("", |value| value.node_key.as_str());
        let normalized_name = name.as_deref().map(normalize).unwrap_or_default();
        let normalized_body = normalize(&body);
        let body_digest = sha256_bytes(normalized_body.as_bytes()).value;
        let node_key = canonical_parts(&[
            &document_key,
            marker.tag(),
            parent_key,
            &normalized_name,
            &body_digest,
        ]);
        if !node_keys.insert(node_key.clone()) {
            faults.push(line_fault(
                SopFaultKind::DuplicateIdentity,
                input,
                line_count,
                offset,
                content_end,
                raw_line,
                "identical marker, parent, name, and body derive a duplicate semantic key",
            ));
            offset = next_offset;
            continue;
        }
        let unit_id = semantic_id_from_digest("unit:sop:", &node_key);
        let clause_id = semantic_id_from_digest(
            "clause:sop:",
            &canonical_parts(&[unit_id.as_str(), SOP_SOURCE_PROFILE]),
        );
        let expression = name.clone().unwrap_or_else(|| body.clone());
        let context = SemanticContext {
            scope: manifest.context.source_scope.clone(),
            purpose: manifest.context.purpose.clone(),
            assumptions: Vec::new(),
            perspective: manifest.context.perspective.clone(),
            world: manifest.context.world.clone(),
        };
        units.push(UnitCompilationInput {
            unit: SemanticUnit {
                unit_id: unit_id.clone(),
                kind: marker.kind(),
                expression,
                aliases: BTreeSet::new(),
                meaning: body,
                context,
                source_set: vec![
                    format!("document:{}", input.document_id),
                    SOP_SOURCE_PROFILE.to_owned(),
                ],
                status: UnitStatus::Asserted,
            },
            file_id: file_id.clone(),
            clause_id,
            byte_start: offset + indent,
            byte_end: content_end,
        });
        if let Some(parent) = parent {
            let relation_key =
                canonical_parts(&["Narrower", parent.unit_id.as_str(), unit_id.as_str()]);
            relations.push(SemanticRelation {
                relation_id: semantic_id_from_digest("relation:sop:", &relation_key),
                source: parent.unit_id.clone(),
                relation_type: RelationType::Narrower,
                target: unit_id.clone(),
                source_ref: format!("document:{}", input.document_id),
            });
        }
        stack.push(ParsedNode { unit_id, node_key });
        offset = next_offset;
    }
    if !subject_seen {
        faults.push(SopFault::document(
            SopFaultKind::InvalidSyntax,
            input,
            None,
            None,
            None,
            "document requires exactly one Subject metadata line",
        ));
    }
    if units.is_empty() {
        faults.push(SopFault::document(
            SopFaultKind::InvalidSyntax,
            input,
            None,
            None,
            None,
            "document requires at least one lowered semantic line",
        ));
    }
    if !faults.is_empty() {
        sort_faults(&mut faults);
        return Err(faults);
    }
    Ok(ParsedDocument {
        source: SourceDocumentInput {
            file_id,
            path: input.path.clone(),
            bytes: input.bytes.clone(),
        },
        units,
        relations,
    })
}

fn parse_semantic_line(content: &str) -> Result<(SopMarker, Option<String>, String), &'static str> {
    let Some(marker_byte) = content.as_bytes().first().copied() else {
        return Err("semantic line is empty");
    };
    let marker = match marker_byte {
        b'&' => SopMarker::Subject,
        b'+' => SopMarker::Member,
        b'@' => SopMarker::Reference,
        b'!' => SopMarker::Claim,
        b'=' => SopMarker::Directive,
        b'-' => SopMarker::Constraint,
        _ => return Err("unsupported nonblank line marker"),
    };
    if content.as_bytes().get(1).is_none_or(|byte| *byte != b' ') {
        return Err("marker must be followed by exactly one required separator space");
    }
    match marker {
        SopMarker::Subject | SopMarker::Member | SopMarker::Reference | SopMarker::Claim => {
            let remainder = &content[2..];
            if !remainder.starts_with('[') {
                return Err("named marker requires an opening bracket");
            }
            let Some(close) = remainder.find(']') else {
                return Err("named marker requires a closing bracket");
            };
            let name = remainder[1..close].trim();
            if name.is_empty() {
                return Err("bracketed name must be nonempty");
            }
            if name.contains('[') || name.contains(']') || name.chars().any(char::is_control) {
                return Err("bracketed name contains an unsupported character");
            }
            let after = &remainder[close + 1..];
            if !after.starts_with(' ') || after.as_bytes().get(1) == Some(&b' ') {
                return Err("closing bracket must be followed by exactly one separator space");
            }
            let body = after[1..].trim();
            if body.is_empty() {
                return Err("semantic body must be nonempty");
            }
            if body.chars().any(char::is_control) {
                return Err("semantic body contains an unsupported control character");
            }
            Ok((marker, Some(name.to_owned()), body.to_owned()))
        }
        SopMarker::Directive | SopMarker::Constraint => {
            if content.as_bytes().get(2) == Some(&b' ') {
                return Err("marker must be followed by exactly one separator space");
            }
            let body = content[2..].trim();
            if body.is_empty() {
                return Err("directive or constraint body must be nonempty");
            }
            if body.chars().any(char::is_control) {
                return Err("semantic body contains an unsupported control character");
            }
            Ok((marker, None, body.to_owned()))
        }
    }
}

fn build_protocol_request(
    manifest: &SopCorpusManifest,
    authority_scope: &AuthorityScope,
    environment_digest: &crate::ContentDigest,
    expected_packages: &[ExpectedPackage],
    name: &str,
    operation: ProtocolOperation,
) -> Result<ProtocolRequest, Vec<SopFault>> {
    let request_id = semantic_id_from_digest("request:sop:", name);
    if let ProtocolOperation::Query { query } = &operation
        && query.request_id != request_id
    {
        return Err(vec![SopFault::external(
            SopFaultKind::InvalidManifest,
            format!("query {name:?} has inconsistent inner request identity"),
        )]);
    }
    Ok(ProtocolRequest {
        protocol_version: PROTOCOL_VERSION.to_owned(),
        request_id,
        caller_context: ProtocolCallerContext {
            caller_id: semantic_id_from_digest("caller:sop:", &manifest.context.project),
            purpose: manifest.context.purpose.clone(),
            job_id: Some(semantic_id_from_digest("job:sop:", name)),
            effect_boundary: "read_only".to_owned(),
        },
        expected_environment_digest: environment_digest.clone(),
        expected_packages: expected_packages.to_vec(),
        requested_scope: authority_scope.clone(),
        request: operation,
    })
}

fn semantic_id_from_digest(prefix: &str, value: &str) -> SemanticId {
    let digest = sha256_bytes(value.as_bytes()).value;
    SemanticId::new(format!("{prefix}{digest}"))
        .unwrap_or_else(|_| unreachable!("digest-derived SemanticId is valid"))
}

fn semantic_id_checked(
    value: String,
    input: &SopDocumentInput,
    line: Option<usize>,
    byte_start: Option<usize>,
    byte_end: Option<usize>,
    faults: &mut Vec<SopFault>,
) -> Option<SemanticId> {
    match SemanticId::new(value) {
        Ok(value) => Some(value),
        Err(error) => {
            faults.push(SopFault::document(
                SopFaultKind::DuplicateIdentity,
                input,
                line,
                byte_start,
                byte_end,
                error.to_string(),
            ));
            None
        }
    }
}

fn canonical_parts(parts: &[&str]) -> String {
    let mut value = String::new();
    for part in parts {
        value.push_str(&part.len().to_string());
        value.push(':');
        value.push_str(part);
        value.push(';');
    }
    value
}

fn normalize(value: &str) -> String {
    value
        .trim()
        .chars()
        .map(|character| character.to_ascii_lowercase())
        .collect()
}

fn valid_portable_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn line_fault(
    kind: SopFaultKind,
    input: &SopDocumentInput,
    line: usize,
    byte_start: usize,
    byte_end: usize,
    raw_line: &str,
    message: impl Into<String>,
) -> SopFault {
    let preview = raw_line.chars().take(120).collect::<String>();
    let suffix = if raw_line.chars().count() > 120 {
        "..."
    } else {
        ""
    };
    SopFault::document(
        kind,
        input,
        Some(line),
        Some(byte_start),
        Some(byte_end),
        format!("{}; line preview={preview:?}{suffix}", message.into()),
    )
}

fn sort_faults(faults: &mut [SopFault]) {
    faults.sort_by(|left, right| {
        left.document_id
            .cmp(&right.document_id)
            .then_with(|| left.byte_start.cmp(&right.byte_start))
            .then_with(|| left.kind.cmp(&right.kind))
            .then_with(|| left.message.cmp(&right.message))
    });
}
