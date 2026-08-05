//! Pure materialization of direction-aware schema universes into canonical
//! documents and one exact-replay golden bundle.
//!
//! The public functions return in-memory values and bytes only. They do not
//! parse untrusted JSON, validate instances, classify compatibility, or access
//! the filesystem.

use std::collections::{BTreeMap, BTreeSet};

use cantor_core::{ContentDigest, sha256_bytes};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    ContractDefinitionUniverse, MACHINE_SCHEMA_GENERATOR_ID, MACHINE_SCHEMA_PROFILE,
    MachineSchemaGenerationContext, MachineSchemaRootDraft, MachineSchemaRootKind,
    SchemaContractDirection, SchemaGenerationLimits, SchemaResourceAccount, canonical_json_bytes,
    generate_public_procedure_schema_universes,
};

pub const MACHINE_SCHEMA_DIALECT: &str = "https://json-schema.org/draft/2020-12/schema";
pub const MACHINE_SCHEMA_BUNDLE_PROFILE: &str = "cantor-schema-golden-bundle/0.1";
const DOCUMENT_FINGERPRINT_PROFILE: &str = "cantor-schema-document/0.1";
const PAYLOAD_DIGEST_PROFILE: &str = "cantor-schema-bundle-payload/0.1";
const BASELINE_FINGERPRINT_PROFILE: &str = "cantor-schema-exact-baseline/0.1";
const MAX_DOCUMENT_FAULT_CHARS: usize = 1024;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalMachineSchemaDocument {
    pub direction: SchemaContractDirection,
    pub root_kind: MachineSchemaRootKind,
    pub type_name: String,
    pub schema_id: String,
    pub schema: Value,
    pub root_fingerprint: ContentDigest,
    pub universe_fingerprint: ContentDigest,
    pub resources: SchemaResourceAccount,
    pub residual_ids: BTreeSet<String>,
    pub canonical_byte_length: u64,
    pub document_digest: ContentDigest,
    pub document_fingerprint: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaDirectionInventory {
    pub direction: SchemaContractDirection,
    pub universe_fingerprint: ContentDigest,
    pub resources: SchemaResourceAccount,
    pub definition_contract_fingerprints: BTreeMap<String, ContentDigest>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineSchemaBundlePayload {
    pub profile: String,
    pub dialect: String,
    pub generator_id: String,
    pub supplied_source_revision: String,
    pub limits: SchemaGenerationLimits,
    pub direction_inventories: BTreeMap<SchemaContractDirection, SchemaDirectionInventory>,
    pub documents: BTreeMap<MachineSchemaRootKind, CanonicalMachineSchemaDocument>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineSchemaGoldenBundle {
    pub payload: MachineSchemaBundlePayload,
    pub payload_digest: ContentDigest,
    pub exact_baseline_fingerprint: ContentDigest,
    pub artifact_paths: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExactSchemaBundleReplay {
    Identical,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemaDocumentFormationFaultKind {
    InvalidUniversePair,
    InvalidRootSet,
    InvalidDirection,
    InvalidRoot,
    ReservedKeyword,
    InvalidDialect,
    InvalidSchemaId,
    InvalidClosure,
    InvalidReference,
    LimitExceeded,
    DigestMismatch,
    BaselineMismatch,
    ArtifactMismatch,
    Serialization,
    InternalInvariant,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaDocumentFormationFault {
    pub kind: SchemaDocumentFormationFaultKind,
    pub path: Vec<String>,
    pub limit: Option<u64>,
    pub observed: Option<u64>,
    pub expected_digest: Option<Box<ContentDigest>>,
    pub observed_digest: Option<Box<ContentDigest>>,
    pub message: String,
}

/// Generates the I02B universes and atomically materializes the canonical
/// public-procedure bundle in memory.
pub fn generate_public_procedure_schema_bundle(
    context: &MachineSchemaGenerationContext,
) -> Result<MachineSchemaGoldenBundle, SchemaDocumentFormationFault> {
    let universes = generate_public_procedure_schema_universes(context)
        .map_err(|error| document_fault_from_generation("universes", error))?;
    materialize_public_procedure_schema_bundle(&universes)
}

/// Materializes exactly one root using every and only definition in its
/// transitive same-direction closure.
pub fn materialize_canonical_schema_document(
    universe: &ContractDefinitionUniverse,
    root_kind: MachineSchemaRootKind,
) -> Result<CanonicalMachineSchemaDocument, SchemaDocumentFormationFault> {
    let root = universe.roots.get(&root_kind).ok_or_else(|| {
        fault(
            SchemaDocumentFormationFaultKind::InvalidRootSet,
            [root_kind.token()],
            "root kind is absent from its direction universe",
        )
    })?;
    validate_root_identity(universe, root_kind, root)?;
    let mut object = root.normalized_root.as_object().cloned().ok_or_else(|| {
        fault(
            SchemaDocumentFormationFaultKind::InvalidRoot,
            [root_kind.token()],
            "root draft must be an object",
        )
    })?;
    for reserved in ["$id", "$defs"] {
        if object.contains_key(reserved) {
            return Err(fault(
                SchemaDocumentFormationFaultKind::ReservedKeyword,
                [root_kind.token(), reserved],
                "root draft already contains a materialization-reserved keyword",
            ));
        }
    }
    if let Some(dialect) = object.get("$schema")
        && dialect.as_str() != Some(MACHINE_SCHEMA_DIALECT)
    {
        return Err(fault(
            SchemaDocumentFormationFaultKind::InvalidDialect,
            [root_kind.token(), "$schema"],
            "root draft declares an unexpected JSON Schema dialect",
        ));
    }
    object.insert(
        "$schema".to_owned(),
        Value::String(MACHINE_SCHEMA_DIALECT.to_owned()),
    );
    object.insert("$id".to_owned(), Value::String(root.schema_id.clone()));
    let mut selected = serde_json::Map::new();
    for name in &root.definition_closure {
        selected.insert(
            name.clone(),
            universe.definitions.get(name).cloned().ok_or_else(|| {
                fault(
                    SchemaDocumentFormationFaultKind::InvalidClosure,
                    [root_kind.token(), "$defs", name],
                    "root closure names a definition absent from its universe",
                )
            })?,
        );
    }
    object.insert("$defs".to_owned(), Value::Object(selected));
    let schema = Value::Object(object);
    validate_materialized_closure(root_kind, &schema, &root.definition_closure)?;
    let bytes = canonical_bytes(&schema, root_kind.token())?;
    enforce_byte_limit(
        root_kind.token(),
        bytes.len() as u64,
        universe.limits.maximum_canonical_document_bytes,
    )?;
    let document_digest = sha256_bytes(&bytes);
    let document_fingerprint = document_fingerprint(
        universe.direction,
        root_kind,
        &root.type_name,
        &root.schema_id,
        &root.root_fingerprint,
        &universe.universe_fingerprint,
        &document_digest,
    );
    let mut resources = root.resources.clone();
    resources.canonical_bytes = bytes.len() as u64;
    Ok(CanonicalMachineSchemaDocument {
        direction: universe.direction,
        root_kind,
        type_name: root.type_name.clone(),
        schema_id: root.schema_id.clone(),
        schema,
        root_fingerprint: root.root_fingerprint.clone(),
        universe_fingerprint: universe.universe_fingerprint.clone(),
        resources,
        residual_ids: root.residual_ids.clone(),
        canonical_byte_length: bytes.len() as u64,
        document_digest,
        document_fingerprint,
    })
}

/// Materializes both direction universes as one atomic, content-addressed
/// bundle. The payload is hashed before digest fields exist.
pub fn materialize_public_procedure_schema_bundle(
    universes: &BTreeMap<SchemaContractDirection, ContractDefinitionUniverse>,
) -> Result<MachineSchemaGoldenBundle, SchemaDocumentFormationFault> {
    let (input, output) = validate_universe_pair(universes)?;
    let assignments = [
        (
            SchemaContractDirection::InputDeserialize,
            MachineSchemaRootKind::PrepareInput,
        ),
        (
            SchemaContractDirection::InputDeserialize,
            MachineSchemaRootKind::RunInput,
        ),
        (
            SchemaContractDirection::InputDeserialize,
            MachineSchemaRootKind::VerifyInput,
        ),
        (
            SchemaContractDirection::OutputSerialize,
            MachineSchemaRootKind::BaseResponse,
        ),
        (
            SchemaContractDirection::OutputSerialize,
            MachineSchemaRootKind::PreparationResponse,
        ),
    ];
    validate_root_sets(input, output)?;
    let mut documents = BTreeMap::new();
    for (direction, root_kind) in assignments {
        let universe = universes.get(&direction).ok_or_else(|| {
            fault(
                SchemaDocumentFormationFaultKind::InvalidUniversePair,
                [direction.token()],
                "required direction universe is absent",
            )
        })?;
        documents.insert(
            root_kind,
            materialize_canonical_schema_document(universe, root_kind)?,
        );
    }
    let direction_inventories = universes
        .iter()
        .map(|(direction, universe)| {
            let fingerprints = universe
                .definition_accounts
                .iter()
                .map(|(name, account)| (name.clone(), account.contract_fingerprint.clone()))
                .collect();
            (
                *direction,
                SchemaDirectionInventory {
                    direction: *direction,
                    universe_fingerprint: universe.universe_fingerprint.clone(),
                    resources: universe.resources.clone(),
                    definition_contract_fingerprints: fingerprints,
                },
            )
        })
        .collect();
    let payload = MachineSchemaBundlePayload {
        profile: MACHINE_SCHEMA_BUNDLE_PROFILE.to_owned(),
        dialect: MACHINE_SCHEMA_DIALECT.to_owned(),
        generator_id: input.generator_id.clone(),
        supplied_source_revision: input.supplied_source_revision.clone(),
        limits: input.limits.clone(),
        direction_inventories,
        documents,
    };
    let payload_bytes = canonical_serialized_bytes(&payload, "payload")?;
    enforce_byte_limit(
        "payload",
        payload_bytes.len() as u64,
        input.limits.maximum_canonical_bundle_bytes,
    )?;
    let payload_digest = domain_digest(PAYLOAD_DIGEST_PROFILE, [payload_bytes.as_slice()]);
    let baseline_parts = std::iter::once(payload_digest.value.as_bytes())
        .chain(payload.documents.iter().flat_map(|(kind, document)| {
            [
                kind.token().as_bytes(),
                document.document_fingerprint.value.as_bytes(),
                document.document_digest.value.as_bytes(),
            ]
        }))
        .collect::<Vec<_>>();
    let exact_baseline_fingerprint = domain_digest(BASELINE_FINGERPRINT_PROFILE, baseline_parts);
    let bundle = MachineSchemaGoldenBundle {
        payload,
        payload_digest,
        exact_baseline_fingerprint,
        artifact_paths: fixed_artifact_paths(),
    };
    let envelope = canonical_serialized_bytes(&bundle, "bundle")?;
    enforce_byte_limit(
        "bundle",
        envelope.len() as u64,
        input.limits.maximum_canonical_bundle_bytes,
    )?;
    Ok(bundle)
}

/// Projects the bundle to the six fixed canonical artifact byte sequences.
/// This function performs no filesystem access.
pub fn canonical_machine_schema_artifacts(
    bundle: &MachineSchemaGoldenBundle,
) -> Result<BTreeMap<String, Vec<u8>>, SchemaDocumentFormationFault> {
    validate_bundle_integrity(bundle)?;
    let mut artifacts = BTreeMap::new();
    for (kind, document) in &bundle.payload.documents {
        let key = kind.token();
        let path = bundle.artifact_paths.get(key).ok_or_else(|| {
            fault(
                SchemaDocumentFormationFaultKind::ArtifactMismatch,
                [key],
                "document artifact path is absent",
            )
        })?;
        artifacts.insert(path.clone(), canonical_bytes(&document.schema, key)?);
    }
    let bundle_path = bundle.artifact_paths.get("bundle").ok_or_else(|| {
        fault(
            SchemaDocumentFormationFaultKind::ArtifactMismatch,
            ["bundle"],
            "bundle artifact path is absent",
        )
    })?;
    artifacts.insert(
        bundle_path.clone(),
        canonical_serialized_bytes(bundle, "bundle")?,
    );
    if artifacts.len() != 6 {
        return Err(fault(
            SchemaDocumentFormationFaultKind::ArtifactMismatch,
            ["artifacts"],
            "artifact projection must contain exactly six entries",
        ));
    }
    Ok(artifacts)
}

/// Verifies only byte-exact baseline replay. It deliberately does not classify
/// a changed bundle as compatible or breaking.
pub fn verify_exact_schema_bundle_replay(
    expected_baseline: &ContentDigest,
    candidate: &MachineSchemaGoldenBundle,
) -> Result<ExactSchemaBundleReplay, SchemaDocumentFormationFault> {
    validate_bundle_integrity(candidate)?;
    if &candidate.exact_baseline_fingerprint != expected_baseline {
        let mut result = fault(
            SchemaDocumentFormationFaultKind::BaselineMismatch,
            ["exact_baseline_fingerprint"],
            "candidate is not byte-identical to the expected baseline",
        );
        result.expected_digest = Some(Box::new(expected_baseline.clone()));
        result.observed_digest = Some(Box::new(candidate.exact_baseline_fingerprint.clone()));
        return Err(result);
    }
    Ok(ExactSchemaBundleReplay::Identical)
}

fn validate_universe_pair(
    universes: &BTreeMap<SchemaContractDirection, ContractDefinitionUniverse>,
) -> Result<(&ContractDefinitionUniverse, &ContractDefinitionUniverse), SchemaDocumentFormationFault>
{
    if universes.len() != 2 {
        return Err(fault(
            SchemaDocumentFormationFaultKind::InvalidUniversePair,
            ["universes"],
            "bundle requires exactly two direction universes",
        ));
    }
    let input = universes
        .get(&SchemaContractDirection::InputDeserialize)
        .ok_or_else(|| {
            fault(
                SchemaDocumentFormationFaultKind::InvalidUniversePair,
                ["input_deserialize"],
                "input universe is absent",
            )
        })?;
    let output = universes
        .get(&SchemaContractDirection::OutputSerialize)
        .ok_or_else(|| {
            fault(
                SchemaDocumentFormationFaultKind::InvalidUniversePair,
                ["output_serialize"],
                "output universe is absent",
            )
        })?;
    if input.direction != SchemaContractDirection::InputDeserialize
        || output.direction != SchemaContractDirection::OutputSerialize
    {
        return Err(fault(
            SchemaDocumentFormationFaultKind::InvalidDirection,
            ["universes"],
            "universe map key and embedded direction disagree",
        ));
    }
    if input.profile != MACHINE_SCHEMA_PROFILE
        || output.profile != MACHINE_SCHEMA_PROFILE
        || input.generator_id != MACHINE_SCHEMA_GENERATOR_ID
        || output.generator_id != MACHINE_SCHEMA_GENERATOR_ID
        || input.profile != output.profile
        || input.generator_id != output.generator_id
        || input.supplied_source_revision != output.supplied_source_revision
        || input.limits != output.limits
    {
        return Err(fault(
            SchemaDocumentFormationFaultKind::InvalidUniversePair,
            ["metadata"],
            "direction universes do not share exact generation metadata",
        ));
    }
    Ok((input, output))
}

fn validate_root_sets(
    input: &ContractDefinitionUniverse,
    output: &ContractDefinitionUniverse,
) -> Result<(), SchemaDocumentFormationFault> {
    let expected_input = BTreeSet::from([
        MachineSchemaRootKind::PrepareInput,
        MachineSchemaRootKind::RunInput,
        MachineSchemaRootKind::VerifyInput,
    ]);
    let expected_output = BTreeSet::from([
        MachineSchemaRootKind::BaseResponse,
        MachineSchemaRootKind::PreparationResponse,
    ]);
    if input.roots.keys().copied().collect::<BTreeSet<_>>() != expected_input
        || output.roots.keys().copied().collect::<BTreeSet<_>>() != expected_output
    {
        return Err(fault(
            SchemaDocumentFormationFaultKind::InvalidRootSet,
            ["roots"],
            "direction universes do not contain the exact five-root assignment",
        ));
    }
    Ok(())
}

fn validate_root_identity(
    universe: &ContractDefinitionUniverse,
    root_kind: MachineSchemaRootKind,
    root: &MachineSchemaRootDraft,
) -> Result<(), SchemaDocumentFormationFault> {
    if root.direction != universe.direction || root.root_kind != root_kind {
        return Err(fault(
            SchemaDocumentFormationFaultKind::InvalidDirection,
            [root_kind.token()],
            "root identity disagrees with its universe or map key",
        ));
    }
    let expected_id = format!(
        "urn:cantor:schema:public-procedure:0.1:{}:{}",
        universe.direction.token(),
        root_kind.token()
    );
    if root.schema_id != expected_id {
        return Err(fault(
            SchemaDocumentFormationFaultKind::InvalidSchemaId,
            [root_kind.token(), "schema_id"],
            "root schema id is not the stable direction-qualified identity",
        ));
    }
    Ok(())
}

fn validate_materialized_closure(
    root_kind: MachineSchemaRootKind,
    schema: &Value,
    expected: &BTreeSet<String>,
) -> Result<(), SchemaDocumentFormationFault> {
    let object = schema.as_object().ok_or_else(|| {
        fault(
            SchemaDocumentFormationFaultKind::InvalidRoot,
            [root_kind.token()],
            "materialized schema is not an object",
        )
    })?;
    let definitions = object
        .get("$defs")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            fault(
                SchemaDocumentFormationFaultKind::InvalidClosure,
                [root_kind.token(), "$defs"],
                "materialized definitions are absent",
            )
        })?;
    let mut root_without_defs = object.clone();
    root_without_defs.remove("$defs");
    let mut pending = collect_local_targets(&Value::Object(root_without_defs), root_kind.token())?;
    let mut visited = BTreeSet::new();
    while let Some(name) = pending.pop_first() {
        if !visited.insert(name.clone()) {
            continue;
        }
        let definition = definitions.get(&name).ok_or_else(|| {
            fault(
                SchemaDocumentFormationFaultKind::InvalidReference,
                [root_kind.token(), "$defs", name.as_str()],
                "local reference target is absent",
            )
        })?;
        pending.extend(collect_local_targets(definition, name.as_str())?);
    }
    let actual = definitions.keys().cloned().collect::<BTreeSet<_>>();
    if visited != actual || actual != *expected {
        return Err(fault(
            SchemaDocumentFormationFaultKind::InvalidClosure,
            [root_kind.token(), "$defs"],
            "materialized closure is incomplete, excessive, or unreachable",
        ));
    }
    Ok(())
}

fn collect_local_targets(
    value: &Value,
    subject: &str,
) -> Result<BTreeSet<String>, SchemaDocumentFormationFault> {
    let mut targets = BTreeSet::new();
    collect_local_targets_at(value, subject, &mut targets)?;
    Ok(targets)
}

fn collect_local_targets_at(
    value: &Value,
    subject: &str,
    targets: &mut BTreeSet<String>,
) -> Result<(), SchemaDocumentFormationFault> {
    match value {
        Value::Array(values) => {
            for child in values {
                collect_local_targets_at(child, subject, targets)?;
            }
        }
        Value::Object(object) => {
            if let Some(reference) = object.get("$ref") {
                let text = reference.as_str().ok_or_else(|| {
                    fault(
                        SchemaDocumentFormationFaultKind::InvalidReference,
                        [subject, "$ref"],
                        "$ref must be a string",
                    )
                })?;
                let name = text
                    .strip_prefix("#/$defs/")
                    .filter(|name| !name.is_empty())
                    .ok_or_else(|| {
                        fault(
                            SchemaDocumentFormationFaultKind::InvalidReference,
                            [subject, "$ref"],
                            "only nonempty local $defs references are allowed",
                        )
                    })?;
                targets.insert(name.to_owned());
            }
            for child in object.values() {
                collect_local_targets_at(child, subject, targets)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_bundle_integrity(
    bundle: &MachineSchemaGoldenBundle,
) -> Result<(), SchemaDocumentFormationFault> {
    if bundle.artifact_paths != fixed_artifact_paths() {
        return Err(fault(
            SchemaDocumentFormationFaultKind::ArtifactMismatch,
            ["artifact_paths"],
            "bundle artifact table differs from the fixed six-entry table",
        ));
    }
    if bundle.payload.profile != MACHINE_SCHEMA_BUNDLE_PROFILE
        || bundle.payload.dialect != MACHINE_SCHEMA_DIALECT
        || bundle.payload.generator_id != MACHINE_SCHEMA_GENERATOR_ID
    {
        return Err(fault(
            SchemaDocumentFormationFaultKind::InvalidUniversePair,
            ["payload", "metadata"],
            "bundle payload declares unexpected profile, dialect, or generator",
        ));
    }
    let expected_directions = BTreeSet::from([
        SchemaContractDirection::InputDeserialize,
        SchemaContractDirection::OutputSerialize,
    ]);
    if bundle
        .payload
        .direction_inventories
        .keys()
        .copied()
        .collect::<BTreeSet<_>>()
        != expected_directions
        || bundle
            .payload
            .direction_inventories
            .iter()
            .any(|(direction, inventory)| *direction != inventory.direction)
    {
        return Err(fault(
            SchemaDocumentFormationFaultKind::InvalidUniversePair,
            ["payload", "direction_inventories"],
            "bundle must contain exactly two self-consistent direction inventories",
        ));
    }
    let expected_roots = BTreeSet::from([
        MachineSchemaRootKind::PrepareInput,
        MachineSchemaRootKind::RunInput,
        MachineSchemaRootKind::VerifyInput,
        MachineSchemaRootKind::BaseResponse,
        MachineSchemaRootKind::PreparationResponse,
    ]);
    if bundle
        .payload
        .documents
        .keys()
        .copied()
        .collect::<BTreeSet<_>>()
        != expected_roots
    {
        return Err(fault(
            SchemaDocumentFormationFaultKind::InvalidRootSet,
            ["payload", "documents"],
            "bundle must contain exactly the five canonical root documents",
        ));
    }
    let payload_bytes = canonical_serialized_bytes(&bundle.payload, "payload")?;
    enforce_byte_limit(
        "payload",
        payload_bytes.len() as u64,
        bundle.payload.limits.maximum_canonical_bundle_bytes,
    )?;
    let observed_payload = domain_digest(PAYLOAD_DIGEST_PROFILE, [payload_bytes.as_slice()]);
    if observed_payload != bundle.payload_digest {
        return Err(digest_fault(
            SchemaDocumentFormationFaultKind::DigestMismatch,
            "payload_digest",
            &bundle.payload_digest,
            &observed_payload,
        ));
    }
    for (kind, document) in &bundle.payload.documents {
        let expected_direction = match kind {
            MachineSchemaRootKind::PrepareInput
            | MachineSchemaRootKind::RunInput
            | MachineSchemaRootKind::VerifyInput => SchemaContractDirection::InputDeserialize,
            MachineSchemaRootKind::BaseResponse | MachineSchemaRootKind::PreparationResponse => {
                SchemaContractDirection::OutputSerialize
            }
        };
        if document.root_kind != *kind || document.direction != expected_direction {
            return Err(fault(
                SchemaDocumentFormationFaultKind::InvalidDirection,
                ["payload", "documents", kind.token()],
                "document key, root kind, and direction disagree",
            ));
        }
        let expected_id = format!(
            "urn:cantor:schema:public-procedure:0.1:{}:{}",
            expected_direction.token(),
            kind.token()
        );
        let object = document.schema.as_object().ok_or_else(|| {
            fault(
                SchemaDocumentFormationFaultKind::InvalidRoot,
                ["payload", "documents", kind.token()],
                "canonical document schema must be an object",
            )
        })?;
        if document.schema_id != expected_id
            || object.get("$id").and_then(Value::as_str) != Some(expected_id.as_str())
            || object.get("$schema").and_then(Value::as_str) != Some(MACHINE_SCHEMA_DIALECT)
        {
            return Err(fault(
                SchemaDocumentFormationFaultKind::InvalidSchemaId,
                ["payload", "documents", kind.token()],
                "document identity, $id, or $schema is inconsistent",
            ));
        }
        let definition_names = object
            .get("$defs")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                fault(
                    SchemaDocumentFormationFaultKind::InvalidClosure,
                    ["payload", "documents", kind.token(), "$defs"],
                    "canonical document definitions are absent",
                )
            })?
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        validate_materialized_closure(*kind, &document.schema, &definition_names)?;
        let bytes = canonical_bytes(&document.schema, kind.token())?;
        let observed = sha256_bytes(&bytes);
        enforce_byte_limit(
            kind.token(),
            bytes.len() as u64,
            bundle.payload.limits.maximum_canonical_document_bytes,
        )?;
        if observed != document.document_digest
            || bytes.len() as u64 != document.canonical_byte_length
            || document.resources.canonical_bytes != document.canonical_byte_length
        {
            return Err(digest_fault(
                SchemaDocumentFormationFaultKind::DigestMismatch,
                kind.token(),
                &document.document_digest,
                &observed,
            ));
        }
        let inventory = &bundle.payload.direction_inventories[&expected_direction];
        if document.universe_fingerprint != inventory.universe_fingerprint {
            return Err(fault(
                SchemaDocumentFormationFaultKind::InvalidUniversePair,
                ["payload", "documents", kind.token(), "universe_fingerprint"],
                "document does not bind its direction inventory",
            ));
        }
        let observed_fingerprint = document_fingerprint(
            document.direction,
            *kind,
            &document.type_name,
            &document.schema_id,
            &document.root_fingerprint,
            &document.universe_fingerprint,
            &document.document_digest,
        );
        if observed_fingerprint != document.document_fingerprint {
            return Err(digest_fault(
                SchemaDocumentFormationFaultKind::DigestMismatch,
                "document_fingerprint",
                &document.document_fingerprint,
                &observed_fingerprint,
            ));
        }
    }
    let parts = std::iter::once(bundle.payload_digest.value.as_bytes())
        .chain(
            bundle
                .payload
                .documents
                .iter()
                .flat_map(|(kind, document)| {
                    [
                        kind.token().as_bytes(),
                        document.document_fingerprint.value.as_bytes(),
                        document.document_digest.value.as_bytes(),
                    ]
                }),
        )
        .collect::<Vec<_>>();
    let observed_baseline = domain_digest(BASELINE_FINGERPRINT_PROFILE, parts);
    if observed_baseline != bundle.exact_baseline_fingerprint {
        return Err(digest_fault(
            SchemaDocumentFormationFaultKind::BaselineMismatch,
            "exact_baseline_fingerprint",
            &bundle.exact_baseline_fingerprint,
            &observed_baseline,
        ));
    }
    let envelope_bytes = canonical_serialized_bytes(bundle, "bundle")?;
    enforce_byte_limit(
        "bundle",
        envelope_bytes.len() as u64,
        bundle.payload.limits.maximum_canonical_bundle_bytes,
    )?;
    Ok(())
}

fn document_fingerprint(
    direction: SchemaContractDirection,
    root_kind: MachineSchemaRootKind,
    type_name: &str,
    schema_id: &str,
    root_fingerprint: &ContentDigest,
    universe_fingerprint: &ContentDigest,
    document_digest: &ContentDigest,
) -> ContentDigest {
    domain_digest(
        DOCUMENT_FINGERPRINT_PROFILE,
        [
            direction.token().as_bytes(),
            root_kind.token().as_bytes(),
            type_name.as_bytes(),
            schema_id.as_bytes(),
            root_fingerprint.value.as_bytes(),
            universe_fingerprint.value.as_bytes(),
            document_digest.value.as_bytes(),
        ],
    )
}

fn fixed_artifact_paths() -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "prepare_input".to_owned(),
            "input_deserialize.prepare_input.schema.json".to_owned(),
        ),
        (
            "run_input".to_owned(),
            "input_deserialize.run_input.schema.json".to_owned(),
        ),
        (
            "verify_input".to_owned(),
            "input_deserialize.verify_input.schema.json".to_owned(),
        ),
        (
            "base_response".to_owned(),
            "output_serialize.base_response.schema.json".to_owned(),
        ),
        (
            "preparation_response".to_owned(),
            "output_serialize.preparation_response.schema.json".to_owned(),
        ),
        (
            "bundle".to_owned(),
            "public_procedure_machine_schema.bundle.json".to_owned(),
        ),
    ])
}

fn canonical_serialized_bytes<T: Serialize>(
    value: &T,
    subject: &str,
) -> Result<Vec<u8>, SchemaDocumentFormationFault> {
    let value = serde_json::to_value(value).map_err(|error| {
        fault(
            SchemaDocumentFormationFaultKind::Serialization,
            [subject],
            error,
        )
    })?;
    canonical_bytes(&value, subject)
}

fn canonical_bytes(value: &Value, subject: &str) -> Result<Vec<u8>, SchemaDocumentFormationFault> {
    canonical_json_bytes(value).map_err(|error| document_fault_from_generation(subject, error))
}

fn enforce_byte_limit(
    subject: &str,
    observed: u64,
    limit: u64,
) -> Result<(), SchemaDocumentFormationFault> {
    if observed > limit {
        let mut result = fault(
            SchemaDocumentFormationFaultKind::LimitExceeded,
            [subject, "canonical_bytes"],
            "canonical byte limit exceeded",
        );
        result.limit = Some(limit);
        result.observed = Some(observed);
        Err(result)
    } else {
        Ok(())
    }
}

fn domain_digest<'a>(domain: &str, parts: impl IntoIterator<Item = &'a [u8]>) -> ContentDigest {
    let mut preimage = domain.as_bytes().to_vec();
    for part in parts {
        preimage.push(0);
        preimage.extend_from_slice(part);
    }
    sha256_bytes(&preimage)
}

fn digest_fault(
    kind: SchemaDocumentFormationFaultKind,
    path: &str,
    expected: &ContentDigest,
    observed: &ContentDigest,
) -> SchemaDocumentFormationFault {
    let mut result = fault(kind, [path], "content digest mismatch");
    result.expected_digest = Some(Box::new(expected.clone()));
    result.observed_digest = Some(Box::new(observed.clone()));
    result
}

fn document_fault_from_generation(
    subject: &str,
    error: crate::MachineSchemaGenerationFault,
) -> SchemaDocumentFormationFault {
    SchemaDocumentFormationFault {
        kind: if error.kind == crate::MachineSchemaGenerationFaultKind::LimitExceeded {
            SchemaDocumentFormationFaultKind::LimitExceeded
        } else {
            SchemaDocumentFormationFaultKind::InternalInvariant
        },
        path: std::iter::once(subject.to_owned())
            .chain(error.path)
            .collect(),
        limit: error.limit,
        observed: error.observed,
        expected_digest: None,
        observed_digest: None,
        message: error
            .message
            .chars()
            .take(MAX_DOCUMENT_FAULT_CHARS)
            .collect(),
    }
}

fn fault<'a>(
    kind: SchemaDocumentFormationFaultKind,
    path: impl IntoIterator<Item = &'a str>,
    message: impl ToString,
) -> SchemaDocumentFormationFault {
    SchemaDocumentFormationFault {
        kind,
        path: path.into_iter().map(str::to_owned).collect(),
        limit: None,
        observed: None,
        expected_digest: None,
        observed_digest: None,
        message: message
            .to_string()
            .chars()
            .take(MAX_DOCUMENT_FAULT_CHARS)
            .collect(),
    }
}
