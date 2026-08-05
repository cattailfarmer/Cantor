//! Pure, bounded, direction-aware schema generation primitives.
//!
//! This module forms in-memory root drafts and definition universes. It does
//! not publish canonical schema documents, parse untrusted JSON, validate an
//! instance, resolve external references, or perform an external effect.

use std::collections::{BTreeMap, BTreeSet};

use cantor_core::{ContentDigest, sha256_bytes};
use schemars::{JsonSchema, generate::SchemaSettings};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{PrepareRequest, PreparedRunRequest, ProcedureToolResponse, VerifyRequest};

pub const MACHINE_SCHEMA_PROFILE: &str = "cantor-public-procedure-machine-schema/0.1";
pub const MACHINE_SCHEMA_GENERATOR_ID: &str = "schemars/1.2.2+cantor/i02b/0.1";
const DEFINITION_FINGERPRINT_PROFILE: &str = "cantor-schema-contract-definition/0.1";
const ROOT_FINGERPRINT_PROFILE: &str = "cantor-schema-root-draft/0.1";
const UNIVERSE_FINGERPRINT_PROFILE: &str = "cantor-schema-definition-universe/0.1";
const MAX_FAULT_CHARS: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemaContractDirection {
    InputDeserialize,
    OutputSerialize,
}

impl SchemaContractDirection {
    pub(crate) fn token(self) -> &'static str {
        match self {
            Self::InputDeserialize => "input_deserialize",
            Self::OutputSerialize => "output_serialize",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MachineSchemaRootKind {
    PrepareInput,
    RunInput,
    VerifyInput,
    BaseResponse,
    PreparationResponse,
}

impl MachineSchemaRootKind {
    pub(crate) fn token(self) -> &'static str {
        match self {
            Self::PrepareInput => "prepare_input",
            Self::RunInput => "run_input",
            Self::VerifyInput => "verify_input",
            Self::BaseResponse => "base_response",
            Self::PreparationResponse => "preparation_response",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaGenerationLimits {
    pub maximum_canonical_document_bytes: u64,
    pub maximum_canonical_bundle_bytes: u64,
    pub maximum_definitions: u64,
    pub maximum_reference_occurrences: u64,
    pub maximum_document_depth: u64,
    pub maximum_object_properties: u64,
    pub maximum_alternatives: u64,
    pub maximum_semantic_residuals: u64,
    pub maximum_conformance_cases: u64,
    pub maximum_conformance_corpus_bytes: u64,
}

impl Default for SchemaGenerationLimits {
    fn default() -> Self {
        Self {
            maximum_canonical_document_bytes: 4_194_304,
            maximum_canonical_bundle_bytes: 16_777_216,
            maximum_definitions: 256,
            maximum_reference_occurrences: 4_096,
            maximum_document_depth: 64,
            maximum_object_properties: 4_096,
            maximum_alternatives: 2_048,
            maximum_semantic_residuals: 1_024,
            maximum_conformance_cases: 4_096,
            maximum_conformance_corpus_bytes: 67_108_864,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaResourceAccount {
    pub canonical_bytes: u64,
    pub definitions: u64,
    pub reference_occurrences: u64,
    pub maximum_document_depth: u64,
    pub object_properties: u64,
    pub alternatives: u64,
    pub semantic_residuals: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefinitionRecursionClass {
    Acyclic,
    DirectSelf,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractDefinitionAccount {
    pub direction: SchemaContractDirection,
    pub stable_type_name: String,
    pub local_pointer: String,
    pub direct_local_reference_targets: BTreeSet<String>,
    pub recursion_class: DefinitionRecursionClass,
    pub raw_content_digest: ContentDigest,
    pub contract_fingerprint: ContentDigest,
    pub residual_ids: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineSchemaRootDraft {
    pub direction: SchemaContractDirection,
    pub root_kind: MachineSchemaRootKind,
    pub type_name: String,
    pub schema_id: String,
    pub normalized_root: Value,
    pub definition_closure: BTreeSet<String>,
    pub raw_content_digest: ContentDigest,
    pub root_fingerprint: ContentDigest,
    pub resources: SchemaResourceAccount,
    pub residual_ids: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractDefinitionUniverse {
    pub profile: String,
    pub generator_id: String,
    pub supplied_source_revision: String,
    pub direction: SchemaContractDirection,
    pub limits: SchemaGenerationLimits,
    pub definitions: BTreeMap<String, Value>,
    pub definition_accounts: BTreeMap<String, ContractDefinitionAccount>,
    pub roots: BTreeMap<MachineSchemaRootKind, MachineSchemaRootDraft>,
    pub resources: SchemaResourceAccount,
    pub universe_fingerprint: ContentDigest,
    pub residual_ids: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineSchemaGenerationContext {
    pub supplied_source_revision: String,
    pub limits: SchemaGenerationLimits,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MachineSchemaGenerationFaultKind {
    InvalidSourceRevision,
    InvalidLimit,
    GeneratedShape,
    DefinitionCollision,
    InvalidReference,
    UnresolvedReference,
    UnexpectedCycle,
    LimitExceeded,
    Serialization,
    InternalInvariant,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineSchemaGenerationFault {
    pub kind: MachineSchemaGenerationFaultKind,
    pub path: Vec<String>,
    pub limit: Option<u64>,
    pub observed: Option<u64>,
    pub message: String,
}

/// Generates both public procedure schema universes atomically.
pub fn generate_public_procedure_schema_universes(
    context: &MachineSchemaGenerationContext,
) -> Result<
    BTreeMap<SchemaContractDirection, ContractDefinitionUniverse>,
    MachineSchemaGenerationFault,
> {
    validate_context(context)?;
    let input =
        generate_contract_definition_universe(SchemaContractDirection::InputDeserialize, context)?;
    let output =
        generate_contract_definition_universe(SchemaContractDirection::OutputSerialize, context)?;
    Ok(BTreeMap::from([
        (SchemaContractDirection::InputDeserialize, input),
        (SchemaContractDirection::OutputSerialize, output),
    ]))
}

/// Generates one contract-scoped definition universe without external effects.
pub fn generate_contract_definition_universe(
    direction: SchemaContractDirection,
    context: &MachineSchemaGenerationContext,
) -> Result<ContractDefinitionUniverse, MachineSchemaGenerationFault> {
    validate_context(context)?;
    preflight_known_footprint(direction, &context.limits)?;
    let mut builder = UniverseBuilder::new(direction, context);
    match direction {
        SchemaContractDirection::InputDeserialize => {
            builder.add_root::<PrepareRequest>(MachineSchemaRootKind::PrepareInput)?;
            builder.add_root::<PreparedRunRequest>(MachineSchemaRootKind::RunInput)?;
            builder.add_root::<VerifyRequest>(MachineSchemaRootKind::VerifyInput)?;
        }
        SchemaContractDirection::OutputSerialize => {
            builder.add_root::<ProcedureToolResponse>(MachineSchemaRootKind::BaseResponse)?;
            builder
                .add_root::<ProcedureToolResponse>(MachineSchemaRootKind::PreparationResponse)?;
        }
    }
    builder.finish()
}

fn preflight_known_footprint(
    direction: SchemaContractDirection,
    limits: &SchemaGenerationLimits,
) -> Result<(), MachineSchemaGenerationFault> {
    let required = match direction {
        SchemaContractDirection::InputDeserialize => [
            (
                "maximum_canonical_document_bytes",
                limits.maximum_canonical_document_bytes,
                51_098,
            ),
            (
                "maximum_canonical_bundle_bytes",
                limits.maximum_canonical_bundle_bytes,
                53_936,
            ),
            ("maximum_definitions", limits.maximum_definitions, 80),
            (
                "maximum_reference_occurrences",
                limits.maximum_reference_occurrences,
                406,
            ),
            ("maximum_document_depth", limits.maximum_document_depth, 8),
            (
                "maximum_object_properties",
                limits.maximum_object_properties,
                571,
            ),
            ("maximum_alternatives", limits.maximum_alternatives, 250),
            (
                "maximum_semantic_residuals",
                limits.maximum_semantic_residuals,
                6,
            ),
        ],
        SchemaContractDirection::OutputSerialize => [
            (
                "maximum_canonical_document_bytes",
                limits.maximum_canonical_document_bytes,
                52_936,
            ),
            (
                "maximum_canonical_bundle_bytes",
                limits.maximum_canonical_bundle_bytes,
                53_846,
            ),
            ("maximum_definitions", limits.maximum_definitions, 83),
            (
                "maximum_reference_occurrences",
                limits.maximum_reference_occurrences,
                398,
            ),
            ("maximum_document_depth", limits.maximum_document_depth, 8),
            (
                "maximum_object_properties",
                limits.maximum_object_properties,
                567,
            ),
            ("maximum_alternatives", limits.maximum_alternatives, 271),
            (
                "maximum_semantic_residuals",
                limits.maximum_semantic_residuals,
                6,
            ),
        ],
    };
    for (name, available, observed_minimum) in required {
        if available < observed_minimum {
            return Err(fault_with_limit(
                MachineSchemaGenerationFaultKind::LimitExceeded,
                [direction.token(), name],
                available,
                observed_minimum,
                "configured limit is below the pinned generator footprint",
            ));
        }
    }
    Ok(())
}

struct PendingRoot {
    type_name: String,
    normalized_root: Value,
}

struct UniverseBuilder<'a> {
    direction: SchemaContractDirection,
    context: &'a MachineSchemaGenerationContext,
    definitions: BTreeMap<String, Value>,
    roots: BTreeMap<MachineSchemaRootKind, PendingRoot>,
}

impl<'a> UniverseBuilder<'a> {
    fn new(
        direction: SchemaContractDirection,
        context: &'a MachineSchemaGenerationContext,
    ) -> Self {
        Self {
            direction,
            context,
            definitions: BTreeMap::new(),
            roots: BTreeMap::new(),
        }
    }

    fn add_root<T: JsonSchema>(
        &mut self,
        root_kind: MachineSchemaRootKind,
    ) -> Result<(), MachineSchemaGenerationFault> {
        let settings = match self.direction {
            SchemaContractDirection::InputDeserialize => {
                SchemaSettings::draft2020_12().for_deserialize()
            }
            SchemaContractDirection::OutputSerialize => {
                SchemaSettings::draft2020_12().for_serialize()
            }
        };
        let mut root = settings
            .into_generator()
            .into_root_schema_for::<T>()
            .to_value();
        let object = root.as_object_mut().ok_or_else(|| {
            fault(
                MachineSchemaGenerationFaultKind::GeneratedShape,
                [root_kind.token()],
                "generated root is not an object",
            )
        })?;
        let definitions = match object.remove("$defs") {
            None => Map::new(),
            Some(Value::Object(definitions)) => definitions,
            Some(_) => {
                return Err(fault(
                    MachineSchemaGenerationFaultKind::GeneratedShape,
                    [root_kind.token(), "$defs"],
                    "generated $defs is not an object",
                ));
            }
        };
        for (name, definition) in definitions {
            validate_definition_name(&name)?;
            if let Some(existing) = self.definitions.get(&name) {
                if canonical_json_bytes(existing)? != canonical_json_bytes(&definition)? {
                    return Err(fault(
                        MachineSchemaGenerationFaultKind::DefinitionCollision,
                        [root_kind.token(), name.as_str()],
                        "equal definition name has unequal normalized bytes",
                    ));
                }
            } else {
                self.definitions.insert(name, definition);
            }
        }
        self.roots.insert(
            root_kind,
            PendingRoot {
                type_name: T::schema_name().into_owned(),
                normalized_root: root,
            },
        );
        Ok(())
    }

    fn finish(self) -> Result<ContractDefinitionUniverse, MachineSchemaGenerationFault> {
        enforce_count(
            "definitions",
            self.definitions.len() as u64,
            self.context.limits.maximum_definitions,
        )?;
        let direct_targets = definition_target_map(&self.definitions)?;
        validate_definition_cycles(&direct_targets)?;
        let mut definition_accounts = BTreeMap::new();
        for (name, definition) in &self.definitions {
            let bytes = canonical_json_bytes(definition)?;
            let targets = direct_targets.get(name).cloned().unwrap_or_default();
            let recursion_class = if targets.contains(name) {
                DefinitionRecursionClass::DirectSelf
            } else {
                DefinitionRecursionClass::Acyclic
            };
            let residual_ids = definition_residuals(name);
            let contract_fingerprint = domain_digest(
                DEFINITION_FINGERPRINT_PROFILE,
                [
                    self.direction.token().as_bytes(),
                    name.as_bytes(),
                    bytes.as_slice(),
                ],
            );
            definition_accounts.insert(
                name.clone(),
                ContractDefinitionAccount {
                    direction: self.direction,
                    stable_type_name: name.clone(),
                    local_pointer: format!("#/$defs/{name}"),
                    direct_local_reference_targets: targets,
                    recursion_class,
                    raw_content_digest: sha256_bytes(&bytes),
                    contract_fingerprint,
                    residual_ids,
                },
            );
        }

        let residual_ids = universe_residuals();
        enforce_count(
            "semantic_residuals",
            residual_ids.len() as u64,
            self.context.limits.maximum_semantic_residuals,
        )?;
        let mut roots = BTreeMap::new();
        for (root_kind, pending) in self.roots {
            let root_targets = collect_local_reference_targets(
                &pending.normalized_root,
                &[root_kind.token().to_owned()],
            )?;
            let closure = definition_closure(&root_targets, &direct_targets)?;
            let materialized =
                materialize_root(&pending.normalized_root, &closure, &self.definitions)?;
            let resources = measure_and_enforce(
                &materialized,
                closure.len() as u64,
                residual_ids.len() as u64,
                &self.context.limits,
                self.context.limits.maximum_canonical_document_bytes,
                root_kind.token(),
            )?;
            let root_bytes = canonical_json_bytes(&pending.normalized_root)?;
            let mut parts = vec![
                self.direction.token().as_bytes(),
                root_kind.token().as_bytes(),
                pending.type_name.as_bytes(),
                root_bytes.as_slice(),
            ];
            let closure_names = closure.iter().map(String::as_bytes).collect::<Vec<_>>();
            parts.extend(closure_names);
            let root_fingerprint = domain_digest(ROOT_FINGERPRINT_PROFILE, parts);
            roots.insert(
                root_kind,
                MachineSchemaRootDraft {
                    direction: self.direction,
                    root_kind,
                    type_name: pending.type_name,
                    schema_id: format!(
                        "urn:cantor:schema:public-procedure:0.1:{}:{}",
                        self.direction.token(),
                        root_kind.token()
                    ),
                    normalized_root: pending.normalized_root,
                    definition_closure: closure,
                    raw_content_digest: sha256_bytes(&root_bytes),
                    root_fingerprint,
                    resources,
                    residual_ids: residual_ids.clone(),
                },
            );
        }

        let resources = aggregate_resources(
            &self.definitions,
            &roots,
            residual_ids.len() as u64,
            &self.context.limits,
        )?;
        let limits_bytes = canonical_json_bytes(
            &serde_json::to_value(&self.context.limits).map_err(|error| {
                fault(
                    MachineSchemaGenerationFaultKind::Serialization,
                    ["limits"],
                    error.to_string(),
                )
            })?,
        )?;
        let resources_bytes =
            canonical_json_bytes(&serde_json::to_value(&resources).map_err(|error| {
                fault(
                    MachineSchemaGenerationFaultKind::Serialization,
                    ["resources"],
                    error.to_string(),
                )
            })?)?;
        let mut parts = vec![
            self.direction.token().as_bytes(),
            MACHINE_SCHEMA_GENERATOR_ID.as_bytes(),
            self.context.supplied_source_revision.as_bytes(),
            limits_bytes.as_slice(),
        ];
        let definition_parts = definition_accounts
            .iter()
            .flat_map(|(name, account)| {
                [
                    name.as_bytes(),
                    account.contract_fingerprint.value.as_bytes(),
                ]
            })
            .collect::<Vec<_>>();
        parts.extend(definition_parts);
        let root_parts = roots
            .iter()
            .flat_map(|(kind, root)| {
                [
                    kind.token().as_bytes(),
                    root.root_fingerprint.value.as_bytes(),
                ]
            })
            .collect::<Vec<_>>();
        parts.extend(root_parts);
        parts.push(resources_bytes.as_slice());
        let universe_fingerprint = domain_digest(UNIVERSE_FINGERPRINT_PROFILE, parts);

        Ok(ContractDefinitionUniverse {
            profile: MACHINE_SCHEMA_PROFILE.to_owned(),
            generator_id: MACHINE_SCHEMA_GENERATOR_ID.to_owned(),
            supplied_source_revision: self.context.supplied_source_revision.clone(),
            direction: self.direction,
            limits: self.context.limits.clone(),
            definitions: self.definitions,
            definition_accounts,
            roots,
            resources,
            universe_fingerprint,
            residual_ids,
        })
    }
}

fn validate_context(
    context: &MachineSchemaGenerationContext,
) -> Result<(), MachineSchemaGenerationFault> {
    let revision = context.supplied_source_revision.as_bytes();
    if !matches!(revision.len(), 40 | 64)
        || !revision
            .iter()
            .all(|byte| byte.is_ascii_digit() || (*byte >= b'a' && *byte <= b'f'))
    {
        return Err(fault(
            MachineSchemaGenerationFaultKind::InvalidSourceRevision,
            ["supplied_source_revision"],
            "source revision must be 40 or 64 lowercase hexadecimal characters",
        ));
    }
    let defaults = SchemaGenerationLimits::default();
    let fields = [
        (
            "maximum_canonical_document_bytes",
            context.limits.maximum_canonical_document_bytes,
            defaults.maximum_canonical_document_bytes,
        ),
        (
            "maximum_canonical_bundle_bytes",
            context.limits.maximum_canonical_bundle_bytes,
            defaults.maximum_canonical_bundle_bytes,
        ),
        (
            "maximum_definitions",
            context.limits.maximum_definitions,
            defaults.maximum_definitions,
        ),
        (
            "maximum_reference_occurrences",
            context.limits.maximum_reference_occurrences,
            defaults.maximum_reference_occurrences,
        ),
        (
            "maximum_document_depth",
            context.limits.maximum_document_depth,
            defaults.maximum_document_depth,
        ),
        (
            "maximum_object_properties",
            context.limits.maximum_object_properties,
            defaults.maximum_object_properties,
        ),
        (
            "maximum_alternatives",
            context.limits.maximum_alternatives,
            defaults.maximum_alternatives,
        ),
        (
            "maximum_semantic_residuals",
            context.limits.maximum_semantic_residuals,
            defaults.maximum_semantic_residuals,
        ),
        (
            "maximum_conformance_cases",
            context.limits.maximum_conformance_cases,
            defaults.maximum_conformance_cases,
        ),
        (
            "maximum_conformance_corpus_bytes",
            context.limits.maximum_conformance_corpus_bytes,
            defaults.maximum_conformance_corpus_bytes,
        ),
    ];
    for (name, value, maximum) in fields {
        if value == 0 || value > maximum {
            return Err(fault_with_limit(
                MachineSchemaGenerationFaultKind::InvalidLimit,
                [name],
                maximum,
                value,
                "limit must be positive and may not exceed profile 0.1",
            ));
        }
    }
    Ok(())
}

fn validate_definition_name(name: &str) -> Result<(), MachineSchemaGenerationFault> {
    let mut chars = name.chars();
    if !chars
        .next()
        .is_some_and(|ch| ch.is_ascii_alphabetic() || ch == '_')
        || !chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        || name.ends_with(|ch: char| ch.is_ascii_digit())
    {
        return Err(fault(
            MachineSchemaGenerationFaultKind::GeneratedShape,
            ["$defs", name],
            "definition name is not an inventory-stable Rust identifier or has a collision suffix",
        ));
    }
    Ok(())
}

fn definition_target_map(
    definitions: &BTreeMap<String, Value>,
) -> Result<BTreeMap<String, BTreeSet<String>>, MachineSchemaGenerationFault> {
    let mut result = BTreeMap::new();
    for (name, definition) in definitions {
        let targets =
            collect_local_reference_targets(definition, &["$defs".to_owned(), name.clone()])?;
        for target in &targets {
            if !definitions.contains_key(target) {
                return Err(fault(
                    MachineSchemaGenerationFaultKind::UnresolvedReference,
                    ["$defs", name.as_str(), target.as_str()],
                    "local reference target is missing from the same-direction universe",
                ));
            }
        }
        result.insert(name.clone(), targets);
    }
    Ok(result)
}

fn collect_local_reference_targets(
    value: &Value,
    path: &[String],
) -> Result<BTreeSet<String>, MachineSchemaGenerationFault> {
    let mut result = BTreeSet::new();
    collect_references(value, path, &mut result)?;
    Ok(result)
}

fn collect_references(
    value: &Value,
    path: &[String],
    result: &mut BTreeSet<String>,
) -> Result<(), MachineSchemaGenerationFault> {
    match value {
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                let mut child_path = path.to_vec();
                child_path.push(index.to_string());
                collect_references(child, &child_path, result)?;
            }
        }
        Value::Object(object) => {
            for (key, child) in object {
                let mut child_path = path.to_vec();
                child_path.push(key.clone());
                if key == "$ref" {
                    let reference = child.as_str().ok_or_else(|| {
                        fault(
                            MachineSchemaGenerationFaultKind::InvalidReference,
                            child_path.iter().map(String::as_str),
                            "$ref is not a string",
                        )
                    })?;
                    let target = reference.strip_prefix("#/$defs/").ok_or_else(|| {
                        fault(
                            MachineSchemaGenerationFaultKind::InvalidReference,
                            child_path.iter().map(String::as_str),
                            "only fragment-local #/$defs references are permitted",
                        )
                    })?;
                    validate_definition_name(target)?;
                    result.insert(target.to_owned());
                }
                collect_references(child, &child_path, result)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_definition_cycles(
    targets: &BTreeMap<String, BTreeSet<String>>,
) -> Result<(), MachineSchemaGenerationFault> {
    let mut visited = BTreeSet::new();
    let mut active = BTreeSet::new();
    for name in targets.keys() {
        visit_definition(name, targets, &mut visited, &mut active)?;
    }
    Ok(())
}

fn visit_definition(
    name: &str,
    targets: &BTreeMap<String, BTreeSet<String>>,
    visited: &mut BTreeSet<String>,
    active: &mut BTreeSet<String>,
) -> Result<(), MachineSchemaGenerationFault> {
    if visited.contains(name) {
        return Ok(());
    }
    active.insert(name.to_owned());
    for target in targets.get(name).into_iter().flatten() {
        if active.contains(target) {
            if target == name && matches!(name, "ProcedureType" | "ProcedureValue") {
                continue;
            }
            return Err(fault(
                MachineSchemaGenerationFaultKind::UnexpectedCycle,
                active.iter().map(String::as_str).chain([target.as_str()]),
                "unexpected mutual or unauthorized direct schema cycle",
            ));
        }
        visit_definition(target, targets, visited, active)?;
    }
    active.remove(name);
    visited.insert(name.to_owned());
    Ok(())
}

fn definition_closure(
    roots: &BTreeSet<String>,
    targets: &BTreeMap<String, BTreeSet<String>>,
) -> Result<BTreeSet<String>, MachineSchemaGenerationFault> {
    let mut closure = BTreeSet::new();
    let mut pending = roots.clone();
    while let Some(name) = pending.pop_first() {
        if !targets.contains_key(&name) {
            return Err(fault(
                MachineSchemaGenerationFaultKind::UnresolvedReference,
                [name.as_str()],
                "root references a definition absent from its universe",
            ));
        }
        if closure.insert(name.clone()) {
            pending.extend(targets.get(&name).into_iter().flatten().cloned());
        }
    }
    Ok(closure)
}

fn materialize_root(
    root: &Value,
    closure: &BTreeSet<String>,
    definitions: &BTreeMap<String, Value>,
) -> Result<Value, MachineSchemaGenerationFault> {
    let mut object = root.as_object().cloned().ok_or_else(|| {
        fault(
            MachineSchemaGenerationFaultKind::InternalInvariant,
            ["root"],
            "normalized root ceased to be an object",
        )
    })?;
    let mut selected = Map::new();
    for name in closure {
        selected.insert(
            name.clone(),
            definitions.get(name).cloned().ok_or_else(|| {
                fault(
                    MachineSchemaGenerationFaultKind::InternalInvariant,
                    ["$defs", name.as_str()],
                    "closure target disappeared",
                )
            })?,
        );
    }
    object.insert("$defs".to_owned(), Value::Object(selected));
    Ok(Value::Object(object))
}

fn aggregate_resources(
    definitions: &BTreeMap<String, Value>,
    roots: &BTreeMap<MachineSchemaRootKind, MachineSchemaRootDraft>,
    residual_count: u64,
    limits: &SchemaGenerationLimits,
) -> Result<SchemaResourceAccount, MachineSchemaGenerationFault> {
    let structure = serde_json::json!({
        "$defs": definitions,
        "roots": roots.iter().map(|(kind, root)| (kind.token(), &root.normalized_root)).collect::<BTreeMap<_, _>>()
    });
    measure_and_enforce(
        &structure,
        definitions.len() as u64,
        residual_count,
        limits,
        limits.maximum_canonical_bundle_bytes,
        "universe",
    )
}

fn measure_and_enforce(
    value: &Value,
    definitions: u64,
    residuals: u64,
    limits: &SchemaGenerationLimits,
    byte_limit: u64,
    subject: &str,
) -> Result<SchemaResourceAccount, MachineSchemaGenerationFault> {
    let mut account = SchemaResourceAccount {
        definitions,
        semantic_residuals: residuals,
        ..SchemaResourceAccount::default()
    };
    measure_value(value, 0, &mut account)?;
    account.canonical_bytes = canonical_json_bytes(value)?.len() as u64;
    for (name, observed, limit) in [
        ("canonical_bytes", account.canonical_bytes, byte_limit),
        (
            "definitions",
            account.definitions,
            limits.maximum_definitions,
        ),
        (
            "reference_occurrences",
            account.reference_occurrences,
            limits.maximum_reference_occurrences,
        ),
        (
            "maximum_document_depth",
            account.maximum_document_depth,
            limits.maximum_document_depth,
        ),
        (
            "object_properties",
            account.object_properties,
            limits.maximum_object_properties,
        ),
        (
            "alternatives",
            account.alternatives,
            limits.maximum_alternatives,
        ),
        (
            "semantic_residuals",
            account.semantic_residuals,
            limits.maximum_semantic_residuals,
        ),
    ] {
        if observed > limit {
            return Err(fault_with_limit(
                MachineSchemaGenerationFaultKind::LimitExceeded,
                [subject, name],
                limit,
                observed,
                "schema resource limit exceeded",
            ));
        }
    }
    Ok(account)
}

fn measure_value(
    value: &Value,
    depth: u64,
    account: &mut SchemaResourceAccount,
) -> Result<(), MachineSchemaGenerationFault> {
    account.maximum_document_depth = account.maximum_document_depth.max(depth);
    match value {
        Value::Array(values) => {
            for child in values {
                measure_value(
                    child,
                    depth.checked_add(1).ok_or_else(|| {
                        fault(
                            MachineSchemaGenerationFaultKind::LimitExceeded,
                            ["depth"],
                            "schema depth counter overflow",
                        )
                    })?,
                    account,
                )?;
            }
        }
        Value::Object(object) => {
            if let Some(Value::Object(properties)) = object.get("properties") {
                account.object_properties = account
                    .object_properties
                    .checked_add(properties.len() as u64)
                    .ok_or_else(|| counter_overflow("object_properties"))?;
            }
            for key in ["enum", "oneOf", "anyOf", "allOf"] {
                if let Some(Value::Array(values)) = object.get(key) {
                    account.alternatives = account
                        .alternatives
                        .checked_add(values.len() as u64)
                        .ok_or_else(|| counter_overflow("alternatives"))?;
                }
            }
            if object.contains_key("$ref") {
                account.reference_occurrences = account
                    .reference_occurrences
                    .checked_add(1)
                    .ok_or_else(|| counter_overflow("reference_occurrences"))?;
            }
            for child in object.values() {
                measure_value(
                    child,
                    depth
                        .checked_add(1)
                        .ok_or_else(|| counter_overflow("depth"))?,
                    account,
                )?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub(crate) fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, MachineSchemaGenerationFault> {
    let mut output = Vec::new();
    write_canonical_json(value, &mut output)?;
    Ok(output)
}

fn write_canonical_json(
    value: &Value,
    output: &mut Vec<u8>,
) -> Result<(), MachineSchemaGenerationFault> {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            output.extend(serde_json::to_vec(value).map_err(|error| {
                fault(
                    MachineSchemaGenerationFaultKind::Serialization,
                    ["scalar"],
                    error.to_string(),
                )
            })?);
        }
        Value::Array(values) => {
            output.push(b'[');
            for (index, child) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_json(child, output)?;
            }
            output.push(b']');
        }
        Value::Object(object) => {
            output.push(b'{');
            let mut keys = object.keys().collect::<Vec<_>>();
            keys.sort();
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                output.extend(serde_json::to_vec(key).map_err(|error| {
                    fault(
                        MachineSchemaGenerationFaultKind::Serialization,
                        ["object_key"],
                        error.to_string(),
                    )
                })?);
                output.push(b':');
                write_canonical_json(&object[key], output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn domain_digest<'a>(domain: &str, parts: impl IntoIterator<Item = &'a [u8]>) -> ContentDigest {
    let mut preimage = domain.as_bytes().to_vec();
    for part in parts {
        preimage.push(0);
        preimage.extend_from_slice(part);
    }
    sha256_bytes(&preimage)
}

fn definition_residuals(name: &str) -> BTreeSet<String> {
    match name {
        "ProcedureType" => BTreeSet::from(["RMS-R02".to_owned(), "RMS-R03".to_owned()]),
        "ProcedureValue" => BTreeSet::from([
            "RMS-R02".to_owned(),
            "RMS-R04".to_owned(),
            "RMS-R05".to_owned(),
        ]),
        _ => BTreeSet::new(),
    }
}

fn universe_residuals() -> BTreeSet<String> {
    (1..=6).map(|number| format!("RMS-R{number:02}")).collect()
}

fn enforce_count(
    name: &str,
    observed: u64,
    limit: u64,
) -> Result<(), MachineSchemaGenerationFault> {
    if observed > limit {
        Err(fault_with_limit(
            MachineSchemaGenerationFaultKind::LimitExceeded,
            [name],
            limit,
            observed,
            "schema resource limit exceeded",
        ))
    } else {
        Ok(())
    }
}

fn counter_overflow(name: &str) -> MachineSchemaGenerationFault {
    fault(
        MachineSchemaGenerationFaultKind::LimitExceeded,
        [name],
        "schema resource counter overflow",
    )
}

fn fault<'a>(
    kind: MachineSchemaGenerationFaultKind,
    path: impl IntoIterator<Item = &'a str>,
    message: impl ToString,
) -> MachineSchemaGenerationFault {
    MachineSchemaGenerationFault {
        kind,
        path: path.into_iter().map(str::to_owned).collect(),
        limit: None,
        observed: None,
        message: message.to_string().chars().take(MAX_FAULT_CHARS).collect(),
    }
}

fn fault_with_limit<'a>(
    kind: MachineSchemaGenerationFaultKind,
    path: impl IntoIterator<Item = &'a str>,
    limit: u64,
    observed: u64,
    message: impl ToString,
) -> MachineSchemaGenerationFault {
    let mut result = fault(kind, path, message);
    result.limit = Some(limit);
    result.observed = Some(observed);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_writer_sorts_objects_and_retains_arrays() {
        let value = serde_json::json!({"z": [3, 2, 1], "a": {"b": true, "a": null}});
        assert_eq!(
            canonical_json_bytes(&value).expect("canonical bytes"),
            br#"{"a":{"a":null,"b":true},"z":[3,2,1]}"#
        );
    }

    #[test]
    fn unexpected_mutual_cycle_is_refused() {
        let targets = BTreeMap::from([
            ("Alpha".to_owned(), BTreeSet::from(["Beta".to_owned()])),
            ("Beta".to_owned(), BTreeSet::from(["Alpha".to_owned()])),
        ]);
        assert_eq!(
            validate_definition_cycles(&targets)
                .expect_err("mutual cycle must fail")
                .kind,
            MachineSchemaGenerationFaultKind::UnexpectedCycle
        );
    }
}
