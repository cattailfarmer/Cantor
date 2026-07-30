use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    AuthorityScope, CantorQueryRequest, CantorQueryResult, CantorRecognitionCertificate,
    CompiledSourcePackage, ContentDigest, FabricMetrics, PackageProofRecord, QueryFault,
    QueryFaultKind, QuoteRecord, SemanticFabric, SemanticId, SemanticUnit, TrustFault, TrustStore,
    admit_package, execute_query, sha256_digest, verify_query_result_digest,
};

pub const PROTOCOL_VERSION: &str = "cantor-protocol/0.1";
pub const EMBEDDED_ENVIRONMENT_VERSION: &str = "cantor-embedded-environment/0.1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitClass {
    Success,
    InvalidRequest,
    TrustFailure,
    Unresolved,
    PolicyDenial,
    SemanticFault,
    InternalFault,
}

impl ExitClass {
    pub const fn code(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::InvalidRequest => 2,
            Self::TrustFailure => 3,
            Self::Unresolved => 4,
            Self::PolicyDenial => 5,
            Self::SemanticFault => 6,
            Self::InternalFault => 70,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolCallerContext {
    pub caller_id: SemanticId,
    pub purpose: String,
    pub job_id: Option<SemanticId>,
    pub effect_boundary: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedPackage {
    pub package_id: SemanticId,
    pub package_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "target", rename_all = "snake_case", deny_unknown_fields)]
pub enum InspectRequest {
    Fabric,
    Package { package_id: SemanticId },
    Certificate { package_id: SemanticId },
    SemanticUnit { unit_id: SemanticId },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProtocolOperation {
    Query { query: Box<CantorQueryRequest> },
    Inspect { inspect: InspectRequest },
}

impl ProtocolOperation {
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Query { .. } => "query",
            Self::Inspect { .. } => "inspect",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolRequest {
    pub protocol_version: String,
    pub request_id: SemanticId,
    pub caller_context: ProtocolCallerContext,
    pub expected_environment_digest: ContentDigest,
    pub expected_packages: Vec<ExpectedPackage>,
    pub requested_scope: AuthorityScope,
    pub request: ProtocolOperation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmbeddedRuntimeEnvironment {
    pub environment_version: String,
    pub now_epoch_seconds: u64,
    pub trust_store: TrustStore,
    pub packages: Vec<CompiledSourcePackage>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result_kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum InspectResult {
    Fabric {
        metrics: FabricMetrics,
        package_ids: Vec<SemanticId>,
    },
    Package {
        package_proof: PackageProofRecord,
        semantic_unit_ids: Vec<SemanticId>,
        relation_ids: Vec<SemanticId>,
    },
    Certificate {
        package_id: SemanticId,
        certificate: CantorRecognitionCertificate,
    },
    SemanticUnit {
        package_id: SemanticId,
        certificate_id: SemanticId,
        unit: SemanticUnit,
        quote: QuoteRecord,
        document_digest: ContentDigest,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "outcome",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ProtocolOutcome {
    Query(CantorQueryResult),
    Inspect(InspectResult),
    Fault,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolFault {
    pub class: ExitClass,
    pub code: String,
    pub stage: String,
    pub message: String,
    pub related_ids: Vec<SemanticId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolStatus {
    Success,
    Partial,
    Fault,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolContinuation {
    Finish,
    QueryOrReframe,
    Stop,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolProof {
    pub admitted_package_ids: Vec<SemanticId>,
    pub expected_package_set_verified: bool,
    pub environment_digest: Option<ContentDigest>,
    pub core_result_digest: Option<ContentDigest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolResponse {
    pub protocol_version: String,
    pub request_id: SemanticId,
    pub operation: String,
    pub status: ProtocolStatus,
    pub exit_class: ExitClass,
    pub result: ProtocolOutcome,
    pub faults: Vec<ProtocolFault>,
    pub proof: ProtocolProof,
    pub continuation: ProtocolContinuation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolVerificationFault {
    pub code: String,
    pub message: String,
}

impl ProtocolResponse {
    pub fn transport_fault(
        request_id: SemanticId,
        operation: impl Into<String>,
        class: ExitClass,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_owned(),
            request_id,
            operation: operation.into(),
            status: ProtocolStatus::Fault,
            exit_class: class,
            result: ProtocolOutcome::Fault,
            faults: vec![ProtocolFault {
                class,
                code: code.into(),
                stage: "transport".to_owned(),
                message: message.into(),
                related_ids: Vec::new(),
            }],
            proof: ProtocolProof {
                admitted_package_ids: Vec::new(),
                expected_package_set_verified: false,
                environment_digest: None,
                core_result_digest: None,
            },
            continuation: ProtocolContinuation::Stop,
        }
    }
}

pub fn verify_protocol_response(
    request: &ProtocolRequest,
    response: &ProtocolResponse,
) -> Result<(), ProtocolVerificationFault> {
    verify_protocol_envelope(request, response)?;
    let expected_continuation = match response.status {
        ProtocolStatus::Success => ProtocolContinuation::Finish,
        ProtocolStatus::Partial => ProtocolContinuation::QueryOrReframe,
        ProtocolStatus::Fault => ProtocolContinuation::Stop,
    };
    if response.continuation != expected_continuation {
        return verification_fault(
            "continuation_mismatch",
            "continuation directive is inconsistent with protocol status",
        );
    }
    match (&response.status, &response.result, response.exit_class) {
        (ProtocolStatus::Success, ProtocolOutcome::Query(result), ExitClass::Success) => {
            if !response.faults.is_empty() || !result.faults.is_empty() {
                return verification_fault(
                    "success_contains_faults",
                    "successful query response contains fault records",
                );
            }
            verify_protocol_query_result(request, response, result)
        }
        (ProtocolStatus::Partial, ProtocolOutcome::Query(result), exit_class)
            if exit_class != ExitClass::Success =>
        {
            if response.faults.is_empty() || result.faults.is_empty() {
                return verification_fault(
                    "partial_without_faults",
                    "partial query response must preserve visible protocol and query faults",
                );
            }
            if response.faults.len() != result.faults.len() {
                return verification_fault(
                    "fault_projection_mismatch",
                    "protocol fault projection differs from the core query fault set",
                );
            }
            let expected_faults = result
                .faults
                .iter()
                .map(protocol_query_fault)
                .collect::<Vec<_>>();
            if response.faults != expected_faults {
                return verification_fault(
                    "fault_projection_mismatch",
                    "protocol faults do not exactly preserve core query faults",
                );
            }
            verify_protocol_query_result(request, response, result)
        }
        (ProtocolStatus::Success, ProtocolOutcome::Inspect(result), ExitClass::Success) => {
            if !response.faults.is_empty() {
                return verification_fault(
                    "invalid_inspect_proof",
                    "successful inspection must be fault-free",
                );
            }
            let result_digest =
                sha256_digest(result).map_err(|fault| ProtocolVerificationFault {
                    code: "inspect_result_verification_failure".to_owned(),
                    message: fault.to_string(),
                })?;
            if response.proof.core_result_digest.as_ref() != Some(&result_digest) {
                return verification_fault(
                    "inspect_result_digest_mismatch",
                    "inspection result differs from its protocol proof digest",
                );
            }
            verify_protocol_inspect_result(request, result)
        }
        (ProtocolStatus::Fault, ProtocolOutcome::Fault, exit_class)
            if exit_class != ExitClass::Success =>
        {
            if response.faults.is_empty() {
                return verification_fault(
                    "fault_without_record",
                    "fault response must contain at least one structured fault",
                );
            }
            if response.proof.core_result_digest.is_some()
                || response
                    .faults
                    .iter()
                    .any(|fault| fault.class != exit_class)
            {
                return verification_fault(
                    "invalid_fault_envelope",
                    "fault response class or proof fields are inconsistent",
                );
            }
            Ok(())
        }
        _ => verification_fault(
            "status_outcome_mismatch",
            "protocol status, outcome, and exit class are inconsistent",
        ),
    }
}

pub fn verify_protocol_response_against_environment(
    environment: &EmbeddedRuntimeEnvironment,
    request: &ProtocolRequest,
    response: &ProtocolResponse,
) -> Result<(), ProtocolVerificationFault> {
    verify_protocol_response(request, response)?;
    let expected = execute_protocol_request(environment, request.clone());
    if &expected != response {
        return verification_fault(
            "response_reexecution_mismatch",
            "response differs from deterministic re-execution against the pinned environment",
        );
    }
    Ok(())
}

fn verify_protocol_envelope(
    request: &ProtocolRequest,
    response: &ProtocolResponse,
) -> Result<(), ProtocolVerificationFault> {
    if response.protocol_version != PROTOCOL_VERSION {
        return verification_fault(
            "response_protocol_mismatch",
            "response protocol version is unsupported",
        );
    }
    if response.request_id != request.request_id {
        return verification_fault(
            "response_request_mismatch",
            "response identity differs from the originating request",
        );
    }
    if response.operation != request.request.name() {
        return verification_fault(
            "response_operation_mismatch",
            "response operation differs from the originating request",
        );
    }
    if response.proof.environment_digest.as_ref() != Some(&request.expected_environment_digest) {
        return verification_fault(
            "response_environment_mismatch",
            "response does not prove the environment digest expected by the request",
        );
    }
    if response.status != ProtocolStatus::Fault {
        let expected = request
            .expected_packages
            .iter()
            .map(|package| &package.package_id)
            .collect::<BTreeSet<_>>();
        let admitted = response
            .proof
            .admitted_package_ids
            .iter()
            .collect::<BTreeSet<_>>();
        if !response.proof.expected_package_set_verified || admitted != expected {
            return verification_fault(
                "admitted_package_set_mismatch",
                "response admission proof differs from the request's expected package set",
            );
        }
    }
    Ok(())
}

fn verify_protocol_query_result(
    request: &ProtocolRequest,
    response: &ProtocolResponse,
    result: &CantorQueryResult,
) -> Result<(), ProtocolVerificationFault> {
    if result.request_id != response.request_id
        || result.protocol_version != crate::QUERY_PROTOCOL_VERSION
    {
        return verification_fault(
            "core_result_binding_mismatch",
            "core result identity or protocol differs from its protocol envelope",
        );
    }
    if response.proof.core_result_digest.as_ref() != Some(&result.result_digest) {
        return verification_fault(
            "core_result_digest_mismatch",
            "protocol proof does not bind the returned core result digest",
        );
    }
    match verify_query_result_digest(result) {
        Ok(true) => {}
        Ok(false) => {
            return verification_fault(
                "invalid_core_result_digest",
                "returned core result does not match its recomputed digest",
            );
        }
        Err(error) => {
            return verification_fault("core_result_verification_failure", error.message);
        }
    }
    let admitted = response
        .proof
        .admitted_package_ids
        .iter()
        .collect::<BTreeSet<_>>();
    if result
        .proof
        .package_proofs
        .iter()
        .any(|proof| !admitted.contains(&proof.package_id))
    {
        return verification_fault(
            "unadmitted_package_proof",
            "core result cites a package absent from protocol admission proof",
        );
    }
    let expected_digests = request
        .expected_packages
        .iter()
        .map(|package| (&package.package_id, &package.package_digest))
        .collect::<BTreeMap<_, _>>();
    if result
        .proof
        .package_proofs
        .iter()
        .any(|proof| expected_digests.get(&proof.package_id) != Some(&&proof.package_digest))
    {
        return verification_fault(
            "package_digest_proof_mismatch",
            "core result package proof differs from request package bindings",
        );
    }
    Ok(())
}

fn verify_protocol_inspect_result(
    request: &ProtocolRequest,
    result: &InspectResult,
) -> Result<(), ProtocolVerificationFault> {
    let expected = request
        .expected_packages
        .iter()
        .map(|package| (&package.package_id, &package.package_digest))
        .collect::<BTreeMap<_, _>>();
    match result {
        InspectResult::Fabric { package_ids, .. } => {
            let actual = package_ids.iter().collect::<BTreeSet<_>>();
            let expected_ids = expected.keys().copied().collect::<BTreeSet<_>>();
            if actual != expected_ids {
                return verification_fault(
                    "inspect_package_set_mismatch",
                    "fabric inspection differs from expected package identities",
                );
            }
        }
        InspectResult::Package { package_proof, .. } => {
            if expected.get(&package_proof.package_id) != Some(&&package_proof.package_digest) {
                return verification_fault(
                    "inspect_package_digest_mismatch",
                    "package inspection differs from expected package binding",
                );
            }
        }
        InspectResult::Certificate {
            package_id,
            certificate,
        } => {
            if expected.get(package_id) != Some(&&certificate.package_digest) {
                return verification_fault(
                    "inspect_certificate_digest_mismatch",
                    "certificate inspection differs from expected package binding",
                );
            }
        }
        InspectResult::SemanticUnit { package_id, .. } => {
            if !expected.contains_key(package_id) {
                return verification_fault(
                    "inspect_unit_package_mismatch",
                    "semantic-unit inspection cites an unexpected package",
                );
            }
        }
    }
    Ok(())
}

fn verification_fault<T>(
    code: impl Into<String>,
    message: impl Into<String>,
) -> Result<T, ProtocolVerificationFault> {
    Err(ProtocolVerificationFault {
        code: code.into(),
        message: message.into(),
    })
}

pub fn execute_protocol_request(
    environment: &EmbeddedRuntimeEnvironment,
    request: ProtocolRequest,
) -> ProtocolResponse {
    if environment.environment_version != EMBEDDED_ENVIRONMENT_VERSION {
        return unsupported_environment_response(environment, &request);
    }
    let environment_digest = match embedded_environment_digest(environment) {
        Ok(digest) => digest,
        Err(fault) => {
            return request_fault(
                &request,
                request.request.name().to_owned(),
                ExitClass::InternalFault,
                "environment_digest_failure",
                fault.to_string(),
                None,
            );
        }
    };
    if let Err(response) = validate_protocol_request(environment, &request, &environment_digest) {
        return *response;
    }
    let fabric = match prepare_protocol_fabric(environment, &request, &environment_digest) {
        Ok(fabric) => fabric,
        Err(response) => return *response,
    };
    execute_protocol_fabric(&fabric, &request, &environment_digest)
}

pub(crate) fn validate_protocol_request(
    environment: &EmbeddedRuntimeEnvironment,
    request: &ProtocolRequest,
    environment_digest: &ContentDigest,
) -> Result<(), Box<ProtocolResponse>> {
    if environment.environment_version != EMBEDDED_ENVIRONMENT_VERSION {
        return Err(Box::new(unsupported_environment_response(
            environment,
            request,
        )));
    }
    let operation = request.request.name().to_owned();
    if &request.expected_environment_digest != environment_digest {
        return Err(Box::new(request_fault(
            request,
            operation,
            ExitClass::TrustFailure,
            "environment_digest_mismatch",
            "runtime environment differs from the digest bound into the request",
            Some(environment_digest),
        )));
    }
    if request.protocol_version != PROTOCOL_VERSION {
        return Err(Box::new(request_fault(
            request,
            operation,
            ExitClass::InvalidRequest,
            "unsupported_protocol",
            format!(
                "protocol {} is unsupported; expected {PROTOCOL_VERSION}",
                request.protocol_version
            ),
            Some(environment_digest),
        )));
    }
    if request.caller_context.purpose.trim().is_empty()
        || request.caller_context.effect_boundary != "read_only"
    {
        return Err(Box::new(request_fault(
            request,
            operation,
            ExitClass::PolicyDenial,
            "caller_context_denied",
            "caller purpose is required and effect boundary must be read_only",
            Some(environment_digest),
        )));
    }
    if environment.packages.is_empty() || request.expected_packages.is_empty() {
        return Err(Box::new(request_fault(
            request,
            operation,
            ExitClass::InvalidRequest,
            "package_set_empty",
            "at least one package and expected package binding are required",
            Some(environment_digest),
        )));
    }
    if let Err(message) = verify_expected_package_set(environment, request) {
        return Err(Box::new(request_fault(
            request,
            operation,
            ExitClass::TrustFailure,
            "expected_package_mismatch",
            message,
            Some(environment_digest),
        )));
    }
    Ok(())
}

pub(crate) fn prepare_protocol_fabric(
    environment: &EmbeddedRuntimeEnvironment,
    request: &ProtocolRequest,
    environment_digest: &ContentDigest,
) -> Result<SemanticFabric, Box<ProtocolResponse>> {
    let operation = request.request.name().to_owned();
    let mut admitted = Vec::with_capacity(environment.packages.len());
    for package in &environment.packages {
        match admit_package(
            package,
            &environment.trust_store,
            &request.requested_scope,
            environment.now_epoch_seconds,
        ) {
            Ok(package) => admitted.push(package),
            Err(fault) => {
                return Err(Box::new(trust_fault(
                    request,
                    operation,
                    fault,
                    environment_digest,
                )));
            }
        }
    }
    SemanticFabric::from_admitted(admitted)
        .map_err(|fault| Box::new(query_failure(request, operation, fault, environment_digest)))
}

pub(crate) fn execute_protocol_fabric(
    fabric: &SemanticFabric,
    request: &ProtocolRequest,
    environment_digest: &ContentDigest,
) -> ProtocolResponse {
    let operation = request.request.name().to_owned();
    let admitted_package_ids = fabric.package_ids().cloned().collect::<Vec<_>>();

    match &request.request {
        ProtocolOperation::Query { query } => {
            if query.request_id != request.request_id
                || query.authority_context.caller_id != request.caller_context.caller_id
                || query.purpose != request.caller_context.purpose
            {
                return request_fault(
                    request,
                    operation,
                    ExitClass::PolicyDenial,
                    "envelope_binding_mismatch",
                    "query request, caller, and purpose must be bound to the protocol envelope",
                    Some(environment_digest),
                );
            }
            let requested_package_scopes = request
                .requested_scope
                .projects
                .iter()
                .chain(request.requested_scope.namespaces.iter())
                .collect::<BTreeSet<_>>();
            if !query
                .authority_context
                .allowed_package_scopes
                .iter()
                .all(|scope| requested_package_scopes.contains(scope))
            {
                return request_fault(
                    request,
                    operation,
                    ExitClass::PolicyDenial,
                    "query_scope_exceeds_envelope",
                    "query package scopes must be a subset of the protocol request scope",
                    Some(environment_digest),
                );
            }
            match execute_query(fabric, query) {
                Ok(result) => {
                    let exit_class = classify_query_faults(&result.faults);
                    let status = if result.faults.is_empty() {
                        ProtocolStatus::Success
                    } else {
                        ProtocolStatus::Partial
                    };
                    let faults = result
                        .faults
                        .iter()
                        .map(protocol_query_fault)
                        .collect::<Vec<_>>();
                    ProtocolResponse {
                        protocol_version: PROTOCOL_VERSION.to_owned(),
                        request_id: request.request_id.clone(),
                        operation,
                        status,
                        exit_class,
                        proof: ProtocolProof {
                            admitted_package_ids,
                            expected_package_set_verified: true,
                            environment_digest: Some(environment_digest.clone()),
                            core_result_digest: Some(result.result_digest.clone()),
                        },
                        result: ProtocolOutcome::Query(result),
                        faults,
                        continuation: if exit_class == ExitClass::Success {
                            ProtocolContinuation::Finish
                        } else {
                            ProtocolContinuation::QueryOrReframe
                        },
                    }
                }
                Err(fault) => query_failure(request, operation, fault, environment_digest),
            }
        }
        ProtocolOperation::Inspect { inspect } => match inspect_fabric(fabric, inspect) {
            Ok(result) => {
                let result_digest = match sha256_digest(&result) {
                    Ok(digest) => digest,
                    Err(fault) => {
                        return request_fault(
                            request,
                            operation,
                            ExitClass::InternalFault,
                            "inspect_result_digest_failure",
                            fault.to_string(),
                            Some(environment_digest),
                        );
                    }
                };
                ProtocolResponse {
                    protocol_version: PROTOCOL_VERSION.to_owned(),
                    request_id: request.request_id.clone(),
                    operation,
                    status: ProtocolStatus::Success,
                    exit_class: ExitClass::Success,
                    result: ProtocolOutcome::Inspect(result),
                    faults: Vec::new(),
                    proof: ProtocolProof {
                        admitted_package_ids,
                        expected_package_set_verified: true,
                        environment_digest: Some(environment_digest.clone()),
                        core_result_digest: Some(result_digest),
                    },
                    continuation: ProtocolContinuation::Finish,
                }
            }
            Err(fault) => query_failure(request, operation, fault, environment_digest),
        },
    }
}

fn unsupported_environment_response(
    environment: &EmbeddedRuntimeEnvironment,
    request: &ProtocolRequest,
) -> ProtocolResponse {
    request_fault(
        request,
        request.request.name().to_owned(),
        ExitClass::TrustFailure,
        "unsupported_environment",
        format!(
            "environment {} is unsupported; expected {EMBEDDED_ENVIRONMENT_VERSION}",
            environment.environment_version
        ),
        None,
    )
}

fn verify_expected_package_set(
    environment: &EmbeddedRuntimeEnvironment,
    request: &ProtocolRequest,
) -> Result<(), String> {
    let expected = request
        .expected_packages
        .iter()
        .map(|package| (package.package_id.clone(), package.package_digest.clone()))
        .collect::<BTreeMap<_, _>>();
    if expected.len() != request.expected_packages.len() {
        return Err(
            "expected package identities must be unique and exactly cover input packages"
                .to_owned(),
        );
    }
    let mut actual = BTreeMap::new();
    for package in &environment.packages {
        let certificate = package
            .certificate
            .as_ref()
            .ok_or_else(|| format!("package {} is unsigned", package.package_id))?;
        if actual
            .insert(
                package.package_id.clone(),
                certificate.package_digest.clone(),
            )
            .is_some()
        {
            return Err(format!(
                "environment repeats package identity {}",
                package.package_id
            ));
        }
    }
    if actual != expected {
        return Err("environment package set differs from expected package bindings".to_owned());
    }
    Ok(())
}

fn inspect_fabric(
    fabric: &SemanticFabric,
    request: &InspectRequest,
) -> Result<InspectResult, QueryFault> {
    match request {
        InspectRequest::Fabric => Ok(InspectResult::Fabric {
            metrics: fabric.metrics()?,
            package_ids: fabric.package_ids().cloned().collect(),
        }),
        InspectRequest::Package { package_id } => {
            let package = fabric.package(package_id).ok_or_else(|| {
                QueryFault::new(
                    QueryFaultKind::UnknownIdentity,
                    "inspect",
                    format!("unknown admitted package {package_id}"),
                    vec![package_id.clone()],
                )
            })?;
            Ok(InspectResult::Package {
                package_proof: package_proof(package)?,
                semantic_unit_ids: package
                    .content()
                    .semantic_units
                    .iter()
                    .map(|unit| unit.unit_id.clone())
                    .collect(),
                relation_ids: package
                    .content()
                    .relations
                    .iter()
                    .map(|relation| relation.relation_id.clone())
                    .collect(),
            })
        }
        InspectRequest::Certificate { package_id } => {
            let package = fabric.package(package_id).ok_or_else(|| {
                QueryFault::new(
                    QueryFaultKind::UnknownIdentity,
                    "inspect",
                    format!("unknown admitted package {package_id}"),
                    vec![package_id.clone()],
                )
            })?;
            let certificate = package.package().certificate.clone().ok_or_else(|| {
                QueryFault::new(
                    QueryFaultKind::ProofGap,
                    "inspect",
                    "admitted package has no certificate",
                    vec![package_id.clone()],
                )
            })?;
            Ok(InspectResult::Certificate {
                package_id: package_id.clone(),
                certificate,
            })
        }
        InspectRequest::SemanticUnit { unit_id } => {
            let package = fabric.package_for_unit(unit_id).ok_or_else(|| {
                QueryFault::new(
                    QueryFaultKind::UnknownIdentity,
                    "inspect",
                    format!("unknown semantic unit {unit_id}"),
                    vec![unit_id.clone()],
                )
            })?;
            let unit = package.semantic_unit(unit_id).cloned().ok_or_else(|| {
                QueryFault::new(
                    QueryFaultKind::ProofGap,
                    "inspect",
                    "unit index does not resolve in its admitted package",
                    vec![unit_id.clone()],
                )
            })?;
            let quote = package.quote(unit_id).cloned().ok_or_else(|| {
                QueryFault::new(
                    QueryFaultKind::ProofGap,
                    "inspect",
                    "semantic unit has no admitted quote",
                    vec![unit_id.clone()],
                )
            })?;
            let document_digest = package
                .content()
                .sources
                .iter()
                .find(|source| source.file_id == quote.anchor.file_id)
                .map(|source| source.document_digest.clone())
                .ok_or_else(|| {
                    QueryFault::new(
                        QueryFaultKind::ProofGap,
                        "inspect",
                        "semantic-unit quote has no signed source snapshot",
                        vec![unit_id.clone()],
                    )
                })?;
            Ok(InspectResult::SemanticUnit {
                package_id: package.package().package_id.clone(),
                certificate_id: package.certificate_id().clone(),
                unit,
                quote,
                document_digest,
            })
        }
    }
}

fn package_proof(package: &crate::AdmittedPackage) -> Result<PackageProofRecord, QueryFault> {
    let certificate = package.package().certificate.as_ref().ok_or_else(|| {
        QueryFault::new(
            QueryFaultKind::ProofGap,
            "inspect",
            "admitted package has no certificate",
            vec![package.package().package_id.clone()],
        )
    })?;
    Ok(PackageProofRecord {
        package_id: package.package().package_id.clone(),
        certificate_id: certificate.certificate_id.clone(),
        package_digest: certificate.package_digest.clone(),
        semantic_root_digest: certificate.semantic_root_digest.clone(),
        source_root_digest: certificate.source_root_digest.clone(),
        authority_signer_id: certificate.authority_signer_id.clone(),
        compiler_signer_id: certificate.compiler_signer_id.clone(),
        admitted_at_epoch_seconds: package.admitted_at_epoch_seconds(),
    })
}

fn classify_query_faults(faults: &[QueryFault]) -> ExitClass {
    if faults.iter().any(|fault| {
        matches!(
            fault.kind,
            QueryFaultKind::ProofGap
                | QueryFaultKind::Contradiction
                | QueryFaultKind::BudgetExhausted
        )
    }) {
        ExitClass::SemanticFault
    } else if faults
        .iter()
        .any(|fault| fault.kind == QueryFaultKind::Unauthorized)
    {
        ExitClass::PolicyDenial
    } else if faults
        .iter()
        .any(|fault| fault.kind == QueryFaultKind::InvalidRequest)
    {
        ExitClass::InvalidRequest
    } else if faults.is_empty() {
        ExitClass::Success
    } else {
        ExitClass::Unresolved
    }
}

fn protocol_query_fault(fault: &QueryFault) -> ProtocolFault {
    let class = classify_query_faults(std::slice::from_ref(fault));
    ProtocolFault {
        class,
        code: format!("{:?}", fault.kind),
        stage: fault.stage.clone(),
        message: fault.message.clone(),
        related_ids: fault.related_ids.clone(),
    }
}

fn trust_fault(
    request: &ProtocolRequest,
    operation: String,
    fault: TrustFault,
    environment_digest: &ContentDigest,
) -> ProtocolResponse {
    ProtocolResponse {
        protocol_version: PROTOCOL_VERSION.to_owned(),
        request_id: request.request_id.clone(),
        operation,
        status: ProtocolStatus::Fault,
        exit_class: ExitClass::TrustFailure,
        result: ProtocolOutcome::Fault,
        faults: vec![ProtocolFault {
            class: ExitClass::TrustFailure,
            code: format!("{:?}", fault.kind),
            stage: fault.gate,
            message: fault.message,
            related_ids: Vec::new(),
        }],
        proof: ProtocolProof {
            admitted_package_ids: Vec::new(),
            expected_package_set_verified: true,
            environment_digest: Some(environment_digest.clone()),
            core_result_digest: None,
        },
        continuation: ProtocolContinuation::Stop,
    }
}

fn query_failure(
    request: &ProtocolRequest,
    operation: String,
    fault: QueryFault,
    environment_digest: &ContentDigest,
) -> ProtocolResponse {
    let protocol_fault = protocol_query_fault(&fault);
    ProtocolResponse {
        protocol_version: PROTOCOL_VERSION.to_owned(),
        request_id: request.request_id.clone(),
        operation,
        status: ProtocolStatus::Fault,
        exit_class: protocol_fault.class,
        result: ProtocolOutcome::Fault,
        faults: vec![protocol_fault],
        proof: ProtocolProof {
            admitted_package_ids: Vec::new(),
            expected_package_set_verified: true,
            environment_digest: Some(environment_digest.clone()),
            core_result_digest: None,
        },
        continuation: ProtocolContinuation::Stop,
    }
}

fn request_fault(
    request: &ProtocolRequest,
    operation: String,
    class: ExitClass,
    code: impl Into<String>,
    message: impl Into<String>,
    environment_digest: Option<&ContentDigest>,
) -> ProtocolResponse {
    ProtocolResponse {
        protocol_version: PROTOCOL_VERSION.to_owned(),
        request_id: request.request_id.clone(),
        operation,
        status: ProtocolStatus::Fault,
        exit_class: class,
        result: ProtocolOutcome::Fault,
        faults: vec![ProtocolFault {
            class,
            code: code.into(),
            stage: "request_validation".to_owned(),
            message: message.into(),
            related_ids: Vec::new(),
        }],
        proof: ProtocolProof {
            admitted_package_ids: Vec::new(),
            expected_package_set_verified: false,
            environment_digest: environment_digest.cloned(),
            core_result_digest: None,
        },
        continuation: ProtocolContinuation::Stop,
    }
}

pub fn embedded_environment_digest(
    environment: &EmbeddedRuntimeEnvironment,
) -> Result<ContentDigest, TrustFault> {
    sha256_digest(environment)
}
