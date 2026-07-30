//! Bounded resident preparation for Cantor's deterministic protocol.
//!
//! A prepared runtime is a physical execution optimization. It does not mint
//! semantic authority: every request must still carry the exact environment,
//! package, caller, purpose, effect, and scope bindings required by the direct
//! protocol path.

use std::{
    fmt,
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
};

use serde::{Deserialize, Serialize};

use crate::protocol::{
    execute_protocol_fabric, prepare_protocol_fabric, validate_protocol_request,
};
use crate::{
    AuthorityScope, ContentDigest, EmbeddedRuntimeEnvironment, ExitClass, ProtocolContinuation,
    ProtocolFault, ProtocolOutcome, ProtocolProof, ProtocolRequest, ProtocolResponse,
    ProtocolStatus, SemanticFabric, embedded_environment_digest, sha256_digest,
};

pub const PREPARED_RUNTIME_PROFILE: &str = "cantor-prepared-runtime/0.1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeGeneration {
    pub profile: String,
    pub protocol_version: String,
    pub environment_version: String,
    pub environment_digest: ContentDigest,
    pub generation_id: ContentDigest,
    pub pinned_trust_time: u64,
    pub ordered_package_ids: Vec<crate::SemanticId>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedRuntimeMetrics {
    pub projection_hits: u64,
    pub projection_misses: u64,
    pub projection_preparations: u64,
    pub projection_replacements: u64,
    pub executions: u64,
}

#[derive(Debug, Default)]
struct RuntimeCounters {
    projection_hits: AtomicU64,
    projection_misses: AtomicU64,
    projection_preparations: AtomicU64,
    projection_replacements: AtomicU64,
    executions: AtomicU64,
}

impl RuntimeCounters {
    fn snapshot(&self) -> PreparedRuntimeMetrics {
        PreparedRuntimeMetrics {
            projection_hits: self.projection_hits.load(Ordering::Relaxed),
            projection_misses: self.projection_misses.load(Ordering::Relaxed),
            projection_preparations: self.projection_preparations.load(Ordering::Relaxed),
            projection_replacements: self.projection_replacements.load(Ordering::Relaxed),
            executions: self.executions.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Debug)]
struct ScopeProjection {
    scope: AuthorityScope,
    fabric: SemanticFabric,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedRuntimeFault {
    pub code: String,
    pub message: String,
}

impl PreparedRuntimeFault {
    fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for PreparedRuntimeFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for PreparedRuntimeFault {}

pub struct PreparedRuntime {
    environment: Arc<EmbeddedRuntimeEnvironment>,
    generation: RuntimeGeneration,
    projection: RwLock<Option<Arc<ScopeProjection>>>,
    counters: RuntimeCounters,
}

impl fmt::Debug for PreparedRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedRuntime")
            .field("generation", &self.generation)
            .field("metrics", &self.metrics())
            .finish_non_exhaustive()
    }
}

impl PreparedRuntime {
    pub fn new(environment: EmbeddedRuntimeEnvironment) -> Result<Self, PreparedRuntimeFault> {
        Self::from_shared(Arc::new(environment))
    }

    pub fn from_shared(
        environment: Arc<EmbeddedRuntimeEnvironment>,
    ) -> Result<Self, PreparedRuntimeFault> {
        let environment_digest = embedded_environment_digest(&environment).map_err(|fault| {
            PreparedRuntimeFault::new("environment_digest_failure", fault.to_string())
        })?;
        let generation_id = sha256_digest(&(
            PREPARED_RUNTIME_PROFILE,
            crate::PROTOCOL_VERSION,
            environment.environment_version.as_str(),
            &environment_digest,
        ))
        .map_err(|fault| {
            PreparedRuntimeFault::new("generation_digest_failure", fault.to_string())
        })?;
        let generation = RuntimeGeneration {
            profile: PREPARED_RUNTIME_PROFILE.to_owned(),
            protocol_version: crate::PROTOCOL_VERSION.to_owned(),
            environment_version: environment.environment_version.clone(),
            environment_digest,
            generation_id,
            pinned_trust_time: environment.now_epoch_seconds,
            ordered_package_ids: environment
                .packages
                .iter()
                .map(|package| package.package_id.clone())
                .collect(),
        };
        Ok(Self {
            environment,
            generation,
            projection: RwLock::new(None),
            counters: RuntimeCounters::default(),
        })
    }

    pub fn prepare(
        environment: EmbeddedRuntimeEnvironment,
        binding_request: &ProtocolRequest,
    ) -> Result<Self, PreparedRuntimeActivationFault> {
        let runtime = Self::new(environment).map_err(PreparedRuntimeActivationFault::Runtime)?;
        runtime
            .prime(binding_request)
            .map_err(PreparedRuntimeActivationFault::Protocol)?;
        Ok(runtime)
    }

    pub fn environment(&self) -> &EmbeddedRuntimeEnvironment {
        &self.environment
    }

    pub const fn generation(&self) -> &RuntimeGeneration {
        &self.generation
    }

    pub fn metrics(&self) -> PreparedRuntimeMetrics {
        self.counters.snapshot()
    }

    pub fn prepared_scope(&self) -> Result<Option<AuthorityScope>, PreparedRuntimeFault> {
        self.projection
            .read()
            .map(|projection| {
                projection
                    .as_ref()
                    .map(|projection| projection.scope.clone())
            })
            .map_err(|_| {
                PreparedRuntimeFault::new(
                    "projection_lock_poisoned",
                    "prepared projection state is unavailable",
                )
            })
    }

    pub fn prime(&self, request: &ProtocolRequest) -> Result<(), Box<ProtocolResponse>> {
        validate_protocol_request(
            &self.environment,
            request,
            &self.generation.environment_digest,
        )?;
        self.acquire_projection(request).map(|_| ())
    }

    pub fn execute(&self, request: ProtocolRequest) -> ProtocolResponse {
        self.counters.executions.fetch_add(1, Ordering::Relaxed);
        if let Err(response) = validate_protocol_request(
            &self.environment,
            &request,
            &self.generation.environment_digest,
        ) {
            return *response;
        }
        let projection = match self.acquire_projection(&request) {
            Ok(projection) => projection,
            Err(response) => return *response,
        };
        // The Arc snapshot is acquired before this call, so neither the
        // projection lock nor a generation-slot lock is held during semantic
        // query or inspection execution.
        execute_protocol_fabric(
            &projection.fabric,
            &request,
            &self.generation.environment_digest,
        )
    }

    fn acquire_projection(
        &self,
        request: &ProtocolRequest,
    ) -> Result<Arc<ScopeProjection>, Box<ProtocolResponse>> {
        let read = self.projection.read().map_err(|_| {
            Box::new(runtime_protocol_fault(
                request,
                Some(&self.generation.environment_digest),
                "projection_lock_poisoned",
                "prepared projection state is unavailable",
            ))
        })?;
        if let Some(projection) = read
            .as_ref()
            .filter(|projection| projection.scope == request.requested_scope)
        {
            self.counters
                .projection_hits
                .fetch_add(1, Ordering::Relaxed);
            return Ok(Arc::clone(projection));
        }
        drop(read);
        self.counters
            .projection_misses
            .fetch_add(1, Ordering::Relaxed);

        let mut write = self.projection.write().map_err(|_| {
            Box::new(runtime_protocol_fault(
                request,
                Some(&self.generation.environment_digest),
                "projection_lock_poisoned",
                "prepared projection state is unavailable",
            ))
        })?;
        if let Some(projection) = write
            .as_ref()
            .filter(|projection| projection.scope == request.requested_scope)
        {
            self.counters
                .projection_hits
                .fetch_add(1, Ordering::Relaxed);
            return Ok(Arc::clone(projection));
        }

        let fabric = prepare_protocol_fabric(
            &self.environment,
            request,
            &self.generation.environment_digest,
        )?;
        let replacement = Arc::new(ScopeProjection {
            scope: request.requested_scope.clone(),
            fabric,
        });
        if write.is_some() {
            self.counters
                .projection_replacements
                .fetch_add(1, Ordering::Relaxed);
        }
        self.counters
            .projection_preparations
            .fetch_add(1, Ordering::Relaxed);
        *write = Some(Arc::clone(&replacement));
        Ok(replacement)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PreparedRuntimeActivationFault {
    Runtime(PreparedRuntimeFault),
    Protocol(Box<ProtocolResponse>),
}

impl fmt::Display for PreparedRuntimeActivationFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Runtime(fault) => write!(formatter, "{fault}"),
            Self::Protocol(response) => {
                let code = response
                    .faults
                    .first()
                    .map_or("protocol_fault", |fault| fault.code.as_str());
                write!(
                    formatter,
                    "{code}: replacement binding request was rejected"
                )
            }
        }
    }
}

impl std::error::Error for PreparedRuntimeActivationFault {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeTransitionDisposition {
    Activated,
    Invalidated,
    InvalidatedAfterFailedReplacement,
    RolledBack,
    RejectedStaleExpectation,
    RejectedUnavailable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeTransitionReceipt {
    pub previous_generation: Option<ContentDigest>,
    pub next_generation: Option<ContentDigest>,
    pub disposition: RuntimeTransitionDisposition,
    pub fault: Option<PreparedRuntimeFault>,
}

#[derive(Debug, Default)]
pub struct PreparedRuntimeSlot {
    active: RwLock<Option<Arc<PreparedRuntime>>>,
}

impl PreparedRuntimeSlot {
    pub const fn new() -> Self {
        Self {
            active: RwLock::new(None),
        }
    }

    pub fn with_active(runtime: PreparedRuntime) -> Self {
        Self {
            active: RwLock::new(Some(Arc::new(runtime))),
        }
    }

    pub fn active_generation(&self) -> Result<Option<ContentDigest>, PreparedRuntimeFault> {
        self.active
            .read()
            .map(|active| {
                active
                    .as_ref()
                    .map(|runtime| runtime.generation().generation_id.clone())
            })
            .map_err(|_| slot_lock_fault())
    }

    pub fn execute(
        &self,
        request: ProtocolRequest,
    ) -> Result<ProtocolResponse, PreparedRuntimeFault> {
        let runtime = {
            let active = self.active.read().map_err(|_| slot_lock_fault())?;
            active.as_ref().cloned().ok_or_else(|| {
                PreparedRuntimeFault::new(
                    "runtime_unavailable",
                    "no prepared runtime generation is active",
                )
            })?
        };
        // The slot lock is released when the read guard above is dropped.
        Ok(runtime.execute(request))
    }

    pub fn replace(
        &self,
        expected_generation: Option<&ContentDigest>,
        replacement: PreparedRuntime,
    ) -> RuntimeTransitionReceipt {
        self.install(
            expected_generation,
            Some(Arc::new(replacement)),
            RuntimeTransitionDisposition::Activated,
        )
    }

    pub fn rollback(
        &self,
        expected_generation: Option<&ContentDigest>,
        replacement: PreparedRuntime,
    ) -> RuntimeTransitionReceipt {
        self.install(
            expected_generation,
            Some(Arc::new(replacement)),
            RuntimeTransitionDisposition::RolledBack,
        )
    }

    pub fn invalidate(
        &self,
        expected_generation: Option<&ContentDigest>,
    ) -> RuntimeTransitionReceipt {
        self.install(
            expected_generation,
            None,
            RuntimeTransitionDisposition::Invalidated,
        )
    }

    pub fn replace_or_invalidate(
        &self,
        expected_generation: Option<&ContentDigest>,
        replacement_environment: EmbeddedRuntimeEnvironment,
        binding_request: &ProtocolRequest,
    ) -> RuntimeTransitionReceipt {
        match PreparedRuntime::prepare(replacement_environment, binding_request) {
            Ok(replacement) => self.replace(expected_generation, replacement),
            Err(fault) => {
                let mut receipt = self.install(
                    expected_generation,
                    None,
                    RuntimeTransitionDisposition::InvalidatedAfterFailedReplacement,
                );
                if receipt.disposition
                    == RuntimeTransitionDisposition::InvalidatedAfterFailedReplacement
                {
                    receipt.fault = Some(activation_fault_record(fault));
                }
                receipt
            }
        }
    }

    fn install(
        &self,
        expected_generation: Option<&ContentDigest>,
        replacement: Option<Arc<PreparedRuntime>>,
        disposition: RuntimeTransitionDisposition,
    ) -> RuntimeTransitionReceipt {
        let mut active = match self.active.write() {
            Ok(active) => active,
            Err(_) => {
                return RuntimeTransitionReceipt {
                    previous_generation: None,
                    next_generation: None,
                    disposition: RuntimeTransitionDisposition::RejectedUnavailable,
                    fault: Some(slot_lock_fault()),
                };
            }
        };
        let previous_generation = active
            .as_ref()
            .map(|runtime| runtime.generation().generation_id.clone());
        if previous_generation.as_ref() != expected_generation {
            return RuntimeTransitionReceipt {
                previous_generation: previous_generation.clone(),
                next_generation: previous_generation,
                disposition: RuntimeTransitionDisposition::RejectedStaleExpectation,
                fault: Some(PreparedRuntimeFault::new(
                    "stale_generation_expectation",
                    "active generation differs from the transition expectation",
                )),
            };
        }
        let next_generation = replacement
            .as_ref()
            .map(|runtime| runtime.generation().generation_id.clone());
        *active = replacement;
        RuntimeTransitionReceipt {
            previous_generation,
            next_generation,
            disposition,
            fault: None,
        }
    }
}

fn activation_fault_record(fault: PreparedRuntimeActivationFault) -> PreparedRuntimeFault {
    match fault {
        PreparedRuntimeActivationFault::Runtime(fault) => fault,
        PreparedRuntimeActivationFault::Protocol(response) => {
            let protocol_fault = response.faults.first();
            PreparedRuntimeFault::new(
                protocol_fault.map_or("replacement_protocol_fault", |fault| fault.code.as_str()),
                protocol_fault.map_or("replacement binding request was rejected", |fault| {
                    fault.message.as_str()
                }),
            )
        }
    }
}

fn slot_lock_fault() -> PreparedRuntimeFault {
    PreparedRuntimeFault::new(
        "runtime_slot_lock_poisoned",
        "prepared runtime generation slot is unavailable",
    )
}

fn runtime_protocol_fault(
    request: &ProtocolRequest,
    environment_digest: Option<&ContentDigest>,
    code: impl Into<String>,
    message: impl Into<String>,
) -> ProtocolResponse {
    ProtocolResponse {
        protocol_version: crate::PROTOCOL_VERSION.to_owned(),
        request_id: request.request_id.clone(),
        operation: request.request.name().to_owned(),
        status: ProtocolStatus::Fault,
        exit_class: ExitClass::InternalFault,
        result: ProtocolOutcome::Fault,
        faults: vec![ProtocolFault {
            class: ExitClass::InternalFault,
            code: code.into(),
            stage: "prepared_runtime".to_owned(),
            message: message.into(),
            related_ids: Vec::new(),
        }],
        proof: ProtocolProof {
            admitted_package_ids: Vec::new(),
            expected_package_set_verified: true,
            environment_digest: environment_digest.cloned(),
            core_result_digest: None,
        },
        continuation: ProtocolContinuation::Stop,
    }
}
