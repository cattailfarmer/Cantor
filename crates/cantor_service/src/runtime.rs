use std::{
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Instant,
};

use cantor_core::{
    ContentDigest, PreparedRuntime, RuntimeTransitionDisposition, RuntimeTransitionReceipt,
};

use crate::{
    artifacts::{LoadedGeneration, SecretToken, ValidatedServiceConfig, load_generation},
    model::{
        ActiveBinding, SERVICE_PROFILE, SERVICE_PROTOCOL_VERSION, ServiceFault, ServiceOperation,
        ServiceRequest, ServiceResponse, ServiceResult, ServiceStatus,
    },
};

#[derive(Debug)]
struct ActiveServiceGeneration {
    runtime: Arc<PreparedRuntime>,
    binding: ActiveBinding,
}

#[derive(Debug, Default)]
struct ServiceCounters {
    accepted_connections: AtomicU64,
    rejected_connections: AtomicU64,
    worker_panics: AtomicU64,
    completed_requests: AtomicU64,
    successful_refreshes: AtomicU64,
}

#[derive(Debug)]
pub struct ServiceRuntime {
    config: ValidatedServiceConfig,
    token: SecretToken,
    active: RwLock<Arc<ActiveServiceGeneration>>,
    counters: ServiceCounters,
    started_at: Instant,
    shutdown_requested: AtomicBool,
}

impl ServiceRuntime {
    pub fn new(
        config: ValidatedServiceConfig,
        token: SecretToken,
        loaded: LoadedGeneration,
    ) -> Self {
        Self {
            config,
            token,
            active: RwLock::new(Arc::new(ActiveServiceGeneration {
                binding: loaded.binding(),
                runtime: Arc::new(loaded.runtime),
            })),
            counters: ServiceCounters::default(),
            started_at: Instant::now(),
            shutdown_requested: AtomicBool::new(false),
        }
    }

    pub const fn config(&self) -> &ValidatedServiceConfig {
        &self.config
    }

    pub fn record_accepted_connection(&self) {
        self.counters
            .accepted_connections
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_rejected_connection(&self) {
        self.counters
            .rejected_connections
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_worker_panic(&self) {
        self.counters.worker_panics.fetch_add(1, Ordering::Relaxed);
    }

    pub fn shutdown_requested(&self) -> bool {
        self.shutdown_requested.load(Ordering::Acquire)
    }

    pub fn active_binding(&self) -> Result<ActiveBinding, ServiceFault> {
        self.active_snapshot().map(|active| active.binding.clone())
    }

    pub fn dispatch(&self, request: ServiceRequest) -> ServiceResponse {
        let request_id = request.request_id.clone();
        let authenticated = self.token.matches(&request.auth_token);
        let response = self.dispatch_inner(request);
        self.counters
            .completed_requests
            .fetch_add(1, Ordering::Relaxed);
        match response {
            Ok((binding, result)) => ServiceResponse::success(request_id, binding, result),
            Err(fault) => {
                let binding = authenticated.then(|| self.active_binding().ok()).flatten();
                ServiceResponse::fault(request_id, binding, fault)
            }
        }
    }

    fn dispatch_inner(
        &self,
        request: ServiceRequest,
    ) -> Result<(ActiveBinding, ServiceResult), ServiceFault> {
        if !self.token.matches(&request.auth_token) {
            return Err(ServiceFault::new(
                "authentication_failed",
                "authentication",
                "caller authentication failed",
            ));
        }
        if request.protocol_version != SERVICE_PROTOCOL_VERSION {
            return Err(ServiceFault::new(
                "unsupported_service_protocol",
                "request_validation",
                format!(
                    "expected {SERVICE_PROTOCOL_VERSION}, received {}",
                    request.protocol_version
                ),
            ));
        }
        match request.operation {
            ServiceOperation::Status => {
                let active = self.active_snapshot()?;
                let binding = active.binding.clone();
                let status = self.status_from(&active)?;
                Ok((
                    binding,
                    ServiceResult::Status {
                        status: Box::new(status),
                    },
                ))
            }
            ServiceOperation::Execute { request } => {
                let active = self.active_snapshot()?;
                let binding = active.binding.clone();
                let response = active.runtime.execute(*request);
                Ok((
                    binding,
                    ServiceResult::Protocol {
                        response: Box::new(response),
                    },
                ))
            }
            ServiceOperation::Refresh {
                expected_generation_id,
                expected_activation_sequence,
            } => self.refresh(&expected_generation_id, expected_activation_sequence),
            ServiceOperation::Shutdown {
                expected_generation_id,
            } => {
                let binding = self.request_shutdown(&expected_generation_id)?;
                Ok((binding.clone(), ServiceResult::Shutdown { binding }))
            }
        }
    }

    fn status_from(&self, active: &ActiveServiceGeneration) -> Result<ServiceStatus, ServiceFault> {
        let elapsed = self.started_at.elapsed().as_millis();
        Ok(ServiceStatus {
            service_profile: SERVICE_PROFILE.to_owned(),
            active_binding: active.binding.clone(),
            runtime_generation: active.runtime.generation().clone(),
            runtime_metrics: active.runtime.metrics(),
            ordered_package_ids: active.runtime.generation().ordered_package_ids.clone(),
            uptime_milliseconds: u64::try_from(elapsed).unwrap_or(u64::MAX),
            accepted_connections: self.counters.accepted_connections.load(Ordering::Relaxed),
            rejected_connections: self.counters.rejected_connections.load(Ordering::Relaxed),
            worker_panics: self.counters.worker_panics.load(Ordering::Relaxed),
            completed_requests: self.counters.completed_requests.load(Ordering::Relaxed),
            successful_refreshes: self.counters.successful_refreshes.load(Ordering::Relaxed),
        })
    }

    fn refresh(
        &self,
        expected_generation_id: &ContentDigest,
        expected_activation_sequence: u64,
    ) -> Result<(ActiveBinding, ServiceResult), ServiceFault> {
        {
            let active = self.active_snapshot()?;
            validate_refresh_expectation(
                &active.binding,
                expected_generation_id,
                expected_activation_sequence,
            )?;
        }
        let candidate = load_generation(&self.config)?;
        let candidate_binding = candidate.binding();
        if candidate_binding.activation_sequence <= expected_activation_sequence {
            return Err(ServiceFault::new(
                "non_increasing_activation_sequence",
                "refresh",
                "candidate activation sequence must be greater than the active sequence",
            ));
        }
        if candidate_binding.generation_id == *expected_generation_id {
            return Err(ServiceFault::new(
                "unchanged_runtime_generation",
                "refresh",
                "candidate activation must bind a distinct runtime generation",
            ));
        }
        let replacement = Arc::new(ActiveServiceGeneration {
            runtime: Arc::new(candidate.runtime),
            binding: candidate_binding.clone(),
        });
        let mut active = self.active.write().map_err(|_| {
            ServiceFault::new(
                "active_generation_lock_poisoned",
                "refresh",
                "active service generation is unavailable",
            )
        })?;
        validate_refresh_expectation(
            &active.binding,
            expected_generation_id,
            expected_activation_sequence,
        )?;
        let previous_generation = active.binding.generation_id.clone();
        *active = replacement;
        self.counters
            .successful_refreshes
            .fetch_add(1, Ordering::Relaxed);
        let transition = RuntimeTransitionReceipt {
            previous_generation: Some(previous_generation),
            next_generation: Some(candidate_binding.generation_id.clone()),
            disposition: RuntimeTransitionDisposition::Activated,
            fault: None,
        };
        Ok((
            candidate_binding.clone(),
            ServiceResult::Refresh {
                transition,
                binding: candidate_binding,
            },
        ))
    }

    fn request_shutdown(
        &self,
        expected_generation_id: &ContentDigest,
    ) -> Result<ActiveBinding, ServiceFault> {
        let active = self.active.write().map_err(|_| {
            ServiceFault::new(
                "active_generation_lock_poisoned",
                "shutdown",
                "active service generation is unavailable",
            )
        })?;
        if active.binding.generation_id != *expected_generation_id {
            return Err(stale_generation_fault());
        }
        self.shutdown_requested.store(true, Ordering::Release);
        Ok(active.binding.clone())
    }

    fn active_snapshot(&self) -> Result<Arc<ActiveServiceGeneration>, ServiceFault> {
        self.active
            .read()
            .map(|active| Arc::clone(&active))
            .map_err(|_| {
                ServiceFault::new(
                    "active_generation_lock_poisoned",
                    "runtime",
                    "active service generation is unavailable",
                )
            })
    }
}

fn validate_refresh_expectation(
    binding: &ActiveBinding,
    expected_generation_id: &ContentDigest,
    expected_activation_sequence: u64,
) -> Result<(), ServiceFault> {
    if binding.generation_id != *expected_generation_id {
        return Err(stale_generation_fault());
    }
    if binding.activation_sequence != expected_activation_sequence {
        return Err(ServiceFault::new(
            "stale_activation_expectation",
            "refresh",
            "active activation sequence differs from the refresh expectation",
        ));
    }
    Ok(())
}

fn stale_generation_fault() -> ServiceFault {
    ServiceFault::new(
        "stale_generation_expectation",
        "lifecycle",
        "active runtime generation differs from the request expectation",
    )
}
