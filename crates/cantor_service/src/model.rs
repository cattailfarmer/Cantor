use serde::{Deserialize, Serialize};

use cantor_core::{
    ContentDigest, PreparedRuntimeMetrics, ProtocolRequest, ProtocolResponse, RuntimeGeneration,
    RuntimeTransitionReceipt, SemanticId,
};

pub const SERVICE_PROTOCOL_VERSION: &str = "cantor-service-protocol/0.1";
pub const SERVICE_PROFILE: &str = "cantor-resident-service/0.1";
pub const SERVICE_CONFIG_SCHEMA: &str = "cantor-service-config/0.1";
pub const ACTIVATION_SCHEMA: &str = "cantor-environment-activation/0.1";
pub const SERVICE_CONFIGURATION_DIAGNOSTIC_PROFILE: &str =
    "cantor-operator-configuration-diagnostic/0.1";

pub struct ServiceRequest {
    pub protocol_version: String,
    pub request_id: SemanticId,
    pub auth_token: String,
    pub operation: ServiceOperation,
}

impl<'de> Deserialize<'de> for ServiceRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireRequest {
            protocol_version: String,
            request_id: SemanticId,
            auth_token: String,
            operation: ServiceOperation,
        }

        let wire = WireRequest::deserialize(deserializer)?;
        Ok(Self {
            protocol_version: wire.protocol_version,
            request_id: wire.request_id,
            auth_token: wire.auth_token,
            operation: wire.operation,
        })
    }
}

impl Serialize for ServiceRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct WireRequest<'a> {
            protocol_version: &'a str,
            request_id: &'a SemanticId,
            auth_token: &'a str,
            operation: &'a ServiceOperation,
        }

        WireRequest {
            protocol_version: &self.protocol_version,
            request_id: &self.request_id,
            auth_token: &self.auth_token,
            operation: &self.operation,
        }
        .serialize(serializer)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum ServiceOperation {
    Status,
    Execute {
        request: Box<ProtocolRequest>,
    },
    Refresh {
        expected_generation_id: ContentDigest,
        expected_activation_sequence: u64,
    },
    Shutdown {
        expected_generation_id: ContentDigest,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceDisposition {
    Success,
    Fault,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveBinding {
    pub generation_id: ContentDigest,
    pub activation_sequence: u64,
    pub activation_digest: ContentDigest,
    pub environment_file_sha256: ContentDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigurationDiagnosticStatus {
    Ready,
    Refused,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigurationDiagnosticCheckStatus {
    Passed,
    Refused,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigurationDiagnosticSubject {
    ServiceConfig,
    AuthenticationToken,
    ActivationEnvironment,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigurationDiagnosticCheck {
    pub ordinal: u8,
    pub subject: ConfigurationDiagnosticSubject,
    pub status: ConfigurationDiagnosticCheckStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicConfigurationDiagnosticFault {
    pub code: String,
    pub stage: String,
    pub subject: ConfigurationDiagnosticSubject,
    pub guidance: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadyServiceConfigurationSummary {
    pub service_config_schema: String,
    pub listen_family: String,
    pub listen_port: u16,
    pub max_frame_bytes: usize,
    pub max_connections: usize,
    pub read_timeout_milliseconds: u128,
    pub write_timeout_milliseconds: u128,
    pub active_binding: ActiveBinding,
    pub runtime_metrics: PreparedRuntimeMetrics,
    pub ordered_package_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigurationDiagnosticPrivacyBoundary {
    pub authority_paths_recorded: bool,
    pub token_content_recorded: bool,
    pub token_hash_recorded: bool,
    pub config_content_recorded: bool,
    pub activation_content_recorded: bool,
    pub environment_content_recorded: bool,
    pub raw_fault_message_recorded: bool,
    pub listener_bound: bool,
    pub service_started: bool,
    pub provider_contacted: bool,
    pub remote_accessed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfigurationDiagnostic {
    pub profile: String,
    pub status: ConfigurationDiagnosticStatus,
    pub config_file_sha256: Option<ContentDigest>,
    pub checks: Vec<ConfigurationDiagnosticCheck>,
    pub ready_summary: Option<ReadyServiceConfigurationSummary>,
    pub fault: Option<PublicConfigurationDiagnosticFault>,
    pub privacy: ConfigurationDiagnosticPrivacyBoundary,
    pub non_authority_statement: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceStatus {
    pub service_profile: String,
    pub active_binding: ActiveBinding,
    pub runtime_generation: RuntimeGeneration,
    pub runtime_metrics: PreparedRuntimeMetrics,
    pub ordered_package_ids: Vec<SemanticId>,
    pub uptime_milliseconds: u64,
    pub accepted_connections: u64,
    pub rejected_connections: u64,
    pub worker_panics: u64,
    pub completed_requests: u64,
    pub successful_refreshes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ServiceResult {
    Status {
        status: Box<ServiceStatus>,
    },
    Protocol {
        response: Box<ProtocolResponse>,
    },
    Refresh {
        transition: RuntimeTransitionReceipt,
        binding: ActiveBinding,
    },
    Shutdown {
        binding: ActiveBinding,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceFault {
    pub code: String,
    pub stage: String,
    pub message: String,
}

impl ServiceFault {
    pub fn new(
        code: impl Into<String>,
        stage: impl Into<String>,
        message: impl AsRef<str>,
    ) -> Self {
        Self {
            code: code.into(),
            stage: stage.into(),
            message: bounded_message(message.as_ref()),
        }
    }
}

impl std::fmt::Display for ServiceFault {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{} at {}: {}",
            self.code, self.stage, self.message
        )
    }
}

impl std::error::Error for ServiceFault {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceResponse {
    pub protocol_version: String,
    pub request_id: SemanticId,
    pub disposition: ServiceDisposition,
    pub active_binding: Option<ActiveBinding>,
    pub result: Option<ServiceResult>,
    pub faults: Vec<ServiceFault>,
}

impl ServiceResponse {
    pub fn success(request_id: SemanticId, binding: ActiveBinding, result: ServiceResult) -> Self {
        Self {
            protocol_version: SERVICE_PROTOCOL_VERSION.to_owned(),
            request_id,
            disposition: ServiceDisposition::Success,
            active_binding: Some(binding),
            result: Some(result),
            faults: Vec::new(),
        }
    }

    pub fn fault(
        request_id: SemanticId,
        binding: Option<ActiveBinding>,
        fault: ServiceFault,
    ) -> Self {
        Self {
            protocol_version: SERVICE_PROTOCOL_VERSION.to_owned(),
            request_id,
            disposition: ServiceDisposition::Fault,
            active_binding: binding,
            result: None,
            faults: vec![fault],
        }
    }
}

pub fn unavailable_request_id() -> SemanticId {
    SemanticId::new("request:unavailable")
        .unwrap_or_else(|_| unreachable!("static fallback request identity is valid"))
}

fn bounded_message(message: &str) -> String {
    message.chars().take(512).collect()
}
