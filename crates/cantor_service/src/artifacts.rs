use std::{
    fmt,
    fs::{self, File},
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use cantor_core::{
    ContentDigest, EmbeddedRuntimeEnvironment, PreparedRuntime, preflight_runtime_environment,
    sha256_bytes, sha256_digest,
};
use serde::{Deserialize, Serialize};

use crate::model::{
    ACTIVATION_SCHEMA, ActiveBinding, ConfigurationDiagnosticCheck,
    ConfigurationDiagnosticCheckStatus, ConfigurationDiagnosticPrivacyBoundary,
    ConfigurationDiagnosticStatus, ConfigurationDiagnosticSubject,
    PublicConfigurationDiagnosticFault, ReadyServiceConfigurationSummary, SERVICE_CONFIG_SCHEMA,
    SERVICE_CONFIGURATION_DIAGNOSTIC_PROFILE, ServiceConfigurationDiagnostic, ServiceFault,
};

pub const MAX_CONFIG_BYTES: usize = 64 * 1024;
pub const MAX_ACTIVATION_BYTES: usize = 64 * 1024;
pub const MAX_ENVIRONMENT_BYTES: usize = 64 * 1024 * 1024;
pub const HARD_MIN_FRAME_BYTES: usize = 1024;
pub const HARD_MAX_FRAME_BYTES: usize = 1024 * 1024;
pub const HARD_MAX_CONNECTIONS: usize = 256;
pub const HARD_MAX_TIMEOUT_MS: u64 = 60_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    pub schema: String,
    pub listen_address: String,
    pub activation_path: PathBuf,
    pub allowed_environment_root: PathBuf,
    pub auth_token_path: PathBuf,
    pub max_frame_bytes: usize,
    pub max_connections: usize,
    pub read_timeout_ms: u64,
    pub write_timeout_ms: u64,
}

#[derive(Clone, Debug)]
pub struct ValidatedServiceConfig {
    pub listen_address: SocketAddr,
    pub activation_path: PathBuf,
    pub allowed_environment_root: PathBuf,
    pub auth_token_path: PathBuf,
    pub max_frame_bytes: usize,
    pub max_connections: usize,
    pub read_timeout: Duration,
    pub write_timeout: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentActivation {
    pub schema: String,
    pub sequence: u64,
    pub environment_path: PathBuf,
    pub environment_file_sha256: String,
}

pub struct SecretToken([u8; 64]);

impl fmt::Debug for SecretToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretToken([REDACTED])")
    }
}

impl SecretToken {
    pub fn from_file(path: &Path) -> Result<Self, ServiceFault> {
        let bytes = read_bounded(path, 256, "token")?;
        let text = std::str::from_utf8(&bytes).map_err(|_| {
            ServiceFault::new(
                "invalid_auth_token",
                "startup",
                "authentication token file must be UTF-8 hexadecimal text",
            )
        })?;
        Self::parse(text)
    }

    pub fn parse(text: &str) -> Result<Self, ServiceFault> {
        let trimmed = text
            .strip_suffix("\r\n")
            .or_else(|| text.strip_suffix('\n'))
            .unwrap_or(text);
        if trimmed.len() != 64 || !trimmed.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ServiceFault::new(
                "invalid_auth_token",
                "authentication",
                "authentication token must contain exactly 64 hexadecimal characters",
            ));
        }
        let mut normalized = [0_u8; 64];
        for (target, byte) in normalized.iter_mut().zip(trimmed.bytes()) {
            *target = byte.to_ascii_lowercase();
        }
        Ok(Self(normalized))
    }

    pub fn expose_for_client(&self) -> String {
        String::from_utf8(self.0.to_vec())
            .unwrap_or_else(|_| unreachable!("validated token bytes are ASCII"))
    }

    pub fn matches(&self, candidate: &str) -> bool {
        let candidate = candidate.as_bytes();
        let mut difference = candidate.len() ^ self.0.len();
        for index in 0..self.0.len() {
            let candidate_byte = candidate
                .get(index)
                .copied()
                .unwrap_or_default()
                .to_ascii_lowercase();
            difference |= usize::from(self.0[index] ^ candidate_byte);
        }
        difference == 0
    }
}

#[derive(Debug)]
pub struct LoadedGeneration {
    pub activation: EnvironmentActivation,
    pub activation_digest: ContentDigest,
    pub environment_file_digest: ContentDigest,
    pub runtime: PreparedRuntime,
}

impl LoadedGeneration {
    pub fn binding(&self) -> ActiveBinding {
        ActiveBinding {
            generation_id: self.runtime.generation().generation_id.clone(),
            activation_sequence: self.activation.sequence,
            activation_digest: self.activation_digest.clone(),
            environment_file_sha256: self.environment_file_digest.clone(),
        }
    }
}

pub fn load_service_config(path: &Path) -> Result<ValidatedServiceConfig, ServiceFault> {
    if !path.is_absolute() {
        return Err(ServiceFault::new(
            "relative_config_path",
            "startup",
            "service configuration path must be absolute",
        ));
    }
    let bytes = read_bounded(path, MAX_CONFIG_BYTES, "service configuration")?;
    let config: ServiceConfig = serde_json::from_slice(&bytes).map_err(|error| {
        ServiceFault::new(
            "invalid_service_config",
            "startup",
            format!("service configuration is not valid strict JSON: {error}"),
        )
    })?;
    validate_service_config(config)
}

pub fn validate_service_config(
    config: ServiceConfig,
) -> Result<ValidatedServiceConfig, ServiceFault> {
    if config.schema != SERVICE_CONFIG_SCHEMA {
        return Err(ServiceFault::new(
            "unsupported_service_config",
            "startup",
            format!(
                "expected configuration schema {SERVICE_CONFIG_SCHEMA}, received {}",
                config.schema
            ),
        ));
    }
    let listen_address: SocketAddr = config.listen_address.parse().map_err(|error| {
        ServiceFault::new(
            "invalid_listen_address",
            "startup",
            format!("listen_address is invalid: {error}"),
        )
    })?;
    if !listen_address.ip().is_loopback() {
        return Err(ServiceFault::new(
            "non_loopback_address",
            "startup",
            "cantord accepts loopback listen addresses only",
        ));
    }
    validate_frame_limit(config.max_frame_bytes)?;
    validate_limit(
        config.max_connections,
        HARD_MAX_CONNECTIONS,
        "max_connections",
    )?;
    validate_timeout(config.read_timeout_ms, "read_timeout_ms")?;
    validate_timeout(config.write_timeout_ms, "write_timeout_ms")?;
    let activation_path = canonical_regular_file(&config.activation_path, "activation_path")?;
    let allowed_environment_root =
        canonical_directory(&config.allowed_environment_root, "allowed_environment_root")?;
    let auth_token_path = canonical_regular_file(&config.auth_token_path, "auth_token_path")?;
    if activation_path == auth_token_path {
        return Err(ServiceFault::new(
            "authority_path_collision",
            "startup",
            "activation and authentication token paths must differ",
        ));
    }
    Ok(ValidatedServiceConfig {
        listen_address,
        activation_path,
        allowed_environment_root,
        auth_token_path,
        max_frame_bytes: config.max_frame_bytes,
        max_connections: config.max_connections,
        read_timeout: Duration::from_millis(config.read_timeout_ms),
        write_timeout: Duration::from_millis(config.write_timeout_ms),
    })
}

pub fn load_generation(config: &ValidatedServiceConfig) -> Result<LoadedGeneration, ServiceFault> {
    let bytes = read_bounded(
        &config.activation_path,
        MAX_ACTIVATION_BYTES,
        "activation descriptor",
    )?;
    let activation: EnvironmentActivation = serde_json::from_slice(&bytes).map_err(|error| {
        ServiceFault::new(
            "invalid_activation_descriptor",
            "activation",
            format!("activation descriptor is not valid strict JSON: {error}"),
        )
    })?;
    if activation.schema != ACTIVATION_SCHEMA {
        return Err(ServiceFault::new(
            "unsupported_activation_schema",
            "activation",
            format!(
                "expected activation schema {ACTIVATION_SCHEMA}, received {}",
                activation.schema
            ),
        ));
    }
    if activation.sequence == 0 {
        return Err(ServiceFault::new(
            "invalid_activation_sequence",
            "activation",
            "activation sequence must be positive",
        ));
    }
    validate_sha256_text(
        &activation.environment_file_sha256,
        "environment_file_sha256",
    )?;
    let environment_path =
        canonical_regular_file(&activation.environment_path, "environment_path")?;
    if !environment_path.starts_with(&config.allowed_environment_root) {
        return Err(ServiceFault::new(
            "environment_path_escape",
            "activation",
            "activated environment resolves outside allowed_environment_root",
        ));
    }
    let environment_bytes = read_bounded(
        &environment_path,
        MAX_ENVIRONMENT_BYTES,
        "runtime environment",
    )?;
    let environment_file_digest = sha256_bytes(&environment_bytes);
    if environment_file_digest.value != activation.environment_file_sha256.to_ascii_lowercase() {
        return Err(ServiceFault::new(
            "environment_file_digest_mismatch",
            "activation",
            "runtime environment bytes do not match the activation descriptor",
        ));
    }
    let environment: EmbeddedRuntimeEnvironment = serde_json::from_slice(&environment_bytes)
        .map_err(|error| {
            ServiceFault::new(
                "invalid_runtime_environment",
                "activation",
                format!("runtime environment is not valid strict JSON: {error}"),
            )
        })?;
    preflight_runtime_environment(&environment)
        .map_err(|fault| ServiceFault::new(fault.code, "activation_preflight", fault.message))?;
    let runtime = PreparedRuntime::new(environment).map_err(|fault| {
        ServiceFault::new(
            "prepared_runtime_initialization_failed",
            "activation_preflight",
            fault.to_string(),
        )
    })?;
    let activation_digest = sha256_digest(&activation).map_err(|fault| {
        ServiceFault::new("activation_digest_failed", "activation", fault.to_string())
    })?;
    Ok(LoadedGeneration {
        activation,
        activation_digest,
        environment_file_digest,
        runtime,
    })
}

pub fn diagnose_service_configuration(path: &Path) -> ServiceConfigurationDiagnostic {
    let config_file_sha256 = read_bounded(path, MAX_CONFIG_BYTES, "service configuration")
        .ok()
        .map(|bytes| sha256_bytes(&bytes));
    let mut checks = Vec::with_capacity(3);
    let config = match load_service_config(path) {
        Ok(config) => {
            checks.push(passed_check(
                0,
                ConfigurationDiagnosticSubject::ServiceConfig,
            ));
            config
        }
        Err(fault) => {
            return refused_diagnostic(
                config_file_sha256,
                checks,
                ConfigurationDiagnosticSubject::ServiceConfig,
                fault,
            );
        }
    };
    match SecretToken::from_file(&config.auth_token_path) {
        Ok(_token) => {
            checks.push(passed_check(
                1,
                ConfigurationDiagnosticSubject::AuthenticationToken,
            ));
        }
        Err(fault) => {
            return refused_diagnostic(
                config_file_sha256,
                checks,
                ConfigurationDiagnosticSubject::AuthenticationToken,
                fault,
            );
        }
    }
    let loaded = match load_generation(&config) {
        Ok(loaded) => {
            checks.push(passed_check(
                2,
                ConfigurationDiagnosticSubject::ActivationEnvironment,
            ));
            loaded
        }
        Err(fault) => {
            return refused_diagnostic(
                config_file_sha256,
                checks,
                ConfigurationDiagnosticSubject::ActivationEnvironment,
                fault,
            );
        }
    };
    let ready_summary = ReadyServiceConfigurationSummary {
        service_config_schema: SERVICE_CONFIG_SCHEMA.to_owned(),
        listen_family: if config.listen_address.is_ipv4() {
            "ipv4_loopback".to_owned()
        } else {
            "ipv6_loopback".to_owned()
        },
        listen_port: config.listen_address.port(),
        max_frame_bytes: config.max_frame_bytes,
        max_connections: config.max_connections,
        read_timeout_milliseconds: config.read_timeout.as_millis(),
        write_timeout_milliseconds: config.write_timeout.as_millis(),
        active_binding: loaded.binding(),
        runtime_metrics: loaded.runtime.metrics(),
        ordered_package_count: loaded.runtime.generation().ordered_package_ids.len(),
    };
    ServiceConfigurationDiagnostic {
        profile: SERVICE_CONFIGURATION_DIAGNOSTIC_PROFILE.to_owned(),
        status: ConfigurationDiagnosticStatus::Ready,
        config_file_sha256,
        checks,
        ready_summary: Some(ready_summary),
        fault: None,
        privacy: diagnostic_privacy_boundary(),
        non_authority_statement: diagnostic_non_authority_statement(),
    }
}

fn passed_check(
    ordinal: u8,
    subject: ConfigurationDiagnosticSubject,
) -> ConfigurationDiagnosticCheck {
    ConfigurationDiagnosticCheck {
        ordinal,
        subject,
        status: ConfigurationDiagnosticCheckStatus::Passed,
    }
}

fn refused_diagnostic(
    config_file_sha256: Option<ContentDigest>,
    mut checks: Vec<ConfigurationDiagnosticCheck>,
    subject: ConfigurationDiagnosticSubject,
    fault: ServiceFault,
) -> ServiceConfigurationDiagnostic {
    checks.push(ConfigurationDiagnosticCheck {
        ordinal: u8::try_from(checks.len()).unwrap_or(u8::MAX),
        subject,
        status: ConfigurationDiagnosticCheckStatus::Refused,
    });
    let guidance = public_diagnostic_guidance(&fault.code, subject).to_owned();
    ServiceConfigurationDiagnostic {
        profile: SERVICE_CONFIGURATION_DIAGNOSTIC_PROFILE.to_owned(),
        status: ConfigurationDiagnosticStatus::Refused,
        config_file_sha256,
        checks,
        ready_summary: None,
        fault: Some(PublicConfigurationDiagnosticFault {
            code: fault.code,
            stage: fault.stage,
            subject,
            guidance,
        }),
        privacy: diagnostic_privacy_boundary(),
        non_authority_statement: diagnostic_non_authority_statement(),
    }
}

fn public_diagnostic_guidance(code: &str, subject: ConfigurationDiagnosticSubject) -> &'static str {
    match (code, subject) {
        (
            "artifact_read_failed"
            | "artifact_metadata_failed"
            | "artifact_limit_exceeded"
            | "empty_artifact",
            ConfigurationDiagnosticSubject::ServiceConfig,
        ) => "provision one readable nonempty service configuration within the 64 KiB limit",
        (
            "artifact_read_failed"
            | "artifact_metadata_failed"
            | "artifact_limit_exceeded"
            | "empty_artifact",
            ConfigurationDiagnosticSubject::AuthenticationToken,
        ) => {
            "provision a readable bounded authentication token with exactly 64 hexadecimal characters"
        }
        (
            "artifact_read_failed"
            | "artifact_metadata_failed"
            | "artifact_limit_exceeded"
            | "empty_artifact",
            ConfigurationDiagnosticSubject::ActivationEnvironment,
        ) => "provision readable bounded activation and environment artifacts",
        ("relative_config_path", _) => "select one absolute service configuration path",
        ("invalid_service_config" | "unsupported_service_config", _) => {
            "repair the strict cantor-service-config/0.1 document"
        }
        ("invalid_listen_address" | "non_loopback_address", _) => {
            "select one valid loopback listener address"
        }
        ("invalid_resource_limit" | "invalid_timeout", _) => {
            "choose resource values within the published resident-service bounds"
        }
        (
            "relative_authority_path"
            | "authority_path_unavailable"
            | "authority_metadata_failed"
            | "authority_not_regular_file"
            | "authority_not_directory"
            | "authority_path_collision",
            _,
        ) => "provision distinct absolute regular-file and directory authority paths",
        ("invalid_auth_token", _) => {
            "provision a bounded authentication token with exactly 64 hexadecimal characters"
        }
        (
            "invalid_activation_descriptor"
            | "unsupported_activation_schema"
            | "invalid_activation_sequence"
            | "invalid_sha256",
            _,
        ) => "republish one strict positive-sequence activation descriptor",
        ("environment_path_escape", _) => {
            "place the activated environment within the configured allowed root"
        }
        ("environment_file_digest_mismatch", _) => {
            "republish the activation digest from the exact environment bytes"
        }
        (
            "invalid_runtime_environment"
            | "prepared_runtime_initialization_failed"
            | "activation_digest_failed",
            _,
        ) => "repair the signed runtime environment before service startup",
        _ => "review the named validation stage without exposing private artifact details",
    }
}

fn diagnostic_privacy_boundary() -> ConfigurationDiagnosticPrivacyBoundary {
    ConfigurationDiagnosticPrivacyBoundary {
        authority_paths_recorded: false,
        token_content_recorded: false,
        token_hash_recorded: false,
        config_content_recorded: false,
        activation_content_recorded: false,
        environment_content_recorded: false,
        raw_fault_message_recorded: false,
        listener_bound: false,
        service_started: false,
        provider_contacted: false,
        remote_accessed: false,
    }
}

fn diagnostic_non_authority_statement() -> String {
    "This deterministic preflight validates existing local startup artifacts without binding a listener. It records no authority path, token, raw fault, config, activation, or environment content and grants no mutation, migration, provider, effect, persistence, operator-product, or production authority.".to_owned()
}

fn validate_limit(value: usize, maximum: usize, name: &str) -> Result<(), ServiceFault> {
    if value == 0 || value > maximum {
        Err(ServiceFault::new(
            "invalid_resource_limit",
            "startup",
            format!("{name} must be from 1 through {maximum}"),
        ))
    } else {
        Ok(())
    }
}

fn validate_frame_limit(value: usize) -> Result<(), ServiceFault> {
    if !(HARD_MIN_FRAME_BYTES..=HARD_MAX_FRAME_BYTES).contains(&value) {
        Err(ServiceFault::new(
            "invalid_resource_limit",
            "startup",
            format!(
                "max_frame_bytes must be from {HARD_MIN_FRAME_BYTES} through {HARD_MAX_FRAME_BYTES}"
            ),
        ))
    } else {
        Ok(())
    }
}

fn validate_timeout(value: u64, name: &str) -> Result<(), ServiceFault> {
    if value == 0 || value > HARD_MAX_TIMEOUT_MS {
        Err(ServiceFault::new(
            "invalid_timeout",
            "startup",
            format!("{name} must be from 1 through {HARD_MAX_TIMEOUT_MS}"),
        ))
    } else {
        Ok(())
    }
}

fn canonical_regular_file(path: &Path, name: &str) -> Result<PathBuf, ServiceFault> {
    if !path.is_absolute() {
        return Err(ServiceFault::new(
            "relative_authority_path",
            "startup",
            format!("{name} must be absolute"),
        ));
    }
    let canonical = fs::canonicalize(path).map_err(|error| {
        ServiceFault::new(
            "authority_path_unavailable",
            "startup",
            format!("{name} cannot be resolved: {error}"),
        )
    })?;
    let metadata = fs::metadata(&canonical).map_err(|error| {
        ServiceFault::new(
            "authority_metadata_failed",
            "startup",
            format!("{name} metadata is unavailable: {error}"),
        )
    })?;
    if !metadata.is_file() {
        return Err(ServiceFault::new(
            "authority_not_regular_file",
            "startup",
            format!("{name} must resolve to a regular file"),
        ));
    }
    Ok(canonical)
}

fn canonical_directory(path: &Path, name: &str) -> Result<PathBuf, ServiceFault> {
    if !path.is_absolute() {
        return Err(ServiceFault::new(
            "relative_authority_path",
            "startup",
            format!("{name} must be absolute"),
        ));
    }
    let canonical = fs::canonicalize(path).map_err(|error| {
        ServiceFault::new(
            "authority_path_unavailable",
            "startup",
            format!("{name} cannot be resolved: {error}"),
        )
    })?;
    if !canonical.is_dir() {
        return Err(ServiceFault::new(
            "authority_not_directory",
            "startup",
            format!("{name} must resolve to a directory"),
        ));
    }
    Ok(canonical)
}

fn validate_sha256_text(value: &str, name: &str) -> Result<(), ServiceFault> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Err(ServiceFault::new(
            "invalid_sha256",
            "activation",
            format!("{name} must contain exactly 64 hexadecimal characters"),
        ))
    } else {
        Ok(())
    }
}

fn read_bounded(path: &Path, maximum: usize, label: &str) -> Result<Vec<u8>, ServiceFault> {
    let file = File::open(path).map_err(|error| {
        ServiceFault::new(
            "artifact_read_failed",
            "artifact_load",
            format!("cannot open {label}: {error}"),
        )
    })?;
    let length = file
        .metadata()
        .map_err(|error| {
            ServiceFault::new(
                "artifact_metadata_failed",
                "artifact_load",
                format!("cannot inspect {label}: {error}"),
            )
        })?
        .len();
    if length > maximum as u64 {
        return Err(ServiceFault::new(
            "artifact_limit_exceeded",
            "artifact_load",
            format!("{label} contains {length} bytes; maximum is {maximum}"),
        ));
    }
    let mut bytes = Vec::with_capacity(length as usize);
    file.take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            ServiceFault::new(
                "artifact_read_failed",
                "artifact_load",
                format!("cannot read {label}: {error}"),
            )
        })?;
    if bytes.len() > maximum {
        return Err(ServiceFault::new(
            "artifact_limit_exceeded",
            "artifact_load",
            format!("{label} exceeds the {maximum}-byte maximum while being read"),
        ));
    }
    if bytes.is_empty() {
        return Err(ServiceFault::new(
            "empty_artifact",
            "artifact_load",
            format!("{label} is empty"),
        ));
    }
    Ok(bytes)
}
