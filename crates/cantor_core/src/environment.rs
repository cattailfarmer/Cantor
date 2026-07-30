//! Shared fail-closed validation for serialized runtime environments.
//!
//! Adapters may choose different transports, but they must not invent their
//! own package-admission or semantic-fabric readiness rules.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    ContentDigest, EMBEDDED_ENVIRONMENT_VERSION, EmbeddedRuntimeEnvironment, SemanticFabric,
    admit_package, embedded_environment_digest,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeEnvironmentFault {
    pub code: String,
    pub message: String,
}

impl RuntimeEnvironmentFault {
    fn new(code: impl Into<String>, message: impl AsRef<str>) -> Self {
        Self {
            code: code.into(),
            message: bounded(message.as_ref()),
        }
    }
}

impl fmt::Display for RuntimeEnvironmentFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for RuntimeEnvironmentFault {}

/// Validates the complete environment that an adapter intends to make
/// resident and returns its canonical semantic digest.
pub fn preflight_runtime_environment(
    environment: &EmbeddedRuntimeEnvironment,
) -> Result<ContentDigest, RuntimeEnvironmentFault> {
    if environment.environment_version != EMBEDDED_ENVIRONMENT_VERSION {
        return Err(RuntimeEnvironmentFault::new(
            "unsupported_environment_version",
            format!(
                "expected {EMBEDDED_ENVIRONMENT_VERSION}, received {}",
                environment.environment_version
            ),
        ));
    }
    if environment.packages.is_empty() {
        return Err(RuntimeEnvironmentFault::new(
            "empty_environment",
            "at least one signed package is required",
        ));
    }
    let digest = embedded_environment_digest(environment).map_err(|fault| {
        RuntimeEnvironmentFault::new("environment_digest_failed", bounded(&fault.to_string()))
    })?;
    let mut admitted = Vec::with_capacity(environment.packages.len());
    for package in &environment.packages {
        let certificate = package.certificate.as_ref().ok_or_else(|| {
            RuntimeEnvironmentFault::new(
                "environment_package_rejected",
                format!(
                    "package {} has no recognition certificate",
                    package.package_id
                ),
            )
        })?;
        admitted.push(
            admit_package(
                package,
                &environment.trust_store,
                &certificate.authority_scope,
                environment.now_epoch_seconds,
            )
            .map_err(|fault| {
                RuntimeEnvironmentFault::new(
                    "environment_package_rejected",
                    bounded(&fault.message),
                )
            })?,
        );
    }
    SemanticFabric::from_admitted(admitted).map_err(|fault| {
        RuntimeEnvironmentFault::new("environment_fabric_rejected", bounded(&fault.message))
    })?;
    Ok(digest)
}

fn bounded(message: &str) -> String {
    message.chars().take(512).collect()
}
