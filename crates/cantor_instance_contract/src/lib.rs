//! Strict provider-free boundary between the Cantor kernel and hosted instances.
//!
//! A valid manifest and an admitted compatibility result prove structural
//! correspondence only. They do not authorize execution, installation, model
//! inference, provider access, remote contact, mutation, or publication.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fmt::Write as _;

use serde::de;
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

pub mod fixture;

pub const INSTANCE_PROFILE: &str = "cantor-instance-contract/0.1";
pub const KERNEL_PROFILE: &str = "cantor-kernel-capabilities/0.1";
pub const KERNEL_API_PROFILE: &str = "cantor-kernel-api/0.1";
pub const COMPATIBILITY_PROFILE: &str = "cantor-instance-compatibility/0.1";
pub const NON_AUTHORITY: &str = "Structural compatibility only. No execution, installation, model, provider, operator, kernel, remote, mutation, update, publication, or effect authority is granted.";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceLineage {
    pub repository: String,
    pub base_commit: String,
    pub source_snapshot_uuid: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentRole {
    KernelCandidate,
    InstanceAdapter,
    Package,
    Evidence,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentBinding {
    pub component_id: String,
    pub role: ComponentRole,
    pub relative_path: String,
    pub content_sha256: String,
    #[serde(deserialize_with = "deserialize_unique_set")]
    pub required_capabilities: BTreeSet<String>,
    #[serde(deserialize_with = "deserialize_unique_set")]
    pub provided_capabilities: BTreeSet<String>,
    #[serde(deserialize_with = "deserialize_unique_set")]
    pub requested_authorities: BTreeSet<String>,
    pub kernel_slot: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceManifest {
    pub profile: String,
    pub instance_id: String,
    pub display_name: String,
    pub revision: u64,
    pub kernel_api_profile: String,
    pub source_lineage: SourceLineage,
    #[serde(deserialize_with = "deserialize_unique_set")]
    pub required_capabilities: BTreeSet<String>,
    #[serde(deserialize_with = "deserialize_unique_set")]
    pub provided_capabilities: BTreeSet<String>,
    #[serde(deserialize_with = "deserialize_unique_set")]
    pub requested_authorities: BTreeSet<String>,
    pub components: BTreeMap<String, ComponentBinding>,
    pub non_authority: String,
    pub manifest_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelCapabilities {
    pub profile: String,
    pub api_profile: String,
    pub implementation_commit: String,
    #[serde(deserialize_with = "deserialize_unique_set")]
    pub capabilities: BTreeSet<String>,
    pub non_authority: String,
    pub capabilities_digest: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityStatus {
    Admitted,
    Held,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityResult {
    pub profile: String,
    pub instance_id: String,
    pub instance_revision: u64,
    pub kernel_implementation_commit: String,
    pub manifest_digest: String,
    pub kernel_capabilities_digest: String,
    pub status: CompatibilityStatus,
    #[serde(deserialize_with = "deserialize_unique_set")]
    pub missing_capabilities: BTreeSet<String>,
    #[serde(deserialize_with = "deserialize_unique_set")]
    pub refusals: BTreeSet<String>,
    pub non_authority: String,
    pub result_digest: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractFaultCode {
    MachineForm,
    InvalidProfile,
    InvalidIdentity,
    InvalidLineage,
    InvalidCapability,
    InvalidComponent,
    AuthorityEscalation,
    DigestMismatch,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractFault {
    pub code: ContractFaultCode,
    pub detail: String,
}

impl fmt::Display for ContractFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.detail)
    }
}

impl std::error::Error for ContractFault {}

pub fn seal_kernel_capabilities(
    mut kernel: KernelCapabilities,
) -> Result<KernelCapabilities, ContractFault> {
    kernel.capabilities_digest.clear();
    validate_kernel_shape(&kernel, false)?;
    kernel.capabilities_digest = digest_value(&kernel)?;
    Ok(kernel)
}

pub fn validate_kernel_capabilities(kernel: &KernelCapabilities) -> Result<(), ContractFault> {
    validate_kernel_shape(kernel, true)?;
    let mut unsigned = kernel.clone();
    let supplied = std::mem::take(&mut unsigned.capabilities_digest);
    if digest_value(&unsigned)? != supplied {
        return fault(
            ContractFaultCode::DigestMismatch,
            "kernel capabilities digest differs",
        );
    }
    Ok(())
}

pub fn seal_instance_manifest(
    mut manifest: InstanceManifest,
) -> Result<InstanceManifest, ContractFault> {
    manifest.manifest_digest.clear();
    validate_manifest_shape(&manifest, false)?;
    manifest.manifest_digest = digest_value(&manifest)?;
    Ok(manifest)
}

pub fn validate_instance_manifest(manifest: &InstanceManifest) -> Result<(), ContractFault> {
    validate_manifest_shape(manifest, true)?;
    let mut unsigned = manifest.clone();
    let supplied = std::mem::take(&mut unsigned.manifest_digest);
    if digest_value(&unsigned)? != supplied {
        return fault(
            ContractFaultCode::DigestMismatch,
            "instance manifest digest differs",
        );
    }
    Ok(())
}

pub fn compile_compatibility(
    kernel: &KernelCapabilities,
    manifest: &InstanceManifest,
) -> Result<CompatibilityResult, ContractFault> {
    validate_kernel_capabilities(kernel)?;
    validate_instance_manifest(manifest)?;

    let mut missing_capabilities = BTreeSet::new();
    let mut refusals = BTreeSet::new();
    if manifest.kernel_api_profile != kernel.api_profile {
        refusals.insert(format!(
            "kernel_api_profile_mismatch:{}:{}",
            manifest.kernel_api_profile, kernel.api_profile
        ));
    }
    for capability in &manifest.required_capabilities {
        if !kernel.capabilities.contains(capability) {
            missing_capabilities.insert(capability.clone());
        }
    }
    for component in manifest.components.values() {
        if component.role == ComponentRole::KernelCandidate {
            refusals.insert(format!(
                "kernel_candidate_requires_separate_promotion:{}",
                component.component_id
            ));
        }
    }
    let status = if missing_capabilities.is_empty() && refusals.is_empty() {
        CompatibilityStatus::Admitted
    } else {
        CompatibilityStatus::Held
    };
    let mut result = CompatibilityResult {
        profile: COMPATIBILITY_PROFILE.to_owned(),
        instance_id: manifest.instance_id.clone(),
        instance_revision: manifest.revision,
        kernel_implementation_commit: kernel.implementation_commit.clone(),
        manifest_digest: manifest.manifest_digest.clone(),
        kernel_capabilities_digest: kernel.capabilities_digest.clone(),
        status,
        missing_capabilities,
        refusals,
        non_authority: NON_AUTHORITY.to_owned(),
        result_digest: String::new(),
    };
    result.result_digest = digest_value(&result)?;
    Ok(result)
}

pub fn validate_compatibility_result(
    kernel: &KernelCapabilities,
    manifest: &InstanceManifest,
    result: &CompatibilityResult,
) -> Result<(), ContractFault> {
    let rebuilt = compile_compatibility(kernel, manifest)?;
    if rebuilt != *result {
        return fault(
            ContractFaultCode::DigestMismatch,
            "compatibility result differs from deterministic replay",
        );
    }
    Ok(())
}

pub fn parse_kernel_capabilities(bytes: &[u8]) -> Result<KernelCapabilities, ContractFault> {
    serde_json::from_slice(bytes).map_err(|error| ContractFault {
        code: ContractFaultCode::MachineForm,
        detail: format!("kernel JSON refused: {error}"),
    })
}

pub fn parse_instance_manifest(bytes: &[u8]) -> Result<InstanceManifest, ContractFault> {
    serde_json::from_slice(bytes).map_err(|error| ContractFault {
        code: ContractFaultCode::MachineForm,
        detail: format!("instance JSON refused: {error}"),
    })
}

pub fn compatibility_machine_form(result: &CompatibilityResult) -> Result<Vec<u8>, ContractFault> {
    serde_json::to_vec_pretty(result).map_err(|error| ContractFault {
        code: ContractFaultCode::MachineForm,
        detail: format!("compatibility JSON failed: {error}"),
    })
}

fn validate_kernel_shape(
    kernel: &KernelCapabilities,
    require_digest: bool,
) -> Result<(), ContractFault> {
    if kernel.profile != KERNEL_PROFILE || kernel.api_profile != KERNEL_API_PROFILE {
        return fault(
            ContractFaultCode::InvalidProfile,
            "kernel profile or API profile differs",
        );
    }
    validate_commit(
        &kernel.implementation_commit,
        "kernel implementation commit",
    )?;
    if kernel.capabilities.is_empty() {
        return fault(
            ContractFaultCode::InvalidCapability,
            "kernel requires at least one capability",
        );
    }
    for capability in &kernel.capabilities {
        validate_capability(capability, "kernel.")?;
    }
    if kernel.non_authority != NON_AUTHORITY {
        return fault(
            ContractFaultCode::AuthorityEscalation,
            "kernel non-authority statement differs",
        );
    }
    validate_optional_digest(&kernel.capabilities_digest, require_digest, "kernel digest")
}

fn validate_manifest_shape(
    manifest: &InstanceManifest,
    require_digest: bool,
) -> Result<(), ContractFault> {
    if manifest.profile != INSTANCE_PROFILE || manifest.kernel_api_profile != KERNEL_API_PROFILE {
        return fault(
            ContractFaultCode::InvalidProfile,
            "instance profile or kernel API profile differs",
        );
    }
    validate_identifier(&manifest.instance_id, "instance_id")?;
    require_text(&manifest.display_name, "display_name")?;
    if manifest.revision == 0 {
        return fault(
            ContractFaultCode::InvalidIdentity,
            "instance revision must be positive",
        );
    }
    require_text(&manifest.source_lineage.repository, "source repository")?;
    validate_commit(&manifest.source_lineage.base_commit, "source base commit")?;
    require_text(
        &manifest.source_lineage.source_snapshot_uuid,
        "source_snapshot_uuid",
    )?;
    if !manifest.requested_authorities.is_empty() {
        return fault(
            ContractFaultCode::AuthorityEscalation,
            "instance cannot request authority",
        );
    }
    if manifest.non_authority != NON_AUTHORITY {
        return fault(
            ContractFaultCode::AuthorityEscalation,
            "instance non-authority statement differs",
        );
    }
    if manifest.components.is_empty() {
        return fault(
            ContractFaultCode::InvalidComponent,
            "instance requires at least one component",
        );
    }
    for capability in &manifest.required_capabilities {
        validate_capability(capability, "kernel.")?;
    }
    let mut provided = BTreeSet::new();
    for (key, component) in &manifest.components {
        validate_component(&manifest.instance_id, key, component)?;
        if !component
            .required_capabilities
            .is_subset(&manifest.required_capabilities)
        {
            return fault(
                ContractFaultCode::InvalidCapability,
                format!(
                    "component requirements exceed manifest requirements: {}",
                    component.component_id
                ),
            );
        }
        if component.role != ComponentRole::KernelCandidate {
            provided.extend(component.provided_capabilities.iter().cloned());
        }
    }
    if provided != manifest.provided_capabilities {
        return fault(
            ContractFaultCode::InvalidCapability,
            "manifest provided capabilities differ from component union",
        );
    }
    validate_optional_digest(&manifest.manifest_digest, require_digest, "manifest digest")
}

fn validate_component(
    instance_id: &str,
    key: &str,
    component: &ComponentBinding,
) -> Result<(), ContractFault> {
    validate_identifier(key, "component map key")?;
    validate_identifier(&component.component_id, "component_id")?;
    if key != component.component_id {
        return fault(
            ContractFaultCode::InvalidComponent,
            "component key must equal component_id",
        );
    }
    validate_relative_path(&component.relative_path)?;
    validate_sha256(&component.content_sha256, "component content_sha256")?;
    if !component.requested_authorities.is_empty() {
        return fault(
            ContractFaultCode::AuthorityEscalation,
            format!("component requests authority: {}", component.component_id),
        );
    }
    for capability in &component.required_capabilities {
        validate_capability(capability, "kernel.")?;
    }
    let instance_prefix = format!("instance.{instance_id}.");
    let package_prefix = format!("package.{instance_id}.");
    match component.role {
        ComponentRole::KernelCandidate => {
            let Some(slot) = &component.kernel_slot else {
                return fault(
                    ContractFaultCode::InvalidComponent,
                    "kernel candidate requires an explicit kernel slot",
                );
            };
            validate_capability(slot, "kernel.")?;
            for capability in &component.provided_capabilities {
                validate_capability(capability, "kernel.")?;
            }
        }
        ComponentRole::InstanceAdapter => {
            reject_kernel_slot(component)?;
            for capability in &component.provided_capabilities {
                validate_capability(capability, &instance_prefix)?;
            }
        }
        ComponentRole::Package => {
            reject_kernel_slot(component)?;
            for capability in &component.provided_capabilities {
                validate_capability(capability, &package_prefix)?;
            }
        }
        ComponentRole::Evidence => {
            reject_kernel_slot(component)?;
            if !component.provided_capabilities.is_empty() {
                return fault(
                    ContractFaultCode::AuthorityEscalation,
                    "evidence cannot provide capabilities",
                );
            }
        }
    }
    Ok(())
}

fn reject_kernel_slot(component: &ComponentBinding) -> Result<(), ContractFault> {
    if component.kernel_slot.is_some() {
        return fault(
            ContractFaultCode::AuthorityEscalation,
            format!(
                "non-kernel component cannot occupy a kernel slot: {}",
                component.component_id
            ),
        );
    }
    Ok(())
}

fn validate_relative_path(path: &str) -> Result<(), ContractFault> {
    if path.is_empty()
        || path.len() > 512
        || path.starts_with('/')
        || path.contains('\\')
        || path.contains(':')
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return fault(
            ContractFaultCode::InvalidComponent,
            format!("component path is not repository-relative: {path}"),
        );
    }
    Ok(())
}

fn validate_identifier(value: &str, label: &str) -> Result<(), ContractFault> {
    if value.is_empty()
        || value.len() > 128
        || value.contains("..")
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
        || !value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
    {
        return fault(
            ContractFaultCode::InvalidIdentity,
            format!("{label} is not a normalized identifier: {value}"),
        );
    }
    Ok(())
}

fn validate_capability(value: &str, required_prefix: &str) -> Result<(), ContractFault> {
    validate_identifier(value, "capability")?;
    if !value.starts_with(required_prefix) {
        return fault(
            ContractFaultCode::InvalidCapability,
            format!("capability must start with {required_prefix}: {value}"),
        );
    }
    for forbidden in [
        "execution-authority",
        "provider-authority",
        "operator-authority",
        "kernel-authority",
        "effect-authority",
    ] {
        if value.contains(forbidden) {
            return fault(
                ContractFaultCode::AuthorityEscalation,
                format!("forbidden authority capability: {value}"),
            );
        }
    }
    Ok(())
}

fn validate_commit(value: &str, label: &str) -> Result<(), ContractFault> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return fault(
            ContractFaultCode::InvalidLineage,
            format!("{label} must be a lowercase forty-character Git commit"),
        );
    }
    Ok(())
}

fn validate_sha256(value: &str, label: &str) -> Result<(), ContractFault> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return fault(
            ContractFaultCode::DigestMismatch,
            format!("{label} must be lowercase SHA256"),
        );
    }
    Ok(())
}

fn validate_optional_digest(value: &str, required: bool, label: &str) -> Result<(), ContractFault> {
    if required {
        validate_sha256(value, label)
    } else if value.is_empty() {
        Ok(())
    } else {
        fault(
            ContractFaultCode::DigestMismatch,
            format!("{label} must be empty before sealing"),
        )
    }
}

fn require_text(value: &str, label: &str) -> Result<(), ContractFault> {
    if value.trim().is_empty() {
        return fault(
            ContractFaultCode::InvalidIdentity,
            format!("{label} cannot be empty"),
        );
    }
    Ok(())
}

fn digest_value<T: Serialize>(value: &T) -> Result<String, ContractFault> {
    let bytes = serde_json::to_vec(value).map_err(|error| ContractFault {
        code: ContractFaultCode::MachineForm,
        detail: format!("canonical JSON failed: {error}"),
    })?;
    let mut digest = Sha256::new();
    digest.update(bytes);
    let bytes = digest.finalize();
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}").map_err(|error| ContractFault {
            code: ContractFaultCode::MachineForm,
            detail: format!("SHA256 encoding failed: {error}"),
        })?;
    }
    Ok(encoded)
}

fn fault<T>(code: ContractFaultCode, detail: impl Into<String>) -> Result<T, ContractFault> {
    Err(ContractFault {
        code,
        detail: detail.into(),
    })
}

fn deserialize_unique_set<'de, D>(deserializer: D) -> Result<BTreeSet<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let values = Vec::<String>::deserialize(deserializer)?;
    let mut unique = BTreeSet::new();
    for value in values {
        if !unique.insert(value.clone()) {
            return Err(de::Error::custom(format!(
                "duplicate set member refused: {value}"
            )));
        }
    }
    Ok(unique)
}
