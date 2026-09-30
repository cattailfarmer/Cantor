//! Effect-free assembly of explicitly supplied SOP project content.
//!
//! Logical paths are attribution labels only. This crate has no host path,
//! filesystem, storage, transport, execution, or publication authority.

use std::collections::{BTreeSet, HashSet};

use cantor_sop_semantics::{
    Fault, Manifest, Package, Result, SnapshotInput, SourceDocument, digest, source, validate,
};
use serde::de;
use serde::{Deserialize, Deserializer, Serialize};

pub const PROJECT_PROFILE: &str = "cantor-sop-supplied-project/0.1";
pub const RESULT_PROFILE: &str = "cantor-sop-project-assembly/0.1";
pub const CAPABILITY: &str = "kernel.sop.project-assemble";
pub const MAX_PROJECT_FILES: usize = 2_048;
pub const MAX_PROJECT_DIAGNOSTICS: usize = 1_000;
pub const MAX_PROJECT_MACHINE_BYTES: usize = 80 * 1024 * 1024;
pub const NON_AUTHORITY: &str = "Supplied-value semantic assembly only. Logical paths grant no host access. No filesystem, storage, query, execution, provider, operator, installation, update, remote, mutation, publication, or external-effect authority is granted.";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuppliedProject {
    pub profile: String,
    pub packages: Vec<SuppliedPackage>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuppliedPackage {
    pub id: String,
    pub version: String,
    #[serde(deserialize_with = "deserialize_unique_set")]
    pub namespaces: BTreeSet<String>,
    #[serde(deserialize_with = "deserialize_unique_set")]
    pub dependencies: BTreeSet<String>,
    pub files: Vec<SuppliedFile>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuppliedFile {
    pub id: String,
    pub path: String,
    pub namespace: String,
    pub text: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectDiagnostic {
    pub source: Option<String>,
    pub path: Option<String>,
    pub diagnostic: source::Diagnostic,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectAnalysis {
    pub input: SnapshotInput,
    pub diagnostics: Vec<ProjectDiagnostic>,
    pub semantic_manifest: Option<Manifest>,
    pub complete: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectAssemblyResult {
    pub profile: String,
    pub capability: String,
    pub project_digest: String,
    pub snapshot_digest: String,
    pub analysis: ProjectAnalysis,
    pub non_authority: String,
    pub result_digest: String,
}

pub fn parse_project(bytes: &[u8]) -> Result<SuppliedProject> {
    if bytes.len() > MAX_PROJECT_MACHINE_BYTES {
        return Err(Fault::new(
            "project_machine_limit",
            format!("supplied project machine form exceeds {MAX_PROJECT_MACHINE_BYTES} bytes"),
        ));
    }
    serde_json::from_slice(bytes).map_err(Fault::from)
}

pub fn assemble(project: &SuppliedProject) -> Result<ProjectAssemblyResult> {
    let project = normalize(project);
    validate_project_shape(&project)?;
    let project_digest = digest::value("cantor-sop-supplied-project/0.1", &project)?;
    let analysis = analyze_project(project)?;
    let snapshot_digest = digest::generation(&analysis.input)?;
    let mut result = ProjectAssemblyResult {
        profile: RESULT_PROFILE.to_owned(),
        capability: CAPABILITY.to_owned(),
        project_digest,
        snapshot_digest,
        analysis,
        non_authority: NON_AUTHORITY.to_owned(),
        result_digest: String::new(),
    };
    result.result_digest = digest::value("cantor-sop-project-assembly-result/0.1", &result)?;
    Ok(result)
}

pub fn validate_result(project: &SuppliedProject, result: &ProjectAssemblyResult) -> Result<()> {
    let expected = assemble(project)?;
    if &expected != result {
        return Err(Fault::new(
            "project_result_mismatch",
            "project assembly result differs from deterministic replay",
        ));
    }
    Ok(())
}

fn normalize(project: &SuppliedProject) -> SuppliedProject {
    let mut project = project.clone();
    project.packages.sort_by(|a, b| a.id.cmp(&b.id));
    for package in &mut project.packages {
        package
            .files
            .sort_by(|a, b| (&a.id, &a.path).cmp(&(&b.id, &b.path)));
    }
    project
}

fn validate_project_shape(project: &SuppliedProject) -> Result<()> {
    if project.profile != PROJECT_PROFILE {
        return Err(Fault::new(
            "unsupported_project",
            format!("expected {PROJECT_PROFILE}"),
        ));
    }
    if project.packages.is_empty() || project.packages.len() > 256 {
        return Err(Fault::new(
            "package_limit",
            "supplied project requires 1..256 packages",
        ));
    }
    let mut package_ids = BTreeSet::new();
    let mut source_ids = BTreeSet::new();
    let mut coordinates = BTreeSet::new();
    let mut file_count = 0_usize;
    let mut source_bytes = 0_usize;
    for package in &project.packages {
        validate::identifier(&package.id)?;
        if !package_ids.insert(package.id.as_str()) || source_ids.contains(package.id.as_str()) {
            return Err(
                Fault::new("duplicate_package", "package identity is repeated").at(&package.id),
            );
        }
        if package.version.trim().is_empty()
            || package.version.len() > 65_536
            || package.version.contains('\0')
        {
            return Err(Fault::new(
                "invalid_version",
                "package version requires 1..65536 UTF-8 bytes",
            )
            .at(&package.id));
        }
        if package.namespaces.is_empty()
            || package.namespaces.len() > 64
            || package.dependencies.len() > 256
        {
            return Err(Fault::new(
                "invalid_package",
                "package needs 1..64 namespaces and at most 256 dependencies",
            )
            .at(&package.id));
        }
        for namespace in &package.namespaces {
            validate::identifier(namespace)?;
        }
        for dependency in &package.dependencies {
            validate::identifier(dependency)?;
        }
        for file in &package.files {
            file_count = file_count
                .checked_add(1)
                .ok_or_else(|| Fault::new("source_limit", "source file count overflow"))?;
            if file_count > MAX_PROJECT_FILES {
                return Err(Fault::new(
                    "source_limit",
                    format!("supplied project exceeds {MAX_PROJECT_FILES} source files"),
                ));
            }
            validate::identifier(&file.id)?;
            if !source_ids.insert(file.id.as_str()) || package_ids.contains(file.id.as_str()) {
                return Err(
                    Fault::new("duplicate_source", "source identity is repeated").at(&file.id),
                );
            }
            validate_logical_path(&file.path)?;
            if !coordinates.insert((package.id.as_str(), file.path.as_str())) {
                return Err(Fault::new(
                    "duplicate_source_path",
                    "package logical source path is repeated",
                )
                .at(&file.path));
            }
            validate::identifier(&file.namespace)?;
            if !package.namespaces.contains(&file.namespace) {
                return Err(Fault::new(
                    "undeclared_namespace",
                    "source default namespace must be declared by its package",
                )
                .at(&file.id));
            }
            if file.text.len() > source::MAX_DOCUMENT_BYTES {
                return Err(Fault::new(
                    "source_limit",
                    format!(
                        "source exceeds the {} byte document limit",
                        source::MAX_DOCUMENT_BYTES
                    ),
                )
                .at(&file.id));
            }
            source_bytes = checked_source_total(source_bytes, file.text.len())?;
        }
    }
    let known: HashSet<_> = package_ids.iter().copied().collect();
    for package in &project.packages {
        for dependency in &package.dependencies {
            if dependency == &package.id || !known.contains(dependency.as_str()) {
                return Err(Fault::new(
                    "unresolved_dependency",
                    format!("invalid dependency {dependency}"),
                )
                .at(&package.id));
            }
        }
    }
    Ok(())
}

fn checked_source_total(current: usize, additional: usize) -> Result<usize> {
    let total = current
        .checked_add(additional)
        .ok_or_else(|| Fault::new("source_limit", "source byte count overflow"))?;
    if total > cantor_sop_semantics::MAX_INPUT_BYTES {
        return Err(Fault::new(
            "source_limit",
            "supplied project source exceeds 64 MiB",
        ));
    }
    Ok(total)
}

fn validate_logical_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.len() > 4_096
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains('\\')
        || path.contains(':')
        || path.contains('\0')
        || path
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(Fault::new(
            "invalid_source_path",
            "source paths must be portable relative logical paths",
        )
        .at(path));
    }
    Ok(())
}

fn analyze_project(project: SuppliedProject) -> Result<ProjectAnalysis> {
    let mut input = SnapshotInput {
        profile: cantor_sop_semantics::INPUT_PROFILE.to_owned(),
        packages: Vec::new(),
        sources: Vec::new(),
        kinds: Vec::new(),
        contexts: Vec::new(),
        units: Vec::new(),
        relation_types: Vec::new(),
        relations: Vec::new(),
        rules: Vec::new(),
        views: Vec::new(),
    };
    let mut diagnostics = Vec::new();
    for package in project.packages {
        input.packages.push(Package {
            id: package.id.clone(),
            version: package.version,
            namespaces: package.namespaces,
            dependencies: package.dependencies,
        });
        for file in package.files {
            let source = SourceDocument {
                id: file.id,
                package: package.id.clone(),
                path: file.path,
                text: file.text,
            };
            let analysis = source::analyze(&source, &file.namespace);
            for diagnostic in analysis.diagnostics {
                diagnostics.push(ProjectDiagnostic {
                    source: Some(source.id.clone()),
                    path: Some(source.path.clone()),
                    diagnostic,
                });
                if diagnostics.len() > MAX_PROJECT_DIAGNOSTICS {
                    return Err(Fault::new(
                        "diagnostic_limit",
                        format!("project exceeds {MAX_PROJECT_DIAGNOSTICS} diagnostics"),
                    ));
                }
            }
            analysis.declarations.append_to(&mut input);
            input.sources.push(source);
        }
    }
    let semantic_manifest = if diagnostics.is_empty() {
        match validate::manifest(&input) {
            Ok(manifest) => Some(manifest),
            Err(fault) => {
                diagnostics.push(ProjectDiagnostic {
                    source: None,
                    path: None,
                    diagnostic: source::Diagnostic {
                        code: fault.code,
                        message: match fault.subject {
                            Some(subject) => format!("{subject}: {}", fault.message),
                            None => fault.message,
                        },
                        start: 0,
                        end: 0,
                    },
                });
                None
            }
        }
    } else {
        None
    };
    let complete = diagnostics.is_empty() && semantic_manifest.is_some();
    Ok(ProjectAnalysis {
        input,
        diagnostics,
        semantic_manifest,
        complete,
    })
}

fn deserialize_unique_set<'de, D>(
    deserializer: D,
) -> std::result::Result<BTreeSet<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let values = Vec::<String>::deserialize(deserializer)?;
    let mut result = BTreeSet::new();
    for value in values {
        if !result.insert(value.clone()) {
            return Err(de::Error::custom(format!(
                "duplicate semantic set member refused: {value}"
            )));
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_source_budget_refuses_without_allocating_the_boundary() {
        assert_eq!(
            checked_source_total(cantor_sop_semantics::MAX_INPUT_BYTES, 1)
                .unwrap_err()
                .code,
            "source_limit"
        );
    }
}
