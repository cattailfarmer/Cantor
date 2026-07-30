use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    AdmittedPackage, QueryFault, QueryFaultKind, SemanticId, SemanticRelation, SemanticUnit,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FabricMetrics {
    pub package_count: usize,
    pub semantic_unit_count: usize,
    pub relation_count: usize,
    pub signed_source_bytes: usize,
    pub serialized_package_bytes: usize,
}

#[derive(Clone, Debug)]
pub struct SemanticFabric {
    packages: BTreeMap<SemanticId, AdmittedPackage>,
    unit_packages: BTreeMap<SemanticId, SemanticId>,
    units: BTreeMap<SemanticId, SemanticUnit>,
    labels: BTreeMap<String, BTreeSet<SemanticId>>,
    relations: Vec<(SemanticId, SemanticRelation)>,
}

impl SemanticFabric {
    pub fn from_admitted(
        packages: impl IntoIterator<Item = AdmittedPackage>,
    ) -> Result<Self, QueryFault> {
        let mut fabric = Self {
            packages: BTreeMap::new(),
            unit_packages: BTreeMap::new(),
            units: BTreeMap::new(),
            labels: BTreeMap::new(),
            relations: Vec::new(),
        };
        let mut relation_ids = BTreeSet::new();
        for package in packages {
            let package_id = package.package().package_id.clone();
            if fabric.packages.contains_key(&package_id) {
                return Err(QueryFault::new(
                    QueryFaultKind::ProofGap,
                    "fabric_load",
                    format!("duplicate admitted package identity {package_id}"),
                    vec![package_id],
                ));
            }
            for unit in &package.content().semantic_units {
                if fabric
                    .unit_packages
                    .insert(unit.unit_id.clone(), package_id.clone())
                    .is_some()
                {
                    return Err(QueryFault::new(
                        QueryFaultKind::Ambiguous,
                        "fabric_load",
                        format!(
                            "semantic identity {} occurs in more than one admitted package",
                            unit.unit_id
                        ),
                        vec![unit.unit_id.clone()],
                    ));
                }
                fabric.units.insert(unit.unit_id.clone(), unit.clone());
            }
            for (label, unit_ids) in &package.content().exact_indexes.labels {
                fabric
                    .labels
                    .entry(label.clone())
                    .or_default()
                    .extend(unit_ids.iter().cloned());
            }
            for relation in &package.content().relations {
                if !relation_ids.insert(relation.relation_id.clone()) {
                    return Err(QueryFault::new(
                        QueryFaultKind::Ambiguous,
                        "fabric_load",
                        format!(
                            "relation identity {} occurs in more than one admitted package",
                            relation.relation_id
                        ),
                        vec![relation.relation_id.clone()],
                    ));
                }
                fabric
                    .relations
                    .push((package_id.clone(), relation.clone()));
            }
            fabric.packages.insert(package_id, package);
        }
        if fabric.packages.is_empty() {
            return Err(QueryFault::new(
                QueryFaultKind::ProofGap,
                "fabric_load",
                "semantic fabric requires at least one admitted package",
                Vec::new(),
            ));
        }
        fabric
            .relations
            .sort_by(|left, right| left.1.relation_id.cmp(&right.1.relation_id));
        Ok(fabric)
    }

    pub fn package(&self, id: &SemanticId) -> Option<&AdmittedPackage> {
        self.packages.get(id)
    }

    pub fn package_for_unit(&self, id: &SemanticId) -> Option<&AdmittedPackage> {
        let package_id = self.unit_packages.get(id)?;
        self.packages.get(package_id)
    }

    pub fn unit(&self, id: &SemanticId) -> Option<&SemanticUnit> {
        self.units.get(id)
    }

    pub fn exact_label(&self, label: &str) -> impl Iterator<Item = &SemanticId> {
        self.labels.get(&normalize(label)).into_iter().flatten()
    }

    pub fn units(&self) -> impl Iterator<Item = &SemanticUnit> {
        self.units.values()
    }

    pub fn relations(&self) -> impl Iterator<Item = &(SemanticId, SemanticRelation)> {
        self.relations.iter()
    }

    pub fn package_ids(&self) -> impl Iterator<Item = &SemanticId> {
        self.packages.keys()
    }

    pub fn metrics(&self) -> Result<FabricMetrics, QueryFault> {
        let mut signed_source_bytes = 0_usize;
        let mut serialized_package_bytes = 0_usize;
        for package in self.packages.values() {
            signed_source_bytes = signed_source_bytes.saturating_add(
                package
                    .content()
                    .sources
                    .iter()
                    .map(|source| source.bytes.len())
                    .fold(0_usize, usize::saturating_add),
            );
            serialized_package_bytes = serialized_package_bytes.saturating_add(
                serde_json::to_vec(package.package())
                    .map_err(|error| {
                        QueryFault::new(
                            QueryFaultKind::ProofGap,
                            "fabric_metrics",
                            error.to_string(),
                            Vec::new(),
                        )
                    })?
                    .len(),
            );
        }
        Ok(FabricMetrics {
            package_count: self.packages.len(),
            semantic_unit_count: self.units.len(),
            relation_count: self.relations.len(),
            signed_source_bytes,
            serialized_package_bytes,
        })
    }
}

pub(super) fn normalize(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}
