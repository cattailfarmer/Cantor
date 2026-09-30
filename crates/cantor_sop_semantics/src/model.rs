use std::collections::{BTreeMap, BTreeSet};

use serde::de;
use serde::{Deserialize, Deserializer, Serialize};

pub type Id = String;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotInput {
    pub profile: String,
    pub packages: Vec<Package>,
    pub sources: Vec<SourceDocument>,
    pub kinds: Vec<Kind>,
    pub contexts: Vec<Context>,
    pub units: Vec<Unit>,
    pub relation_types: Vec<RelationType>,
    pub relations: Vec<Relation>,
    pub rules: Vec<Rule>,
    pub views: Vec<View>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Package {
    pub id: Id,
    pub version: String,
    #[serde(deserialize_with = "deserialize_unique_set")]
    pub namespaces: BTreeSet<String>,
    #[serde(deserialize_with = "deserialize_unique_set")]
    pub dependencies: BTreeSet<Id>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceDocument {
    pub id: Id,
    pub package: Id,
    pub path: String,
    pub text: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceSpan {
    pub source: Id,
    pub start: u64,
    pub end: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Kind {
    pub id: Id,
    pub package: Id,
    pub label: String,
    pub meaning: String,
    pub source: SourceSpan,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Validity {
    pub not_before: Option<i64>,
    pub not_after: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub id: Id,
    pub package: Id,
    #[serde(deserialize_with = "deserialize_unique_set")]
    pub scopes: BTreeSet<String>,
    #[serde(deserialize_with = "deserialize_unique_set")]
    pub purposes: BTreeSet<String>,
    #[serde(deserialize_with = "deserialize_unique_set")]
    pub perspectives: BTreeSet<String>,
    pub validity: Validity,
    pub source: SourceSpan,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Authored,
    Unresolved,
    Superseded,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Unit {
    pub id: Id,
    pub package: Id,
    pub namespace: String,
    pub kind: Id,
    pub label: String,
    #[serde(deserialize_with = "deserialize_unique_set")]
    pub aliases: BTreeSet<String>,
    pub meaning: String,
    pub context: Id,
    pub status: Status,
    pub source: SourceSpan,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Flow {
    Input,
    Output,
    Member,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Role {
    pub name: String,
    #[serde(deserialize_with = "deserialize_unique_set")]
    pub allowed_kinds: BTreeSet<Id>,
    pub minimum: u32,
    pub maximum: u32,
    pub flow: Flow,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationType {
    pub id: Id,
    pub package: Id,
    pub label: String,
    pub meaning: String,
    pub roles: Vec<Role>,
    pub source: SourceSpan,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Participant {
    pub role: String,
    pub unit: Id,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Expr {
    Fact { unit: Id },
    All { args: Vec<Expr> },
    Any { args: Vec<Expr> },
    Not { arg: Box<Expr> },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Truth {
    True,
    False,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Relation {
    pub id: Id,
    pub package: Id,
    pub relation_type: Id,
    pub participants: Vec<Participant>,
    pub context: Id,
    pub guard: Option<Expr>,
    pub source: SourceSpan,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: Id,
    pub package: Id,
    pub label: String,
    pub context: Id,
    pub condition: Expr,
    pub conclusion: Id,
    pub source: SourceSpan,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct View {
    pub id: Id,
    pub package: Id,
    pub label: String,
    pub context: Id,
    #[serde(deserialize_with = "deserialize_unique_set")]
    pub units: BTreeSet<Id>,
    #[serde(deserialize_with = "deserialize_unique_set")]
    pub relations: BTreeSet<Id>,
    pub source: SourceSpan,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub profile: String,
    pub semantic_schema: String,
    pub storage_version: u32,
    pub compiler: String,
    pub generation: String,
    #[serde(deserialize_with = "deserialize_unique_set")]
    pub required_features: BTreeSet<String>,
    pub package_digests: BTreeMap<Id, String>,
    pub counts: BTreeMap<String, u64>,
    pub recognition: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceExcerpt {
    pub span: SourceSpan,
    pub path: String,
    pub source_digest: String,
    pub span_digest: String,
    pub text: String,
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
