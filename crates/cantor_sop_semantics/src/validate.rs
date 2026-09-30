use std::collections::{BTreeMap, BTreeSet};

use crate::{Fault, MAX_INPUT_BYTES, MAX_RECORDS, Result, digest, model::*};

fn invalid(code: &str, subject: &str, message: impl Into<String>) -> Fault {
    Fault::new(code, message).at(subject)
}

pub fn identifier(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 512
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b":._/-".contains(&byte))
    {
        return Err(invalid(
            "invalid_identifier",
            value,
            "identifiers require 1..512 ASCII letters, digits, colon, period, underscore, slash, or hyphen",
        ));
    }
    Ok(())
}

fn text(value: &str, subject: &str, required: bool) -> Result<()> {
    if value.len() > 65_536 || (required && value.trim().is_empty()) || value.contains('\0') {
        return Err(invalid(
            "invalid_text",
            subject,
            "text is empty, contains NUL, or exceeds 65536 UTF-8 bytes",
        ));
    }
    Ok(())
}

pub fn source_document(source: &SourceDocument) -> Result<()> {
    identifier(&source.id)?;
    identifier(&source.package)?;
    text(&source.path, &source.id, true)?;
    if source.text.len() > MAX_INPUT_BYTES {
        return Err(invalid(
            "source_limit",
            &source.id,
            "source text exceeds 64 MiB",
        ));
    }
    Ok(())
}

fn context_validity(context: &Context) -> Result<()> {
    if context
        .validity
        .not_before
        .zip(context.validity.not_after)
        .is_some_and(|(start, end)| start > end)
    {
        return Err(invalid(
            "invalid_validity",
            &context.id,
            "validity interval is inverted",
        ));
    }
    Ok(())
}

fn relation_type_shape(relation_type: &RelationType) -> Result<()> {
    if relation_type.roles.is_empty() || relation_type.roles.len() > 32 {
        return Err(invalid(
            "role_limit",
            &relation_type.id,
            "a relation type requires 1..32 roles",
        ));
    }
    let mut names = BTreeSet::new();
    for role in &relation_type.roles {
        identifier(&role.name)?;
        if !names.insert(&role.name) {
            return Err(invalid(
                "duplicate_role",
                &relation_type.id,
                "role names must be unique",
            ));
        }
        if role.minimum > role.maximum
            || role.maximum == 0
            || role.maximum > 1024
            || role.allowed_kinds.is_empty()
        {
            return Err(invalid(
                "invalid_role",
                &relation_type.id,
                "role needs kinds and cardinality 0 <= minimum <= maximum <= 1024",
            ));
        }
    }
    Ok(())
}

fn relation_shape(
    relation: &Relation,
    relation_type: &RelationType,
    mut unit_kind: impl FnMut(&str) -> Result<String>,
) -> Result<()> {
    if relation.participants.len() < 2 || relation.participants.len() > 1024 {
        return Err(invalid(
            "relation_arity",
            &relation.id,
            "relations require 2..1024 participants",
        ));
    }
    let mut seen = BTreeSet::new();
    let mut counts = BTreeMap::new();
    for participant in &relation.participants {
        if !seen.insert(participant) {
            return Err(invalid(
                "duplicate_participant",
                &relation.id,
                "role/unit pair is repeated",
            ));
        }
        let role = relation_type
            .roles
            .iter()
            .find(|role| role.name == participant.role)
            .ok_or_else(|| {
                invalid(
                    "unknown_role",
                    &relation.id,
                    format!("unknown role {}", participant.role),
                )
            })?;
        let kind = unit_kind(&participant.unit)?;
        if !role.allowed_kinds.contains(&kind) {
            return Err(invalid(
                "participant_kind",
                &relation.id,
                format!("{kind} is not accepted for role {}", participant.role),
            ));
        }
        *counts.entry(&participant.role).or_insert(0_u32) += 1;
    }
    for role in &relation_type.roles {
        let count = counts.get(&role.name).copied().unwrap_or(0);
        if count < role.minimum || count > role.maximum {
            return Err(invalid(
                "role_cardinality",
                &relation.id,
                format!(
                    "role {} has {count} participants; expected {}..{}",
                    role.name, role.minimum, role.maximum
                ),
            ));
        }
    }
    Ok(())
}

fn view_relation(view: &View, relation: &Relation) -> Result<()> {
    if relation
        .participants
        .iter()
        .any(|participant| !view.units.contains(&participant.unit))
    {
        return Err(invalid(
            "incomplete_view_relation",
            &view.id,
            "view must include every participant of a selected relation",
        ));
    }
    Ok(())
}

struct Validator<'a> {
    owners: BTreeMap<&'a str, &'a str>,
    visible: BTreeMap<&'a str, BTreeSet<&'a str>>,
    sources: BTreeMap<&'a str, &'a SourceDocument>,
    kinds: BTreeSet<&'a str>,
    contexts: BTreeSet<&'a str>,
    units: BTreeMap<&'a str, &'a Unit>,
}

impl Validator<'_> {
    fn reference(&self, owner: &str, target: &str) -> Result<()> {
        let target_owner = self.owners.get(target).ok_or_else(|| {
            invalid(
                "unresolved_reference",
                owner,
                format!("unknown identity {target}"),
            )
        })?;
        if !self
            .visible
            .get(owner)
            .is_some_and(|visible| visible.contains(target_owner))
        {
            return Err(invalid(
                "undeclared_dependency",
                owner,
                format!("{target} belongs to a package outside the dependency closure"),
            ));
        }
        Ok(())
    }

    fn span(&self, owner: &str, span: &SourceSpan) -> Result<()> {
        let source = self.sources.get(span.source.as_str()).ok_or_else(|| {
            invalid(
                "unresolved_source",
                owner,
                format!("unknown source {}", span.source),
            )
        })?;
        if source.package != owner {
            return Err(invalid(
                "source_ownership",
                owner,
                "a declaration's source must belong to its package",
            ));
        }
        let start = usize::try_from(span.start)
            .map_err(|_| invalid("invalid_span", owner, "start is out of range"))?;
        let end = usize::try_from(span.end)
            .map_err(|_| invalid("invalid_span", owner, "end is out of range"))?;
        if start >= end
            || end > source.text.len()
            || !source.text.is_char_boundary(start)
            || !source.text.is_char_boundary(end)
        {
            return Err(invalid(
                "invalid_span",
                &span.source,
                "source span must be nonempty, in bounds, and on UTF-8 character boundaries",
            ));
        }
        Ok(())
    }

    fn kind(&self, owner: &str, id: &str) -> Result<()> {
        self.reference(owner, id)?;
        if !self.kinds.contains(id) {
            return Err(invalid(
                "wrong_record_kind",
                id,
                "expected a kind definition",
            ));
        }
        Ok(())
    }

    fn context(&self, owner: &str, id: &str) -> Result<()> {
        self.reference(owner, id)?;
        if !self.contexts.contains(id) {
            return Err(invalid("wrong_record_kind", id, "expected a context"));
        }
        Ok(())
    }

    fn unit(&self, owner: &str, id: &str) -> Result<&Unit> {
        self.reference(owner, id)?;
        self.units
            .get(id)
            .copied()
            .ok_or_else(|| invalid("wrong_record_kind", id, "expected a semantic unit"))
    }

    fn expr(&self, owner: &str, expr: &Expr, depth: usize, nodes: &mut usize) -> Result<()> {
        *nodes += 1;
        if depth > 16 || *nodes > 1024 {
            return Err(invalid(
                "expression_limit",
                owner,
                "guard exceeds depth 16 or 1024 nodes",
            ));
        }
        match expr {
            Expr::Fact { unit } => {
                self.unit(owner, unit)?;
            }
            Expr::Not { arg } => self.expr(owner, arg, depth + 1, nodes)?,
            Expr::All { args } | Expr::Any { args } => {
                if args.is_empty() || args.len() > 64 {
                    return Err(invalid(
                        "expression_arity",
                        owner,
                        "all/any require 1..64 operands",
                    ));
                }
                for arg in args {
                    self.expr(owner, arg, depth + 1, nodes)?;
                }
            }
        }
        Ok(())
    }
}

pub fn validate(input: &SnapshotInput) -> Result<()> {
    if input.profile != crate::INPUT_PROFILE {
        return Err(Fault::new(
            "unsupported_profile",
            format!("expected {}", crate::INPUT_PROFILE),
        ));
    }
    if input.packages.is_empty() || input.packages.len() > 256 {
        return Err(Fault::new(
            "package_limit",
            "a snapshot requires 1..256 packages",
        ));
    }
    let count = input.packages.len()
        + input.sources.len()
        + input.kinds.len()
        + input.contexts.len()
        + input.units.len()
        + input.relation_types.len()
        + input.relations.len()
        + input.rules.len()
        + input.views.len();
    if count > MAX_RECORDS {
        return Err(Fault::new(
            "record_limit",
            "snapshot exceeds the record budget",
        ));
    }

    let mut identities = BTreeSet::new();
    let mut owners = BTreeMap::new();
    let packages: BTreeMap<_, _> = input
        .packages
        .iter()
        .map(|package| (package.id.as_str(), package))
        .collect();
    for package in &input.packages {
        identifier(&package.id)?;
        if !identities.insert(package.id.as_str()) {
            return Err(invalid(
                "duplicate_identity",
                &package.id,
                "identity already declared",
            ));
        }
        text(&package.version, &package.id, true)?;
        if package.namespaces.is_empty()
            || package.namespaces.len() > 64
            || package.dependencies.len() > 256
        {
            return Err(invalid(
                "invalid_package",
                &package.id,
                "package needs 1..64 namespaces and at most 256 dependencies",
            ));
        }
        for namespace in &package.namespaces {
            identifier(namespace)?;
        }
        for dependency in &package.dependencies {
            if dependency == &package.id || !packages.contains_key(dependency.as_str()) {
                return Err(invalid(
                    "unresolved_dependency",
                    &package.id,
                    format!("invalid dependency {dependency}"),
                ));
            }
        }
    }

    let mut visible: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    while visible.len() < packages.len() {
        let before = visible.len();
        for package in &input.packages {
            if visible.contains_key(package.id.as_str())
                || package
                    .dependencies
                    .iter()
                    .any(|dependency| !visible.contains_key(dependency.as_str()))
            {
                continue;
            }
            let mut closure = BTreeSet::from([package.id.as_str()]);
            for dependency in &package.dependencies {
                closure.extend(visible[dependency.as_str()].iter().copied());
            }
            visible.insert(&package.id, closure);
        }
        if before == visible.len() {
            return Err(Fault::new(
                "dependency_cycle",
                "package dependency graph must be acyclic",
            ));
        }
    }

    macro_rules! register {
        ($items:expr) => {
            for item in $items {
                identifier(&item.id)?;
                if !identities.insert(item.id.as_str()) {
                    return Err(invalid(
                        "duplicate_identity",
                        &item.id,
                        "identity already declared",
                    ));
                }
                if !packages.contains_key(item.package.as_str()) {
                    return Err(invalid(
                        "unresolved_package",
                        &item.id,
                        "owning package is missing",
                    ));
                }
                owners.insert(item.id.as_str(), item.package.as_str());
            }
        };
    }
    register!(&input.sources);
    register!(&input.kinds);
    register!(&input.contexts);
    register!(&input.units);
    register!(&input.relation_types);
    register!(&input.relations);
    register!(&input.rules);
    register!(&input.views);

    let mut source_bytes = 0_usize;
    let mut source_paths = BTreeSet::new();
    for source in &input.sources {
        source_document(source)?;
        if !source_paths.insert((&source.package, &source.path)) {
            return Err(invalid(
                "duplicate_source_path",
                &source.id,
                "package source path is duplicated",
            ));
        }
        source_bytes = source_bytes
            .checked_add(source.text.len())
            .ok_or_else(|| Fault::new("source_limit", "source byte overflow"))?;
        if source_bytes > MAX_INPUT_BYTES {
            return Err(Fault::new("source_limit", "source text exceeds 64 MiB"));
        }
    }

    let validator = Validator {
        owners,
        visible,
        sources: input
            .sources
            .iter()
            .map(|source| (source.id.as_str(), source))
            .collect(),
        kinds: input.kinds.iter().map(|kind| kind.id.as_str()).collect(),
        contexts: input
            .contexts
            .iter()
            .map(|context| context.id.as_str())
            .collect(),
        units: input
            .units
            .iter()
            .map(|unit| (unit.id.as_str(), unit))
            .collect(),
    };

    for kind in &input.kinds {
        text(&kind.label, &kind.id, true)?;
        text(&kind.meaning, &kind.id, true)?;
        validator.span(&kind.package, &kind.source)?;
    }
    for context in &input.contexts {
        validator.span(&context.package, &context.source)?;
        for value in context
            .scopes
            .iter()
            .chain(context.purposes.iter())
            .chain(context.perspectives.iter())
        {
            text(value, &context.id, true)?;
        }
        context_validity(context)?;
    }
    for unit in &input.units {
        text(&unit.label, &unit.id, true)?;
        text(&unit.meaning, &unit.id, true)?;
        if unit.aliases.len() > 128 {
            return Err(invalid(
                "alias_limit",
                &unit.id,
                "at most 128 aliases are supported",
            ));
        }
        for alias in &unit.aliases {
            text(alias, &unit.id, true)?;
        }
        if !packages[unit.package.as_str()]
            .namespaces
            .contains(&unit.namespace)
        {
            return Err(invalid(
                "undeclared_namespace",
                &unit.id,
                "namespace is not declared by the owning package",
            ));
        }
        validator.kind(&unit.package, &unit.kind)?;
        validator.context(&unit.package, &unit.context)?;
        validator.span(&unit.package, &unit.source)?;
    }

    let relation_types: BTreeMap<_, _> = input
        .relation_types
        .iter()
        .map(|relation_type| (relation_type.id.as_str(), relation_type))
        .collect();
    for relation_type in &input.relation_types {
        text(&relation_type.label, &relation_type.id, true)?;
        text(&relation_type.meaning, &relation_type.id, true)?;
        validator.span(&relation_type.package, &relation_type.source)?;
        relation_type_shape(relation_type)?;
        for role in &relation_type.roles {
            for kind in &role.allowed_kinds {
                validator.kind(&relation_type.package, kind)?;
            }
        }
    }

    let mut incidences = 0_usize;
    for relation in &input.relations {
        validator.reference(&relation.package, &relation.relation_type)?;
        let relation_type = relation_types
            .get(relation.relation_type.as_str())
            .ok_or_else(|| {
                invalid(
                    "wrong_record_kind",
                    &relation.id,
                    "expected a relation type",
                )
            })?;
        validator.context(&relation.package, &relation.context)?;
        validator.span(&relation.package, &relation.source)?;
        incidences += relation.participants.len();
        if incidences > 1_000_000 {
            return Err(Fault::new(
                "incidence_limit",
                "snapshot exceeds one million participant incidences",
            ));
        }
        relation_shape(relation, relation_type, |id| {
            validator
                .unit(&relation.package, id)
                .map(|unit| unit.kind.clone())
        })?;
        if let Some(expr) = &relation.guard {
            validator.expr(&relation.package, expr, 0, &mut 0)?;
        }
    }

    for rule in &input.rules {
        text(&rule.label, &rule.id, true)?;
        validator.context(&rule.package, &rule.context)?;
        validator.span(&rule.package, &rule.source)?;
        validator.unit(&rule.package, &rule.conclusion)?;
        validator.expr(&rule.package, &rule.condition, 0, &mut 0)?;
    }

    let relations: BTreeMap<_, _> = input
        .relations
        .iter()
        .map(|relation| (relation.id.as_str(), relation))
        .collect();
    for view in &input.views {
        text(&view.label, &view.id, true)?;
        validator.context(&view.package, &view.context)?;
        validator.span(&view.package, &view.source)?;
        for unit in &view.units {
            validator.unit(&view.package, unit)?;
        }
        for relation_id in &view.relations {
            validator.reference(&view.package, relation_id)?;
            let relation = relations
                .get(relation_id.as_str())
                .ok_or_else(|| invalid("wrong_record_kind", &view.id, "view expects a relation"))?;
            view_relation(view, relation)?;
        }
    }
    Ok(())
}

pub fn manifest(input: &SnapshotInput) -> Result<Manifest> {
    validate(input)?;
    let normalized = digest::normalize(input);
    let mut package_digests = BTreeMap::new();
    while package_digests.len() < normalized.packages.len() {
        for package in &normalized.packages {
            if package_digests.contains_key(&package.id)
                || package
                    .dependencies
                    .iter()
                    .any(|dependency| !package_digests.contains_key(dependency))
            {
                continue;
            }
            let dependencies: BTreeMap<_, _> = package
                .dependencies
                .iter()
                .map(|dependency| (dependency, &package_digests[dependency]))
                .collect();
            let owned = serde_json::json!({
                "package": package,
                "dependencies": dependencies,
                "sources": normalized.sources.iter().filter(|item| item.package == package.id).collect::<Vec<_>>(),
                "kinds": normalized.kinds.iter().filter(|item| item.package == package.id).collect::<Vec<_>>(),
                "contexts": normalized.contexts.iter().filter(|item| item.package == package.id).collect::<Vec<_>>(),
                "units": normalized.units.iter().filter(|item| item.package == package.id).collect::<Vec<_>>(),
                "relation_types": normalized.relation_types.iter().filter(|item| item.package == package.id).collect::<Vec<_>>(),
                "relations": normalized.relations.iter().filter(|item| item.package == package.id).collect::<Vec<_>>(),
                "rules": normalized.rules.iter().filter(|item| item.package == package.id).collect::<Vec<_>>(),
                "views": normalized.views.iter().filter(|item| item.package == package.id).collect::<Vec<_>>()
            });
            package_digests.insert(
                package.id.clone(),
                digest::value("cantor-sop-semantic-package/0.1", &owned)?,
            );
        }
    }
    let counts = BTreeMap::from([
        ("packages".to_owned(), normalized.packages.len() as u64),
        ("sources".to_owned(), normalized.sources.len() as u64),
        ("kinds".to_owned(), normalized.kinds.len() as u64),
        ("contexts".to_owned(), normalized.contexts.len() as u64),
        ("units".to_owned(), normalized.units.len() as u64),
        (
            "relation_types".to_owned(),
            normalized.relation_types.len() as u64,
        ),
        ("relations".to_owned(), normalized.relations.len() as u64),
        ("rules".to_owned(), normalized.rules.len() as u64),
        ("views".to_owned(), normalized.views.len() as u64),
    ]);
    Ok(Manifest {
        profile: crate::SNAPSHOT_PROFILE.to_owned(),
        semantic_schema: crate::SEMANTIC_SCHEMA.to_owned(),
        storage_version: crate::STORAGE_VERSION,
        compiler: crate::COMPILER_ID.to_owned(),
        generation: digest::generation(&normalized)?,
        required_features: crate::REQUIRED_FEATURES
            .iter()
            .map(|feature| (*feature).to_owned())
            .collect(),
        package_digests,
        counts,
        recognition: "unrecognized_preview".to_owned(),
    })
}
