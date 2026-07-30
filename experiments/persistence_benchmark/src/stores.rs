use std::{
    fs::{self, File},
    io::Write,
    path::Path,
};

use cantor_core::{CompiledSourcePackage, EmbeddedRuntimeEnvironment, TrustStore};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};

const REDB_HEADER: TableDefinition<&str, &[u8]> = TableDefinition::new("environment_header");
pub(crate) const REDB_PACKAGES: TableDefinition<u64, &[u8]> = TableDefinition::new("packages");

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentHeader {
    environment_version: String,
    now_epoch_seconds: u64,
    trust_store: TrustStore,
}

impl EnvironmentHeader {
    fn from_environment(environment: &EmbeddedRuntimeEnvironment) -> Self {
        Self {
            environment_version: environment.environment_version.clone(),
            now_epoch_seconds: environment.now_epoch_seconds,
            trust_store: environment.trust_store.clone(),
        }
    }

    fn into_environment(self, packages: Vec<CompiledSourcePackage>) -> EmbeddedRuntimeEnvironment {
        EmbeddedRuntimeEnvironment {
            environment_version: self.environment_version,
            now_epoch_seconds: self.now_epoch_seconds,
            trust_store: self.trust_store,
            packages,
        }
    }
}

pub fn write_json(
    path: &Path,
    environment: &EmbeddedRuntimeEnvironment,
) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = serde_json::to_vec(environment)?;
    let mut file = File::create(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

pub fn load_json(path: &Path) -> Result<EmbeddedRuntimeEnvironment, Box<dyn std::error::Error>> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

pub fn write_sqlite(
    path: &Path,
    environment: &EmbeddedRuntimeEnvironment,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut connection = Connection::open(path)?;
    connection.execute_batch(
        "
        PRAGMA journal_mode = DELETE;
        PRAGMA synchronous = FULL;
        CREATE TABLE environment (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            header_json BLOB NOT NULL
        ) STRICT;
        CREATE TABLE package (
            ordinal INTEGER PRIMARY KEY,
            package_id TEXT NOT NULL UNIQUE,
            package_digest TEXT NOT NULL,
            package_json BLOB NOT NULL
        ) STRICT;
        ",
    )?;
    let transaction = connection.transaction()?;
    transaction.execute(
        "INSERT INTO environment(singleton, header_json) VALUES (1, ?1)",
        [serde_json::to_vec(&EnvironmentHeader::from_environment(
            environment,
        ))?],
    )?;
    {
        let mut statement = transaction.prepare(
            "INSERT INTO package(ordinal, package_id, package_digest, package_json)
             VALUES (?1, ?2, ?3, ?4)",
        )?;
        for (ordinal, package) in environment.packages.iter().enumerate() {
            let digest = package
                .certificate
                .as_ref()
                .ok_or("unsigned package in persistence benchmark")?
                .package_digest
                .value
                .as_str();
            statement.execute(params![
                ordinal as i64,
                package.package_id.as_str(),
                digest,
                serde_json::to_vec(package)?
            ])?;
        }
    }
    transaction.commit()?;
    connection.close().map_err(|(_, error)| error)?;
    Ok(())
}

pub fn load_sqlite(path: &Path) -> Result<EmbeddedRuntimeEnvironment, Box<dyn std::error::Error>> {
    let connection = Connection::open(path)?;
    let header_bytes: Vec<u8> = connection.query_row(
        "SELECT header_json FROM environment WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    let header: EnvironmentHeader = serde_json::from_slice(&header_bytes)?;
    let mut statement = connection.prepare(
        "SELECT ordinal, package_id, package_digest, package_json
         FROM package ORDER BY ordinal ASC",
    )?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut packages = Vec::with_capacity(rows.len());
    for (expected_ordinal, (ordinal, package_id, package_digest, bytes)) in
        rows.into_iter().enumerate()
    {
        if ordinal != expected_ordinal as i64 {
            return Err(format!(
                "sqlite package ordinal {ordinal} is not contiguous expected ordinal {expected_ordinal}"
            )
            .into());
        }
        let package = serde_json::from_slice::<CompiledSourcePackage>(&bytes)?;
        if package.package_id.as_str() != package_id {
            return Err(format!(
                "sqlite package identity metadata {package_id} differs from signed package {}",
                package.package_id
            )
            .into());
        }
        let signed_digest = package
            .certificate
            .as_ref()
            .ok_or("unsigned package in SQLite persistence artifact")?
            .package_digest
            .value
            .as_str();
        if signed_digest != package_digest {
            return Err(
                "sqlite package digest metadata differs from recognition certificate".into(),
            );
        }
        packages.push(package);
    }
    Ok(header.into_environment(packages))
}

pub fn write_redb(
    path: &Path,
    environment: &EmbeddedRuntimeEnvironment,
) -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::create(path)?;
    let transaction = database.begin_write()?;
    {
        let header_bytes = serde_json::to_vec(&EnvironmentHeader::from_environment(environment))?;
        let mut table = transaction.open_table(REDB_HEADER)?;
        table.insert("environment", header_bytes.as_slice())?;
    }
    {
        let mut table = transaction.open_table(REDB_PACKAGES)?;
        for (ordinal, package) in environment.packages.iter().enumerate() {
            let bytes = serde_json::to_vec(package)?;
            table.insert(ordinal as u64, bytes.as_slice())?;
        }
    }
    transaction.commit()?;
    drop(database);
    Ok(())
}

pub fn load_redb(path: &Path) -> Result<EmbeddedRuntimeEnvironment, Box<dyn std::error::Error>> {
    let database = Database::open(path)?;
    let transaction = database.begin_read()?;
    let header = {
        let table = transaction.open_table(REDB_HEADER)?;
        let bytes = table
            .get("environment")?
            .ok_or("redb environment header missing")?
            .value()
            .to_vec();
        serde_json::from_slice::<EnvironmentHeader>(&bytes)?
    };
    let packages = {
        let table = transaction.open_table(REDB_PACKAGES)?;
        let mut packages = Vec::new();
        for (expected_ordinal, entry) in table.iter()?.enumerate() {
            let (ordinal, value) = entry?;
            if ordinal.value() != expected_ordinal as u64 {
                return Err(format!(
                    "redb package ordinal {} is not contiguous expected ordinal {expected_ordinal}",
                    ordinal.value()
                )
                .into());
            }
            packages.push(serde_json::from_slice::<CompiledSourcePackage>(
                value.value(),
            )?);
        }
        packages
    };
    Ok(header.into_environment(packages))
}
