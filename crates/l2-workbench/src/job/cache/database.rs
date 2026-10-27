use std::{fs, path::Path, time::Duration};

use rusqlite::{Connection, OpenFlags, TransactionBehavior};

use super::{
    error::{CacheError, Result},
    filesystem::HeldDirectory,
};

pub(super) const DATABASE_NAME: &str = "cache.sqlite3";
const SCHEMA_VERSION: u32 = 2;
const APPLICATION_ID: i64 = 0x4c32_5343;
const INITIALIZATION_LOCK: &str = "cache-init.lock";

#[derive(Clone, Copy)]
pub(super) enum Durability {
    Recomputable,
    Checkpoint,
}

pub(super) fn initialize(state: &HeldDirectory, locks: &HeldDirectory) -> Result<()> {
    let _lock = locks.lock_with_retry(INITIALIZATION_LOCK, true)?;
    let mut connection = open_connection(state, Durability::Checkpoint)?;
    // Check ownership and schema before changing another database's journal mode
    let application_id = pragma_i64(&connection, "application_id")?;
    let version = pragma_i64(&connection, "user_version")?;
    if version == 0 && application_id == 0 {
        let tables = user_table_count(&connection)?;
        if tables != 0 {
            return Err(CacheError::IncompatibleDatabase);
        }
        enable_wal(&connection)?;
        create_schema(&mut connection)?;
        return Ok(());
    }
    if application_id != APPLICATION_ID {
        return Err(CacheError::IncompatibleDatabase);
    }
    let version = u32::try_from(version).map_err(|_| CacheError::IncompatibleDatabase)?;
    if version == 1 {
        validate_stage_schema(&connection)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        create_execution_schema(&transaction)?;
        validate_schema(&transaction)?;
        transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        transaction.commit()?;
    } else if version != SCHEMA_VERSION {
        return Err(CacheError::IncompatibleSchema(version));
    }
    validate_schema(&connection)?;
    enable_wal(&connection)
}

pub(super) fn open_connection(state: &HeldDirectory, durability: Durability) -> Result<Connection> {
    let database_path = state.ensure_regular_file(DATABASE_NAME)?;
    for suffix in ["-wal", "-shm"] {
        validate_sidecar(state.path(), suffix)?;
    }
    let connection = Connection::open_with_flags(
        &database_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.execute_batch("PRAGMA foreign_keys = ON; PRAGMA trusted_schema = OFF;")?;
    let synchronous = match durability {
        Durability::Recomputable => 1_i64,
        Durability::Checkpoint => 2_i64,
    };
    connection.pragma_update(None, "synchronous", synchronous)?;
    Ok(connection)
}

pub(super) fn checkpoint_wal(state: &HeldDirectory) -> Result<()> {
    let connection = open_connection(state, Durability::Checkpoint)?;
    connection.execute_batch("PRAGMA wal_checkpoint(PASSIVE);")?;
    Ok(())
}

fn enable_wal(connection: &Connection) -> Result<()> {
    let journal_mode: String =
        connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(CacheError::InvalidInput("`SQLite` WAL mode is unavailable"));
    }
    Ok(())
}

fn create_schema(connection: &mut Connection) -> Result<()> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(
        "CREATE TABLE entries (
             key TEXT PRIMARY KEY NOT NULL CHECK(length(key) = 64),
             stage TEXT NOT NULL,
             status INTEGER NOT NULL CHECK(status IN (1, 2)),
             relative_path TEXT NOT NULL,
             metadata_json TEXT NOT NULL,
             manifest_json TEXT NOT NULL,
             bytes INTEGER NOT NULL CHECK(bytes >= 0),
             created_ns INTEGER NOT NULL,
             accessed_ns INTEGER NOT NULL
         );
         CREATE INDEX entries_lru ON entries(accessed_ns, created_ns, key);
         CREATE TABLE checkpoints (
             key TEXT PRIMARY KEY NOT NULL CHECK(length(key) = 64),
             status INTEGER NOT NULL CHECK(status IN (1, 2)),
             snapshot_version INTEGER NOT NULL,
             snapshot_json TEXT NOT NULL,
             updated_ns INTEGER NOT NULL
         );
         PRAGMA application_id = 1278366531;",
    )?;
    create_execution_schema(&transaction)?;
    validate_schema(&transaction)?;
    transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

fn validate_schema(connection: &Connection) -> Result<()> {
    validate_stage_schema(connection)?;
    if !has_columns(
        connection,
        "executions",
        &["key", "relative_path", "envelope_json", "bytes"],
    )? || !has_columns(
        connection,
        "execution_reservations",
        &["token", "key", "bytes"],
    )? {
        return Err(CacheError::IncompatibleSchema(SCHEMA_VERSION));
    }
    Ok(())
}

fn create_execution_schema(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS executions (
             key TEXT PRIMARY KEY NOT NULL CHECK(length(key) = 64),
             relative_path TEXT NOT NULL,
             envelope_json TEXT NOT NULL,
             bytes INTEGER NOT NULL CHECK(bytes >= 0)
         );
         CREATE TABLE IF NOT EXISTS execution_reservations (
             token TEXT PRIMARY KEY NOT NULL,
             key TEXT NOT NULL CHECK(length(key) = 64),
             bytes INTEGER NOT NULL CHECK(bytes >= 0)
         );
         CREATE INDEX IF NOT EXISTS execution_reservations_key ON execution_reservations(key);",
    )?;
    Ok(())
}

fn validate_stage_schema(connection: &Connection) -> Result<()> {
    let required_entries = [
        "key",
        "stage",
        "status",
        "relative_path",
        "metadata_json",
        "manifest_json",
        "bytes",
        "created_ns",
        "accessed_ns",
    ];
    let required_checkpoints = [
        "key",
        "status",
        "snapshot_version",
        "snapshot_json",
        "updated_ns",
    ];
    if !has_columns(connection, "entries", &required_entries)?
        || !has_columns(connection, "checkpoints", &required_checkpoints)?
    {
        return Err(CacheError::IncompatibleSchema(SCHEMA_VERSION));
    }
    Ok(())
}

fn has_columns(connection: &Connection, table: &str, required: &[&str]) -> Result<bool> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(required
        .iter()
        .all(|required_column| columns.iter().any(|column| column == required_column)))
}

fn pragma_i64(connection: &Connection, name: &str) -> Result<i64> {
    connection
        .query_row(&format!("PRAGMA {name}"), [], |row| row.get(0))
        .map_err(Into::into)
}

fn user_table_count(connection: &Connection) -> Result<u64> {
    connection
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )
        .map_err(Into::into)
}

fn validate_sidecar(state_path: &Path, suffix: &str) -> Result<()> {
    let path = state_path.join(format!("{DATABASE_NAME}{suffix}"));
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => Err(
            CacheError::UnsafePath("SQLite sidecar must be a regular file"),
        ),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}
