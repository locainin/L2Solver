use std::{
    fs,
    ops::{Deref, DerefMut},
    path::Path,
    time::Duration,
};

use rusqlite::{Connection, OpenFlags, TransactionBehavior, config::DbConfig};

use super::{
    error::{CacheError, Result},
    filesystem::{HeldDirectory, LockGuard},
};

pub(super) const DATABASE_NAME: &str = "cache.sqlite3";
const SCHEMA_VERSION: u32 = 3;
const APPLICATION_ID: i64 = 0x4c32_5343;
const INITIALIZATION_LOCK: &str = "cache-init.lock";
const WAL_CLOSE_CHECKPOINT_BYTES: u64 = 64 * 1024;
// Two bounded checkpoint copies and the schema need space even with an empty file quota
const MIN_DATABASE_BYTES: u64 = 4 * 1024 * 1024;
const SQLITE_SHM_BYTES: u64 = 32 * 1024;
const WAL_CHECK_INTERVAL: i32 = 256;

pub(super) fn configure_limit(state: &mut HeldDirectory, file_limit: u64) -> Result<()> {
    let existing = state_bytes(state)?;
    let available = state.available_bytes()?.saturating_add(existing);
    // Leave room for the database, WAL, shared-memory index, and one in-flight write
    let usable = crate::job::workspace_capacity(available);
    let limit = file_limit.max(MIN_DATABASE_BYTES).min(usable / 4);
    if limit < 64 * 1024 {
        return Err(CacheError::InvalidInput("not enough space for cache state"));
    }
    state.set_database_limit(limit);
    Ok(())
}

pub(super) fn state_limit(state: &HeldDirectory) -> Result<u64> {
    let limit = state
        .database_limit()
        .ok_or(CacheError::InvalidInput("cache state limit is missing"))?;
    limit
        .checked_mul(3)
        .and_then(|bytes| bytes.checked_add(limit.div_ceil(8)))
        .and_then(|bytes| bytes.checked_add(SQLITE_SHM_BYTES))
        .ok_or(CacheError::SizeOverflow)
}

pub(super) fn state_bytes(state: &HeldDirectory) -> Result<u64> {
    let database = match fs::symlink_metadata(state.path().join(DATABASE_NAME)) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => metadata.len(),
        Ok(_) => {
            return Err(CacheError::UnsafePath(
                "SQLite database must be a regular file",
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Err(error) => return Err(error.into()),
    };
    let wal = validate_sidecar(state.path(), "-wal")?.unwrap_or(0);
    let shm = validate_sidecar(state.path(), "-shm")?.unwrap_or(0);
    database
        .checked_add(wal)
        .and_then(|bytes| bytes.checked_add(shm))
        .ok_or(CacheError::SizeOverflow)
}

pub(super) struct CacheConnection<'state> {
    connection: Connection,
    state: &'state HeldDirectory,
    writer: Option<LockGuard>,
}

impl Deref for CacheConnection<'_> {
    type Target = Connection;

    fn deref(&self) -> &Self::Target {
        &self.connection
    }
}

impl DerefMut for CacheConnection<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.connection
    }
}

impl Drop for CacheConnection<'_> {
    fn drop(&mut self) {
        if self.writer.is_some() {
            let _ = self.connection.progress_handler(0, None::<fn() -> bool>);
        }
        // Committed WAL data stays authoritative until SQLite checkpoints it
        match validate_sidecar(self.state.path(), "-wal") {
            Ok(Some(size)) if size < WAL_CLOSE_CHECKPOINT_BYTES => {
                // A configuration error keeps the normal close checkpoint enabled
                let _ = self
                    .connection
                    .set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true);
            }
            Ok(Some(_)) => {
                // Clear large logs even if idle connections keep the database open
                if self.connection.busy_timeout(Duration::ZERO).is_ok() {
                    let _ = self
                        .connection
                        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)");
                }
            }
            Ok(None) | Err(_) => {}
        }
    }
}

pub(super) fn initialize(state: &HeldDirectory, locks: &HeldDirectory) -> Result<()> {
    let _lock = locks.lock_with_retry(INITIALIZATION_LOCK, true)?;
    let mut connection = open_connection(state)?;
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
    if matches!(version, 1 | 2) {
        validate_stage_schema(&connection)?;
        if version == 2 {
            validate_execution_schema(&connection)?;
        }
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if version == 1 {
            create_execution_schema(&transaction)?;
        }
        create_retirement_schema(&transaction)?;
        validate_schema(&transaction)?;
        transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        transaction.commit()?;
    } else if version != SCHEMA_VERSION {
        return Err(CacheError::IncompatibleSchema(version));
    }
    validate_schema(&connection)?;
    enable_wal(&connection)
}

pub(super) fn open_connection(state: &HeldDirectory) -> Result<CacheConnection<'_>> {
    let database_path = state.ensure_regular_file(DATABASE_NAME)?;
    check_sidecars(state)?;
    let connection = Connection::open_with_flags(
        &database_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    if let Some(limit) = state.database_limit() {
        let page_size: u64 = connection.pragma_query_value(None, "page_size", |row| row.get(0))?;
        let pages = (limit / page_size).clamp(1, u64::from(u32::MAX) - 1);
        connection.pragma_update(None, "max_page_count", pages)?;
        connection.pragma_update(None, "journal_size_limit", limit)?;
    }
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.execute_batch("PRAGMA foreign_keys = ON; PRAGMA trusted_schema = OFF;")?;
    // Sync committed WAL changes before old generation files can be removed
    connection.pragma_update(None, "synchronous", 2_i64)?;
    Ok(CacheConnection {
        connection,
        state,
        writer: None,
    })
}

pub(super) fn check_sidecars(state: &HeldDirectory) -> Result<()> {
    state.check_location()?;
    let _ = validate_sidecar(state.path(), "-wal")?;
    let _ = validate_sidecar(state.path(), "-shm")?;
    Ok(())
}

// Writers share a gate so a pinned reader cannot grow the WAL without bound
pub(super) fn open_writer(state: &HeldDirectory) -> Result<CacheConnection<'_>> {
    let lock = state.lock_with_retry("state-writer.lock", true)?;
    writer_with_lock(state, lock)
}

pub(super) fn try_open_writer(state: &HeldDirectory) -> Result<CacheConnection<'_>> {
    let lock = state.lock("state-writer.lock", true)?;
    writer_with_lock(state, lock)
}

fn writer_with_lock(state: &HeldDirectory, lock: LockGuard) -> Result<CacheConnection<'_>> {
    let mut connection = open_connection(state)?;
    if let Some(limit) = state.database_limit() {
        let wal = state.path().join(format!("{DATABASE_NAME}-wal"));
        if validate_sidecar(state.path(), "-wal")?.unwrap_or(0) >= limit {
            connection.busy_timeout(Duration::ZERO)?;
            connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
            if validate_sidecar(state.path(), "-wal")?.unwrap_or(0) >= limit {
                return Err(CacheError::CacheBusy);
            }
            connection.busy_timeout(Duration::from_secs(5))?;
        }
        // Stop a long SQL statement after its current operation crosses the WAL allowance
        connection.connection.progress_handler(
            WAL_CHECK_INTERVAL,
            Some(move || match fs::symlink_metadata(&wal) {
                Ok(metadata) => {
                    !metadata.is_file()
                        || metadata.file_type().is_symlink()
                        || metadata.len() >= limit
                }
                Err(error) => error.kind() != std::io::ErrorKind::NotFound,
            }),
        )?;
    }
    connection.writer = Some(lock);
    Ok(connection)
}

pub(super) fn checkpoint_wal(state: &HeldDirectory) -> Result<()> {
    let connection = open_connection(state)?;
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
    create_retirement_schema(&transaction)?;
    validate_schema(&transaction)?;
    transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

fn validate_schema(connection: &Connection) -> Result<()> {
    validate_stage_schema(connection)?;
    validate_execution_schema(connection)?;
    if !has_columns(
        connection,
        "retired_generations",
        &["key", "relative_path", "bytes"],
    )? {
        return Err(CacheError::IncompatibleSchema(SCHEMA_VERSION));
    }
    Ok(())
}

fn validate_execution_schema(connection: &Connection) -> Result<()> {
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

fn create_retirement_schema(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS retired_generations (
             key TEXT NOT NULL CHECK(length(key) = 64),
             relative_path TEXT NOT NULL,
             bytes INTEGER NOT NULL CHECK(bytes >= 0),
             PRIMARY KEY(key, relative_path)
         );",
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
    let mut rows = statement.query([])?;
    let mut matched = 0;
    while let Some(row) = rows.next()? {
        let name = row
            .get_ref(1)?
            .as_str()
            .map_err(|_| CacheError::CorruptDatabase)?;
        if required.contains(&name) {
            matched += 1;
        }
    }
    Ok(matched == required.len())
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

fn validate_sidecar(state_path: &Path, suffix: &str) -> Result<Option<u64>> {
    let path = state_path.join(format!("{DATABASE_NAME}{suffix}"));
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => Err(
            CacheError::UnsafePath("SQLite sidecar must be a regular file"),
        ),
        Ok(metadata) => Ok(Some(metadata.len())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}
