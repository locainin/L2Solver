use std::io;

use rusqlite::{OptionalExtension, Transaction, params};

use super::{
    database::{self, Durability},
    error::{CacheError, Result},
    filesystem::HeldDirectory,
    manager::{CacheInner, remove_generation},
    manifest::safe_entry_path,
};

// Record old files before replacing their live pointer so their space stays counted
pub(super) fn record(
    transaction: &Transaction<'_>,
    entries: &HeldDirectory,
    key: &str,
    relative_path: &str,
    bytes: i64,
) -> Result<()> {
    safe_entry_path(entries.path(), key, relative_path)?;
    if bytes < 0 {
        return Err(CacheError::CorruptDatabase);
    }
    transaction.execute(
        "INSERT INTO retired_generations(key, relative_path, bytes) VALUES (?1, ?2, ?3)",
        params![key, relative_path, bytes],
    )?;
    Ok(())
}

// Call only while holding the exclusive key lock
pub(super) fn cleanup(inner: &CacheInner, key: &str, relative_path: &str) -> Result<()> {
    safe_entry_path(inner.entries.path(), key, relative_path)?;
    let connection = database::open_connection(&inner.state_root, Durability::Checkpoint)?;
    let is_current: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM entries WHERE key = ?1 AND relative_path = ?2)
             OR EXISTS(SELECT 1 FROM executions WHERE key = ?1 AND relative_path = ?2)",
        params![key, relative_path],
        |row| row.get(0),
    )?;
    if is_current {
        return Err(CacheError::CorruptEntry(
            "retired generation is still active".to_owned(),
        ));
    }
    remove_generation(&inner.entries, key, relative_path)?;
    match inner.entries.open_child(key) {
        Ok(directory) => directory.sync()?,
        Err(CacheError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    inner.entries.sync()?;
    // Release accounting only after the directory removal has reached stable storage
    connection.execute(
        "DELETE FROM retired_generations WHERE key = ?1 AND relative_path = ?2",
        params![key, relative_path],
    )?;
    Ok(())
}

pub(super) fn cleanup_key(inner: &CacheInner, key: &str) -> Result<()> {
    let connection = database::open_connection(&inner.state_root, Durability::Checkpoint)?;
    let mut statement =
        connection.prepare("SELECT relative_path FROM retired_generations WHERE key = ?1")?;
    let paths = statement
        .query_map([key], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for path in paths {
        match cleanup(inner, key, &path) {
            Ok(()) | Err(CacheError::Io(_) | CacheError::Database(_)) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub(super) enum Current {
    Stage,
    Execution,
}

pub(super) fn record_current(
    transaction: &Transaction<'_>,
    entries: &HeldDirectory,
    current: Current,
    key: &str,
    replacement: &str,
) -> Result<Option<String>> {
    let query = match current {
        Current::Stage => "SELECT relative_path, bytes FROM entries WHERE key = ?1",
        Current::Execution => "SELECT relative_path, bytes FROM executions WHERE key = ?1",
    };
    let old = transaction
        .query_row(query, [key], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })
        .optional()?;
    if let Some((path, bytes)) = &old {
        if path != replacement {
            record(transaction, entries, key, path, *bytes)?;
            return Ok(Some(path.clone()));
        }
        safe_entry_path(entries.path(), key, path)?;
    }
    Ok(None)
}
