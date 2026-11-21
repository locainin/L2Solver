//! Bind cache files and their state database before removing any old data

use std::{
    fs,
    io::{self, Read, Write},
};

use super::{
    database,
    error::{CacheError, Result},
    filesystem::HeldDirectory,
    manager::is_referenced,
    manifest::safe_entry_path,
};
use crate::hashing::is_sha256_digest;

const PAIRING: &str = "pairing";

pub(super) fn bind(
    cache: &HeldDirectory,
    state: &HeldDirectory,
    entries: &HeldDirectory,
    staging: &HeldDirectory,
    locks: &HeldDirectory,
) -> Result<()> {
    let cache_identity = cache.identity()?;
    let state_identity = state.identity()?;
    let cached = read_pairing(cache)?;
    let saved = read_pairing(state)?;
    if cached
        .as_deref()
        .is_some_and(|value| value != state_identity)
        || saved
            .as_deref()
            .is_some_and(|value| value != cache_identity)
    {
        return Err(CacheError::UnsafePath(
            "cache and state directories belong to different pairs",
        ));
    }
    // Reject a mismatched pair before SQLite can migrate or change its state file
    database::initialize(state, locks)?;
    if cached.is_none() || saved.is_none() {
        // Old caches have no pairing; refuse unknown or live data before adopting them
        let _quota = locks.lock_with_retry("quota.lock", true)?;
        validate_legacy(state, entries, staging, locks)?;
        if cached.is_none() {
            write_pairing(cache, &state_identity)?;
        }
        if saved.is_none() {
            write_pairing(state, &cache_identity)?;
        }
    }
    Ok(())
}

fn read_pairing(directory: &HeldDirectory) -> Result<Option<String>> {
    let file = match directory.open_file(PAIRING) {
        Ok(file) => file,
        Err(CacheError::Io(error)) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut value = String::new();
    file.take(4097).read_to_string(&mut value)?;
    if value.is_empty() || value.len() > 4096 {
        return Err(CacheError::UnsafePath("cache pairing is invalid"));
    }
    Ok(Some(value))
}

fn write_pairing(directory: &HeldDirectory, identity: &str) -> Result<()> {
    let mut marker = tempfile::NamedTempFile::new_in(directory.path())?;
    marker.write_all(identity.as_bytes())?;
    marker.as_file().sync_all()?;
    marker
        .persist_noclobber(directory.path().join(PAIRING))
        .map_err(|error| error.error)?;
    directory.sync()
}

fn validate_legacy(
    state: &HeldDirectory,
    entries: &HeldDirectory,
    staging: &HeldDirectory,
    locks: &HeldDirectory,
) -> Result<()> {
    for file in fs::read_dir(locks.path())? {
        let file = file?;
        let name = file.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(key) = name.strip_suffix(".lock") else {
            continue;
        };
        if is_sha256_digest(key) {
            // A live legacy reader or writer must finish before pairing can be adopted
            let _lock = locks.inspect_lock(name)?;
        }
    }
    for item in fs::read_dir(staging.path())? {
        let item = item?;
        let name = item.file_name();
        let name = name
            .to_str()
            .ok_or(CacheError::UnsafePath("invalid legacy staging key"))?;
        let directory = staging.inspect_child(name)?;
        if fs::read_dir(directory.path())?
            .next()
            .transpose()?
            .is_some()
        {
            return Err(CacheError::UnsafePath(
                "legacy cache contains unverified staging data",
            ));
        }
    }
    let connection = database::open_connection(state)?;
    for item in fs::read_dir(entries.path())? {
        let item = item?;
        let key = item.file_name();
        let key = key
            .to_str()
            .ok_or(CacheError::UnsafePath("invalid legacy entry key"))?;
        if !is_sha256_digest(key) {
            return Err(CacheError::UnsafePath("invalid legacy entry key"));
        }
        let directory = entries.inspect_child(key)?;
        for item in fs::read_dir(directory.path())? {
            let item = item?;
            let name = item.file_name();
            let name = name
                .to_str()
                .ok_or(CacheError::UnsafePath("invalid legacy generation"))?;
            directory.inspect_child(name)?;
            if !is_referenced(&connection, key, &format!("{key}/{name}"))? {
                return Err(CacheError::UnsafePath(
                    "legacy cache contains an unknown generation",
                ));
            }
        }
    }
    let mut statement = connection.prepare(
        "SELECT key, relative_path FROM entries UNION ALL SELECT key, relative_path FROM executions UNION ALL SELECT key, relative_path FROM retired_generations",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let key: String = row.get(0)?;
        let relative: String = row.get(1)?;
        let path = safe_entry_path(entries.path(), &key, &relative)?;
        if !fs::symlink_metadata(path)?.is_dir() {
            return Err(CacheError::UnsafePath("legacy cache generation is missing"));
        }
    }
    Ok(())
}
