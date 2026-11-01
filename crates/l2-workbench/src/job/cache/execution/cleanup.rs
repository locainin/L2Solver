//! Reclaim cursor files only after checking the committed execution reference

use super::{
    Cache, CacheError, Component, Durability, HASH_MEMORY_BYTES, HeldDirectory, OptionalExtension,
    Result, column_length, database, envelope_revision, generation_directory, memory,
    valid_cursor_directory, verified_component,
};
use std::{fs, io};

mod reader;

struct CursorReference {
    directory: HeldDirectory,
    executor: Component,
    _memory: Option<super::MemoryLease>,
}

fn read_reference(cache: &Cache, key: &str) -> Result<Option<CursorReference>> {
    let connection = database::open_connection(&cache.inner.state_root, Durability::Checkpoint)?;
    let rowid = connection
        .query_row(
            "SELECT rowid FROM executions WHERE key = ?1",
            [key],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    let Some(rowid) = rowid else {
        return Ok(None);
    };
    let path_bytes = column_length(&connection, "executions", "relative_path", rowid)?;
    let encoded_bytes = column_length(&connection, "executions", "envelope_json", rowid)?;
    if path_bytes == 0 || path_bytes > 256 {
        return Err(CacheError::CorruptCheckpoint);
    }
    // Startup maintenance charges an attached budget without fixing an absent budget choice
    let charge = memory::serialized_charge(encoded_bytes)?
        .checked_add(path_bytes)
        .and_then(|bytes| bytes.checked_add(8 * 1024))
        .ok_or(CacheError::SizeOverflow)?;
    let admission = memory::reserve(cache.configured_memory_budget(), charge)?;
    let relative: String = connection.query_row(
        "SELECT relative_path FROM executions WHERE rowid = ?1",
        [rowid],
        |row| row.get(0),
    )?;
    // The incremental column reader skips metadata without materializing its JSON values
    let input = connection.blob_open("main", "executions", "envelope_json", rowid, true)?;
    let locations = reader::read(io::BufReader::with_capacity(8 * 1024, input))
        .map_err(|_| CacheError::CorruptCheckpoint)?;
    let [graph, blobs, executor] = locations.components;
    if envelope_revision(locations.version, locations.revision).is_none()
        || graph.directory.is_some()
        || blobs.directory.is_some()
        || executor
            .directory
            .as_deref()
            .is_some_and(|name| locations.version < 3 || !valid_cursor_directory(name))
    {
        return Err(CacheError::CorruptCheckpoint);
    }
    Ok(Some(CursorReference {
        directory: generation_directory(cache, key, &relative)?,
        executor,
        _memory: admission,
    }))
}

pub(in crate::job::cache) fn cleanup_cursor_debris(cache: &Cache, key: &str) -> Result<()> {
    let Some(CursorReference {
        directory,
        executor,
        _memory,
    }) = read_reference(cache, key)?
    else {
        return Ok(());
    };
    if let Some(current) = &executor.directory
        && directory
            .open_child(current)?
            .open_file("executor")?
            .metadata()?
            .len()
            != executor.bytes
    {
        return Err(CacheError::CorruptCheckpoint);
    }
    let mut verified = None;
    let mut verify_current = || -> Result<()> {
        if verified.is_none() {
            // Verify the current cursor only when cleanup is about to discard older bytes
            let admission = memory::reserve(cache.configured_memory_budget(), HASH_MEMORY_BYTES)?;
            let file = match &executor.directory {
                Some(name) => {
                    verified_component(&directory.open_child(name)?, "executor", &executor)?
                }
                None => verified_component(&directory, "executor", &executor)?,
            };
            verified = Some((file, admission));
        }
        Ok(())
    };
    if executor.directory.is_some() {
        match directory.open_file("executor") {
            Ok(_) => {
                verify_current()?;
                remove_optional_file(&directory, "executor")?;
                directory.sync()?;
            }
            Err(CacheError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    for item in fs::read_dir(directory.path())? {
        let item = item?;
        let name = item.file_name();
        let name = name
            .to_str()
            .ok_or(CacheError::UnsafePath("cursor name is not UTF-8"))?;
        if name.starts_with("cursor-") && Some(name) != executor.directory.as_deref() {
            if !valid_cursor_directory(name) {
                return Err(CacheError::UnsafePath("cursor directory name is invalid"));
            }
            verify_current()?;
            remove_cursor(&directory, name)?;
        }
    }
    Ok(())
}

pub(super) fn remove_cursor(parent: &HeldDirectory, name: &str) -> Result<()> {
    let directory = parent.open_child(name)?;
    // Only the one managed file is removed; unexpected contents leave the charge in place
    remove_optional_file(&directory, "executor")?;
    directory.sync()?;
    parent.remove_empty_child(name)?;
    parent.sync()
}

fn remove_optional_file(directory: &HeldDirectory, name: &str) -> Result<()> {
    match directory.remove_file(name) {
        Ok(()) => Ok(()),
        Err(CacheError::Io(error)) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}
