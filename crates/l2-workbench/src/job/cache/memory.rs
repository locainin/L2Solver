use std::io::{self, Write};

use serde::Serialize;
use serde_json::Value;

use crate::job::{MemoryBudget, MemoryClass, MemoryLease};

use super::error::{CacheError, Result};

// JSON containers and owned strings can be much larger than their encoded bytes
// This is a conservative logical allowance, not an allocator or process RSS measurement
const JSON_BYTES_FACTOR: u64 = 128;
const ENTRY_FIXED_BYTES: u64 = 256;
const TRANSIENT_FIXED_BYTES: u64 = 64 * 1024;

pub(super) fn metadata_charge(encoded_bytes: u64) -> Result<u64> {
    encoded_bytes
        .checked_mul(JSON_BYTES_FACTOR)
        .and_then(|bytes| bytes.checked_add(ENTRY_FIXED_BYTES))
        .ok_or(CacheError::SizeOverflow)
}

pub(super) fn lookup_transient_charge(
    metadata: u64,
    manifest: u64,
    stage: u64,
    path: u64,
) -> Result<u64> {
    manifest
        .checked_mul(JSON_BYTES_FACTOR)
        .and_then(|bytes| bytes.checked_add(metadata.checked_mul(2)?))
        .and_then(|bytes| bytes.checked_add(stage.checked_mul(2)?))
        .and_then(|bytes| bytes.checked_add(path.checked_mul(2)?))
        .and_then(|bytes| bytes.checked_add(TRANSIENT_FIXED_BYTES))
        .ok_or(CacheError::SizeOverflow)
}

pub(super) fn serialized_charge(encoded_bytes: u64) -> Result<u64> {
    encoded_bytes
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(256))
        .ok_or(CacheError::SizeOverflow)
}

pub(super) fn checkpoint_charge(encoded_bytes: u64) -> Result<u64> {
    encoded_bytes
        .checked_mul(JSON_BYTES_FACTOR)
        .and_then(|bytes| bytes.checked_add(TRANSIENT_FIXED_BYTES))
        .ok_or(CacheError::SizeOverflow)
}

pub(super) fn reserve(budget: Option<&MemoryBudget>, bytes: u64) -> Result<Option<MemoryLease>> {
    budget
        .map(|budget| {
            budget
                .try_reserve(MemoryClass::Cache, bytes)
                .map_err(CacheError::from)
        })
        .transpose()
}

pub(super) fn reserve_metadata(
    budget: Option<&MemoryBudget>,
    metadata: &Value,
    limit: usize,
    retained: &mut Option<MemoryLease>,
) -> Result<Option<MemoryLease>> {
    if retained
        .as_ref()
        .is_some_and(|lease| !lease.matches_budget(budget, MemoryClass::Cache))
    {
        return Err(CacheError::InvalidInput(
            "metadata reservation belongs to another budget or class",
        ));
    }
    if budget.is_none() && retained.is_none() {
        return Ok(None);
    }
    let encoded = json_size(metadata)?;
    if encoded > u64::try_from(limit).map_err(|_| CacheError::SizeOverflow)? {
        return Err(CacheError::MetadataTooLarge {
            limit_bytes: limit,
            actual_bytes: usize::try_from(encoded).map_err(|_| CacheError::SizeOverflow)?,
        });
    }
    let required = metadata_charge(encoded)?;
    if let Some(lease) = retained.as_mut() {
        // Keep the original charge continuously while it grows to the cache allowance
        if lease.bytes() < required {
            lease.try_resize(required)?;
        }
    } else {
        *retained = reserve(budget, required)?;
    }
    let transient = lookup_transient_charge(encoded, 0, 0, 0)?;
    // A scoped retained lease can spend its worker's already-admitted future credit
    retained
        .as_ref()
        .map(|lease| lease.try_sibling(transient).map_err(CacheError::from))
        .transpose()
}

struct Counter {
    bytes: u64,
    overflowed: bool,
}

impl Write for Counter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let count =
            u64::try_from(bytes.len()).map_err(|_| io::Error::other("JSON size overflow"))?;
        if let Some(total) = self.bytes.checked_add(count) {
            self.bytes = total;
            Ok(bytes.len())
        } else {
            self.overflowed = true;
            Err(io::Error::other("JSON size overflow"))
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn json_size<T: Serialize>(value: &T) -> Result<u64> {
    let mut counter = Counter {
        bytes: 0,
        overflowed: false,
    };
    let result = serde_json::to_writer(&mut counter, value);
    if counter.overflowed {
        return Err(CacheError::SizeOverflow);
    }
    result?;
    Ok(counter.bytes)
}
