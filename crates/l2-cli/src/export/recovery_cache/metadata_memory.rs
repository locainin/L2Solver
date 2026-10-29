//! Admit the owned JSON metadata copy before encoding a recovery result

use super::{RecoveryMetadataRef, Result};
use l2_workbench::job::{MemoryBudget, MemoryClass, MemoryLease};
use serde_json::Value;
use std::io::{self, Write};

// This covers object nodes, keys, and scalar values without assuming an RSS measurement
const JSON_STRUCTURE_FACTOR: u64 = 128;
const FIXED_BYTES: u64 = 256;

pub(super) fn encode(
    metadata: &RecoveryMetadataRef<'_>,
    budget: Option<&MemoryBudget>,
) -> Result<(Value, Option<MemoryLease>)> {
    let mut memory = reserve(metadata, budget)?;
    // The large, input-dependent array is copied with fallible allocations
    let mut value = serde_json::to_value(without_omissions(metadata))?;
    let mut omissions = Vec::new();
    omissions.try_reserve_exact(metadata.omissions.len())?;
    let expected_array = metadata
        .omissions
        .len()
        .checked_mul(2)
        .ok_or("recovery metadata array size overflow")?;
    let actual_array = omissions.capacity();
    if actual_array > expected_array {
        let extra = (actual_array - expected_array)
            .checked_mul(size_of::<Value>())
            .ok_or("recovery metadata array size overflow")?;
        add_extra(&mut memory, extra)?;
    }
    for omission in metadata.omissions {
        let mut text = String::new();
        text.try_reserve_exact(omission.len())?;
        if text.capacity() > omission.len() {
            add_extra(&mut memory, text.capacity() - omission.len())?;
        }
        text.push_str(omission);
        omissions.push(Value::String(text));
    }
    let field = value
        .get_mut("omissions")
        .ok_or("serialized recovery metadata is missing omissions")?;
    *field = Value::Array(omissions);
    Ok((value, memory))
}

fn reserve(
    metadata: &RecoveryMetadataRef<'_>,
    budget: Option<&MemoryBudget>,
) -> Result<Option<MemoryLease>> {
    let Some(budget) = budget else {
        return Ok(None);
    };
    // Omission payloads are sized separately so long text is not multiplied by the node factor
    let mut encoded = Counter::default();
    serde_json::to_writer(&mut encoded, &without_omissions(metadata))?;
    let mut bytes = encoded
        .bytes
        .checked_mul(JSON_STRUCTURE_FACTOR)
        .and_then(|bytes| bytes.checked_add(FIXED_BYTES))
        .ok_or("recovery metadata size overflow")?;
    let array_bytes = metadata
        .omissions
        .len()
        .checked_mul(size_of::<Value>())
        .and_then(|bytes| bytes.checked_mul(2))
        .ok_or("recovery metadata array size overflow")?;
    bytes = bytes
        .checked_add(u64::try_from(array_bytes)?)
        .ok_or("recovery metadata size overflow")?;
    for omission in metadata.omissions {
        bytes = bytes
            .checked_add(u64::try_from(omission.len())?)
            .ok_or("recovery metadata size overflow")?;
    }
    Ok(Some(budget.try_reserve(MemoryClass::Cache, bytes)?))
}

const fn without_omissions<'a>(metadata: &RecoveryMetadataRef<'a>) -> RecoveryMetadataRef<'a> {
    RecoveryMetadataRef {
        coverage: metadata.coverage,
        omissions: &[],
        case_storage_format: metadata.case_storage_format,
        case_snapshot_usage: metadata.case_snapshot_usage,
    }
}

fn add_extra(memory: &mut Option<MemoryLease>, extra: usize) -> Result<()> {
    if let Some(memory) = memory {
        let bytes = memory
            .bytes()
            .checked_add(u64::try_from(extra)?)
            .ok_or("recovery metadata size overflow")?;
        memory.try_resize(bytes)?;
    }
    Ok(())
}

#[derive(Default)]
struct Counter {
    bytes: u64,
}

impl Write for Counter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(u64::try_from(data.len()).map_err(io::Error::other)?)
            .ok_or_else(|| io::Error::other("recovery metadata size overflow"))?;
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
