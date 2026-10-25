//! Source and omitted-sample receipts retained in discovery reports

use super::super::{
    model::{DiscoveryError, DiscoveryMapping, DiscoverySample, DiscoverySampleReceipt, Partition},
    plan::Partitions,
};
use crate::{evidence::SourceRange, serialization::CountWriter};
use serde::Serialize;
use std::{collections::HashSet, io::Write};

pub(super) fn retained_source_receipts(
    samples: &[DiscoverySample<'_>],
    partitions: &Partitions,
    omitted: &[u64],
    maximum: usize,
) -> Result<(Vec<DiscoverySampleReceipt>, usize), DiscoveryError> {
    let omitted_bytes = encoded_omitted_ids(omitted, maximum)?;
    let remaining = maximum
        .checked_sub(omitted_bytes)
        .ok_or(DiscoveryError::ReportBudgetExceeded { limit: maximum })?;
    let (receipts, bytes) = sample_receipts(samples, partitions, remaining)?;
    Ok((receipts, bytes + omitted_bytes))
}

pub(super) fn sample_receipt(
    sample: &DiscoverySample<'_>,
    partition: Partition,
) -> Result<DiscoverySampleReceipt, DiscoveryError> {
    let source_bit_count = sample
        .bytes
        .len()
        .checked_mul(8)
        .ok_or(DiscoveryError::InvalidSelection)?;
    Ok(DiscoverySampleReceipt {
        sample_id: sample.id,
        session_id: sample.session_id,
        partition,
        sequence: sample.sequence,
        source_scope: clone_string(&sample.source_scope)?,
        direction: clone_string(&sample.direction)?,
        local_identity: clone_string(&sample.local_identity)?,
        input_length: sample.bytes.len(),
        input_sha256: crate::sha256(sample.bytes),
        mappings: clone_mappings(&sample.mappings)?,
        source_bit_start: 0,
        source_bit_count,
    })
}

fn encoded_omitted_ids(ids: &[u64], maximum_bytes: usize) -> Result<usize, DiscoveryError> {
    let mut writer = CountWriter::new(maximum_bytes);
    serde_json::to_writer(&mut writer, ids).map_err(|_| DiscoveryError::ReportBudgetExceeded {
        limit: maximum_bytes,
    })?;
    Ok(writer.written())
}

#[derive(Serialize)]
struct SampleReceiptRef<'a> {
    sample_id: u64,
    session_id: u64,
    partition: Partition,
    sequence: u64,
    source_scope: &'a str,
    direction: &'a str,
    local_identity: &'a str,
    input_length: usize,
    input_sha256: String,
    mappings: &'a [DiscoveryMapping],
    source_bit_start: usize,
    source_bit_count: usize,
}

fn sample_receipts(
    samples: &[DiscoverySample<'_>],
    partitions: &Partitions,
    maximum_bytes: usize,
) -> Result<(Vec<DiscoverySampleReceipt>, usize), DiscoveryError> {
    let mut control_indexes = HashSet::new();
    control_indexes
        .try_reserve(partitions.control.len())
        .map_err(|_| DiscoveryError::AllocationFailed)?;
    control_indexes.extend(partitions.control.iter().copied());

    // Count the encoded receipts before cloning their source maps into the retained report
    let mut writer = CountWriter::new(maximum_bytes);
    writer
        .write_all(b"[")
        .map_err(|_| DiscoveryError::ReportBudgetExceeded {
            limit: maximum_bytes,
        })?;
    for (index, sample) in samples.iter().enumerate() {
        if index > 0 {
            writer
                .write_all(b",")
                .map_err(|_| DiscoveryError::ReportBudgetExceeded {
                    limit: maximum_bytes,
                })?;
        }
        let bit_count = sample
            .bytes
            .len()
            .checked_mul(8)
            .ok_or(DiscoveryError::InvalidSelection)?;
        let receipt = SampleReceiptRef {
            sample_id: sample.id,
            session_id: sample.session_id,
            partition: if control_indexes.contains(&index) {
                Partition::Control
            } else {
                Partition::Discovery
            },
            sequence: sample.sequence,
            source_scope: &sample.source_scope,
            direction: &sample.direction,
            local_identity: &sample.local_identity,
            input_length: sample.bytes.len(),
            input_sha256: crate::sha256(sample.bytes),
            mappings: &sample.mappings,
            source_bit_start: 0,
            source_bit_count: bit_count,
        };
        serde_json::to_writer(&mut writer, &receipt).map_err(|_| {
            DiscoveryError::ReportBudgetExceeded {
                limit: maximum_bytes,
            }
        })?;
    }
    writer
        .write_all(b"]")
        .map_err(|_| DiscoveryError::ReportBudgetExceeded {
            limit: maximum_bytes,
        })?;

    // The complete source receipt set fits, so retained maps are cloned with checked reserves
    let mut receipts = Vec::new();
    receipts
        .try_reserve_exact(samples.len())
        .map_err(|_| DiscoveryError::AllocationFailed)?;
    for (index, sample) in samples.iter().enumerate() {
        receipts.push(DiscoverySampleReceipt {
            sample_id: sample.id,
            session_id: sample.session_id,
            partition: if control_indexes.contains(&index) {
                Partition::Control
            } else {
                Partition::Discovery
            },
            sequence: sample.sequence,
            source_scope: clone_string(&sample.source_scope)?,
            direction: clone_string(&sample.direction)?,
            local_identity: clone_string(&sample.local_identity)?,
            input_length: sample.bytes.len(),
            input_sha256: crate::sha256(sample.bytes),
            mappings: clone_mappings(&sample.mappings)?,
            source_bit_start: 0,
            source_bit_count: sample.bytes.len() * 8,
        });
    }
    Ok((receipts, writer.written()))
}

fn clone_mappings(mappings: &[DiscoveryMapping]) -> Result<Vec<DiscoveryMapping>, DiscoveryError> {
    let mut cloned = Vec::new();
    cloned
        .try_reserve_exact(mappings.len())
        .map_err(|_| DiscoveryError::AllocationFailed)?;
    for mapping in mappings {
        let source = clone_string(&mapping.range.source)?;
        cloned.push(DiscoveryMapping {
            offset: mapping.offset,
            range: SourceRange {
                source,
                packet: mapping.range.packet,
                offset: mapping.range.offset,
                length: mapping.range.length,
            },
        });
    }
    Ok(cloned)
}

pub(super) fn clone_string(value: &str) -> Result<String, DiscoveryError> {
    let mut cloned = String::new();
    cloned
        .try_reserve_exact(value.len())
        .map_err(|_| DiscoveryError::AllocationFailed)?;
    cloned.push_str(value);
    Ok(cloned)
}
