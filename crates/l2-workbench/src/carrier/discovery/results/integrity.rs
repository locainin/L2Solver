//! Bounded row access and streaming integrity checks for result stores

use super::super::model::{
    DiscoveryCandidate, DiscoveryError, DiscoveryIdentity, DiscoveryLimit, Partition,
    PartitionSummary,
};
use super::model::{RESULTS_SCHEMA, StoredDiscoverySummary};
use crate::hashing::is_sha256_digest as valid_sha256;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{error::Error, fmt::Display, io};

#[derive(Serialize)]
struct DigestSummary<'a> {
    schema_version: u32,
    plan_sha256: &'a str,
    identity: &'a DiscoveryIdentity,
    sample_receipt_count: usize,
    omitted_empty_sample_ids: &'a [u64],
    parameter_space_size: usize,
    input_bytes: usize,
    input_budget_bytes: usize,
    attempted_parameters: usize,
    attempted_transforms: usize,
    work_bytes: usize,
    work_budget_bytes: usize,
    candidate_budget: usize,
    output_bytes: u64,
    output_budget_bytes: u64,
    disk_budget_bytes: u64,
    candidate_count: usize,
    printable_run_count: usize,
    enumeration_complete: bool,
    limits: &'a [DiscoveryLimit],
}

pub(super) fn content_digest(
    connection: &Connection,
    summary: &StoredDiscoverySummary,
    max_record_bytes: u64,
) -> Result<String, Box<dyn Error>> {
    let summary_bytes = serde_json::to_vec(&DigestSummary {
        schema_version: summary.schema_version,
        plan_sha256: &summary.plan_sha256,
        identity: &summary.identity,
        sample_receipt_count: summary.sample_receipt_count,
        omitted_empty_sample_ids: &summary.omitted_empty_sample_ids,
        parameter_space_size: summary.parameter_space_size,
        input_bytes: summary.input_bytes,
        input_budget_bytes: summary.input_budget_bytes,
        attempted_parameters: summary.attempted_parameters,
        attempted_transforms: summary.attempted_transforms,
        work_bytes: summary.work_bytes,
        work_budget_bytes: summary.work_budget_bytes,
        candidate_budget: summary.candidate_budget,
        output_bytes: summary.output_bytes,
        output_budget_bytes: summary.output_budget_bytes,
        disk_budget_bytes: summary.disk_budget_bytes,
        candidate_count: summary.candidate_count,
        printable_run_count: summary.printable_run_count,
        enumeration_complete: summary.enumeration_complete,
        limits: &summary.limits,
    })?;
    let mut digest = Sha256::new();
    digest.update(b"l2solver-carrier-discovery-results-v1\0");
    digest.update(summary_bytes);
    digest.update(checked_metadata_value(connection, "plan", max_record_bytes)?.as_bytes());
    digest_rows(
        connection,
        "sample_receipts",
        "sample_id",
        max_record_bytes,
        &mut digest,
    )?;
    digest_candidate_rows(connection, max_record_bytes, &mut digest)?;
    digest_rows(
        connection,
        "printable_runs",
        "run_id",
        max_record_bytes,
        &mut digest,
    )?;
    digest_output_rows(connection, &mut digest)?;
    Ok(format!("{:x}", digest.finalize()))
}

fn digest_candidate_rows(
    connection: &Connection,
    max_record_bytes: u64,
    digest: &mut Sha256,
) -> Result<(), Box<dyn Error>> {
    let mut statement =
        connection.prepare("SELECT candidate_id FROM candidates ORDER BY candidate_id")?;
    let mut rows = statement.query([])?;
    digest.update(b"candidates");
    while let Some(row) = rows.next()? {
        let id = row.get::<_, i64>(0)?;
        let (payload, stored_digest) = checked_row_payload(
            connection,
            "candidates",
            "candidate_id",
            id,
            max_record_bytes,
        )?;
        let (discovery_digest, control_digest) = candidate_digest_indexes(connection, id)?;
        if crate::sha256(payload.as_bytes()) != stored_digest {
            return Err(invalid_store("stored candidate row digest does not match"));
        }
        let candidate: DiscoveryCandidate = serde_json::from_str(&payload)?;
        if discovery_digest
            != candidate
                .discovery
                .as_ref()
                .and_then(|summary| summary.output_sha256.clone())
            || control_digest
                != candidate
                    .control
                    .as_ref()
                    .and_then(|summary| summary.output_sha256.clone())
        {
            return Err(invalid_store(
                "candidate output digest index does not match its receipt",
            ));
        }
        digest.update(u64::try_from(id)?.to_le_bytes());
        digest.update(stored_digest.as_bytes());
        if let Some(value) = discovery_digest {
            digest.update(value.as_bytes());
        }
        if let Some(value) = control_digest {
            digest.update(value.as_bytes());
        }
    }
    Ok(())
}

fn digest_rows(
    connection: &Connection,
    table: &str,
    key: &str,
    max_record_bytes: u64,
    digest: &mut Sha256,
) -> Result<(), Box<dyn Error>> {
    let sql = format!("SELECT {key} FROM {table} ORDER BY {key}");
    let mut statement = connection.prepare(&sql)?;
    let mut rows = statement.query([])?;
    digest.update(table.as_bytes());
    while let Some(row) = rows.next()? {
        let id = row.get::<_, i64>(0)?;
        let (payload, stored_digest) =
            checked_row_payload(connection, table, key, id, max_record_bytes)?;
        if crate::sha256(payload.as_bytes()) != stored_digest {
            return Err(invalid_store("stored result row digest does not match"));
        }
        digest.update(u64::try_from(id)?.to_le_bytes());
        digest.update(stored_digest.as_bytes());
    }
    Ok(())
}

fn digest_output_rows(connection: &Connection, digest: &mut Sha256) -> Result<(), Box<dyn Error>> {
    let mut statement = connection.prepare(
        "SELECT rowid, candidate_id, partition, unit_index, length(payload), payload_sha256 \
         FROM outputs ORDER BY candidate_id, partition, unit_index",
    )?;
    let mut rows = statement.query([])?;
    digest.update(b"outputs");
    let mut buffer = vec![0; 64 * 1024];
    while let Some(row) = rows.next()? {
        let row_id = row.get::<_, i64>(0)?;
        let candidate_id = row.get::<_, usize>(1)?;
        let partition = row.get_ref(2)?.as_str()?;
        if !matches!(partition, "discovery" | "control") {
            return Err(invalid_store("stored output partition is invalid"));
        }
        let unit_index = row.get::<_, usize>(3)?;
        let length = row.get::<_, u64>(4)?;
        let stored_digest = checked_output_digest(row.get_ref(5)?)?;
        let actual_digest = visit_output_blob(connection, row_id, length, &mut buffer, |_| Ok(()))?;
        if actual_digest != stored_digest {
            return Err(invalid_store("stored output row digest does not match"));
        }
        digest.update(u64::try_from(candidate_id)?.to_le_bytes());
        digest.update(partition.as_bytes());
        digest.update(u64::try_from(unit_index)?.to_le_bytes());
        digest.update(stored_digest.as_bytes());
    }
    Ok(())
}

pub(super) fn validate_schema(
    connection: &Connection,
    max_record_bytes: u64,
) -> Result<(), Box<dyn Error>> {
    let version = checked_metadata_value(connection, "schema_version", max_record_bytes)?;
    if version != RESULTS_SCHEMA.to_string() {
        return Err(invalid_store("unsupported result store schema"));
    }
    Ok(())
}

pub(super) fn checked_metadata_value(
    connection: &Connection,
    key: &str,
    max_record_bytes: u64,
) -> Result<String, Box<dyn Error>> {
    let length: u64 = connection
        .query_row(
            "SELECT length(CAST(value AS BLOB)) FROM metadata WHERE key = ?1",
            [key],
            |row| row.get(0),
        )
        .optional()?
        .ok_or_else(|| invalid_store("required result metadata is missing"))?;
    if length > max_record_bytes {
        return Err(invalid_store(
            "stored result metadata record exceeds reader limit",
        ));
    }
    let value: String =
        connection.query_row("SELECT value FROM metadata WHERE key = ?1", [key], |row| {
            row.get(0)
        })?;
    if u64::try_from(value.len())? != length {
        return Err(invalid_store("stored result metadata length changed"));
    }
    Ok(value)
}

pub(super) fn checked_row_payload(
    connection: &Connection,
    table: &str,
    key: &str,
    id: i64,
    max_record_bytes: u64,
) -> Result<(String, String), Box<dyn Error>> {
    let sql = format!(
        "SELECT length(CAST(payload AS BLOB)), length(CAST(payload_sha256 AS BLOB)) FROM {table} WHERE {key} = ?1"
    );
    let (payload_length, digest_length): (u64, Option<u64>) = connection
        .query_row(&sql, [id], |row| Ok((row.get(0)?, row.get(1)?)))
        .optional()?
        .ok_or_else(|| invalid_store("stored result row is missing"))?;
    if payload_length > max_record_bytes {
        return Err(invalid_store("stored result record exceeds reader limit"));
    }
    if digest_length != Some(64) {
        return Err(invalid_store(
            "stored result row digest has an invalid length",
        ));
    }
    let sql = format!("SELECT payload, payload_sha256 FROM {table} WHERE {key} = ?1");
    let (payload, digest): (String, String) =
        connection.query_row(&sql, [id], |row| Ok((row.get(0)?, row.get(1)?)))?;
    if u64::try_from(payload.len())? != payload_length || !valid_sha256(&digest) {
        return Err(invalid_store("stored result row identity is invalid"));
    }
    Ok((payload, digest))
}

pub(super) fn candidate_digest_indexes(
    connection: &Connection,
    candidate_id: i64,
) -> Result<(Option<String>, Option<String>), Box<dyn Error>> {
    let lengths: (Option<u64>, Option<u64>) = connection.query_row(
        "SELECT length(CAST(discovery_sha256 AS BLOB)), length(CAST(control_sha256 AS BLOB)) \
         FROM candidates WHERE candidate_id = ?1",
        [candidate_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if lengths.0.is_some_and(|length| length != 64) || lengths.1.is_some_and(|length| length != 64)
    {
        return Err(invalid_store(
            "candidate output digest index has an invalid length",
        ));
    }
    let indexes: (Option<String>, Option<String>) = connection.query_row(
        "SELECT discovery_sha256, control_sha256 FROM candidates WHERE candidate_id = ?1",
        [candidate_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if indexes
        .0
        .as_deref()
        .is_some_and(|digest| !valid_sha256(digest))
        || indexes
            .1
            .as_deref()
            .is_some_and(|digest| !valid_sha256(digest))
    {
        return Err(invalid_store("candidate output digest index is invalid"));
    }
    Ok(indexes)
}

pub(super) fn checked_output_digest(
    value: rusqlite::types::ValueRef<'_>,
) -> Result<String, Box<dyn Error>> {
    let digest = value.as_str()?;
    if !valid_sha256(digest) {
        return Err(invalid_store(
            "stored output digest has an invalid identity",
        ));
    }
    Ok(digest.to_owned())
}

pub(super) fn visit_output_blob(
    connection: &Connection,
    row_id: i64,
    expected_length: u64,
    buffer: &mut [u8],
    mut visit: impl FnMut(&[u8]) -> Result<(), Box<dyn Error>>,
) -> Result<String, Box<dyn Error>> {
    if buffer.is_empty() {
        return Err(invalid_store("output reader buffer must be nonempty"));
    }
    let mut blob = connection.blob_open("main", "outputs", "payload", row_id, true)?;
    if u64::try_from(blob.size())? != expected_length {
        return Err(invalid_store(
            "stored output length changed inside its snapshot",
        ));
    }
    let mut row_digest = Sha256::new();
    let mut consumed = 0_u64;
    loop {
        let count = io::Read::read(&mut blob, buffer)?;
        if count == 0 {
            break;
        }
        let chunk = buffer
            .get(..count)
            .ok_or_else(|| invalid_store("output reader returned an invalid byte count"))?;
        consumed = consumed
            .checked_add(u64::try_from(count)?)
            .ok_or_else(|| invalid_store("stored output byte count overflowed"))?;
        row_digest.update(chunk);
        visit(chunk)?;
    }
    blob.close()?;
    if consumed != expected_length {
        return Err(invalid_store("stored output bytes are truncated"));
    }
    Ok(format!("{:x}", row_digest.finalize()))
}

pub(super) fn put_metadata<T: Serialize>(
    connection: &Connection,
    key: &str,
    value: &T,
) -> Result<(), Box<dyn Error>> {
    let value = serde_json::to_string(value)?;
    connection.execute(
        "INSERT INTO metadata(key, value) VALUES(?1, ?2) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

pub(super) fn decode_metadata<T: DeserializeOwned>(
    connection: &Connection,
    key: &str,
    max_record_bytes: u64,
) -> Result<T, Box<dyn Error>> {
    Ok(serde_json::from_str(&checked_metadata_value(
        connection,
        key,
        max_record_bytes,
    )?)?)
}

pub(super) fn decode_row<T: DeserializeOwned>(
    payload: &str,
    digest: &str,
) -> Result<T, Box<dyn Error>> {
    if crate::sha256(payload.as_bytes()) != digest {
        return Err(invalid_store("stored result row digest does not match"));
    }
    Ok(serde_json::from_str(payload)?)
}

pub(super) fn page_limit(limit: usize) -> Result<i64, Box<dyn Error>> {
    if limit == 0 {
        return Err(invalid_store("result page size must be positive"));
    }
    Ok(i64::try_from(limit)?)
}

pub(super) const fn partition_name(partition: Partition) -> &'static str {
    match partition {
        Partition::Discovery => "discovery",
        Partition::Control => "control",
    }
}

pub(super) const fn partition_summary(
    candidate: &DiscoveryCandidate,
    partition: Partition,
) -> Option<&PartitionSummary> {
    match partition {
        Partition::Discovery => candidate.discovery.as_ref(),
        Partition::Control => candidate.control.as_ref(),
    }
}

pub(super) fn invalid_store(message: &str) -> Box<dyn Error> {
    io::Error::new(io::ErrorKind::InvalidData, message).into()
}

pub(super) fn store_error(error: impl Display) -> DiscoveryError {
    DiscoveryError::ResultStore(error.to_string())
}
