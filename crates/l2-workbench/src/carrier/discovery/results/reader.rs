//! Read-only paged access to verified discovery results

use super::super::model::{
    DiscoveryCandidate, DiscoverySample, DiscoverySampleReceipt, Partition, PartitionSummary,
    PrintableRun,
};
use super::{
    integrity::{
        candidate_digest_indexes, checked_metadata_value, checked_output_digest,
        checked_row_payload, content_digest, decode_metadata, decode_row, invalid_store,
        page_limit, partition_name, partition_summary, validate_schema, visit_output_blob,
    },
    model::{
        DEFAULT_MAX_RESULT_PAGE_BYTES, DEFAULT_MAX_RESULT_RECORD_BYTES, RESULTS_FILE,
        RESULTS_SCHEMA, ResultPage, ResultReadOptions, StoredDiscoverySummary,
    },
};
use crate::hashing::is_sha256_digest as valid_sha256;
use crate::store::paths::Directory;
use rusqlite::{Connection, OpenFlags, params};
use sha2::{Digest, Sha256};
use std::{error::Error, fs, io::Write, path::Path};

/// Durable results directory opened read-only after integrity verification
pub struct DiscoveryResultStore {
    connection: Connection,
    _directory: Directory,
    summary: StoredDiscoverySummary,
    max_record_bytes: u64,
    max_page_bytes: u64,
}

impl DiscoveryResultStore {
    /// Open a completed result directory and verify its content digest and disk budget
    ///
    /// # Errors
    /// Rejects incomplete, changed, truncated, oversized, or unsupported result stores
    pub fn open(directory: &Path, max_disk_bytes: u64) -> Result<Self, Box<dyn Error>> {
        Self::open_with_options(
            directory,
            ResultReadOptions {
                max_disk_bytes,
                max_record_bytes: DEFAULT_MAX_RESULT_RECORD_BYTES,
                max_page_bytes: DEFAULT_MAX_RESULT_PAGE_BYTES,
            },
        )
    }

    /// Open a completed result directory with independent disk and record budgets
    ///
    /// The read transaction stays open for this handle, so integrity checks and later pages
    /// see the same `SQLite` snapshot
    ///
    /// # Errors
    /// Rejects incomplete, changed, truncated, oversized, or unsupported result stores
    pub fn open_with_options(
        directory: &Path,
        options: ResultReadOptions,
    ) -> Result<Self, Box<dyn Error>> {
        if options.max_disk_bytes == 0
            || options.max_record_bytes == 0
            || options.max_page_bytes == 0
        {
            return Err(invalid_store(
                "reader disk, record, and page budgets must be positive",
            ));
        }
        let held_directory = Directory::open(directory)?;
        let path = held_directory.path().join(RESULTS_FILE);
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_file() || metadata.len() > options.max_disk_bytes {
            return Err(invalid_store(
                "result database is not a regular file within the disk budget",
            ));
        }
        let connection = Connection::open_with_flags(
            fs::canonicalize(path)?,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        // Keep every later page and export on the same checked database snapshot
        connection.execute_batch("BEGIN DEFERRED")?;
        validate_schema(&connection, options.max_record_bytes)?;
        let complete = checked_metadata_value(&connection, "complete", options.max_record_bytes)?;
        if complete != "1" {
            return Err(invalid_store("result store is incomplete"));
        }
        let summary: StoredDiscoverySummary =
            decode_metadata(&connection, "summary", options.max_record_bytes)?;
        let plan_document: String = decode_metadata(&connection, "plan", options.max_record_bytes)?;
        let verified_result_digest =
            content_digest(&connection, &summary, options.max_record_bytes)?;
        if summary.schema_version != RESULTS_SCHEMA
            || crate::sha256(plan_document.as_bytes()) != summary.plan_sha256
            || summary.result_sha256 != verified_result_digest
        {
            return Err(invalid_store("result store content digest does not match"));
        }
        Ok(Self {
            connection,
            _directory: held_directory,
            summary,
            max_record_bytes: options.max_record_bytes,
            max_page_bytes: options.max_page_bytes,
        })
    }

    /// Return the verified summary without loading pageable records
    #[must_use]
    pub const fn summary(&self) -> &StoredDiscoverySummary {
        &self.summary
    }

    /// Read candidate summaries after an optional candidate identifier
    ///
    /// # Errors
    /// Rejects a zero page size or malformed stored rows
    pub fn list_candidates(
        &self,
        after: Option<usize>,
        limit: usize,
    ) -> Result<ResultPage<DiscoveryCandidate>, Box<dyn Error>> {
        let limit = page_limit(limit)?;
        let mut statement = self.connection.prepare(
            "SELECT candidate_id FROM candidates \
             WHERE (?1 IS NULL OR candidate_id > ?1) ORDER BY candidate_id LIMIT ?2",
        )?;
        let mut rows = statement.query(params![after.map(i64::try_from).transpose()?, limit])?;
        let mut candidates = Vec::new();
        let mut page_bytes = 0_u64;
        while let Some(row) = rows.next()? {
            let row_id = row.get::<_, i64>(0)?;
            let id = usize::try_from(row_id)?;
            let row_budget = self
                .max_record_bytes
                .min(self.max_page_bytes.saturating_sub(page_bytes));
            let (payload, digest) = checked_row_payload(
                &self.connection,
                "candidates",
                "candidate_id",
                row_id,
                row_budget,
            )?;
            page_bytes = page_bytes
                .checked_add(u64::try_from(payload.len())?)
                .ok_or_else(|| invalid_store("result page size overflowed"))?;
            candidate_digest_indexes(&self.connection, row_id)?;
            let candidate: DiscoveryCandidate = decode_row(&payload, &digest)?;
            if candidate.id != id {
                return Err(invalid_store(
                    "candidate row identifier does not match its receipt",
                ));
            }
            candidates.push(candidate);
        }
        let next_after = if candidates.len() == usize::try_from(limit)? {
            candidates.last().map(|candidate| candidate.id)
        } else {
            None
        };
        Ok(ResultPage {
            rows: candidates,
            next_after,
        })
    }

    /// Retrieve one complete candidate summary by stable identifier
    ///
    /// # Errors
    /// Rejects missing candidates or changed row contents
    pub fn candidate(&self, candidate_id: usize) -> Result<DiscoveryCandidate, Box<dyn Error>> {
        let candidate_key = i64::try_from(candidate_id)?;
        let (payload, digest) = checked_row_payload(
            &self.connection,
            "candidates",
            "candidate_id",
            candidate_key,
            self.max_record_bytes,
        )?;
        candidate_digest_indexes(&self.connection, candidate_key)?;
        let candidate: DiscoveryCandidate = decode_row(&payload, &digest)?;
        if candidate.id != candidate_id {
            return Err(invalid_store(
                "candidate row identifier does not match its receipt",
            ));
        }
        Ok(candidate)
    }

    /// Read source mappings and discovery/control assignments as a bounded page
    ///
    /// # Errors
    /// Rejects a zero page size or changed source receipt rows
    pub fn sample_receipts(
        &self,
        after_sample_id: Option<u64>,
        limit: usize,
    ) -> Result<ResultPage<DiscoverySampleReceipt, u64>, Box<dyn Error>> {
        let limit = page_limit(limit)?;
        let mut statement = self.connection.prepare(
            "SELECT sample_id FROM sample_receipts \
             WHERE (?1 IS NULL OR sample_id > ?1) ORDER BY sample_id LIMIT ?2",
        )?;
        let mut rows = statement.query(params![
            after_sample_id.map(i64::try_from).transpose()?,
            limit
        ])?;
        let mut receipts = Vec::new();
        let mut page_bytes = 0_u64;
        while let Some(row) = rows.next()? {
            let row_id = row.get::<_, i64>(0)?;
            let id = u64::try_from(row_id)?;
            let row_budget = self
                .max_record_bytes
                .min(self.max_page_bytes.saturating_sub(page_bytes));
            let (payload, digest) = checked_row_payload(
                &self.connection,
                "sample_receipts",
                "sample_id",
                row_id,
                row_budget,
            )?;
            page_bytes = page_bytes
                .checked_add(u64::try_from(payload.len())?)
                .ok_or_else(|| invalid_store("result page size overflowed"))?;
            let receipt: DiscoverySampleReceipt = decode_row(&payload, &digest)?;
            if receipt.sample_id != id {
                return Err(invalid_store(
                    "source receipt identifier does not match its row",
                ));
            }
            receipts.push(receipt);
        }
        let next_after = if receipts.len() == usize::try_from(limit)? {
            receipts.last().map(|receipt| receipt.sample_id)
        } else {
            None
        };
        Ok(ResultPage {
            rows: receipts,
            next_after,
        })
    }

    /// Read exact printable-run receipts in stable run identifier order
    ///
    /// # Errors
    /// Rejects a zero page size or changed row contents
    pub fn printable_runs(
        &self,
        candidate_id: usize,
        partition: Partition,
        after_run_id: Option<usize>,
        limit: usize,
    ) -> Result<ResultPage<PrintableRun>, Box<dyn Error>> {
        let limit = page_limit(limit)?;
        let mut statement = self.connection.prepare(
            "SELECT run_id FROM printable_runs \
             WHERE candidate_id = ?1 AND partition = ?2 \
               AND (?3 IS NULL OR run_id > ?3) \
             ORDER BY run_id LIMIT ?4",
        )?;
        let mut rows = statement.query(params![
            candidate_id,
            partition_name(partition),
            after_run_id.map(i64::try_from).transpose()?,
            limit
        ])?;
        let mut runs = Vec::new();
        let mut page_bytes = 0_u64;
        while let Some(row) = rows.next()? {
            let row_id = row.get::<_, i64>(0)?;
            let id = usize::try_from(row_id)?;
            let row_budget = self
                .max_record_bytes
                .min(self.max_page_bytes.saturating_sub(page_bytes));
            let (payload, digest) = checked_row_payload(
                &self.connection,
                "printable_runs",
                "run_id",
                row_id,
                row_budget,
            )?;
            page_bytes = page_bytes
                .checked_add(u64::try_from(payload.len())?)
                .ok_or_else(|| invalid_store("result page size overflowed"))?;
            let run: PrintableRun = decode_row(&payload, &digest)?;
            if run.run_id != id || run.candidate_id != candidate_id || run.partition != partition {
                return Err(invalid_store(
                    "printable-run row identity does not match its receipt",
                ));
            }
            runs.push(run);
        }
        let next_after = if runs.len() == usize::try_from(limit)? {
            runs.last().map(|run| run.run_id)
        } else {
            None
        };
        Ok(ResultPage {
            rows: runs,
            next_after,
        })
    }

    /// Write the stored transformed output for one candidate and partition
    ///
    /// # Errors
    /// Rejects missing output rows or a stored output digest mismatch
    pub fn export_output(
        &self,
        candidate_id: usize,
        partition: Partition,
        output: &mut impl Write,
    ) -> Result<u64, Box<dyn Error>> {
        let candidate = self.candidate(candidate_id)?;
        let summary = partition_summary(&candidate, partition)
            .ok_or_else(|| invalid_store("candidate has no output for the requested partition"))?;
        if summary.failed_units != 0 || summary.output_sha256.is_none() {
            return Err(invalid_store(
                "candidate output is incomplete for the requested partition",
            ));
        }
        self.validate_output_rows(candidate_id, partition, summary)?;
        let mut statement = self.connection.prepare(
            "SELECT rowid, unit_index, length(payload), payload_sha256 \
             FROM outputs \
             WHERE candidate_id = ?1 AND partition = ?2 ORDER BY unit_index",
        )?;
        let mut rows = statement.query(params![candidate_id, partition_name(partition)])?;
        let mut total = 0_u64;
        let mut buffer = vec![0; 64 * 1024];
        while let Some(row) = rows.next()? {
            let row_id = row.get::<_, i64>(0)?;
            let unit_index = row.get::<_, usize>(1)?;
            if unit_index >= summary.unit_count {
                return Err(invalid_store("stored output unit index is out of range"));
            }
            let length = row.get::<_, u64>(2)?;
            let digest = checked_output_digest(row.get_ref(3)?)?;
            let length_actual =
                visit_output_blob(&self.connection, row_id, length, &mut buffer, |bytes| {
                    output.write_all(bytes)?;
                    Ok(())
                })?;
            if length_actual != digest {
                return Err(invalid_store("stored output unit digest does not match"));
            }
            total = total
                .checked_add(length)
                .ok_or_else(|| invalid_store("stored output byte count overflowed"))?;
        }
        Ok(total)
    }

    pub(super) fn validate_output_rows(
        &self,
        candidate_id: usize,
        partition: Partition,
        summary: &PartitionSummary,
    ) -> Result<(), Box<dyn Error>> {
        let mut statement = self.connection.prepare(
            "SELECT rowid, unit_index, length(payload), payload_sha256 FROM outputs \
             WHERE candidate_id = ?1 AND partition = ?2 ORDER BY unit_index",
        )?;
        let mut rows = statement.query(params![candidate_id, partition_name(partition)])?;
        let mut hasher = Sha256::new();
        let mut total = 0_usize;
        let mut units = 0_usize;
        let mut buffer = vec![0; 64 * 1024];
        while let Some(row) = rows.next()? {
            let row_id = row.get::<_, i64>(0)?;
            let unit_index = row.get::<_, usize>(1)?;
            if unit_index >= summary.unit_count {
                return Err(invalid_store("stored output unit index is out of range"));
            }
            let length = row.get::<_, u64>(2)?;
            let row_digest = checked_output_digest(row.get_ref(3)?)?;
            let actual_row_digest =
                visit_output_blob(&self.connection, row_id, length, &mut buffer, |bytes| {
                    hasher.update(bytes);
                    Ok(())
                })?;
            if actual_row_digest != row_digest {
                return Err(invalid_store("stored output unit digest does not match"));
            }
            units = units
                .checked_add(1)
                .ok_or_else(|| invalid_store("stored output unit count overflowed"))?;
            total = total
                .checked_add(usize::try_from(length)?)
                .ok_or_else(|| invalid_store("stored output byte count overflowed"))?;
        }
        let expected_units = summary
            .unit_count
            .checked_sub(summary.failed_units)
            .ok_or_else(|| invalid_store("candidate failed-unit count exceeds its unit count"))?;
        if units != expected_units
            || total != summary.output_length
            || summary.output_sha256.as_deref().is_some_and(|expected| {
                !valid_sha256(expected) || format!("{:x}", hasher.finalize()) != expected
            })
        {
            return Err(invalid_store(
                "stored output rows do not match their candidate summary",
            ));
        }
        Ok(())
    }

    /// Recompute every stored row digest and the aggregate result digest
    ///
    /// # Errors
    /// Rejects changed or incomplete result contents
    pub fn verify(&self) -> Result<(), Box<dyn Error>> {
        validate_schema(&self.connection, self.max_record_bytes)?;
        if checked_metadata_value(&self.connection, "complete", self.max_record_bytes)? != "1"
            || self.summary.result_sha256
                != content_digest(&self.connection, &self.summary, self.max_record_bytes)?
        {
            return Err(invalid_store("result store content digest does not match"));
        }
        Ok(())
    }

    pub(super) fn verify_sample_receipts(
        &self,
        samples: &[DiscoverySample<'_>],
    ) -> Result<(), Box<dyn Error>> {
        let count: usize =
            self.connection
                .query_row("SELECT COUNT(*) FROM sample_receipts", [], |row| row.get(0))?;
        if count != samples.len() {
            return Err(invalid_store(
                "source sample count does not match stored results",
            ));
        }
        for sample in samples {
            let (payload, digest) = checked_row_payload(
                &self.connection,
                "sample_receipts",
                "sample_id",
                i64::try_from(sample.id)?,
                self.max_record_bytes,
            )?;
            let receipt: DiscoverySampleReceipt = decode_row(&payload, &digest)?;
            if receipt.session_id != sample.session_id
                || receipt.sequence != sample.sequence
                || receipt.source_scope != sample.source_scope
                || receipt.direction != sample.direction
                || receipt.local_identity != sample.local_identity
                || receipt.input_length != sample.bytes.len()
                || receipt.input_sha256 != crate::sha256(sample.bytes)
                || receipt.mappings != sample.mappings
            {
                return Err(invalid_store(
                    "source sample or complete mapping receipt changed",
                ));
            }
        }
        Ok(())
    }
}
