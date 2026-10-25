//! Streaming result-store publication through the shared discovery engine

use super::super::engine;
use super::super::model::{
    DiscoveryCandidate, DiscoveryError, DiscoveryIdentity, DiscoveryPlan, DiscoveryReport,
    DiscoverySample, DiscoverySampleReceipt, Partition, PrintableRun,
};
use super::{
    integrity::{content_digest, invalid_store, partition_name, put_metadata, store_error},
    model::{RESULTS_FILE, RESULTS_SCHEMA, StoreOptions, StoredDiscoverySummary},
};
use crate::store::paths::Directory;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use std::{error::Error, fs, fs::File, path::Path};

/// Discover samples through the shared engine and publish all result receipts into a new store
///
/// `directory` must be a new or empty staging directory. The destination database is created
/// with no-overwrite semantics; a caller can atomically publish the directory after success
///
/// # Errors
/// Rejects invalid input, exhausted budgets, existing result files, and storage failures
pub fn discover_samples_to_store(
    samples: &[DiscoverySample<'_>],
    plan: &DiscoveryPlan,
    directory: &Path,
    options: StoreOptions,
) -> Result<StoredDiscoverySummary, Box<dyn Error>> {
    let mut writer = StoreWriter::create(directory, options)?;
    let report = engine::discover_to_sink(samples, plan, &mut writer)?;
    writer.finish(&report)
}

pub(in crate::carrier::discovery) struct StoreWriter {
    connection: Connection,
    directory: Directory,
    options: StoreOptions,
    logical_bytes: u64,
    output_bytes: u64,
    candidate_count: usize,
    printable_run_count: usize,
    sample_receipt_count: usize,
    plan_sha256: String,
    identity: Option<DiscoveryIdentity>,
    omitted_empty_sample_ids: Vec<u64>,
}

impl StoreWriter {
    pub(in crate::carrier::discovery) fn create(
        directory: &Path,
        options: StoreOptions,
    ) -> Result<Self, Box<dyn Error>> {
        if options.max_output_bytes == 0 || options.max_disk_bytes == 0 {
            return Err(invalid_store("output and disk budgets must be positive"));
        }
        let directory = Directory::open(directory)?;
        let path = directory.path().join(RESULTS_FILE);
        File::create_new(&path)?;
        let database_path = fs::canonicalize(path)?;
        let connection = Connection::open_with_flags(
            database_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        let page_size: u64 = connection.query_row("PRAGMA page_size", [], |row| row.get(0))?;
        let maximum_pages = options.max_disk_bytes / page_size;
        if maximum_pages == 0 {
            return Err(invalid_store(
                "result disk budget is smaller than one SQLite page",
            ));
        }
        let maximum_pages = i64::try_from(maximum_pages.min(4_294_967_294))?;
        connection.pragma_update(None, "max_page_count", maximum_pages)?;
        connection.execute_batch(
            "PRAGMA journal_mode=DELETE;
             PRAGMA synchronous=FULL;
             CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
             CREATE TABLE sample_receipts(sample_id INTEGER PRIMARY KEY, payload TEXT NOT NULL, payload_sha256 TEXT NOT NULL);
             CREATE TABLE candidates(candidate_id INTEGER PRIMARY KEY, payload TEXT NOT NULL, payload_sha256 TEXT NOT NULL, discovery_sha256 TEXT, control_sha256 TEXT);
             CREATE INDEX candidates_discovery_sha256 ON candidates(discovery_sha256);
             CREATE TABLE printable_runs(run_id INTEGER PRIMARY KEY, candidate_id INTEGER NOT NULL, partition TEXT NOT NULL, payload TEXT NOT NULL, payload_sha256 TEXT NOT NULL);
             CREATE INDEX printable_runs_page ON printable_runs(candidate_id, partition, run_id);
             CREATE TABLE outputs(id INTEGER PRIMARY KEY, candidate_id INTEGER NOT NULL, partition TEXT NOT NULL, unit_index INTEGER NOT NULL, payload BLOB NOT NULL, payload_sha256 TEXT NOT NULL, UNIQUE(candidate_id, partition, unit_index));
             INSERT INTO metadata(key, value) VALUES('schema_version', '1'), ('complete', '0');
             BEGIN IMMEDIATE;",
        )?;
        Ok(Self {
            connection,
            directory,
            options,
            logical_bytes: 2,
            output_bytes: 0,
            candidate_count: 0,
            printable_run_count: 0,
            sample_receipt_count: 0,
            plan_sha256: String::new(),
            identity: None,
            omitted_empty_sample_ids: Vec::new(),
        })
    }

    pub(in crate::carrier::discovery) fn finish(
        mut self,
        report: &DiscoveryReport,
    ) -> Result<StoredDiscoverySummary, Box<dyn Error>> {
        let identity = self
            .identity
            .take()
            .ok_or_else(|| invalid_store("result store did not receive source identity"))?;
        // Write each shared output group once before hashing instead of per candidate insertion
        self.finalize_competitor_counts()?;
        let mut summary = StoredDiscoverySummary {
            schema_version: RESULTS_SCHEMA,
            plan_sha256: self.plan_sha256.clone(),
            identity,
            sample_receipt_count: self.sample_receipt_count,
            omitted_empty_sample_ids: std::mem::take(&mut self.omitted_empty_sample_ids),
            parameter_space_size: report.parameter_space_size,
            input_bytes: report.input_bytes,
            input_budget_bytes: report.input_budget_bytes,
            attempted_parameters: report.attempted_parameters,
            attempted_transforms: report.attempted_transforms,
            work_bytes: report.work_bytes,
            work_budget_bytes: report.work_budget_bytes,
            candidate_budget: report.candidate_budget,
            output_bytes: self.output_bytes,
            output_budget_bytes: self.options.max_output_bytes,
            disk_budget_bytes: self.options.max_disk_bytes,
            candidate_count: self.candidate_count,
            printable_run_count: self.printable_run_count,
            enumeration_complete: report.enumeration_complete,
            limits: report.limits.clone(),
            result_sha256: "0".repeat(64),
        };
        // Include the final metadata records in the logical budget before publishing them
        self.add_logical_bytes(serde_json::to_vec(&summary)?.len())
            .map_err(store_error)?;
        self.add_logical_bytes(1).map_err(store_error)?;
        summary.result_sha256 =
            content_digest(&self.connection, &summary, self.options.max_disk_bytes)?;
        put_metadata(&self.connection, "summary", &summary)?;
        put_metadata(&self.connection, "complete", &1_u8)?;
        self.check_database_size()?;
        self.connection.execute_batch("COMMIT;")?;
        File::open(self.directory.path().join(RESULTS_FILE))?.sync_all()?;
        self.directory.sync()?;
        Ok(summary)
    }

    fn check_database_size(&self) -> Result<(), Box<dyn Error>> {
        let pages: u64 = self
            .connection
            .query_row("PRAGMA page_count", [], |row| row.get(0))?;
        let page_size: u64 = self
            .connection
            .query_row("PRAGMA page_size", [], |row| row.get(0))?;
        let size = pages
            .checked_mul(page_size)
            .ok_or_else(|| invalid_store("result database size overflowed"))?;
        if size > self.options.max_disk_bytes {
            return Err(invalid_store("result database exceeded its disk budget"));
        }
        Ok(())
    }

    fn add_logical_bytes(&mut self, bytes: usize) -> Result<(), DiscoveryError> {
        self.logical_bytes = self
            .logical_bytes
            .checked_add(u64::try_from(bytes).map_err(|_| store_error("result size overflowed"))?)
            .ok_or_else(|| store_error("result size overflowed"))?;
        if self.logical_bytes > self.options.max_disk_bytes {
            return Err(store_error("result rows exceeded the disk budget"));
        }
        Ok(())
    }

    fn replace_logical_bytes(
        &mut self,
        previous_bytes: usize,
        updated_bytes: usize,
    ) -> Result<(), DiscoveryError> {
        self.logical_bytes = self
            .logical_bytes
            .checked_sub(u64::try_from(previous_bytes).map_err(store_error)?)
            .ok_or_else(|| store_error("result size accounting underflowed"))?;
        self.add_logical_bytes(updated_bytes)
    }

    fn insert_receipt(&mut self, receipt: &DiscoverySampleReceipt) -> Result<(), DiscoveryError> {
        let payload = serde_json::to_string(receipt).map_err(store_error)?;
        self.add_logical_bytes(payload.len())?;
        let digest = crate::sha256(payload.as_bytes());
        self.connection
            .execute(
                "INSERT INTO sample_receipts(sample_id, payload, payload_sha256) VALUES(?1, ?2, ?3)",
                params![receipt.sample_id, payload, digest],
            )
            .map_err(store_error)?;
        Ok(())
    }

    fn insert_output(
        &mut self,
        candidate_id: usize,
        partition: Partition,
        unit_index: usize,
        bytes: &[u8],
    ) -> Result<(), DiscoveryError> {
        let length = u64::try_from(bytes.len()).map_err(store_error)?;
        self.output_bytes = self
            .output_bytes
            .checked_add(length)
            .ok_or_else(|| store_error("transformed output size overflowed"))?;
        if self.output_bytes > self.options.max_output_bytes {
            return Err(store_error("transformed output exceeded its output budget"));
        }
        self.add_logical_bytes(bytes.len())?;
        self.connection
            .execute(
                "INSERT INTO outputs(candidate_id, partition, unit_index, payload, payload_sha256) VALUES(?1, ?2, ?3, ?4, ?5)",
                params![candidate_id, partition_name(partition), unit_index, bytes, crate::sha256(bytes)],
            )
            .map_err(store_error)?;
        Ok(())
    }

    fn insert_printable_run(&mut self, run: &PrintableRun) -> Result<(), DiscoveryError> {
        let payload = serde_json::to_string(run).map_err(store_error)?;
        self.add_logical_bytes(payload.len())?;
        self.connection
            .execute(
                "INSERT INTO printable_runs(run_id, candidate_id, partition, payload, payload_sha256) VALUES(?1, ?2, ?3, ?4, ?5)",
                params![run.run_id, run.candidate_id, partition_name(run.partition), payload, crate::sha256(payload.as_bytes())],
            )
            .map_err(store_error)?;
        self.printable_run_count = self
            .printable_run_count
            .checked_add(1)
            .ok_or_else(|| store_error("printable-run count overflowed"))?;
        Ok(())
    }

    fn insert_candidate(&mut self, candidate: &DiscoveryCandidate) -> Result<(), DiscoveryError> {
        let mut candidate = candidate.clone();
        let discovery_sha = candidate
            .discovery
            .as_ref()
            .and_then(|summary| summary.output_sha256.clone());
        let control_sha = candidate
            .control
            .as_ref()
            .and_then(|summary| summary.output_sha256.clone());
        // A stored candidate enters its discovery-output group before final group sizes are known
        candidate.competitor_count = usize::from(discovery_sha.is_some());
        let payload = serde_json::to_string(&candidate).map_err(store_error)?;
        self.add_logical_bytes(payload.len())?;
        self.connection
            .execute(
                "INSERT INTO candidates(candidate_id, payload, payload_sha256, discovery_sha256, control_sha256) VALUES(?1, ?2, ?3, ?4, ?5)",
                params![candidate.id, payload, crate::sha256(payload.as_bytes()), discovery_sha, control_sha],
            )
            .map_err(store_error)?;
        self.candidate_count = self
            .candidate_count
            .checked_add(1)
            .ok_or_else(|| store_error("candidate count overflowed"))?;
        Ok(())
    }

    fn finalize_competitor_counts(&mut self) -> Result<(), Box<dyn Error>> {
        let mut after_digest = None;
        loop {
            let group = match after_digest.as_deref() {
                Some(digest) => self
                    .connection
                    .query_row(
                        "SELECT discovery_sha256, COUNT(*) FROM candidates \
                         WHERE discovery_sha256 > ?1 GROUP BY discovery_sha256 \
                         ORDER BY discovery_sha256 LIMIT 1",
                        [digest],
                        |row| Ok((row.get::<_, String>(0)?, row.get::<_, usize>(1)?)),
                    )
                    .optional()?,
                None => self
                    .connection
                    .query_row(
                        "SELECT discovery_sha256, COUNT(*) FROM candidates \
                         WHERE discovery_sha256 IS NOT NULL GROUP BY discovery_sha256 \
                         ORDER BY discovery_sha256 LIMIT 1",
                        [],
                        |row| Ok((row.get::<_, String>(0)?, row.get::<_, usize>(1)?)),
                    )
                    .optional()?,
            };
            let Some((digest, count)) = group else {
                break;
            };
            if count > 1 {
                self.finalize_competitor_group(&digest, count)?;
            }
            after_digest = Some(digest);
        }
        Ok(())
    }

    fn finalize_competitor_group(
        &mut self,
        discovery_digest: &str,
        competitor_count: usize,
    ) -> Result<(), Box<dyn Error>> {
        let mut after_candidate_id = None;
        loop {
            let candidate = match after_candidate_id {
                Some(candidate_id) => self
                    .connection
                    .query_row(
                        "SELECT candidate_id, payload FROM candidates \
                         WHERE discovery_sha256 = ?1 AND candidate_id > ?2 \
                         ORDER BY candidate_id LIMIT 1",
                        params![discovery_digest, candidate_id],
                        |row| Ok((row.get::<_, usize>(0)?, row.get::<_, String>(1)?)),
                    )
                    .optional()?,
                None => self
                    .connection
                    .query_row(
                        "SELECT candidate_id, payload FROM candidates \
                         WHERE discovery_sha256 = ?1 ORDER BY candidate_id LIMIT 1",
                        [discovery_digest],
                        |row| Ok((row.get::<_, usize>(0)?, row.get::<_, String>(1)?)),
                    )
                    .optional()?,
            };
            let Some((candidate_id, payload)) = candidate else {
                break;
            };
            let mut candidate: DiscoveryCandidate = serde_json::from_str(&payload)?;
            candidate.competitor_count = competitor_count;
            let encoded = serde_json::to_string(&candidate)?;
            self.replace_logical_bytes(payload.len(), encoded.len())
                .map_err(store_error)?;
            self.connection.execute(
                "UPDATE candidates SET payload = ?1, payload_sha256 = ?2 WHERE candidate_id = ?3",
                params![encoded, crate::sha256(encoded.as_bytes()), candidate_id],
            )?;
            after_candidate_id = Some(candidate_id);
        }
        Ok(())
    }
}

impl engine::DiscoveryResultSink for StoreWriter {
    fn begin(
        &mut self,
        plan: &DiscoveryPlan,
        identity: &DiscoveryIdentity,
        omitted: &[u64],
        _input_bytes: usize,
        _parameter_space_size: usize,
    ) -> Result<(), DiscoveryError> {
        let plan_bytes = serde_json::to_vec(plan).map_err(store_error)?;
        self.plan_sha256 = crate::sha256(&plan_bytes);
        let plan_document = String::from_utf8(plan_bytes).map_err(store_error)?;
        let encoded_plan = serde_json::to_vec(&plan_document).map_err(store_error)?;
        self.add_logical_bytes(encoded_plan.len())?;
        put_metadata(&self.connection, "plan", &plan_document).map_err(store_error)?;
        self.identity = Some(identity.clone());
        let mut omitted_ids = Vec::new();
        omitted_ids
            .try_reserve_exact(omitted.len())
            .map_err(store_error)?;
        omitted_ids.extend_from_slice(omitted);
        self.omitted_empty_sample_ids = omitted_ids;
        Ok(())
    }

    fn sample_receipt(&mut self, receipt: &DiscoverySampleReceipt) -> Result<(), DiscoveryError> {
        self.insert_receipt(receipt)?;
        self.sample_receipt_count = self
            .sample_receipt_count
            .checked_add(1)
            .ok_or_else(|| store_error("sample receipt count overflowed"))?;
        Ok(())
    }

    fn output(
        &mut self,
        candidate_id: usize,
        partition: Partition,
        unit_index: usize,
        bytes: &[u8],
    ) -> Result<(), DiscoveryError> {
        self.insert_output(candidate_id, partition, unit_index, bytes)
    }

    fn printable_run(&mut self, run: &PrintableRun) -> Result<(), DiscoveryError> {
        self.insert_printable_run(run)
    }

    fn candidate(&mut self, candidate: &DiscoveryCandidate) -> Result<(), DiscoveryError> {
        self.insert_candidate(candidate)
    }
}
