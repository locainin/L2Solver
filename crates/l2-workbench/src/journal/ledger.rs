use super::{Check, Entry, Hypothesis, Journal, RecordedCheck, Result, invalid};
use rusqlite::params;
use serde_json::json;

impl Journal {
    /// Deduplicate the exact input, operation and assumptions while preserving the first title
    ///
    /// # Errors
    /// Rejects missing descriptions, oversized metadata and storage errors
    pub fn record(&mut self, model: &Hypothesis) -> Result<String> {
        if model.title.trim().is_empty() {
            return Err(invalid("hypothesis needs a title"));
        }
        let identity = self.encoded(&json!({"input":model.input,"operation":model.operation,"assumptions":model.assumptions}))?;
        let id = crate::sha256(&identity);
        let encoded = String::from_utf8(self.encoded(model)?)?;
        self.connection.execute(
            "INSERT OR IGNORE INTO hypotheses(id,model) VALUES(?1,?2)",
            params![id, encoded],
        )?;
        Ok(id)
    }

    /// Append a check with the exact supporting document, never replacing earlier outcomes
    ///
    /// # Errors
    /// Rejects missing models, empty evidence or explanations and metadata budgets
    pub fn record_check(&mut self, id: &str, check: &Check, evidence: &[u8]) -> Result<()> {
        let exists: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM hypotheses WHERE id=?1)",
            [id],
            |row| row.get(0),
        )?;
        if !exists {
            return Err(invalid("missing hypothesis"));
        }
        if check.explanation.trim().is_empty() || evidence.is_empty() {
            return Err(invalid(
                "a check requires an explanation and supporting evidence",
            ));
        }
        let encoded = String::from_utf8(self.encoded(check)?)?;
        let digest = crate::sha256(evidence);
        let identity = super::checks::identity(id, encoded.as_bytes(), &digest)?;
        let tx = self.connection.transaction()?;
        tx.execute(
            "INSERT OR IGNORE INTO objects VALUES(?1,?2)",
            params![digest, evidence],
        )?;
        tx.execute(
            "INSERT INTO checks(hypothesis,identity,value,evidence,binding_origin) VALUES(?1,?2,?3,?4,'recorded')",
            params![id, identity, encoded, digest],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Read a model with a bounded verified check preview and a source-wide conclusion
    ///
    /// # Errors
    /// Rejects missing or malformed records
    pub fn entry(&self, id: &str) -> Result<Entry> {
        self.read_snapshot(|journal| {
            let entry = journal.entry_in_snapshot(id)?;
            journal.verify_entry_objects(id, entry.output_sha256.as_deref())?;
            Ok(entry)
        })
    }

    pub(super) fn entry_in_snapshot(&self, id: &str) -> Result<Entry> {
        let (model, output, receipt) = {
            let mut query = self.connection.prepare(
                "SELECT length(CAST(model AS BLOB)),model,length(CAST(output AS BLOB)),output,length(CAST(receipt AS BLOB)),receipt FROM hypotheses WHERE id=?1",
            )?;
            let mut rows = query.query([id])?;
            let row = rows.next()?.ok_or(rusqlite::Error::QueryReturnedNoRows)?;
            (
                super::bounded_text(row, 0, 1, self.options.max_entry_bytes, "hypothesis")?,
                super::optional_sha256(row, 2, 3, "journal derivation output")?,
                super::optional_sha256(row, 4, 5, "journal derivation receipt")?,
            )
        };

        let mut checks = Vec::new();
        let mut retained_bytes = 0_usize;
        let mut retain_prefix = true;
        let mut total = 0_u64;
        let mut failed = false;
        let mut supported = false;
        self.stream_checks(Some(id), None, None, |recorded, encoded_length| {
            total = total
                .checked_add(1)
                .ok_or_else(|| invalid("check count exceeds the supported range"))?;
            // Legacy bindings preserve history without supporting or falsifying the model
            let is_recorded = recorded.binding_origin == super::CheckBindingOrigin::Recorded;
            failed |= is_recorded && recorded.check.outcome == super::CheckOutcome::Fail;
            supported |= is_recorded
                && recorded.check.kind == super::CheckKind::Independent
                && recorded.check.outcome == super::CheckOutcome::Pass;

            // The encoded record bounds decoded text; fixed storage covers both hash strings
            let cost = encoded_length
                .checked_add(128)
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<RecordedCheck>()))
                .ok_or_else(|| invalid("check preview size exceeds the supported range"))?;
            if retain_prefix {
                if cost <= self.options.max_entry_bytes.saturating_sub(retained_bytes) {
                    retained_bytes = retained_bytes
                        .checked_add(cost)
                        .ok_or_else(|| invalid("check preview size exceeds the supported range"))?;
                    checks.push(recorded);
                } else {
                    retain_prefix = false;
                }
            }
            Ok(())
        })?;
        let checks_omitted = total
            .checked_sub(u64::try_from(checks.len())?)
            .ok_or_else(|| invalid("check preview count exceeds the stored history"))?;
        let conclusion = if failed {
            "falsified_under_recorded_checks"
        } else if supported {
            "best_supported_under_recorded_checks"
        } else {
            "unresolved"
        };
        let hypothesis = self.decode_hypothesis(id, &model)?;
        let derivation =
            self.derivation_summary(output.as_deref(), receipt.as_deref(), &hypothesis)?;
        Ok(Entry {
            id: id.to_owned(),
            hypothesis,
            conclusion,
            checks,
            checks_omitted,
            output_sha256: output,
            receipt_sha256: receipt,
            derivation,
        })
    }

    fn decode_hypothesis(&self, id: &str, model: &str) -> Result<Hypothesis> {
        let hypothesis: Hypothesis = serde_json::from_str(model)?;
        if hypothesis.title.trim().is_empty() {
            return Err(invalid("hypothesis needs a title"));
        }
        let identity = self.encoded(&json!({
            "input": &hypothesis.input,
            "operation": &hypothesis.operation,
            "assumptions": &hypothesis.assumptions
        }))?;
        if crate::sha256(&identity) != id {
            return Err(invalid("journal hypothesis identity mismatch"));
        }
        Ok(hypothesis)
    }

    fn verify_entry_objects(&self, id: &str, output: Option<&str>) -> Result<()> {
        let mut statement = self.connection.prepare(
            "SELECT DISTINCT evidence FROM checks WHERE hypothesis=?1 ORDER BY evidence",
        )?;
        let mut rows = statement.query([id])?;
        let mut buffer = vec![0_u8; 64 * 1024];
        while let Some(row) = rows.next()? {
            let hash: String = row.get(0)?;
            self.verify_object_hash_with_buffer(&hash, &mut buffer)?;
        }
        if let Some(hash) = output {
            self.verify_object_hash_with_limit(
                hash,
                Some(crate::derivation::MAX_OUTPUT_BYTES),
                &mut buffer,
            )?;
        }
        Ok(())
    }

    /// Stream entries in stable identity order with an optional operator-selected page size
    ///
    /// # Errors
    /// Returns database, record or visitor errors
    pub fn visit_entries(
        &self,
        after: Option<&str>,
        limit: Option<u64>,
        mut visitor: impl FnMut(Entry) -> Result<()>,
    ) -> Result<()> {
        self.read_snapshot(|journal| {
            journal.verify_snapshot()?;
            let mut statement = journal
                .connection
                .prepare("SELECT id FROM hypotheses WHERE id>?1 ORDER BY id LIMIT ?2")?;
            let rows = statement.query_map(
                params![
                    after.unwrap_or(""),
                    limit.map(i64::try_from).transpose()?.unwrap_or(-1)
                ],
                |row| row.get::<_, String>(0),
            )?;
            for row in rows {
                visitor(journal.entry_in_snapshot(&row?)?)?;
            }
            Ok(())
        })
    }

    fn stream_checks(
        &self,
        hypothesis: Option<&str>,
        after: Option<u64>,
        limit: Option<u64>,
        mut visitor: impl FnMut(RecordedCheck, usize) -> Result<()>,
    ) -> Result<()> {
        // Zero begins a complete history, so malformed nonpositive row IDs cannot be skipped
        let after = after.filter(|id| *id > 0);
        let query = match (hypothesis, after) {
            (Some(_), Some(_)) => {
                "SELECT id,length(CAST(hypothesis AS BLOB)),hypothesis,length(CAST(value AS BLOB)),length(CAST(identity AS BLOB)),identity,length(CAST(evidence AS BLOB)),evidence,value,length(CAST(binding_origin AS BLOB)),binding_origin FROM checks WHERE hypothesis=?1 AND id>?2 ORDER BY id LIMIT ?3"
            }
            (Some(_), None) => {
                "SELECT id,length(CAST(hypothesis AS BLOB)),hypothesis,length(CAST(value AS BLOB)),length(CAST(identity AS BLOB)),identity,length(CAST(evidence AS BLOB)),evidence,value,length(CAST(binding_origin AS BLOB)),binding_origin FROM checks WHERE hypothesis=?1 ORDER BY id LIMIT ?2"
            }
            (None, _) => {
                "SELECT id,length(CAST(hypothesis AS BLOB)),hypothesis,length(CAST(value AS BLOB)),length(CAST(identity AS BLOB)),identity,length(CAST(evidence AS BLOB)),evidence,value,length(CAST(binding_origin AS BLOB)),binding_origin FROM checks ORDER BY hypothesis,id"
            }
        };
        let mut statement = self.connection.prepare(query)?;
        let mut rows = match (hypothesis, after) {
            (Some(hypothesis), Some(after)) => statement.query(params![
                hypothesis,
                after,
                limit.map(i64::try_from).transpose()?.unwrap_or(-1)
            ])?,
            (Some(hypothesis), None) => statement.query(params![
                hypothesis,
                limit.map(i64::try_from).transpose()?.unwrap_or(-1)
            ])?,
            (None, _) => statement.query([])?,
        };
        let budget = u64::try_from(self.options.max_entry_bytes)?;
        while let Some(row) = rows.next()? {
            let hypothesis_length: u64 = row.get(1)?;
            if hypothesis_length != 64 {
                return Err(invalid(
                    "journal check hypothesis must be a 64-character SHA-256 hash",
                ));
            }
            let value_length: u64 = row.get(3)?;
            if value_length > budget {
                return Err(invalid("check exceeds configured metadata reader budget"));
            }
            let identity_length: u64 = row.get(4)?;
            if identity_length != 64 {
                return Err(invalid(
                    "journal check identity must be a 64-character SHA-256 hash",
                ));
            }
            let evidence_length: u64 = row.get(6)?;
            if evidence_length != 64 {
                return Err(invalid(
                    "journal check evidence must be a 64-character SHA-256 hash",
                ));
            }
            let id: u64 = row.get(0)?;
            let stored_hypothesis: String = row.get(2)?;
            let identity: String = row.get(5)?;
            let evidence: String = row.get(7)?;
            let value: String = row.get(8)?;
            let binding_origin =
                super::bounded_text(row, 9, 10, self.options.max_entry_bytes, "check")?;
            let recorded = super::checks::decode(
                id,
                &stored_hypothesis,
                identity,
                value,
                evidence,
                &binding_origin,
            )?;
            visitor(recorded, usize::try_from(value_length)?)?;
        }
        Ok(())
    }
}

impl Journal {
    /// Show recorded independent-pass models first and preserve recorded failures at the end
    ///
    /// # Errors
    /// Returns storage, record and visitor errors
    pub fn visit_review(
        &self,
        limit: Option<u64>,
        mut visitor: impl FnMut(Entry) -> Result<()>,
    ) -> Result<()> {
        self.read_snapshot(|journal| {
            journal.verify_snapshot()?;
            let mut statement = journal.connection.prepare(
                "SELECT h.id FROM hypotheses h ORDER BY CASE WHEN EXISTS(SELECT 1 FROM checks c WHERE c.hypothesis=h.id AND c.binding_origin='recorded' AND json_extract(c.value,'$.outcome')='fail') THEN 2 WHEN EXISTS(SELECT 1 FROM checks c WHERE c.hypothesis=h.id AND c.binding_origin='recorded' AND json_extract(c.value,'$.kind')='independent' AND json_extract(c.value,'$.outcome')='pass') THEN 0 ELSE 1 END,h.id LIMIT ?1",
            )?;
            let rows = statement.query_map(
                [limit.map(i64::try_from).transpose()?.unwrap_or(-1)],
                |row| row.get::<_, String>(0),
            )?;
            for row in rows {
                visitor(journal.entry_in_snapshot(&row?)?)?;
            }
            Ok(())
        })
    }

    /// Stream complete check history with keyset pagination and a per-record metadata budget
    ///
    /// # Errors
    /// Rejects malformed or oversized records and returns storage or visitor errors
    pub fn visit_checks(
        &self,
        hypothesis: &str,
        after: u64,
        limit: Option<u64>,
        mut visitor: impl FnMut(RecordedCheck) -> Result<()>,
    ) -> Result<()> {
        self.stream_checks(Some(hypothesis), Some(after), limit, |check, _| {
            visitor(check)
        })
    }
}
