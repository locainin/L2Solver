use super::{Journal, Result, invalid};

impl Journal {
    /// Recheck base evidence and content-addressed records before relying on saved results
    ///
    /// # Errors
    /// Rejects changed bytes, malformed records and broken database relationships
    pub fn verify(&self) -> Result<()> {
        self.read_snapshot(Self::verify_snapshot)
    }

    pub(super) fn verify_snapshot(&self) -> Result<()> {
        self.base_case()?;
        let check: String = self
            .connection
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
        if check != "ok" {
            return Err(invalid("journal database integrity check failed"));
        }
        let violations: u64 = self.connection.query_row(
            "SELECT COUNT(*) FROM pragma_foreign_key_check",
            [],
            |r| r.get(0),
        )?;
        if violations != 0 {
            return Err(invalid("journal evidence references are broken"));
        }
        self.verify_objects()?;
        self.verify_models()?;
        let mut check = || Ok(());
        super::event_reader::validate_all_events(
            &self.connection,
            self.options.max_entry_bytes,
            &mut check,
        )?;
        self.verify_tool_receipts()
    }
    fn verify_models(&self) -> Result<()> {
        let mut statement = self
            .connection
            .prepare("SELECT length(CAST(id AS BLOB)),id FROM hypotheses ORDER BY id")?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let id_length: u64 = row.get(0)?;
            if id_length != 64 {
                return Err(invalid(
                    "journal hypothesis identity must be a 64-character SHA-256 hash",
                ));
            }
            let id: String = row.get(1)?;
            // The entry reader bounds and validates the stored model and its linked records
            self.entry_in_snapshot(&id)?;
        }
        Ok(())
    }
}
