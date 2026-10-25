use super::{Journal, Result, checks, invalid};
use sha2::{Digest, Sha256};
use std::io::Write;

const IO_BUFFER_BYTES: usize = 64 * 1024;

impl Journal {
    /// Stream a check's evidence by check ID, check identity, or object SHA-256
    ///
    /// A complete hash pass runs before bytes reach the caller's writer. A CLI
    /// can therefore publish its staged output only after this method succeeds.
    ///
    /// # Errors
    /// Rejects unknown references, changed bytes, or writer errors
    pub fn write_evidence(&self, reference: &str, output: &mut impl Write) -> Result<u64> {
        self.read_snapshot(|journal| {
            let evidence_hash = journal.evidence_hash_for(reference)?;
            journal.write_verified_object(&evidence_hash, output)
        })
    }

    fn evidence_hash_for(&self, reference: &str) -> Result<String> {
        if let Ok(id) = reference.parse::<u64>() {
            if id == 0 {
                return Err(invalid("check ID must be positive"));
            }
            return self.check_evidence_by_id(id);
        }
        if !crate::hashing::is_sha256_digest(reference) {
            return Err(invalid(
                "evidence reference must be a check ID or SHA-256 hash",
            ));
        }
        let mut statement = self.connection.prepare(
            "SELECT id,length(CAST(hypothesis AS BLOB)),hypothesis,length(CAST(identity AS BLOB)),identity,length(CAST(value AS BLOB)),value,length(CAST(evidence AS BLOB)),evidence,length(CAST(binding_origin AS BLOB)),binding_origin FROM checks WHERE identity=?1 ORDER BY id LIMIT 1",
        )?;
        let mut rows = statement.query([reference])?;
        if let Some(row) = rows.next()? {
            return self.decode_evidence_hash(row);
        }
        Ok(reference.to_owned())
    }

    fn check_evidence_by_id(&self, id: u64) -> Result<String> {
        let mut statement = self.connection.prepare(
            "SELECT id,length(CAST(hypothesis AS BLOB)),hypothesis,length(CAST(identity AS BLOB)),identity,length(CAST(value AS BLOB)),value,length(CAST(evidence AS BLOB)),evidence,length(CAST(binding_origin AS BLOB)),binding_origin FROM checks WHERE id=?1",
        )?;
        let mut rows = statement.query([id])?;
        let row = rows.next()?.ok_or(rusqlite::Error::QueryReturnedNoRows)?;
        self.decode_evidence_hash(row)
    }

    fn decode_evidence_hash(&self, row: &rusqlite::Row<'_>) -> Result<String> {
        let id: u64 = row.get(0)?;
        let hypothesis = super::required_sha256(row, 1, 2, "journal check hypothesis")?;
        let identity = super::required_sha256(row, 3, 4, "journal check identity")?;
        let value = super::bounded_text(row, 5, 6, self.options.max_entry_bytes, "check")?;
        let evidence = super::required_sha256(row, 7, 8, "journal check evidence")?;
        let binding_origin =
            super::bounded_text(row, 9, 10, self.options.max_entry_bytes, "check")?;
        checks::decode(
            id,
            &hypothesis,
            identity,
            value,
            evidence.clone(),
            &binding_origin,
        )?;
        Ok(evidence)
    }

    fn write_verified_object(&self, hash: &str, output: &mut impl Write) -> Result<u64> {
        if !crate::hashing::is_sha256_digest(hash) {
            return Err(invalid("evidence object identity is not a SHA-256 hash"));
        }
        let (row_id, length): (i64, u64) = self.connection.query_row(
            "SELECT rowid,length(bytes) FROM objects WHERE sha256=?1",
            [hash],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let mut digest = Sha256::new();
        self.visit_blob(row_id, length, |chunk| {
            digest.update(chunk);
            Ok(())
        })?;
        if format!("{:x}", digest.finalize()) != hash {
            return Err(invalid("journal evidence object hash mismatch"));
        }

        // The read transaction keeps this second streamed pass on the verified snapshot
        let mut written = 0_u64;
        self.visit_blob(row_id, length, |chunk| {
            output.write_all(chunk)?;
            written = written
                .checked_add(u64::try_from(chunk.len())?)
                .ok_or_else(|| invalid("exported evidence length exceeds the supported range"))?;
            Ok(())
        })?;
        if written != length {
            return Err(invalid("journal evidence length changed during export"));
        }
        Ok(length)
    }

    fn visit_blob(
        &self,
        row_id: i64,
        expected_length: u64,
        mut visitor: impl FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        let mut reader = self
            .connection
            .blob_open("main", "objects", "bytes", row_id, true)?;
        if u64::try_from(reader.size())? != expected_length {
            return Err(invalid(
                "journal evidence length changed inside its read snapshot",
            ));
        }
        let mut buffer = vec![0_u8; IO_BUFFER_BYTES].into_boxed_slice();
        let mut read = 0_u64;
        loop {
            let count = std::io::Read::read(&mut reader, &mut buffer)?;
            if count == 0 {
                break;
            }
            let chunk = buffer
                .get(..count)
                .ok_or_else(|| invalid("evidence reader returned an invalid byte count"))?;
            visitor(chunk)?;
            read = read
                .checked_add(u64::try_from(count)?)
                .ok_or_else(|| invalid("journal evidence length exceeds the supported range"))?;
        }
        reader.close()?;
        if read != expected_length {
            return Err(invalid("journal evidence object length mismatch"));
        }
        Ok(())
    }
}
