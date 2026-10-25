use super::{Journal, Result, invalid};
use rusqlite::OptionalExtension;
use sha2::{Digest, Sha256};
use std::io::Read;

impl Journal {
    pub(super) fn object(&self, hash: &str, allocation_budget: usize) -> Result<Vec<u8>> {
        self.read_snapshot(|journal| {
            let (row_id, length): (i64, u64) = journal.connection.query_row(
                "SELECT rowid,length(bytes) FROM objects WHERE sha256=?1",
                [hash],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            if length > u64::try_from(allocation_budget)? {
                return Err(invalid(
                    "stored object exceeds this reader's allocation budget",
                ));
            }
            // Read the BLOB only after its size passes the caller's allocation budget
            let mut reader = journal
                .connection
                .blob_open("main", "objects", "bytes", row_id, true)?;
            if u64::try_from(reader.size())? != length {
                return Err(invalid(
                    "journal object length changed inside its read snapshot",
                ));
            }
            let capacity = usize::try_from(length)?;
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(capacity)?;
            bytes.resize(capacity, 0);
            reader.read_exact(&mut bytes)?;
            reader.close()?;
            if crate::sha256(&bytes) != hash {
                return Err(invalid("journal evidence object hash mismatch"));
            }
            Ok(bytes)
        })
    }
    pub(super) fn verify_objects(&self) -> Result<()> {
        let mut statement = self.connection.prepare(
            "SELECT rowid,length(CAST(sha256 AS BLOB)),sha256 FROM objects ORDER BY sha256",
        )?;
        let mut rows = statement.query([])?;
        // Reuse one heap buffer for objects of any stored length
        let mut buffer = vec![0_u8; 64 * 1024];
        while let Some(row) = rows.next()? {
            let id: i64 = row.get(0)?;
            let hash_length: u64 = row.get(1)?;
            if hash_length != 64 {
                return Err(invalid(
                    "journal object identity must be a 64-character SHA-256 hash",
                ));
            }
            // SHA-256 identities have fixed size, so compare the database text by reference
            let expected = row.get_ref(2)?.as_str()?;
            self.verify_object_row(id, expected, &mut buffer)?;
        }
        Ok(())
    }

    pub(super) fn verify_object_hash_with_buffer(
        &self,
        hash: &str,
        buffer: &mut [u8],
    ) -> Result<()> {
        self.verify_object_hash_with_limit(hash, None, buffer)
    }

    pub(super) fn verify_object_hash_with_limit(
        &self,
        hash: &str,
        maximum: Option<usize>,
        buffer: &mut [u8],
    ) -> Result<()> {
        let row: Option<(i64, u64, u64)> = self
            .connection
            .query_row(
                "SELECT rowid,length(bytes),length(CAST(sha256 AS BLOB)) FROM objects WHERE sha256=?1",
                [hash],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let (id, length, hash_length) =
            row.ok_or_else(|| invalid("missing journal evidence object"))?;
        if maximum
            .map(u64::try_from)
            .transpose()?
            .is_some_and(|limit| length > limit)
        {
            return Err(invalid(
                "stored object exceeds this reader's allocation budget",
            ));
        }
        if hash_length != 64 {
            return Err(invalid(
                "journal object identity must be a 64-character SHA-256 hash",
            ));
        }
        self.verify_object_row(id, hash, buffer)
    }

    fn verify_object_row(&self, id: i64, expected: &str, buffer: &mut [u8]) -> Result<()> {
        let mut reader = self
            .connection
            .blob_open("main", "objects", "bytes", id, true)?;
        let mut digest = Sha256::new();
        // Stream the object so verification uses a fixed-size buffer
        loop {
            let count = reader.read(buffer)?;
            if count == 0 {
                break;
            }
            digest.update(
                buffer
                    .get(..count)
                    .ok_or_else(|| invalid("object reader returned an invalid byte count"))?,
            );
        }
        if format!("{:x}", digest.finalize()) != expected {
            return Err(invalid("journal evidence object hash mismatch"));
        }
        Ok(())
    }
}
