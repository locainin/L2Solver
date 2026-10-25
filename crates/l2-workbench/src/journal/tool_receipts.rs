use super::{Journal, Result, ToolReceiptSummary, invalid};
use rusqlite::params;

impl Journal {
    /// Stream imported tool receipts with their raw evidence and linked event counts
    ///
    /// # Errors
    /// Rejects oversized receipt metadata and returns storage or visitor errors
    pub fn visit_tool_receipts(
        &self,
        after: Option<u64>,
        limit: Option<u64>,
        mut visitor: impl FnMut(ToolReceiptSummary) -> Result<()>,
    ) -> Result<u64> {
        if limit == Some(0) {
            return Ok(0);
        }
        self.read_snapshot(|journal| {
            visit(
                journal,
                journal.options.max_entry_bytes,
                after.unwrap_or(0),
                limit,
                &mut visitor,
            )
        })
    }
}

fn visit(
    journal: &Journal,
    budget: usize,
    after: u64,
    limit: Option<u64>,
    visitor: &mut impl FnMut(ToolReceiptSummary) -> Result<()>,
) -> Result<u64> {
    let budget = u64::try_from(budget)?;
    let mut statement = journal.connection.prepare(
        "SELECT r.id,length(CAST(r.sha256 AS BLOB)),r.sha256,length(CAST(r.tool AS BLOB)),r.tool,length(CAST(r.version AS BLOB)),r.version,length(CAST(r.source_sha256 AS BLOB)),r.source_sha256,(SELECT COUNT(*) FROM event_receipts e WHERE e.receipt_sha256=r.sha256) FROM tool_receipts r WHERE r.id>?1 ORDER BY r.id LIMIT ?2",
    )?;
    let mut rows = statement.query(params![
        i64::try_from(after)?,
        limit.map(i64::try_from).transpose()?.unwrap_or(-1)
    ])?;
    let mut count = 0_u64;
    while let Some(row) = rows.next()? {
        let id: i64 = row.get(0)?;
        if id <= 0 {
            return Err(invalid("journal tool receipt ID must be positive"));
        }
        if row.get::<_, u64>(1)? != 64 || row.get::<_, u64>(7)? != 64 {
            return Err(invalid(
                "journal tool receipt hashes must be SHA-256 values",
            ));
        }
        let tool_length: u64 = row.get(3)?;
        let version_length: u64 = row.get(5)?;
        if tool_length > budget || version_length > budget {
            return Err(invalid(
                "tool receipt metadata exceeds the configured reader budget",
            ));
        }
        let hash: String = row.get(2)?;
        let source_sha256: String = row.get(8)?;
        if !crate::hashing::is_sha256_digest(&hash)
            || !crate::hashing::is_sha256_digest(&source_sha256)
        {
            return Err(invalid(
                "journal tool receipt hashes must be SHA-256 values",
            ));
        }
        let receipt = ToolReceiptSummary {
            evidence_sha256: hash,
            tool: row.get(4)?,
            version: row.get(6)?,
            source_sha256,
            linked_events: row.get(9)?,
        };
        journal.verify_tool_receipt(&receipt.evidence_sha256)?;
        visitor(receipt)?;
        count = count
            .checked_add(1)
            .ok_or_else(|| invalid("tool receipt count exceeds the supported range"))?;
    }
    Ok(count)
}
