use super::{Inventory, Result, Source, Store, invalid, verify};
use l2_pcap::CollectionSummary;
use rusqlite::Connection;

impl Store {
    /// Count disk-resident facts without materializing their connection state
    ///
    /// # Errors
    /// Returns database errors or malformed aggregate values
    pub fn inventory(&self) -> Result<Inventory> {
        let (sources,bytes,packets,unsupported): (u64,u64,u64,u64) = self.connection.query_row("SELECT COUNT(*),COALESCE(SUM(bytes),0),COALESCE(SUM(packets),0),COALESCE(SUM(unsupported),0) FROM sources", [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)))?;
        let (collection_summary, sources_with_unknown_collection_quality) =
            collection_inventory(&self.connection)?;
        Ok(Inventory {
            sources,
            bytes,
            packets,
            unsupported_transport_packets: unsupported,
            collection_summary,
            sources_with_unknown_collection_quality,
            flows: self
                .connection
                .query_row("SELECT COUNT(*) FROM flows", [], |row| row.get(0))?,
            dns_exchanges: self.connection.query_row(
                "SELECT COUNT(*) FROM dns_exchanges",
                [],
                |row| row.get(0),
            )?,
            dns_addresses: self.connection.query_row(
                "SELECT COUNT(*) FROM dns_addresses",
                [],
                |row| row.get(0),
            )?,
            limitations: vec![
                "Tuple membership is capture-scoped and does not establish a TCP session, host ownership, delivery, or malicious intent",
                "Raw capture bytes are retained once; packet extraction and selected-flow analysis reuse their exact original ranges",
                "DNS associations use capture order and exact questions/endpoints; multiple pending requests remain ambiguous",
                "Collection counters are source-reported; absent section declarations remain unknown rather than evidence of zero loss",
                "Fragments, unsupported link layouts, and unsupported application syntax remain raw evidence and require further reconstruction",
                "Shared-value groups compare literal IP addresses, ASCII-folded DNS question names, and full packet hashes; unavailable scope is reported, address matches do not establish host identity, and matching packet bytes may be correlated evidence",
            ],
        })
    }

    /// Visit source identities and immutable original capture sizes
    ///
    /// # Errors
    /// Returns storage or visitor errors
    pub fn visit_sources(&self, mut visitor: impl FnMut(Source) -> Result<()>) -> Result<()> {
        let mut statement = self.connection.prepare(
            "SELECT sha256,label,bytes,packets,collection_summary FROM sources ORDER BY id",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            visitor(Source {
                source_id: row.get(0)?,
                label: row.get(1)?,
                bytes: row.get(2)?,
                packets: row.get(3)?,
                collection_summary: crate::capture_collection::from_json(
                    &row.get::<_, String>(4)?,
                )?,
            })?;
        }
        Ok(())
    }

    /// Rehash every retained capture and check database integrity with bounded memory
    ///
    /// # Errors
    /// Rejects altered sources, length mismatches, foreign-key failures, or damaged indexes
    pub fn verify_sources(&self) -> Result<()> {
        let integrity: String =
            self.connection
                .pragma_query_value(None, "integrity_check", |row| row.get(0))?;
        if integrity != "ok" {
            return Err(invalid(format!(
                "index integrity check failed: {integrity}"
            )));
        }
        let invalid_rows: u64 = self.connection.query_row(
            "SELECT COUNT(*) FROM pragma_foreign_key_check",
            [],
            |row| row.get(0),
        )?;
        if invalid_rows != 0 {
            return Err(invalid("index foreign-key check failed"));
        }
        verify::contents(self)
    }
}

fn collection_inventory(connection: &Connection) -> Result<(CollectionSummary, u64)> {
    let mut summary = CollectionSummary::default();
    let mut unknown_sources = 0_u64;
    let mut statement = connection.prepare("SELECT collection_summary FROM sources ORDER BY id")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let value = crate::capture_collection::from_json(&row.get::<_, String>(0)?)?;
        merge_summary(&mut summary, value)?;
        unknown_sources = add_counter(
            unknown_sources,
            u64::from(crate::capture_collection::has_unknown_quality(value)),
        )?;
    }
    Ok((summary, unknown_sources))
}

fn merge_summary(total: &mut CollectionSummary, next: CollectionSummary) -> Result<()> {
    total.sections = add_counter(total.sections, next.sections)?;
    total.reported_sections = add_counter(total.reported_sections, next.reported_sections)?;
    total.incomplete_sections = add_counter(total.incomplete_sections, next.incomplete_sections)?;
    total.capture_dropped = add_counter(total.capture_dropped, next.capture_dropped)?;
    total.interface_dropped = add_counter(total.interface_dropped, next.interface_dropped)?;
    total.packet_block_packets_dropped = add_counter(
        total.packet_block_packets_dropped,
        next.packet_block_packets_dropped,
    )?;
    total.packet_blocks_with_unavailable_drop_count = add_counter(
        total.packet_blocks_with_unavailable_drop_count,
        next.packet_blocks_with_unavailable_drop_count,
    )?;
    Ok(())
}

fn add_counter(total: u64, next: u64) -> Result<u64> {
    total
        .checked_add(next)
        .ok_or_else(|| invalid("collection summary inventory counter overflow"))
}
