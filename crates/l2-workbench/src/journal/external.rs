use super::{Event, Journal, Result, invalid};
use crate::tshark::{TsharkFrameObservation, TsharkReport};
use rusqlite::params;

impl Journal {
    /// Retain a validated `TShark` report and its source-bound frame observations
    ///
    /// Tool values stay opaque to native protocol analysis. Reassembled fields
    /// remain attached to their original frame and receive no physical ranges.
    ///
    /// # Errors
    /// Rejects malformed reports, mismatched sources, duplicate frames or storage errors
    pub fn import_tshark_report(
        &mut self,
        report_bytes: &[u8],
        source_sha256: &str,
        source_length: u64,
    ) -> Result<String> {
        if report_bytes.len() > self.options.max_tool_report_bytes {
            return Err(invalid(
                "TShark report exceeds the configured tool-report budget",
            ));
        }
        if report_bytes.len() > i32::MAX as usize {
            return Err(invalid(
                "TShark report exceeds SQLite's BLOB addressability limit",
            ));
        }
        if !crate::hashing::is_sha256_digest(source_sha256) {
            return Err(invalid("capture source identity is not a SHA-256 hash"));
        }
        let report: TsharkReport = serde_json::from_slice(report_bytes)?;
        report.validate().map_err(invalid)?;
        if report.source.sha256 != source_sha256 || report.source.length != source_length {
            return Err(invalid(
                "TShark report does not match the supplied capture source",
            ));
        }

        let report_sha256 = crate::sha256(report_bytes);
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT OR IGNORE INTO objects(sha256,bytes) VALUES(?1,?2)",
            params![report_sha256, report_bytes],
        )?;
        transaction.execute(
            "INSERT OR IGNORE INTO tool_receipts(sha256,tool,version,source_sha256,schema_version) VALUES(?1,'tshark',?2,?3,?4)",
            params![
                report_sha256,
                report.tool.version,
                source_sha256,
                report.schema_version
            ],
        )?;
        let scope = format!("offline_capture:{source_sha256}");
        for packet in report.packets {
            let observation = TsharkFrameObservation {
                receipt_sha256: report_sha256.clone(),
                tool_version: report.tool.version.clone(),
                packet_number: packet.packet_number,
                fields: packet.fields,
                reassembled_fields: packet.reassembled_fields,
            };
            let fields = serde_json::to_value(observation)?;
            let event = Event {
                source: format!("sha256:{source_sha256}"),
                scope: scope.clone(),
                packet: packet.packet_number,
                kind: "tshark_frame".to_owned(),
                actor: None,
                peer: None,
                clock: None,
                ticks: None,
                fields,
                ranges: Vec::new(),
            };
            let event_identity =
                super::events::insert_event(&transaction, self.options.max_entry_bytes, &event)?;
            transaction.execute(
                "INSERT OR IGNORE INTO event_receipts(event_identity,receipt_sha256,frame) VALUES(?1,?2,?3)",
                params![event_identity, report_sha256, packet.packet_number],
            )?;
        }
        transaction.commit()?;
        Ok(report_sha256)
    }

    pub(super) fn verify_tool_receipts(&self) -> Result<()> {
        let mut statement = self
            .connection
            .prepare("SELECT length(CAST(sha256 AS BLOB)),sha256 FROM tool_receipts ORDER BY id")?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let hash_length: u64 = row.get(0)?;
            if hash_length != 64 {
                return Err(invalid("journal tool receipt identity is invalid"));
            }
            let report_sha256: String = row.get(1)?;
            if !crate::hashing::is_sha256_digest(&report_sha256) {
                return Err(invalid("journal tool receipt identity is invalid"));
            }
            self.verify_tool_receipt(&report_sha256)?;
        }
        Ok(())
    }

    pub(super) fn verify_tool_receipt(&self, report_sha256: &str) -> Result<()> {
        let (tool_length, version_length, source_length): (u64, u64, u64) = self.connection.query_row(
            "SELECT length(CAST(tool AS BLOB)),length(CAST(version AS BLOB)),length(CAST(source_sha256 AS BLOB)) FROM tool_receipts WHERE sha256=?1",
            [report_sha256],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let budget = u64::try_from(self.options.max_entry_bytes)?;
        if tool_length > budget || version_length > budget {
            return Err(invalid(
                "tool receipt metadata exceeds the configured reader budget",
            ));
        }
        if source_length != 64 {
            return Err(invalid("journal tool receipt source identity is invalid"));
        }
        let (tool, version, source_sha256, schema_version): (String, String, String, u8) = self
            .connection
            .query_row(
                "SELECT tool,version,source_sha256,schema_version FROM tool_receipts WHERE sha256=?1",
                [report_sha256],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )?;
        if tool != "tshark" || !crate::hashing::is_sha256_digest(&source_sha256) {
            return Err(invalid("journal tool receipt index is invalid"));
        }
        let bytes = self.object(report_sha256, self.options.max_tool_report_bytes)?;
        let report: TsharkReport = serde_json::from_slice(&bytes)?;
        report.validate().map_err(invalid)?;
        if report.schema_version != schema_version
            || report.source.sha256 != source_sha256
            || report.tool.version != version
        {
            return Err(invalid(
                "journal tool receipt index disagrees with its retained report",
            ));
        }
        self.verify_receipt_events(report_sha256, &report)
    }

    fn verify_receipt_events(&self, receipt_sha256: &str, report: &TsharkReport) -> Result<()> {
        let mut statement = self.connection.prepare(
            "SELECT r.event_identity,r.frame,length(CAST(e.identity AS BLOB)),length(CAST(e.source AS BLOB)),length(CAST(e.scope AS BLOB)),length(CAST(e.kind AS BLOB)),length(CAST(e.actor AS BLOB)),length(CAST(e.peer AS BLOB)),length(CAST(e.value AS BLOB)),e.identity,e.source,e.scope,e.packet,e.kind,e.actor,e.peer,e.value FROM event_receipts r JOIN events e ON e.identity=r.event_identity WHERE r.receipt_sha256=?1 ORDER BY r.frame",
        )?;
        let mut rows = statement.query([receipt_sha256])?;
        let mut frame_index = 0_usize;
        while let Some(row) = rows.next()? {
            verify_receipt_event(
                row,
                receipt_sha256,
                report,
                frame_index,
                self.options.max_entry_bytes,
            )?;
            frame_index += 1;
        }
        if frame_index != report.packets.len() {
            return Err(invalid(
                "journal TShark report is missing one or more event links",
            ));
        }
        Ok(())
    }
}

fn verify_receipt_event(
    row: &rusqlite::Row<'_>,
    receipt_sha256: &str,
    report: &TsharkReport,
    frame_index: usize,
    budget: usize,
) -> Result<()> {
    let identity_length: u64 = row.get(2)?;
    let value_length: u64 = row.get(8)?;
    let budget = u64::try_from(budget)?;
    if identity_length != 64 {
        return Err(invalid("journal event identity is invalid"));
    }
    for (index, name) in [(3, "source"), (4, "scope"), (5, "kind")] {
        if row.get::<_, u64>(index)? > budget {
            return Err(invalid(format!(
                "journal event index column {name} exceeds the configured reader budget"
            )));
        }
    }
    for (index, name) in [(6, "actor"), (7, "peer")] {
        if row
            .get::<_, Option<u64>>(index)?
            .is_some_and(|length| length > budget)
        {
            return Err(invalid(format!(
                "journal event index column {name} exceeds the configured reader budget"
            )));
        }
    }
    if value_length > budget {
        return Err(invalid("TShark event exceeds the configured reader budget"));
    }

    let event_identity: String = row.get(9)?;
    let frame: u64 = row.get(1)?;
    let source: String = row.get(10)?;
    let scope: String = row.get(11)?;
    let indexed_packet: u64 = row.get(12)?;
    let kind: String = row.get(13)?;
    let actor: Option<String> = row.get(14)?;
    let peer: Option<String> = row.get(15)?;
    let value: String = row.get(16)?;
    let event: Event = serde_json::from_str(&value)?;
    let packet = report
        .packets
        .get(frame_index)
        .ok_or_else(|| invalid("TShark receipt has an extra event link"))?;
    let expected_observation = TsharkFrameObservation {
        receipt_sha256: receipt_sha256.to_owned(),
        tool_version: report.tool.version.clone(),
        packet_number: packet.packet_number,
        fields: packet.fields.clone(),
        reassembled_fields: packet.reassembled_fields.clone(),
    };
    let expected_event = Event {
        source: format!("sha256:{}", report.source.sha256),
        scope: format!("offline_capture:{}", report.source.sha256),
        packet: packet.packet_number,
        kind: "tshark_frame".to_owned(),
        actor: None,
        peer: None,
        clock: None,
        ticks: None,
        fields: serde_json::to_value(expected_observation)?,
        ranges: Vec::new(),
    };
    if frame != packet.packet_number
        || crate::sha256(value.as_bytes()) != event_identity
        || source != expected_event.source
        || scope != expected_event.scope
        || indexed_packet != expected_event.packet
        || kind != expected_event.kind
        || actor != expected_event.actor
        || peer != expected_event.peer
        || serde_json::to_value(event)? != serde_json::to_value(expected_event)?
    {
        return Err(invalid(
            "journal TShark event link disagrees with its retained report",
        ));
    }
    Ok(())
}
