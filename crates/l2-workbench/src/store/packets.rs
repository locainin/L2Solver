use super::{Packet, Result, Source, Store, context::Context, invalid, paths};
use crate::evidence::SourceRange;
use l2_capture::{CaptureLocator, CapturedFrame};
use rusqlite::{Connection, OptionalExtension, Row, params};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

pub(super) fn packet_row(row: &Row<'_>) -> rusqlite::Result<Packet> {
    let source_id: String = row.get(0)?;
    let number: u32 = row.get(1)?;
    Ok(Packet {
        source_id: source_id.clone(),
        number,
        range: SourceRange {
            source: source_id,
            packet: Some(u64::from(number)),
            offset: row.get(2)?,
            length: row.get(3)?,
        },
        flow: row.get(4)?,
    })
}

pub(super) fn source_file(directory: &Path, source: &str) -> Result<File> {
    let digest = source
        .strip_prefix("sha256:")
        .filter(|digest| crate::hashing::is_sha256_digest(digest))
        .ok_or_else(|| invalid("invalid indexed source hash"))?;
    paths::regular(&directory.join(format!("{digest}.pcap")))
}

pub(super) fn read_frame(
    connection: &Connection,
    file: &mut File,
    packet: &Packet,
) -> Result<CapturedFrame> {
    let (original, ticks, framing, format, context,digest): (u32,Option<Vec<u8>>,u64,u32,String,Vec<u8>) = connection.prepare_cached("SELECT p.original_length,p.ticks,p.framing_offset,p.format,c.value,p.sha256 FROM packets p JOIN sources s ON s.id=p.source JOIN contexts c ON c.id=p.context WHERE s.sha256=?1 AND p.number=?2")?.query_row(params![packet.source_id,packet.number], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?)))?;
    if packet.range.length > u64::from(l2_pcap::MAX_FRAME_LENGTH)
        || packet
            .range
            .offset
            .checked_add(packet.range.length)
            .is_none_or(|end| end > file.metadata().map_or(0, |metadata| metadata.len()))
    {
        return Err(invalid("indexed frame range exceeds its retained source"));
    }
    let locator = match format {
        0 => CaptureLocator::ClassicPcap {
            record_offset: framing,
            data_offset: packet.range.offset,
        },
        2 | 3 | 6 => CaptureLocator::PcapNg {
            block_offset: framing,
            data_offset: packet.range.offset,
            block_type: format,
        },
        _ => return Err(invalid("unsupported indexed packet framing")),
    };
    let context: Context = serde_json::from_str(&context)?;
    let metadata = context.metadata(original, ticks.as_deref(), locator)?;
    file.seek(SeekFrom::Start(packet.range.offset))?;
    let mut bytes = vec![0; usize::try_from(packet.range.length)?];
    file.read_exact(&mut bytes)?;
    // Each export is bound to the exact packet bytes retained during source acquisition
    if Sha256::digest(&bytes).as_slice() != digest.as_slice() {
        return Err(invalid(
            "retained packet bytes changed after source acquisition",
        ));
    }
    Ok(CapturedFrame::new(bytes, metadata)?)
}

impl Store {
    /// Locate one flow's original source and its packet-row count
    ///
    /// # Errors
    /// Returns an error for a missing tuple or malformed stored source metadata
    pub(super) fn flow_source(&self, flow: i64) -> Result<(Source, u64)> {
        let retained: Option<(String, String, u64, u64, String)> = self
            .connection
            .query_row(
                "SELECT s.sha256,s.label,s.bytes,s.packets,s.collection_summary FROM flows f JOIN sources s ON s.id=f.source WHERE f.id=?1",
                [flow],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
            )
            .optional()?;
        let (source_id, label, bytes, packets, stored) =
            retained.ok_or_else(|| invalid(format!("indexed flow {flow} was not found")))?;
        let source = Source {
            source_id,
            label,
            bytes,
            packets,
            collection_summary: crate::capture_collection::from_json(&stored)?,
        };
        let records = self.connection.query_row(
            "SELECT COUNT(*) FROM packets WHERE flow=?1",
            [flow],
            |row| row.get(0),
        )?;
        Ok((source, records))
    }
    /// Look up one original source record without scanning unrelated packets
    ///
    /// # Errors
    /// Returns an error for a missing record or malformed stored fields
    pub fn packet(&self, source: &str, number: u32) -> Result<Packet> {
        Ok(self.connection.prepare_cached("SELECT s.sha256,p.number,p.offset,p.length,p.flow FROM packets p JOIN sources s ON s.id=p.source WHERE s.sha256=?1 AND p.number=?2")?.query_row(params![source,number], packet_row)?)
    }

    /// Read exactly one retained packet, preserving its capture metadata and locator
    ///
    /// # Errors
    /// Rejects missing packets, invalid ranges, and unavailable source files
    pub fn frame(&self, source: &str, number: u32) -> Result<CapturedFrame> {
        let packet = self.packet(source, number)?;
        read_frame(
            &self.connection,
            &mut source_file(&self.sources.path(), source)?,
            &packet,
        )
    }

    /// Stream every original packet reference for one bidirectional tuple
    ///
    /// # Errors
    /// Returns storage or visitor errors
    pub fn visit_flow_packets(
        &self,
        flow: i64,
        mut visitor: impl FnMut(Packet) -> Result<()>,
    ) -> Result<()> {
        let mut statement = self.connection.prepare("SELECT s.sha256,p.number,p.offset,p.length,p.flow FROM packets p JOIN sources s ON s.id=p.source WHERE p.flow=?1 ORDER BY p.number")?;
        let mut rows = statement.query([flow])?;
        while let Some(row) = rows.next()? {
            visitor(packet_row(row)?)?;
        }
        Ok(())
    }

    /// Stream checked original frames for one flow through a single retained-source handle
    ///
    /// # Errors
    /// Rejects changed source bytes and returns storage or visitor errors
    pub fn visit_flow_frames(
        &self,
        flow: i64,
        mut visitor: impl FnMut(Packet, CapturedFrame) -> Result<()>,
    ) -> Result<()> {
        let (source, _) = self.flow_source(flow)?;
        let mut file = source_file(&self.sources.path(), &source.source_id)?;
        self.visit_flow_packets(flow, |packet| {
            if packet.source_id != source.source_id {
                return Err(invalid("indexed flow crosses retained capture sources"));
            }
            let frame = read_frame(&self.connection, &mut file, &packet)?;
            visitor(packet, frame)
        })
    }
}

impl Store {
    /// Stream checked original frames while holding only one retained source handle
    ///
    /// # Errors
    /// Returns storage, changed-evidence or visitor errors
    pub fn visit_frames(
        &self,
        mut visitor: impl FnMut(Packet, CapturedFrame) -> Result<()>,
    ) -> Result<()> {
        let mut statement=self.connection.prepare("SELECT s.sha256,p.number,p.offset,p.length,p.flow FROM packets p JOIN sources s ON s.id=p.source ORDER BY p.source,p.number")?;
        let mut rows = statement.query([])?;
        let mut current: Option<(String, File)> = None;
        while let Some(row) = rows.next()? {
            let packet = packet_row(row)?;
            if current
                .as_ref()
                .is_none_or(|(source, _)| source != &packet.source_id)
            {
                current = Some((
                    packet.source_id.clone(),
                    source_file(&self.sources.path(), &packet.source_id)?,
                ));
            }
            let file = &mut current
                .as_mut()
                .ok_or_else(|| invalid("retained source is unavailable"))?
                .1;
            let frame = read_frame(&self.connection, file, &packet)?;
            visitor(packet, frame)?;
        }
        Ok(())
    }
}
