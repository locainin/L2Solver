use super::{
    IngestReceipt, Result, Store,
    context::Context,
    dns,
    flows::{self, Transport},
    invalid, packets,
    paths::Directory,
    scopes, shared,
};
use l2_audit::ForensicScope;
use l2_capture::{CaptureLocator, CapturedFrame, EvidenceSourceId};
use l2_core::FrameField;
use l2_discovery::{ip_packet_from_payload, link::decode_network_frame};
use l2_pcap::{CaptureLimits, CaptureSource};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    io::{self, BufReader, Read, Write},
};

pub(super) struct CopyReader<'a, R> {
    pub inner: R,
    pub file: &'a mut dyn Write,
    pub hash: &'a mut Sha256,
    pub bytes: &'a mut u64,
}

impl<R: Read> Read for CopyReader<'_, R> {
    fn read(&mut self, destination: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(destination)?;
        let bytes = destination
            .get(..read)
            .ok_or_else(|| io::Error::other("reader returned an invalid length"))?;
        self.file.write_all(bytes)?;
        self.hash.update(bytes);
        *self.bytes = self
            .bytes
            .checked_add(u64::try_from(read).map_err(io::Error::other)?)
            .ok_or_else(|| io::Error::other("capture byte count overflow"))?;
        Ok(read)
    }
}

impl Store {
    /// Copy and index one capture in one pass, rolling back every uncommitted row
    ///
    /// # Errors
    /// Rejects malformed captures, duplicate sources, invalid labels, and I/O failures
    ///
    /// Failures after publication can leave an orphan or an uncertain commit outcome
    /// Reopening supports verification or reindexing into a fresh directory; retrying an
    /// orphan is supported only on this still-open store
    pub fn ingest(&mut self, label: &str, reader: impl Read) -> Result<IngestReceipt> {
        self.ingest_with_source_sync(label, reader, Directory::sync)
    }

    fn ingest_with_source_sync(
        &mut self,
        label: &str,
        reader: impl Read,
        sync_source_directory: impl FnOnce(&Directory) -> Result<()>,
    ) -> Result<IngestReceipt> {
        if label.is_empty() || label.len() > 256 || label.chars().any(char::is_control) {
            return Err(invalid("invalid capture source label"));
        }
        // Keep the database and retained evidence rooted at their opened directories
        check_storage_locations(&self.directory, &self.sources)?;
        let mut retained = tempfile::NamedTempFile::new_in(self.sources.path())?;
        let transaction = self.connection.transaction()?;
        transaction.execute("INSERT INTO sources(label) VALUES(?1)", [label])?;
        let source = transaction.last_insert_rowid();
        let mut hash = Sha256::new();
        let mut bytes = 0_u64;
        let mut packets = 0_u64;
        let mut supported = 0_u64;
        let mut flow_cache = HashMap::new();
        let mut last_context = None;
        let mut scope_cache = scopes::Cache::default();
        let collection_summary = {
            let copying = CopyReader {
                inner: reader,
                file: retained.as_file_mut(),
                hash: &mut hash,
                bytes: &mut bytes,
            };
            let mut capture = CaptureSource::with_limits(
                BufReader::with_capacity(1024 * 1024, copying),
                CaptureLimits::STREAMING,
            )?;
            while let Some(frame) = capture.next_packet()? {
                packets += 1;
                supported += u64::from(retain_packet(
                    &transaction,
                    source,
                    u32::try_from(packets)?,
                    &frame,
                    &mut flow_cache,
                    &mut last_context,
                    &mut scope_cache,
                )?);
            }
            capture.collection_summary()
        };
        let source_id = EvidenceSourceId::from_bytes(hash.finalize().into()).to_string();
        let digest = source_id
            .strip_prefix("sha256:")
            .ok_or_else(|| invalid("canonical source identity lacks its SHA-256 prefix"))?;
        // Detect duplicate content explicitly so the storage schema never becomes the public error API
        let duplicate: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM sources WHERE sha256=?1)",
            [&source_id],
            |row| row.get(0),
        )?;
        if duplicate {
            return Err(invalid("duplicate capture source content"));
        }
        transaction.execute(
            "UPDATE sources SET sha256=?1,bytes=?2,packets=?3,unsupported=?4,collection_summary=?5 WHERE id=?6",
            params![source_id, bytes, packets, packets - supported, crate::capture_collection::to_json(collection_summary)?, source],
        )?;
        retained.as_file().sync_all()?;
        check_storage_locations(&self.directory, &self.sources)?;
        let path = self.sources.path().join(format!("{digest}.pcap"));
        // Reuse an orphan only when its regular-file contents match this complete source
        match retained.persist_noclobber(&path) {
            Ok(_) => {}
            Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {
                drop(error.file);
                verify_existing_source(&self.sources, &source_id, bytes)?;
            }
            Err(error) => return Err(error.into()),
        }
        sync_source_directory(&self.sources)?;
        check_storage_locations(&self.directory, &self.sources)?;
        transaction.commit()?;
        Ok(IngestReceipt {
            source_id,
            bytes,
            packets,
            transport_packets: supported,
            unsupported_transport_packets: packets - supported,
            collection_summary,
        })
    }
}

fn verify_existing_source(sources: &Directory, source_id: &str, expected_bytes: u64) -> Result<()> {
    let mut file = packets::source_file(&sources.path(), source_id)?;
    if file.metadata()?.len() != expected_bytes {
        return Err(invalid("occupied source path has a different length"));
    }

    let mut hash = Sha256::new();
    let bytes = io::copy(&mut file, &mut hash)?;
    let actual_source_id = EvidenceSourceId::from_bytes(hash.finalize().into()).to_string();
    if bytes != expected_bytes || actual_source_id != source_id {
        return Err(invalid(
            "occupied source path does not match incoming source",
        ));
    }
    // Matching bytes may have been written by another process and still need a durability barrier
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/store/ingest_internal.rs"]
mod internal_tests;

fn check_storage_locations(directory: &Directory, sources: &Directory) -> Result<()> {
    directory.check_location()?;
    // Source evidence has its own held directory and can move independently
    sources.check_location()
}

fn retain_packet(
    connection: &Connection,
    source: i64,
    number: u32,
    frame: &CapturedFrame,
    cache: &mut HashMap<Vec<u8>, i64>,
    last: &mut Option<(Context, i64)>,
    scope_cache: &mut scopes::Cache,
) -> Result<bool> {
    let context = retain_context(connection, frame, last)?;
    let (offset, framing, format) = match frame
        .metadata()
        .locator()
        .ok_or_else(|| invalid("capture packet locator is missing"))?
    {
        CaptureLocator::ClassicPcap {
            record_offset,
            data_offset,
        } => (data_offset, record_offset, 0),
        CaptureLocator::PcapNg {
            block_offset,
            data_offset,
            block_type,
        } => (data_offset, block_offset, block_type),
    };
    let transport = transport(frame, offset, connection, scope_cache)?;
    let flow = transport
        .as_ref()
        .map(|transport| flows::retain(connection, cache, source, transport))
        .transpose()?;
    let ticks = frame
        .metadata()
        .timestamp()
        .map(|time| time.ticks().to_be_bytes());
    let direction = transport.as_ref().map_or(0, Transport::direction);
    let digest: [u8; 32] = Sha256::digest(frame.bytes()).into();
    connection.prepare_cached("INSERT INTO packets(source,number,offset,length,original_length,context,ticks,framing_offset,format,flow,payload_length,direction,sha256) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)")?
        .execute(params![source,number,offset,frame.bytes().len(),frame.metadata().original_len(),context,ticks.as_ref().map(<[u8;8]>::as_slice),framing,format,flow,transport.as_ref().map_or(0, |transport| transport.payload.len()),direction,digest.as_slice()])?;
    let facts = shared::packet_facts(connection, scope_cache, frame, transport.as_ref())?;
    shared::observe_packet(connection, source, number, frame, offset, &digest, facts)?;
    if let Some(transport) = transport.as_ref() {
        dns::observe(connection, source, number, transport)?;
    }
    Ok(flow.is_some())
}

fn retain_context(
    connection: &Connection,
    frame: &CapturedFrame,
    last: &mut Option<(Context, i64)>,
) -> Result<i64> {
    let context = Context::from_metadata(frame.metadata());
    if let Some((previous, id)) = last
        && *previous == context
    {
        return Ok(*id);
    }
    let value = serde_json::to_string(&context)?;
    let inserted = connection
        .prepare_cached(
            "INSERT INTO contexts(value) VALUES(?1) ON CONFLICT(value) DO NOTHING RETURNING id",
        )?
        .query_row([&value], |row| row.get(0))
        .optional()?;
    let id = match inserted {
        Some(id) => id,
        None => connection
            .prepare_cached("SELECT id FROM contexts WHERE value=?1")?
            .query_row([&value], |row| row.get(0))?,
    };
    *last = Some((context, id));
    Ok(id)
}

pub(super) fn transport<'a>(
    frame: &'a CapturedFrame,
    offset: u64,
    connection: &Connection,
    scope_cache: &mut scopes::Cache,
) -> Result<Option<Transport<'a>>> {
    let Some(decoded) = decode_network_frame(frame.metadata().link_type(), frame.bytes()) else {
        return Ok(None);
    };
    // Cooked protocol fields are usable only when their hardware layout is understood
    let Some(FrameField::EtherType(protocol)) = decoded.field() else {
        return Ok(None);
    };
    let Some(ip) = ip_packet_from_payload(protocol, decoded.payload()) else {
        return Ok(None);
    };
    let Some(transport) = ip.transport else {
        return Ok(None);
    };
    let scope = scope_cache.retain(
        connection,
        &ForensicScope::from_network_frame(frame.metadata(), &decoded),
    )?;
    Ok(Some(Transport {
        scope,
        protocol: ip.protocol,
        source: flows::address_bytes(ip.source),
        destination: flows::address_bytes(ip.destination),
        ports: transport.ports,
        payload: transport.payload,
        payload_offset: offset
            + u64::try_from(decoded.payload_offset() + transport.payload_offset)?,
    }))
}
