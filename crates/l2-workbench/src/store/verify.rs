use super::{
    Options, Result, Store,
    context::Context,
    dns,
    ingest::{self, CopyReader},
    invalid, packets, schema, scopes, shared,
};
use l2_capture::{CaptureLocator, CapturedFrame, EvidenceSourceId};
use l2_pcap::{CaptureLimits, CaptureSource};
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};
use std::io::{self, BufReader};

pub(super) fn contents(store: &Store) -> Result<()> {
    let temporary = tempfile::NamedTempFile::new()?;
    let mut expected = Connection::open(temporary.path())?;
    schema::configure(&expected, Options::default())?;
    schema::create(&expected)?;
    // This private scratch index rebuilds derived facts while large packet data stays on disk
    expected.pragma_update(None, "foreign_keys", false)?;
    let transaction = expected.transaction()?;
    let mut scope_cache = scopes::Cache::default();
    store.visit_sources(|source| verify_source(store, &source, &transaction, &mut scope_cache))?;
    transaction.commit()?;
    verify_flow_inventory(store)?;
    store.connection.execute(
        "ATTACH DATABASE ?1 AS verify_expected",
        [temporary
            .path()
            .to_str()
            .ok_or_else(|| invalid("temporary verification path is not UTF-8"))?],
    )?;
    let comparison = compare_facts(store);
    // Detach even after a failed comparison so a later verification can retry cleanly
    let detached = store
        .connection
        .execute_batch("DETACH DATABASE verify_expected");
    comparison?;
    detached?;
    Ok(())
}

fn compare_facts(store: &Store) -> Result<()> {
    for (table, columns) in [
        // Scope IDs are rebuilt in original source and packet order, including non-IP frames
        ("scopes", "id,value"),
        (
            "shared_facts",
            "kind,fact_key,source,packet,scope,offset,length",
        ),
        ("dns_pending", "key,source,packet"),
        ("dns_exchanges", "source,response,request,status,questions"),
        (
            "dns_addresses",
            "source,scope,response,request,requester,address,offset,length,status,owner",
        ),
    ] {
        for (first, second) in [("main", "verify_expected"), ("verify_expected", "main")] {
            let query = format!(
                "SELECT EXISTS(SELECT {columns} FROM {first}.{table} EXCEPT SELECT {columns} FROM {second}.{table})"
            );
            let differs: bool = store.connection.query_row(&query, [], |row| row.get(0))?;
            if differs {
                return Err(invalid(format!(
                    "indexed {table} facts disagree with original capture"
                )));
            }
        }
    }
    Ok(())
}

fn verify_source(
    store: &Store,
    source: &super::Source,
    expected: &Connection,
    scope_cache: &mut scopes::Cache,
) -> Result<()> {
    let source_number: i64 = store.connection.query_row(
        "SELECT id FROM sources WHERE sha256=?1",
        [&source.source_id],
        |row| row.get(0),
    )?;
    let file = packets::source_file(&store.sources.path(), &source.source_id)?;
    if file.metadata()?.len() != source.bytes {
        return Err(invalid("retained source length changed"));
    }
    let mut hash = Sha256::new();
    let mut bytes = 0;
    let mut count = 0_u64;
    let mut sink = io::sink();
    let collection_summary = {
        let reader = CopyReader {
            inner: file,
            file: &mut sink,
            hash: &mut hash,
            bytes: &mut bytes,
        };
        let mut capture = CaptureSource::with_limits(
            BufReader::with_capacity(1024 * 1024, reader),
            CaptureLimits::STREAMING,
        )?;
        while let Some(frame) = capture.next_packet()? {
            count += 1;
            let number = u32::try_from(count)?;
            let data_offset = match frame
                .metadata()
                .locator()
                .ok_or_else(|| invalid("source locator missing"))?
            {
                CaptureLocator::ClassicPcap { data_offset, .. }
                | CaptureLocator::PcapNg { data_offset, .. } => data_offset,
            };
            let transport = ingest::transport(&frame, data_offset, expected, scope_cache)?;
            let digest = packet(store, source_number, number, &frame, transport.as_ref())?;
            let facts = shared::packet_facts(expected, scope_cache, &frame, transport.as_ref())?;
            shared::observe_packet(
                expected,
                source_number,
                number,
                &frame,
                data_offset,
                &digest,
                facts,
            )?;
            if let Some(transport) = transport {
                dns::observe(expected, source_number, number, &transport)?;
            }
        }
        capture.collection_summary()
    };
    if count != source.packets
        || bytes != source.bytes
        || EvidenceSourceId::from_bytes(hash.finalize().into()).to_string() != source.source_id
        || collection_summary != source.collection_summary
    {
        return Err(invalid(
            "retained source identity, record count, or collection summary changed",
        ));
    }
    verify_packet_inventory(store, source_number, count)?;
    Ok(())
}

fn verify_packet_inventory(store: &Store, source: i64, expected: u64) -> Result<()> {
    let (indexed, unsupported): (u64, u64) = store.connection.query_row(
        "SELECT COUNT(*),COALESCE(SUM(flow IS NULL),0) FROM packets WHERE source=?1",
        [source],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if indexed != expected {
        return Err(invalid("indexed source record count disagrees"));
    }
    let stored: u64 = store.connection.query_row(
        "SELECT unsupported FROM sources WHERE id=?1",
        [source],
        |row| row.get(0),
    )?;
    if unsupported != stored {
        return Err(invalid("indexed unsupported packet count disagrees"));
    }
    Ok(())
}

fn verify_flow_inventory(store: &Store) -> Result<()> {
    let orphaned: u64 = store.connection.query_row(
        "SELECT COUNT(*) FROM flows f WHERE NOT EXISTS(SELECT 1 FROM packets p WHERE p.flow=f.id)",
        [],
        |row| row.get(0),
    )?;
    if orphaned != 0 {
        return Err(invalid("indexed flow has no supported packet"));
    }
    Ok(())
}

fn packet(
    store: &Store,
    source: i64,
    number: u32,
    frame: &CapturedFrame,
    transport: Option<&super::flows::Transport<'_>>,
) -> Result<[u8; 32]> {
    let (offset, framing, format) = match frame
        .metadata()
        .locator()
        .ok_or_else(|| invalid("source locator missing"))?
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
    let mut statement=store.connection.prepare_cached("SELECT p.offset,p.length,p.original_length,p.ticks,p.framing_offset,p.format,c.value,p.flow,p.payload_length,p.direction,p.sha256 FROM packets p JOIN contexts c ON c.id=p.context WHERE p.source=?1 AND p.number=?2")?;
    let mut rows = statement.query(params![source, number])?;
    let row = rows
        .next()?
        .ok_or_else(|| invalid("indexed packet missing"))?;
    let context: Context = serde_json::from_str(&row.get::<_, String>(6)?)?;
    let digest: [u8; 32] = Sha256::digest(frame.bytes()).into();
    let ticks: Option<Vec<u8>> = row.get(3)?;
    let expected_ticks = frame
        .metadata()
        .timestamp()
        .map(|timestamp| timestamp.ticks().to_be_bytes());
    if row.get::<_, u64>(0)? != offset
        || row.get::<_, usize>(1)? != frame.bytes().len()
        || row.get::<_, u32>(2)? != frame.metadata().original_len()
        || ticks.as_deref() != expected_ticks.as_ref().map(<[u8; 8]>::as_slice)
        || row.get::<_, u64>(4)? != framing
        || row.get::<_, u32>(5)? != format
        || context != Context::from_metadata(frame.metadata())
        || digest.as_slice() != row.get::<_, Vec<u8>>(10)?.as_slice()
    {
        return Err(invalid(
            "indexed packet metadata disagrees with original capture",
        ));
    }
    let flow: Option<i64> = row.get(7)?;
    if transport.is_some() != flow.is_some() {
        return Err(invalid("indexed transport support disagrees"));
    }
    if let (Some(transport), Some(flow)) = (transport, flow) {
        let [a, b] = transport.endpoints();
        let matches:bool=store.connection.prepare_cached("SELECT EXISTS(SELECT 1 FROM flows WHERE id=?1 AND source=?2 AND scope=?3 AND protocol=?4 AND a=?5 AND ap=?6 AND b=?7 AND bp=?8)")?.query_row(params![flow,source,transport.scope,transport.protocol,a.0,a.1,b.0,b.1],|row|row.get(0))?;
        if !matches
            || row.get::<_, usize>(8)? != transport.payload.len()
            || row.get::<_, u8>(9)? != transport.direction()
        {
            return Err(invalid("indexed flow disagrees with original packet"));
        }
    }
    Ok(digest)
}
