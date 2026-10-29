//! Decode bounded records into the canonical version-two graph stream

use super::super::{
    Edge, MAX_BLOBS, MAX_EDGES, MAX_LIMITATION_BYTES, MAX_LIMITATIONS, MAX_NODE_DETAILS_BYTES,
    MAX_NODE_KIND_BYTES, MAX_NODE_RANGES, MAX_NODES, MAX_REASON_BYTES, MAX_RELATION_BYTES,
    MAX_SOURCES, MAX_TOTAL_DETAILS_BYTES, MAX_TOTAL_SOURCE_RANGES, Node, SCHEMA_VERSION, Source,
    SourceRange,
    case::{validate_content_id, validate_label, validate_text},
};
use super::{
    PublishedEvidenceLimits,
    canonical::{CountWriter, HASH_DOMAIN, PLACEHOLDER},
    format::{
        BlobReference, COMPACT_VERSION, Counts, Details, Header, LEGACY_VERSION, Record, VERSION,
        expand_compact_details,
    },
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    io::{self, BufRead, Read, Write},
    rc::Rc,
};

/// Decode supported published records to canonical version-two JSON Lines
///
/// Versions three through five check record order, references, ranges, declared counts, and Case IDs
/// Version two is parsed as a stream and copied without changing its bytes. A caller that
/// persists the output should publish it only after this function succeeds
///
/// # Errors
/// Returns an error for unsupported versions, malformed records, exceeded limits, invalid
/// references, inconsistent identities, or failed input or output
pub fn decode_published_evidence<R: BufRead, W: Write>(
    version: u32,
    input: R,
    output: W,
    limits: PublishedEvidenceLimits,
) -> io::Result<()> {
    if limits.maximum_stream_bytes == 0 || limits.maximum_record_bytes == 0 {
        return Err(io::Error::other("evidence limits must be nonzero"));
    }
    match version {
        2 => decode_legacy(input, output, limits.maximum_stream_bytes),
        LEGACY_VERSION | COMPACT_VERSION | VERSION => {
            decode_normalized(input, output, limits, version)
        }
        _ => Err(io::Error::other("unsupported published evidence version")),
    }
}

fn decode_legacy<R: BufRead, W: Write>(input: R, output: W, maximum: u64) -> io::Result<()> {
    let mut tee = Tee {
        input,
        output: CountWriter::new(io::BufWriter::new(output), maximum),
    };
    let records =
        serde_json::Deserializer::from_reader(&mut tee).into_iter::<serde::de::IgnoredAny>();
    for record in records {
        record.map_err(io::Error::other)?;
    }
    tee.output.flush()?;
    Ok(())
}

struct Tee<R, W> {
    input: R,
    output: CountWriter<W>,
}
impl<R: Read, W: Write> Read for Tee<R, W> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let n = self.input.read(bytes)?;
        let read = bytes
            .get(..n)
            .ok_or_else(|| invalid("invalid legacy read length"))?;
        self.output.write_all(read)?;
        Ok(n)
    }
}

fn decode_normalized<R: BufRead, W: Write>(
    input: R,
    output: W,
    limits: PublishedEvidenceLimits,
    version: u32,
) -> io::Result<()> {
    let mut records = RecordReader {
        input,
        buffer: Vec::new(),
        bytes: 0,
        limits,
    };
    let mut output = CountWriter::new(output, limits.maximum_stream_bytes);
    let mut previous_ordinal = 0;
    while let Some(record) = records.next()? {
        let Record::Header(header) = record else {
            return Err(invalid("expected evidence header"));
        };
        if header.ordinal <= previous_ordinal {
            return Err(invalid("evidence Case ordinals are not increasing"));
        }
        previous_ordinal = header.ordinal;
        read_case(&mut records, &mut output, &header, version)?;
    }
    Ok(())
}

fn read_case<R: BufRead, W: Write>(
    reader: &mut RecordReader<R>,
    output: &mut CountWriter<W>,
    header: &Header,
    version: u32,
) -> io::Result<()> {
    validate_header(header, version)?;
    let mut canonical = CanonicalWriter::new(output, header.ordinal);
    canonical.write_all(b"{\"case_id\":\"")?;
    canonical.write_id(&header.case_id)?;
    canonical.write_all(b"\",\"scope\":")?;
    json(&mut canonical, &header.scope)?;
    canonical.write_all(b",\"metadata\":")?;
    json(&mut canonical, &header.metadata)?;
    canonical.write_all(b",\"sources\":[")?;
    // Ordered sections prevent a reference from arriving before its source table
    let sources = read_sources(reader, &mut canonical, header.counts.sources)?;
    canonical.write_all(b"],\"blobs\":[")?;
    let blobs = read_blobs(reader, &mut canonical, header, &sources)?;
    canonical.write_all(b"],\"nodes\":[")?;
    read_nodes(reader, &mut canonical, header, &sources, &blobs)?;
    canonical.write_all(b"],\"edges\":[")?;
    read_edges(reader, &mut canonical, header)?;
    canonical.write_all(b"],\"limitations\":[")?;
    read_limitations(reader, &mut canonical, header.counts.limitations)?;
    if !matches!(reader.required()?, Record::End) {
        return Err(invalid("expected end of evidence Case"));
    }
    canonical.write_all(b"]}\n")?;
    // The canonical digest covers the complete graph, including limitations and receipts
    if format!("case-{:x}", canonical.digest.finalize()) != header.case_id {
        return Err(invalid("evidence Case identity does not match its graph"));
    }
    Ok(())
}

fn read_sources<R: BufRead, W: Write>(
    reader: &mut RecordReader<R>,
    canonical: &mut CanonicalWriter<'_, W>,
    count: usize,
) -> io::Result<Vec<Source>> {
    let mut sources = Vec::with_capacity(count);
    let mut source_ids = HashSet::new();
    for index in 0..count {
        let Record::Source(source) = reader.required()? else {
            return Err(invalid("expected source record"));
        };
        validate_content_id(&source.id).map_err(io::Error::other)?;
        validate_label(&source.label).map_err(io::Error::other)?;
        validate_text(&source.kind, 64, "source kind").map_err(io::Error::other)?;
        let mut names = HashSet::new();
        names.insert(source.label.as_str());
        for alias in &source.aliases {
            validate_label(alias).map_err(io::Error::other)?;
            if !names.insert(alias.as_str()) {
                return Err(invalid("duplicate evidence source alias"));
            }
        }
        if !source_ids.insert(source.id.clone()) {
            return Err(invalid("duplicate evidence source"));
        }
        comma(canonical, index)?;
        json(canonical, &source)?;
        sources.push(source);
    }
    Ok(sources)
}

struct Blobs {
    lengths: HashMap<Rc<str>, usize>,
    ordered: Vec<Rc<str>>,
}

impl Blobs {
    fn resolve_reference(
        &self,
        reference: Option<BlobReference>,
        version: u32,
    ) -> io::Result<Option<String>> {
        match reference {
            None => Ok(None),
            Some(BlobReference::Id(id)) => {
                if !self.lengths.contains_key(id.as_str()) {
                    return Err(invalid("missing node blob"));
                }
                Ok(Some(id))
            }
            Some(BlobReference::Index(index)) if version == VERSION => Ok(Some(
                self.ordered
                    .get(index)
                    .ok_or_else(|| invalid("missing node blob reference"))?
                    .to_string(),
            )),
            Some(BlobReference::Index(_)) => {
                Err(invalid("node blob reference requires version five"))
            }
        }
    }
}

fn read_blobs<R: BufRead, W: Write>(
    reader: &mut RecordReader<R>,
    canonical: &mut CanonicalWriter<'_, W>,
    header: &Header,
    sources: &[Source],
) -> io::Result<Blobs> {
    let mut blobs = Blobs {
        lengths: HashMap::new(),
        ordered: Vec::new(),
    };
    blobs
        .lengths
        .try_reserve(header.counts.blobs)
        .map_err(io::Error::other)?;
    blobs
        .ordered
        .try_reserve_exact(header.counts.blobs)
        .map_err(io::Error::other)?;
    for index in 0..header.counts.blobs {
        let Record::Blob(blob) = reader.required()? else {
            return Err(invalid("expected blob record"));
        };
        validate_content_id(&blob.id).map_err(io::Error::other)?;
        if header.version == LEGACY_VERSION && blob.schema_payload.is_some() {
            return Err(invalid("version three cannot contain schema payloads"));
        }
        let id = Rc::<str>::from(blob.id.as_str());
        if blobs
            .lengths
            .insert(Rc::clone(&id), blob.byte_length)
            .is_some()
        {
            return Err(invalid("duplicate evidence blob"));
        }
        // Share the validated ID between ordered and keyed lookups
        blobs.ordered.push(id);
        comma(canonical, index)?;
        json(canonical, &blob)?;
    }
    for source in sources {
        if let Some(id) = &source.blob {
            let size = blobs
                .lengths
                .get(id.as_str())
                .ok_or_else(|| invalid("missing source blob"))?;
            if id != &source.id || u64::try_from(*size).ok() != Some(source.length) {
                return Err(invalid("source blob identity or size differs"));
            }
        }
    }
    Ok(blobs)
}

fn read_nodes<R: BufRead, W: Write>(
    reader: &mut RecordReader<R>,
    canonical: &mut CanonicalWriter<'_, W>,
    header: &Header,
    sources: &[Source],
    blobs: &Blobs,
) -> io::Result<()> {
    let mut total_ranges = 0_usize;
    let mut total_details = 0_usize;
    for index in 0..header.counts.nodes {
        let Record::Node(record) = reader.required()? else {
            return Err(invalid("expected node record"));
        };
        if u64::try_from(index).ok().and_then(|n| n.checked_add(1)) != Some(record.0) {
            return Err(invalid("noncanonical evidence node ID"));
        }
        let blob = blobs.resolve_reference(record.2, header.version)?;
        total_ranges = total_ranges
            .checked_add(record.3.len())
            .ok_or_else(|| invalid("range count overflow"))?;
        if record.3.len() > MAX_NODE_RANGES || total_ranges > MAX_TOTAL_SOURCE_RANGES {
            return Err(invalid("evidence source range limit exceeded"));
        }
        let mut ranges = Vec::with_capacity(record.3.len());
        for (source_index, packet, offset, length) in record.3 {
            let source = sources
                .get(source_index)
                .ok_or_else(|| invalid("missing evidence source reference"))?;
            if length == 0
                || packet == Some(0)
                || offset
                    .checked_add(length)
                    .is_none_or(|end| end > source.length)
            {
                return Err(invalid("invalid evidence source range"));
            }
            ranges.push(SourceRange {
                source: source.id.clone(),
                packet,
                offset,
                length,
            });
        }
        // The normalized wrapper has field tags in addition to the original details
        if record.4.get().len() > MAX_NODE_DETAILS_BYTES * 16 {
            return Err(invalid("evidence node details exceed their limit"));
        }
        let (details, detail_bytes) = if header.version == LEGACY_VERSION {
            let details: Details =
                serde_json::from_str(record.4.get()).map_err(io::Error::other)?;
            details.expand(&header.strings.0)?
        } else {
            expand_compact_details(
                &record.4,
                &header.strings.0,
                blob.as_deref(),
                header.version,
            )?
        };
        total_details = total_details
            .checked_add(detail_bytes)
            .ok_or_else(|| invalid("evidence detail count overflow"))?;
        if total_details > MAX_TOTAL_DETAILS_BYTES {
            return Err(invalid("evidence Case details exceed their limit"));
        }
        let node = Node {
            id: record.0,
            kind: record.1.resolve(&header.strings.0)?,
            blob,
            ranges,
            details,
        };
        validate_text(&node.kind, MAX_NODE_KIND_BYTES, "node kind").map_err(io::Error::other)?;
        comma(canonical, index)?;
        json(canonical, &node)?;
    }
    Ok(())
}

fn read_edges<R: BufRead, W: Write>(
    reader: &mut RecordReader<R>,
    canonical: &mut CanonicalWriter<'_, W>,
    header: &Header,
) -> io::Result<()> {
    for index in 0..header.counts.edges {
        let Record::Edge(record) = reader.required()? else {
            return Err(invalid("expected edge record"));
        };
        let max_node = u64::try_from(header.counts.nodes).map_err(io::Error::other)?;
        if record.0 == 0 || record.1 == 0 || record.0 > max_node || record.1 > max_node {
            return Err(invalid("missing edge endpoint"));
        }
        let edge = Edge {
            from: record.0,
            to: record.1,
            relation: record.2.resolve(&header.strings.0)?,
            status: record.3,
            reason: record.4.resolve(&header.strings.0)?,
        };
        validate_text(&edge.relation, MAX_RELATION_BYTES, "edge relation")
            .map_err(io::Error::other)?;
        validate_text(&edge.reason, MAX_REASON_BYTES, "edge reason").map_err(io::Error::other)?;
        comma(canonical, index)?;
        json(canonical, &edge)?;
    }
    Ok(())
}

fn read_limitations<R: BufRead, W: Write>(
    reader: &mut RecordReader<R>,
    canonical: &mut CanonicalWriter<'_, W>,
    count: usize,
) -> io::Result<()> {
    for index in 0..count {
        let Record::Limitation(value) = reader.required()? else {
            return Err(invalid("expected limitation record"));
        };
        validate_text(&value, MAX_LIMITATION_BYTES, "limitation").map_err(io::Error::other)?;
        comma(canonical, index)?;
        json(canonical, &value)?;
    }
    Ok(())
}

fn validate_header(header: &Header, version: u32) -> io::Result<()> {
    let Counts {
        sources,
        blobs,
        nodes,
        edges,
        limitations,
    } = header.counts;
    if header.version != version
        || header.metadata.schema_version != SCHEMA_VERSION
        || header.ordinal == 0
        || sources > MAX_SOURCES
        || blobs > MAX_BLOBS
        || nodes > MAX_NODES
        || edges > MAX_EDGES
        || limitations > MAX_LIMITATIONS
        || header.case_id.len() != PLACEHOLDER.len()
        || !header.case_id.strip_prefix("case-").is_some_and(|digest| {
            digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
    {
        return Err(invalid("invalid evidence header"));
    }
    Ok(())
}

fn json<W: Write, T: Serialize + ?Sized>(writer: &mut W, value: &T) -> io::Result<()> {
    serde_json::to_writer(writer, value).map_err(io::Error::other)
}
fn comma<W: Write>(writer: &mut W, index: usize) -> io::Result<()> {
    if index > 0 {
        writer.write_all(b",")?;
    }
    Ok(())
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

struct CanonicalWriter<'a, W> {
    output: &'a mut CountWriter<W>,
    digest: Sha256,
}
impl<'a, W: Write> CanonicalWriter<'a, W> {
    fn new(output: &'a mut CountWriter<W>, ordinal: u64) -> Self {
        let mut digest = Sha256::new();
        digest.update(HASH_DOMAIN);
        digest.update(ordinal.to_be_bytes());
        Self { output, digest }
    }
    fn write_id(&mut self, id: &str) -> io::Result<()> {
        self.output.write_all(id.as_bytes())?;
        // Case identity is hashed with its ID field replaced by the fixed placeholder
        self.digest.update(PLACEHOLDER.as_bytes());
        Ok(())
    }
}
impl<W: Write> Write for CanonicalWriter<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let n = self.output.write(bytes)?;
        let written = bytes
            .get(..n)
            .ok_or_else(|| invalid("invalid canonical write length"))?;
        self.digest.update(written);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}

struct RecordReader<R> {
    input: R,
    buffer: Vec<u8>,
    bytes: u64,
    limits: PublishedEvidenceLimits,
}
impl<R: BufRead> RecordReader<R> {
    fn next(&mut self) -> io::Result<Option<Record>> {
        self.buffer.clear();
        let record_maximum =
            u64::try_from(self.limits.maximum_record_bytes).map_err(io::Error::other)?;
        // Probe at most one byte past the tighter of the record and stream limits
        let maximum =
            record_maximum.min(self.limits.maximum_stream_bytes.saturating_sub(self.bytes));
        let length = (&mut self.input)
            .take(maximum.saturating_add(1))
            .read_until(b'\n', &mut self.buffer)?;
        if length == 0 {
            return Ok(None);
        }
        let length = u64::try_from(length).map_err(io::Error::other)?;
        self.bytes = self
            .bytes
            .checked_add(length)
            .ok_or_else(|| invalid("evidence input count overflow"))?;
        if self.bytes > self.limits.maximum_stream_bytes
            || length > maximum
            || self.buffer.last() != Some(&b'\n')
        {
            return Err(invalid(
                "evidence record exceeds its limit or is incomplete",
            ));
        }
        serde_json::from_slice(&self.buffer)
            .map(Some)
            .map_err(io::Error::other)
    }
    fn required(&mut self) -> io::Result<Record> {
        self.next()?
            .ok_or_else(|| invalid("incomplete evidence Case"))
    }
}
