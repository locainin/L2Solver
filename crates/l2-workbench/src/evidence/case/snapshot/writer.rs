//! Bounded snapshot graph and blob-pack encoding

use super::super::super::record::RecordRef;
use super::super::{Case, EvidenceError};
use super::{
    CaseSnapshotLimits, CaseSnapshotUsage,
    format::{MAX_SNAPSHOT_RECORD_BYTES, SNAPSHOT_FORMAT_VERSION, SnapshotBlobRef, SnapshotHeader},
    io::{
        BoundedRecordBuffer, LimitedWriter, RecordBufferFailure, case_too_large, write_error,
        write_limited,
    },
};
use flate2::{Compression, write::GzEncoder};
use serde::Serialize;
use std::io::Write;

impl Case {
    /// Write the exact graph and retained blob bytes to two bounded snapshot streams
    ///
    /// The graph is compressed JSONL; the blob pack stores each content-addressed blob once in
    /// Case order. The supplied limits apply to combined physical bytes and expanded graph plus
    /// blob bytes, independently.
    ///
    /// # Errors
    /// Returns an error for invalid Case data, exceeded limits, allocation failure, or I/O failure
    pub fn write_snapshot<G, B>(
        &self,
        graph: &mut G,
        blob_pack: &mut B,
        limits: CaseSnapshotLimits,
    ) -> Result<CaseSnapshotUsage, EvidenceError>
    where
        G: Write,
        B: Write,
    {
        let pack_bytes =
            u64::try_from(self.blob_bytes).map_err(|_| EvidenceError::ArithmeticOverflow {
                field: "snapshot blob pack",
            })?;
        if pack_bytes > limits.maximum_storage_bytes {
            return Err(case_too_large(pack_bytes, limits.maximum_storage_bytes));
        }
        if pack_bytes > limits.maximum_decoded_bytes {
            return Err(case_too_large(pack_bytes, limits.maximum_decoded_bytes));
        }
        self.validate()?;

        let mut pack_writer = LimitedWriter::new(
            blob_pack,
            limits.maximum_storage_bytes,
            0,
            limits.maximum_storage_bytes,
        );
        for blob in &self.blobs {
            write_limited(&mut pack_writer, &blob.bytes)?;
        }
        if pack_writer.written != pack_bytes {
            return Err(EvidenceError::InconsistentResourceCount {
                field: "snapshot blob pack",
            });
        }
        let (graph_bytes, graph_decoded_bytes) =
            self.write_graph_stream(graph, pack_bytes, limits)?;
        Ok(CaseSnapshotUsage {
            graph_bytes,
            graph_decoded_bytes,
            blob_pack_bytes: pack_writer.written,
        })
    }

    fn write_graph_stream<G: Write>(
        &self,
        graph: &mut G,
        pack_bytes: u64,
        limits: CaseSnapshotLimits,
    ) -> Result<(u64, u64), EvidenceError> {
        // The graph and pack share the same storage and decoded-data budgets
        let graph_storage_limit = limits.maximum_storage_bytes - pack_bytes;
        let graph_decoded_limit = limits.maximum_decoded_bytes - pack_bytes;
        let header = self.snapshot_header(pack_bytes)?;
        let mut graph_writer = LimitedWriter::new(
            graph,
            graph_storage_limit,
            pack_bytes,
            limits.maximum_storage_bytes,
        );
        let mut encoder = GzEncoder::new(&mut graph_writer, Compression::fast());
        let mut graph_decoded_bytes = 0_u64;
        write_snapshot_records(
            self,
            &mut encoder,
            &mut graph_decoded_bytes,
            graph_decoded_limit,
            &header,
        )?;
        encoder.try_finish().map_err(|error| write_error(&error))?;
        let graph_writer = encoder.finish().map_err(|error| write_error(&error))?;
        graph_writer.flush().map_err(|error| write_error(&error))?;
        Ok((graph_writer.written, graph_decoded_bytes))
    }

    fn snapshot_header(&self, pack_bytes: u64) -> Result<SnapshotHeader, EvidenceError> {
        Ok(SnapshotHeader {
            format_version: SNAPSHOT_FORMAT_VERSION,
            schema_version: self.schema_version,
            collection_complete: self.collection_complete,
            resource_limits: self.resource_limits,
            source_count: snapshot_count(self.sources.len(), "snapshot sources")?,
            blob_count: snapshot_count(self.blobs.len(), "snapshot blobs")?,
            node_count: snapshot_count(self.nodes.len(), "snapshot nodes")?,
            edge_count: snapshot_count(self.edges.len(), "snapshot edges")?,
            limitation_count: snapshot_count(self.limitations.len(), "snapshot limitations")?,
            blob_pack_bytes: pack_bytes,
        })
    }
}

fn snapshot_count(count: usize, field: &'static str) -> Result<u64, EvidenceError> {
    u64::try_from(count).map_err(|_| EvidenceError::ArithmeticOverflow { field })
}

fn write_snapshot_records<W: Write>(
    case: &Case,
    encoder: &mut GzEncoder<W>,
    decoded_bytes: &mut u64,
    maximum_decoded_bytes: u64,
    header: &SnapshotHeader,
) -> Result<(), EvidenceError> {
    write_record(
        encoder,
        decoded_bytes,
        maximum_decoded_bytes,
        &RecordRef {
            record: "header",
            value: header,
        },
    )?;
    for source in &case.sources {
        write_record(
            encoder,
            decoded_bytes,
            maximum_decoded_bytes,
            &RecordRef {
                record: "source",
                value: source,
            },
        )?;
    }
    write_snapshot_blob_records(case, encoder, decoded_bytes, maximum_decoded_bytes)?;
    for node in &case.nodes {
        write_record(
            encoder,
            decoded_bytes,
            maximum_decoded_bytes,
            &RecordRef {
                record: "node",
                value: node,
            },
        )?;
    }
    for edge in &case.edges {
        write_record(
            encoder,
            decoded_bytes,
            maximum_decoded_bytes,
            &RecordRef {
                record: "edge",
                value: edge,
            },
        )?;
    }
    for limitation in &case.limitations {
        write_record(
            encoder,
            decoded_bytes,
            maximum_decoded_bytes,
            &RecordRef {
                record: "limitation",
                value: limitation,
            },
        )?;
    }
    Ok(())
}

fn write_snapshot_blob_records<W: Write>(
    case: &Case,
    encoder: &mut GzEncoder<W>,
    decoded_bytes: &mut u64,
    maximum_decoded_bytes: u64,
) -> Result<(), EvidenceError> {
    let mut offset = 0_u64;
    for blob in &case.blobs {
        let length = snapshot_count(blob.bytes.len(), "snapshot blob length")?;
        write_record(
            encoder,
            decoded_bytes,
            maximum_decoded_bytes,
            &RecordRef {
                record: "blob",
                value: &SnapshotBlobRef {
                    id: &blob.id,
                    offset,
                    length,
                },
            },
        )?;
        offset = offset
            .checked_add(length)
            .ok_or(EvidenceError::ArithmeticOverflow {
                field: "snapshot blob offset",
            })?;
    }
    Ok(())
}
fn write_record<W, T>(
    encoder: &mut GzEncoder<W>,
    decoded_bytes: &mut u64,
    maximum_decoded_bytes: u64,
    record: &T,
) -> Result<(), EvidenceError>
where
    W: Write,
    T: Serialize,
{
    let available = maximum_decoded_bytes.saturating_sub(*decoded_bytes);
    let maximum_record = usize::try_from(available)
        .unwrap_or(usize::MAX)
        .min(MAX_SNAPSHOT_RECORD_BYTES + 1);
    if maximum_record == 0 {
        return Err(case_too_large(
            decoded_bytes.saturating_add(1),
            maximum_decoded_bytes,
        ));
    }
    let mut line = BoundedRecordBuffer::new(maximum_record.saturating_sub(1));
    let serialization = serde_json::to_writer(&mut line, record);
    if let Some(failure) = line.failure {
        return Err(match failure {
            RecordBufferFailure::TooLarge => case_too_large(
                decoded_bytes
                    .saturating_add(u64::try_from(line.bytes.len()).unwrap_or(u64::MAX))
                    .saturating_add(2),
                maximum_decoded_bytes,
            ),
            RecordBufferFailure::Allocation => EvidenceError::AllocationFailed {
                field: "snapshot graph record",
            },
        });
    }
    serialization.map_err(|_| EvidenceError::InvalidJson)?;
    if line.bytes.len() > MAX_SNAPSHOT_RECORD_BYTES {
        return Err(case_too_large(
            u64::try_from(line.bytes.len()).unwrap_or(u64::MAX),
            u64::try_from(MAX_SNAPSHOT_RECORD_BYTES).unwrap_or(u64::MAX),
        ));
    }
    let line_length = u64::try_from(line.bytes.len())
        .ok()
        .and_then(|length| length.checked_add(1))
        .ok_or(EvidenceError::ArithmeticOverflow {
            field: "snapshot graph record",
        })?;
    let next_decoded =
        decoded_bytes
            .checked_add(line_length)
            .ok_or(EvidenceError::ArithmeticOverflow {
                field: "snapshot graph bytes",
            })?;
    if next_decoded > maximum_decoded_bytes {
        return Err(case_too_large(next_decoded, maximum_decoded_bytes));
    }
    write_encoded(encoder, &line.bytes)?;
    write_encoded(encoder, b"\n")?;
    *decoded_bytes = next_decoded;
    Ok(())
}

fn write_encoded<W: Write>(writer: &mut W, bytes: &[u8]) -> Result<(), EvidenceError> {
    writer.write_all(bytes).map_err(|error| write_error(&error))
}
