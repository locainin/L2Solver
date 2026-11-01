//! Validate derived PNG spools through the shared streaming parser

use super::super::file_artifact::DerivedArtifact;
use super::{JobReader, StreamContext, StreamObject, archive::next_index, omit, omit_formatted};
use l2_workbench::{
    artifact::{
        FileRange, PNG_SIGNATURE, PngLimits, PngRangeChunk, PngReadError, StreamPngBoundary,
        parse_png_from_reader_with_memory,
    },
    job::{Counter, MemoryClass},
};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fmt,
    io::{self, Read, Seek, SeekFrom},
};

// Reading, hashing, and CRC inspection each consume work for the same bytes
const WORK_PER_BYTE: usize = 3;
const PNG_BUFFER_BYTES: u64 = 16 * 1024;

#[cfg(test)]
#[path = "../../../tests/refine/stream_png.rs"]
mod tests;

pub(super) fn inspect_png(
    context: &mut StreamContext<'_>,
    object: StreamObject,
) -> Result<Option<StreamObject>, Box<dyn Error>> {
    let prefix = object
        .observation
        .prefix
        .get(..object.observation.prefix_length)
        .ok_or("invalid stream prefix")?;
    if !prefix.starts_with(&PNG_SIGNATURE) {
        return Ok(Some(object));
    }
    let length = object
        .derived
        .steps
        .last()
        .ok_or("stream receipt is missing")?
        .output_length;
    // Admit the parser buffer and chunk records before reading the spool
    let scratch = context
        .memory
        .try_reserve(MemoryClass::Executor, PNG_BUFFER_BYTES)?;
    let mut metadata = context.memory.try_reserve(MemoryClass::Executor, 0)?;
    let limits = PngLimits {
        max_input_bytes: length,
        max_chunks: PngLimits::default().max_chunks.min(
            (context.options.limits.max_input_bytes / std::mem::size_of::<PngRangeChunk>()).max(1),
        ),
    };
    let mut file = object.derived.spool.file.try_clone()?;
    file.seek(SeekFrom::Start(0))?;
    let reader = JobReader {
        inner: &mut file,
        job: context.job,
    };
    let mut reader = WorkHashReader::new(reader, &mut context.budget.work);
    let result = parse_png_from_reader_with_memory(&mut reader, length, limits, &mut metadata);
    let (work, digest) = reader.finish();
    context.report.work_bytes = context
        .report
        .work_bytes
        .checked_add(work)
        .ok_or("PNG inspection work overflows")?;
    let parsed = match result {
        Ok(parsed) => parsed,
        Err(PngReadError::Io(error)) if is_work_limit(&error) => {
            omit(
                context,
                None,
                "derived PNG inspection exceeded the stream work limit",
            )?;
            return Ok(Some(object));
        }
        Err(PngReadError::Io(error)) => return Err(error.into()),
        Err(PngReadError::Memory(error)) => return Err(error.into()),
        Err(PngReadError::Format(error)) => {
            omit_formatted(
                context,
                None,
                format_args!("derived PNG validation failed: {error}"),
            )?;
            return Ok(Some(object));
        }
    };
    // The parser stops at IEND, so its read digest covers exactly the PNG prefix
    let boundary = StreamPngBoundary {
        range: FileRange {
            offset: 0,
            length: parsed.bytes_after_iend_range.offset,
        },
        sha256: digest,
        chunk_count: parsed.chunks.len(),
    };
    drop(parsed);
    drop(metadata);
    drop(scratch);
    retain_png(context, &object, boundary)?;
    Ok(Some(object))
}

fn retain_png(
    context: &mut StreamContext<'_>,
    object: &StreamObject,
    boundary: StreamPngBoundary,
) -> Result<(), Box<dyn Error>> {
    let Some((index, _)) = next_index(context)? else {
        return Ok(());
    };
    let source_sha256 = context.report.source_sha256.clone();
    // Keep the private spool open while its validated range awaits publication
    context.analysis.append_stream_png(
        context.source_index,
        index,
        context.source,
        &source_sha256,
        boundary,
        DerivedArtifact::new(object.derived.clone(), context.memory, 1)?,
    )?;
    context.job.increment(Counter::ValidatedArtifacts, 1)?;
    Ok(())
}

#[derive(Debug)]
struct WorkLimit;

impl fmt::Display for WorkLimit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("stream work limit exhausted")
    }
}

impl Error for WorkLimit {}

fn is_work_limit(error: &io::Error) -> bool {
    matches!(error.get_ref(), Some(cause) if cause.is::<WorkLimit>())
}

struct WorkHashReader<'a, R> {
    inner: R,
    remaining: &'a mut usize,
    work: usize,
    digest: Sha256,
}

impl<'a, R> WorkHashReader<'a, R> {
    fn new(inner: R, remaining: &'a mut usize) -> Self {
        Self {
            inner,
            remaining,
            work: 0,
            digest: Sha256::new(),
        }
    }

    fn finish(self) -> (usize, String) {
        (self.work, format!("{:x}", self.digest.finalize()))
    }
}

impl<R: Read> Read for WorkHashReader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let limit = buffer.len().min(*self.remaining / WORK_PER_BYTE);
        if limit == 0 {
            // A work limit is an omission, not a claim that the PNG bytes are invalid
            return Err(io::Error::other(WorkLimit));
        }
        let destination = buffer
            .get_mut(..limit)
            .ok_or_else(|| io::Error::other("PNG read buffer is invalid"))?;
        let count = self.inner.read(destination)?;
        let cost = count * WORK_PER_BYTE;
        *self.remaining -= cost;
        self.work += cost;
        self.digest.update(
            destination
                .get(..count)
                .ok_or_else(|| io::Error::other("PNG read length is invalid"))?,
        );
        Ok(count)
    }
}
