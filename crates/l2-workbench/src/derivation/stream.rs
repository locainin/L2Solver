//! Incremental execution of canonical operations on caller-owned streams

use super::{Operation, StepFailure};
use crate::job::{MemoryBudget, MemoryClass, MemoryError};
use base64::read::DecoderReader;
use flate2::bufread::{GzDecoder, ZlibDecoder};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fmt,
    io::{self, BufRead, BufReader, Read, Write},
};

const BUFFER_BYTES: usize = 16 * 1024;
const MAX_INTERRUPTED_READS: usize = 8;
// One input-length probe and a Base64 decoder's three-byte internal group
const WORK_PROBE_BYTES: usize = 4;

/// Conservative admission for stream buffers, gzip headers, and decoder state
pub const STREAM_WORKSPACE_BYTES: u64 = 1024 * 1024;

/// Immutable identity expected from the complete input stream
#[derive(Clone, Copy, Debug)]
pub struct StreamInput<'a> {
    /// Exact input length, including bytes outside a selected slice
    pub length: usize,
    /// Lowercase SHA-256 expected for the complete input
    pub sha256: &'a str,
}

/// Limits shared by one incremental operation
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamLimits {
    /// Maximum complete input length
    pub max_input_bytes: usize,
    /// Maximum output length
    pub max_output_bytes: usize,
    /// Maximum input and output work, including four reserved probe bytes
    pub max_work_bytes: usize,
    /// Maximum output length as a multiple of complete input length
    pub max_expansion_ratio: usize,
}

/// Exact successful operation and byte identities
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StreamReceipt {
    /// Canonical operation applied to the input
    pub operation: Operation,
    /// Complete source length
    pub input_length: usize,
    /// Verified source digest
    pub input_sha256: String,
    /// Produced output length
    pub output_length: usize,
    /// Output digest calculated during the write
    pub output_sha256: String,
    /// Input, output, and conservative probe bytes charged to this operation
    pub work_bytes: usize,
}

/// A stream operation could not be completed
#[derive(Debug)]
pub enum StreamTransformError {
    /// The operation is not supported by the incremental executor
    UnsupportedOperation,
    /// Input length exceeds the selected limit
    InputLimit { length: usize, limit: usize },
    /// The expansion ratio would be exceeded
    ExpansionLimit { limit: usize },
    /// The exact input identity or declared length changed
    InputChanged,
    /// The canonical operation rejected its input or a budget
    Step(StepFailure),
    /// The source or destination could not be read or written
    Io(io::Error),
    /// Shared memory admission did not permit the decoder workspace
    Memory(MemoryError),
}

impl fmt::Display for StreamTransformError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedOperation => {
                formatter.write_str("operation has no streaming implementation")
            }
            Self::InputLimit { length, limit } => {
                write!(formatter, "stream input length {length} exceeds {limit}")
            }
            Self::ExpansionLimit { limit } => {
                write!(formatter, "stream expansion exceeds ratio {limit}")
            }
            Self::InputChanged => formatter.write_str("stream input identity changed"),
            Self::Step(error) => write!(formatter, "stream operation failed: {error:?}"),
            Self::Io(error) => write!(formatter, "stream I/O failed: {error}"),
            Self::Memory(error) => write!(formatter, "stream workspace admission failed: {error}"),
        }
    }
}

impl Error for StreamTransformError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Memory(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for StreamTransformError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Apply one canonical operation with fixed-size buffers and a verified input identity
///
/// The caller must discard the destination on error because it may contain a prefix
/// A caller sharing a work budget across attempts must reserve the whole permitted
/// output allowance on failure, because a decoder or writer may process unwritten bytes
///
/// # Errors
/// Returns an explicit failure for unsupported operations, invalid input, exhausted
/// budgets, memory admission, a changed source, or a source or destination I/O error
pub fn stream_transform<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    operation: &Operation,
    input: StreamInput<'_>,
    limits: StreamLimits,
    memory: &MemoryBudget,
) -> Result<StreamReceipt, StreamTransformError> {
    if input.length > limits.max_input_bytes {
        return Err(StreamTransformError::InputLimit {
            length: input.length,
            limit: limits.max_input_bytes,
        });
    }
    let work_base = input
        .length
        .checked_add(WORK_PROBE_BYTES)
        .filter(|work| *work <= limits.max_work_bytes)
        .ok_or(StreamTransformError::Step(
            StepFailure::WorkBudgetExceeded {
                limit: limits.max_work_bytes,
            },
        ))?;
    // Gzip can retain three optional header fields as well as decoder state
    let _workspace = memory
        .try_reserve(MemoryClass::Executor, STREAM_WORKSPACE_BYTES)
        .map_err(StreamTransformError::Memory)?;
    let mut checked = CheckedInput {
        reader,
        remaining: input.length,
        digest: Sha256::new(),
        failure: None,
    };
    let mut output = BoundedOutput {
        writer,
        length: 0,
        digest: Sha256::new(),
        input_length: input.length,
        work_base,
        limits,
    };
    let result = apply_stream(&mut checked, &mut output, operation, input.length);
    // A decoder rejection must not hide an earlier source change or I/O error
    if let Some(failure) = checked.failure.take() {
        return Err(failure);
    }
    if let Err(error) = result {
        if is_conclusive_failure(&error) {
            // Failed syntax still needs a complete identity before it can be reported
            let drained = drain_input(&mut checked);
            if let Some(failure) = checked.failure.take() {
                return Err(failure);
            }
            drained?;
            checked.verify(input.sha256)?;
        }
        return Err(error);
    }
    checked.verify(input.sha256)?;
    let output_length = output.length;
    Ok(StreamReceipt {
        operation: operation.clone(),
        input_length: input.length,
        input_sha256: input.sha256.to_owned(),
        output_length,
        output_sha256: format!("{:x}", output.digest.finalize()),
        work_bytes: work_base + output_length,
    })
}

const fn is_conclusive_failure(error: &StreamTransformError) -> bool {
    matches!(
        error,
        StreamTransformError::Step(
            StepFailure::InvalidHexLength { .. }
                | StepFailure::InvalidHexDigit { .. }
                | StepFailure::InvalidBase64
                | StepFailure::InvalidCompressedStream
                | StepFailure::TrailingCompressedData
                | StepFailure::SliceOutOfBounds { .. }
        )
    )
}

fn drain_input(reader: &mut impl Read) -> io::Result<()> {
    let mut buffer = [0_u8; BUFFER_BYTES];
    loop {
        if reader.read(&mut buffer)? == 0 {
            return Ok(());
        }
    }
}

fn apply_stream<R: Read, W: Write>(
    input: &mut CheckedInput<'_, R>,
    output: &mut BoundedOutput<'_, W>,
    operation: &Operation,
    length: usize,
) -> Result<(), StreamTransformError> {
    match operation {
        Operation::HexDecode {} => decode_hex(input, output, length),
        Operation::Base64Decode { alphabet, padding } => {
            let engine = super::transform::base64_engine(*alphabet, *padding);
            let mut decoder = DecoderReader::new(input, &engine);
            copy_decoded(&mut decoder, output, &StepFailure::InvalidBase64)
        }
        Operation::GzipDecompress {} => {
            let mut decoder = GzDecoder::new(BufReader::new(input));
            copy_decoded(&mut decoder, output, &StepFailure::InvalidCompressedStream)?;
            reject_trailing(decoder.into_inner())
        }
        Operation::ZlibDecompress {} => {
            let mut decoder = ZlibDecoder::new(BufReader::new(input));
            copy_decoded(&mut decoder, output, &StepFailure::InvalidCompressedStream)?;
            reject_trailing(decoder.into_inner())
        }
        Operation::Slice {
            start,
            length: selected,
        } => slice_stream(input, output, length, *start, *selected),
        _ => Err(StreamTransformError::UnsupportedOperation),
    }
}

fn reject_trailing(mut reader: impl BufRead) -> Result<(), StreamTransformError> {
    if !reader.fill_buf()?.is_empty() {
        return Err(StreamTransformError::Step(
            StepFailure::TrailingCompressedData,
        ));
    }
    Ok(())
}

struct CheckedInput<'a, R> {
    reader: &'a mut R,
    remaining: usize,
    digest: Sha256,
    failure: Option<StreamTransformError>,
}

impl<R: Read> Read for CheckedInput<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() || self.remaining == 0 {
            return Ok(0);
        }
        let count = buffer.len().min(self.remaining);
        let part = buffer
            .get_mut(..count)
            .ok_or_else(|| io::Error::other("invalid stream input buffer"))?;
        let read = match read_source(self.reader, part) {
            Ok(read) => read,
            Err(error) => {
                let kind = error.kind();
                self.failure = Some(StreamTransformError::Io(error));
                // Some decoders retry Interrupted forever, so expose a non-retryable
                // placeholder while retaining the original source error for the caller
                let decoder_kind = if kind == io::ErrorKind::Interrupted {
                    io::ErrorKind::Other
                } else {
                    kind
                };
                return Err(io::Error::new(decoder_kind, "stream source read failed"));
            }
        };
        if read == 0 {
            self.failure = Some(StreamTransformError::InputChanged);
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "stream source ended early",
            ));
        }
        let bytes = part
            .get(..read)
            .ok_or_else(|| io::Error::other("stream reader returned an invalid length"))?;
        self.digest.update(bytes);
        self.remaining -= read;
        Ok(read)
    }
}

impl<R: Read> CheckedInput<'_, R> {
    fn verify(self, expected: &str) -> Result<(), StreamTransformError> {
        if self.remaining != 0 {
            return Err(StreamTransformError::InputChanged);
        }
        let mut extra = [0_u8; 1];
        if read_source(self.reader, &mut extra)? != 0
            || format!("{:x}", self.digest.finalize()) != expected
        {
            return Err(StreamTransformError::InputChanged);
        }
        Ok(())
    }
}

fn read_source(reader: &mut impl Read, buffer: &mut [u8]) -> io::Result<usize> {
    let mut interrupted = 0;
    loop {
        match reader.read(buffer) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                interrupted += 1;
                if interrupted == MAX_INTERRUPTED_READS {
                    return Err(error);
                }
            }
            result => return result,
        }
    }
}

struct BoundedOutput<'a, W> {
    writer: &'a mut W,
    length: usize,
    digest: Sha256,
    input_length: usize,
    work_base: usize,
    limits: StreamLimits,
}

impl<W: Write> BoundedOutput<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> Result<(), StreamTransformError> {
        let length = self
            .length
            .checked_add(bytes.len())
            .ok_or(StreamTransformError::Step(
                StepFailure::OutputLimitExceeded {
                    limit: self.limits.max_output_bytes,
                },
            ))?;
        self.check_length(length)?;
        self.writer.write_all(bytes)?;
        self.digest.update(bytes);
        self.length = length;
        Ok(())
    }

    const fn check_length(&self, length: usize) -> Result<(), StreamTransformError> {
        if length > self.limits.max_output_bytes {
            return Err(StreamTransformError::Step(
                StepFailure::OutputLimitExceeded {
                    limit: self.limits.max_output_bytes,
                },
            ));
        }
        if length > self.limits.max_work_bytes - self.work_base {
            return Err(StreamTransformError::Step(
                StepFailure::WorkBudgetExceeded {
                    limit: self.limits.max_work_bytes,
                },
            ));
        }
        let ratio_limit = self
            .input_length
            .saturating_mul(self.limits.max_expansion_ratio);
        if length > ratio_limit {
            return Err(StreamTransformError::ExpansionLimit {
                limit: self.limits.max_expansion_ratio,
            });
        }
        Ok(())
    }

    fn probe_limit(&self) -> usize {
        let ratio = self
            .input_length
            .saturating_mul(self.limits.max_expansion_ratio);
        let maximum = self
            .limits
            .max_output_bytes
            .min(self.limits.max_work_bytes - self.work_base)
            .min(ratio);
        maximum
            .saturating_sub(self.length)
            .saturating_add(1)
            .min(BUFFER_BYTES)
    }
}

fn copy_decoded<R: Read, W: Write>(
    reader: &mut R,
    output: &mut BoundedOutput<'_, W>,
    invalid: &StepFailure,
) -> Result<(), StreamTransformError> {
    let mut buffer = [0_u8; BUFFER_BYTES];
    loop {
        // One extra byte proves an exact boundary without expanding a full block
        let part = buffer
            .get_mut(..output.probe_limit())
            .ok_or_else(|| io::Error::other("invalid decoder output buffer"))?;
        let read = reader.read(part).map_err(|error| {
            if matches!(
                error.kind(),
                io::ErrorKind::InvalidData
                    | io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::InvalidInput
            ) {
                StreamTransformError::Step(invalid.clone())
            } else {
                StreamTransformError::Io(error)
            }
        })?;
        if read == 0 {
            return Ok(());
        }
        let part = buffer
            .get(..read)
            .ok_or_else(|| io::Error::other("decoder returned an invalid length"))?;
        output.write(part)?;
    }
}

fn decode_hex<R: Read, W: Write>(
    reader: &mut R,
    output: &mut BoundedOutput<'_, W>,
    length: usize,
) -> Result<(), StreamTransformError> {
    if !length.is_multiple_of(2) {
        return Err(StreamTransformError::Step(StepFailure::InvalidHexLength {
            length,
        }));
    }
    // The output length is known before reading any hexadecimal input
    output.check_length(length / 2)?;
    let mut input = [0_u8; BUFFER_BYTES];
    let mut decoded = [0_u8; BUFFER_BYTES / 2];
    let mut high = None;
    let mut offset = 0_usize;
    loop {
        let read = reader.read(&mut input)?;
        if read == 0 {
            return Ok(());
        }
        let mut count = 0;
        let bytes = input
            .get(..read)
            .ok_or_else(|| io::Error::other("stream reader returned an invalid length"))?;
        for byte in bytes {
            let nibble = crate::hex::decode_nibble(*byte).ok_or(StreamTransformError::Step(
                StepFailure::InvalidHexDigit { offset },
            ))?;
            offset += 1;
            if let Some(first) = high.take() {
                let slot = decoded
                    .get_mut(count)
                    .ok_or_else(|| io::Error::other("invalid hex output buffer"))?;
                *slot = (first << 4) | nibble;
                count += 1;
            } else {
                high = Some(nibble);
            }
        }
        let bytes = decoded
            .get(..count)
            .ok_or_else(|| io::Error::other("invalid hex output length"))?;
        output.write(bytes)?;
    }
}

fn slice_stream<R: Read, W: Write>(
    reader: &mut R,
    output: &mut BoundedOutput<'_, W>,
    input_length: usize,
    start: usize,
    length: Option<usize>,
) -> Result<(), StreamTransformError> {
    let length = match length {
        Some(length) => length,
        None => input_length
            .checked_sub(start)
            .ok_or(StreamTransformError::Step(StepFailure::SliceOutOfBounds {
                start,
                length: 0,
                input_length,
            }))?,
    };
    let end = start
        .checked_add(length)
        .filter(|end| *end <= input_length)
        .ok_or(StreamTransformError::Step(StepFailure::SliceOutOfBounds {
            start,
            length,
            input_length,
        }))?;
    output.check_length(length)?;
    let mut buffer = [0_u8; BUFFER_BYTES];
    let mut position = 0_usize;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            return Ok(());
        }
        let block_end = position + read;
        let from = start.saturating_sub(position).min(read);
        let to = end.saturating_sub(position).min(read);
        if from < to {
            let bytes = buffer
                .get(from..to)
                .ok_or_else(|| io::Error::other("invalid slice output range"))?;
            output.write(bytes)?;
        }
        position = block_end;
    }
}
