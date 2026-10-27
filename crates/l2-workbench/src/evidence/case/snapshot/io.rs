//! Shared bounded readers and writers for exact snapshots

use super::super::EvidenceError;
use std::{
    fmt,
    io::{self, Read, Write},
};

pub(super) struct LimitedWriter<W> {
    inner: W,
    maximum: u64,
    pub(super) written: u64,
    error_length_base: u64,
    error_maximum: u64,
}

impl<W> LimitedWriter<W> {
    pub(super) const fn new(
        inner: W,
        maximum: u64,
        error_length_base: u64,
        error_maximum: u64,
    ) -> Self {
        Self {
            inner,
            maximum,
            written: 0,
            error_length_base,
            error_maximum,
        }
    }
}

impl<W: Write> Write for LimitedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let remaining = self.maximum.saturating_sub(self.written);
        if remaining == 0 {
            let length = self
                .error_length_base
                .saturating_add(self.maximum)
                .saturating_add(1);
            return Err(limit_exceeded_io(length, self.error_maximum));
        }
        let length = bytes
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        let written_bytes = bytes
            .get(..length)
            .ok_or_else(|| io::Error::other("bounded snapshot slice was out of range"))?;
        let written = self.inner.write(written_bytes)?;
        self.written = self
            .written
            .checked_add(u64::try_from(written).map_err(io::Error::other)?)
            .ok_or_else(|| io::Error::other("snapshot storage count overflow"))?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

pub(super) fn write_limited<W: Write>(
    writer: &mut LimitedWriter<W>,
    bytes: &[u8],
) -> Result<(), EvidenceError> {
    writer.write_all(bytes).map_err(|error| write_error(&error))
}

pub(super) fn write_error(error: &io::Error) -> EvidenceError {
    limit_exceeded_from_io(error).unwrap_or(EvidenceError::WriteFailed)
}

pub(super) fn read_error(error: &io::Error) -> EvidenceError {
    limit_exceeded_from_io(error).unwrap_or(EvidenceError::InvalidJson)
}

#[derive(Debug)]
struct SnapshotLimitExceeded {
    length: u64,
    maximum: u64,
}

impl fmt::Display for SnapshotLimitExceeded {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "snapshot exceeds {} bytes", self.maximum)
    }
}

impl std::error::Error for SnapshotLimitExceeded {}

fn limit_exceeded_io(length: u64, maximum: u64) -> io::Error {
    io::Error::other(SnapshotLimitExceeded { length, maximum })
}

fn limit_exceeded_from_io(error: &io::Error) -> Option<EvidenceError> {
    let limit = error.get_ref()?.downcast_ref::<SnapshotLimitExceeded>()?;
    Some(case_too_large(limit.length, limit.maximum))
}

pub(super) fn case_too_large(length: u64, maximum: u64) -> EvidenceError {
    EvidenceError::CaseTooLarge {
        length: usize::try_from(length).unwrap_or(usize::MAX),
        maximum: usize::try_from(maximum).unwrap_or(usize::MAX),
    }
}
pub(super) struct BoundedRecordBuffer {
    pub(super) bytes: Vec<u8>,
    maximum: usize,
    pub(super) failure: Option<RecordBufferFailure>,
}

#[derive(Clone, Copy)]
pub(super) enum RecordBufferFailure {
    TooLarge,
    Allocation,
}

impl BoundedRecordBuffer {
    pub(super) const fn new(maximum: usize) -> Self {
        Self {
            bytes: Vec::new(),
            maximum,
            failure: None,
        }
    }
}

impl Write for BoundedRecordBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self.bytes.len().checked_add(bytes.len()).ok_or_else(|| {
            self.failure = Some(RecordBufferFailure::TooLarge);
            io::Error::new(io::ErrorKind::InvalidData, "snapshot record is too large")
        })?;
        if next > self.maximum {
            self.failure = Some(RecordBufferFailure::TooLarge);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "snapshot record is too large",
            ));
        }
        self.bytes.try_reserve(bytes.len()).map_err(|_| {
            self.failure = Some(RecordBufferFailure::Allocation);
            io::Error::other("snapshot record allocation failed")
        })?;
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) struct CountingReader<R> {
    inner: R,
    maximum: u64,
    pub(super) read_bytes: u64,
    error_length: u64,
    error_maximum: u64,
}

impl<R> CountingReader<R> {
    pub(super) const fn new(inner: R, maximum: u64, error_length: u64, error_maximum: u64) -> Self {
        Self {
            inner,
            maximum,
            read_bytes: 0,
            error_length,
            error_maximum,
        }
    }

    pub(super) const fn set_maximum(&mut self, maximum: u64) -> bool {
        self.maximum = maximum;
        self.read_bytes <= maximum
    }
}

impl<R: Read> Read for CountingReader<R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let remaining = self.maximum.saturating_sub(self.read_bytes);
        if remaining == 0 {
            let mut probe = [0_u8; 1];
            return match self.inner.read(&mut probe) {
                Ok(0) => Ok(0),
                Ok(_) => Err(limit_exceeded_io(self.error_length, self.error_maximum)),
                Err(error) => Err(error),
            };
        }
        let maximum_length = usize::try_from(remaining).unwrap_or(usize::MAX);
        let read_length = bytes.len().min(maximum_length);
        let read_buffer = bytes
            .get_mut(..read_length)
            .ok_or_else(|| io::Error::other("bounded snapshot slice was out of range"))?;
        let read = self.inner.read(read_buffer)?;
        self.read_bytes = self
            .read_bytes
            .checked_add(u64::try_from(read).map_err(io::Error::other)?)
            .ok_or_else(|| io::Error::other("snapshot input count overflow"))?;
        Ok(read)
    }
}
