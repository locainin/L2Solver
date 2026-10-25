//! Format autodetection while preserving the bytes consumed for detection

use std::io::Read;

use crate::{
    CaptureLimits, CaptureReader, CapturedFrame, Error, PcapNgReader, reader::read_exact_counted,
};

/// A capture reader selected from the first four bytes of the source
pub struct CaptureSource<R: Read> {
    reader: SourceReader<R>,
}

enum SourceReader<R: Read> {
    Classic(CaptureReader<PrefixedReader<R>>),
    PcapNg(PcapNgReader<PrefixedReader<R>>),
}

impl<R: Read> CaptureSource<R> {
    /// Detect classic PCAP or PCAPNG and prepare a streaming reader
    ///
    /// The detection prefix is replayed into the selected reader, so format
    /// autodetection does not discard any capture bytes
    ///
    /// # Errors
    ///
    /// Returns an error when the prefix or selected format header is truncated,
    /// malformed, unsupported, interrupted too often, or fails to read
    pub fn new(reader: R) -> Result<Self, Error> {
        Self::with_limits(reader, CaptureLimits::default())
    }

    /// Detect a capture format using explicit byte and record ceilings
    ///
    /// # Errors
    /// Returns an error when limits are invalid or the prefix or selected format is
    /// truncated, malformed, unsupported, interrupted too often, or fails to read
    pub fn with_limits(mut reader: R, limits: CaptureLimits) -> Result<Self, Error> {
        let mut prefix = [0; 4];
        let mut input_bytes = 0;
        read_exact_counted(
            &mut reader,
            &mut prefix,
            &mut input_bytes,
            "capture format prefix",
            limits.max_input_bytes(),
        )?;
        let reader = PrefixedReader {
            prefix,
            prefix_position: 0,
            reader,
        };
        let source = if prefix == [0x0a, 0x0d, 0x0d, 0x0a] {
            SourceReader::PcapNg(PcapNgReader::with_limits(reader, limits)?)
        } else {
            SourceReader::Classic(CaptureReader::with_limits(reader, limits)?)
        };
        Ok(Self { reader: source })
    }

    /// Read the next packet from the selected capture format
    ///
    /// # Errors
    ///
    /// Returns the selected reader's bounded parse, input, or I/O errors
    pub fn next_packet(&mut self) -> Result<Option<CapturedFrame>, Error> {
        match &mut self.reader {
            SourceReader::Classic(reader) => reader.next_packet(),
            SourceReader::PcapNg(reader) => reader.next_packet(),
        }
    }

    /// Return collection declarations observed so far, without assuming absent counters are zero
    #[must_use]
    pub fn collection_summary(&self) -> crate::CollectionSummary {
        match &self.reader {
            SourceReader::Classic(_) => crate::CollectionSummary::default(),
            SourceReader::PcapNg(reader) => reader.collection_summary(),
        }
    }
}

struct PrefixedReader<R: Read> {
    prefix: [u8; 4],
    prefix_position: usize,
    reader: R,
}

impl<R: Read> Read for PrefixedReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.prefix_position < self.prefix.len() {
            let remaining = self
                .prefix
                .get(self.prefix_position..)
                .ok_or_else(|| std::io::Error::other("capture prefix range"))?;
            let count = remaining.len().min(buffer.len());
            let source = remaining
                .get(..count)
                .ok_or_else(|| std::io::Error::other("capture prefix range"))?;
            let destination = buffer
                .get_mut(..count)
                .ok_or_else(|| std::io::Error::other("capture destination range"))?;
            destination.copy_from_slice(source);
            self.prefix_position += count;
            // Report the replayed prefix before asking the underlying reader for more bytes
            return Ok(count);
        }
        self.reader.read(buffer)
    }
}
