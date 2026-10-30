//! Preserve command outcomes after a standard-output reader closes

use std::io::{self, Write};

/// A writer that becomes a sink after the output reader closes
pub struct BrokenPipeWriter<W> {
    inner: W,
    closed: bool,
}

impl<W> BrokenPipeWriter<W> {
    /// Wrap an output destination
    #[must_use]
    pub const fn new(inner: W) -> Self {
        Self {
            inner,
            closed: false,
        }
    }
}

impl<W: Write> Write for BrokenPipeWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.closed {
            return Ok(bytes.len());
        }
        match self.inner.write(bytes) {
            Ok(written) => Ok(written),
            Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {
                // Keep computing the command result after the reader closes
                self.closed = true;
                Ok(bytes.len())
            }
            Err(error) => Err(error),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        match self.inner.flush() {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {
                self.closed = true;
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
}
