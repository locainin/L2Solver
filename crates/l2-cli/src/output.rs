//! Output limits and pipe handling keep automation failures explicit

use std::{
    error::Error,
    io::{self, Write},
};

pub const MAX_SURVEY_JSON_BYTES: usize = 32 * 1024 * 1024;

pub struct BoundedWriter<W> {
    inner: W,
    limit: usize,
    written: usize,
    artifact: &'static str,
}

/// Standard-output writer that becomes a sink after its reader closes
pub struct BrokenPipeWriter<W> {
    inner: W,
    closed: bool,
}

impl<W> BrokenPipeWriter<W> {
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
                // The command keeps computing its semantic result after output closes
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

impl<W> BoundedWriter<W> {
    #[must_use]
    pub(crate) const fn written(&self) -> usize {
        self.written
    }

    #[must_use]
    pub const fn new(inner: W, limit: usize) -> Self {
        Self {
            inner,
            limit,
            written: 0,
            artifact: "survey JSON",
        }
    }

    /// Create a bounded writer with a precise artifact name for diagnostics
    #[must_use]
    pub const fn named(inner: W, limit: usize, artifact: &'static str) -> Self {
        Self {
            inner,
            limit,
            written: 0,
            artifact,
        }
    }
}

impl<W: Write> Write for BoundedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let remaining = self.limit.saturating_sub(self.written);
        if bytes.len() > remaining {
            return Err(io::Error::other(format!(
                "{} output exceeds {} bytes",
                self.artifact, self.limit
            )));
        }
        let count = self.inner.write(bytes)?;
        if count > bytes.len() {
            return Err(io::Error::other(
                "output writer reported more bytes than supplied",
            ));
        }
        self.written = self
            .written
            .checked_add(count)
            .ok_or_else(|| io::Error::other("output byte count overflow"))?;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

pub fn write_json<T: serde::Serialize>(
    value: &T,
    output: &mut impl Write,
    limit: usize,
) -> Result<(), Box<dyn Error>> {
    // Complete the bounded document before publishing any bytes to the destination
    let mut document = Vec::new();
    {
        let mut bounded = BoundedWriter::new(&mut document, limit);
        serde_json::to_writer(&mut bounded, value)?;
        bounded.write_all(b"\n")?;
    }
    output.write_all(&document)?;
    Ok(())
}
