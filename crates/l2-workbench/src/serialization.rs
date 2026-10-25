use std::io::{self, Write};

/// Count encoded bytes without allocating an output document
pub struct CountWriter {
    maximum: usize,
    written: usize,
    exceeded: bool,
}

impl CountWriter {
    pub(super) const fn new(maximum: usize) -> Self {
        Self {
            maximum,
            written: 0,
            exceeded: false,
        }
    }

    pub(super) const fn written(&self) -> usize {
        self.written
    }
    pub(super) const fn exceeded(&self) -> bool {
        self.exceeded
    }
}

impl Write for CountWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(next) = self.written.checked_add(bytes.len()) else {
            self.exceeded = true;
            return Err(io::Error::other("encoded JSON size overflow"));
        };
        if next > self.maximum {
            self.exceeded = true;
            return Err(io::Error::other("encoded JSON exceeds size limit"));
        }
        self.written = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
