//! Hash serialized identity data without retaining a complete JSON copy

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::{self, Write};

#[cfg(test)]
#[path = "../../tests/refine/hash.rs"]
mod tests;

pub(super) struct DigestWriter(Sha256);

impl DigestWriter {
    pub(super) fn new() -> Self {
        Self(Sha256::new())
    }

    pub(super) fn finish(self) -> String {
        format!("{:x}", self.0.finalize())
    }
}

impl Write for DigestWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn hash_json(value: &impl Serialize) -> Result<String, serde_json::Error> {
    let mut output = DigestWriter::new();
    serde_json::to_writer(&mut output, value)?;
    Ok(output.finish())
}
