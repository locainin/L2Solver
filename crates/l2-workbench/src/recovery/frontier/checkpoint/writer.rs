//! Stream a checkpoint without exceeding the caller's physical byte limit

use super::super::RecoveryError;
use serde::Serialize;
use std::io::{self, Write};

pub(super) fn write<W: Write>(
    output: &mut W,
    limit: usize,
    value: &impl Serialize,
) -> Result<usize, RecoveryError> {
    let mut bounded = BoundedWriter {
        output,
        limit,
        written: 0,
        exceeded: false,
    };
    if serde_json::to_writer(&mut bounded, value).is_err() {
        return Err(if bounded.exceeded {
            RecoveryError::InvalidCheckpoint
        } else {
            RecoveryError::CheckpointWrite
        });
    }
    Ok(bounded.written)
}

struct BoundedWriter<'a, W> {
    output: &'a mut W,
    limit: usize,
    written: usize,
    exceeded: bool,
}

impl<W: Write> Write for BoundedWriter<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        // Check before forwarding bytes so the destination never crosses its limit
        if bytes.len() > self.limit - self.written {
            self.exceeded = true;
            return Err(io::Error::other("checkpoint exceeds its byte limit"));
        }
        let written = self.output.write(bytes)?;
        self.written += written;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}
