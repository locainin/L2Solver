//! Count diagnostic JSON without retaining an uncharged output buffer

use serde::Serialize;
use std::io::{self, Write};

pub(in crate::job) const MAX_DIAGNOSTIC_BYTES: usize = 1024 * 1024;

struct CounterWriter {
    maximum: usize,
    written: usize,
}

impl Write for CounterWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(written) = self.written.checked_add(bytes.len()) else {
            return Err(io::Error::other("diagnostic size overflow"));
        };
        if written > self.maximum {
            return Err(io::Error::other("diagnostic size limit reached"));
        }
        self.written = written;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(in crate::job) fn encoded_fits<T: Serialize>(value: &T, maximum: usize) -> bool {
    let mut writer = CounterWriter {
        maximum,
        written: 0,
    };
    serde_json::to_writer(&mut writer, value).is_ok()
}
