//! Bounded writes to a new file, preserving long runs of zero bytes as holes

use std::{
    fs::File,
    io::{self, Seek, SeekFrom, Write},
};

const SCAN_BYTES: usize = 64 * 1024;

/// Sequential, bounded output to an initially empty file
///
/// [`Write::write_all`] rejects a chunk before writing when it exceeds the limit
/// Discard the unfinished file after any other write error, which may be partial
#[derive(Debug)]
pub struct SparseWriter<'file> {
    file: &'file mut File,
    maximum: u64,
    position: u64,
}

impl<'file> SparseWriter<'file> {
    /// Start writing at the beginning of an empty, privately owned file
    ///
    /// The file must be writable and must not be opened in append mode
    ///
    /// # Errors
    /// Rejects a nonempty file, a nonzero position, append mode on Unix, or an I/O failure
    pub fn new(file: &'file mut File, maximum: u64) -> io::Result<Self> {
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() != 0 || file.stream_position()? != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "sparse output must be an empty regular file at offset zero",
            ));
        }
        #[cfg(unix)]
        if rustix::fs::fcntl_getfl(&*file)?.contains(rustix::fs::OFlags::APPEND) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "sparse output cannot use append mode",
            ));
        }
        Ok(Self {
            file,
            maximum,
            position: 0,
        })
    }

    /// Set the final length, including any trailing hole, and return that length
    ///
    /// # Errors
    /// Returns an error if the final length cannot be set
    pub fn finish(self) -> io::Result<u64> {
        self.file.set_len(self.position)?;
        Ok(self.position)
    }
}

impl Write for SparseWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let length = u64::try_from(bytes.len()).map_err(io::Error::other)?;
        self.position
            .checked_add(length)
            .filter(|end| *end <= self.maximum)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "storage byte limit exceeded")
            })?;
        // Split mixed reads so framing bytes do not make long zero runs dense
        let mut chunks = bytes.chunks(SCAN_BYTES);
        let Some(first) = chunks.next() else {
            return Ok(0);
        };
        let zeroes = first.iter().all(|byte| *byte == 0);
        let mut run_length = first.len();
        for chunk in chunks {
            if chunk.iter().all(|byte| *byte == 0) != zeroes {
                break;
            }
            run_length += chunk.len();
        }
        if zeroes {
            let position = self.position + u64::try_from(run_length).map_err(io::Error::other)?;
            self.file.seek(SeekFrom::Start(position))?;
            self.position = position;
            Ok(run_length)
        } else {
            let (run, _) = bytes.split_at(run_length);
            let written = self.file.write(run)?;
            self.position += u64::try_from(written).map_err(io::Error::other)?;
            Ok(written)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}
