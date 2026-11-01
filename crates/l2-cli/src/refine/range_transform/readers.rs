//! Cancellation-aware I/O for private temporary streams

use l2_workbench::job::Job;
use std::io::{self, Read, Seek, SeekFrom};

pub(super) struct JobReader<'a, R> {
    pub(super) inner: R,
    pub(super) job: &'a Job,
}
impl<R: Read> Read for JobReader<'_, R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.job.check_cancelled().map_err(io::Error::other)?;
        self.inner.read(bytes)
    }
}
impl<R: Seek> Seek for JobReader<'_, R> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.job.check_cancelled().map_err(io::Error::other)?;
        self.inner.seek(position)
    }
}
