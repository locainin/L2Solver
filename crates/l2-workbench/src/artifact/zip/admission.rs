//! Live charges for parser-owned buffers and retained ZIP member reports

use super::{
    model::{
        ZipArtifactEntry, ZipArtifactEntryMetadata, ZipArtifactError, ZipArtifactOmission,
        ZipArtifactReport, ZipEntryDataFailure, ZipReadError,
    },
    view::Patch,
};
use crate::job::MemoryLease;
use std::{mem::size_of, ops::Range};

// The flate2 1.1.10 read decoder allocates this input buffer for one active member
// Recheck this charge when the decoder dependency or enabled backend changes
const DEFLATE_INPUT_BUFFER_BYTES: u64 = 32 * 1024;

pub(super) struct ZipAdmission<'a> {
    memory: Option<&'a mut MemoryLease>,
    scratch: Option<MemoryLease>,
    before: u64,
}

impl<'a> ZipAdmission<'a> {
    pub(super) const fn is_active(&self) -> bool {
        self.memory.is_some()
    }

    pub(super) fn new(
        memory: Option<&'a mut MemoryLease>,
        scan_bytes: usize,
    ) -> Result<Self, ZipReadError> {
        let before = memory.as_deref().map_or(0, MemoryLease::bytes);
        let base = scan_bytes
            .checked_add(64)
            .and_then(|bytes| bytes.checked_add(4 * size_of::<ZipArtifactOmission>()))
            .ok_or_else(allocation_failure)?;
        let base = u64::try_from(base).map_err(|_| allocation_failure())?;
        let scratch = memory
            .as_deref()
            .map(|memory| memory.try_sibling(base))
            .transpose()
            .map_err(ZipReadError::Memory)?;
        Ok(Self {
            memory,
            scratch,
            before,
        })
    }

    pub(super) fn reserve_metadata(
        &mut self,
        entries: usize,
        directory_bytes: u64,
    ) -> Result<(), ZipReadError> {
        let Some(scratch) = &mut self.scratch else {
            return Ok(());
        };
        // These are the parser-owned directory, range, report, omission and patch buffers
        let per_entry = size_of::<ZipArtifactEntryMetadata>()
            + size_of::<Option<ZipEntryDataFailure>>()
            + size_of::<(Range<u64>, usize, bool)>()
            + size_of::<ZipArtifactEntry>()
            + 2 * size_of::<ZipArtifactOmission>();
        let additional = entries
            .checked_mul(per_entry)
            .and_then(|bytes| bytes.checked_add(4 * size_of::<Patch>() + 24))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .and_then(|bytes| bytes.checked_add(directory_bytes))
            .and_then(|bytes| scratch.bytes().checked_add(bytes))
            .ok_or_else(allocation_failure)?;
        scratch.try_resize(additional).map_err(ZipReadError::Memory)
    }

    pub(super) fn reserve_output(
        &mut self,
        bytes: usize,
        deflate: bool,
    ) -> Result<(), ZipReadError> {
        let Some(memory) = &mut self.memory else {
            return Ok(());
        };
        let requested = u64::try_from(bytes)
            .ok()
            .and_then(|bytes| self.before.checked_add(bytes))
            .ok_or_else(allocation_failure)?;
        memory.try_resize(requested).map_err(ZipReadError::Memory)?;
        if deflate && let Some(scratch) = &mut self.scratch {
            let requested = scratch
                .bytes()
                .checked_add(DEFLATE_INPUT_BUFFER_BYTES)
                .ok_or_else(allocation_failure)?;
            scratch
                .try_resize(requested)
                .map_err(ZipReadError::Memory)?;
        }
        Ok(())
    }

    pub(super) fn finish(
        mut self,
        result: Result<ZipArtifactReport, ZipReadError>,
    ) -> Result<ZipArtifactReport, ZipReadError> {
        let Some(memory) = &mut self.memory else {
            return result;
        };
        match result {
            Ok(report) => {
                let retained = report_bytes(&report).and_then(|bytes| {
                    self.before
                        .checked_add(bytes)
                        .ok_or_else(allocation_failure)
                });
                if let Some(scratch) = self.scratch.take() {
                    memory.absorb(scratch);
                }
                let adjusted = retained
                    .and_then(|bytes| memory.try_resize(bytes).map_err(ZipReadError::Memory));
                match adjusted {
                    Ok(()) => Ok(report),
                    Err(error) => {
                        drop(report);
                        memory
                            .try_resize(self.before)
                            .map_err(ZipReadError::Memory)?;
                        Err(error)
                    }
                }
            }
            Err(error) => {
                drop(self.scratch.take());
                memory
                    .try_resize(self.before)
                    .map_err(ZipReadError::Memory)?;
                Err(error)
            }
        }
    }
}

fn report_bytes(report: &ZipArtifactReport) -> Result<u64, ZipReadError> {
    let mut bytes = report
        .archive_sha256
        .capacity()
        .checked_add(
            report
                .entries
                .capacity()
                .checked_mul(size_of::<ZipArtifactEntry>())
                .ok_or_else(allocation_failure)?,
        )
        .and_then(|bytes| {
            bytes.checked_add(
                report
                    .omissions
                    .capacity()
                    .checked_mul(size_of::<ZipArtifactOmission>())?,
            )
        })
        .ok_or_else(allocation_failure)?;
    for entry in &report.entries {
        bytes = bytes
            .checked_add(entry.metadata.raw_name.capacity())
            .and_then(|bytes| bytes.checked_add(entry.content.as_ref().map_or(0, Vec::capacity)))
            .ok_or_else(allocation_failure)?;
    }
    u64::try_from(bytes).map_err(|_| allocation_failure())
}

const fn allocation_failure() -> ZipReadError {
    ZipReadError::Format(ZipArtifactError::AllocationFailure)
}
