//! Bounded random-access views and read-only ZIP metadata overlays

use std::{
    cell::{Cell, RefCell},
    io::{self, Read, Seek, SeekFrom},
    ops::Range,
};

const READ_BUFFER_BYTES: usize = 16 * 1024;

pub(super) enum ViewFailure {
    Io(io::Error),
    WorkLimit { requested: usize, remaining: usize },
    Allocation,
}

pub(super) struct View<R> {
    reader: RefCell<R>,
    length: usize,
    remaining: Cell<usize>,
    failure: RefCell<Option<ViewFailure>>,
}

impl<R: Read + Seek> View<R> {
    pub(super) const fn new(reader: R, length: usize, maximum_read_bytes: usize) -> Self {
        Self {
            reader: RefCell::new(reader),
            length,
            remaining: Cell::new(maximum_read_bytes),
            failure: RefCell::new(None),
        }
    }

    pub(super) const fn len(&self) -> usize {
        self.length
    }

    pub(super) const fn remaining(&self) -> usize {
        self.remaining.get()
    }

    pub(super) fn get(&self, range: Range<usize>) -> Option<Vec<u8>> {
        let length = range.end.checked_sub(range.start)?;
        if range.end > self.length {
            return None;
        }
        let mut bytes = Vec::new();
        if bytes.try_reserve_exact(length).is_err() {
            self.record_failure(ViewFailure::Allocation);
            return None;
        }
        bytes.resize(length, 0);
        self.read_exact_at(range.start, &mut bytes).ok()?;
        Some(bytes)
    }

    pub(super) fn array<const N: usize>(&self, offset: usize) -> Option<[u8; N]> {
        if offset.checked_add(N)? > self.length {
            return None;
        }
        let mut bytes = [0_u8; N];
        self.read_exact_at(offset, &mut bytes).ok()?;
        Some(bytes)
    }

    pub(super) fn take_failure(&self) -> Option<ViewFailure> {
        self.failure.borrow_mut().take()
    }

    fn record_failure(&self, failure: ViewFailure) {
        let mut current = self.failure.borrow_mut();
        if current.is_none() {
            *current = Some(failure);
        }
    }

    fn read_exact_at(&self, offset: usize, bytes: &mut [u8]) -> io::Result<()> {
        let remaining = self.remaining.get();
        if bytes.len() > remaining {
            self.record_failure(ViewFailure::WorkLimit {
                requested: bytes.len(),
                remaining,
            });
            return Err(io::Error::other("ZIP reader work limit reached"));
        }
        self.remaining.set(remaining - bytes.len());
        let offset = u64::try_from(offset).map_err(io::Error::other)?;
        let mut reader = self.reader.borrow_mut();
        let result = reader.seek(SeekFrom::Start(offset)).and_then(|_| {
            for chunk in bytes.chunks_mut(READ_BUFFER_BYTES) {
                reader.read_exact(chunk)?;
            }
            Ok(())
        });
        if let Err(error) = result {
            let reported = io::Error::new(error.kind(), error.to_string());
            self.record_failure(ViewFailure::Io(error));
            return Err(reported);
        }
        Ok(())
    }
}

pub(super) struct Patch {
    pub(super) offset: usize,
    pub(super) bytes: Vec<u8>,
}

pub(super) struct Reader<'a, R> {
    view: &'a View<R>,
    position: usize,
    patches: Vec<Patch>,
}

impl<'a, R: Read + Seek> Reader<'a, R> {
    pub(super) const fn new(view: &'a View<R>, patches: Vec<Patch>) -> Self {
        Self {
            view,
            position: 0,
            patches,
        }
    }
}

impl<R: Read + Seek> Read for Reader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = buffer
            .len()
            .min(self.view.len().saturating_sub(self.position));
        let part = buffer
            .get_mut(..count)
            .ok_or_else(|| io::Error::other("ZIP buffer length is invalid"))?;
        self.view.read_exact_at(self.position, part)?;
        let end = self.position + count;
        // Apply private metadata patches only to bytes returned to the ZIP library
        for patch in &self.patches {
            let patch_end = patch
                .offset
                .checked_add(patch.bytes.len())
                .ok_or_else(|| io::Error::other("ZIP patch length overflow"))?;
            let start = self.position.max(patch.offset);
            let stop = end.min(patch_end);
            if start < stop {
                let destination = part
                    .get_mut(start - self.position..stop - self.position)
                    .ok_or_else(|| io::Error::other("ZIP patch destination is invalid"))?;
                let source = patch
                    .bytes
                    .get(start - patch.offset..stop - patch.offset)
                    .ok_or_else(|| io::Error::other("ZIP patch source is invalid"))?;
                destination.copy_from_slice(source);
            }
        }
        self.position = end;
        Ok(count)
    }
}

impl<R: Read + Seek> Seek for Reader<'_, R> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let next = match position {
            SeekFrom::Start(offset) => i128::from(offset),
            SeekFrom::Current(offset) => {
                i128::try_from(self.position).map_err(io::Error::other)? + i128::from(offset)
            }
            SeekFrom::End(offset) => {
                i128::try_from(self.view.len()).map_err(io::Error::other)? + i128::from(offset)
            }
        };
        self.position = usize::try_from(next).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "ZIP seek offset is invalid")
        })?;
        u64::try_from(self.position).map_err(io::Error::other)
    }
}
