//! Bounded syntax observations collected while a stream is already being read or written

use l2_workbench::{
    derivation::{Base64Alphabet, Base64Padding, Operation},
    job::Job,
    recovery::proposals::{TransformProposalBudget, propose_transforms},
};
use std::{
    fs::File,
    io::{self, Read, Write},
};

pub(super) const PROPOSAL_PREFIX_BYTES: usize = 4096;

pub(in crate::refine) struct Observation {
    pub(super) prefix: [u8; PROPOSAL_PREFIX_BYTES],
    pub(super) prefix_length: usize,
    length: usize,
    standard_symbols: bool,
    url_symbols: bool,
}

impl Observation {
    const fn new() -> Self {
        Self {
            prefix: [0; PROPOSAL_PREFIX_BYTES],
            prefix_length: 0,
            length: 0,
            standard_symbols: false,
            url_symbols: false,
        }
    }

    fn accept(&mut self, bytes: &[u8]) -> io::Result<()> {
        let count = bytes.len().min(self.prefix.len() - self.prefix_length);
        let destination = self
            .prefix
            .get_mut(self.prefix_length..self.prefix_length + count)
            .ok_or_else(|| io::Error::other("invalid proposal prefix"))?;
        destination.copy_from_slice(
            bytes
                .get(..count)
                .ok_or_else(|| io::Error::other("invalid observed bytes"))?,
        );
        self.prefix_length += count;
        self.length = self
            .length
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("observed stream length overflows"))?;
        // Later alphabet-specific symbols select the correct canonical Base64 engine
        self.standard_symbols |= bytes.iter().any(|byte| matches!(byte, b'+' | b'/'));
        self.url_symbols |= bytes.iter().any(|byte| matches!(byte, b'-' | b'_'));
        Ok(())
    }

    pub(super) fn operations(&self) -> io::Result<Vec<Operation>> {
        let prefix = self
            .prefix
            .get(..self.prefix_length)
            .ok_or_else(|| io::Error::other("invalid proposal prefix length"))?;
        let candidates = propose_transforms(
            prefix,
            TransformProposalBudget {
                max_candidates: 7,
                max_reports: 0,
            },
        );
        let mut operations = Vec::new();
        operations
            .try_reserve(candidates.proposals.len())
            .map_err(io::Error::other)?;
        for candidate in candidates.proposals {
            let Some(mut operation) = candidate.recipe.steps.into_iter().next() else {
                continue;
            };
            if let Operation::Base64Decode { alphabet, padding } = &mut operation {
                if self.standard_symbols && self.url_symbols {
                    continue;
                }
                *alphabet = if self.url_symbols {
                    Base64Alphabet::UrlSafe
                } else {
                    Base64Alphabet::Standard
                };
                *padding = if self.length.is_multiple_of(4) {
                    Base64Padding::Required
                } else {
                    Base64Padding::Forbidden
                };
            }
            if !operations.contains(&operation) {
                operations.push(operation);
            }
        }
        Ok(operations)
    }

    pub(super) fn gzip_header_observation_limited(&self, operations: &[Operation]) -> bool {
        self.length > self.prefix_length
            && self.prefix.starts_with(&[0x1f, 0x8b])
            && !operations.contains(&Operation::GzipDecompress {})
    }
}

pub(in crate::refine) struct ObservingReader<R> {
    reader: R,
    observation: Option<Observation>,
}

impl<R> ObservingReader<R> {
    pub(in crate::refine) const fn new(reader: R, enabled: bool) -> Self {
        Self {
            reader,
            observation: if enabled {
                Some(Observation::new())
            } else {
                None
            },
        }
    }

    pub(in crate::refine) fn finish(self) -> Option<Observation> {
        self.observation
    }
}

impl<R: Read> Read for ObservingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.reader.read(buffer)?;
        if let Some(observation) = &mut self.observation {
            observation.accept(
                buffer
                    .get(..count)
                    .ok_or_else(|| io::Error::other("invalid observed read length"))?,
            )?;
        }
        Ok(count)
    }
}

pub(super) struct ObservingWriter<'a> {
    file: &'a mut File,
    job: &'a Job,
    observation: Observation,
}
impl<'a> ObservingWriter<'a> {
    pub(super) const fn new(file: &'a mut File, job: &'a Job) -> Self {
        Self {
            file,
            job,
            observation: Observation::new(),
        }
    }
    pub(super) const fn finish(self) -> Observation {
        self.observation
    }
}
impl Write for ObservingWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.job.check_cancelled().map_err(io::Error::other)?;
        let written = self.file.write(bytes)?;
        self.observation.accept(
            bytes
                .get(..written)
                .ok_or_else(|| io::Error::other("invalid spool write length"))?,
        )?;
        Ok(written)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}
