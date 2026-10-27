//! Hash source bytes once while observing bounded ZIP end-record candidates

use sha2::{Digest, Sha256};
use std::io;

const ZIP_END_HEADER_BYTES: usize = 22;
const ZIP_LOOKAHEAD_BYTES: usize = ZIP_END_HEADER_BYTES - 1;

/// Limits for syntactic ZIP end-record observation during a source pass
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ZipEndScanLimits {
    /// Maximum source bytes searched for ZIP end-record headers
    pub max_scan_bytes: usize,
    /// Maximum distinct candidate end boundaries retained
    pub max_candidates: usize,
}

/// One unvalidated possible ZIP end and the digest of its source prefix
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamZipEnd {
    /// Source offset immediately after the declared end record and comment
    pub end: usize,
    /// SHA-256 of the source bytes before that boundary
    pub sha256: String,
}

/// Bounded syntactic candidates, before the canonical ZIP parser checks them
pub struct ZipEndObservation {
    /// Candidate boundaries whose complete prefix digests were captured
    pub candidates: Vec<StreamZipEnd>,
    /// Source bytes considered by the marker scanner
    pub scanned_bytes: usize,
    /// Source offsets that could not be checked for a complete end header
    pub unscanned_bytes: usize,
    /// Candidate boundaries omitted after the candidate limit was reached
    pub omitted_candidates: usize,
}

struct Candidate {
    end: usize,
    sha256: Option<String>,
}

struct ZipScan {
    limits: ZipEndScanLimits,
    next_offset: usize,
    candidates: Vec<Candidate>,
    omitted: usize,
}

pub(super) struct SourceHasher {
    hasher: Sha256,
    source_length: usize,
    consumed: usize,
    committed: usize,
    pending: Vec<u8>,
    checkpoint: Option<usize>,
    prefix_sha256: Option<String>,
    zip: Option<ZipScan>,
}

pub(super) struct HashResult {
    pub(super) source_sha256: String,
    pub(super) prefix_sha256: Option<String>,
    pub(super) zip_observation: Option<ZipEndObservation>,
}

impl SourceHasher {
    pub(super) fn new(
        source_length: usize,
        checkpoint: Option<usize>,
        zip_limits: Option<ZipEndScanLimits>,
    ) -> io::Result<Self> {
        if checkpoint.is_some_and(|offset| offset > source_length) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "source hash checkpoint exceeds its length",
            ));
        }
        let prefix_sha256 = checkpoint
            .filter(|offset| *offset == 0)
            .map(|_| format!("{:x}", Sha256::new().finalize()));
        Ok(Self {
            hasher: Sha256::new(),
            source_length,
            consumed: 0,
            committed: 0,
            pending: Vec::new(),
            checkpoint,
            prefix_sha256,
            zip: zip_limits.map(|limits| ZipScan {
                limits,
                next_offset: 0,
                candidates: Vec::new(),
                omitted: 0,
            }),
        })
    }

    pub(super) fn accept(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.consumed += bytes.len();
        if self.zip.is_none() {
            return self.commit(bytes);
        }
        // Hold enough lookahead to recognize a complete end header before hashing its end
        let mut pending = std::mem::take(&mut self.pending);
        pending
            .try_reserve_exact(bytes.len())
            .map_err(io::Error::other)?;
        pending.extend_from_slice(bytes);
        self.observe(&pending)?;
        let count = pending.len().saturating_sub(ZIP_LOOKAHEAD_BYTES);
        let prefix = pending
            .get(..count)
            .ok_or_else(|| io::Error::other("source hash buffer is invalid"))?;
        self.commit(prefix)?;
        pending.copy_within(count.., 0);
        pending.truncate(pending.len() - count);
        self.pending = pending;
        Ok(())
    }

    pub(super) fn current_digest(&self) -> String {
        let mut current = self.hasher.clone();
        current.update(&self.pending);
        format!("{:x}", current.finalize())
    }

    fn observe(&mut self, bytes: &[u8]) -> io::Result<()> {
        let Some(zip) = &mut self.zip else {
            return Ok(());
        };
        let scanned = self.consumed.min(zip.limits.max_scan_bytes);
        let stop = scanned.saturating_sub(ZIP_LOOKAHEAD_BYTES);
        while zip.next_offset < stop {
            let start = zip.next_offset - self.committed;
            let end = stop - self.committed;
            let search = bytes
                .get(start..end)
                .ok_or_else(|| io::Error::other("ZIP scan range is invalid"))?;
            let Some(relative) = search.iter().position(|byte| *byte == b'P') else {
                zip.next_offset = stop;
                break;
            };
            let offset = zip.next_offset + relative;
            zip.next_offset = offset + 1;
            let index = offset - self.committed;
            if bytes.get(index..index + 4) != Some(b"PK\x05\x06") {
                continue;
            }
            let field = bytes
                .get(index + 20..index + 22)
                .ok_or_else(|| io::Error::other("ZIP end header is invalid"))?;
            let raw = <[u8; 2]>::try_from(field).map_err(io::Error::other)?;
            let end = offset
                .checked_add(ZIP_END_HEADER_BYTES)
                .and_then(|end| end.checked_add(usize::from(u16::from_le_bytes(raw))));
            let Some(end) = end.filter(|end| *end <= self.source_length) else {
                continue;
            };
            if zip.candidates.iter().any(|candidate| candidate.end == end) {
                continue;
            }
            if zip.candidates.len() >= zip.limits.max_candidates {
                zip.omitted = zip.omitted.saturating_add(1);
                continue;
            }
            zip.candidates.try_reserve(1).map_err(io::Error::other)?;
            zip.candidates.push(Candidate { end, sha256: None });
        }
        Ok(())
    }

    fn commit(&mut self, bytes: &[u8]) -> io::Result<()> {
        let end = self.committed + bytes.len();
        while let Some(boundary) = self.next_boundary(end) {
            let count = boundary - self.committed;
            let start = bytes.len() - (end - self.committed);
            let part = bytes
                .get(start..start + count)
                .ok_or_else(|| io::Error::other("source hash boundary is invalid"))?;
            self.hasher.update(part);
            self.committed = boundary;
            let digest = format!("{:x}", self.hasher.clone().finalize());
            if self.checkpoint == Some(boundary) {
                self.prefix_sha256 = Some(digest.clone());
                self.checkpoint = None;
            }
            if let Some(zip) = &mut self.zip {
                for candidate in &mut zip.candidates {
                    if candidate.end == boundary {
                        candidate.sha256 = Some(digest.clone());
                    }
                }
            }
        }
        let start = bytes.len() - (end - self.committed);
        self.hasher.update(
            bytes
                .get(start..)
                .ok_or_else(|| io::Error::other("source hash range is invalid"))?,
        );
        self.committed = end;
        Ok(())
    }

    fn next_boundary(&self, end: usize) -> Option<usize> {
        let checkpoint = self
            .checkpoint
            .filter(|offset| *offset > self.committed && *offset <= end);
        let zip = self.zip.as_ref().and_then(|zip| {
            zip.candidates
                .iter()
                .filter(|candidate| {
                    candidate.sha256.is_none()
                        && candidate.end > self.committed
                        && candidate.end <= end
                })
                .map(|candidate| candidate.end)
                .min()
        });
        match (checkpoint, zip) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (Some(value), None) | (None, Some(value)) => Some(value),
            (None, None) => None,
        }
    }

    pub(super) fn finish(mut self) -> io::Result<HashResult> {
        let pending = std::mem::take(&mut self.pending);
        self.commit(&pending)?;
        let zip_observation = if let Some(zip) = self.zip {
            let scanned_bytes = self.source_length.min(zip.limits.max_scan_bytes);
            let mut candidates = Vec::new();
            candidates
                .try_reserve_exact(zip.candidates.len())
                .map_err(io::Error::other)?;
            for candidate in zip.candidates {
                let sha256 = candidate
                    .sha256
                    .ok_or_else(|| io::Error::other("ZIP candidate digest is missing"))?;
                candidates.push(StreamZipEnd {
                    end: candidate.end,
                    sha256,
                });
            }
            let unscanned_bytes = if scanned_bytes < self.source_length {
                self.source_length - scanned_bytes + scanned_bytes.min(ZIP_LOOKAHEAD_BYTES)
            } else {
                0
            };
            Some(ZipEndObservation {
                candidates,
                scanned_bytes,
                unscanned_bytes,
                omitted_candidates: zip.omitted,
            })
        } else {
            None
        };
        Ok(HashResult {
            source_sha256: format!("{:x}", self.hasher.finalize()),
            prefix_sha256: self.prefix_sha256,
            zip_observation,
        })
    }
}
