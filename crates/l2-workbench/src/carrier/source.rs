use super::model::CarrierError;
use crate::evidence::SourceRange;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
};

const SOURCE_BLOCK_BYTES: usize = 64 * 1024;
const SOURCE_BLOCK_BYTES_U64: u64 = 64 * 1024;
const BLOCK_DIGEST_BYTES: u64 = 32;

#[derive(Clone, Copy)]
struct BlockJob {
    block_index: u64,
    range_index: usize,
}

struct RangeBatch {
    outputs: Vec<Vec<u8>>,
    copied: Vec<usize>,
    jobs: Vec<BlockJob>,
}

/// Seekable source with a content hash and per-block verification index
///
/// The index stays in an unnamed temporary file; reads verify only touched blocks
pub struct SourceReader {
    id: String,
    length: u64,
    reader: Box<dyn ReadSeek>,
    block_hashes: File,
}

/// Object-safe read and seek capability for source files
trait ReadSeek: Read + Seek {}

impl<T: Read + Seek> ReadSeek for T {}

impl SourceReader {
    /// Identify a seekable source and retain the block index built by the same scan
    ///
    /// The caller can match the derived identity and length against an evidence case
    /// without first hashing the source through a separate reader pass
    ///
    /// # Errors
    /// Returns an error when the source cannot be measured, read, indexed, or rewound
    pub fn identify<R>(mut reader: R) -> Result<Self, CarrierError>
    where
        R: Read + Seek + 'static,
    {
        let length = reader
            .seek(SeekFrom::End(0))
            .map_err(|_| CarrierError::SourceIo)?;
        let (digest, block_hashes) = index_reader(length, &mut reader)?;
        Ok(Self {
            id: format!("sha256:{digest}"),
            length,
            reader: Box::new(reader),
            block_hashes,
        })
    }

    /// Verify a canonical source identity and retain its seekable reader
    ///
    /// The reader is scanned in fixed-size chunks and rewound after verification
    ///
    /// # Errors
    /// Returns an error for a malformed digest, mismatched size or content, or I/O failure
    pub fn verify<R>(
        id: impl Into<String>,
        length: u64,
        mut reader: R,
    ) -> Result<Self, CarrierError>
    where
        R: Read + Seek + 'static,
    {
        let id = id.into();
        Self::validate_identity(&id)?;
        // Bind the held reader and its requested ranges to one content-derived identity
        let (digest, block_hashes) = index_reader(length, &mut reader)?;
        if id != format!("sha256:{digest}") {
            return Err(CarrierError::SourceHashMismatch);
        }
        Ok(Self {
            id,
            length,
            reader: Box::new(reader),
            block_hashes,
        })
    }

    /// Return the verified content-derived source identity
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Return the verified source byte length
    #[must_use]
    pub const fn length(&self) -> u64 {
        self.length
    }

    /// Validate the canonical digest syntax before opening a source path
    ///
    /// # Errors
    /// Rejects identities without a lowercase SHA-256 digest
    pub fn validate_identity(id: &str) -> Result<(), CarrierError> {
        validate_source_id(id)
    }

    pub(super) fn read_ranges(
        &mut self,
        ranges: &[&SourceRange],
    ) -> Result<Vec<Vec<u8>>, CarrierError> {
        let mut batch = prepare_range_batch(ranges, &self.id, self.length)?;
        self.fill_range_batch(ranges, &mut batch)?;
        if batch
            .outputs
            .iter()
            .zip(batch.copied)
            .any(|(output, count)| output.len() != count)
        {
            return Err(CarrierError::SourceChanged);
        }
        self.verify_current_length()?;
        Ok(batch.outputs)
    }

    fn fill_range_batch(
        &mut self,
        ranges: &[&SourceRange],
        batch: &mut RangeBatch,
    ) -> Result<(), CarrierError> {
        batch.jobs.sort_unstable_by_key(|job| job.block_index);
        let mut job_index = 0_usize;
        while let Some(job) = batch.jobs.get(job_index).copied() {
            let block_start = job
                .block_index
                .checked_mul(SOURCE_BLOCK_BYTES_U64)
                .ok_or(CarrierError::InvalidSourceRange)?;
            let block = self.read_verified_block(job.block_index, block_start)?;
            while let Some(current) = batch
                .jobs
                .get(job_index)
                .copied()
                .filter(|current| current.block_index == job.block_index)
            {
                let range = ranges
                    .get(current.range_index)
                    .copied()
                    .ok_or(CarrierError::InvalidSourceRange)?;
                let range_end = source_range_end(range)?;
                let output = batch
                    .outputs
                    .get_mut(current.range_index)
                    .ok_or(CarrierError::InvalidSourceRange)?;
                let copied_bytes = copy_block_range(range, range_end, block_start, &block, output)?;
                let count = batch
                    .copied
                    .get_mut(current.range_index)
                    .ok_or(CarrierError::InvalidSourceRange)?;
                *count = count
                    .checked_add(copied_bytes)
                    .ok_or(CarrierError::RangeTooLarge)?;
                job_index += 1;
            }
        }
        Ok(())
    }

    fn verify_current_length(&mut self) -> Result<(), CarrierError> {
        let actual_length = self
            .reader
            .seek(SeekFrom::End(0))
            .map_err(|_| CarrierError::SourceIo)?;
        if actual_length == self.length {
            Ok(())
        } else {
            Err(CarrierError::SourceChanged)
        }
    }

    fn read_verified_block(
        &mut self,
        block_index: u64,
        block_start: u64,
    ) -> Result<Vec<u8>, CarrierError> {
        let remaining = self
            .length
            .checked_sub(block_start)
            .ok_or(CarrierError::InvalidSourceRange)?;
        let block_length = usize::try_from(remaining.min(SOURCE_BLOCK_BYTES_U64))
            .map_err(|_| CarrierError::RangeTooLarge)?;
        let mut block = vec![0; block_length];
        self.reader
            .seek(SeekFrom::Start(block_start))
            .map_err(|_| CarrierError::SourceIo)?;
        self.reader.read_exact(&mut block).map_err(|error| {
            if error.kind() == std::io::ErrorKind::UnexpectedEof {
                CarrierError::SourceChanged
            } else {
                CarrierError::SourceIo
            }
        })?;
        verify_block_hash(&mut self.block_hashes, block_index, &block)?;
        Ok(block)
    }
}

fn prepare_range_batch(
    ranges: &[&SourceRange],
    source_id: &str,
    source_length: u64,
) -> Result<RangeBatch, CarrierError> {
    let mut batch = RangeBatch {
        outputs: Vec::new(),
        copied: Vec::new(),
        jobs: Vec::new(),
    };
    batch
        .outputs
        .try_reserve_exact(ranges.len())
        .map_err(|_| CarrierError::RangeTooLarge)?;
    batch
        .copied
        .try_reserve_exact(ranges.len())
        .map_err(|_| CarrierError::RangeTooLarge)?;
    for (range_index, range) in ranges.iter().copied().enumerate() {
        validate_range(range, source_id, source_length)?;
        let length = usize::try_from(range.length).map_err(|_| CarrierError::RangeTooLarge)?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(length)
            .map_err(|_| CarrierError::RangeTooLarge)?;
        output.resize(length, 0);
        batch.outputs.push(output);
        batch.copied.push(0_usize);
        let end = source_range_end(range)?;
        let first_block = range.offset / SOURCE_BLOCK_BYTES_U64;
        let last_block =
            end.checked_sub(1).ok_or(CarrierError::InvalidSourceRange)? / SOURCE_BLOCK_BYTES_U64;
        let job_count = last_block
            .checked_sub(first_block)
            .and_then(|count| count.checked_add(1))
            .and_then(|count| usize::try_from(count).ok())
            .ok_or(CarrierError::RangeTooLarge)?;
        batch
            .jobs
            .try_reserve(job_count)
            .map_err(|_| CarrierError::RangeTooLarge)?;
        for block_index in first_block..=last_block {
            batch.jobs.push(BlockJob {
                block_index,
                range_index,
            });
        }
    }
    Ok(batch)
}

fn source_range_end(range: &SourceRange) -> Result<u64, CarrierError> {
    range
        .offset
        .checked_add(range.length)
        .ok_or(CarrierError::InvalidSourceRange)
}

fn validate_source_id(id: &str) -> Result<(), CarrierError> {
    let digest = id
        .strip_prefix("sha256:")
        .ok_or(CarrierError::InvalidSourceId)?;
    if !crate::hashing::is_sha256_digest(digest) {
        return Err(CarrierError::InvalidSourceId);
    }
    Ok(())
}

fn index_reader<R: Read + Seek>(
    expected_length: u64,
    reader: &mut R,
) -> Result<(String, File), CarrierError> {
    let actual_length = reader
        .seek(SeekFrom::End(0))
        .map_err(|_| CarrierError::SourceIo)?;
    if actual_length != expected_length {
        return Err(CarrierError::SourceLengthMismatch);
    }
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|_| CarrierError::SourceIo)?;
    let mut block_hashes = tempfile::tempfile().map_err(|_| CarrierError::SourceIo)?;
    let digest = hash_reader(reader, expected_length, &mut block_hashes)?;
    let verified_length = reader
        .seek(SeekFrom::End(0))
        .map_err(|_| CarrierError::SourceIo)?;
    if verified_length != expected_length {
        return Err(CarrierError::SourceChanged);
    }
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|_| CarrierError::SourceIo)?;
    block_hashes
        .seek(SeekFrom::Start(0))
        .map_err(|_| CarrierError::SourceIo)?;
    Ok((digest, block_hashes))
}

fn hash_reader<R: Read, W: Write>(
    reader: &mut R,
    length: u64,
    block_hashes: &mut W,
) -> Result<String, CarrierError> {
    let mut remaining = length;
    let mut chunk = vec![0_u8; SOURCE_BLOCK_BYTES].into_boxed_slice();
    let mut hash = Sha256::new();
    while remaining != 0 {
        // Keep source hashing and its block index bounded for very large captures
        let count = usize::try_from(remaining.min(SOURCE_BLOCK_BYTES_U64))
            .map_err(|_| CarrierError::RangeTooLarge)?;
        let part = chunk.get_mut(..count).ok_or(CarrierError::SourceIo)?;
        reader
            .read_exact(part)
            .map_err(|_| CarrierError::SourceIo)?;
        hash.update(&*part);
        let block_digest: [u8; 32] = Sha256::digest(&*part).into();
        block_hashes
            .write_all(&block_digest)
            .map_err(|_| CarrierError::SourceIo)?;
        remaining -= u64::try_from(count).map_err(|_| CarrierError::RangeTooLarge)?;
    }
    let digest = hash.finalize();
    Ok(format!("{digest:x}"))
}

fn verify_block_hash(
    block_hashes: &mut File,
    block_index: u64,
    block: &[u8],
) -> Result<(), CarrierError> {
    let digest_offset = block_index
        .checked_mul(BLOCK_DIGEST_BYTES)
        .ok_or(CarrierError::SourceIo)?;
    block_hashes
        .seek(SeekFrom::Start(digest_offset))
        .map_err(|_| CarrierError::SourceIo)?;
    let mut expected = [0; 32];
    block_hashes
        .read_exact(&mut expected)
        .map_err(|_| CarrierError::SourceIo)?;
    let actual: [u8; 32] = Sha256::digest(block).into();
    if actual == expected {
        Ok(())
    } else {
        Err(CarrierError::SourceChanged)
    }
}

fn copy_block_range(
    range: &SourceRange,
    range_end: u64,
    block_start: u64,
    block: &[u8],
    output: &mut [u8],
) -> Result<usize, CarrierError> {
    let block_end = block_start
        .checked_add(u64::try_from(block.len()).map_err(|_| CarrierError::RangeTooLarge)?)
        .ok_or(CarrierError::InvalidSourceRange)?;
    let copy_start = range.offset.max(block_start);
    let copy_end = range_end.min(block_end);
    if copy_start >= copy_end {
        return Ok(0);
    }
    let block_offset =
        usize::try_from(copy_start - block_start).map_err(|_| CarrierError::RangeTooLarge)?;
    let output_offset =
        usize::try_from(copy_start - range.offset).map_err(|_| CarrierError::RangeTooLarge)?;
    let copy_length =
        usize::try_from(copy_end - copy_start).map_err(|_| CarrierError::RangeTooLarge)?;
    let block_end = block_offset
        .checked_add(copy_length)
        .ok_or(CarrierError::RangeTooLarge)?;
    let output_end = output_offset
        .checked_add(copy_length)
        .ok_or(CarrierError::RangeTooLarge)?;
    let source_bytes = block
        .get(block_offset..block_end)
        .ok_or(CarrierError::SourceChanged)?;
    let output_bytes = output
        .get_mut(output_offset..output_end)
        .ok_or(CarrierError::SourceChanged)?;
    output_bytes.copy_from_slice(source_bytes);
    Ok(copy_length)
}

fn validate_range(
    range: &SourceRange,
    source: &str,
    source_length: u64,
) -> Result<(), CarrierError> {
    if range.source != source
        || range.length == 0
        || range.packet == Some(0)
        || range
            .offset
            .checked_add(range.length)
            .is_none_or(|end| end > source_length)
    {
        return Err(CarrierError::InvalidSourceRange);
    }
    Ok(())
}
