use std::{
    error::Error,
    fs::File,
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
};

use l2_workbench::artifact::zip::{
    ZipArtifactLimits, ZipArtifactOmissionReason, ZipReadError, ZipReaderBudget, ZipReaderLimits,
    inspect_zip_at_depth_with_operation_budget, inspect_zip_from_reader_with_source_sha256,
};
use sha2::{Digest, Sha256};

#[test]
fn file_backed_zip_uses_bounded_reads_and_expands_small_member() -> Result<(), Box<dyn Error>> {
    const BLOCK: usize = 16 * 1024;
    const LARGE_BYTES: usize = 70 * 1024 * 1024;
    let mut writer = zip::ZipWriter::new(tempfile::tempfile()?);
    writer.start_file(
        "large.bin",
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
    )?;
    let zeroes = [0_u8; BLOCK];
    for _ in 0..(LARGE_BYTES / BLOCK) {
        writer.write_all(&zeroes)?;
    }
    writer.start_file(
        "small.txt",
        zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated),
    )?;
    writer.write_all(b"small exact member")?;
    let mut file = writer.finish()?;
    let length = usize::try_from(file.metadata()?.len())?;
    let digest = file_digest(&mut file)?;
    let mut reader = CountingFile {
        file,
        bytes: 0,
        largest: 0,
    };
    let mut budget = reader_budget(2 * 1024 * 1024, 1024);
    let limits = ZipArtifactLimits {
        max_archive_bytes: length,
        max_entry_expanded_bytes: 1024,
        max_total_expanded_bytes: 1024,
        ..ZipArtifactLimits::default()
    };
    let report = inspect_zip_from_reader_with_source_sha256(
        &mut reader,
        length,
        &digest,
        ZipReaderLimits {
            archive: limits,
            ..ZipReaderLimits::default()
        },
        0,
        &mut budget,
    )?;
    assert_eq!(report.archive_sha256, digest);
    assert_eq!(report.archive_size, length);
    assert_eq!(report.entry_count, 2);
    assert_eq!(
        report.entries.first().and_then(|entry| entry.omission),
        Some(ZipArtifactOmissionReason::EntryExpandedByteLimit)
    );
    assert_eq!(
        report
            .entries
            .get(1)
            .and_then(|entry| entry.content.as_deref()),
        Some(b"small exact member".as_slice())
    );
    assert_eq!(
        budget.expanded_bytes_remaining,
        1024 - b"small exact member".len()
    );
    assert_eq!(2 * 1024 * 1024 - budget.read_bytes_remaining, reader.bytes);
    assert!(
        reader.bytes < 2 * 1024 * 1024,
        "read {} bytes while checking metadata",
        reader.bytes
    );
    assert!(
        reader.largest <= 128 * 1024,
        "requested {} bytes in one read",
        reader.largest
    );
    Ok(())
}

#[test]
fn seekable_zip_reports_reader_and_metadata_limits_before_expansion() -> Result<(), Box<dyn Error>>
{
    let bytes = super::zip_support::build_zip(&[super::zip_support::FixtureEntry::stored(
        b"one", b"payload",
    )])?;
    let digest = l2_workbench::sha256(&bytes);
    let mut budget = reader_budget(8, 4096);
    let limits = ZipReaderLimits::default();
    assert!(matches!(
        inspect_zip_from_reader_with_source_sha256(
            &mut Cursor::new(&bytes),
            bytes.len(),
            &digest,
            limits,
            0,
            &mut budget
        ),
        Err(ZipReadError::WorkLimit { .. })
    ));
    assert_eq!(budget.expanded_bytes_remaining, 4096);
    budget.read_bytes_remaining = 4096;
    let limits = ZipReaderLimits {
        max_directory_bytes: 1,
        ..ZipReaderLimits::default()
    };
    assert!(matches!(
        inspect_zip_from_reader_with_source_sha256(
            &mut Cursor::new(&bytes),
            bytes.len(),
            &digest,
            limits,
            0,
            &mut budget
        ),
        Err(ZipReadError::DirectoryLimit { .. })
    ));
    assert_eq!(budget.expanded_bytes_remaining, 4096);
    Ok(())
}

#[test]
fn zip64_end_metadata_counts_toward_the_metadata_limit() -> Result<(), Box<dyn Error>> {
    let mut bytes = super::zip_support::build_zip(&[])?;
    super::zip_support::add_optional_zip64_footer(&mut bytes)?;
    let digest = l2_workbench::sha256(&bytes);
    let limits = ZipReaderLimits {
        max_directory_bytes: 32,
        ..ZipReaderLimits::default()
    };
    let mut budget = reader_budget(4096, 4096);
    assert!(matches!(
        inspect_zip_from_reader_with_source_sha256(
            &mut Cursor::new(&bytes),
            bytes.len(),
            &digest,
            limits,
            0,
            &mut budget
        ),
        Err(ZipReadError::DirectoryLimit { .. })
    ));
    Ok(())
}

#[test]
fn seekable_zip_reports_underlying_read_failure() {
    struct FailedReader;
    impl Read for FailedReader {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "read failed",
            ))
        }
    }
    impl Seek for FailedReader {
        fn seek(&mut self, _: SeekFrom) -> io::Result<u64> {
            Ok(0)
        }
    }
    let mut budget = reader_budget(1024, 1024);
    assert!(
        matches!(inspect_zip_from_reader_with_source_sha256(&mut FailedReader, 64, &l2_workbench::sha256(b"data"), ZipReaderLimits::default(), 0, &mut budget), Err(ZipReadError::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied)
    );
}

#[test]
fn file_backed_and_slice_zip_share_end_directory_and_member_decisions() -> Result<(), Box<dyn Error>>
{
    let bytes = super::zip_support::build_zip(&[super::zip_support::FixtureEntry::stored(
        b"one", b"payload",
    )])?;
    let digest = l2_workbench::sha256(&bytes);
    let mut slice_budget = 4096;
    let mut stream_budget = reader_budget(4096, 4096);
    let limits = ZipArtifactLimits::default();
    let expected =
        inspect_zip_at_depth_with_operation_budget(&bytes, limits, 0, &mut slice_budget)?;
    let actual = inspect_zip_from_reader_with_source_sha256(
        &mut Cursor::new(&bytes),
        bytes.len(),
        &digest,
        ZipReaderLimits {
            archive: limits,
            ..ZipReaderLimits::default()
        },
        0,
        &mut stream_budget,
    )?;
    assert_eq!(actual, expected);
    assert_eq!(stream_budget.expanded_bytes_remaining, slice_budget);
    let remaining_after_first = stream_budget.read_bytes_remaining;
    inspect_zip_from_reader_with_source_sha256(
        &mut Cursor::new(&bytes),
        bytes.len(),
        &digest,
        ZipReaderLimits {
            archive: limits,
            ..ZipReaderLimits::default()
        },
        0,
        &mut stream_budget,
    )?;
    assert!(stream_budget.read_bytes_remaining < remaining_after_first);
    for end in [0, 4, bytes.len() - 1] {
        let truncated = bytes.get(..end).ok_or("invalid truncated fixture")?;
        let mut budget = reader_budget(4096, 4096);
        assert!(
            inspect_zip_from_reader_with_source_sha256(
                &mut Cursor::new(truncated),
                truncated.len(),
                &l2_workbench::sha256(truncated),
                ZipReaderLimits {
                    archive: limits,
                    ..ZipReaderLimits::default()
                },
                0,
                &mut budget
            )
            .is_err()
        );
    }
    Ok(())
}

const fn reader_budget(read_bytes: usize, expanded_bytes: usize) -> ZipReaderBudget {
    ZipReaderBudget {
        read_bytes_remaining: read_bytes,
        expanded_bytes_remaining: expanded_bytes,
    }
}

struct CountingFile {
    file: File,
    bytes: usize,
    largest: usize,
}
impl Read for CountingFile {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.largest = self.largest.max(bytes.len());
        let count = self.file.read(bytes)?;
        self.bytes += count;
        Ok(count)
    }
}
impl Seek for CountingFile {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.file.seek(position)
    }
}

fn file_digest(file: &mut File) -> Result<String, Box<dyn Error>> {
    file.seek(SeekFrom::Start(0))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(buffer.get(..count).ok_or("digest buffer length invalid")?);
    }
    Ok(format!("{:x}", digest.finalize()))
}
