use std::{error::Error, fs};

use l2_workbench::{job::cache::SourceFingerprint, sha256};

#[test]
fn opened_file_identity_reads_from_start_and_matches_the_source_bytes() -> Result<(), Box<dyn Error>>
{
    use l2_workbench::job::cache::SourceIdentity;
    use std::io::{Seek, SeekFrom};

    let temporary = tempfile::tempdir()?;
    let source = temporary.path().join("source.bin");
    let bytes = vec![42_u8; 300_000];
    fs::write(&source, &bytes)?;
    let mut file = fs::File::open(&source)?;
    file.seek(SeekFrom::Start(99))?;

    let fingerprint = SourceFingerprint::fast_open_file(&mut file)?;
    assert_eq!(fingerprint, SourceFingerprint::fast(&source)?);
    file.seek(SeekFrom::Start(99))?;
    assert_eq!(
        SourceIdentity::sha256_open_file(&mut file)?,
        SourceIdentity::from_sha256(sha256(&bytes))?
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn opened_file_identity_rejects_non_regular_and_unreadable_handles() -> Result<(), Box<dyn Error>> {
    use l2_workbench::job::cache::SourceIdentity;
    use std::io::Write;

    let temporary = tempfile::tempdir()?;
    let mut directory = fs::File::open(temporary.path())?;
    assert!(SourceFingerprint::fast_open_file(&mut directory).is_err());
    assert!(SourceIdentity::sha256_open_file(&mut directory).is_err());
    let source = temporary.path().join("write-only.bin");
    let mut write_only = fs::File::create(source)?;
    write_only.write_all(b"x")?;
    assert!(SourceFingerprint::fast_open_file(&mut write_only).is_err());
    assert!(SourceIdentity::sha256_open_file(&mut write_only).is_err());
    Ok(())
}

#[test]
fn whole_file_fingerprints_cross_the_read_buffer_boundary_without_changing_digest_format()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let source = temporary.path().join("source.bin");
    for size in [0_usize, 65_535, 65_536, 65_537, 131_073, 196_607, 196_608] {
        let bytes = (0..size)
            .map(|index| u8::try_from(index % 251))
            .collect::<Result<Vec<_>, _>>()?;
        fs::write(&source, &bytes)?;
        let fingerprint = SourceFingerprint::fast(&source)?;

        // The range identity covers its offset and length before the sampled bytes
        let mut expected_input = 0_u64.to_be_bytes().to_vec();
        expected_input.extend_from_slice(&u64::try_from(size)?.to_be_bytes());
        expected_input.extend_from_slice(&bytes);
        assert_eq!(fingerprint.size_bytes, u64::try_from(size)?);
        assert_eq!(
            fingerprint.sample_sha256,
            sha256(&expected_input),
            "whole-file sample identity changed for {size} bytes"
        );
    }
    Ok(())
}

#[test]
fn larger_file_fingerprints_keep_the_existing_three_range_identity() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let source = temporary.path().join("source.bin");
    for (size, ranges) in [
        (
            196_609_usize,
            [(0, 65_536), (65_536, 131_072), (131_073, 196_609)],
        ),
        (
            262_144,
            [(0, 65_536), (98_304, 163_840), (196_608, 262_144)],
        ),
    ] {
        let bytes = (0..size)
            .map(|index| u8::try_from((index / 97 + index % 251) % 256))
            .collect::<Result<Vec<_>, _>>()?;
        fs::write(&source, &bytes)?;
        let fingerprint = SourceFingerprint::fast(&source)?;

        // Larger files use three 64 KiB samples at their start, midpoint, and end
        let mut expected_input = Vec::new();
        for (start, end) in ranges {
            expected_input.extend_from_slice(&u64::try_from(start)?.to_be_bytes());
            expected_input.extend_from_slice(&65_536_u64.to_be_bytes());
            expected_input
                .extend_from_slice(bytes.get(start..end).ok_or("invalid sample fixture")?);
        }
        assert_eq!(
            fingerprint.sample_sha256,
            sha256(&expected_input),
            "three-range sample identity changed for {size} bytes"
        );
        assert_eq!(fingerprint.size_bytes, u64::try_from(size)?);
    }
    Ok(())
}
