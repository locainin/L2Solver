use std::{error::Error, fs};

use l2_workbench::{job::cache::SourceFingerprint, sha256};

#[test]
fn expected_length_blocks_fingerprinting_and_hashing_before_any_content_read()
-> Result<(), Box<dyn Error>> {
    use l2_workbench::job::cache::SourceIdentity;
    use std::io::Seek;

    let directory = tempfile::tempdir()?;
    let source = directory.path().join("source.bin");
    fs::write(&source, vec![3_u8; 256 * 1024])?;
    let mut file = fs::File::open(source)?;
    assert!(SourceFingerprint::fast_open_file_with_expected_length(&mut file, 1).is_err());
    assert_eq!(file.stream_position()?, 0);
    let mut checks = 0;
    assert!(
        SourceIdentity::sha256_open_file_with_expected_length_and_check(&mut file, 1, || {
            checks += 1;
            Ok(())
        })
        .is_err()
    );
    assert_eq!(checks, 0);
    assert_eq!(file.stream_position()?, 0);
    Ok(())
}

#[test]
fn fingerprint_read_reservation_matches_whole_and_three_range_samples() {
    for (length, expected) in [
        (0, 0),
        (65_537, 65_537),
        (196_608, 196_608),
        (196_609, 196_608),
        (1_000_000, 196_608),
    ] {
        assert_eq!(
            SourceFingerprint::sample_read_bytes(length),
            expected,
            "source length {length}"
        );
    }
}

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

#[test]
fn opened_file_digest_stops_when_the_cancellation_check_fails() -> Result<(), Box<dyn Error>> {
    use l2_workbench::job::cache::SourceIdentity;
    use std::io;

    let temporary = tempfile::tempdir()?;
    let source = temporary.path().join("source.bin");
    fs::write(&source, vec![0_u8; 256 * 1024])?;
    let mut file = fs::File::open(source)?;
    let mut checks = 0;
    let error = SourceIdentity::sha256_open_file_with_check(&mut file, || {
        checks += 1;
        if checks == 3 {
            Err(io::Error::other("cancelled during hashing"))
        } else {
            Ok(())
        }
    })
    .err()
    .ok_or("cancelled hashing completed")?;
    assert!(error.to_string().contains("cancelled during hashing"));
    assert_eq!(checks, 3);
    Ok(())
}

#[test]
fn opened_file_digest_rejects_growth_after_the_opening_length() -> Result<(), Box<dyn Error>> {
    use l2_workbench::job::cache::SourceIdentity;
    use std::io::Write;

    let temporary = tempfile::tempdir()?;
    let source = temporary.path().join("source.bin");
    fs::write(&source, vec![0_u8; 128 * 1024])?;
    let mut file = fs::File::open(&source)?;
    let mut writer = fs::OpenOptions::new().append(true).open(&source)?;
    let growth = vec![1_u8; 64 * 1024];
    let mut checks = 0;
    let result = SourceIdentity::sha256_open_file_with_check(&mut file, || {
        checks += 1;
        if checks >= 2 {
            writer.write_all(&growth)?;
        }
        Ok(())
    });
    assert!(result.is_err(), "growing source was accepted");
    assert!(checks <= 4, "hashing did not stop at the opening length");
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
