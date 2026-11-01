use std::{
    error::Error,
    fs,
    io::{self, Write},
    path::Path,
};

use crate::arguments::{RecoveryOptions, RefineOptions};
use l2_workbench::job::{Counter, Job, cache::SourceIdentity};

pub(super) fn write_large_archive(path: &Path, fill: u8, png: &[u8]) -> Result<(), Box<dyn Error>> {
    write_archive_blocks(path, fill, png, 320)
}

pub(super) fn write_archive_blocks(
    path: &Path,
    fill: u8,
    png: &[u8],
    blocks: usize,
) -> Result<(), Box<dyn Error>> {
    let mut writer = zip::ZipWriter::new(fs::File::create(path)?);
    writer.start_file(
        "large.bin",
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
    )?;
    for _ in 0..blocks {
        writer.write_all(&[fill; 16 * 1024])?;
    }
    writer.start_file(
        "small.png",
        zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated),
    )?;
    writer.write_all(png)?;
    writer.finish()?.sync_all()?;
    Ok(())
}

pub(super) fn write_large_png(
    path: &Path,
    blocks: usize,
    valid_crc: bool,
) -> Result<u64, Box<dyn Error>> {
    let basic = super::structural_png()?;
    let mut file = fs::File::create(path)?;
    file.write_all(basic.get(..33).ok_or("PNG header missing")?)?;
    let payload_length = blocks.checked_mul(16 * 1024).ok_or("PNG size overflow")?;
    file.write_all(&u32::try_from(payload_length)?.to_be_bytes())?;
    file.write_all(b"rUST")?;
    let mut crc = crc32fast::Hasher::new();
    crc.update(b"rUST");
    for _ in 0..blocks {
        let bytes = [7_u8; 16 * 1024];
        crc.update(&bytes);
        file.write_all(&bytes)?;
    }
    let checksum = if valid_crc {
        crc.finalize()
    } else {
        crc.finalize() ^ 1
    };
    file.write_all(&checksum.to_be_bytes())?;
    file.write_all(basic.get(33..).ok_or("PNG IEND missing")?)?;
    let png_length = fs::metadata(path)?.len();
    file.write_all(b"trailing bytes are not part of the PNG")?;
    file.sync_all()?;
    Ok(png_length)
}

#[cfg(target_os = "linux")]
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the exact output and isolated read accounting form one scenario"
)]
fn large_png_is_published_to_iend_after_one_source_pass() -> Result<(), Box<dyn Error>> {
    const CHILD_MARKER: &str = "L2_TEST_LARGE_PNG_READS_CHILD";
    if std::env::var_os(CHILD_MARKER).is_none() {
        let output = std::process::Command::new(std::env::current_exe()?)
            .args(["refine::tests::large_formats::large_png_is_published_to_iend_after_one_source_pass", "--exact"])
            .env(CHILD_MARKER, "1")
            .output()?;
        assert!(
            output.status.success(),
            "child failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return Ok(());
    }
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("large.png");
    let output = directory.path().join("result");
    let png_length = write_large_png(&input, 70 * 64, true)?;
    let source_length = fs::metadata(&input)?.len();
    assert!(png_length > 64 * 1024 * 1024);
    let options = RefineOptions {
        input: input.clone(),
        output: Some(output.clone()),
        dry_run: false,
        salvage: false,
        recovery: RecoveryOptions {
            no_cache: true,
            memory_limit: 128 * 1024 * 1024,
            source_read_limit: 160 * 1024 * 1024,
            ..RecoveryOptions::default()
        },
    };
    let job = Job::new("large PNG read accounting");
    let before = super::range_analysis::process_read_bytes()?;
    assert!(!super::run_with_job(&options, &mut Vec::new(), &job)?);
    let observed = super::range_analysis::process_read_bytes()? - before;
    let reads = job
        .snapshot()?
        .counters
        .get(&Counter::SourceReadBytes)
        .copied()
        .ok_or("source read counter missing")?;
    assert!(reads >= source_length + png_length);
    assert!(
        reads <= source_length + png_length + 2 * 1024 * 1024,
        "unexpected source reread: {reads}"
    );
    assert!(reads <= options.recovery.source_read_limit);
    assert!(
        observed >= reads.saturating_sub(16) && observed <= reads + 128 * 1024,
        "accounted {reads}, observed {observed}"
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("manifest.json"))?)?;
    let artifacts = manifest
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .ok_or("artifacts missing")?;
    let png = artifacts
        .iter()
        .find(|item| {
            item.get("byte_length").and_then(serde_json::Value::as_u64) == Some(png_length)
        })
        .ok_or("large PNG missing")?;
    let name = png
        .get("file")
        .and_then(serde_json::Value::as_str)
        .ok_or("PNG filename missing")?;
    assert_eq!(
        Path::new(name)
            .extension()
            .and_then(std::ffi::OsStr::to_str),
        Some("png")
    );
    let artifact_hash = serde_json::to_value(SourceIdentity::sha256_file(output.join(name))?)?;
    assert_eq!(png.get("sha256"), artifact_hash.get("value"));
    assert_eq!(
        png.pointer("/origins/0/validation/boundary")
            .and_then(serde_json::Value::as_str),
        Some("png_iend")
    );
    assert_eq!(
        png.pointer("/nodes/0/validated_as")
            .and_then(serde_json::Value::as_str),
        Some("png_structure")
    );
    assert_eq!(
        manifest.pointer("/sources/0/sha256"),
        serde_json::to_value(SourceIdentity::sha256_file(input)?)?.get("value")
    );
    Ok(())
}

#[test]
fn large_png_with_bad_crc_is_not_published_as_validated() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("corrupt.png");
    let output = directory.path().join("result");
    let png_length = write_large_png(&input, 320, false)?;
    let options = RefineOptions {
        input,
        output: Some(output.clone()),
        dry_run: false,
        salvage: false,
        recovery: RecoveryOptions {
            no_cache: true,
            memory_limit: 16 * 1024 * 1024,
            ..RecoveryOptions::default()
        },
    };
    assert!(!super::run(&options, &mut Vec::new())?);
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("manifest.json"))?)?;
    let artifacts = manifest
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .ok_or("artifacts missing")?;
    assert!(!artifacts.iter().any(
        |item| item.get("byte_length").and_then(serde_json::Value::as_u64) == Some(png_length)
    ));
    Ok(())
}

#[test]
fn large_png_copy_over_read_limit_records_an_explicit_omission() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("large.png");
    let output = directory.path().join("result");
    let png_length = write_large_png(&input, 320, true)?;
    let options = RefineOptions {
        input,
        output: Some(output.clone()),
        dry_run: false,
        salvage: false,
        recovery: RecoveryOptions {
            no_cache: true,
            memory_limit: 16 * 1024 * 1024,
            source_read_limit: 7 * 1024 * 1024,
            ..RecoveryOptions::default()
        },
    };
    assert!(!super::run(&options, &mut Vec::new())?);
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("manifest.json"))?)?;
    let artifacts = manifest
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .ok_or("artifacts missing")?;
    assert!(!artifacts.iter().any(
        |item| item.get("byte_length").and_then(serde_json::Value::as_u64) == Some(png_length)
    ));
    assert!(
        manifest
            .pointer("/sources/0/omissions")
            .and_then(serde_json::Value::as_array)
            .ok_or("source omissions missing")?
            .iter()
            .any(|item| item.get("kind").and_then(serde_json::Value::as_str)
                == Some("source_range_output_read_limit"))
    );
    Ok(())
}

#[test]
fn archive_above_sixty_four_mib_keeps_its_exact_boundary_and_small_member()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("large.zip");
    let output = directory.path().join("result");
    let png = super::structural_png()?;
    write_archive_blocks(&input, 7, &png, 70 * 64)?;
    let length = fs::metadata(&input)?.len();
    assert!(length > 64 * 1024 * 1024);
    let options = RefineOptions {
        input: input.clone(),
        output: Some(output.clone()),
        dry_run: false,
        salvage: false,
        recovery: RecoveryOptions {
            no_cache: true,
            memory_limit: 8 * 1024 * 1024,
            source_read_limit: 160 * 1024 * 1024,
            ..RecoveryOptions::default()
        },
    };
    assert!(!super::run(&options, &mut Vec::new())?);
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("manifest.json"))?)?;
    let artifacts = manifest
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .ok_or("artifacts missing")?;
    let archive = artifacts
        .iter()
        .find(|item| item.get("byte_length").and_then(serde_json::Value::as_u64) == Some(length))
        .ok_or("large archive missing")?;
    let file = archive
        .get("file")
        .and_then(serde_json::Value::as_str)
        .ok_or("archive filename missing")?;
    assert_eq!(
        SourceIdentity::sha256_file(output.join(file))?,
        SourceIdentity::sha256_file(input)?
    );
    assert!(
        artifacts.iter().any(
            |item| item.get("sha256").and_then(serde_json::Value::as_str)
                == Some(l2_workbench::sha256(&png).as_str())
        ),
        "validated small member missing; source omissions: {:?}",
        manifest.pointer("/sources/0/omissions")
    );
    Ok(())
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the source range and member provenance are one end-to-end scenario"
)]
fn prefixed_archive_with_overlay_keeps_exact_zip_range_and_member_origin()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let archive_path = directory.path().join("archive.zip");
    let input = directory.path().join("prefixed-with-overlay.bin");
    let output = directory.path().join("result");
    let png = super::structural_png()?;
    write_archive_blocks(&archive_path, 3, &png, 70 * 64)?;
    let mut source = fs::File::create(&input)?;
    source.write_all(b"executable prefix")?;
    io::copy(&mut fs::File::open(archive_path)?, &mut source)?;
    source.sync_all()?;
    let archive_length = fs::metadata(&input)?.len();
    let archive_hash = serde_json::to_value(SourceIdentity::sha256_file(&input)?)?
        .get("value")
        .and_then(serde_json::Value::as_str)
        .ok_or("archive digest missing")?
        .to_owned();
    source.write_all(b"overlay after ZIP boundary")?;
    source.sync_all()?;
    let options = RefineOptions {
        input,
        output: Some(output.clone()),
        dry_run: false,
        salvage: false,
        recovery: RecoveryOptions {
            no_cache: true,
            memory_limit: 8 * 1024 * 1024,
            source_read_limit: 160 * 1024 * 1024,
            ..RecoveryOptions::default()
        },
    };
    assert!(!super::run(&options, &mut Vec::new())?);
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("manifest.json"))?)?;
    let artifacts = manifest
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .ok_or("artifacts missing")?;
    let archive = artifacts
        .iter()
        .find(|item| {
            item.get("sha256").and_then(serde_json::Value::as_str) == Some(archive_hash.as_str())
        })
        .ok_or("exact ZIP range missing")?;
    assert_eq!(
        archive
            .get("byte_length")
            .and_then(serde_json::Value::as_u64),
        Some(archive_length)
    );
    assert_eq!(
        archive
            .pointer("/origins/0/origin/range/length")
            .and_then(serde_json::Value::as_u64),
        Some(archive_length)
    );
    let name = archive
        .get("file")
        .and_then(serde_json::Value::as_str)
        .ok_or("archive filename missing")?;
    assert_eq!(
        serde_json::to_value(SourceIdentity::sha256_file(output.join(name))?)?
            .get("value")
            .and_then(serde_json::Value::as_str),
        Some(archive_hash.as_str())
    );
    assert_ne!(
        manifest
            .pointer("/sources/0/sha256")
            .and_then(serde_json::Value::as_str),
        Some(archive_hash.as_str())
    );
    let member = artifacts
        .iter()
        .find(|item| {
            item.get("sha256").and_then(serde_json::Value::as_str)
                == Some(l2_workbench::sha256(&png).as_str())
        })
        .ok_or("validated member missing")?;
    assert_eq!(
        member
            .pointer("/origins/0/origin/archive_range/length")
            .and_then(serde_json::Value::as_u64),
        Some(archive_length)
    );
    Ok(())
}

#[test]
fn multiple_plausible_zip_end_boundaries_are_reported_as_partial() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("ambiguous.zip");
    let output = directory.path().join("result");
    write_large_archive(&input, 4, &super::structural_png()?)?;
    let mut source = fs::OpenOptions::new().append(true).open(&input)?;
    source.write_all(b"PK\x05\x06")?;
    source.write_all(&[0_u8; 18])?;
    source.sync_all()?;
    let options = RefineOptions {
        input,
        output: Some(output.clone()),
        dry_run: false,
        salvage: false,
        recovery: RecoveryOptions {
            no_cache: true,
            memory_limit: 8 * 1024 * 1024,
            source_read_limit: 16 * 1024 * 1024,
            ..RecoveryOptions::default()
        },
    };
    assert!(!super::run(&options, &mut Vec::new())?);
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("manifest.json"))?)?;
    assert!(
        manifest
            .pointer("/sources/0/omissions")
            .and_then(serde_json::Value::as_array)
            .ok_or("omissions missing")?
            .iter()
            .any(|item| {
                item.get("kind").and_then(serde_json::Value::as_str)
                    == Some("source_range_validation_limit")
                    && item
                        .get("reason")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|reason| reason.contains("multiple ZIP end boundaries"))
            })
    );
    Ok(())
}

#[test]
fn zip_before_a_large_overlay_is_found_during_the_source_pass() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("archive-with-overlay.bin");
    let output = directory.path().join("result");
    write_archive_blocks(&input, 5, &super::structural_png()?, 70 * 64)?;
    let archive_length = fs::metadata(&input)?.len();
    let archive_digest = serde_json::to_value(SourceIdentity::sha256_file(&input)?)?
        .get("value")
        .and_then(serde_json::Value::as_str)
        .ok_or("archive digest missing")?
        .to_owned();
    let mut source = fs::OpenOptions::new().append(true).open(&input)?;
    for _ in 0..64 {
        source.write_all(&[0_u8; 16 * 1024])?;
    }
    source.sync_all()?;
    let source_length = fs::metadata(&input)?.len();
    let options = RefineOptions {
        input,
        output: Some(output.clone()),
        dry_run: false,
        salvage: false,
        recovery: RecoveryOptions {
            no_cache: true,
            memory_limit: 192 * 1024 * 1024,
            source_read_limit: 160 * 1024 * 1024,
            ..RecoveryOptions::default()
        },
    };
    let job = Job::new("large ZIP overlay");
    assert!(!super::run_with_job(&options, &mut Vec::new(), &job)?);
    let reads = job
        .snapshot()?
        .counters
        .get(&Counter::SourceReadBytes)
        .copied()
        .ok_or("read counter missing")?;
    assert!(
        reads >= source_length + archive_length
            && reads <= source_length + archive_length + 1024 * 1024
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("manifest.json"))?)?;
    let artifact = manifest
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .ok_or("artifacts missing")?
        .iter()
        .find(|item| {
            item.get("sha256").and_then(serde_json::Value::as_str) == Some(archive_digest.as_str())
        })
        .ok_or("ZIP before large overlay was missed")?;
    assert_eq!(
        artifact
            .get("byte_length")
            .and_then(serde_json::Value::as_u64),
        Some(archive_length)
    );
    Ok(())
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the end-to-end assertions share one source and result"
)]
fn file_backed_zip_publishes_exact_archive_and_validated_small_member() -> Result<(), Box<dyn Error>>
{
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("large.zip");
    let output = directory.path().join("result");
    let png = super::structural_png()?;
    write_large_archive(&input, 0, &png)?;
    let length = fs::metadata(&input)?.len();
    let source_hash = serde_json::to_value(SourceIdentity::sha256_file(&input)?)?
        .get("value")
        .and_then(serde_json::Value::as_str)
        .ok_or("source digest missing")?
        .to_owned();
    let options = RefineOptions {
        input: input.clone(),
        output: Some(output.clone()),
        dry_run: false,
        salvage: false,
        recovery: RecoveryOptions {
            no_cache: true,
            memory_limit: 8 * 1024 * 1024,
            source_read_limit: 16 * 1024 * 1024,
            ..RecoveryOptions::default()
        },
    };
    let job = Job::new("large archive refinement");
    assert!(!super::run_with_job(&options, &mut Vec::new(), &job)?);
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("manifest.json"))?)?;
    assert_eq!(
        manifest
            .pointer("/sources/0/sha256")
            .and_then(serde_json::Value::as_str),
        Some(source_hash.as_str())
    );
    let artifacts = manifest
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .ok_or("artifacts missing")?;
    let archive = artifacts
        .iter()
        .find(|item| {
            item.get("sha256").and_then(serde_json::Value::as_str) == Some(source_hash.as_str())
        })
        .ok_or("original ZIP missing")?;
    assert_eq!(
        archive
            .get("byte_length")
            .and_then(serde_json::Value::as_u64),
        Some(length)
    );
    let filename = archive
        .get("file")
        .and_then(serde_json::Value::as_str)
        .ok_or("archive filename missing")?;
    assert!(
        Path::new(filename)
            .extension()
            .is_some_and(|ext| ext == "zip")
    );
    assert_eq!(
        SourceIdentity::sha256_file(output.join(filename))?,
        SourceIdentity::sha256_file(&input)?
    );
    assert!(artifacts.iter().any(|item| {
        item.get("sha256").and_then(serde_json::Value::as_str)
            == Some(l2_workbench::sha256(&png).as_str())
            && item
                .get("file")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|name| Path::new(name).extension().is_some_and(|ext| ext == "png"))
    }));
    assert!(
        manifest
            .pointer("/sources/0/omissions")
            .and_then(serde_json::Value::as_array)
            .ok_or("source omissions missing")?
            .iter()
            .any(|item| item.get("kind").and_then(serde_json::Value::as_str) == Some("zip_member"))
    );
    let source_reads = job
        .snapshot()?
        .counters
        .get(&Counter::SourceReadBytes)
        .copied()
        .ok_or("read counter missing")?;
    assert!(source_reads >= length * 2 && source_reads <= options.recovery.source_read_limit);
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the isolated run and its read accounting form one scenario"
)]
fn multiple_file_backed_archives_count_metadata_and_publication_reads() -> Result<(), Box<dyn Error>>
{
    const CHILD_MARKER: &str = "L2_TEST_MULTIPLE_ARCHIVE_READS_CHILD";
    if std::env::var_os(CHILD_MARKER).is_none() {
        let output = std::process::Command::new(std::env::current_exe()?)
            .args(["refine::tests::large_formats::multiple_file_backed_archives_count_metadata_and_publication_reads", "--exact"])
            .env(CHILD_MARKER, "1")
            .output()?;
        assert!(
            output.status.success(),
            "child failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return Ok(());
    }
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("inputs");
    let output = directory.path().join("result");
    fs::create_dir(&input)?;
    let png = super::structural_png()?;
    let first = input.join("first.zip");
    let second = input.join("second.zip");
    write_large_archive(&first, 0, &png)?;
    write_large_archive(&second, 1, &png)?;
    let total_length = fs::metadata(&first)?.len() + fs::metadata(&second)?.len();
    fs::write(
        input.join("manifest.json"),
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "artifacts": [
                {"file": "first.zip", "byte_length": fs::metadata(&first)?.len()},
                {"file": "second.zip", "byte_length": fs::metadata(&second)?.len()}
            ]
        }))?,
    )?;
    let options = RefineOptions {
        input,
        output: Some(output.clone()),
        dry_run: false,
        salvage: false,
        recovery: RecoveryOptions {
            no_cache: true,
            memory_limit: 8 * 1024 * 1024,
            source_read_limit: 30 * 1024 * 1024,
            ..RecoveryOptions::default()
        },
    };
    let job = Job::new("multiple file-backed archive reads");
    let before = super::range_analysis::process_read_bytes()?;
    assert!(!super::run_with_job(&options, &mut Vec::new(), &job)?);
    let observed = super::range_analysis::process_read_bytes()? - before;
    let reads = job
        .snapshot()?
        .counters
        .get(&Counter::SourceReadBytes)
        .copied()
        .ok_or("read counter missing")?;
    assert!(
        reads > 2 * total_length,
        "metadata reads were not counted: {reads}"
    );
    assert!(reads <= options.recovery.source_read_limit);
    assert!(
        observed >= reads.saturating_sub(16),
        "accounted {reads}, observed {observed}"
    );
    assert!(
        observed <= reads + 128 * 1024,
        "accounted {reads}, observed {observed}"
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("manifest.json"))?)?;
    let artifacts = manifest
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .ok_or("artifacts missing")?;
    for path in [first, second] {
        let digest = serde_json::to_value(SourceIdentity::sha256_file(&path)?)?
            .get("value")
            .and_then(serde_json::Value::as_str)
            .ok_or("digest missing")?
            .to_owned();
        let artifact = artifacts
            .iter()
            .find(|item| {
                item.get("sha256").and_then(serde_json::Value::as_str) == Some(digest.as_str())
            })
            .ok_or("archive missing")?;
        let filename = artifact
            .get("file")
            .and_then(serde_json::Value::as_str)
            .ok_or("filename missing")?;
        assert_eq!(
            SourceIdentity::sha256_file(output.join(filename))?,
            SourceIdentity::sha256_file(path)?
        );
    }
    Ok(())
}

#[test]
fn archive_copy_over_read_limit_reports_omission_but_keeps_small_member()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("large.zip");
    let output = directory.path().join("result");
    let png = super::structural_png()?;
    write_large_archive(&input, 0, &png)?;
    let length = fs::metadata(&input)?.len();
    let options = RefineOptions {
        input,
        output: Some(output.clone()),
        dry_run: false,
        salvage: false,
        recovery: RecoveryOptions {
            no_cache: true,
            memory_limit: 8 * 1024 * 1024,
            source_read_limit: 7 * 1024 * 1024,
            ..RecoveryOptions::default()
        },
    };
    let job = Job::new("archive copy limit");
    assert!(!super::run_with_job(&options, &mut Vec::new(), &job)?);
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("manifest.json"))?)?;
    let artifacts = manifest
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .ok_or("artifacts missing")?;
    assert!(
        !artifacts.iter().any(
            |item| item.get("byte_length").and_then(serde_json::Value::as_u64) == Some(length)
        )
    );
    assert!(artifacts.iter().any(
        |item| item.get("sha256").and_then(serde_json::Value::as_str)
            == Some(l2_workbench::sha256(&png).as_str())
    ));
    assert!(
        manifest
            .pointer("/sources/0/omissions")
            .and_then(serde_json::Value::as_array)
            .ok_or("omissions missing")?
            .iter()
            .any(|item| item.get("kind").and_then(serde_json::Value::as_str)
                == Some("source_range_output_read_limit"))
    );
    let reads = job
        .snapshot()?
        .counters
        .get(&Counter::SourceReadBytes)
        .copied()
        .ok_or("read counter missing")?;
    assert!(reads <= options.recovery.source_read_limit);
    Ok(())
}
