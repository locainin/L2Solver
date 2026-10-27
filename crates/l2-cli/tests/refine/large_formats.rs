use std::{error::Error, fs, io::Write, path::Path};

use crate::arguments::{RecoveryOptions, RefineOptions};
use l2_workbench::job::{Counter, Job, cache::SourceIdentity};

fn write_large_archive(path: &Path, fill: u8, png: &[u8]) -> Result<(), Box<dyn Error>> {
    write_archive_blocks(path, fill, png, 320)
}

fn write_archive_blocks(
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
    assert!(artifacts.iter().any(
        |item| item.get("sha256").and_then(serde_json::Value::as_str)
            == Some(l2_workbench::sha256(&png).as_str())
    ));
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
