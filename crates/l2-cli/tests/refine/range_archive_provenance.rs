use crate::arguments::{RecoveryOptions, RefineOptions};
use l2_workbench::job::{Job, MemoryBudget};
use std::{
    error::Error,
    fs,
    io::{Seek, SeekFrom, Write},
    path::Path,
};

#[test]
fn validated_zip_member_keeps_source_provenance_when_archive_cannot_be_published()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("source.zip");
    let output = directory.path().join("result");
    let png = super::structural_png()?;
    super::large_formats::write_archive_blocks(&input, 0x91, &png, 192)?;
    let length = fs::metadata(&input)?.len();
    let source_limit = crate::refine::read_budget::analysis_reservation(length)
        .ok_or("source read reservation overflows")?
        + 512 * 1024;
    let recovery = RecoveryOptions {
        no_cache: true,
        memory_limit: 8 * 1024 * 1024,
        source_read_limit: source_limit,
        ..RecoveryOptions::default()
    };
    assert_archive_was_extracted_without_output_room(&input, &recovery, &png)?;
    let archive_sha256 = l2_workbench::sha256(&fs::read(&input)?);
    let options = RefineOptions {
        input,
        output: Some(output.clone()),
        dry_run: false,
        salvage: false,
        recovery,
    };
    assert!(!super::run(&options, &mut Vec::new())?);
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("manifest.json"))?)?;
    let artifacts = manifest
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .ok_or("artifacts missing")?;
    assert!(
        !artifacts.iter().any(|artifact| {
            artifact
                .get("origins")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|origins| {
                    origins.iter().any(|origin| {
                        origin
                            .pointer("/origin/kind")
                            .and_then(serde_json::Value::as_str)
                            == Some("archive_member")
                    })
                })
        }),
        "member was published without its archive parent"
    );
    assert_eq!(
        manifest
            .pointer("/sources/0/sha256")
            .and_then(serde_json::Value::as_str),
        Some(archive_sha256.as_str())
    );
    assert_source_member(artifacts, &output, &png, length, &archive_sha256)?;
    let omissions = manifest
        .pointer("/sources/0/omissions")
        .and_then(serde_json::Value::as_array)
        .ok_or("source omissions missing")?;
    assert!(omissions.iter().any(|omission| {
        omission.get("kind").and_then(serde_json::Value::as_str)
            == Some("source_range_output_read_limit")
    }));
    assert!(!omissions.iter().any(|omission| {
        omission.get("kind").and_then(serde_json::Value::as_str)
            == Some("source_archive_members_omitted")
    }));
    assert!(omissions.iter().any(|omission| {
        omission.get("kind").and_then(serde_json::Value::as_str)
            == Some("source_archive_member_omission")
            && omission
                .get("entry_index")
                .and_then(serde_json::Value::as_u64)
                == Some(0)
    }));
    Ok(())
}

fn assert_source_member(
    artifacts: &[serde_json::Value],
    output: &Path,
    png: &[u8],
    length: u64,
    archive_sha256: &str,
) -> Result<(), Box<dyn Error>> {
    let png_sha256 = l2_workbench::sha256(png);
    let member = artifacts
        .iter()
        .find(|artifact| {
            artifact.get("sha256").and_then(serde_json::Value::as_str) == Some(png_sha256.as_str())
        })
        .ok_or("validated small member was omitted")?;
    let member_file = member
        .get("file")
        .and_then(serde_json::Value::as_str)
        .ok_or("member file missing")?;
    assert_eq!(fs::read(output.join(member_file))?, png);
    let origin = member
        .get("origins")
        .and_then(serde_json::Value::as_array)
        .and_then(|origins| {
            origins.iter().find(|origin| {
                origin
                    .pointer("/origin/kind")
                    .and_then(serde_json::Value::as_str)
                    == Some("source_archive_member")
            })
        })
        .ok_or("source-anchored member origin missing")?;
    assert_eq!(
        origin
            .get("source_index")
            .and_then(serde_json::Value::as_u64),
        Some(0)
    );
    assert_eq!(
        origin
            .pointer("/origin/archive_range/offset")
            .and_then(serde_json::Value::as_u64),
        Some(0)
    );
    assert_eq!(
        origin
            .pointer("/origin/archive_range/length")
            .and_then(serde_json::Value::as_u64),
        Some(length)
    );
    assert_eq!(
        origin
            .pointer("/origin/archive_sha256")
            .and_then(serde_json::Value::as_str),
        Some(archive_sha256)
    );
    assert_eq!(
        origin
            .pointer("/origin/entry_index")
            .and_then(serde_json::Value::as_u64),
        Some(1)
    );
    assert_eq!(
        origin
            .pointer("/origin/expanded_size")
            .and_then(serde_json::Value::as_u64),
        Some(u64::try_from(png.len())?)
    );
    assert_eq!(
        origin
            .pointer("/origin/crc32")
            .and_then(serde_json::Value::as_u64),
        Some(u64::from(crc32fast::hash(png)))
    );
    Ok(())
}

#[test]
fn source_member_identifies_archive_prefix_when_the_input_has_trailing_bytes()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("source.bin");
    let output = directory.path().join("result");
    let png = super::structural_png()?;
    super::large_formats::write_archive_blocks(&input, 0x91, &png, 192)?;
    let archive_length = fs::metadata(&input)?.len();
    let archive_sha256 = l2_workbench::sha256(&fs::read(&input)?);
    fs::OpenOptions::new()
        .append(true)
        .open(&input)?
        .write_all(b"trailing source bytes")?;
    let source_length = fs::metadata(&input)?.len();
    let source_sha256 = l2_workbench::sha256(&fs::read(&input)?);
    assert_ne!(archive_sha256, source_sha256);
    let source_limit = crate::refine::read_budget::analysis_reservation(source_length)
        .ok_or("source read reservation overflows")?
        + 512 * 1024;
    let options = RefineOptions {
        input,
        output: Some(output.clone()),
        dry_run: false,
        salvage: false,
        recovery: RecoveryOptions {
            no_cache: true,
            memory_limit: 8 * 1024 * 1024,
            source_read_limit: source_limit,
            ..RecoveryOptions::default()
        },
    };
    let job = Job::new("ZIP source prefix provenance");
    assert!(!super::run_with_job(&options, &mut Vec::new(), &job)?);
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("manifest.json"))?)?;
    assert_eq!(
        manifest
            .pointer("/sources/0/sha256")
            .and_then(serde_json::Value::as_str),
        Some(source_sha256.as_str())
    );
    let artifacts = manifest
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .ok_or("artifacts missing")?;
    assert_source_member(artifacts, &output, &png, archive_length, &archive_sha256)?;
    let reads = job
        .snapshot()?
        .counters
        .get(&l2_workbench::job::Counter::SourceReadBytes)
        .copied()
        .ok_or("read counter missing")?;
    assert!(reads <= source_limit);
    Ok(())
}

#[test]
fn corrupt_zip_member_is_omitted_and_later_valid_member_keeps_source_provenance()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("source.zip");
    let output = directory.path().join("result");
    let png = super::structural_png()?;
    write_archive_with_corrupt_member(&input, &png)?;
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
    let job = Job::new("ZIP member CRC validation");
    assert!(!super::run_with_job(&options, &mut Vec::new(), &job)?);
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("manifest.json"))?)?;
    let artifacts = manifest
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .ok_or("artifacts missing")?;
    let valid_sha256 = l2_workbench::sha256(&png);
    assert!(artifacts.iter().any(
        |item| item.get("sha256").and_then(serde_json::Value::as_str)
            == Some(valid_sha256.as_str())
    ));
    assert!(
        !artifacts.iter().any(|item| {
            item.get("origins")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|origins| {
                    origins.iter().any(|origin| {
                        origin
                            .pointer("/origin/entry_index")
                            .and_then(serde_json::Value::as_u64)
                            == Some(1)
                    })
                })
        }),
        "corrupt member was published"
    );
    assert!(
        manifest
            .pointer("/sources/0/omissions")
            .and_then(serde_json::Value::as_array)
            .ok_or("omissions missing")?
            .iter()
            .any(|omission| {
                omission.get("kind").and_then(serde_json::Value::as_str)
                    == Some("source_archive_member_omission")
                    && omission
                        .get("entry_index")
                        .and_then(serde_json::Value::as_u64)
                        == Some(1)
                    && omission
                        .pointer("/reason/entry_data_failure/failure")
                        .and_then(serde_json::Value::as_str)
                        == Some("crc_mismatch")
            })
    );
    let reads = job
        .snapshot()?
        .counters
        .get(&l2_workbench::job::Counter::SourceReadBytes)
        .copied()
        .ok_or("read counter missing")?;
    assert!(reads <= options.recovery.source_read_limit);
    Ok(())
}

fn write_archive_with_corrupt_member(path: &Path, png: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut writer = zip::ZipWriter::new(fs::File::create(path)?);
    let stored =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    writer.start_file("large.bin", stored)?;
    for _ in 0..320 {
        writer.write_all(&[0x91; 16 * 1024])?;
    }
    writer.start_file("corrupt.png", stored)?;
    writer.write_all(png)?;
    writer.start_file(
        "small.png",
        zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated),
    )?;
    writer.write_all(png)?;
    writer.finish()?.sync_all()?;
    let offset = {
        let mut archive = zip::ZipArchive::new(fs::File::open(path)?)?;
        let member = archive.by_index(1)?;
        member.data_start().ok_or("member data offset missing")?
    };
    let mut file = fs::OpenOptions::new().write(true).open(path)?;
    file.seek(SeekFrom::Start(offset + 8))?;
    file.write_all(&[0xff])?;
    file.sync_all()?;
    Ok(())
}

fn assert_archive_was_extracted_without_output_room(
    path: &Path,
    recovery: &RecoveryOptions,
    png: &[u8],
) -> Result<(), Box<dyn Error>> {
    use crate::refine::{
        input::{prepare_input_set_with_limit, read_sources},
        policy::RefinePolicy,
        range_transform::StreamingBudget,
    };

    let memory = MemoryBudget::new(recovery.memory_limit);
    let job = Job::new("ZIP parent output admission");
    let input = prepare_input_set_with_limit(path, recovery.source_read_limit, &job, &memory)?;
    let policy = RefinePolicy::new(recovery, false)?;
    let sources = read_sources(
        &input,
        policy.total_input_limit,
        policy.per_file_limit,
        &job,
        &memory,
    )?;
    let source = sources.first().ok_or("source missing")?;
    assert!(source.bytes().is_none(), "fixture is not file-backed");
    let mut streaming = StreamingBudget::new(&policy, &sources)?;
    let observation = streaming.reserve_observation(source.length())?;
    streaming.begin_source()?;
    let mut options = policy.analyzer;
    options.limits.max_total_work_bytes = streaming.range_work_limit(
        source.length(),
        options.limits.max_total_work_bytes,
        recovery.profile,
    );
    let range = source.analyze_ranges(&input, 0, options, &job, &memory, observation.is_some())?;
    assert!(!range.retain_source, "archive output unexpectedly fits");
    let archive = range.archive.as_ref().ok_or("archive was not inspected")?;
    assert!(
        archive
            .entries
            .iter()
            .any(|entry| entry.content.as_deref() == Some(png)),
        "the independent parser did not extract the PNG member"
    );
    Ok(())
}
