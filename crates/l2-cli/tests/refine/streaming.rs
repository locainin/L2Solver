use base64::{engine::general_purpose::STANDARD, write::EncoderWriter};
use flate2::{Compression, write::GzEncoder};
use l2_workbench::job::{Job, cache::SourceIdentity};
use std::{
    error::Error,
    fs::{self, File},
    io::{self, Write},
    path::Path,
};

use crate::arguments::{RecoveryOptions, RefineOptions};

fn write_encoded_archive(
    directory: &Path,
    corrupt_tail: bool,
) -> Result<(Vec<u8>, String), Box<dyn Error>> {
    let png = super::structural_png()?;
    let archive = directory.join("independent.zip");
    super::large_formats::write_archive_blocks(&archive, 0xa7, &png, 17 * 64)?;
    let original_hash = serde_json::to_value(SourceIdentity::sha256_file(&archive)?)?
        .get("value")
        .and_then(serde_json::Value::as_str)
        .ok_or("archive digest missing")?
        .to_owned();
    let base64 = EncoderWriter::new(File::create(directory.join("encoded.txt"))?, &STANDARD);
    let mut gzip = GzEncoder::new(base64, Compression::none());
    io::copy(&mut File::open(archive)?, &mut gzip)?;
    let mut encoded = gzip.finish()?.finish()?;
    if corrupt_tail {
        encoded.write_all(b"!")?;
    }
    encoded.sync_all()?;
    Ok((png, original_hash))
}

fn options(input: &Path, output: &Path) -> RefineOptions {
    RefineOptions {
        input: input.to_owned(),
        output: Some(output.to_owned()),
        dry_run: false,
        salvage: false,
        recovery: RecoveryOptions {
            no_cache: true,
            memory_limit: 64 * 1024 * 1024,
            source_read_limit: 256 * 1024 * 1024,
            ..RecoveryOptions::default()
        },
    }
}

fn has_png_extension(name: &str) -> bool {
    Path::new(name)
        .extension()
        .is_some_and(|extension| extension == "png")
}

#[cfg(target_os = "linux")]
fn assert_stream_job_stats(
    input: &Path,
    settings: &RefineOptions,
    job: &Job,
    reads_before: u64,
) -> Result<(), Box<dyn Error>> {
    use l2_workbench::job::Counter;

    let observed = super::range_analysis::process_read_bytes()? - reads_before;
    let snapshot = job.snapshot()?;
    let source_reads = snapshot
        .counters
        .get(&Counter::SourceReadBytes)
        .copied()
        .ok_or("source read counter missing")?;
    assert!(
        snapshot
            .counters
            .get(&Counter::Transforms)
            .copied()
            .unwrap_or(0)
            >= 4
    );
    assert!(
        snapshot
            .counters
            .get(&Counter::ValidatedArtifacts)
            .copied()
            .unwrap_or(0)
            >= 2
    );
    let source_length = fs::metadata(input)?.len();
    assert!(source_reads <= settings.recovery.source_read_limit);
    assert!(observed >= source_reads.saturating_sub(16));
    eprintln!(
        "stream fixture: source_bytes={source_length} source_read_bytes={source_reads} process_read_bytes={observed}"
    );
    Ok(())
}

#[test]
fn refine_streams_large_base64_gzip_zip_and_validates_its_member() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let (png, zip_hash) = write_encoded_archive(directory.path(), false)?;
    let input = directory.path().join("encoded.txt");
    let output = directory.path().join("result");
    let source_hash = SourceIdentity::sha256_file(&input)?;
    assert!(fs::metadata(&input)?.len() > 16 * 1024 * 1024);
    let job = Job::new("streamed encoded archive");
    let settings = options(&input, &output);
    #[cfg(target_os = "linux")]
    let reads_before = super::range_analysis::process_read_bytes()?;
    assert!(!super::run_with_job(&settings, &mut Vec::new(), &job)?);
    #[cfg(target_os = "linux")]
    assert_stream_job_stats(&input, &settings, &job, reads_before)?;
    assert_eq!(SourceIdentity::sha256_file(&input)?, source_hash);
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("manifest.json"))?)?;
    let artifacts = manifest
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .ok_or("artifacts missing")?;
    let zip = artifacts
        .iter()
        .find(|item| item.get("sha256").and_then(serde_json::Value::as_str) == Some(&zip_hash))
        .ok_or("derived archive missing")?;
    let steps = zip
        .pointer("/origins/0/origin/steps")
        .and_then(serde_json::Value::as_array)
        .ok_or("derivation receipt missing")?;
    assert_eq!(steps.len(), 2);
    assert_eq!(
        steps
            .first()
            .and_then(|step| step.pointer("/operation/kind"))
            .and_then(serde_json::Value::as_str),
        Some("base64_decode")
    );
    assert_eq!(
        steps
            .get(1)
            .and_then(|step| step.pointer("/operation/kind"))
            .and_then(serde_json::Value::as_str),
        Some("gzip_decompress")
    );
    let zip_name = zip
        .get("file")
        .and_then(serde_json::Value::as_str)
        .ok_or("archive output name missing")?;
    assert_eq!(
        serde_json::to_value(SourceIdentity::sha256_file(output.join(zip_name))?)?.get("value"),
        Some(&serde_json::Value::String(zip_hash))
    );
    assert!(artifacts.iter().any(|item| {
        item.get("file")
            .and_then(serde_json::Value::as_str)
            .filter(|name| has_png_extension(name))
            .and_then(|name| fs::read(output.join(name)).ok())
            .is_some_and(|bytes| bytes == png)
    }));
    Ok(())
}

#[test]
fn refine_streams_large_encoded_png_and_publishes_exact_iend_prefix() -> Result<(), Box<dyn Error>>
{
    use std::io::Read;

    let directory = tempfile::tempdir()?;
    let png_path = directory.path().join("independent.png");
    let png_length = super::large_formats::write_large_png(&png_path, 17 * 64, true)?;
    let expected = directory.path().join("expected.png");
    io::copy(
        &mut File::open(&png_path)?.take(png_length),
        &mut File::create(&expected)?,
    )?;
    let expected_hash = serde_json::to_value(SourceIdentity::sha256_file(&expected)?)?;
    let full_hash = serde_json::to_value(SourceIdentity::sha256_file(&png_path)?)?;
    assert_ne!(expected_hash.get("value"), full_hash.get("value"));
    let input = directory.path().join("encoded.txt");
    let encoded = EncoderWriter::new(File::create(&input)?, &STANDARD);
    let mut gzip = GzEncoder::new(encoded, Compression::none());
    io::copy(&mut File::open(&png_path)?, &mut gzip)?;
    gzip.finish()?.finish()?.sync_all()?;
    assert!(fs::metadata(&input)?.len() > 16 * 1024 * 1024);
    let original = SourceIdentity::sha256_file(&input)?;
    let output = directory.path().join("result");
    assert!(!super::run(&options(&input, &output), &mut Vec::new())?);
    assert_eq!(SourceIdentity::sha256_file(&input)?, original);
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("manifest.json"))?)?;
    let artifact = manifest
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .and_then(|items| {
            items.iter().find(|item| {
                item.get("byte_length").and_then(serde_json::Value::as_u64) == Some(png_length)
                    && item.pointer("/origins/0/validation/boundary")
                        == Some(&serde_json::json!("png_iend"))
            })
        })
        .ok_or("derived PNG boundary missing")?;
    let name = artifact
        .get("file")
        .and_then(serde_json::Value::as_str)
        .ok_or("PNG output name missing")?;
    assert_eq!(artifact.get("sha256"), expected_hash.get("value"));
    assert_eq!(
        serde_json::to_value(SourceIdentity::sha256_file(output.join(name))?)?.get("value"),
        expected_hash.get("value")
    );
    assert_eq!(
        artifact.pointer("/origins/0/origin/output_range/length"),
        Some(&serde_json::json!(png_length))
    );
    assert_eq!(
        artifact.pointer("/origins/0/origin/steps/1/output_sha256"),
        full_hash.get("value")
    );
    Ok(())
}

#[test]
fn refine_carves_interior_png_and_zip_from_a_large_decoded_stream() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let png = super::structural_png()?;
    let zip = super::structural_zip()?;
    let decoded = directory.path().join("decoded.bin");
    let (png_offset, second_png_offset, zip_offset) = write_interior_objects(&decoded, &png, &zip)?;
    let decoded_hash = serde_json::to_value(SourceIdentity::sha256_file(&decoded)?)?;
    let input = directory.path().join("encoded.txt");
    let encoded = EncoderWriter::new(File::create(&input)?, &STANDARD);
    let mut gzip = GzEncoder::new(encoded, Compression::none());
    io::copy(&mut File::open(&decoded)?, &mut gzip)?;
    gzip.finish()?.finish()?.sync_all()?;
    assert!(fs::metadata(&input)?.len() > 16 * 1024 * 1024);
    let source_hash = SourceIdentity::sha256_file(&input)?;
    let output = directory.path().join("result");
    assert!(!super::run(&options(&input, &output), &mut Vec::new())?);
    assert_eq!(SourceIdentity::sha256_file(&input)?, source_hash);
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("manifest.json"))?)?;
    let artifacts = manifest
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .ok_or("artifacts missing")?;
    assert_interior_objects(
        artifacts,
        &output,
        &decoded_hash,
        [
            (png.as_slice(), png_offset, "png"),
            (zip.as_slice(), zip_offset, "zip"),
        ],
        second_png_offset,
    )?;
    assert!(artifacts.iter().any(|item| {
        item.get("sha256").and_then(serde_json::Value::as_str)
            == Some(l2_workbench::sha256(b"member payload").as_str())
    }));
    let omissions = manifest
        .pointer("/sources/0/omissions")
        .and_then(serde_json::Value::as_array)
        .ok_or("source omissions missing")?;
    assert!(omissions.iter().any(|omission| {
        omission.get("kind") == Some(&serde_json::json!("derived_stream_range_coverage"))
            && omission.get("output_sha256") == decoded_hash.get("value")
            && omission
                .get("uncovered_range")
                .is_none_or(serde_json::Value::is_null)
            && omission
                .get("max_object_bytes")
                .and_then(serde_json::Value::as_u64)
                .is_some_and(|size| size <= 4 * 1024 * 1024)
    }));
    assert!(
        manifest
            .pointer("/sources/0/work_bytes_charged")
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|work| work > 0)
    );
    assert!(
        manifest
            .pointer("/sources/0/zip_expanded_work_bytes_charged")
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|work| work >= 14)
    );
    Ok(())
}

fn assert_interior_objects(
    artifacts: &[serde_json::Value],
    output: &Path,
    decoded_hash: &serde_json::Value,
    objects: [(&[u8], u64, &str); 2],
    second_png_offset: u64,
) -> Result<(), Box<dyn Error>> {
    for (bytes, offset, format) in objects {
        let artifact = artifacts
            .iter()
            .find(|item| {
                item.pointer("/origins/0/origin/output_range/offset")
                    == Some(&serde_json::json!(offset))
                    && item.pointer("/origins/0/origin/steps/1/output_sha256")
                        == decoded_hash.get("value")
                    && item.pointer("/origins/0/validation/format")
                        == Some(&serde_json::json!(format))
            })
            .ok_or("derived interior object missing")?;
        assert_eq!(
            artifact.get("sha256"),
            Some(&serde_json::json!(l2_workbench::sha256(bytes)))
        );
        let name = artifact
            .get("file")
            .and_then(serde_json::Value::as_str)
            .ok_or("object filename missing")?;
        assert_eq!(fs::read(output.join(name))?, bytes);
        if format == "png" {
            let origins = artifact
                .get("origins")
                .and_then(serde_json::Value::as_array)
                .ok_or("PNG origins missing")?;
            assert_eq!(origins.len(), 2);
            assert!(origins.iter().any(|origin| {
                origin.pointer("/origin/output_range/offset")
                    == Some(&serde_json::json!(second_png_offset))
            }));
        }
    }
    Ok(())
}

fn write_interior_objects(
    path: &Path,
    png: &[u8],
    zip: &[u8],
) -> Result<(u64, u64, u64), Box<dyn Error>> {
    let mut payload = File::create(path)?;
    payload.write_all(&[0x91; 128])?;
    for _ in 0..17 * 64 {
        payload.write_all(&[0x91; 16 * 1024])?;
    }
    let png_offset = fs::metadata(path)?.len();
    payload.write_all(png)?;
    payload.write_all(&[0x91; 64])?;
    let second_png_offset = png_offset + u64::try_from(png.len())? + 64;
    payload.write_all(png)?;
    payload.write_all(&[0x91; 64])?;
    let zip_offset = second_png_offset + u64::try_from(png.len())? + 64;
    payload.write_all(zip)?;
    payload.write_all(&[0x91; 32])?;
    payload.sync_all()?;
    Ok((png_offset, second_png_offset, zip_offset))
}

#[test]
fn refine_does_not_publish_a_derived_png_with_a_bad_crc() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let png = directory.path().join("corrupt.png");
    super::large_formats::write_large_png(&png, 150, false)?;
    let input = directory.path().join("encoded.txt");
    let encoded = EncoderWriter::new(File::create(&input)?, &STANDARD);
    let mut gzip = GzEncoder::new(encoded, Compression::none());
    io::copy(&mut File::open(&png)?, &mut gzip)?;
    gzip.finish()?.finish()?.sync_all()?;
    let output = directory.path().join("result");
    let mut settings = options(&input, &output);
    settings.recovery.memory_limit = 8 * 1024 * 1024;
    assert!(!super::run(&settings, &mut Vec::new())?);
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("manifest.json"))?)?;
    let artifacts = manifest
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .ok_or("artifacts missing")?;
    assert!(!artifacts.iter().any(|item| {
        item.pointer("/origins/0/validation/boundary") == Some(&serde_json::json!("png_iend"))
    }));
    let omissions = manifest
        .pointer("/sources/0/omissions")
        .and_then(serde_json::Value::as_array)
        .ok_or("source omissions missing")?;
    assert!(omissions.iter().any(|omission| {
        omission
            .get("reason")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|reason| reason.contains("derived PNG validation failed"))
    }));
    assert!(omissions.iter().any(|omission| {
        omission
            .get("reason")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|reason| reason.contains("retained validated format"))
    }));
    Ok(())
}

#[test]
fn refine_carves_an_interior_png_from_a_valid_derived_png() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let nested = super::structural_png()?;
    let outer = directory.path().join("outer.png");
    let mut file = File::create(&outer)?;
    file.write_all(nested.get(..33).ok_or("PNG header missing")?)?;
    let payload_length = nested.len() + 150 * 16 * 1024;
    file.write_all(&u32::try_from(payload_length)?.to_be_bytes())?;
    file.write_all(b"rUST")?;
    let mut crc = crc32fast::Hasher::new();
    crc.update(b"rUST");
    file.write_all(&nested)?;
    crc.update(&nested);
    for _ in 0..150 {
        let block = [7_u8; 16 * 1024];
        file.write_all(&block)?;
        crc.update(&block);
    }
    file.write_all(&crc.finalize().to_be_bytes())?;
    file.write_all(nested.get(33..).ok_or("PNG IEND missing")?)?;
    file.sync_all()?;
    let outer_hash = serde_json::to_value(SourceIdentity::sha256_file(&outer)?)?;
    let input = directory.path().join("encoded.txt");
    let encoded = EncoderWriter::new(File::create(&input)?, &STANDARD);
    let mut gzip = GzEncoder::new(encoded, Compression::none());
    io::copy(&mut File::open(&outer)?, &mut gzip)?;
    gzip.finish()?.finish()?.sync_all()?;
    let output = directory.path().join("result");
    let mut settings = options(&input, &output);
    settings.recovery.memory_limit = 8 * 1024 * 1024;
    assert!(!super::run(&settings, &mut Vec::new())?);
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("manifest.json"))?)?;
    let artifacts = manifest
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .ok_or("artifacts missing")?;
    assert!(
        artifacts
            .iter()
            .any(|item| item.get("sha256") == outer_hash.get("value"))
    );
    let inner = artifacts
        .iter()
        .find(|item| {
            item.get("sha256") == Some(&serde_json::json!(l2_workbench::sha256(&nested)))
                && item.pointer("/origins/0/origin/output_range/offset")
                    == Some(&serde_json::json!(41))
                && item.pointer("/origins/0/origin/steps/1/output_sha256")
                    == outer_hash.get("value")
        })
        .ok_or("nested PNG range missing")?;
    let name = inner
        .get("file")
        .and_then(serde_json::Value::as_str)
        .ok_or("nested PNG file missing")?;
    assert_eq!(fs::read(output.join(name))?, nested);
    Ok(())
}

#[test]
fn refine_reports_long_gzip_header_observation_limit_for_source_and_derived_stream()
-> Result<(), Box<dyn Error>> {
    use flate2::GzBuilder;

    let directory = tempfile::tempdir()?;
    let gzip_path = directory.path().join("long-header.gz");
    let mut gzip = GzBuilder::new()
        .extra(vec![0xa5; 5000])
        .write(File::create(&gzip_path)?, Compression::none());
    for _ in 0..150 {
        gzip.write_all(&[0x91; 16 * 1024])?;
    }
    gzip.finish()?.sync_all()?;
    let encoded_path = directory.path().join("encoded.txt");
    let mut encoded = EncoderWriter::new(File::create(&encoded_path)?, &STANDARD);
    io::copy(&mut File::open(&gzip_path)?, &mut encoded)?;
    encoded.finish()?.sync_all()?;

    for (input, name) in [
        (&gzip_path, "source-result"),
        (&encoded_path, "derived-result"),
    ] {
        let output = directory.path().join(name);
        let original = SourceIdentity::sha256_file(input)?;
        let mut settings = options(input, &output);
        settings.recovery.memory_limit = 8 * 1024 * 1024;
        assert!(!super::run(&settings, &mut Vec::new())?);
        assert_eq!(SourceIdentity::sha256_file(input)?, original);
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(output.join("manifest.json"))?)?;
        let omissions = manifest
            .pointer("/sources/0/omissions")
            .and_then(serde_json::Value::as_array)
            .ok_or("source omissions missing")?;
        assert!(
            omissions.iter().any(|omission| omission
                .get("reason")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|reason| reason.contains("gzip")
                    && reason.contains("4096")
                    && reason.contains("observation"))),
            "missing gzip observation limit for {name}"
        );
    }
    Ok(())
}

#[test]
fn refine_rejects_invalid_base64_tail_before_publishing_derived_content()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let (_png, zip_hash) = write_encoded_archive(directory.path(), true)?;
    let input = directory.path().join("encoded.txt");
    let output = directory.path().join("result");
    assert!(!super::run(&options(&input, &output), &mut Vec::new())?);
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("manifest.json"))?)?;
    let artifacts = manifest
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .ok_or("artifacts missing")?;
    assert!(
        !artifacts
            .iter()
            .any(|item| item.get("sha256").and_then(serde_json::Value::as_str) == Some(&zip_hash))
    );
    let omissions = manifest
        .pointer("/sources/0/omissions")
        .and_then(serde_json::Value::as_array)
        .ok_or("source omissions missing")?;
    assert!(omissions.iter().any(
        |omission| omission.get("kind").and_then(serde_json::Value::as_str)
            == Some("source_stream_transform")
    ));
    Ok(())
}

#[test]
fn streaming_source_read_limit_records_an_explicit_omission() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let (_png, zip_hash) = write_encoded_archive(directory.path(), false)?;
    let input = directory.path().join("encoded.txt");
    let output = directory.path().join("result");
    let mut settings = options(&input, &output);
    settings.recovery.source_read_limit = fs::metadata(&input)?.len() + 1024 * 1024;
    assert!(!super::run(&settings, &mut Vec::new())?);
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("manifest.json"))?)?;
    let omissions = manifest
        .pointer("/sources/0/omissions")
        .and_then(serde_json::Value::as_array)
        .ok_or("source omissions missing")?;
    assert!(omissions.iter().any(|omission| {
        omission.get("kind").and_then(serde_json::Value::as_str) == Some("source_stream_transform")
            && omission
                .get("reason")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|reason| reason.contains("source read limit"))
    }));
    let artifacts = manifest
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .ok_or("artifacts missing")?;
    assert!(
        !artifacts
            .iter()
            .any(|item| item.get("sha256").and_then(serde_json::Value::as_str) == Some(&zip_hash))
    );
    Ok(())
}

fn write_nested_archive(directory: &Path) -> Result<String, Box<dyn Error>> {
    let png = super::structural_png()?;
    let mut previous = directory.join("nested.zip");
    super::large_formats::write_archive_blocks(&previous, 0x6d, &png, 17 * 64)?;
    let hash = serde_json::to_value(SourceIdentity::sha256_file(&previous)?)?
        .get("value")
        .and_then(serde_json::Value::as_str)
        .ok_or("archive digest missing")?
        .to_owned();
    for depth in 0..3 {
        let next = directory.join(format!("layer-{depth}.gz"));
        let mut encoder = GzEncoder::new(File::create(&next)?, Compression::none());
        io::copy(&mut File::open(&previous)?, &mut encoder)?;
        encoder.finish()?.sync_all()?;
        previous = next;
    }
    let mut encoded = EncoderWriter::new(File::create(directory.join("encoded.txt"))?, &STANDARD);
    io::copy(&mut File::open(previous)?, &mut encoded)?;
    encoded.finish()?.sync_all()?;
    Ok(hash)
}

#[test]
fn streaming_spool_output_limit_stops_nested_transforms() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let zip_hash = write_nested_archive(directory.path())?;
    let input = directory.path().join("encoded.txt");
    let output = directory.path().join("result");
    let mut settings = options(&input, &output);
    settings.recovery.source_read_limit = fs::metadata(&input)?
        .len()
        .checked_mul(2)
        .and_then(|size| size.checked_add(1024 * 1024))
        .ok_or("read limit overflows")?;
    assert!(!super::run(&settings, &mut Vec::new())?);
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("manifest.json"))?)?;
    let artifacts = manifest
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .ok_or("artifacts missing")?;
    assert!(
        !artifacts
            .iter()
            .any(|item| item.get("sha256").and_then(serde_json::Value::as_str) == Some(&zip_hash))
    );
    let omissions = manifest
        .pointer("/sources/0/omissions")
        .and_then(serde_json::Value::as_array)
        .ok_or("source omissions missing")?;
    assert!(omissions.iter().any(|omission| {
        omission.get("kind").and_then(serde_json::Value::as_str) == Some("source_stream_transform")
            && omission
                .get("reason")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|reason| {
                    reason.contains("OutputLimitExceeded") || reason.contains("budget is exhausted")
                })
    }));
    Ok(())
}

#[test]
fn streaming_recursion_limit_prevents_unbounded_nested_expansion() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let (png, _zip_hash) = write_encoded_archive(directory.path(), false)?;
    let input = directory.path().join("encoded.txt");
    let output = directory.path().join("result");
    let mut settings = options(&input, &output);
    settings.recovery.profile = crate::arguments::RecoveryProfile::Fast;
    assert!(!super::run(&settings, &mut Vec::new())?);
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("manifest.json"))?)?;
    let artifacts = manifest
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .ok_or("artifacts missing")?;
    assert!(!artifacts.iter().any(|item| {
        item.get("file")
            .and_then(serde_json::Value::as_str)
            .filter(|name| has_png_extension(name))
            .and_then(|name| fs::read(output.join(name)).ok())
            .is_some_and(|bytes| bytes == png)
    }));
    let omissions = manifest
        .pointer("/sources/0/omissions")
        .and_then(serde_json::Value::as_array)
        .ok_or("source omissions missing")?;
    assert!(omissions.iter().any(
        |omission| omission.get("kind").and_then(serde_json::Value::as_str) == Some("depth_limit")
    ));
    Ok(())
}

#[test]
fn range_reader_rejects_mutation_during_a_streaming_attempt() -> Result<(), Box<dyn Error>> {
    use std::io::{Seek, SeekFrom};
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("input.bin");
    fs::write(&path, vec![b'a'; 1024 * 1024])?;
    let job = Job::new("changed streaming source");
    let input = super::prepare_input_set(&path)?;
    let sources = super::read_sources(&input, 1, 1, &job)?;
    let source = sources.first().ok_or("source missing")?;
    let result = source.with_range_reader(&input, 0, &job, |_reader| -> io::Result<()> {
        let mut file = fs::OpenOptions::new().write(true).open(&path)?;
        file.seek(SeekFrom::Start(500_000))?;
        file.write_all(b"changed")?;
        Ok(())
    });
    assert!(result.is_err());
    Ok(())
}

#[test]
fn unsupported_whole_source_streaming_is_reported_as_incomplete() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("unsupported.bin");
    let output = directory.path().join("result");
    let mut file = File::create(&input)?;
    for _ in 0..320 {
        file.write_all(&[0x91; 16 * 1024])?;
    }
    file.sync_all()?;
    let mut settings = options(&input, &output);
    settings.recovery.memory_limit = 16 * 1024 * 1024;
    assert!(!super::run(&settings, &mut Vec::new())?);
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("manifest.json"))?)?;
    let omissions = manifest
        .pointer("/sources/0/omissions")
        .and_then(serde_json::Value::as_array)
        .ok_or("source omissions missing")?;
    assert!(omissions.iter().any(|omission| {
        omission.get("kind").and_then(serde_json::Value::as_str) == Some("source_stream_transform")
            && omission
                .get("reason")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|reason| reason.contains("no supported whole-source"))
    }));
    Ok(())
}

#[test]
fn normal_refinement_finds_a_valid_object_near_the_end_of_a_large_file()
-> Result<(), Box<dyn Error>> {
    use std::io::{Seek, SeekFrom};
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("sparse.bin");
    let output = directory.path().join("result");
    let png = super::structural_png()?;
    let length = 70_u64 * 1024 * 1024;
    let offset = length - u64::try_from(png.len())? - 32;
    let mut file = File::create(&input)?;
    file.set_len(length)?;
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(&png)?;
    file.sync_all()?;
    let mut settings = options(&input, &output);
    settings.recovery.memory_limit = 48 * 1024 * 1024;
    settings.recovery.source_read_limit = 160 * 1024 * 1024;
    assert!(!super::run(&settings, &mut Vec::new())?);
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("manifest.json"))?)?;
    let artifacts = manifest
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .ok_or("artifacts missing")?;
    assert!(artifacts.iter().any(|item| {
        item.get("file")
            .and_then(serde_json::Value::as_str)
            .filter(|name| has_png_extension(name))
            .and_then(|name| fs::read(output.join(name)).ok())
            .is_some_and(|bytes| bytes == png)
    }));
    Ok(())
}
