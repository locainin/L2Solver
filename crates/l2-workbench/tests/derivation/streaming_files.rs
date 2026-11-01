use base64::{engine::general_purpose::STANDARD, write::EncoderWriter};
use flate2::{Compression, write::GzEncoder};
use l2_workbench::job::MemoryBudget;
use l2_workbench::{
    artifact::{
        ArtifactAnalysisOptions, ArtifactValidationState, analyze_artifacts,
        zip::{ZipReaderBudget, ZipReaderLimits, inspect_zip_from_reader_with_source_sha256},
    },
    derivation::{
        Base64Alphabet, Base64Padding, Operation, StreamInput, StreamLimits, stream_transform,
    },
};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

fn file_sha256(path: &Path) -> Result<String, Box<dyn Error>> {
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut block = [0; 16 * 1024];
    loop {
        let read = file.read(&mut block)?;
        if read == 0 {
            break;
        }
        hash.update(block.get(..read).ok_or("invalid hash buffer")?);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn test_png() -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut bytes, 1, 1);
        encoder.set_color(png::ColorType::Rgb);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header()?;
        writer.write_image_data(&[3, 4, 5])?;
        writer.finish()?;
    }
    Ok(bytes)
}

fn write_test_archive(path: &Path, png: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut zip = zip::ZipWriter::new(File::create(path)?);
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file("large.bin", options)?;
    for index in 0..17 * 64 {
        let byte = u8::try_from(index % 251)?;
        zip.write_all(&[byte; 16 * 1024])?;
    }
    zip.start_file("image.png", options)?;
    zip.write_all(png)?;
    zip.finish()?;
    Ok(())
}

#[test]
fn large_encoded_gzip_archive_streams_to_strict_zip_validation_and_member_analysis()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let zip_path = directory.path().join("independent.zip");
    let encoded_path = directory.path().join("encoded.txt");
    let gzip_path = directory.path().join("decoded.gz");
    let decoded_zip_path = directory.path().join("decoded.zip");
    let png = test_png()?;
    write_test_archive(&zip_path, &png)?;
    let zip_length = usize::try_from(zip_path.metadata()?.len())?;
    assert!(zip_length > 16 * 1024 * 1024);
    let original_zip_hash = file_sha256(&zip_path)?;
    let base64 = EncoderWriter::new(File::create(&encoded_path)?, &STANDARD);
    let mut gzip = GzEncoder::new(base64, Compression::none());
    io::copy(&mut File::open(&zip_path)?, &mut gzip)?;
    gzip.finish()?.finish()?;
    let encoded_length = usize::try_from(encoded_path.metadata()?.len())?;
    let encoded_hash = file_sha256(&encoded_path)?;
    let limits = StreamLimits {
        max_input_bytes: 64 * 1024 * 1024,
        max_output_bytes: 64 * 1024 * 1024,
        max_work_bytes: 128 * 1024 * 1024,
        max_expansion_ratio: 1000,
    };
    let memory = MemoryBudget::new(2 * 1024 * 1024);
    let first = stream_transform(
        &mut File::open(&encoded_path)?,
        &mut File::create(&gzip_path)?,
        &Operation::Base64Decode {
            alphabet: Base64Alphabet::Standard,
            padding: Base64Padding::Required,
        },
        StreamInput {
            length: encoded_length,
            sha256: &encoded_hash,
        },
        limits,
        &memory,
    )?;
    let second = stream_transform(
        &mut File::open(&gzip_path)?,
        &mut File::create(&decoded_zip_path)?,
        &Operation::GzipDecompress {},
        StreamInput {
            length: first.output_length,
            sha256: &first.output_sha256,
        },
        limits,
        &memory,
    )?;
    assert_eq!(second.output_length, zip_length);
    assert_eq!(second.output_sha256, original_zip_hash);
    assert_eq!(file_sha256(&encoded_path)?, encoded_hash);
    let mut decoded_zip = File::open(&decoded_zip_path)?;
    let mut budget = ZipReaderBudget {
        read_bytes_remaining: 4 * 1024 * 1024,
        expanded_bytes_remaining: 1024 * 1024,
    };
    let archive = inspect_zip_from_reader_with_source_sha256(
        &mut decoded_zip,
        second.output_length,
        &second.output_sha256,
        ZipReaderLimits::default(),
        0,
        &mut budget,
    )?;
    assert_eq!(archive.entry_count, 2);
    let member = archive
        .entries
        .iter()
        .find_map(|entry| entry.content.as_deref())
        .ok_or("validated member missing")?;
    assert_eq!(member, png);
    let analysis = analyze_artifacts(member, ArtifactAnalysisOptions::default())?;
    assert!(
        analysis
            .artifacts
            .iter()
            .any(|artifact| artifact.bytes == png
                && artifact.validation.state == ArtifactValidationState::Validated)
    );
    Ok(())
}
