use std::error::Error;

use l2_workbench::artifact::zip::ZipArtifactLimits;
use l2_workbench::artifact::{
    self, EmbeddedDiscoveryLimits, EmbeddedFormat, EmbeddedValidationEvidence,
    EmbeddedValidationFailure, PngLimits,
};

use super::{image_support::structural_png, zip_support};

#[test]
fn oversized_zip_directory_is_omitted_before_any_validation_claim() -> Result<(), Box<dyn Error>> {
    let source = zip_support::entry_count_limited_zip();
    let report = artifact::discover_embedded_objects(&source, discovery_limits(source.len()))?;
    assert_eq!(report.omissions.zip_entry_count_limited, 1);
    assert_eq!(report.omissions.unvalidated_candidate_count, 1);
    assert!(report.candidates.iter().any(|candidate| matches!(
        candidate.validation,
        Err(EmbeddedValidationFailure::ZipEntryCountLimit {
            count: 4097,
            maximum: 4096
        })
    )));
    Ok(())
}

#[test]
fn embedded_zip_ranges() -> Result<(), Box<dyn Error>> {
    let archive =
        zip_support::build_zip(&[zip_support::FixtureEntry::stored(b"sample.bin", b"data")])?;
    let mut blob = b"capture prefix".to_vec();
    let zip_offset = blob.len();
    blob.extend_from_slice(&archive);
    blob.extend_from_slice(b"capture suffix");

    let report = artifact::discover_embedded_objects(&blob, discovery_limits(blob.len()))?;
    assert_eq!(report.candidates.len(), 1);
    let candidate = report
        .candidates
        .iter()
        .find(|candidate| candidate.format == EmbeddedFormat::Zip && candidate.validation.is_ok())
        .ok_or("missing validated ZIP candidate")?;

    assert_eq!(candidate.offset, zip_offset);
    assert_eq!(candidate.range.offset, zip_offset);
    assert_eq!(candidate.range.length, archive.len());
    assert!(matches!(
        candidate.validation,
        Ok(EmbeddedValidationEvidence::Zip { entry_count: 1, .. })
    ));
    Ok(())
}

#[test]
fn embedded_png_boundary() -> Result<(), Box<dyn Error>> {
    let png = structural_png(&[])?;
    let mut blob = b"unrelated prefix".to_vec();
    let png_offset = blob.len();
    blob.extend_from_slice(&png);
    blob.extend_from_slice(b"tail bytes are outside the PNG");

    let report = artifact::discover_embedded_objects(&blob, discovery_limits(blob.len()))?;
    let candidate = report
        .candidates
        .iter()
        .find(|candidate| candidate.format == EmbeddedFormat::Png && candidate.validation.is_ok())
        .ok_or("missing validated PNG candidate")?;

    assert_eq!(candidate.range.offset, png_offset);
    assert_eq!(candidate.range.length, png.len());
    assert!(matches!(
        candidate.validation,
        Ok(EmbeddedValidationEvidence::Png {
            trailing_range: Some(range),
            ..
        }) if range.offset == png_offset + png.len() && range.length == blob.len() - range.offset
    ));
    Ok(())
}

#[test]
fn embedded_magic_rejected() -> Result<(), Box<dyn Error>> {
    let blob = [
        b"ordinary bytes".as_slice(),
        b"PK\x03\x04random marker".as_slice(),
        &artifact::PNG_SIGNATURE,
        b"still not an object".as_slice(),
    ]
    .concat();
    let report = artifact::discover_embedded_objects(&blob, discovery_limits(blob.len()))?;

    assert!(!report.candidates.is_empty());
    assert!(
        report
            .candidates
            .iter()
            .all(|candidate| candidate.validation.is_err())
    );
    Ok(())
}

#[test]
fn embedded_corrupt_truncated() -> Result<(), Box<dyn Error>> {
    let mut corrupt_png = structural_png(&[])?;
    let crc_offset = artifact::PNG_SIGNATURE.len() + 8 + 13 + 3;
    *corrupt_png
        .get_mut(crc_offset)
        .ok_or("PNG CRC byte is missing")? ^= 1;
    let truncated_png = [
        artifact::PNG_SIGNATURE.as_slice(),
        &[0, 0, 0, 20, b'I', b'H', b'D', b'R'],
    ]
    .concat();
    let mut corrupt_zip =
        zip_support::build_zip(&[zip_support::FixtureEntry::stored(b"bad.bin", b"bad data")])?;
    let central_header = corrupt_zip
        .windows(4)
        .position(|window| window == b"PK\x01\x02")
        .ok_or("central directory header is missing")?;
    *corrupt_zip
        .get_mut(central_header)
        .ok_or("central directory signature is missing")? = 0;
    let truncated_zip = b"PK\x03\x04\x14\0";
    let blob = [
        b"synthetic".as_slice(),
        &corrupt_png,
        b"gap".as_slice(),
        &truncated_png,
        b"more gap".as_slice(),
        &corrupt_zip,
        b"final gap".as_slice(),
        truncated_zip,
    ]
    .concat();

    let report = artifact::discover_embedded_objects(&blob, discovery_limits(blob.len()))?;
    assert!(report.candidates.len() >= 4);
    assert!(
        report
            .candidates
            .iter()
            .all(|candidate| candidate.validation.is_err())
    );
    Ok(())
}

#[test]
fn embedded_zip_work() -> Result<(), Box<dyn Error>> {
    let archive =
        zip_support::build_zip(&[zip_support::FixtureEntry::stored(b"budget.bin", b"data")])?;
    let mut blob = b"prefix".to_vec();
    blob.extend_from_slice(&archive);
    let mut policy = discovery_limits(blob.len());
    policy.max_zip_operation_expanded_bytes = 0;

    let report = artifact::discover_embedded_objects(&blob, policy)?;
    let candidate = report
        .candidates
        .iter()
        .find(|candidate| candidate.format == EmbeddedFormat::Zip && candidate.validation.is_ok())
        .ok_or("missing structurally valid ZIP candidate")?;
    assert!(matches!(
        candidate.validation,
        Ok(EmbeddedValidationEvidence::Zip {
            expanded_byte_count: 0,
            omitted_entry_count: 1,
            ..
        })
    ));
    Ok(())
}

#[test]
fn embedded_empty_zip() -> Result<(), Box<dyn Error>> {
    let archive = [b"PK\x05\x06".as_slice(), &[0; 18]].concat();
    let mut blob = b"prefix".to_vec();
    let zip_offset = blob.len();
    blob.extend_from_slice(&archive);

    let report = artifact::discover_embedded_objects(&blob, discovery_limits(blob.len()))?;
    let candidate = report
        .candidates
        .iter()
        .find(|candidate| candidate.format == EmbeddedFormat::Zip && candidate.validation.is_ok())
        .ok_or("missing validated empty ZIP candidate")?;
    assert_eq!(candidate.offset, zip_offset);
    assert_eq!(candidate.range.length, archive.len());
    assert!(matches!(
        candidate.validation,
        Ok(EmbeddedValidationEvidence::Zip { entry_count: 0, .. })
    ));
    Ok(())
}

#[test]
fn embedded_multiple_candidates() -> Result<(), Box<dyn Error>> {
    let first = structural_png(&[])?;
    let archive = zip_support::build_zip(&[zip_support::FixtureEntry::stored(
        b"other.bin",
        b"other data",
    )])?;
    let mut blob = b"unrelated".to_vec();
    blob.extend_from_slice(&first);
    blob.extend_from_slice(b"interstitial bytes");
    blob.extend_from_slice(&archive);

    let report = artifact::discover_embedded_objects(&blob, discovery_limits(blob.len()))?;
    let valid: Vec<_> = report
        .candidates
        .iter()
        .filter(|candidate| candidate.validation.is_ok())
        .collect();

    assert!(
        valid
            .iter()
            .any(|candidate| candidate.format == EmbeddedFormat::Png)
    );
    assert!(
        valid
            .iter()
            .any(|candidate| candidate.format == EmbeddedFormat::Zip)
    );
    Ok(())
}

#[test]
fn embedded_budget_omissions() -> Result<(), Box<dyn Error>> {
    let png = structural_png(&[])?;
    let mut blob = b"prefix".to_vec();
    blob.extend_from_slice(&png);
    blob.extend_from_slice(b"between");
    blob.extend_from_slice(&png);

    let mut output_limited = discovery_limits(blob.len());
    output_limited.max_candidates = 1;
    let report = artifact::discover_embedded_objects(&blob, output_limited)?;
    assert_eq!(report.omissions.output_candidate_count, 1);

    let mut work_limited = discovery_limits(blob.len());
    work_limited.max_validation_attempts = 0;
    let report = artifact::discover_embedded_objects(&blob, work_limited)?;
    assert_eq!(report.omissions.unvalidated_candidate_count, 2);
    assert!(report.candidates.iter().all(|candidate| matches!(
        candidate.validation,
        Err(EmbeddedValidationFailure::ValidationAttemptsExhausted)
    )));

    let mut scan_limited = discovery_limits(blob.len());
    scan_limited.max_scan_bytes = 8;
    let report = artifact::discover_embedded_objects(&blob, scan_limited)?;
    assert_eq!(
        report.omissions.unscanned_range.map(|range| range.offset),
        Some(8)
    );
    assert_eq!(
        report.omissions.unscanned_range.map(|range| range.length),
        Some(blob.len() - 8)
    );
    Ok(())
}

#[test]
fn embedded_parser_work_budget() -> Result<(), Box<dyn Error>> {
    let png = structural_png(&[])?;
    let mut blob = png.clone();
    blob.extend_from_slice(&png);
    let report = artifact::discover_embedded_objects_with_work(
        &blob,
        discovery_limits(blob.len()),
        blob.len(),
    )?;

    assert_eq!(report.validation_attempt_count, 1);
    assert_eq!(report.validation_input_bytes, blob.len());
    assert_eq!(report.omissions.unvalidated_candidate_count, 1);
    assert!(report.candidates.iter().any(|candidate| matches!(
        candidate.validation,
        Err(EmbeddedValidationFailure::ValidationWorkExhausted)
    )));
    Ok(())
}

fn discovery_limits(scan_bytes: usize) -> EmbeddedDiscoveryLimits {
    EmbeddedDiscoveryLimits {
        max_scan_bytes: scan_bytes,
        max_validation_attempts: 32,
        max_candidates: 32,
        png_limits: PngLimits::default(),
        zip_limits: ZipArtifactLimits::default(),
        max_zip_operation_expanded_bytes: 1024,
    }
}
