use std::{
    error::Error,
    io::{self, Cursor, Read},
};

use super::{image_support::structural_png, zip_support};
use l2_workbench::artifact::{
    AnalysisOmission, AnalysisStatus, ArtifactAnalysisOptions, ArtifactOrigin,
    ArtifactValidationState, EmbeddedFormat, FileRange, StreamMemory, ZipEndScanLimits,
    analyze_artifacts_from_reader, analyze_artifacts_observing_zip_ends,
};

#[test]
fn retained_range_bytes_grow_the_shared_report_lease() -> Result<(), Box<dyn Error>> {
    use l2_workbench::job::{MemoryBudget, MemoryClass, MemoryError};
    let png = structural_png(&[])?;
    let source = [b"prefix".as_slice(), png.as_slice()].concat();
    let budget = MemoryBudget::new(4096);
    let mut png_memory = budget.try_reserve(MemoryClass::Executor, 0)?;
    let mut report_memory = budget.try_reserve(MemoryClass::Executor, 0)?;
    let result = analyze_artifacts_observing_zip_ends(
        &mut Cursor::new(&source),
        source.len(),
        options(),
        None,
        false,
        ZipEndScanLimits {
            max_scan_bytes: 0,
            max_candidates: 0,
        },
        Some(StreamMemory {
            png_metadata: &mut png_memory,
            report: &mut report_memory,
        }),
    )?;
    assert!(
        result
            .analysis
            .artifacts
            .iter()
            .any(|artifact| artifact.bytes == png)
    );
    assert!(report_memory.bytes() >= u64::try_from(png.len())?);
    drop(result);
    drop(report_memory);
    drop(png_memory);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    let budget = MemoryBudget::new(1);
    let mut png_memory = budget.try_reserve(MemoryClass::Executor, 0)?;
    let mut report_memory = budget.try_reserve(MemoryClass::Executor, 0)?;
    let error = analyze_artifacts_observing_zip_ends(
        &mut Cursor::new(&source),
        source.len(),
        options(),
        None,
        false,
        ZipEndScanLimits {
            max_scan_bytes: 0,
            max_candidates: 0,
        },
        Some(StreamMemory {
            png_metadata: &mut png_memory,
            report: &mut report_memory,
        }),
    )
    .err()
    .ok_or("range output ignored memory pressure")?;
    assert!(matches!(
        error
            .get_ref()
            .and_then(|source| source.downcast_ref::<MemoryError>()),
        Some(MemoryError::Limit { .. })
    ));
    Ok(())
}

fn analyze_with_checkpoint(
    reader: &mut impl Read,
    length: usize,
    settings: ArtifactAnalysisOptions,
    checkpoint: usize,
    scan_png: bool,
) -> io::Result<l2_workbench::artifact::StreamSourceAnalysis> {
    analyze_artifacts_observing_zip_ends(
        reader,
        length,
        settings,
        Some(checkpoint),
        scan_png,
        ZipEndScanLimits {
            max_scan_bytes: 0,
            max_candidates: 0,
        },
        None,
    )
}

fn analyze_png_only(
    reader: &mut impl Read,
    length: usize,
    settings: ArtifactAnalysisOptions,
) -> io::Result<l2_workbench::artifact::StreamSourceAnalysis> {
    analyze_artifacts_observing_zip_ends(
        reader,
        length,
        settings,
        None,
        true,
        ZipEndScanLimits {
            max_scan_bytes: 0,
            max_candidates: 0,
        },
        None,
    )
}

#[test]
fn zip_end_observation_crosses_short_reads_and_captures_the_prefix_hash()
-> Result<(), Box<dyn Error>> {
    struct ShortReader<'a> {
        source: Cursor<&'a [u8]>,
        bytes: usize,
    }
    impl Read for ShortReader<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let count = buffer.len().min(3);
            let read = self.source.read(
                buffer
                    .get_mut(..count)
                    .ok_or_else(|| io::Error::other("invalid test buffer"))?,
            )?;
            self.bytes += read;
            Ok(read)
        }
    }
    let mut source = b"prefix".to_vec();
    source.extend_from_slice(b"PK\x05\x06");
    source.extend_from_slice(&[0_u8; 18]);
    let boundary = source.len();
    source.extend_from_slice(&[9_u8; 300]);
    let mut reader = ShortReader {
        source: Cursor::new(&source),
        bytes: 0,
    };
    let result = analyze_artifacts_observing_zip_ends(
        &mut reader,
        source.len(),
        options(),
        None,
        false,
        ZipEndScanLimits {
            max_scan_bytes: source.len(),
            max_candidates: 4,
        },
        None,
    )?;
    let observation = result.zip_observation.ok_or("ZIP observation missing")?;
    assert_eq!(observation.candidates.len(), 1);
    let candidate = observation.candidates.first().ok_or("candidate missing")?;
    assert_eq!(candidate.end, boundary);
    assert_eq!(
        candidate.sha256,
        l2_workbench::sha256(source.get(..boundary).ok_or("prefix missing")?)
    );
    assert_eq!(reader.bytes, source.len());
    assert_eq!(result.analysis.source_sha256, l2_workbench::sha256(&source));
    Ok(())
}

#[test]
fn zip_end_observation_reports_candidate_and_scan_limits() -> Result<(), Box<dyn Error>> {
    let mut source = Vec::new();
    for _ in 0..3 {
        source.extend_from_slice(b"PK\x05\x06");
        source.extend_from_slice(&[0_u8; 18]);
    }
    let result = analyze_artifacts_observing_zip_ends(
        &mut Cursor::new(&source),
        source.len(),
        options(),
        None,
        false,
        ZipEndScanLimits {
            max_scan_bytes: source.len(),
            max_candidates: 1,
        },
        None,
    )?;
    let observed = result.zip_observation.ok_or("ZIP observation missing")?;
    assert_eq!(observed.candidates.len(), 1);
    assert_eq!(observed.omitted_candidates, 2);
    let result = analyze_artifacts_observing_zip_ends(
        &mut Cursor::new(&source),
        source.len(),
        options(),
        None,
        false,
        ZipEndScanLimits {
            max_scan_bytes: 10,
            max_candidates: 4,
        },
        None,
    )?;
    let observed = result.zip_observation.ok_or("ZIP observation missing")?;
    assert_eq!(observed.scanned_bytes, 10);
    assert!(observed.candidates.is_empty());
    assert_eq!(observed.unscanned_bytes, source.len());
    Ok(())
}

#[test]
fn png_iend_and_zip_end_hashes_remain_exact_with_shared_lookahead() -> Result<(), Box<dyn Error>> {
    let png = structural_png(&[])?;
    let mut source = png.clone();
    source.extend_from_slice(b"PK\x05\x06");
    let mut fields = [0_u8; 18];
    *fields.get_mut(16).ok_or("comment length missing")? = 7;
    source.extend_from_slice(&fields);
    source.extend_from_slice(b"comment");
    let zip_end = source.len();
    source.extend_from_slice(b"after ZIP");
    let result = analyze_artifacts_observing_zip_ends(
        &mut Cursor::new(&source),
        source.len(),
        options(),
        Some(zip_end),
        true,
        ZipEndScanLimits {
            max_scan_bytes: source.len(),
            max_candidates: 4,
        },
        None,
    )?;
    assert_eq!(
        result.png.ok_or("PNG missing")?.sha256,
        l2_workbench::sha256(&png)
    );
    let observation = result.zip_observation.ok_or("ZIP observation missing")?;
    let end = observation.candidates.first().ok_or("ZIP end missing")?;
    assert_eq!(end.end, zip_end);
    assert_eq!(
        end.sha256,
        l2_workbench::sha256(source.get(..zip_end).ok_or("ZIP prefix missing")?)
    );
    assert_eq!(result.prefix_sha256.as_deref(), Some(end.sha256.as_str()));
    Ok(())
}

#[test]
fn prefix_checkpoint_and_full_source_hash_share_one_reader_pass() -> Result<(), Box<dyn Error>> {
    let source = structural_png(&[])?;
    let checkpoint = 17;
    for scan_png in [false, true] {
        let result = analyze_with_checkpoint(
            &mut Cursor::new(&source),
            source.len(),
            options(),
            checkpoint,
            scan_png,
        )?;
        assert_eq!(
            result.prefix_sha256.as_deref(),
            Some(l2_workbench::sha256(source.get(..checkpoint).ok_or("prefix missing")?).as_str())
        );
        assert_eq!(result.analysis.source_sha256, l2_workbench::sha256(&source));
        assert_eq!(result.png.is_some(), scan_png);
    }
    Ok(())
}

#[test]
fn prefix_checkpoint_outside_the_source_is_rejected() {
    let source = [0_u8; 8];
    assert!(
        analyze_with_checkpoint(&mut Cursor::new(&source), source.len(), options(), 9, false)
            .is_err()
    );
}

#[test]
fn streamed_png_and_source_are_hashed_in_one_pass_with_exact_iend_range()
-> Result<(), Box<dyn Error>> {
    struct Counted<'a> {
        source: Cursor<&'a [u8]>,
        bytes: usize,
    }
    impl Read for Counted<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let count = self.source.read(buffer)?;
            self.bytes += count;
            Ok(count)
        }
    }
    let png = structural_png(&[])?;
    let source = [png.as_slice(), b"unchanged trailing bytes"].concat();
    let mut reader = Counted {
        source: Cursor::new(&source),
        bytes: 0,
    };
    let mut settings = options();
    settings.limits.max_input_bytes = 256;
    let result = analyze_png_only(&mut reader, source.len(), settings)?;
    let boundary = result.png.ok_or("valid PNG was not identified")?;
    assert_eq!(
        boundary.range,
        FileRange {
            offset: 0,
            length: png.len()
        }
    );
    assert_eq!(boundary.sha256, l2_workbench::sha256(&png));
    assert_eq!(boundary.chunk_count, 2);
    assert_eq!(result.analysis.source_sha256, l2_workbench::sha256(&source));
    assert_eq!(
        reader.bytes,
        source.len(),
        "source content was read more than once"
    );
    Ok(())
}

#[test]
fn streamed_png_crc_failure_never_claims_a_validated_boundary() -> Result<(), Box<dyn Error>> {
    let mut source = structural_png(&[])?;
    *source.last_mut().ok_or("PNG is empty")? ^= 1;
    let result = analyze_png_only(&mut Cursor::new(&source), source.len(), options())?;
    assert!(result.png.is_none());
    assert_eq!(result.analysis.source_sha256, l2_workbench::sha256(&source));
    Ok(())
}

#[test]
fn streamed_png_validation_work_limit_is_explicit_and_source_is_still_hashed()
-> Result<(), Box<dyn Error>> {
    let source = structural_png(&[])?;
    let mut settings = options();
    settings.limits.max_total_work_bytes = 8;
    let result = analyze_png_only(&mut Cursor::new(&source), source.len(), settings)?;
    assert!(result.png.is_none());
    assert!(result.analysis.omissions.iter().any(|omission| matches!(
        omission,
        AnalysisOmission::SourceRangeValidationLimit {
            format: l2_workbench::artifact::AnalysisFormat::Png,
            ..
        }
    )));
    assert_eq!(result.analysis.source_sha256, l2_workbench::sha256(&source));
    Ok(())
}

fn options() -> ArtifactAnalysisOptions {
    let mut options = ArtifactAnalysisOptions::default();
    options.limits.max_input_bytes = 512;
    options.limits.max_total_output_bytes = 4096;
    options.limits.max_total_work_bytes = 32_768;
    options.limits.max_artifacts = 16;
    options
}

#[test]
fn rolling_ranges_validate_objects_across_windows_and_keep_duplicate_origins()
-> Result<(), Box<dyn Error>> {
    let png = structural_png(&[])?;
    let zip = zip_support::build_zip(&[zip_support::FixtureEntry::stored(b"member", b"payload")])?;
    let mut bytes = vec![0_u8; 1536];
    let png_offsets = [252_usize, 700];
    let zip_offset = 1020;
    for offset in png_offsets {
        bytes
            .get_mut(offset..offset + png.len())
            .ok_or("PNG fixture exceeds source")?
            .copy_from_slice(&png);
    }
    bytes
        .get_mut(zip_offset..zip_offset + zip.len())
        .ok_or("ZIP fixture exceeds source")?
        .copy_from_slice(&zip);
    let report = analyze_artifacts_from_reader(&mut Cursor::new(&bytes), bytes.len(), options())?;

    assert_eq!(report.source_sha256, l2_workbench::sha256(&bytes));
    assert_eq!(report.status, AnalysisStatus::Partial);
    let png_artifact = report
        .artifacts
        .iter()
        .find(|artifact| artifact.bytes == png)
        .ok_or("PNG was not retained")?;
    assert_eq!(
        png_artifact.validation.state,
        ArtifactValidationState::Validated
    );
    for offset in png_offsets {
        assert!(
            png_artifact.origins.contains(&ArtifactOrigin::SourceRange {
                range: FileRange {
                    offset,
                    length: png.len()
                },
                format: EmbeddedFormat::Png,
            }),
            "missing PNG origin at {offset}"
        );
    }
    let zip_artifact = report
        .artifacts
        .iter()
        .find(|artifact| artifact.bytes == zip)
        .ok_or("ZIP was not retained")?;
    assert_eq!(
        zip_artifact.validation.state,
        ArtifactValidationState::Validated
    );
    assert!(zip_artifact.origins.contains(&ArtifactOrigin::SourceRange {
        range: FileRange {
            offset: zip_offset,
            length: zip.len()
        },
        format: EmbeddedFormat::Zip,
    }));
    assert!(report.omissions.iter().any(|omission| matches!(
        omission,
        AnalysisOmission::SourceRangeCoverage {
            max_object_bytes: 256,
            ..
        }
    )));
    Ok(())
}

#[test]
fn rolling_ranges_report_uncovered_bytes_and_keep_the_full_digest() -> Result<(), Box<dyn Error>> {
    let bytes = vec![0_u8; 4096];
    let mut options = options();
    options.limits.max_total_work_bytes = 1024;
    let report = analyze_artifacts_from_reader(&mut Cursor::new(&bytes), bytes.len(), options)?;
    assert_eq!(report.source_sha256, l2_workbench::sha256(&bytes));
    assert_eq!(report.status, AnalysisStatus::Partial);
    assert!(report.artifacts.is_empty());
    assert!(report.omissions.iter().any(|omission| matches!(
        omission,
        AnalysisOmission::SourceRangeCoverage {
            uncovered_range: Some(_),
            ..
        }
    )));
    Ok(())
}

#[test]
fn rolling_ranges_propagate_source_read_errors() -> Result<(), Box<dyn Error>> {
    struct FailedRead;
    impl Read for FailedRead {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "source read failed",
            ))
        }
    }
    let error = analyze_artifacts_from_reader(&mut FailedRead, 4096, options())
        .err()
        .ok_or("read failure was ignored")?;
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    Ok(())
}

#[test]
fn rolling_ranges_reject_short_and_long_source_streams() {
    let bytes = vec![0_u8; 64];
    for declared in [63, 65] {
        assert!(
            analyze_artifacts_from_reader(&mut Cursor::new(&bytes), declared, options()).is_err(),
            "stream length {declared} must not be accepted"
        );
    }
}

#[test]
fn rolling_ranges_do_not_claim_malformed_or_encoded_objects_are_validated()
-> Result<(), Box<dyn Error>> {
    use base64::{Engine, engine::general_purpose::STANDARD};

    let mut corrupt = structural_png(&[])?;
    let last = corrupt.last_mut().ok_or("empty PNG")?;
    *last ^= 1;
    let encoded = STANDARD.encode(structural_png(&[])?);
    let mut source = corrupt;
    source.extend_from_slice(encoded.as_bytes());
    let report = analyze_artifacts_from_reader(&mut Cursor::new(&source), source.len(), options())?;
    assert_eq!(report.status, AnalysisStatus::Partial);
    assert!(
        report.artifacts.is_empty(),
        "malformed or encoded data was advertised as validated"
    );
    Ok(())
}

#[test]
fn entry_count_limited_zip_is_not_reported_as_validated() -> Result<(), Box<dyn Error>> {
    let source = zip_support::entry_count_limited_zip();
    let report = analyze_artifacts_from_reader(&mut Cursor::new(&source), source.len(), options())?;
    assert!(
        report.artifacts.is_empty(),
        "ZIP directory was not parsed and cannot be validated"
    );
    assert!(report.omissions.iter().any(|omission| matches!(omission,
        AnalysisOmission::SourceRangeCoverage { omitted_candidates, .. } if *omitted_candidates > 0)));
    Ok(())
}

#[test]
fn rolling_ranges_bound_each_reader_buffer_to_the_window() -> Result<(), Box<dyn Error>> {
    struct MeasuredReader<'a> {
        cursor: Cursor<&'a [u8]>,
        largest: usize,
    }
    impl Read for MeasuredReader<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.largest = self.largest.max(buffer.len());
            self.cursor.read(buffer)
        }
    }
    let bytes = vec![0_u8; 4096];
    let mut reader = MeasuredReader {
        cursor: Cursor::new(&bytes),
        largest: 0,
    };
    analyze_artifacts_from_reader(&mut reader, bytes.len(), options())?;
    assert!(
        reader.largest <= options().limits.max_input_bytes,
        "read request exceeded the window budget"
    );
    Ok(())
}

#[test]
fn exhausted_tiny_windows_hash_the_tail_in_bounded_bulk_reads() -> Result<(), Box<dyn Error>> {
    struct CountingReader<'a> {
        cursor: Cursor<&'a [u8]>,
        calls: usize,
    }
    impl Read for CountingReader<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.calls += 1;
            self.cursor.read(buffer)
        }
    }
    let bytes = vec![0_u8; 4096];
    let mut reader = CountingReader {
        cursor: Cursor::new(&bytes),
        calls: 0,
    };
    let mut options = options();
    options.limits.max_input_bytes = 2;
    options.limits.max_total_work_bytes = 1;
    let report = analyze_artifacts_from_reader(&mut reader, bytes.len(), options)?;
    assert_eq!(report.source_sha256, l2_workbench::sha256(&bytes));
    assert!(
        reader.calls <= 4,
        "exhausted tail required {} reads",
        reader.calls
    );
    Ok(())
}

#[test]
fn scan_does_not_resume_after_a_work_limited_window() -> Result<(), Box<dyn Error>> {
    let source = vec![0_u8; 4096];
    let mut options = options();
    options.limits.max_total_work_bytes = 768;
    let report = analyze_artifacts_from_reader(&mut Cursor::new(&source), source.len(), options)?;
    assert!(report.omissions.iter().any(|omission| matches!(
        omission,
        AnalysisOmission::SourceRangeCoverage {
            uncovered_range: Some(FileRange {
                offset: 256,
                length: 3840
            }),
            ..
        }
    )));
    Ok(())
}

#[test]
fn rolling_ranges_report_signature_scan_limit_without_losing_parser_evidence()
-> Result<(), Box<dyn Error>> {
    let png = structural_png(&[])?;
    let mut options = options();
    options.limits.max_signature_scan_bytes = 1;
    let report = analyze_artifacts_from_reader(&mut Cursor::new(&png), png.len(), options)?;
    let artifact = report
        .artifacts
        .first()
        .ok_or("validated PNG was not retained")?;
    assert_eq!(
        artifact.validation.state,
        ArtifactValidationState::Validated
    );
    assert!(!artifact.signatures_scanned);
    assert!(report.omissions.iter().any(|omission| matches!(omission,
        AnalysisOmission::SourceRangeCoverage { signature_scans_omitted, .. } if *signature_scans_omitted > 0)));
    Ok(())
}

#[test]
fn zero_output_budget_keeps_source_digest_and_reports_omitted_candidate()
-> Result<(), Box<dyn Error>> {
    let png = structural_png(&[])?;
    let mut options = options();
    options.limits.max_total_output_bytes = 0;
    let report = analyze_artifacts_from_reader(&mut Cursor::new(&png), png.len(), options)?;
    assert_eq!(report.source_sha256, l2_workbench::sha256(&png));
    assert!(report.artifacts.is_empty());
    assert!(report.omissions.iter().any(|omission| matches!(omission,
        AnalysisOmission::SourceRangeCoverage { omitted_candidates, .. } if *omitted_candidates > 0)));
    Ok(())
}
