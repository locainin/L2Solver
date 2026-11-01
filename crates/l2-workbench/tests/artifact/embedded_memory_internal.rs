use super::{TestResult, png_with_chunks, zip_support};
use crate::{
    artifact::{
        EmbeddedDiscoveryLimits, EmbeddedFormat, EmbeddedValidationEvidence,
        EmbeddedValidationFailure, PngLimits,
        embedded::{
            EmbeddedDiscoveryMemoryError,
            discover_embedded_objects_with_work_and_skip_start_with_memory,
        },
        zip::ZipArtifactLimits,
    },
    job::{MemoryBudget, MemoryClass, MemoryError},
};
use std::mem::size_of;

fn limits(length: usize) -> EmbeddedDiscoveryLimits {
    EmbeddedDiscoveryLimits {
        max_scan_bytes: length,
        max_validation_attempts: 32,
        max_candidates: 32,
        png_limits: PngLimits::default(),
        zip_limits: ZipArtifactLimits::default(),
        max_zip_operation_expanded_bytes: 1024,
    }
}

#[test]
fn source_without_markers_needs_no_heap_metadata() -> TestResult {
    let source = b"ordinary source bytes";
    let budget = MemoryBudget::new(0);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 0)?;
    let report = discover_embedded_objects_with_work_and_skip_start_with_memory(
        source,
        limits(source.len()),
        usize::MAX,
        None,
        &mut lease,
    )?;
    assert!(report.candidates.is_empty());
    assert_eq!(report.validation_attempt_count, 0);
    assert_eq!(lease.bytes(), 0);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn marker_metadata_pressure_is_typed_and_preserves_existing_charge() -> TestResult {
    let mut source = b"prefix".to_vec();
    source.extend_from_slice(&png_with_chunks(0)?);
    let budget = MemoryBudget::new(7);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 7)?;
    let result = discover_embedded_objects_with_work_and_skip_start_with_memory(
        &source,
        limits(source.len()),
        usize::MAX,
        None,
        &mut lease,
    );
    assert!(matches!(
        result,
        Err(EmbeddedDiscoveryMemoryError::Memory(
            MemoryError::Limit { .. }
        ))
    ));
    assert_eq!(lease.bytes(), 7);
    assert_eq!(budget.snapshot()?.used_bytes, 7);
    Ok(())
}

#[test]
fn png_parser_pressure_releases_marker_and_candidate_buffers() -> TestResult {
    let mut source = b"prefix".to_vec();
    source.extend_from_slice(&png_with_chunks(100)?);
    let budget = MemoryBudget::new(1_024);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 17)?;
    let result = discover_embedded_objects_with_work_and_skip_start_with_memory(
        &source,
        limits(source.len()),
        usize::MAX,
        None,
        &mut lease,
    );
    assert!(matches!(
        result,
        Err(EmbeddedDiscoveryMemoryError::Memory(
            MemoryError::Limit { .. }
        ))
    ));
    assert_eq!(lease.bytes(), 17);
    assert_eq!(budget.snapshot()?.used_bytes, 17);
    Ok(())
}

#[test]
fn embedded_zip_parser_pressure_is_typed_and_releases_discovery_buffers() -> TestResult {
    let payload = vec![0x7e; 8_192];
    let archive = zip_support::build_zip(&[zip_support::FixtureEntry::stored(b"file", &payload)])?;
    let mut source = b"prefix".to_vec();
    source.extend_from_slice(&archive);
    let mut policy = limits(source.len());
    policy.max_candidates = 1;
    policy.max_validation_attempts = 1;
    let budget = MemoryBudget::new(4 * 1024);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 7)?;
    let result = discover_embedded_objects_with_work_and_skip_start_with_memory(
        &source,
        policy,
        usize::MAX,
        None,
        &mut lease,
    );
    assert!(matches!(
        result,
        Err(EmbeddedDiscoveryMemoryError::Memory(
            MemoryError::Limit { .. }
        ))
    ));
    assert!(budget.snapshot()?.peak_bytes > 7);
    assert_eq!(lease.bytes(), 7);
    assert_eq!(budget.snapshot()?.used_bytes, 7);
    Ok(())
}

#[test]
fn corrupt_embedded_zip_releases_the_failed_parser_report() -> TestResult {
    let mut archive =
        zip_support::build_zip(&[zip_support::FixtureEntry::stored(b"file", b"payload")])?;
    let central_offset = archive
        .windows(4)
        .position(|part| part == b"PK\x01\x02")
        .ok_or("missing central directory")?;
    *archive
        .get_mut(central_offset)
        .ok_or("missing central signature")? = 0;
    let mut source = b"prefix".to_vec();
    source.extend_from_slice(&archive);
    let budget = MemoryBudget::new(100_000);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 7)?;
    let report = discover_embedded_objects_with_work_and_skip_start_with_memory(
        &source,
        limits(source.len()),
        usize::MAX,
        None,
        &mut lease,
    )?;
    let candidate = report.candidates.first().ok_or("missing ZIP candidate")?;
    assert!(matches!(
        candidate.validation,
        Err(EmbeddedValidationFailure::Zip(_))
    ));
    let retained = report.candidates.capacity() * size_of::<crate::artifact::EmbeddedCandidate>();
    assert_eq!(lease.bytes(), 7 + u64::try_from(retained)?);
    Ok(())
}

#[test]
fn discovered_png_and_zip_keep_ranges_work_and_retained_report_charged() -> TestResult {
    let png = png_with_chunks(1)?;
    let archive =
        zip_support::build_zip(&[zip_support::FixtureEntry::stored(b"file", b"payload")])?;
    let mut source = b"prefix".to_vec();
    let png_offset = source.len();
    source.extend_from_slice(&png);
    source.extend_from_slice(b"gap");
    let zip_offset = source.len();
    source.extend_from_slice(&archive);
    source.extend_from_slice(b"suffix");
    let budget = MemoryBudget::new(100_000);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 17)?;
    let report = discover_embedded_objects_with_work_and_skip_start_with_memory(
        &source,
        limits(source.len()),
        usize::MAX,
        None,
        &mut lease,
    )?;
    let png_candidate = report
        .candidates
        .iter()
        .find(|candidate| candidate.offset == png_offset)
        .ok_or("missing PNG candidate")?;
    assert_eq!(png_candidate.range.length, png.len());
    assert!(matches!(
        png_candidate.validation,
        Ok(EmbeddedValidationEvidence::Png { chunk_count: 3, .. })
    ));
    let zip_candidate = report
        .candidates
        .iter()
        .find(|candidate| candidate.offset == zip_offset)
        .ok_or("missing ZIP candidate")?;
    assert_eq!(zip_candidate.range.length, archive.len());
    let Ok(EmbeddedValidationEvidence::Zip {
        archive_sha256,
        expanded_byte_count,
        ..
    }) = &zip_candidate.validation
    else {
        return Err("expected ZIP evidence".into());
    };
    assert_eq!(*expanded_byte_count, 7);
    assert_eq!(archive_sha256, &crate::sha256(&archive));
    assert_eq!(report.zip_work_bytes, 7);
    let retained = report.candidates.capacity() * size_of::<crate::artifact::EmbeddedCandidate>()
        + archive_sha256.capacity();
    assert!(lease.bytes() >= 17 + u64::try_from(retained)?);
    assert_eq!(budget.snapshot()?.used_bytes, lease.bytes());
    drop(report);
    drop(lease);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn sparse_markers_fit_a_full_working_set_without_worst_case_reservations() -> TestResult {
    let mut source = vec![0; 8 * 1024];
    source.extend_from_slice(&png_with_chunks(0)?);
    let mut policy = limits(source.len());
    policy.max_candidates = source.len();
    policy.max_validation_attempts = source.len();
    let budget = MemoryBudget::new(64 * 1024);
    let working_set = budget.try_working_set(4 * 1024)?;
    let mut lease = working_set.budget().try_reserve(MemoryClass::Executor, 0)?;
    let snapshot = budget.snapshot()?;
    let free = snapshot.limit_bytes - snapshot.used_bytes - snapshot.working_sets.reserved_bytes;
    let blocker = budget.try_reserve(MemoryClass::Cache, free)?;
    let report = discover_embedded_objects_with_work_and_skip_start_with_memory(
        &source,
        policy,
        usize::MAX,
        None,
        &mut lease,
    )?;
    assert_eq!(report.candidates.len(), 1);
    assert!(
        report
            .candidates
            .first()
            .ok_or("missing candidate")?
            .validation
            .is_ok()
    );
    drop(report);
    drop(lease);
    drop(blocker);
    drop(working_set);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn corrupt_png_and_skipped_start_preserve_discovery_results() -> TestResult {
    let mut source = png_with_chunks(0)?;
    source.extend_from_slice(b"gap");
    let corrupt_offset = source.len();
    let mut corrupt = png_with_chunks(0)?;
    *corrupt.get_mut(29).ok_or("missing PNG CRC")? ^= 1;
    source.extend_from_slice(&corrupt);
    let budget = MemoryBudget::new(16 * 1024);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 0)?;
    let report = discover_embedded_objects_with_work_and_skip_start_with_memory(
        &source,
        limits(source.len()),
        usize::MAX,
        Some(EmbeddedFormat::Png),
        &mut lease,
    )?;
    assert_eq!(report.candidates.len(), 1);
    let candidate = report.candidates.first().ok_or("missing candidate")?;
    assert_eq!(candidate.offset, corrupt_offset);
    assert!(matches!(
        candidate.validation,
        Err(EmbeddedValidationFailure::Png(
            crate::artifact::PngError::InvalidChecksum { .. }
        ))
    ));
    assert_eq!(report.validation_attempt_count, 1);
    Ok(())
}

#[test]
fn zero_zip_work_limit_omits_member_without_reserving_payload_ceiling() -> TestResult {
    let archive =
        zip_support::build_zip(&[zip_support::FixtureEntry::stored(b"file", b"payload")])?;
    let mut source = b"prefix".to_vec();
    source.extend_from_slice(&archive);
    let mut policy = limits(source.len());
    policy.max_zip_operation_expanded_bytes = 0;
    let budget = MemoryBudget::new(8 * 1024);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 0)?;
    let report = discover_embedded_objects_with_work_and_skip_start_with_memory(
        &source,
        policy,
        usize::MAX,
        None,
        &mut lease,
    )?;
    assert_eq!(report.zip_work_bytes, 0);
    assert!(matches!(
        report
            .candidates
            .first()
            .ok_or("missing candidate")?
            .validation,
        Ok(EmbeddedValidationEvidence::Zip {
            expanded_byte_count: 0,
            omitted_entry_count: 1,
            ..
        })
    ));
    Ok(())
}
