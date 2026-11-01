use std::{error::Error, mem::size_of};

use crate::{
    artifact::{
        ArtifactBoundaryEvidence, ArtifactResourceOmissionReason, ArtifactStructure,
        ArtifactValidationFailure, ArtifactValidationFormat, ArtifactValidationOutcome,
        ArtifactValidationPolicy, ArtifactValidator, PngChunk, PngError,
    },
    job::{MemoryBudget, MemoryClass, MemoryError},
};

#[path = "embedded_memory_internal.rs"]
mod embedded_memory;
#[path = "png_memory_internal.rs"]
mod png_memory;
#[path = "signature_detection_internal.rs"]
mod signature_detection;
#[path = "zip_detector_memory_internal.rs"]
mod zip_detector_memory;
#[expect(
    dead_code,
    reason = "the shared archive fixtures cover additional cases"
)]
#[path = "zip_support.rs"]
mod zip_support;
#[expect(dead_code, reason = "the shared image fixtures cover additional cases")]
mod image_support {
    use crate as l2_workbench;

    include!("image_support.rs");
}

type TestResult = Result<(), Box<dyn Error>>;

fn png_with_chunks(extra_chunks: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    let chunks = vec![(*b"abCd", b"".as_slice()); extra_chunks];
    image_support::structural_png(&chunks)
}

#[test]
fn png_memory_pressure_is_typed_and_restores_the_existing_charge() -> TestResult {
    let png = png_with_chunks(0)?;
    let budget = MemoryBudget::new(7);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 7)?;
    let mut zip_work = 50;

    let result = ArtifactValidator::default().validate_with_zip_budget_and_memory(
        &png,
        &mut zip_work,
        &mut lease,
    );

    assert!(matches!(result, Err(MemoryError::Limit { .. })));
    assert_eq!(lease.bytes(), 7);
    assert_eq!(budget.snapshot()?.used_bytes, 7);
    assert_eq!(zip_work, 50);
    Ok(())
}

#[test]
fn png_report_capacity_stays_charged_and_iend_boundary_is_preserved() -> TestResult {
    let png = png_with_chunks(1)?;
    let mut source = png.clone();
    source.extend_from_slice(b"overlay");
    let budget = MemoryBudget::new(16 * 1024);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 9)?;
    let mut zip_work = 50;
    let outcome = ArtifactValidator::default().validate_with_zip_budget_and_memory(
        &source,
        &mut zip_work,
        &mut lease,
    )?;

    let ArtifactValidationOutcome::Validated {
        format: ArtifactValidationFormat::Png,
        boundary: ArtifactBoundaryEvidence::PngIend,
        range,
        structure: ArtifactStructure::Png(report),
    } = &outcome
    else {
        return Err("expected a validated PNG".into());
    };
    assert_eq!(range.length, png.len());
    assert_eq!(report.bytes_after_iend, b"overlay");
    assert_eq!(report.chunks.len(), 3);
    let retained = report.chunks.capacity() * size_of::<PngChunk<'_>>();
    assert!(lease.bytes() >= 9 + u64::try_from(retained)?);
    assert_eq!(budget.snapshot()?.used_bytes, lease.bytes());
    assert_eq!(zip_work, 50);
    drop(outcome);
    drop(lease);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn validated_png_skips_zip_tail_detection_inside_a_full_working_set() -> TestResult {
    let mut source = png_with_chunks(0)?;
    source.resize(32 * 1024, 0);
    let budget = MemoryBudget::new(64 * 1024);
    let working_set = budget.try_working_set(2 * 1024)?;
    let mut lease = working_set.budget().try_reserve(MemoryClass::Executor, 0)?;
    let snapshot = budget.snapshot()?;
    let free = snapshot.limit_bytes - snapshot.used_bytes - snapshot.working_sets.reserved_bytes;
    let blocker = budget.try_reserve(MemoryClass::Cache, free)?;
    let mut zip_work = 50;

    let outcome = ArtifactValidator::default().validate_with_zip_budget_and_memory(
        &source,
        &mut zip_work,
        &mut lease,
    )?;
    assert!(matches!(
        outcome,
        ArtifactValidationOutcome::Validated {
            format: ArtifactValidationFormat::Png,
            ..
        }
    ));
    assert_eq!(zip_work, 50);
    drop(outcome);
    drop(lease);
    drop(blocker);
    drop(working_set);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn corrupt_png_remains_a_checksum_rejection_without_retaining_scratch() -> TestResult {
    let mut png = png_with_chunks(0)?;
    *png.get_mut(29).ok_or("missing PNG CRC")? ^= 1;
    let budget = MemoryBudget::new(16 * 1024);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 11)?;
    let mut zip_work = 50;
    let outcome = ArtifactValidator::default().validate_with_zip_budget_and_memory(
        &png,
        &mut zip_work,
        &mut lease,
    )?;
    assert!(matches!(
        outcome,
        ArtifactValidationOutcome::Rejected {
            format: ArtifactValidationFormat::Png,
            reason: ArtifactValidationFailure::Png(PngError::InvalidChecksum { .. }),
            ..
        }
    ));
    assert_eq!(lease.bytes(), 11);
    assert_eq!(zip_work, 50);
    Ok(())
}

#[test]
fn zip_memory_pressure_precedes_member_work_and_restores_the_existing_charge() -> TestResult {
    let archive =
        zip_support::build_zip(&[zip_support::FixtureEntry::stored(b"file", b"payload")])?;
    let budget = MemoryBudget::new(20);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 7)?;
    let mut zip_work = 50;
    let result = ArtifactValidator::default().validate_with_zip_budget_and_memory(
        &archive,
        &mut zip_work,
        &mut lease,
    );
    assert!(matches!(result, Err(MemoryError::Limit { .. })));
    assert_eq!(lease.bytes(), 7);
    assert_eq!(budget.snapshot()?.used_bytes, 7);
    assert_eq!(zip_work, 50);
    Ok(())
}

#[test]
fn zip_member_and_metadata_remain_charged_while_the_report_is_live() -> TestResult {
    let archive =
        zip_support::build_zip(&[zip_support::FixtureEntry::stored(b"file", b"payload")])?;
    let budget = MemoryBudget::new(100_000);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 7)?;
    let mut zip_work = 50;
    let outcome = ArtifactValidator::default().validate_with_zip_budget_and_memory(
        &archive,
        &mut zip_work,
        &mut lease,
    )?;
    let ArtifactValidationOutcome::Validated {
        structure: ArtifactStructure::Zip(report),
        ..
    } = &outcome
    else {
        return Err("expected a validated ZIP".into());
    };
    let member = report.entries.first().ok_or("missing ZIP member")?;
    assert_eq!(member.content.as_deref(), Some(b"payload".as_slice()));
    assert!(
        lease.bytes()
            >= 7 + u64::try_from(member.content.as_ref().ok_or("missing content")?.capacity())?
    );
    assert_eq!(zip_work, 43);
    assert_eq!(budget.snapshot()?.used_bytes, lease.bytes());
    drop(outcome);
    drop(lease);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn corrupt_zip_member_still_consumes_work_and_reports_the_omission() -> TestResult {
    let archive =
        zip_support::build_zip(&[
            zip_support::FixtureEntry::stored(b"file", b"payload").with_crc(0)
        ])?;
    let budget = MemoryBudget::new(100_000);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 0)?;
    let mut zip_work = 50;
    let outcome = ArtifactValidator::default().validate_with_zip_budget_and_memory(
        &archive,
        &mut zip_work,
        &mut lease,
    )?;
    let ArtifactValidationOutcome::Validated {
        structure: ArtifactStructure::Zip(report),
        ..
    } = outcome
    else {
        return Err("expected a ZIP report".into());
    };
    assert_eq!(report.omitted_entry_count, 1);
    assert_eq!(report.extracted_entry_count, 0);
    assert_eq!(zip_work, 43);
    Ok(())
}

#[test]
fn zip_entry_limit_drops_the_discarded_report_charge() -> TestResult {
    let archive = zip_support::build_zip(&[
        zip_support::FixtureEntry::stored(b"one", b"1"),
        zip_support::FixtureEntry::stored(b"two", b"2"),
    ])?;
    let policy = ArtifactValidationPolicy {
        zip_limits: crate::artifact::zip::ZipArtifactLimits {
            max_entries: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let budget = MemoryBudget::new(100_000);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 13)?;
    let mut zip_work = 50;
    let outcome = ArtifactValidator::new(policy)?.validate_with_zip_budget_and_memory(
        &archive,
        &mut zip_work,
        &mut lease,
    )?;
    assert!(matches!(
        outcome,
        ArtifactValidationOutcome::Omitted {
            reason: ArtifactResourceOmissionReason::ZipEntryLimit {
                count: 2,
                maximum: 1
            },
            ..
        }
    ));
    assert_eq!(lease.bytes(), 13);
    assert_eq!(zip_work, 50);
    Ok(())
}

#[test]
fn valid_prefixed_zip_can_supersede_a_corrupt_png_candidate() -> TestResult {
    let mut source = png_with_chunks(0)?;
    *source.get_mut(29).ok_or("missing PNG CRC")? ^= 1;
    source.extend_from_slice(&zip_support::build_zip(&[
        zip_support::FixtureEntry::stored(b"file", b"payload"),
    ])?);
    let budget = MemoryBudget::new(100_000);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 0)?;
    let mut zip_work = 50;
    let outcome = ArtifactValidator::default().validate_with_zip_budget_and_memory(
        &source,
        &mut zip_work,
        &mut lease,
    )?;
    assert!(matches!(outcome, ArtifactValidationOutcome::Validated {
        format: ArtifactValidationFormat::Zip,
        range, ..
    } if range.length == source.len()));
    assert_eq!(zip_work, 43);
    Ok(())
}
