use super::{TestResult, zip_support};
use crate::{
    artifact::zip::has_zip_end_record_with_memory,
    job::{MemoryBudget, MemoryClass, MemoryError},
};

#[test]
fn zip64_search_admits_overlapping_tail_and_scan_buffers() -> TestResult {
    let mut source = vec![0; 70_000];
    source.extend_from_slice(&zip_support::zip64_count_archive(0));
    let budget = MemoryBudget::new(70_000);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 13)?;
    let result = has_zip_end_record_with_memory(&source, &mut lease);
    assert!(matches!(result, Err(MemoryError::Limit { .. })));
    assert_eq!(lease.bytes(), 13);
    assert_eq!(budget.snapshot()?.used_bytes, 13);
    Ok(())
}

#[test]
fn zip64_detector_recognizes_a_prefixed_footer_and_releases_scratch() -> TestResult {
    let mut source = vec![0; 70_000];
    source.extend_from_slice(&zip_support::zip64_count_archive(0));
    let budget = MemoryBudget::new(200_000);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 13)?;
    assert!(has_zip_end_record_with_memory(&source, &mut lease)?);
    assert_eq!(lease.bytes(), 13);
    assert_eq!(budget.snapshot()?.used_bytes, 13);
    Ok(())
}

#[test]
fn missing_zip_end_record_does_not_produce_a_candidate() -> TestResult {
    let source = b"ordinary bytes";
    let budget = MemoryBudget::new(1_024);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 0)?;
    assert!(!has_zip_end_record_with_memory(source, &mut lease)?);
    assert_eq!(lease.bytes(), 0);
    Ok(())
}
