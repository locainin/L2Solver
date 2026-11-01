use super::{TestResult, png_with_chunks};
use crate::{
    artifact::{
        PngChunk, PngError, PngLimits, PngRangeChunk, PngReadError, png::parse_png_optional_memory,
    },
    job::{MemoryBudget, MemoryClass, MemoryError},
};
use std::mem::size_of;

#[test]
fn simultaneous_range_and_slice_reports_require_separate_admission() -> TestResult {
    let png = png_with_chunks(0)?;
    let range_capacity = 4 * size_of::<PngRangeChunk>();
    let borrowed_capacity = 2 * size_of::<PngChunk<'_>>();
    let budget = MemoryBudget::new(7 + u64::try_from(range_capacity + borrowed_capacity - 1)?);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 7)?;
    let result = parse_png_optional_memory(&png, PngLimits::default(), Some(&mut lease));
    assert!(matches!(
        result,
        Err(PngReadError::Memory(MemoryError::Limit { .. }))
    ));
    assert!(budget.snapshot()?.peak_bytes >= 7 + u64::try_from(range_capacity)?);
    assert_eq!(lease.bytes(), 7);
    assert_eq!(budget.snapshot()?.used_bytes, 7);
    Ok(())
}

#[test]
fn png_slice_report_keeps_only_its_own_vector_charged() -> TestResult {
    let png = png_with_chunks(2)?;
    let budget = MemoryBudget::new(16 * 1024);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 11)?;
    let report = parse_png_optional_memory(&png, PngLimits::default(), Some(&mut lease))?;
    let report_bytes = report.chunks.capacity() * size_of::<PngChunk<'_>>();
    assert_eq!(report.chunks.len(), 4);
    assert_eq!(lease.bytes(), 11 + u64::try_from(report_bytes)?);
    assert_eq!(budget.snapshot()?.used_bytes, lease.bytes());
    drop(report);
    drop(lease);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn corrupt_later_chunk_releases_earlier_range_metadata() -> TestResult {
    let mut png = png_with_chunks(0)?;
    *png.last_mut().ok_or("missing IEND CRC")? ^= 1;
    let budget = MemoryBudget::new(16 * 1024);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 11)?;
    let result = parse_png_optional_memory(&png, PngLimits::default(), Some(&mut lease));
    assert!(matches!(
        result,
        Err(PngReadError::Format(PngError::InvalidChecksum { .. }))
    ));
    assert!(budget.snapshot()?.peak_bytes > 11);
    assert_eq!(lease.bytes(), 11);
    assert_eq!(budget.snapshot()?.used_bytes, 11);
    Ok(())
}
