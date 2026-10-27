use super::zip_support::{FixtureEntry, build_zip, deflate};
use l2_workbench::{
    artifact::zip::{
        ZipArtifactEntry, ZipArtifactLimits, ZipMemoryError, ZipReadError, ZipReaderBudget,
        ZipReaderLimits, inspect_zip_at_depth_with_memory,
        inspect_zip_from_reader_with_source_sha256_and_memory,
    },
    job::{MemoryBudget, MemoryClass, MemoryError},
};
use std::{error::Error, io::Cursor};

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn zip_member_memory_pressure_precedes_extraction_and_work_charges() -> TestResult {
    let archive = build_zip(&[FixtureEntry::stored(b"file", b"payload")])?;
    let budget = MemoryBudget::new(6);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 0)?;
    let mut work_remaining = 100;
    let result = inspect_zip_at_depth_with_memory(
        &archive,
        ZipArtifactLimits::default(),
        0,
        &mut work_remaining,
        &mut lease,
    );
    assert!(matches!(
        result,
        Err(ZipMemoryError::Memory(MemoryError::Limit { .. }))
    ));
    assert_eq!(work_remaining, 100);
    assert_eq!(lease.bytes(), 0);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn zip_member_output_stays_charged_until_the_caller_releases_it() -> TestResult {
    let archive = build_zip(&[FixtureEntry::stored(b"file", b"payload")])?;
    let budget = MemoryBudget::new(100_000);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 0)?;
    let mut work_remaining = 100;
    let report = inspect_zip_at_depth_with_memory(
        &archive,
        ZipArtifactLimits::default(),
        0,
        &mut work_remaining,
        &mut lease,
    )?;
    assert_eq!(
        report
            .entries
            .first()
            .and_then(|entry| entry.content.as_deref()),
        Some(b"payload".as_slice())
    );
    let minimum = 64 + std::mem::size_of::<ZipArtifactEntry>() + b"file".len() + b"payload".len();
    assert!(lease.bytes() >= u64::try_from(minimum)?);
    assert_eq!(work_remaining, 93);
    drop(report);
    drop(lease);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn rejected_member_releases_its_output_charge_but_keeps_work_charged() -> TestResult {
    let content = b"payload";
    let archive =
        build_zip(&[FixtureEntry::deflated(b"bad", content, deflate(content)?).with_crc(0)])?;
    let budget = MemoryBudget::new(100_000);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 0)?;
    let mut work_remaining = 100;
    let report = inspect_zip_at_depth_with_memory(
        &archive,
        ZipArtifactLimits::default(),
        0,
        &mut work_remaining,
        &mut lease,
    )?;
    assert_eq!(report.extracted_entry_count, 0);
    assert_eq!(work_remaining, 93);
    assert!(lease.bytes() > 0);
    Ok(())
}

#[test]
fn zip_admission_counts_only_members_allowed_by_the_operation_work_budget() -> TestResult {
    let archive = build_zip(&[
        FixtureEntry::stored(b"first", b"one"),
        FixtureEntry::stored(b"second", b"two"),
    ])?;
    let budget = MemoryBudget::new(100_000);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 0)?;
    let mut work_remaining = 5;
    let report = inspect_zip_at_depth_with_memory(
        &archive,
        ZipArtifactLimits::default(),
        0,
        &mut work_remaining,
        &mut lease,
    )?;
    assert_eq!(report.extracted_entry_count, 1);
    assert_eq!(report.omitted_entry_count, 1);
    assert_eq!(work_remaining, 2);
    assert!(lease.bytes() >= 3);
    Ok(())
}

#[test]
fn zip_admission_preserves_an_existing_charge_when_more_output_is_denied() -> TestResult {
    let archive = build_zip(&[FixtureEntry::stored(b"file", b"payload")])?;
    let budget = MemoryBudget::new(100_000);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 10)?;
    let mut work_remaining = 100;
    let first = inspect_zip_at_depth_with_memory(
        &archive,
        ZipArtifactLimits::default(),
        0,
        &mut work_remaining,
        &mut lease,
    )?;
    let retained = lease.bytes();
    let blocker = budget.try_reserve(MemoryClass::Publication, 100_000 - retained)?;
    let second = inspect_zip_at_depth_with_memory(
        &archive,
        ZipArtifactLimits::default(),
        0,
        &mut work_remaining,
        &mut lease,
    );
    assert!(matches!(
        second,
        Err(ZipMemoryError::Memory(MemoryError::Limit { .. }))
    ));
    assert_eq!(lease.bytes(), retained);
    assert_eq!(work_remaining, 93);
    drop(first);
    drop(blocker);
    lease.try_resize(10)?;
    assert_eq!(budget.snapshot()?.used_bytes, 10);
    Ok(())
}

#[test]
fn seekable_zip_memory_pressure_is_typed_and_does_not_charge_expansion_work() -> TestResult {
    let archive = build_zip(&[FixtureEntry::stored(b"file", b"payload")])?;
    let memory = MemoryBudget::new(0);
    let mut lease = memory.try_reserve(MemoryClass::Executor, 0)?;
    let mut work = ZipReaderBudget {
        read_bytes_remaining: 4096,
        expanded_bytes_remaining: 100,
    };
    let result = inspect_zip_from_reader_with_source_sha256_and_memory(
        &mut Cursor::new(&archive),
        archive.len(),
        &l2_workbench::sha256(&archive),
        ZipReaderLimits::default(),
        0,
        &mut work,
        &mut lease,
    );
    assert!(matches!(
        result,
        Err(ZipReadError::Memory(MemoryError::Limit { .. }))
    ));
    assert_eq!(work.expanded_bytes_remaining, 100);
    assert_eq!(lease.bytes(), 0);
    Ok(())
}

#[test]
fn seekable_zip_read_limit_releases_scratch_without_charging_member_work() -> TestResult {
    let archive = build_zip(&[FixtureEntry::stored(b"file", b"payload")])?;
    let memory = MemoryBudget::new(100_000);
    let mut lease = memory.try_reserve(MemoryClass::Executor, 0)?;
    let mut work = ZipReaderBudget {
        read_bytes_remaining: 8,
        expanded_bytes_remaining: 100,
    };
    let result = inspect_zip_from_reader_with_source_sha256_and_memory(
        &mut Cursor::new(&archive),
        archive.len(),
        &l2_workbench::sha256(&archive),
        ZipReaderLimits::default(),
        0,
        &mut work,
        &mut lease,
    );
    assert!(matches!(result, Err(ZipReadError::WorkLimit { .. })));
    assert_eq!(work.expanded_bytes_remaining, 100);
    assert_eq!(lease.bytes(), 0);
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn seekable_zip_member_output_and_metadata_remain_charged_until_release() -> TestResult {
    let archive = build_zip(&[FixtureEntry::stored(b"file", b"payload")])?;
    let memory = MemoryBudget::new(1_000_000);
    let mut lease = memory.try_reserve(MemoryClass::Executor, 0)?;
    let mut work = ZipReaderBudget {
        read_bytes_remaining: 4096,
        expanded_bytes_remaining: 100,
    };
    let report = inspect_zip_from_reader_with_source_sha256_and_memory(
        &mut Cursor::new(&archive),
        archive.len(),
        &l2_workbench::sha256(&archive),
        ZipReaderLimits::default(),
        0,
        &mut work,
        &mut lease,
    )?;
    assert_eq!(
        report
            .entries
            .first()
            .and_then(|entry| entry.content.as_deref()),
        Some(b"payload".as_slice())
    );
    let minimum = 64 + std::mem::size_of::<ZipArtifactEntry>() + b"file".len() + b"payload".len();
    assert!(lease.bytes() >= u64::try_from(minimum)?);
    assert_eq!(work.expanded_bytes_remaining, 93);
    drop(report);
    drop(lease);
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn deflate_input_buffer_is_admitted_before_member_work() -> TestResult {
    let payload = b"payload";
    let compressed = build_zip(&[FixtureEntry::deflated(b"file", payload, deflate(payload)?)])?;
    let memory = MemoryBudget::new(8 * 1024);
    let mut lease = memory.try_reserve(MemoryClass::Executor, 0)?;
    let mut work = 100;
    let result = inspect_zip_at_depth_with_memory(
        &compressed,
        ZipArtifactLimits::default(),
        0,
        &mut work,
        &mut lease,
    );
    assert!(matches!(
        result,
        Err(ZipMemoryError::Memory(MemoryError::Limit { .. }))
    ));
    assert_eq!(work, 100);
    assert_eq!(lease.bytes(), 0);
    let stored = build_zip(&[FixtureEntry::stored(b"file", payload)])?;
    let report = inspect_zip_at_depth_with_memory(
        &stored,
        ZipArtifactLimits::default(),
        0,
        &mut work,
        &mut lease,
    )?;
    assert_eq!(report.extracted_entry_count, 1);
    assert_eq!(work, 93);
    Ok(())
}

#[test]
fn admitted_reader_and_slice_keep_identical_member_and_work_results() -> TestResult {
    let broken = b"broken";
    let archive = build_zip(&[
        FixtureEntry::deflated(b"bad", broken, deflate(broken)?).with_crc(0),
        FixtureEntry::stored(b"good", b"payload"),
    ])?;
    let memory = MemoryBudget::new(1_000_000);
    let mut slice_lease = memory.try_reserve(MemoryClass::Executor, 0)?;
    let mut reader_lease = memory.try_reserve(MemoryClass::Executor, 0)?;
    let mut slice_work = 100;
    let mut reader_work = ZipReaderBudget {
        read_bytes_remaining: 4096,
        expanded_bytes_remaining: 100,
    };
    let slice = inspect_zip_at_depth_with_memory(
        &archive,
        ZipArtifactLimits::default(),
        0,
        &mut slice_work,
        &mut slice_lease,
    )?;
    let reader = inspect_zip_from_reader_with_source_sha256_and_memory(
        &mut Cursor::new(&archive),
        archive.len(),
        &l2_workbench::sha256(&archive),
        ZipReaderLimits::default(),
        0,
        &mut reader_work,
        &mut reader_lease,
    )?;
    assert_eq!(slice, reader);
    assert_eq!(slice_work, reader_work.expanded_bytes_remaining);
    assert_eq!(slice.extracted_entry_count, 1);
    assert_eq!(slice.omitted_entry_count, 1);
    drop(slice);
    drop(reader);
    drop(slice_lease);
    drop(reader_lease);
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    Ok(())
}
