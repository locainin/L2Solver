use super::zip_support::{FixtureEntry, build_zip, deflate};
use l2_workbench::{
    artifact::zip::{
        ZipArtifactEntry, ZipArtifactLimits, ZipArtifactOmissionReason, ZipEntryDataFailure,
        ZipMemoryError, ZipReadError, ZipReaderBudget, ZipReaderLimits,
        inspect_zip_at_depth_with_memory, inspect_zip_from_reader_with_source_sha256_and_memory,
    },
    job::{MemoryBudget, MemoryClass, MemoryError},
};
use std::{error::Error, io::Cursor};

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn high_expansion_members_remain_bounded_even_with_a_forged_size() -> TestResult {
    const EXPANDED: usize = 8 * 1024 * 1024;
    const LIMIT: usize = 64 * 1024;
    const FORGED_SIZE: usize = 32 * 1024;
    const MEMORY_LIMIT: u64 = 512 * 1024;
    const LATER_CONTENT: &[u8] = b"recoverable member";

    let payload = vec![0_u8; EXPANDED];
    let compressed = deflate(&payload)?;
    assert!(compressed.len() < EXPANDED / 100);
    for forged in [false, true] {
        let mut member = FixtureEntry::deflated(b"large.bin", &payload, compressed.clone());
        if forged {
            // Keep both ZIP headers consistent while understating the decoder output
            member = member.with_declared_sizes(compressed.len(), FORGED_SIZE);
        }
        // A small later member must remain recoverable after the rejected expansion
        let archive = build_zip(&[member, FixtureEntry::stored(b"later.txt", LATER_CONTENT)])?;
        let memory = MemoryBudget::new(MEMORY_LIMIT);
        let mut lease = memory.try_reserve(MemoryClass::Executor, 0)?;
        let mut work = ZipReaderBudget {
            read_bytes_remaining: 1024 * 1024,
            expanded_bytes_remaining: LIMIT,
        };
        let limits = ZipReaderLimits {
            archive: ZipArtifactLimits {
                max_entry_expanded_bytes: LIMIT,
                max_total_expanded_bytes: LIMIT,
                ..ZipArtifactLimits::default()
            },
            ..ZipReaderLimits::default()
        };
        let report = inspect_zip_from_reader_with_source_sha256_and_memory(
            &mut Cursor::new(&archive),
            archive.len(),
            &l2_workbench::sha256(&archive),
            limits,
            0,
            &mut work,
            &mut lease,
        )?;
        let entry = report.entries.first().ok_or("archive member missing")?;
        assert_eq!(entry.content, None);
        let later = report
            .entries
            .get(1)
            .ok_or("later archive member missing")?;
        assert_eq!(later.content.as_deref(), Some(LATER_CONTENT));
        let (omission, charged) = if forged {
            (
                ZipArtifactOmissionReason::EntryDataFailure {
                    index: 0,
                    failure: ZipEntryDataFailure::SizeMismatch,
                },
                FORGED_SIZE,
            )
        } else {
            (ZipArtifactOmissionReason::EntryExpandedByteLimit, 0)
        };
        assert_eq!(entry.omission, Some(omission));
        assert_eq!(report.expanded_byte_count, LATER_CONTENT.len());
        assert_eq!(
            report.expanded_work_byte_count,
            charged + LATER_CONTENT.len()
        );
        assert_eq!(
            work.expanded_bytes_remaining,
            LIMIT - charged - LATER_CONTENT.len()
        );
        assert!(memory.snapshot()?.peak_bytes <= MEMORY_LIMIT);
    }
    Ok(())
}

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
