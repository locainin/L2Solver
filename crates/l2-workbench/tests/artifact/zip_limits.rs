use l2_workbench::artifact::zip::{
    MAX_ZIP_DEPTH, MAX_ZIP_ENTRIES, ZipArtifactLimits, ZipArtifactOmissionReason,
    ZipEntryDataFailure, inspect_zip_at_depth, inspect_zip_at_depth_with_operation_budget,
    inspect_zip_with_limits,
};
use std::error::Error;

use super::zip_support::{FixtureEntry, build_zip, deflate, zip64_count_archive};

#[test]
fn per_entry_limit_metadata_omission() -> Result<(), Box<dyn Error>> {
    let entries = [FixtureEntry::stored(b"large.bin", b"12345")];
    let archive = build_zip(&entries)?;
    let limits = ZipArtifactLimits {
        max_entry_expanded_bytes: 4,
        ..ZipArtifactLimits::default()
    };

    let report = inspect_zip_with_limits(&archive, limits)?;

    let entry = report.entries.first().ok_or("entry metadata is missing")?;
    assert_eq!(entry.metadata.raw_name, b"large.bin");
    assert_eq!(entry.content, None);
    assert_eq!(
        entry.omission,
        Some(ZipArtifactOmissionReason::EntryExpandedByteLimit)
    );
    assert_eq!(report.expanded_byte_count, 0);
    assert_eq!(report.omitted_entry_count, 1);
    Ok(())
}

#[test]
fn cumulative_expansion_omits_later_entries() -> Result<(), Box<dyn Error>> {
    let entries = [
        FixtureEntry::stored(b"first.bin", b"123"),
        FixtureEntry::stored(b"second.bin", b"456"),
    ];
    let archive = build_zip(&entries)?;
    let limits = ZipArtifactLimits {
        max_total_expanded_bytes: 5,
        ..ZipArtifactLimits::default()
    };

    let report = inspect_zip_with_limits(&archive, limits)?;

    let first = report.entries.first().ok_or("first entry is missing")?;
    assert_eq!(first.content.as_deref(), Some(b"123".as_slice()));
    let second = report.entries.get(1).ok_or("second entry is missing")?;
    assert_eq!(second.content, None);
    assert_eq!(
        second.omission,
        Some(ZipArtifactOmissionReason::TotalExpandedByteLimit)
    );
    assert_eq!(report.expanded_byte_count, 3);
    assert_eq!(report.omitted_entry_count, 1);
    Ok(())
}

#[test]
fn failed_crc_uses_archive_budget() -> Result<(), Box<dyn Error>> {
    let corrupt_content = b"123";
    let entries = [
        FixtureEntry::deflated(b"corrupt.bin", corrupt_content, deflate(corrupt_content)?)
            .with_crc(0),
        FixtureEntry::stored(b"later.bin", b"456"),
    ];
    let archive = build_zip(&entries)?;
    let limits = ZipArtifactLimits {
        max_total_expanded_bytes: 5,
        ..ZipArtifactLimits::default()
    };

    let report = inspect_zip_with_limits(&archive, limits)?;

    let corrupt = report.entries.first().ok_or("corrupt entry is missing")?;
    assert_eq!(
        corrupt.omission,
        Some(ZipArtifactOmissionReason::EntryDataFailure {
            index: 0,
            failure: ZipEntryDataFailure::CrcMismatch,
        })
    );
    let later = report.entries.get(1).ok_or("later entry is missing")?;
    assert_eq!(later.content, None);
    assert_eq!(
        later.omission,
        Some(ZipArtifactOmissionReason::TotalExpandedByteLimit)
    );
    assert_eq!(report.expanded_byte_count, 0);
    assert_eq!(report.expanded_work_byte_count, corrupt_content.len());
    Ok(())
}

#[test]
fn failed_crc_uses_shared_budget() -> Result<(), Box<dyn Error>> {
    let corrupt_content = b"123";
    let corrupt_archive = build_zip(&[FixtureEntry::deflated(
        b"corrupt.bin",
        corrupt_content,
        deflate(corrupt_content)?,
    )
    .with_crc(0)])?;
    let later_archive = build_zip(&[FixtureEntry::stored(b"later.bin", b"456")])?;
    let limits = ZipArtifactLimits {
        max_total_expanded_bytes: 5,
        ..ZipArtifactLimits::default()
    };
    let mut remaining = 5;

    let failed =
        inspect_zip_at_depth_with_operation_budget(&corrupt_archive, limits, 0, &mut remaining)?;

    assert_eq!(failed.expanded_byte_count, 0);
    assert_eq!(failed.expanded_work_byte_count, corrupt_content.len());
    assert_eq!(remaining, 2);
    let blocked =
        inspect_zip_at_depth_with_operation_budget(&later_archive, limits, 1, &mut remaining)?;
    assert_eq!(remaining, 2);
    assert_eq!(blocked.expanded_work_byte_count, 0);
    let blocked_entry = blocked.entries.first().ok_or("later member is missing")?;
    assert_eq!(blocked_entry.content, None);
    assert_eq!(
        blocked_entry.omission,
        Some(ZipArtifactOmissionReason::OperationExpandedByteLimit)
    );
    Ok(())
}

#[test]
fn zero_total_budget_omits_data() -> Result<(), Box<dyn Error>> {
    let entries = [
        FixtureEntry::stored(b"empty.bin", b""),
        FixtureEntry::stored(b"payload.bin", b"x"),
    ];
    let archive = build_zip(&entries)?;
    let limits = ZipArtifactLimits {
        max_total_expanded_bytes: 0,
        ..ZipArtifactLimits::default()
    };

    let report = inspect_zip_with_limits(&archive, limits)?;

    assert_eq!(report.extracted_entry_count, 1);
    assert_eq!(report.expanded_byte_count, 0);
    assert_eq!(report.omitted_entry_count, 1);
    let empty = report.entries.first().ok_or("empty member is missing")?;
    assert_eq!(empty.content.as_deref(), Some(b"".as_slice()));
    let payload = report.entries.get(1).ok_or("payload member is missing")?;
    assert_eq!(payload.content, None);
    assert_eq!(
        payload.omission,
        Some(ZipArtifactOmissionReason::TotalExpandedByteLimit)
    );
    Ok(())
}

#[test]
fn entry_count_limit_aggregate_omission() -> Result<(), Box<dyn Error>> {
    let entries = [
        FixtureEntry::stored(b"one.bin", b"1"),
        FixtureEntry::stored(b"two.bin", b"2"),
        FixtureEntry::stored(b"three.bin", b"3"),
    ];
    let archive = build_zip(&entries)?;
    let limits = ZipArtifactLimits {
        max_entries: 2,
        ..ZipArtifactLimits::default()
    };

    let report = inspect_zip_with_limits(&archive, limits)?;

    assert_eq!(report.entry_count, 3);
    assert_eq!(report.entries.len(), 0);
    assert_eq!(report.omitted_entry_count, 3);
    assert!(report.omissions.iter().any(|omission| {
        omission.reason == ZipArtifactOmissionReason::EntryCountLimit && omission.count == 3
    }));
    Ok(())
}

#[test]
fn archive_size_limit_oversized_input() -> Result<(), Box<dyn Error>> {
    let entries = [FixtureEntry::stored(b"small.bin", b"x")];
    let archive = build_zip(&entries)?;
    let limits = ZipArtifactLimits {
        max_archive_bytes: archive.len().saturating_sub(1),
        ..ZipArtifactLimits::default()
    };

    assert!(inspect_zip_with_limits(&archive, limits).is_err());
    Ok(())
}

#[test]
fn excessive_nested_omits_archive_contents() -> Result<(), Box<dyn Error>> {
    let entries = [FixtureEntry::stored(
        b"nested.zip",
        b"opaque nested archive",
    )];
    let archive = build_zip(&entries)?;
    let limits = ZipArtifactLimits {
        max_depth: 1,
        ..ZipArtifactLimits::default()
    };

    let report = inspect_zip_at_depth(&archive, limits, 2)?;

    assert_eq!(report.entries.len(), 0);
    assert_eq!(report.entry_count, 1);
    assert_eq!(report.omitted_entry_count, 1);
    assert!(report.omissions.iter().any(|omission| {
        omission.reason == ZipArtifactOmissionReason::DepthLimit && omission.count == 1
    }));
    Ok(())
}

#[test]
fn zero_depth_omits_nested_archives() -> Result<(), Box<dyn Error>> {
    let entries = [FixtureEntry::stored(b"small.bin", b"x")];
    let archive = build_zip(&entries)?;
    let limits = ZipArtifactLimits {
        max_depth: 0,
        ..ZipArtifactLimits::default()
    };

    let top_level = inspect_zip_at_depth(&archive, limits, 0)?;
    let nested = inspect_zip_at_depth(&archive, limits, 1)?;

    assert_eq!(top_level.extracted_entry_count, 1);
    assert_eq!(nested.entries.len(), 0);
    assert!(nested.omissions.iter().any(|omission| {
        omission.reason == ZipArtifactOmissionReason::DepthLimit && omission.count == 1
    }));
    Ok(())
}

#[test]
fn very_large_without_allocations() -> Result<(), Box<dyn Error>> {
    let entries = [FixtureEntry::stored(b"small.bin", b"x")];
    let archive = build_zip(&entries)?;
    let depth = MAX_ZIP_DEPTH.saturating_add(1);
    let limits = ZipArtifactLimits {
        max_archive_bytes: usize::MAX,
        max_entries: usize::MAX,
        max_entry_expanded_bytes: usize::MAX,
        max_total_expanded_bytes: usize::MAX,
        max_depth: usize::MAX,
    };

    let report = inspect_zip_at_depth(&archive, limits, depth)?;

    assert_eq!(report.entries.len(), 1);
    assert_eq!(report.extracted_entry_count, 1);
    Ok(())
}

#[test]
fn zero_operational_limits_are_rejected() -> Result<(), Box<dyn Error>> {
    let entries = [FixtureEntry::stored(b"small.bin", b"x")];
    let archive = build_zip(&entries)?;
    let zero_limits = [
        ZipArtifactLimits {
            max_archive_bytes: 0,
            ..ZipArtifactLimits::default()
        },
        ZipArtifactLimits {
            max_entries: 0,
            ..ZipArtifactLimits::default()
        },
        ZipArtifactLimits {
            max_entry_expanded_bytes: 0,
            ..ZipArtifactLimits::default()
        },
    ];

    for limits in zero_limits {
        assert!(inspect_zip_with_limits(&archive, limits).is_err());
    }
    Ok(())
}

#[test]
fn inconsistent_single_entry_counts_rejected() -> Result<(), Box<dyn Error>> {
    let entries = [FixtureEntry::stored(b"small.bin", b"x")];
    let mut archive = build_zip(&entries)?;
    let count_offset = archive
        .len()
        .checked_sub(14)
        .ok_or("ZIP end record is missing")?;
    let count_end = count_offset
        .checked_add(2)
        .ok_or("ZIP end record offset overflowed")?;
    let entry_count_on_disk = archive
        .get_mut(count_offset..count_end)
        .ok_or("ZIP entry count is missing")?;
    entry_count_on_disk.copy_from_slice(&u16::MAX.to_le_bytes());

    assert!(matches!(
        inspect_zip_with_limits(&archive, ZipArtifactLimits::default()),
        Err(l2_workbench::artifact::zip::ZipArtifactError::InvalidArchive)
    ));
    Ok(())
}

#[test]
fn zip64_entry_reported_directory_allocation() -> Result<(), Box<dyn Error>> {
    let count = MAX_ZIP_ENTRIES.saturating_add(1);
    let entry_count = u64::try_from(count)?;
    let archive = zip64_count_archive(entry_count);

    let report = inspect_zip_with_limits(&archive, ZipArtifactLimits::default())?;

    assert_eq!(report.entry_count, count);
    assert_eq!(report.entries.len(), 0);
    assert_eq!(report.omitted_entry_count, count);
    assert!(report.omissions.iter().any(|omission| {
        omission.reason == ZipArtifactOmissionReason::EntryCountLimit && omission.count == count
    }));
    Ok(())
}
