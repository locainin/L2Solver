use l2_workbench::artifact::zip::{
    ZipArtifactError, ZipArtifactOmissionReason, has_zip_end_record, inspect_zip,
};
use std::error::Error;

use super::zip_support::{
    DescriptorFormat, FixtureEntry, add_optional_zip64_footer, append_central_record, build_zip,
    deflate, prepend_central_record, zip64_data_descriptor_archive,
};

#[test]
fn stored_deflated_metadata_exact_bytes() -> Result<(), Box<dyn Error>> {
    let plain = b"generic stored payload";
    let compressed_plain = b"generic deflated payload";
    let entries = [
        FixtureEntry::stored(b"folder/stored.bin", plain),
        FixtureEntry::deflated(
            b"folder/deflated.bin",
            compressed_plain,
            deflate(compressed_plain)?,
        ),
    ];
    let archive = build_zip(&entries)?;

    let report = inspect_zip(&archive)?;

    assert_eq!(report.entry_count, 2);
    assert_eq!(report.entries.len(), 2);
    assert_eq!(report.extracted_entry_count, 2);
    assert_eq!(
        report.expanded_byte_count,
        plain.len() + compressed_plain.len()
    );

    let stored = report.entries.first().ok_or("stored entry is missing")?;
    assert_eq!(stored.metadata.raw_name, b"folder/stored.bin");
    assert_eq!(stored.metadata.compressed_size, u64::try_from(plain.len())?);
    assert_eq!(stored.content.as_deref(), Some(plain.as_slice()));
    assert_eq!(stored.omission, None);

    let deflated = report.entries.get(1).ok_or("deflated entry is missing")?;
    assert_eq!(deflated.metadata.raw_name, b"folder/deflated.bin");
    assert_eq!(
        deflated.content.as_deref(),
        Some(compressed_plain.as_slice())
    );
    assert_eq!(deflated.omission, None);
    Ok(())
}

#[test]
fn competing_end_not_complete_archive() -> Result<(), Box<dyn Error>> {
    let entries = [FixtureEntry::stored(b"visible.bin", b"member bytes")];
    let mut archive = build_zip(&entries)?;
    let actual_eocd = archive.len().checked_sub(22).ok_or("EOCD is missing")?;
    archive
        .get_mut(actual_eocd + 20..actual_eocd + 22)
        .ok_or("EOCD comment length is missing")?
        .copy_from_slice(&22_u16.to_le_bytes());

    // The legal comment is also an empty end record ending at EOF
    archive.extend_from_slice(b"PK\x05\x06");
    archive.extend_from_slice(&[0; 18]);

    assert!(has_zip_end_record(&archive));
    assert!(matches!(
        inspect_zip(&archive),
        Err(ZipArtifactError::AmbiguousEndRecords)
    ));
    Ok(())
}

#[test]
fn eocd_entry_central_directory_member() -> Result<(), Box<dyn Error>> {
    let entries = [
        FixtureEntry::stored(b"first.bin", b"first"),
        FixtureEntry::stored(b"second.bin", b"second"),
    ];

    for declared_count in [0_u16, 1] {
        let mut archive = build_zip(&entries)?;
        let eocd = archive.len().checked_sub(22).ok_or("EOCD is missing")?;

        // Both count fields can agree with each other while omitting real directory records
        archive
            .get_mut(eocd + 8..eocd + 10)
            .ok_or("EOCD disk entry count is missing")?
            .copy_from_slice(&declared_count.to_le_bytes());
        archive
            .get_mut(eocd + 10..eocd + 12)
            .ok_or("EOCD total entry count is missing")?
            .copy_from_slice(&declared_count.to_le_bytes());

        assert!(matches!(
            inspect_zip(&archive),
            Err(ZipArtifactError::InvalidArchive)
        ));
    }
    Ok(())
}

#[test]
fn central_directory_misordered_archive_extra() -> Result<(), Box<dyn Error>> {
    let entries = [FixtureEntry::stored(b"entry.bin", b"content")];

    let mut leading_archive_extra = build_zip(&entries)?;
    prepend_central_record(&mut leading_archive_extra, &archive_extra_record(b"extra")?)?;
    assert_eq!(
        inspect_zip(&leading_archive_extra)?.extracted_entry_count,
        1
    );

    let mut prefixed_archive_extra = leading_archive_extra.clone();
    prefixed_archive_extra.splice(0..0, b"generic archive prefix".iter().copied());
    assert_eq!(
        inspect_zip(&prefixed_archive_extra)?.extracted_entry_count,
        1
    );

    let mut optional_zip64_archive_extra = leading_archive_extra.clone();
    add_optional_zip64_footer(&mut optional_zip64_archive_extra)?;
    assert_eq!(
        inspect_zip(&optional_zip64_archive_extra)?.extracted_entry_count,
        1
    );

    let mut empty_auxiliary_directory = build_zip(&[])?;
    prepend_central_record(&mut empty_auxiliary_directory, &archive_extra_record(&[])?)?;
    append_central_record(&mut empty_auxiliary_directory, &digital_signature(&[])?)?;
    assert_eq!(inspect_zip(&empty_auxiliary_directory)?.entry_count, 0);

    let mut one_signature = build_zip(&entries)?;
    append_central_record(&mut one_signature, &digital_signature(b"one")?)?;
    assert_eq!(inspect_zip(&one_signature)?.extracted_entry_count, 1);

    let mut repeated_signatures = build_zip(&entries)?;
    let mut signatures = digital_signature(b"one")?;
    signatures.extend_from_slice(&digital_signature(b"two")?);
    append_central_record(&mut repeated_signatures, &signatures)?;
    assert!(matches!(
        inspect_zip(&repeated_signatures),
        Err(ZipArtifactError::InvalidArchive)
    ));

    let mut signature_before_members = build_zip(&entries)?;
    prepend_central_record(&mut signature_before_members, &digital_signature(b"early")?)?;
    assert!(matches!(
        inspect_zip(&signature_before_members),
        Err(ZipArtifactError::InvalidArchive)
    ));

    let mut misplaced_archive_extra = build_zip(&entries)?;
    append_central_record(
        &mut misplaced_archive_extra,
        &archive_extra_record(b"extra")?,
    )?;
    assert!(matches!(
        inspect_zip(&misplaced_archive_extra),
        Err(ZipArtifactError::InvalidArchive)
    ));
    Ok(())
}

#[test]
fn empty_zip64_without_false_ambiguity() -> Result<(), Box<dyn Error>> {
    let mut optional_zip64 = build_zip(&[])?;
    add_optional_zip64_footer(&mut optional_zip64)?;
    assert_eq!(inspect_zip(&optional_zip64)?.entry_count, 0);

    let required_zip64 = super::zip_support::zip64_count_archive(0);
    assert_eq!(inspect_zip(&required_zip64)?.entry_count, 0);
    Ok(())
}

fn digital_signature(payload: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut record = b"PK\x05\x05".to_vec();
    record.extend_from_slice(&u16::try_from(payload.len())?.to_le_bytes());
    record.extend_from_slice(payload);
    Ok(record)
}

fn archive_extra_record(payload: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut record = b"PK\x06\x08".to_vec();
    record.extend_from_slice(&u32::try_from(payload.len())?.to_le_bytes());
    record.extend_from_slice(payload);
    Ok(record)
}

#[test]
fn valid_classic_data_descriptors_retained() -> Result<(), Box<dyn Error>> {
    for (name, format) in [
        (b"signed.bin".as_slice(), DescriptorFormat::ClassicSigned),
        (
            b"unsigned.bin".as_slice(),
            DescriptorFormat::ClassicUnsigned,
        ),
    ] {
        let entries =
            [FixtureEntry::stored(name, b"descriptor bytes").with_data_descriptor(format)];
        let archive = build_zip(&entries)?;

        let report = inspect_zip(&archive)?;

        assert_eq!(report.extracted_entry_count, 1);
        assert_eq!(report.omitted_entry_count, 0);
        assert_eq!(
            report
                .entries
                .first()
                .and_then(|entry| entry.content.as_deref()),
            Some(b"descriptor bytes".as_slice())
        );
    }
    Ok(())
}

#[test]
fn valid_zip64_data_descriptors_retained() -> Result<(), Box<dyn Error>> {
    for signed in [true, false] {
        let archive = zip64_data_descriptor_archive(b"zip64.bin", b"zip64 bytes", signed)?;

        let report = inspect_zip(&archive)?;

        assert_eq!(report.entry_count, 1);
        assert_eq!(report.extracted_entry_count, 1);
        assert_eq!(report.omitted_entry_count, 0);
        assert_eq!(
            report
                .entries
                .first()
                .and_then(|entry| entry.content.as_deref()),
            Some(b"zip64 bytes".as_slice())
        );
    }
    Ok(())
}

#[test]
fn invalid_data_omissions_later_salvage() -> Result<(), Box<dyn Error>> {
    let entries = [
        FixtureEntry::stored(b"wrong-crc.bin", b"first").with_data_descriptor_values(
            DescriptorFormat::ClassicSigned,
            1,
            5,
            5,
        ),
        FixtureEntry::deflated(b"wrong-size.bin", b"second", deflate(b"second")?)
            .with_data_descriptor_values(
                DescriptorFormat::ClassicSigned,
                crc32fast::hash(b"second"),
                8,
                7,
            ),
        FixtureEntry::stored(b"valid-later.bin", b"recovered")
            .with_data_descriptor(DescriptorFormat::ClassicSigned),
    ];
    let archive = build_zip(&entries)?;

    let report = inspect_zip(&archive)?;

    assert_eq!(report.extracted_entry_count, 1);
    assert_eq!(report.omitted_entry_count, 2);
    assert_eq!(report.expanded_byte_count, b"recovered".len());
    let first = report.entries.first().ok_or("first entry is missing")?;
    assert_eq!(first.content, None);
    assert_eq!(
        first.omission,
        Some(ZipArtifactOmissionReason::EntryDataFailure {
            index: 0,
            failure: l2_workbench::artifact::zip::ZipEntryDataFailure::DataDescriptorMismatch,
        })
    );
    let second = report.entries.get(1).ok_or("second entry is missing")?;
    assert_eq!(second.content, None);
    assert_eq!(
        second.omission,
        Some(ZipArtifactOmissionReason::EntryDataFailure {
            index: 1,
            failure: l2_workbench::artifact::zip::ZipEntryDataFailure::DataDescriptorMismatch,
        })
    );
    let recovered = report.entries.get(2).ok_or("later entry is missing")?;
    assert_eq!(recovered.content.as_deref(), Some(b"recovered".as_slice()));
    Ok(())
}

#[test]
fn unsafe_member_retained_raw_metadata() -> Result<(), Box<dyn Error>> {
    let entries = [FixtureEntry::stored(b"../../outside.bin", b"payload")];
    let archive = build_zip(&entries)?;

    let report = inspect_zip(&archive)?;

    let entry = report.entries.first().ok_or("entry is missing")?;
    assert_eq!(entry.metadata.raw_name, b"../../outside.bin");
    assert_eq!(entry.content.as_deref(), Some(b"payload".as_slice()));
    Ok(())
}

#[test]
fn encrypted_unknown_entries_explicitly_omitted() -> Result<(), Box<dyn Error>> {
    let entries = [
        FixtureEntry::stored(b"encrypted.bin", b"encrypted payload").encrypted(),
        FixtureEntry::stored(b"opaque.bin", b"opaque payload").with_method(99),
    ];
    let archive = build_zip(&entries)?;

    let report = inspect_zip(&archive)?;

    let encrypted = report.entries.first().ok_or("encrypted entry is missing")?;
    assert!(encrypted.metadata.encrypted);
    assert_eq!(encrypted.content, None);
    assert_eq!(
        encrypted.omission,
        Some(ZipArtifactOmissionReason::Encrypted)
    );

    let opaque = report.entries.get(1).ok_or("opaque entry is missing")?;
    assert_eq!(opaque.content, None);
    assert_eq!(
        opaque.omission,
        Some(ZipArtifactOmissionReason::UnsupportedCompression { method: 99 })
    );
    assert_eq!(report.extracted_entry_count, 0);
    assert_eq!(report.omitted_entry_count, 2);
    assert_eq!(report.omissions.len(), 2);
    assert_eq!(
        report
            .omissions
            .first()
            .ok_or("encrypted omission is missing")?
            .reason,
        ZipArtifactOmissionReason::Encrypted
    );
    assert_eq!(
        report
            .omissions
            .get(1)
            .ok_or("unsupported-method omission is missing")?
            .reason,
        ZipArtifactOmissionReason::UnsupportedCompression { method: 99 }
    );
    assert!(report.omissions.iter().all(|omission| omission.count == 1));
    Ok(())
}

#[test]
fn corrupt_members_later_recovered() -> Result<(), Box<dyn Error>> {
    let entries = [
        FixtureEntry::stored(b"bad-crc.bin", b"payload").with_crc(0),
        FixtureEntry::deflated(b"bad-deflate.bin", b"expected output", vec![0xff]),
        FixtureEntry::stored(b"bad-size.bin", b"12345678").with_declared_sizes(8, 7),
        FixtureEntry::stored(b"good.bin", b"recovered payload"),
    ];
    let archive = build_zip(&entries)?;

    let report = inspect_zip(&archive)?;

    assert_eq!(report.entries.len(), 4);
    assert_eq!(report.extracted_entry_count, 1);
    assert_eq!(report.omitted_entry_count, 3);
    assert_eq!(report.expanded_byte_count, b"recovered payload".len());
    assert_eq!(report.omissions.len(), 3);
    assert!(report.omissions.iter().all(|omission| omission.count == 1));

    for (entry, failure) in
        report
            .entries
            .iter()
            .zip(["crc_mismatch", "decompression_failure", "size_mismatch"])
    {
        assert_eq!(entry.content, None);
        let omission = serde_json::to_value(entry.omission)?;
        assert_eq!(
            omission,
            serde_json::json!({
                "entry_data_failure": {
                    "index": entry.metadata.index,
                    "failure": failure,
                }
            })
        );
    }
    assert_eq!(
        report
            .omissions
            .iter()
            .map(serde_json::to_value)
            .collect::<Result<Vec<_>, _>>()?,
        [
            serde_json::json!({
                "reason": {
                    "entry_data_failure": {
                        "index": 0,
                        "failure": "crc_mismatch",
                    }
                },
                "count": 1,
            }),
            serde_json::json!({
                "reason": {
                    "entry_data_failure": {
                        "index": 1,
                        "failure": "decompression_failure",
                    }
                },
                "count": 1,
            }),
            serde_json::json!({
                "reason": {
                    "entry_data_failure": {
                        "index": 2,
                        "failure": "size_mismatch",
                    }
                },
                "count": 1,
            }),
        ]
    );

    let recovered = report.entries.get(3).ok_or("healthy entry is missing")?;
    assert_eq!(
        recovered.content.as_deref(),
        Some(b"recovered payload".as_slice())
    );
    assert_eq!(recovered.omission, None);
    Ok(())
}

#[test]
fn inconsistent_member_preserves_later_entries() -> Result<(), Box<dyn Error>> {
    let entries = [
        FixtureEntry::stored(b"first.dat", b"first bytes"),
        FixtureEntry::stored(b"second.dat", b"second bytes"),
    ];
    let mut archive = build_zip(&entries)?;
    let local_method = archive
        .get_mut(8..10)
        .ok_or("first local compression method is missing")?;
    local_method.copy_from_slice(&8_u16.to_le_bytes());

    let report = inspect_zip(&archive)?;

    let first = report.entries.first().ok_or("first entry is missing")?;
    assert_eq!(first.content, None);
    assert_eq!(
        first.omission,
        Some(ZipArtifactOmissionReason::EntryDataFailure {
            index: 0,
            failure: l2_workbench::artifact::zip::ZipEntryDataFailure::InvalidEntryHeader,
        })
    );
    let second = report.entries.get(1).ok_or("second entry is missing")?;
    assert_eq!(second.content.as_deref(), Some(b"second bytes".as_slice()));
    assert_eq!(second.omission, None);
    assert_eq!(report.extracted_entry_count, 1);
    assert_eq!(report.omitted_entry_count, 1);
    Ok(())
}

#[test]
fn truncated_archive_is_rejected() -> Result<(), Box<dyn Error>> {
    let entries = [FixtureEntry::stored(b"truncated.bin", b"payload")];
    let mut archive = build_zip(&entries)?;
    archive.truncate(archive.len().saturating_sub(8));

    assert!(matches!(
        inspect_zip(&archive),
        Err(ZipArtifactError::InvalidArchive)
    ));
    Ok(())
}

#[test]
fn truncated_member_data_is_rejected() -> Result<(), Box<dyn Error>> {
    let entries =
        [FixtureEntry::stored(b"truncated-member.bin", b"payload").with_declared_sizes(8, 8)];
    let archive = build_zip(&entries)?;

    assert!(matches!(
        inspect_zip(&archive),
        Err(ZipArtifactError::InvalidArchive)
    ));
    Ok(())
}
