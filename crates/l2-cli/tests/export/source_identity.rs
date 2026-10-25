use super::{
    ArtifactCollection, ArtifactLimits, capture_identity_matches, collect_matching_tshark_snapshot,
    summary_text, tshark_is_complete,
};
use crate::workbench::{
    ExportObjectSet, ObjectExportBudget, ObjectExportStatus, ObjectExportUsage,
    full_source::SourceCoverage,
};
use l2_workbench::{sha256, tshark::SourceIdentity};

#[test]
fn accepts_matching_capture_identity() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = b"capture bytes";
    let digest = sha256(bytes);
    let source = source_coverage(bytes, &digest)?;
    let identity = SourceIdentity {
        label: String::from("capture.pcap"),
        length: u64::try_from(bytes.len())?,
        sha256: digest,
    };

    assert!(capture_identity_matches(&source, &identity));
    Ok(())
}

#[test]
fn rejects_different_capture_identity() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = b"capture bytes";
    let source = source_coverage(bytes, &sha256(bytes))?;
    let identity = SourceIdentity {
        label: String::from("capture.pcap"),
        length: u64::try_from(bytes.len())?,
        sha256: sha256(b"changed capture bytes"),
    };

    assert!(!capture_identity_matches(&source, &identity));
    Ok(())
}

#[test]
fn mismatch_omits_tshark_objects() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = b"capture bytes";
    let source = source_coverage(bytes, &sha256(bytes))?;
    let identity = SourceIdentity {
        label: String::from("capture.pcap"),
        length: u64::try_from(bytes.len())?,
        sha256: sha256(b"changed capture bytes"),
    };
    let temporary = tempfile::tempdir()?;
    let missing_directory = temporary.path().join("must-not-be-read");
    let mut artifacts = ArtifactCollection::new(temporary.path(), ArtifactLimits::default())?;
    let objects = ExportObjectSet {
        temporary_directory: tempfile::tempdir()?,
        directories: vec![(String::from("http"), missing_directory)],
        partial_directories: Vec::new(),
        source_identity: identity,
        budget: ObjectExportBudget {
            temporary_bytes: 1,
            temporary_files: 1,
        },
        usage: ObjectExportUsage {
            temporary_bytes_peak: 2,
            temporary_files_peak: 1,
            temporary_tree_entries_peak: 1,
            protocol_directory_count: 0,
            temporary_scan_complete: false,
        },
        status: ObjectExportStatus::Complete,
        issues: Vec::new(),
    };

    let (objects, issue) = collect_matching_tshark_snapshot(&source, &objects, &mut artifacts)?;

    assert_eq!(objects.objects_exported, 0);
    assert_eq!(artifacts.coverage().references_selected, 0);
    assert!(
        issue
            .as_deref()
            .is_some_and(|message| message.contains("capture changed"))
    );
    Ok(())
}

#[test]
fn partial_tshark_export_does_not_publish_unfinished_objects()
-> Result<(), Box<dyn std::error::Error>> {
    let bytes = b"capture bytes";
    let digest = sha256(bytes);
    let source = source_coverage(bytes, &digest)?;
    let temporary = tempfile::tempdir()?;
    let staging = temporary.path().join("staging");
    let object_directory = temporary.path().join("objects");
    std::fs::create_dir(&staging)?;
    std::fs::create_dir(&object_directory)?;
    std::fs::write(object_directory.join("partial.bin"), b"not proven complete")?;
    let mut artifacts = ArtifactCollection::new(&staging, ArtifactLimits::default())?;
    let objects = ExportObjectSet {
        temporary_directory: tempfile::tempdir()?,
        directories: vec![(String::from("http"), object_directory)],
        partial_directories: Vec::new(),
        source_identity: SourceIdentity {
            label: String::from("capture.pcap"),
            length: u64::try_from(bytes.len())?,
            sha256: digest,
        },
        budget: ObjectExportBudget::default(),
        usage: ObjectExportUsage::default(),
        status: ObjectExportStatus::Partial,
        issues: vec![String::from("temporary object limit reached")],
    };

    let (collection, issue) = collect_matching_tshark_snapshot(&source, &objects, &mut artifacts)?;

    assert_eq!(collection.objects_exported, 0);
    assert_eq!(artifacts.coverage().references_selected, 0);
    assert_eq!(collection.export_status, Some(ObjectExportStatus::Partial));
    assert!(issue.is_none());
    assert_eq!(collection.issues, objects.issues);
    assert!(!tshark_is_complete(&collection, None));
    Ok(())
}

#[test]
fn partial_tshark_export_preserves_verified_objects_and_exact_limit_receipt()
-> Result<(), Box<dyn std::error::Error>> {
    let bytes = b"capture bytes";
    let digest = sha256(bytes);
    let source = source_coverage(bytes, &digest)?;
    let temporary = tempfile::tempdir()?;
    let staging = temporary.path().join("staging");
    let object_directory = temporary.path().join("objects");
    std::fs::create_dir(&staging)?;
    std::fs::create_dir(&object_directory)?;
    std::fs::write(object_directory.join("complete.bin"), b"complete bytes")?;
    let mut artifacts = ArtifactCollection::new(&staging, ArtifactLimits::default())?;
    let usage = ObjectExportUsage {
        temporary_bytes_peak: 15,
        temporary_files_peak: 2,
        temporary_tree_entries_peak: 3,
        protocol_directory_count: 1,
        temporary_scan_complete: false,
    };
    let issue = String::from(
        "`TShark` object export stopped after observing temporary bytes above its budget of 8 (observed 15; tree-entry limits stop at the first extra entry, while byte and file totals may overshoot between scans)",
    );
    let objects = ExportObjectSet {
        temporary_directory: tempfile::tempdir()?,
        directories: Vec::new(),
        partial_directories: vec![(String::from("http"), object_directory)],
        source_identity: SourceIdentity {
            label: String::from("capture.pcap"),
            length: u64::try_from(bytes.len())?,
            sha256: digest,
        },
        budget: ObjectExportBudget {
            temporary_bytes: 8,
            temporary_files: 10,
        },
        usage,
        status: ObjectExportStatus::Partial,
        issues: vec![issue.clone()],
    };

    let (collection, mismatch) =
        collect_matching_tshark_snapshot(&source, &objects, &mut artifacts)?;

    assert_eq!(collection.objects_exported, 1);
    assert_eq!(collection.export_status, Some(ObjectExportStatus::Partial));
    assert_eq!(collection.export_budget, Some(objects.budget));
    assert_eq!(collection.export_usage, Some(usage));
    assert_eq!(collection.issues, vec![issue]);
    assert!(mismatch.is_none());
    assert!(!tshark_is_complete(&collection, None));
    assert_eq!(artifacts.coverage().references_selected, 1);
    let file_name = artifacts
        .file_names()?
        .into_iter()
        .next()
        .ok_or("verified partial TShark object was not staged")?;
    assert_eq!(std::fs::read(staging.join(file_name))?, b"complete bytes");
    Ok(())
}

#[test]
fn escapes_and_bounds_tshark_diagnostics() {
    let diagnostic = format!("\u{1b}[31m{}", "x".repeat(600));

    let safe = summary_text(&diagnostic);

    assert!(safe.starts_with("\\u{1b}[31m"));
    assert!(!safe.chars().any(char::is_control));
    assert!(safe.len() <= 512);
}

fn source_coverage(
    bytes: &[u8],
    digest: &str,
) -> Result<SourceCoverage, Box<dyn std::error::Error>> {
    Ok(SourceCoverage {
        source_id: format!("sha256:{digest}"),
        bytes: u64::try_from(bytes.len())?,
        packet_records: 0,
        supported_transport_records: 0,
        packets_without_supported_transport: 0,
        collection_summary: l2_pcap::CollectionSummary::default(),
    })
}
