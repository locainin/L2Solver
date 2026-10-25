use super::artifact_collection::{
    AddOutcome, ArtifactCollection, ArtifactProvenance, OmissionReason,
};
use crate::workbench::{ObjectExportBudget, ObjectExportStatus, ObjectExportUsage};
use std::{
    collections::BinaryHeap,
    error::Error,
    fs::{self, File, Metadata, OpenOptions},
    io,
    path::{Path, PathBuf},
};

#[derive(Default)]
pub(super) struct Collection {
    pub(super) objects_exported: u64,
    pub(super) imf_objects_exported: u64,
    pub(super) duplicates: u64,
    pub(super) skipped: u64,
    pub(super) unsafe_entries_skipped: u64,
    pub(super) scan_entries: u64,
    pub(super) scan_limit_reached: bool,
    pub(super) export_status: Option<ObjectExportStatus>,
    pub(super) export_budget: Option<ObjectExportBudget>,
    pub(super) export_usage: Option<ObjectExportUsage>,
    pub(super) issues: Vec<String>,
}

/// Add `TShark` objects in stable order while using the shared disk-backed artifact index
pub(super) fn collect(
    directories: &[(String, PathBuf)],
    artifacts: &mut ArtifactCollection,
    scan_entry_budget: u64,
) -> Result<Collection, Box<dyn Error>> {
    let mut collection = Collection::default();
    if !safe_file_checks_available() {
        note_issue(
            &mut collection,
            "TShark objects were skipped because this platform cannot verify file identity and links"
                .to_owned(),
        );
        return Ok(collection);
    }

    for (protocol, directory) in directories {
        if !safe_protocol(protocol) {
            note_issue(
                &mut collection,
                "unsafe TShark object type was skipped".to_owned(),
            );
            continue;
        }
        match collect_protocol(
            protocol,
            directory,
            artifacts,
            &mut collection,
            scan_entry_budget,
        ) {
            Ok(false) => {}
            Ok(true) => {
                collection.scan_limit_reached = true;
                note_issue(
                    &mut collection,
                    format!(
                        "TShark object directory scan stopped at its {scan_entry_budget}-entry budget; remaining entries in {protocol} and later protocol directories were not inspected"
                    ),
                );
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => note_issue(
                &mut collection,
                format!("TShark {protocol} output directory was unavailable"),
            ),
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => note_issue(
                &mut collection,
                format!("TShark {protocol} output directory could not be read"),
            ),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(collection)
}

fn collect_protocol(
    protocol: &str,
    directory: &Path,
    artifacts: &mut ArtifactCollection,
    collection: &mut Collection,
    scan_entry_budget: u64,
) -> io::Result<bool> {
    let metadata = fs::symlink_metadata(directory)?;
    if !metadata.file_type().is_dir() {
        note_issue(
            collection,
            format!("unsafe TShark {protocol} output directory was skipped"),
        );
        return Ok(false);
    }

    let selection = selected_entries(
        directory,
        protocol,
        artifacts,
        collection,
        scan_entry_budget,
    )?;
    for (ordinal, (name, byte_length)) in selection.candidates.into_iter().enumerate() {
        let path = directory.join(name);
        collect_entry(
            protocol,
            &path,
            byte_length,
            u64::try_from(ordinal).map_err(io::Error::other)?,
            artifacts,
            collection,
        )?;
    }
    if selection.omitted_count != 0 {
        artifacts
            .record_omissions(
                OmissionReason::ProvenanceCount,
                selection.omitted_count,
                selection.omitted_bytes,
            )
            .map_err(|error| as_io_error(error.as_ref()))?;
        count_skipped(collection, selection.omitted_count)?;
        note_issue(
            collection,
            format!(
                "{} TShark {protocol} objects were omitted by the remaining provenance-entry limit",
                selection.omitted_count
            ),
        );
    }
    Ok(selection.scan_limit_reached)
}

struct EntrySelection {
    candidates: Vec<(std::ffi::OsString, u64)>,
    omitted_count: u64,
    omitted_bytes: u64,
    scan_limit_reached: bool,
}

/// Keep only the lexically earliest names that fit remaining provenance capacity
fn selected_entries(
    directory: &Path,
    protocol: &str,
    artifacts: &ArtifactCollection,
    collection: &mut Collection,
    scan_entry_budget: u64,
) -> io::Result<EntrySelection> {
    let capacity = usize::try_from(artifacts.remaining_provenance_entries()).unwrap_or(usize::MAX);
    let mut candidates = BinaryHeap::<(std::ffi::OsString, u64)>::new();
    let mut eligible_count = 0_u64;
    let mut eligible_bytes = 0_u64;
    let mut retained_candidate_bytes = 0_u64;

    let mut scan_limit_reached = false;
    for entry in fs::read_dir(directory)? {
        collection.scan_entries = checked_add(collection.scan_entries, 1)?;
        if collection.scan_entries > scan_entry_budget {
            scan_limit_reached = true;
            break;
        }
        let Ok(entry) = entry else {
            count_skipped(collection, 1)?;
            note_issue(
                collection,
                format!("TShark {protocol} entry could not be inspected"),
            );
            continue;
        };
        let path = entry.path();
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) if safe_regular_file(&metadata) => metadata,
            Ok(_) => {
                count_unsafe(collection, 1)?;
                note_issue(
                    collection,
                    format!("unsafe object entry from TShark {protocol} was skipped"),
                );
                continue;
            }
            Err(_) => {
                count_unsafe(collection, 1)?;
                note_issue(
                    collection,
                    format!("TShark {protocol} object identity could not be checked"),
                );
                continue;
            }
        };
        eligible_count = checked_add(eligible_count, 1)?;
        eligible_bytes = checked_add(eligible_bytes, metadata.len())?;
        if capacity == 0 {
            continue;
        }

        let candidate = (entry.file_name(), metadata.len());
        if candidates.len() < capacity {
            retained_candidate_bytes = checked_add(retained_candidate_bytes, candidate.1)?;
            candidates.push(candidate);
        } else if candidates.peek().is_some_and(|last| candidate.0 < last.0) {
            let removed = candidates.pop().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "TShark candidate index is inconsistent",
                )
            })?;
            retained_candidate_bytes = retained_candidate_bytes
                .checked_sub(removed.1)
                .ok_or_else(|| io::Error::other("TShark candidate byte count underflow"))?;
            retained_candidate_bytes = checked_add(retained_candidate_bytes, candidate.1)?;
            candidates.push(candidate);
        }
    }

    let selected_count = u64::try_from(candidates.len()).map_err(io::Error::other)?;
    let omitted_count = eligible_count
        .checked_sub(selected_count)
        .ok_or_else(|| io::Error::other("TShark selected count exceeds eligible entries"))?;
    let omitted_bytes = eligible_bytes
        .checked_sub(retained_candidate_bytes)
        .ok_or_else(|| io::Error::other("TShark selected bytes exceed eligible bytes"))?;
    let mut result = candidates.into_vec();
    result.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(EntrySelection {
        candidates: result,
        omitted_count,
        omitted_bytes,
        scan_limit_reached,
    })
}

fn collect_entry(
    protocol: &str,
    path: &Path,
    expected_length: u64,
    source_ordinal: u64,
    artifacts: &mut ArtifactCollection,
    collection: &mut Collection,
) -> io::Result<()> {
    let mut source = match open_regular_object(path) {
        Ok(source) if source.metadata()?.len() == expected_length => source,
        Ok(_) => {
            record_unsafe(artifacts, collection, expected_length)?;
            note_issue(
                collection,
                format!("TShark {protocol} object length changed while opening"),
            );
            return Ok(());
        }
        Err(_) => {
            record_unsafe(artifacts, collection, expected_length)?;
            note_issue(
                collection,
                format!(
                    "unsafe object entry or changed identity from TShark {protocol} was omitted"
                ),
            );
            return Ok(());
        }
    };

    let number = artifacts
        .next_file_number()
        .map_err(|error| as_io_error(error.as_ref()))?;
    let name = format!(
        "{number:06}-tshark-{protocol}.{}",
        extension_for_protocol(protocol)
    );
    let provenance = ArtifactProvenance {
        category: String::from("tshark_object"),
        case_id: None,
        selected_node_id: None,
        validation_node_id: None,
        extension_node_id: None,
        flow: None,
        supporting_flows: Vec::new(),
        cohort_scope: None,
        node: None,
        description: None,
        selection: Some(serde_json::json!({
            "protocol": protocol,
            "source_ordinal": source_ordinal
        })),
        signature_candidates: Vec::new(),
        source_ranges: Vec::new(),
        canonical_origin: serde_json::json!({
            "category": "tshark_object",
            "protocol": protocol,
            "source_ordinal": source_ordinal
        }),
    };
    match artifacts
        .add_open_file(&mut source, &name, &provenance)
        .map_err(|error| as_io_error(error.as_ref()))?
    {
        AddOutcome::Stored => {
            collection.objects_exported = checked_add(collection.objects_exported, 1)?;
            if protocol == "imf" {
                collection.imf_objects_exported = checked_add(collection.imf_objects_exported, 1)?;
            }
        }
        AddOutcome::Duplicate | AddOutcome::SameOrigin => {
            collection.duplicates = checked_add(collection.duplicates, 1)?;
        }
        AddOutcome::Omitted(reason) => {
            count_skipped(collection, 1)?;
            note_issue(
                collection,
                format!(
                    "TShark {protocol} object was omitted: {}",
                    omission_label(reason)
                ),
            );
        }
    }
    Ok(())
}

fn record_unsafe(
    artifacts: &mut ArtifactCollection,
    collection: &mut Collection,
    byte_length: u64,
) -> io::Result<()> {
    artifacts
        .record_omission(OmissionReason::UnreadableObject, byte_length)
        .map_err(|error| as_io_error(error.as_ref()))?;
    count_unsafe(collection, 1)
}

const fn omission_label(reason: OmissionReason) -> &'static str {
    match reason {
        OmissionReason::ArtifactCount => "aggregate artifact-count limit",
        OmissionReason::ArtifactBytes => "aggregate artifact-byte limit",
        OmissionReason::ProvenanceCount => "aggregate provenance-entry limit",
        OmissionReason::ProvenanceBytes => "aggregate provenance-byte limit",
        OmissionReason::UnreadableObject => "unreadable object bytes",
    }
}

fn extension_for_protocol(protocol: &str) -> &'static str {
    match protocol {
        "imf" => "eml",
        _ => "bin",
    }
}

fn open_regular_object(path: &Path) -> io::Result<File> {
    let link_metadata = fs::symlink_metadata(path)?;
    if !safe_regular_file(&link_metadata) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsafe TShark object entry",
        ));
    }
    let source = open_object(path)?;
    let opened_metadata = source.metadata()?;
    if !safe_regular_file(&opened_metadata) || !same_file(&link_metadata, &opened_metadata) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TShark object identity changed while opening",
        ));
    }
    Ok(source)
}

pub(super) fn safe_regular_file(metadata: &Metadata) -> bool {
    if !metadata.file_type().is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        metadata.nlink() == 1
    }
    #[cfg(not(unix))]
    {
        false
    }
}

#[cfg(unix)]
const fn safe_file_checks_available() -> bool {
    true
}

#[cfg(not(unix))]
const fn safe_file_checks_available() -> bool {
    false
}

fn open_object(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(unix)]
    {
        options.open(path)
    }
    #[cfg(not(unix))]
    {
        let _ = (options, path);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "safe TShark object opening is unavailable on this platform",
        ))
    }
}

fn same_file(left: &Metadata, right: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        left.dev() == right.dev() && left.ino() == right.ino()
    }
    #[cfg(not(unix))]
    {
        left.len() == right.len() && left.file_type().is_file() && right.file_type().is_file()
    }
}

fn count_skipped(collection: &mut Collection, count: u64) -> io::Result<()> {
    collection.skipped = checked_add(collection.skipped, count)?;
    Ok(())
}

fn count_unsafe(collection: &mut Collection, count: u64) -> io::Result<()> {
    collection.unsafe_entries_skipped = checked_add(collection.unsafe_entries_skipped, count)?;
    count_skipped(collection, count)
}

fn checked_add(total: u64, next: u64) -> io::Result<u64> {
    total
        .checked_add(next)
        .ok_or_else(|| io::Error::other("TShark object count overflow"))
}

fn note_issue(collection: &mut Collection, issue: String) {
    if !collection.issues.contains(&issue) {
        collection.issues.push(issue);
    }
}

fn as_io_error(error: &(dyn Error + 'static)) -> io::Error {
    io::Error::other(error.to_string())
}

fn safe_protocol(protocol: &str) -> bool {
    !protocol.is_empty()
        && protocol
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}
