use super::super::budget::{ObjectFileSnapshot, StableObject};
use super::{retain_partial_export, retain_stable_objects};
use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
};

#[cfg(unix)]
#[test]
fn partial_snapshot_keeps_only_unchanged_regular_files() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir()?;
    let object_root = temporary.path().join("objects");
    let protocol_root = object_root.join("http");
    let snapshot_root = temporary.path().join("partial-objects");
    fs::create_dir(&object_root)?;
    fs::create_dir(&protocol_root)?;

    let complete_path = protocol_root.join("complete.bin");
    let changed_path = protocol_root.join("changed.bin");
    let replaced_path = protocol_root.join("replaced.bin");
    fs::write(&complete_path, b"complete object")?;
    fs::write(&changed_path, b"before")?;
    fs::write(&replaced_path, b"original regular file")?;

    let stable_objects = [
        stable_object(&object_root, &complete_path)?,
        stable_object(&object_root, &changed_path)?,
        stable_object(&object_root, &replaced_path)?,
        StableObject {
            relative_path: PathBuf::from("../outside.bin"),
            snapshot: stable_object(&object_root, &complete_path)?.snapshot,
        },
    ];
    fs::write(&changed_path, b"changed while export stopped")?;
    fs::remove_file(&replaced_path)?;
    symlink(&complete_path, &replaced_path)?;

    let snapshot = retain_stable_objects(&object_root, &snapshot_root, &stable_objects)?;

    assert!(snapshot.omitted_unstable);
    assert_eq!(snapshot.directories.len(), 1);
    let (protocol, snapshot_directory) = snapshot
        .directories
        .first()
        .ok_or("partial snapshot directory is missing")?;
    assert_eq!(protocol, "http");
    assert_eq!(
        fs::read(snapshot_directory.join("complete.bin"))?,
        b"complete object"
    );
    assert!(!snapshot_directory.join("changed.bin").exists());
    assert!(!snapshot_directory.join("replaced.bin").exists());
    assert_eq!(fs::read_link(&replaced_path)?, complete_path);
    assert_eq!(fs::read_dir(snapshot_directory)?.count(), 1);
    Ok(())
}

#[cfg(unix)]
#[test]
fn partial_export_preserves_exact_cause_usage_and_stable_objects() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let object_root = temporary.path().join("objects");
    let protocol_root = object_root.join("http");
    let snapshot_root = temporary.path().join("partial-objects");
    fs::create_dir(&object_root)?;
    fs::create_dir(&protocol_root)?;
    let stable_path = protocol_root.join("stable.bin");
    fs::write(&stable_path, b"stable object")?;
    let stable = stable_object(&object_root, &stable_path)?;
    let usage = super::ObjectExportUsage {
        temporary_bytes_peak: 13,
        temporary_files_peak: 1,
        temporary_tree_entries_peak: 2,
        protocol_directory_count: 1,
        temporary_scan_complete: true,
    };
    let cause = String::from("TShark object export failed with exit status 7: export denied");

    let partial = retain_partial_export(
        &object_root,
        &snapshot_root,
        usage,
        &[stable],
        cause.clone(),
    )?;

    assert_eq!(partial.usage, usage);
    assert_eq!(partial.issues, vec![cause]);
    assert_eq!(partial.directories.len(), 1);
    let (protocol, snapshot_directory) = partial
        .directories
        .first()
        .ok_or("partial snapshot directory is missing")?;
    assert_eq!(protocol, "http");
    assert_eq!(
        fs::read(snapshot_directory.join("stable.bin"))?,
        b"stable object"
    );
    assert!(!protocol_root.join("stable.bin").exists());
    Ok(())
}

#[cfg(unix)]
fn stable_object(root: &Path, path: &Path) -> Result<StableObject, Box<dyn Error>> {
    let relative_path = path.strip_prefix(root)?.to_owned();
    let metadata = fs::symlink_metadata(path)?;
    let snapshot = ObjectFileSnapshot::from_metadata(&metadata)
        .ok_or("fixture must be a private regular file")?;
    Ok(StableObject {
        relative_path,
        snapshot,
    })
}
