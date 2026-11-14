use super::super::budget::{ObjectFileSnapshot, StableObject};
use super::retain_stable_objects;
use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
};

#[test]
fn inventory_interruption() {
    for output in [
        "Available export object types:\nhttp\ninvalid_type\nftp-data\n",
        "Available export object types:\nhttp\n\ninvalid_type\nftp-data\n",
        "Available export object types:\ninvalid_type\nhttp\n",
        "Available export object types:\nhttp\nUnknown footer!\n",
    ] {
        assert!(super::parse_types(output).is_err(), "accepted {output:?}");
    }
}

#[test]
fn upstream_inventory() -> Result<(), Box<dyn Error>> {
    let output = "tshark: The available export object types for the \"--export-objects\" option are:\n     dicom\n     ftp-data\n     http\n     imf\n     smb\n     tftp\n     x509af\n     zipfile\n";
    let types = super::parse_types(output)?;
    assert_eq!(
        types,
        [
            "dicom", "ftp-data", "http", "imf", "smb", "tftp", "x509af", "zipfile"
        ]
    );
    Ok(())
}

#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
#[test]
fn unsafe_complete_export() -> Result<(), Box<dyn Error>> {
    for mode in ["symlink", "fifo", "hardlink", "nested", "foreign"] {
        let (temporary, object_root, result) = run_fake_export(mode)?;

        assert_eq!(result.status, super::ObjectExportStatus::Partial, "{mode}");
        assert!(!result.issues.is_empty(), "{mode}");
        assert_eq!(result.directories.len(), 1, "{mode}");
        let (protocol, directory) = result
            .directories
            .first()
            .ok_or("verified partial directory is missing")?;
        assert_eq!(protocol, "http", "{mode}");
        assert_ne!(directory, &object_root.join("http"), "{mode}");
        assert_eq!(fs::read(directory.join("good.bin"))?, b"safe", "{mode}");
        assert_eq!(fs::read_dir(directory)?.count(), 1, "{mode}");
        assert_eq!(
            fs::read(temporary.path().join("outside.bin"))?,
            b"host secret"
        );
    }
    Ok(())
}

#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
#[test]
fn late_regular_object() -> Result<(), Box<dyn Error>> {
    let (_temporary, object_root, result) = run_fake_export("valid")?;

    assert_eq!(result.status, super::ObjectExportStatus::Complete);
    assert_eq!(result.issues, Vec::<String>::new());
    assert_eq!(result.directories.len(), 1);
    let (protocol, directory) = result
        .directories
        .first()
        .ok_or("verified complete directory is missing")?;
    assert_eq!(protocol, "http");
    assert_ne!(directory, &object_root.join("http"));
    assert_eq!(fs::read(directory.join("good.bin"))?, b"safe");
    Ok(())
}

#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
fn run_fake_export(
    mode: &str,
) -> Result<(tempfile::TempDir, PathBuf, super::ResolvedObjectExport), Box<dyn Error>> {
    use std::{
        ffi::OsString,
        time::{Duration, Instant},
    };

    let temporary = tempfile::tempdir()?;
    let object_root = temporary.path().join("objects");
    let protocol_root = object_root.join("http");
    fs::create_dir_all(&protocol_root)?;
    let outside = temporary.path().join("outside.bin");
    fs::write(&outside, b"host secret")?;
    let script = r#"
        printf safe > "$OUTPUT_DIR/good.bin"
        case "$MODE" in
            symlink) ln -s "$OUTSIDE" "$OUTPUT_DIR/unsafe" ;;
            fifo) mkfifo "$OUTPUT_DIR/unsafe" ;;
            hardlink) ln "$OUTSIDE" "$OUTPUT_DIR/unsafe" ;;
            nested) mkdir "$OUTPUT_DIR/nested"; printf hidden > "$OUTPUT_DIR/nested/unsafe" ;;
            foreign) mkdir "$OUTPUT_ROOT/other"; printf hidden > "$OUTPUT_ROOT/other/unsafe" ;;
            valid) ;;
            *) exit 1 ;;
        esac
        exit 0
    "#;
    let arguments = [OsString::from("-c"), OsString::from(script)];
    let environment = [
        (OsString::from("MODE"), OsString::from(mode)),
        (
            OsString::from("OUTPUT_DIR"),
            protocol_root.as_os_str().to_owned(),
        ),
        (
            OsString::from("OUTPUT_ROOT"),
            object_root.as_os_str().to_owned(),
        ),
        (OsString::from("OUTSIDE"), outside.as_os_str().to_owned()),
    ];
    let output = super::process::run_streaming(
        Path::new("/bin/sh"),
        &arguments,
        &environment,
        super::StreamingPolicy {
            stderr_maximum: 1024,
            deadline: Instant::now() + Duration::from_secs(5),
            object_root: &object_root,
            protocol_directory_count: 1,
            object_budget: super::ObjectExportBudget {
                temporary_bytes: 1024,
                temporary_files: 10,
            },
            job: None,
        },
    );
    let result = super::resolve_object_export(
        output,
        &object_root,
        &temporary.path().join("verified-objects"),
        &[(String::from("http"), protocol_root)],
    )?;
    Ok((temporary, object_root, result))
}

#[test]
fn cancelled_object_export_preserves_the_job_cancellation_type() -> Result<(), Box<dyn Error>> {
    let error = super::resolve_object_export(
        Err(super::process::ProcessError::Cancelled),
        Path::new("unused-object-root"),
        Path::new("unused-partial-root"),
        &[],
    )
    .err()
    .ok_or("cancelled object export unexpectedly succeeded")?;
    assert_eq!(
        error.downcast_ref::<l2_workbench::job::JobError>(),
        Some(&l2_workbench::job::JobError::Cancelled)
    );
    Ok(())
}

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

    let allowed = [(String::from("http"), protocol_root)];
    let snapshot = retain_stable_objects(&object_root, &snapshot_root, &stable_objects, &allowed)?;

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
#[derive(Clone, Copy, Debug)]
enum StopCause {
    FailedExit,
    Limit,
    Timeout,
}

#[cfg(unix)]
impl StopCause {
    fn output(
        self,
        usage: super::ObjectExportUsage,
        stable: StableObject,
    ) -> (
        Result<super::process::StreamOutput, super::process::ProcessError>,
        String,
    ) {
        use super::super::budget::{ObjectExportLimit, ObjectExportResource};
        use std::os::unix::process::ExitStatusExt;

        match self {
            Self::FailedExit => {
                let status = std::process::ExitStatus::from_raw(7 << 8);
                (
                    Ok(super::process::StreamOutput {
                        stderr: b"export denied".to_vec(),
                        stderr_truncated: false,
                        status,
                        object_usage: usage,
                        objects: vec![stable],
                        unsafe_entries: false,
                    }),
                    format!("TShark object export failed with exit status {status}: export denied"),
                )
            }
            Self::Limit => (
                Err(super::process::ProcessError::ObjectExportLimit(
                    ObjectExportLimit {
                        resource: ObjectExportResource::Bytes,
                        maximum: 8,
                        observed: 30,
                        usage,
                        stable_objects: vec![stable],
                    },
                )),
                String::from(concat!(
                    "`TShark` object export stopped after observing temporary bytes above its budget of 8 ",
                    "(observed 30; tree-entry limits stop at the first extra entry, while byte and file totals may overshoot between scans)"
                )),
            ),
            Self::Timeout => (
                Err(super::process::ProcessError::ObjectExportTimeout(
                    super::process::ObjectExportTimeout {
                        stderr: b"timeout diagnostic".to_vec(),
                        stderr_truncated: false,
                        stderr_complete: true,
                        status: None,
                        usage,
                        stable_objects: vec![stable],
                    },
                )),
                String::from("TShark object export exceeded its time budget: timeout diagnostic"),
            ),
        }
    }
}

#[cfg(unix)]
#[test]
fn partial_export_receipt() -> Result<(), Box<dyn Error>> {
    for stop in [StopCause::FailedExit, StopCause::Limit, StopCause::Timeout] {
        let temporary = tempfile::tempdir()?;
        let object_root = temporary.path().join("objects");
        let protocol_root = object_root.join("http");
        let snapshot_root = temporary.path().join("partial-objects");
        fs::create_dir(&object_root)?;
        fs::create_dir(&protocol_root)?;
        let stable_path = protocol_root.join("stable.bin");
        let unfinished_path = protocol_root.join("unfinished.bin");
        fs::write(&stable_path, b"stable object")?;
        fs::write(&unfinished_path, b"unfinished object")?;
        let stable = stable_object(&object_root, &stable_path)?;
        let usage = super::ObjectExportUsage {
            temporary_bytes_peak: 30,
            temporary_files_peak: 2,
            temporary_tree_entries_peak: 3,
            protocol_directory_count: 1,
            temporary_scan_complete: !matches!(stop, StopCause::Limit),
        };
        let (output, cause) = stop.output(usage, stable);

        let partial = super::resolve_object_export(
            output,
            &object_root,
            &snapshot_root,
            &[(String::from("http"), protocol_root.clone())],
        )?;

        assert_eq!(
            partial.status,
            super::ObjectExportStatus::Partial,
            "{stop:?}"
        );
        assert_eq!(partial.usage, usage, "{stop:?}");
        assert_eq!(partial.issues, vec![cause], "{stop:?}");
        assert_eq!(partial.directories.len(), 1, "{stop:?}");
        let (protocol, snapshot_directory) = partial
            .directories
            .first()
            .ok_or("partial snapshot directory is missing")?;
        assert_eq!(protocol, "http", "{stop:?}");
        assert_ne!(snapshot_directory, &protocol_root, "{stop:?}");
        assert_eq!(
            fs::read(snapshot_directory.join("stable.bin"))?,
            b"stable object",
            "{stop:?}"
        );
        assert!(
            !snapshot_directory.join("unfinished.bin").exists(),
            "{stop:?}"
        );
        assert_eq!(
            fs::read(&unfinished_path)?,
            b"unfinished object",
            "{stop:?}"
        );
        assert!(!protocol_root.join("stable.bin").exists(), "{stop:?}");
    }
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
