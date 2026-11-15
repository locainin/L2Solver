use super::super::budget::{ObjectFileSnapshot, StableObject};
use super::retain_stable_objects;
use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

fn clean_scope() -> l2_workbench::tshark::ScopeReceipt {
    use l2_workbench::tshark::{ScopeReceipt, ScopeUsage};

    ScopeReceipt {
        memory_max_bytes: 4,
        memory_high_bytes: 3,
        swap_max_bytes: 0,
        tasks_max: 2,
        effective_memory_max_bytes: 4,
        effective_memory_high_bytes: 3,
        effective_swap_max_bytes: 0,
        effective_tasks_max: 2,
        usage: Some(ScopeUsage {
            memory_peak_bytes: None,
            tasks_peak: None,
            memory_events: Some(l2_workbench::job::CgroupMemoryEvents::default()),
            tasks_max_events: Some(0),
            observed_after_stop: true,
            observed_while_frozen: false,
        }),
    }
}

#[test]
fn inventory_interruption() {
    let invalid_type = "TShark returned an unsafe export object type";
    for (output, diagnostic) in [
        (
            "not an inventory\n",
            "TShark did not list its export object types",
        ),
        (
            "Available export object types:\n\n",
            "TShark returned no usable export object types",
        ),
        (
            "Available export object types:\nhttp\ninvalid_type\nftp-data\n",
            invalid_type,
        ),
        (
            "Available export object types:\nhttp\n\ninvalid_type\nftp-data\n",
            invalid_type,
        ),
        (
            "Available export object types:\ninvalid_type\nhttp\n",
            invalid_type,
        ),
        (
            "Available export object types:\nhttp\nUnknown footer!\n",
            invalid_type,
        ),
    ] {
        assert_eq!(
            super::parse_types(output)
                .err()
                .map(|error| error.to_string()),
            Some(diagnostic.to_owned()),
            "inventory {output:?}"
        );
    }
}

#[cfg(unix)]
#[test]
fn export_completion_invariants() -> Result<(), Box<dyn Error>> {
    use std::os::unix::{fs::symlink, process::ExitStatusExt};

    // Make one condition fail at a time so no other failure can hide it
    for mode in [
        "complete",
        "root_symlink",
        "protocol_symlink",
        "unsafe",
        "changed",
    ] {
        let temporary = tempfile::tempdir()?;
        let object_root = temporary.path().join("objects");
        let protocol_root = object_root.join("http");
        let actual_root = temporary.path().join("actual");
        if mode == "root_symlink" {
            fs::create_dir_all(actual_root.join("http"))?;
            symlink(&actual_root, &object_root)?;
        } else {
            fs::create_dir(&object_root)?;
            if mode == "protocol_symlink" {
                fs::create_dir(&actual_root)?;
                symlink(&actual_root, &protocol_root)?;
            } else {
                fs::create_dir(&protocol_root)?;
            }
        }
        let mut objects = Vec::new();
        if mode == "changed" {
            let object = protocol_root.join("changed.bin");
            fs::write(&object, b"before")?;
            objects.push(stable_object(&object_root, &object)?);
            // A later rewrite must not remain in the completed export
            fs::write(&object, b"changed after the scan")?;
        }
        let output = super::process::StreamOutput {
            stderr: Vec::new(),
            stderr_truncated: false,
            status: std::process::ExitStatus::from_raw(0),
            object_usage: super::ObjectExportUsage::default(),
            objects,
            unsafe_entries: mode == "unsafe",
            scope: None,
        };
        let result = super::resolve_object_export(
            Ok(output),
            &object_root,
            &temporary.path().join("verified-objects"),
            &[(String::from("http"), protocol_root)],
            deadline(),
            None,
            Some(&clean_scope()),
        )?;

        if mode == "complete" {
            assert_eq!(result.status, super::ObjectExportStatus::Complete, "{mode}");
            assert!(result.issues.is_empty(), "{mode}");
        } else {
            assert_eq!(result.status, super::ObjectExportStatus::Partial, "{mode}");
            assert_eq!(
                result.issues,
                ["TShark object output contained unsafe or changed entries"],
                "{mode}"
            );
        }
        assert!(result.directories.is_empty(), "{mode}");
    }
    Ok(())
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

#[test]
fn large_inventory_order_and_deduplication() -> Result<(), Box<dyn Error>> {
    use std::fmt::Write as _;

    let mut inventory = String::from("Available export object types:\n");
    for number in 0..12_000 {
        writeln!(inventory, "protocol{number:05}")?;
    }
    inventory.push_str("protocol00000\nprotocol06000\nprotocol11999\n");
    let types = super::parse_types(&inventory)?;
    assert_eq!(types.len(), 12_000);
    assert_eq!(types.first().map(String::as_str), Some("protocol00000"));
    assert_eq!(types.get(6_000).map(String::as_str), Some("protocol06000"));
    assert_eq!(types.last().map(String::as_str), Some("protocol11999"));
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
        deadline(),
        None,
        Some(&clean_scope()),
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
        deadline(),
        None,
        None,
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
    let snapshot = retain_stable_objects(
        &object_root,
        &snapshot_root,
        &stable_objects,
        &allowed,
        deadline(),
        None,
    )?;

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

#[cfg(target_os = "linux")]
#[test]
fn snapshot_copies_across_filesystems() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::MetadataExt;

    let temporary_objects = tempfile::tempdir_in("/dev/shm")?;
    let temporary_snapshot = tempfile::tempdir_in(".")?;
    assert_ne!(
        temporary_objects.path().metadata()?.dev(),
        temporary_snapshot.path().metadata()?.dev(),
        "the test requires separate filesystems"
    );
    let object_root = temporary_objects.path();
    let protocol_root = object_root.join("http");
    fs::create_dir(&protocol_root)?;
    let object = protocol_root.join("object.bin");
    fs::write(&object, b"tmpfs object")?;
    let stable = stable_object(object_root, &object)?;
    let snapshot = retain_stable_objects(
        object_root,
        &temporary_snapshot.path().join("objects"),
        &[stable],
        &[(String::from("http"), protocol_root)],
        deadline(),
        None,
    )?;

    assert!(!snapshot.omitted_unstable);
    let (_, directory) = snapshot.directories.first().ok_or("snapshot missing")?;
    assert_eq!(fs::read(directory.join("object.bin"))?, b"tmpfs object");
    assert_eq!(fs::read(object)?, b"tmpfs object");
    Ok(())
}

#[cfg(unix)]
#[test]
fn snapshot_deadline_and_cancellation() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let object_root = temporary.path().join("objects");
    let protocol_root = object_root.join("http");
    fs::create_dir_all(&protocol_root)?;
    let object = protocol_root.join("object.bin");
    fs::write(&object, b"stable object")?;
    let stable = stable_object(&object_root, &object)?;
    let allowed = [(String::from("http"), protocol_root)];
    let expired = retain_stable_objects(
        &object_root,
        &temporary.path().join("expired"),
        std::slice::from_ref(&stable),
        &allowed,
        Instant::now(),
        None,
    )?;
    assert!(expired.deadline_reached);
    assert_eq!(expired.directories, Vec::new());
    assert_eq!(fs::read(&object)?, b"stable object");

    let job = l2_workbench::job::Job::new("cancelled object copy");
    job.request_cancel();
    let error = retain_stable_objects(
        &object_root,
        &temporary.path().join("cancelled"),
        &[stable],
        &allowed,
        deadline(),
        Some(&job),
    )
    .err()
    .ok_or("cancelled snapshot unexpectedly succeeded")?;
    assert_eq!(
        error.downcast_ref::<l2_workbench::job::JobError>(),
        Some(&l2_workbench::job::JobError::Cancelled)
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn snapshot_disk_full() -> Result<(), Box<dyn Error>> {
    let mut source = fs::File::open("/dev/zero")?;
    let mut destination = fs::OpenOptions::new().write(true).open("/dev/full")?;
    let error = super::copy_object_data(&mut source, &mut destination, 1, deadline(), None)
        .err()
        .ok_or("full destination unexpectedly accepted output")?;
    assert_eq!(
        error
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::raw_os_error),
        Some(libc::ENOSPC)
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn expired_snapshot_is_partial() -> Result<(), Box<dyn Error>> {
    use std::os::unix::process::ExitStatusExt;

    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("objects");
    let protocol = root.join("http");
    fs::create_dir_all(&protocol)?;
    let object = protocol.join("object.bin");
    fs::write(&object, b"finished")?;
    let output = super::process::StreamOutput {
        stderr: Vec::new(),
        stderr_truncated: false,
        status: std::process::ExitStatus::from_raw(0),
        object_usage: super::ObjectExportUsage::default(),
        objects: vec![stable_object(&root, &object)?],
        unsafe_entries: false,
        scope: None,
    };
    let result = super::resolve_object_export(
        Ok(output),
        &root,
        &temporary.path().join("snapshot"),
        &[(String::from("http"), protocol)],
        Instant::now(),
        None,
        Some(&clean_scope()),
    )?;
    assert_eq!(result.status, super::ObjectExportStatus::Partial);
    assert_eq!(result.directories, Vec::new());
    assert_eq!(
        result.issues,
        ["TShark object snapshot stopped at its time budget; remaining objects were omitted"]
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn scope_resource_limits() -> Result<(), Box<dyn Error>> {
    use l2_workbench::job::CgroupMemoryEvents;
    for (name, events, task_events, partial) in [
        (
            "memory pressure",
            CgroupMemoryEvents {
                high: 1,
                max: 1,
                ..CgroupMemoryEvents::default()
            },
            0,
            false,
        ),
        (
            "out of memory",
            CgroupMemoryEvents {
                oom: 1,
                ..CgroupMemoryEvents::default()
            },
            0,
            true,
        ),
        (
            "OOM kill",
            CgroupMemoryEvents {
                oom_kill: 1,
                ..CgroupMemoryEvents::default()
            },
            0,
            true,
        ),
        ("task limit", CgroupMemoryEvents::default(), 1, true),
    ] {
        let mut receipt = clean_scope();
        let usage = receipt.usage.as_mut().ok_or("scope usage missing")?;
        usage.memory_events = Some(events);
        usage.tasks_max_events = Some(task_events);
        let (status, issues) = scope_result(Some(receipt))?;
        let expected = if partial {
            super::ObjectExportStatus::Partial
        } else {
            super::ObjectExportStatus::Complete
        };
        assert_eq!(status, expected, "{name}");
        assert_eq!(issues.is_empty(), !partial, "{name}");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn scope_counter_availability() -> Result<(), Box<dyn Error>> {
    let mut missing_memory = clean_scope();
    missing_memory
        .usage
        .as_mut()
        .ok_or("usage missing")?
        .memory_events = None;
    let mut missing_tasks = clean_scope();
    missing_tasks
        .usage
        .as_mut()
        .ok_or("usage missing")?
        .tasks_max_events = None;
    let mut before_stop = clean_scope();
    before_stop
        .usage
        .as_mut()
        .ok_or("usage missing")?
        .observed_after_stop = false;
    for receipt in [
        None,
        Some(missing_memory),
        Some(missing_tasks),
        Some(before_stop),
    ] {
        let (status, issues) = scope_result(receipt)?;
        assert_eq!(status, super::ObjectExportStatus::Partial);
        assert!(
            issues
                .iter()
                .any(|issue| issue.contains("resource event counters unavailable"))
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn frozen_scope_counters() -> Result<(), Box<dyn Error>> {
    let mut receipt = clean_scope();
    let usage = receipt.usage.as_mut().ok_or("scope usage missing")?;
    usage.observed_after_stop = false;
    usage.observed_while_frozen = true;
    let (status, issues) = scope_result(Some(receipt))?;
    assert_eq!(status, super::ObjectExportStatus::Complete);
    assert_eq!(issues, Vec::<String>::new());
    Ok(())
}

#[cfg(target_os = "linux")]
fn scope_result(
    receipt: Option<l2_workbench::tshark::ScopeReceipt>,
) -> Result<(super::ObjectExportStatus, Vec<String>), Box<dyn Error>> {
    use std::os::unix::process::ExitStatusExt;

    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("objects");
    let protocol = root.join("http");
    fs::create_dir_all(&protocol)?;
    let object = protocol.join("object.bin");
    fs::write(&object, b"finished")?;
    let output = super::process::StreamOutput {
        stderr: Vec::new(),
        stderr_truncated: false,
        status: std::process::ExitStatus::from_raw(0),
        object_usage: super::ObjectExportUsage::default(),
        objects: vec![stable_object(&root, &object)?],
        unsafe_entries: false,
        scope: receipt,
    };
    let result = super::resolve_object_export(
        Ok(output),
        &root,
        &temporary.path().join("snapshot"),
        &[(String::from("http"), protocol)],
        deadline(),
        None,
        receipt.as_ref(),
    )?;
    let (_, directory) = result.directories.first().ok_or("snapshot missing")?;
    assert_eq!(fs::read(directory.join("object.bin"))?, b"finished");
    Ok((result.status, result.issues))
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
                        scope: None,
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
            deadline(),
            None,
            Some(&clean_scope()),
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
        assert_eq!(
            fs::read(protocol_root.join("stable.bin"))?,
            b"stable object",
            "{stop:?}"
        );
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
