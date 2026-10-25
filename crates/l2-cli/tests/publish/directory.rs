use super::publish;
use std::{
    error::Error,
    fs,
    os::unix::fs::symlink,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};

use super::publish::test_hooks::{self, TestFault};

fn set_fault(fault: TestFault) {
    test_hooks::TEST_FAULT.with(|slot| slot.set(Some(fault)));
}

#[test]
fn publishes_complete_directory() -> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let destination = root.path().join("bundle");
    publish::create_directory(&destination, |staging| {
        fs::write(staging.join("page.json"), b"evidence")?;
        Ok(())
    })?;
    assert_eq!(fs::read(destination.join("page.json"))?, b"evidence");
    let repeated = publish::create_directory(&destination, |staging| {
        fs::write(staging.join("page.json"), b"replacement")?;
        Ok(())
    });
    assert!(repeated.is_err());
    assert_eq!(fs::read(destination.join("page.json"))?, b"evidence");
    assert_eq!(fs::read_dir(root.path())?.count(), 1);
    Ok(())
}

#[test]
fn existing_destination_skips_expensive_writer() -> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let destination = root.path().join("bundle");
    fs::create_dir(&destination)?;
    fs::write(destination.join("page.json"), b"existing")?;
    let mut writer_called = false;

    let result = publish::create_directory(&destination, |_| {
        writer_called = true;
        Ok(())
    });

    assert!(result.is_err(), "existing destination must be rejected");
    assert!(
        !writer_called,
        "existing output must be rejected before staging work"
    );
    assert_eq!(fs::read(destination.join("page.json"))?, b"existing");
    assert_eq!(fs::read_dir(root.path())?.count(), 1);
    Ok(())
}

#[test]
fn failed_refresh_preserves_the_existing_directory() -> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let destination = root.path().join("bundle");
    publish::create_directory(&destination, |staging| {
        fs::write(staging.join("page.json"), b"old output")?;
        Ok(())
    })?;
    let prepared: publish::PreparedDirectoryReplacement =
        publish::prepare_directory_replacement(&destination)?;

    let result = publish::replace_directory(prepared, |staging| {
        fs::write(staging.join("page.json"), b"partial new output")?;
        Err::<(), Box<dyn Error>>("injected refresh failure".into())
    });

    let Err(error) = result else {
        return Err("failed refresh unexpectedly succeeded".into());
    };
    assert!(matches!(
        &error,
        publish::DirectoryPublishError::BeforePublication(_)
    ));
    assert_eq!(fs::read(destination.join("page.json"))?, b"old output");
    assert_eq!(fs::read_dir(root.path())?.count(), 1);
    Ok(())
}

#[test]
fn prepared_directory_reads_are_bounded_and_inventory_does_not_follow_links()
-> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let destination = root.path().join("bundle");
    let foreign = root.path().join("outside.txt");
    fs::create_dir(&destination)?;
    fs::create_dir(destination.join("nested"))?;
    fs::write(destination.join("manifest.json"), b"{\"ok\":true}")?;
    fs::write(destination.join("nested/payload"), b"nested bytes")?;
    fs::write(&foreign, b"outside bytes")?;
    symlink(&foreign, destination.join("outside-link"))?;
    let prepared = publish::prepare_directory_replacement(&destination)?;

    assert_eq!(prepared.read_file("manifest.json", 32)?, b"{\"ok\":true}");
    assert!(prepared.read_file("manifest.json", 4).is_err());
    assert!(prepared.read_file("outside-link", 32).is_err());
    assert!(prepared.read_file("../outside.txt", 32).is_err());
    let entries: Vec<publish::DirectoryEntry> = prepared.entries(8)?;
    assert!(entries.iter().any(|entry| {
        entry.relative_path == std::path::Path::new("nested/payload")
            && entry.kind == publish::DirectoryEntryKind::File
    }));
    assert!(entries.iter().any(|entry| {
        entry.relative_path == std::path::Path::new("outside-link")
            && entry.kind == publish::DirectoryEntryKind::Symlink
    }));
    assert_eq!(fs::read(&foreign)?, b"outside bytes");
    Ok(())
}

#[test]
fn prepared_directory_rejects_a_symlink_destination() -> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let target = root.path().join("target");
    let destination = root.path().join("bundle");
    fs::create_dir(&target)?;
    fs::write(target.join("page.json"), b"target")?;
    symlink(&target, &destination)?;

    assert!(publish::prepare_directory_replacement(&destination).is_err());
    assert!(fs::symlink_metadata(&destination)?.file_type().is_symlink());
    assert_eq!(fs::read(target.join("page.json"))?, b"target");
    Ok(())
}

#[test]
fn replacement_rejects_a_changed_target_before_running_writer() -> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let destination = root.path().join("bundle");
    let moved = root.path().join("checked-old-output");
    let foreign = root.path().join("foreign.txt");
    fs::write(&foreign, b"foreign target")?;
    publish::create_directory(&destination, |staging| {
        fs::write(staging.join("page.json"), b"old output")?;
        Ok(())
    })?;
    let prepared = publish::prepare_directory_replacement(&destination)?;
    fs::rename(&destination, &moved)?;
    symlink(&foreign, &destination)?;
    let mut writer_called = false;

    let result = publish::replace_directory(prepared, |_| {
        writer_called = true;
        Ok(())
    });

    assert!(result.is_err(), "changed target must stop replacement");
    assert!(
        !writer_called,
        "changed target must stop before staging work"
    );
    assert!(fs::symlink_metadata(&destination)?.file_type().is_symlink());
    assert_eq!(fs::read(moved.join("page.json"))?, b"old output");
    assert_eq!(fs::read(&foreign)?, b"foreign target");
    assert_eq!(fs::read_dir(root.path())?.count(), 3);
    Ok(())
}

#[test]
fn refresh_exposes_only_complete_old_or_new_directory_contents() -> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let destination = root.path().join("bundle");
    publish::create_directory(&destination, |staging| {
        fs::write(staging.join("payload"), b"old complete payload")?;
        Ok(())
    })?;
    let prepared = publish::prepare_directory_replacement(&destination)?;
    let running = Arc::new(AtomicBool::new(true));
    let read_errors = Arc::new(std::sync::Mutex::new(Vec::new()));
    let reader_running = Arc::clone(&running);
    let reader_errors = Arc::clone(&read_errors);
    let reader_path = destination.join("payload");
    let reader = thread::spawn(move || {
        while reader_running.load(Ordering::Acquire) {
            match fs::read(&reader_path) {
                Ok(payload)
                    if payload == b"old complete payload" || payload == b"new complete payload" => {
                }
                Ok(payload) => reader_errors
                    .lock()
                    .expect("reader error lock is available")
                    .push(format!("partial payload: {payload:?}")),
                Err(error) => reader_errors
                    .lock()
                    .expect("reader error lock is available")
                    .push(error.to_string()),
            }
        }
    });

    publish::replace_directory(prepared, |staging| {
        fs::write(staging.join("payload"), b"new complete payload")?;
        Ok(())
    })?;
    running.store(false, Ordering::Release);
    reader.join().map_err(|_| "directory reader panicked")?;

    assert!(
        read_errors
            .lock()
            .expect("reader error lock is available")
            .is_empty(),
        "refresh readers observed an incomplete output"
    );
    assert_eq!(
        fs::read(destination.join("payload"))?,
        b"new complete payload"
    );
    Ok(())
}

#[test]
fn unsupported_exchange_preserves_existing_directory() -> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let destination = root.path().join("bundle");
    publish::create_directory(&destination, |staging| {
        fs::write(staging.join("page.json"), b"old output")?;
        Ok(())
    })?;
    let prepared = publish::prepare_directory_replacement(&destination)?;
    set_fault(TestFault::UnsupportedDirectoryExchange);

    let result = publish::replace_directory(prepared, |staging| {
        fs::write(staging.join("page.json"), b"new output")?;
        Ok(())
    });

    let Err(error) = result else {
        return Err("unsupported exchange unexpectedly succeeded".into());
    };
    assert!(matches!(
        &error,
        publish::DirectoryPublishError::BeforePublication(_)
    ));
    assert!(error.to_string().contains("RENAME_EXCHANGE"));
    assert_eq!(fs::read(destination.join("page.json"))?, b"old output");
    assert_eq!(fs::read_dir(root.path())?.count(), 1);
    Ok(())
}

#[test]
fn refresh_race_keeps_foreign_symlink_at_reported_path() -> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let destination = root.path().join("bundle");
    let moved = root.path().join("checked-old-output");
    let foreign = root.path().join("foreign.txt");
    fs::write(&foreign, b"foreign target")?;
    publish::create_directory(&destination, |staging| {
        fs::write(staging.join("page.json"), b"old output")?;
        Ok(())
    })?;
    let prepared = publish::prepare_directory_replacement(&destination)?;
    let raced_destination = destination.clone();
    let raced_moved = moved.clone();
    let raced_foreign = foreign.clone();
    test_hooks::set_before_directory_exchange(move || {
        fs::rename(&raced_destination, &raced_moved)?;
        symlink(&raced_foreign, &raced_destination)
    });

    let result = publish::replace_directory(prepared, |staging| {
        fs::write(staging.join("page.json"), b"new output")?;
        Ok(())
    });

    let Err(error) = result else {
        return Err("racing destination replacement unexpectedly succeeded".into());
    };
    let publish::DirectoryPublishError::PublishedReplacementUncertain { retained_path, .. } =
        &error
    else {
        return Err(format!("wrong race error: {error}").into());
    };
    assert!(
        retained_path.exists(),
        "displaced foreign entry must be retained"
    );
    assert!(
        fs::symlink_metadata(retained_path)?
            .file_type()
            .is_symlink(),
        "foreign symlink must not be followed or removed"
    );
    assert_eq!(fs::read(&foreign)?, b"foreign target");
    assert_eq!(fs::read(destination.join("page.json"))?, b"new output");
    assert_eq!(fs::read(moved.join("page.json"))?, b"old output");
    Ok(())
}

#[test]
fn concurrent_new_directory_publication_never_replaces_the_winner() -> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let destination = root.path().join("bundle");
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let mut workers = Vec::new();

    for payload in [b"first".as_slice(), b"second".as_slice()] {
        let destination = destination.clone();
        let barrier = Arc::clone(&barrier);
        let payload = payload.to_vec();
        workers.push(thread::spawn(move || {
            publish::create_directory(&destination, |staging| {
                barrier.wait();
                fs::write(staging.join("payload"), payload)?;
                Ok(())
            })
            .is_ok()
        }));
    }

    let successes = workers
        .into_iter()
        .map(|worker| worker.join().map_err(|_| "publisher thread panicked"))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(successes.iter().filter(|success| **success).count(), 1);
    let payload = fs::read(destination.join("payload"))?;
    assert!(payload == b"first" || payload == b"second");
    assert_eq!(fs::read_dir(root.path())?.count(), 1);
    Ok(())
}

#[test]
fn raced_symlink_is_not_followed_or_replaced_during_new_publication() -> Result<(), Box<dyn Error>>
{
    let root = tempfile::tempdir()?;
    let destination = root.path().join("bundle");
    let foreign = root.path().join("foreign.txt");
    fs::write(&foreign, b"foreign target")?;

    let result = publish::create_directory(&destination, |staging| {
        fs::write(staging.join("payload"), b"new output")?;
        symlink(&foreign, &destination)?;
        Ok(())
    });

    assert!(
        result.is_err(),
        "raced symlink must block no-replace publication"
    );
    assert!(fs::symlink_metadata(&destination)?.file_type().is_symlink());
    assert_eq!(fs::read(&foreign)?, b"foreign target");
    assert_eq!(fs::read_dir(root.path())?.count(), 2);
    Ok(())
}

#[test]
fn replacement_sync_failure_reports_uncertainty_after_atomic_commit() -> Result<(), Box<dyn Error>>
{
    let root = tempfile::tempdir()?;
    let destination = root.path().join("bundle");
    publish::create_directory(&destination, |staging| {
        fs::write(staging.join("page.json"), b"old output")?;
        Ok(())
    })?;
    let prepared = publish::prepare_directory_replacement(&destination)?;
    set_fault(TestFault::DirectorySync);

    let result = publish::replace_directory(prepared, |staging| {
        fs::write(staging.join("page.json"), b"new output")?;
        Ok(())
    });

    let Err(error) = result else {
        return Err("injected directory sync failure unexpectedly succeeded".into());
    };
    assert!(matches!(
        &error,
        publish::DirectoryPublishError::PublishedDurabilityUncertain(_)
    ));
    assert!(error.to_string().contains("blind retry is unsafe"));
    assert_eq!(fs::read(destination.join("page.json"))?, b"new output");
    Ok(())
}

#[test]
fn failure_cleans_staging() -> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let destination = root.path().join("bundle");
    let result = publish::create_directory(&destination, |staging| {
        fs::write(staging.join("page.json"), b"partial")?;
        Err::<(), Box<dyn Error>>("injected write failure".into())
    });
    let Err(error) = result else {
        return Err("write failure unexpectedly published".into());
    };
    assert!(matches!(
        &error,
        publish::DirectoryPublishError::BeforePublication(_)
    ));
    let Some(source) = error.source() else {
        return Err("write error source is missing".into());
    };
    assert_eq!(source.to_string(), "injected write failure");
    assert!(!destination.exists());
    assert_eq!(fs::read_dir(root.path())?.count(), 0);
    Ok(())
}

#[test]
fn sync_failure_keeps_output() -> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let destination = root.path().join("bundle");
    set_fault(TestFault::DirectorySync);

    let result = publish::create_directory(&destination, |staging| {
        fs::write(staging.join("page.json"), b"complete")?;
        Ok(())
    });
    let Err(error) = result else {
        return Err("directory sync failure unexpectedly succeeded".into());
    };

    assert!(matches!(
        &error,
        publish::DirectoryPublishError::PublishedDurabilityUncertain(_)
    ));
    assert!(error.to_string().contains("blind retry is unsafe"));
    let Some(source) = error.source() else {
        return Err("directory sync error source is missing".into());
    };
    assert_eq!(source.to_string(), "injected output-directory sync failure");
    assert_eq!(fs::read(destination.join("page.json"))?, b"complete");
    assert_eq!(fs::read_dir(root.path())?.count(), 1);
    Ok(())
}

#[test]
fn parent_rename_stays_bound() -> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let parent = root.path().join("parent");
    let moved = root.path().join("moved");
    fs::create_dir(&parent)?;
    publish::create_directory(&parent.join("bundle"), |staging| {
        fs::write(staging.join("page.json"), b"evidence")?;
        fs::rename(&parent, &moved)?;
        fs::create_dir(&parent)?;
        Ok(())
    })?;
    assert_eq!(fs::read(moved.join("bundle/page.json"))?, b"evidence");
    assert_eq!(fs::read_dir(parent)?.count(), 0);
    Ok(())
}
