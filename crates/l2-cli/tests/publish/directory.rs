use super::publish;
use std::{error::Error, fs};

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
