use super::super::{ObjectExportBudget, ObjectExportUsage, observe_object_tree};
use std::{
    cell::Cell,
    error::Error,
    fs,
    os::unix::fs::symlink,
    rc::Rc,
    time::{Duration, Instant},
};

#[test]
fn directory_swap() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("objects");
    let protocol = root.join("http");
    let outside = temporary.path().join("outside");
    fs::create_dir_all(&protocol)?;
    fs::create_dir(&outside)?;
    fs::write(outside.join("secret"), b"host data")?;

    let swapped_protocol = protocol;
    let swapped = Rc::new(Cell::new(false));
    let swap_observed = Rc::clone(&swapped);
    super::NEXT_SCANNED_ENTRY.set(Some(Box::new(move || {
        let result =
            fs::remove_dir(&swapped_protocol).and_then(|()| symlink(&outside, &swapped_protocol));
        swap_observed.set(result.is_ok());
    })));
    let mut usage = ObjectExportUsage::default();
    let scan = observe_object_tree(
        super::policy(
            Instant::now() + Duration::from_secs(2),
            &root,
            1,
            ObjectExportBudget::default(),
        ),
        &mut usage,
    );

    assert!(swapped.get(), "directory swap did not run");
    if let Ok(scan) = scan {
        assert!(
            scan.stable_objects.is_empty(),
            "followed a replaced directory"
        );
        assert_eq!(usage.temporary_files_peak, 0, "counted an external file");
    }
    Ok(())
}
