use super::{
    Entry, MAX_TRAVERSAL_ENTRIES, PackageError, open_nofollow, open_root,
    reserve_traversal_entry, visit_directory_unix,
};
use rustix::fs::OFlags;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn pinned_directory_ignores_path_replacement()
-> Result<(), Box<dyn std::error::Error>> {
    let root = test_root("pinned-directory")?;
    let original = root.join("workspace");
    fs::create_dir_all(original.join("source"))?;
    fs::write(original.join("source/original.txt"), b"original")?;

    let directory_fd = open_root(&original)?;
    fs::rename(&original, root.join("renamed"))?;
    fs::create_dir_all(original.join("replacement"))?;
    fs::write(original.join("replacement/replacement.txt"), b"replacement")?;

    let mut entries: Vec<Entry> = Vec::new();
    let mut source_bytes = 0;
    let mut traversal_entries = 0;
    visit_directory_unix(
        &original,
        &original,
        directory_fd,
        &mut entries,
        &mut source_bytes,
        &mut traversal_entries,
    )?;

    assert_eq!(source_bytes, 8);
    let entry = entries
        .first()
        .ok_or_else(|| std::io::Error::other("pinned directory produced no entry"))?;
    assert_eq!(entries.len(), 1);
    assert_eq!(entry.path(), "source/original.txt");
    assert_eq!(entry.bytes(), b"original");
    remove_test_root(&root)?;
    Ok(())
}

#[test]
fn raw_directory_budget_enforced_collection() {
    let mut count = MAX_TRAVERSAL_ENTRIES;

    assert!(matches!(
        reserve_traversal_entry(&mut count),
        Err(PackageError::TooManyEntries { count, maximum })
            if count == MAX_TRAVERSAL_ENTRIES + 1 && maximum == MAX_TRAVERSAL_ENTRIES
    ));
    assert_eq!(count, MAX_TRAVERSAL_ENTRIES);
}

#[test]
fn nofollow_rejects_replaced_symlink() -> Result<(), Box<dyn std::error::Error>> {
    let root = test_root("replaced-entry")?;
    let selected = root.join("selected.txt");
    let outside = root.join("outside.txt");
    fs::write(&selected, b"selected")?;
    fs::write(&outside, b"outside")?;
    let directory_fd = open_root(&root)?;

    fs::remove_file(&selected)?;
    std::os::unix::fs::symlink(&outside, &selected)?;

    let result = open_nofollow(
        &directory_fd,
        OsStr::new("selected.txt"),
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        &selected,
    );
    assert!(matches!(
        result,
        Err(PackageError::Symlink(path)) if path == selected
    ));
    remove_test_root(&root)?;
    Ok(())
}

fn test_root(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "l2solver-xtask-descriptor-test-{name}-{}",
        std::process::id()
    ));
    if let Err(error) = fs::remove_dir_all(&root)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        return Err(error.into());
    }
    fs::create_dir_all(&root)?;
    Ok(root)
}

fn remove_test_root(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::remove_dir_all(root)?;
    Ok(())
}
