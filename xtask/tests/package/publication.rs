use super::{Entry, MAX_ARCHIVE_BYTES, MAX_FILES, PackageError};
use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn staged_output_published_by_link()
-> Result<(), Box<dyn std::error::Error>> {
    let root = test_root("unnamed-output")?;
    let workspace = root.join("workspace");
    fs::create_dir(&workspace)?;
    fs::write(workspace.join("source.txt"), b"source")?;
    let collected = super::select::collect_entries_pinned(&workspace)?;
    let output = workspace.join("review-71.zip");
    let staged = super::publish::stage_output(
        &collected.root_fd,
        Path::new("review-71.zip"),
        &output,
        b"complete archive",
    )?;

    assert!(!output.exists());
    super::publish::publish_output(&collected.root_fd, &staged)?;

    assert_eq!(fs::read(&output)?, b"complete archive");
    remove_test_root(&root)?;
    Ok(())
}

#[test]
fn output_collision_preserves_existing_files()
-> Result<(), Box<dyn std::error::Error>> {
    let root = test_root("collision-preserves")?;
    let workspace = root.join("workspace");
    fs::create_dir(&workspace)?;
    fs::write(workspace.join("source.txt"), b"source")?;
    let collected = super::select::collect_entries_pinned(&workspace)?;
    let first_path = workspace.join("review-72.zip");
    let second_path = workspace.join("review-72.zip.sha256");
    let first = super::publish::stage_output(
        &collected.root_fd,
        Path::new("review-72.zip"),
        &first_path,
        b"complete archive",
    )?;
    let second = super::publish::stage_output(
        &collected.root_fd,
        Path::new("review-72.zip.sha256"),
        &second_path,
        b"checksum",
    )?;
    super::publish::publish_output(&collected.root_fd, &first)?;
    fs::write(&second_path, b"unrelated replacement")?;

    let result = super::publish::publish_output(&collected.root_fd, &second);

    assert!(matches!(result, Err(PackageError::ExistingOutput(path)) if path == second_path));
    assert_eq!(fs::read(&first_path)?, b"complete archive");
    assert_eq!(fs::read(&second_path)?, b"unrelated replacement");
    remove_test_root(&root)?;
    Ok(())
}

#[test]
fn replaced_root_blocks_publication()
-> Result<(), Box<dyn std::error::Error>> {
    let root = test_root("replaced-publication")?;
    let original = root.join("workspace");
    let renamed = root.join("renamed");
    let replacement = root.join("replacement");
    fs::create_dir_all(&original)?;
    fs::write(original.join("source.txt"), b"source")?;

    let collected = super::select::collect_entries_pinned(&original)?;
    let archive_bytes = super::build_zip(&collected.entries)?;
    let archive_sha256 = super::digest_hex(&archive_bytes);

    // Keep an output in the pinned directory so the second create-new fails
    fs::write(original.join("review-41.zip.sha256"), b"keep")?;
    fs::rename(&original, &renamed)?;
    fs::create_dir_all(&replacement)?;
    // A path-based publisher would hit this sentinel before reaching the old
    // directory and would report the wrong output as already existing
    fs::write(replacement.join("review-41.zip"), b"outside sentinel")?;
    std::os::unix::fs::symlink(&replacement, &original)?;

    let result = super::publish_review(
        &original,
        41,
        &collected.root_fd,
        &collected.entries,
        &archive_bytes,
        &archive_sha256,
    );

    assert!(matches!(
        result,
        Err(PackageError::ExistingOutput(path)) if path == original.join("review-41.zip.sha256")
    ));
    assert!(!renamed.join("review-41.zip").exists());
    assert_eq!(
        fs::read(renamed.join("review-41.zip.sha256"))?,
        b"keep"
    );
    assert_eq!(
        fs::read(replacement.join("review-41.zip"))?,
        b"outside sentinel"
    );
    assert!(!replacement.join("review-41.zip.sha256").exists());
    assert!(!replacement.join("review-41.manifest").exists());

    remove_test_root(&root)?;
    Ok(())
}

#[test]
fn renamed_root_receives_normal_publication() -> Result<(), Box<dyn std::error::Error>> {
    let root = test_root("renamed-publication")?;
    let original = root.join("workspace");
    let renamed = root.join("renamed");
    let replacement = root.join("replacement");
    fs::create_dir_all(&original)?;
    fs::write(original.join("source.txt"), b"source")?;

    let collected = super::select::collect_entries_pinned(&original)?;
    let archive_bytes = super::build_zip(&collected.entries)?;
    let archive_sha256 = super::digest_hex(&archive_bytes);
    fs::rename(&original, &renamed)?;
    fs::create_dir_all(&replacement)?;
    std::os::unix::fs::symlink(&replacement, &original)?;

    let result = super::publish_review(
        &original,
        43,
        &collected.root_fd,
        &collected.entries,
        &archive_bytes,
        &archive_sha256,
    )?;

    assert_eq!(result.archive, original.join("review-43.zip"));
    assert_eq!(result.checksum, original.join("review-43.zip.sha256"));
    assert_eq!(result.manifest, original.join("review-43.manifest"));
    assert_eq!(result.file_count, 1);
    for name in [
        "review-43.zip",
        "review-43.zip.sha256",
        "review-43.manifest",
    ] {
        assert!(renamed.join(name).is_file(), "missing {name} in pinned root");
        assert!(!replacement.join(name).exists(), "redirected {name}");
    }
    assert!(fs::read_to_string(renamed.join("review-43.manifest"))?.contains("source.txt\t6\t"));

    remove_test_root(&root)?;
    Ok(())
}

#[test]
fn classic_zip_entry_count_sentinel() {
    assert_eq!(MAX_FILES, usize::from(u16::MAX) - 1);
    let entry = Entry {
        path: String::from("a"),
        bytes: Vec::new(),
        sha256: String::new(),
    };
    let entries = vec![entry; MAX_FILES + 1];

    assert!(matches!(
        super::build_zip(&entries),
        Err(PackageError::TooManyFiles { count, maximum })
            if count == MAX_FILES + 1 && maximum == MAX_FILES
    ));
}

#[test]
fn archive_size_limit_is_enforced() {
    assert!(matches!(
        super::archive::checked_archive_size([(1, MAX_ARCHIVE_BYTES)]),
        Err(PackageError::ArchiveTooLarge { maximum, .. })
            if maximum == MAX_ARCHIVE_BYTES
    ));
}

fn test_root(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "l2solver-xtask-publication-test-{name}-{}",
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
