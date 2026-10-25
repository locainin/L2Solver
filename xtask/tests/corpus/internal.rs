use super::{CorpusLimits, copy_corpus_with_limits};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "l2solver-corpus-test-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root)?;
        Ok(Self { root })
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn limits(entries: usize, files: usize, bytes: u64, depth: usize) -> CorpusLimits {
    CorpusLimits {
        entries,
        files,
        bytes,
        depth,
    }
}

fn copy_failure(
    source: &std::path::Path,
    destination: &std::path::Path,
    limits: CorpusLimits,
    message: &str,
) -> Result<super::CorpusCopyError, Box<dyn std::error::Error>> {
    match copy_corpus_with_limits(source, destination, limits) {
        Ok(()) => Err(message.into()),
        Err(error) => Ok(error),
    }
}

#[test]
fn raw_entry_traversal_respects_limit() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let source = fixture.path("source");
    let destination = fixture.path("destination");
    fs::create_dir(&source)?;
    fs::create_dir(&destination)?;
    for name in ["a", "b", "c"] {
        fs::create_dir(source.join(name))?;
    }

    let error = copy_failure(
        &source,
        &destination,
        limits(2, 10, 100, 10),
        "the third raw entry must exceed the traversal limit",
    )?;

    assert!(error.to_string().contains("more than 2 entries"));
    Ok(())
}

#[test]
fn actual_bytes_checked_while_copying() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let source = fixture.path("source");
    let destination = fixture.path("destination");
    fs::create_dir(&source)?;
    fs::create_dir(&destination)?;
    fs::write(source.join("seed"), b"12345")?;

    let error = copy_failure(
        &source,
        &destination,
        limits(10, 10, 4, 10),
        "the fifth byte must exceed the byte limit",
    )?;

    assert!(error.to_string().contains("more than 4 bytes"));
    Ok(())
}

#[test]
fn nested_corpus_depth_is_bounded() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let source = fixture.path("source");
    let destination = fixture.path("destination");
    fs::create_dir_all(source.join("one/two"))?;
    fs::create_dir(&destination)?;

    let error = copy_failure(
        &source,
        &destination,
        limits(10, 10, 100, 1),
        "the second nested directory must exceed the depth limit",
    )?;

    assert!(error.to_string().contains("depth limit 1"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn source_symlink_is_never_followed() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new()?;
    let source = fixture.path("source");
    let destination = fixture.path("destination");
    let outside = fixture.path("outside");
    fs::create_dir(&source)?;
    fs::create_dir(&destination)?;
    fs::write(&outside, b"outside")?;
    symlink(&outside, source.join("seed"))?;

    let error = copy_failure(
        &source,
        &destination,
        limits(10, 10, 100, 10),
        "a corpus symlink must fail closed",
    )?;

    assert!(error.to_string().contains("symlink"));
    assert!(!destination.join("seed").exists());
    Ok(())
}

#[test]
fn nested_regular_files_copy_exactly() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let source = fixture.path("source");
    let destination = fixture.path("destination");
    fs::create_dir_all(source.join("nested"))?;
    fs::create_dir(&destination)?;
    fs::write(source.join("nested/seed"), b"fuzz-seed")?;

    copy_corpus_with_limits(&source, &destination, limits(10, 10, 100, 10))?;

    assert_eq!(fs::read(destination.join("nested/seed"))?, b"fuzz-seed");
    Ok(())
}
