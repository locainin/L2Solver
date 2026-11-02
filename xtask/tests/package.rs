#[cfg(unix)]
use std::fs;
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;
#[cfg(unix)]
use std::sync::mpsc;
#[cfg(unix)]
use std::time::Duration;
#[cfg(unix)]
use xtask::package::{MAX_FILES, create_review};
use xtask::package::{PackageError, collect_entries, is_excluded_path};

#[test]
fn vcs_secret_paths() {
    let excluded = [
        "target/debug/app",
        ".git/config",
        "fuzz/corpus/ethernet/input",
        "fuzz/artifacts/crash",
        "docs/evidence/review6/mutants.json",
        "benchmarks/cache/download.zip",
        "benchmarks/results/local-run.json",
        "investigations/private-run/manifest.json",
        "pcap_samples/local/lab/capture.pcapng",
        "pcap_samples/2025/sample/runs/index/index.sqlite",
        "pcap_samples/2025/sample/capture.pcap",
        "pcap_samples/2025/sample/source.json",
        "pcap_samples/kbandla-pcaps.json",
        "pcap_samples",
        "tests/pcaps",
        "tests/pcaps/README.md",
        "tests/pcaps/manifest.json",
        "review",
        "review/notes.txt",
        "capture.pcap",
        "capture.PCAP",
        "capture.pcapng",
        "capture.PCAPNG",
        "capture.cap",
        "capture.CAP",
        ".agents/session-state",
        ".codex/runtime-state",
        "mutants.out/diff/file",
        "rust_out",
        "review-4.zip",
        "review-4.zip.sha256",
        "docs/profiles/heaptrack-assess-review4.zst",
        "docs/profiles/heaptrack-review5.txt",
        "docs/screenshots/heaptrack-assess-review5.png",
        "benchmarks/__pycache__/run.cpython-314.pyc",
        ".pytest_cache/state",
        ".ruff_cache/state",
        ".env",
        "keys/operator.pem",
    ];
    for path in excluded {
        assert!(is_excluded_path(Path::new(path)), "{path}");
    }
    for path in [
        "crates/l2-core/src/lib.rs",
        "docs/investigations.md",
        "benchmarks/runner/capture.py",
        "tests/fixtures/captures.rs",
        "docs/profiles/bloat-review5.txt",
        "docs/reference.zip",
        "docs/profiles/hyperfine-review5.json",
        "docs/screenshots/cli-help-review5.png",
    ] {
        assert!(!is_excluded_path(Path::new(path)), "{path}");
    }
}

#[test]
fn captures_are_excluded_at_any_depth_without_hiding_source_files() {
    for path in [
        "root.pcap",
        "nested/input.PCAP",
        "one/two/packet.pCaPnG",
        "tests/fixtures/packet.CaP",
        "tests/pcaps/fixture.pcap",
        "pcap_samples/source.json",
        "review/review-notes.md",
    ] {
        assert!(is_excluded_path(Path::new(path)), "{path}");
    }

    // Similar source names remain eligible outside the private directories
    for path in [
        "tests/fixtures/captures.rs",
        "tests/pcaps.rs",
        "pcap_samples.rs",
        "review.rs",
        "nested/capture.pcap.rs",
        "nested/capture.cap.json",
        "docs/archives/reference.zip",
        "docs/downloads/example.crdownload",
    ] {
        assert!(!is_excluded_path(Path::new(path)), "{path}");
    }
}

#[test]
#[cfg(unix)]
fn capture_files_and_private_directories_are_excluded_from_packages()
-> Result<(), Box<dyn std::error::Error>> {
    let root = test_root("capture-exclusion")?;
    create_file(&root.join("capture.PCAP"), b"root capture")?;
    create_file(&root.join("capture.pcapng"), b"root capture")?;
    create_file(&root.join("capture.CaP"), b"root capture")?;
    create_file(&root.join("tests/pcaps/fixture.pcap"), b"fixture capture")?;
    create_file(&root.join("tests/pcaps/manifest.json"), b"{}")?;
    create_file(&root.join("tests/pcaps/README.md"), b"fixture notes")?;
    create_file(&root.join("nested/capture.pCaPnG"), b"nested capture")?;
    create_file(&root.join("nested/input.CAP"), b"nested capture")?;
    create_file(&root.join("pcap_samples/source.json"), b"private metadata")?;
    create_file(&root.join("review/notes.txt"), b"private review")?;
    // Excluded directories must not be traversed even when they contain a symlink
    std::os::unix::fs::symlink("missing", root.join("review/alias"))?;
    create_file(
        &root.join("tests/fixtures/captures.rs"),
        b"// fixture source",
    )?;
    create_file(&root.join("docs/reference.zip"), b"reference archive")?;

    let entries = collect_entries(&root)?;
    let paths = entries
        .iter()
        .map(|entry| entry.path().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        paths,
        vec![
            String::from("docs/reference.zip"),
            String::from("tests/fixtures/captures.rs"),
        ]
    );
    remove_test_root(&root)?;
    Ok(())
}

#[test]
#[cfg(unix)]
fn package_skips_secrets_and_sorts() -> Result<(), Box<dyn std::error::Error>> {
    let root = test_root("collection")?;
    create_file(&root.join("z.txt"), b"last")?;
    create_file(&root.join("a.txt"), b"first")?;
    create_file(&root.join(".env"), b"TOKEN=not-for-archive")?;
    let pem = format!(
        "-----BEGIN {label}-----\nZmFrZQ==\n-----END {label}-----",
        label = "PRIVATE KEY"
    );
    create_file(&root.join("notes.txt"), pem.as_bytes())?;
    create_file(
        &root.join("marker.rs"),
        b"const MARKER: &str = \"-----BEGIN PRIVATE KEY-----\";",
    )?;
    let mut assignment = b"PASSWORD=".to_vec();
    assignment.extend_from_slice(b"super-secret");
    create_file(&root.join("config.txt"), &assignment)?;
    let mut quoted_assignment = b"PASSWORD=".to_vec();
    quoted_assignment.push(b'\"');
    quoted_assignment.extend_from_slice(b"quoted-secret");
    quoted_assignment.push(b'\"');
    create_file(&root.join("quoted-config.txt"), &quoted_assignment)?;
    create_file(&root.join("target/debug/ignored"), b"artifact")?;
    create_file(
        &root.join("investigations/private-run/manifest.json"),
        b"local investigation",
    )?;
    create_file(
        &root.join("pcap_samples/local/lab/capture.pcapng"),
        b"local capture",
    )?;
    create_file(
        &root.join("pcap_samples/2025/sample/capture.pcap.gz"),
        b"compressed capture",
    )?;
    create_file(
        &root.join("pcap_samples/2025/sample/capture.pcapng.gz"),
        b"compressed next-generation capture",
    )?;
    create_file(
        &root.join("pcap_samples/2025/sample/Unconfirmed 12345.crdownload"),
        b"partial browser download",
    )?;
    // Safari stores an unfinished download inside a directory with this suffix
    create_file(
        &root.join("pcap_samples/2025/sample/browser.pcap.download/Contents.plist"),
        b"partial browser download details",
    )?;
    create_file(&root.join("pcap_samples/2025/sample/source.json"), b"{}")?;
    create_file(&root.join("benchmarks/results/local.json"), b"local result")?;
    create_file(
        &root.join("docs/screenshots/heaptrack-local.png"),
        b"profile image",
    )?;

    let entries = collect_entries(&root)?;
    let paths = entries
        .iter()
        .map(|entry| entry.path().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        paths,
        vec![
            String::from("a.txt"),
            String::from("marker.rs"),
            String::from("z.txt")
        ]
    );
    assert!(entries.len() < MAX_FILES);
    remove_test_root(&root)?;
    Ok(())
}

#[test]
#[cfg(unix)]
fn package_collection_rejects_symlinks() -> Result<(), Box<dyn std::error::Error>> {
    let root = test_root("symlink")?;
    create_file(&root.join("source.txt"), b"source")?;
    std::os::unix::fs::symlink(root.join("source.txt"), root.join("alias.txt"))?;

    assert!(matches!(
        collect_entries(&root),
        Err(PackageError::Symlink(_))
    ));
    remove_test_root(&root)?;
    Ok(())
}

#[test]
#[cfg(unix)]
fn package_collection_symlinked_parent_directories() -> Result<(), Box<dyn std::error::Error>> {
    let root = test_root("symlink-parent")?;
    let outside = test_root("symlink-parent-target")?;
    create_file(&outside.join("source.txt"), b"outside")?;
    std::os::unix::fs::symlink(&outside, root.join("linked"))?;

    assert!(matches!(
        collect_entries(&root),
        Err(PackageError::Symlink(path)) if path == root.join("linked")
    ));
    remove_test_root(&root)?;
    remove_test_root(&outside)?;
    Ok(())
}

#[test]
#[cfg(unix)]
fn package_collection_symlinked_root_ancestors() -> Result<(), Box<dyn std::error::Error>> {
    let root_parent = test_root("symlink-root-ancestor")?;
    let target_parent = test_root("symlink-root-ancestor-target")?;
    create_file(&target_parent.join("workspace/source.txt"), b"outside")?;
    std::os::unix::fs::symlink(&target_parent, root_parent.join("linked"))?;

    assert!(matches!(
        collect_entries(&root_parent.join("linked/workspace")),
        Err(PackageError::Symlink(_))
    ));
    remove_test_root(&root_parent)?;
    remove_test_root(&target_parent)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn package_collection_fifo_without_blocking() -> Result<(), Box<dyn std::error::Error>> {
    let root = test_root("fifo")?;
    let fifo = root.join("named-pipe");
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )?;

    let (sender, receiver) = mpsc::channel();
    let worker_root = root.clone();
    std::thread::spawn(move || {
        let _ = sender.send(collect_entries(&worker_root));
    });
    let result = receiver
        .recv_timeout(Duration::from_secs(2))
        .map_err(|_| std::io::Error::other("FIFO inspection blocked"))?;
    assert!(matches!(
        result,
        Err(PackageError::SpecialFile(path)) if path == fifo
    ));
    remove_test_root(&root)?;
    Ok(())
}

#[test]
#[cfg(unix)]
fn unicode_names_use_utf8_headers() -> Result<(), Box<dyn std::error::Error>> {
    let root = test_root("unicode-name")?;
    let name = "café.txt";
    create_file(&root.join(name), b"unicode")?;

    let package = create_review(&root, 7)?;
    let archive = fs::read(&package.archive)?;
    let Some((local_flags, local_name)) = zip_header(&archive, [0x50, 0x4b, 0x03, 0x04], 6, 26, 30)
    else {
        return Err(std::io::Error::other("local ZIP header missing").into());
    };
    let Some((central_flags, central_name)) =
        zip_header(&archive, [0x50, 0x4b, 0x01, 0x02], 8, 28, 46)
    else {
        return Err(std::io::Error::other("central ZIP header missing").into());
    };
    assert_eq!(local_flags & 0x0800, 0x0800);
    assert_eq!(central_flags & 0x0800, 0x0800);
    assert_eq!(local_name, name.as_bytes());
    assert_eq!(central_name, name.as_bytes());

    remove_test_root(&root)?;
    Ok(())
}

#[test]
#[cfg(unix)]
fn review_package_repeatable_refuses_overwrite() -> Result<(), Box<dyn std::error::Error>> {
    let first_root = test_root("deterministic-first")?;
    let second_root = test_root("deterministic-second")?;
    for root in [&first_root, &second_root] {
        create_file(&root.join("b.txt"), b"second")?;
        create_file(&root.join("a.txt"), b"first")?;
    }

    let first = create_review(&first_root, 5)?;
    let second = create_review(&second_root, 5)?;
    assert_eq!(fs::read(&first.archive)?, fs::read(&second.archive)?);
    assert_eq!(fs::read(&first.checksum)?, fs::read(&second.checksum)?);
    assert_eq!(fs::read(&first.manifest)?, fs::read(&second.manifest)?);
    assert!(matches!(
        create_review(&first_root, 5),
        Err(PackageError::ExistingOutput(_))
    ));

    remove_test_root(&first_root)?;
    remove_test_root(&second_root)?;
    Ok(())
}

#[cfg(not(unix))]
#[test]
fn package_collection_reports_unsupported_platform() {
    assert!(matches!(
        collect_entries(Path::new(".")),
        Err(PackageError::UnsupportedPlatform)
    ));
}

#[cfg(unix)]
fn test_root(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let root =
        std::env::temp_dir().join(format!("l2solver-xtask-test-{name}-{}", std::process::id()));
    if let Err(error) = fs::remove_dir_all(&root)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        return Err(error.into());
    }
    fs::create_dir_all(&root)?;
    Ok(root)
}

#[cfg(unix)]
fn create_file(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, bytes)?;
    Ok(())
}

#[cfg(unix)]
fn remove_test_root(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
fn zip_header(
    archive: &[u8],
    signature: [u8; 4],
    flags_offset: usize,
    name_length_offset: usize,
    name_offset: usize,
) -> Option<(u16, Vec<u8>)> {
    let header_offset = archive
        .windows(signature.len())
        .position(|window| window == signature.as_slice())?;
    let flags_start = header_offset.checked_add(flags_offset)?;
    let flags_end = flags_start.checked_add(2)?;
    let flags = u16::from_le_bytes(archive.get(flags_start..flags_end)?.try_into().ok()?);
    let name_length_start = header_offset.checked_add(name_length_offset)?;
    let name_length_end = name_length_start.checked_add(2)?;
    let name_length = usize::from(u16::from_le_bytes(
        archive
            .get(name_length_start..name_length_end)?
            .try_into()
            .ok()?,
    ));
    let name_start = header_offset.checked_add(name_offset)?;
    let name_end = name_start.checked_add(name_length)?;
    Some((flags, archive.get(name_start..name_end)?.to_vec()))
}
