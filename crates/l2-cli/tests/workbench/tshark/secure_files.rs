use super::{
    VerifiedExecutable, Workspace, descriptor_source, open_trusted_directory, validate_directory,
};
use rustix::io::{FdFlags, fcntl_getfd};
use std::{
    error::Error,
    ffi::OsStr,
    fs::{self, File, Permissions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    path::Path,
    process::Command,
};

fn set_mode(path: &Path, mode: u32) -> Result<(), Box<dyn Error>> {
    fs::set_permissions(path, Permissions::from_mode(mode))?;
    Ok(())
}

fn write_executable(path: &Path, contents: &[u8]) -> Result<(), Box<dyn Error>> {
    fs::write(path, contents)?;
    set_mode(path, 0o755)
}

#[test]
fn private_file_access_exclusivity() -> Result<(), Box<dyn Error>> {
    let parent = tempfile::tempdir()?;
    let workspace = Workspace::new(Some(parent.path()))?;
    assert_eq!(workspace.handle.metadata()?.mode() & 0o077, 0);
    let mut file = workspace.create_file(OsStr::new("capture"))?;
    file.write_all(b"capture data")?;
    assert_eq!(fs::read(workspace.path().join("capture"))?, b"capture data");
    assert_eq!(file.metadata()?.mode() & 0o777, 0o600);
    assert!(fcntl_getfd(&file)?.contains(FdFlags::CLOEXEC));
    assert_eq!(
        workspace
            .create_file(OsStr::new("capture"))
            .err()
            .map(|error| error.kind()),
        Some(std::io::ErrorKind::AlreadyExists)
    );
    Ok(())
}

#[test]
fn private_file_leaf_validation() -> Result<(), Box<dyn Error>> {
    let parent = tempfile::tempdir()?;
    let workspace = Workspace::new(Some(parent.path()))?;
    for name in ["", ".", "..", "/absolute", "nested/file", "name/", "name/."] {
        let error = workspace.create_file(OsStr::new(name)).err();
        assert_eq!(
            error.map(|error| error.kind()),
            Some(std::io::ErrorKind::InvalidInput),
            "name {name:?}"
        );
    }
    Ok(())
}

#[test]
fn private_file_symlink_rejection() -> Result<(), Box<dyn Error>> {
    let parent = tempfile::tempdir()?;
    let outside = parent.path().join("outside");
    fs::write(&outside, b"unchanged")?;
    let workspace = Workspace::new(Some(parent.path()))?;
    symlink(&outside, workspace.path().join("capture"))?;
    assert!(workspace.create_file(OsStr::new("capture")).is_err());
    assert_eq!(fs::read(outside)?, b"unchanged");
    Ok(())
}

#[test]
fn private_file_umasks() -> Result<(), Box<dyn Error>> {
    const CHILD: &str = "L2_TSHARK_SECURE_FILES_UMASK_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let workspace = Workspace::new(None)?;
        assert_eq!(workspace.handle.metadata()?.mode() & 0o777, 0o700);
        let file = workspace.create_file(OsStr::new("keylog"))?;
        assert_eq!(file.metadata()?.mode() & 0o777, 0o600);
        return Ok(());
    }
    let executable = std::env::current_exe()?;
    for mask in ["022", "077"] {
        let status = Command::new("sh")
            .args(["-c", "umask \"$1\"; exec \"$2\" --exact workbench::tshark::secure_files::tests::private_file_umasks", "umask-check", mask])
            .arg(&executable)
            .env(CHILD, "1")
            .status()?;
        assert!(status.success(), "umask {mask} failed with {status}");
    }
    Ok(())
}

#[test]
fn workspace_ancestry_rejection() -> Result<(), Box<dyn Error>> {
    let parent = tempfile::tempdir()?;
    let unsafe_directory = parent.path().join("unsafe");
    let child = unsafe_directory.join("child");
    fs::create_dir_all(&child)?;
    set_mode(&unsafe_directory, 0o777)?;
    assert!(Workspace::new(Some(&unsafe_directory)).is_err());
    assert!(Workspace::new(Some(&child)).is_err());
    assert_eq!(fs::read_dir(&child)?.count(), 0);
    Ok(())
}

#[test]
fn trusted_sticky_parent() -> Result<(), Box<dyn Error>> {
    let parent = tempfile::tempdir()?;
    let sticky = parent.path().join("sticky");
    fs::create_dir(&sticky)?;
    set_mode(&sticky, 0o1777)?;
    let path = {
        let workspace = Workspace::new(Some(&sticky))?;
        let path = workspace.path().to_owned();
        assert!(path.exists());
        path
    };
    assert!(!path.exists(), "workspace was not cleaned up");
    Ok(())
}

#[test]
fn foreign_sticky_owner() -> Result<(), Box<dyn Error>> {
    let parent = tempfile::tempdir()?;
    set_mode(parent.path(), 0o1777)?;
    let directory = File::open(parent.path())?;
    let mut metadata = rustix::fs::fstat(directory)?;
    validate_directory(&metadata)?;
    let current_uid = rustix::process::geteuid().as_raw();
    metadata.st_uid = if current_uid == 1 { 2 } else { 1 };
    assert!(validate_directory(&metadata).is_err());
    Ok(())
}

#[test]
fn renamed_parent_anchoring() -> Result<(), Box<dyn Error>> {
    let fixture = tempfile::tempdir()?;
    let parent = fixture.path().join("parent");
    let moved = fixture.path().join("moved");
    let other = fixture.path().join("other");
    fs::create_dir(&parent)?;
    fs::create_dir(&other)?;
    let verified_parent = open_trusted_directory(&parent)?;
    fs::rename(&parent, &moved)?;
    symlink(&other, &parent)?;

    {
        let workspace = Workspace::in_parent(verified_parent)?;
        let mut file = workspace.create_file(OsStr::new("capture"))?;
        file.write_all(b"private")?;
        assert_eq!(fs::read(workspace.path().join("capture"))?, b"private");
        assert_eq!(fs::read_dir(&other)?.count(), 0);
        assert_eq!(fs::read_dir(&moved)?.count(), 1);
        workspace.close()?;
    }
    assert_eq!(fs::read_dir(&moved)?.count(), 0);
    assert_eq!(fs::read_dir(&other)?.count(), 0);
    Ok(())
}

#[test]
fn workspace_close_error() -> Result<(), Box<dyn Error>> {
    let fixture = tempfile::tempdir()?;
    let parent = fixture.path().join("parent");
    fs::create_dir(&parent)?;
    let workspace = Workspace::new(Some(&parent))?;
    let name = workspace
        .path()
        .file_name()
        .ok_or("workspace name missing")?;
    let directory = parent.join(name);

    // Restore permissions before checking the result so cleanup can finish
    set_mode(&parent, 0o500)?;
    let result = workspace.close();
    set_mode(&parent, 0o700)?;
    if directory.exists() {
        fs::remove_dir(&directory)?;
    }
    assert_eq!(
        result.err().map(|error| error.kind()),
        Some(std::io::ErrorKind::PermissionDenied)
    );
    Ok(())
}

#[test]
fn executable_type_permissions() -> Result<(), Box<dyn Error>> {
    let parent = tempfile::tempdir()?;
    let executable = parent.path().join("tool");
    write_executable(&executable, b"tool")?;
    let selected = VerifiedExecutable::open(&executable)?;
    assert_eq!(fs::read(descriptor_source(&selected.file)?)?, b"tool");
    for mode in [0o644, 0o775, 0o757, 0o4755, 0o2755] {
        set_mode(&executable, mode)?;
        assert!(
            VerifiedExecutable::open(&executable).is_err(),
            "accepted mode {mode:o}"
        );
    }
    assert!(VerifiedExecutable::open(parent.path()).is_err());
    Ok(())
}

#[test]
fn executable_ancestry_rejection() -> Result<(), Box<dyn Error>> {
    let parent = tempfile::tempdir()?;
    let unsafe_directory = parent.path().join("unsafe");
    fs::create_dir(&unsafe_directory)?;
    let executable = unsafe_directory.join("tool");
    write_executable(&executable, b"tool")?;
    set_mode(&unsafe_directory, 0o777)?;
    assert!(VerifiedExecutable::open(&executable).is_err());
    Ok(())
}

#[test]
fn trusted_executable_symlink() -> Result<(), Box<dyn Error>> {
    let parent = tempfile::tempdir()?;
    let executable = parent.path().join("tool");
    let link = parent.path().join("link");
    write_executable(&executable, b"tool")?;
    symlink(&executable, &link)?;
    let selected = VerifiedExecutable::open(&link)?;
    assert_eq!(selected.path, executable.canonicalize()?);
    assert_eq!(fs::read(descriptor_source(&selected.file)?)?, b"tool");
    Ok(())
}

#[test]
fn trusted_directory_flags() -> Result<(), Box<dyn Error>> {
    use rustix::fs::{OFlags, fcntl_getfl};

    let parent = tempfile::tempdir()?;
    for path in [Path::new("/"), parent.path()] {
        let directory = open_trusted_directory(path)?;
        assert!(fcntl_getfd(&directory)?.contains(FdFlags::CLOEXEC));
        assert!(fcntl_getfl(&directory)?.contains(OFlags::DIRECTORY | OFlags::NOFOLLOW));
    }
    Ok(())
}

#[test]
fn executable_fifo_rejection() -> Result<(), Box<dyn Error>> {
    use std::{
        process::Stdio,
        time::{Duration, Instant},
    };

    const PROBE: &str = "L2_EXECUTABLE_FIFO_PROBE";
    if std::env::var_os(PROBE).is_some() {
        let directory = tempfile::tempdir()?;
        let fifo = directory.path().join("fifo");
        rustix::fs::mkfifoat(rustix::fs::CWD, &fifo, rustix::fs::Mode::RUSR)?;
        assert!(VerifiedExecutable::open(&fifo).is_err());
        return Ok(());
    }
    let mut child = Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "workbench::tshark::secure_files::tests::executable_fifo_rejection",
        ])
        .env(PROBE, "1")
        .stdout(Stdio::null())
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break Some(status);
        }
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            break None;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    assert!(
        status.is_some_and(|status| status.success()),
        "FIFO was not rejected before a blocking read"
    );
    Ok(())
}

#[test]
fn executable_descriptor_swap() -> Result<(), Box<dyn Error>> {
    let parent = tempfile::tempdir()?;
    let selected = parent.path().join("tool");
    let original = parent.path().join("original");
    let replacement = parent.path().join("replacement");
    write_executable(&selected, b"original")?;
    write_executable(&replacement, b"replacement")?;
    let verified = VerifiedExecutable::open(&selected)?;
    assert_eq!(verified.path, selected.canonicalize()?);
    assert!(fcntl_getfd(&verified.file)?.contains(FdFlags::CLOEXEC));
    let descriptor = descriptor_source(&verified.file)?;
    fs::rename(&selected, &original)?;
    fs::rename(&replacement, &selected)?;
    assert_eq!(fs::read(&descriptor)?, b"original");
    fs::rename(&selected, &replacement)?;
    fs::rename(&original, &selected)?;
    assert_eq!(fs::read(&descriptor)?, b"original");
    let from_fd = File::open(&descriptor)?.metadata()?;
    let from_original = verified.file.metadata()?;
    assert_eq!(
        (from_fd.dev(), from_fd.ino()),
        (from_original.dev(), from_original.ino())
    );
    Ok(())
}

#[test]
fn unlinked_descriptor_identity() -> Result<(), Box<dyn Error>> {
    let parent = tempfile::tempdir()?;
    let path = parent.path().join("file");
    fs::write(&path, b"held inode")?;
    let file = File::open(&path)?;
    let source = descriptor_source(&file)?;
    fs::remove_file(path)?;
    let mut contents = String::new();
    File::open(&source)?.read_to_string(&mut contents)?;
    assert_eq!(contents, "held inode");
    let child = Command::new("cat").arg(&source).output()?;
    assert!(
        child.status.success(),
        "{}",
        String::from_utf8_lossy(&child.stderr)
    );
    assert_eq!(child.stdout, b"held inode");
    Ok(())
}
