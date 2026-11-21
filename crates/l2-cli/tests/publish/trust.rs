//! Check the filesystem trust boundary before the publisher stages any output

use super::publish::{self, DirectoryPublishError};
use std::{
    error::Error,
    fs, io,
    io::Write,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    process::Command,
};

type TestResult = Result<(), Box<dyn Error>>;

fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

fn assert_permission_denied<T>(result: Result<T, DirectoryPublishError>) -> TestResult {
    let Err(DirectoryPublishError::BeforePublication(error)) = result else {
        return Err("untrusted path did not fail before publication".into());
    };
    assert_eq!(
        error.downcast_ref::<io::Error>().map(io::Error::kind),
        Some(io::ErrorKind::PermissionDenied),
        "{error}"
    );
    Ok(())
}

fn check_denied_parent(parent: &Path) -> TestResult {
    let destination = parent.join("output");
    let denied = io::ErrorKind::PermissionDenied;
    let file = publish::create::<()>(&destination, |_| {
        Err(io::Error::other("file writer should not run"))
    });
    let directory = publish::create_directory_with_precommit::<()>(
        &destination,
        |_| Err(io::Error::other("directory writer should not run").into()),
        || Err(io::Error::other("precommit should not run").into()),
    );
    assert_eq!(file.err().map(|error| error.kind()), Some(denied));
    assert_permission_denied(directory)?;
    assert_eq!(
        fs::read_dir(parent)?.count(),
        0,
        "publication left an entry"
    );
    assert_eq!(
        publish::check_new_directory_destination(&destination)
            .err()
            .map(|error| error.kind()),
        Some(denied)
    );
    Ok(())
}

#[test]
fn shared_ancestors_are_rejected() -> TestResult {
    let root = tempfile::tempdir()?;
    let shared = root.path().join("shared");
    let private = shared.join("private");
    fs::create_dir_all(&private)?;
    set_mode(&private, 0o700)?;

    for mode in [0o777, 0o775] {
        set_mode(&shared, mode)?;
        check_denied_parent(&private)?;
        let existing = tempfile::tempdir_in(&private)?;
        assert_permission_denied(publish::prepare_directory_replacement(existing.path()))?;
    }
    Ok(())
}

#[test]
fn relative_path_checks_cwd_ancestry() -> TestResult {
    const CHILD: &str = "L2_TEST_RELATIVE_TRUST_CHILD";
    if std::env::var_os(CHILD).is_some() {
        return check_denied_parent(Path::new("."));
    }

    let shared = tempfile::tempdir()?;
    let private = shared.path().join("private");
    fs::create_dir(&private)?;
    set_mode(shared.path(), 0o775)?;
    // The child can choose a working directory without changing it for other tests
    let output = Command::new(std::env::current_exe()?)
        .args(["--exact", "trust::relative_path_checks_cwd_ancestry"])
        .env(CHILD, "1")
        .current_dir(private)
        .output()?;
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[test]
fn shared_targets_are_rejected() -> TestResult {
    let root = tempfile::tempdir()?;
    let destination = root.path().join("output");
    fs::create_dir(&destination)?;
    let payload = destination.join("payload");
    fs::write(&payload, b"previous")?;

    // Sticky ancestors protect their child names, while replacement targets need private writes
    for mode in [0o777, 0o775, 0o1777] {
        set_mode(&destination, mode)?;
        assert_permission_denied(publish::prepare_directory_replacement(&destination))?;
        assert_eq!(fs::read(&payload)?, b"previous");
        assert_eq!(fs::read_dir(root.path())?.count(), 1);
    }
    Ok(())
}

#[test]
fn relative_output_through_search_only_ancestor() -> TestResult {
    const CHILD: &str = "L2_TEST_SEARCH_ONLY_ANCESTOR";
    if std::env::var_os(CHILD).is_some() {
        return Ok(publish::create(Path::new("report"), |file| {
            file.write_all(b"complete")
        })?);
    }
    let root = tempfile::tempdir()?;
    let ancestor = root.path().join("search-only");
    let parent = ancestor.join("private");
    fs::create_dir_all(&parent)?;
    set_mode(&ancestor, 0o100)?;
    let result = Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "trust::relative_output_through_search_only_ancestor",
        ])
        .env(CHILD, "1")
        .current_dir(&parent)
        .output();
    set_mode(&ancestor, 0o700)?;
    let result = result?;
    assert!(
        result.status.success(),
        "{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(fs::read(parent.join("report"))?, b"complete");
    Ok(())
}

#[test]
fn prepared_target_rechecks_write_permissions() -> TestResult {
    let root = tempfile::tempdir()?;
    let target = root.path().join("output");
    fs::create_dir(&target)?;
    let prepared = publish::prepare_directory_replacement(&target)?;
    set_mode(&target, 0o775)?;
    let refresh = publish::replace_directory_with_precommit::<()>(
        &prepared,
        |_| Err(io::Error::other("writer must not run").into()),
        || Err(io::Error::other("commit must not run").into()),
    );
    assert_eq!(
        prepared.check_location().err().map(|error| error.kind()),
        Some(io::ErrorKind::PermissionDenied)
    );
    assert_permission_denied(refresh)?;
    assert_eq!(fs::read_dir(root.path())?.count(), 1);
    Ok(())
}

#[test]
fn unsafe_parent_preserves_staging_on_failure() -> TestResult {
    let root = tempfile::tempdir()?;
    let parent = root.path().join("parent");
    fs::create_dir(&parent)?;
    let output = parent.join("output");
    let error = publish::create_directory::<()>(&output, |staging| {
        fs::write(staging.join("payload"), b"unfinished")?;
        set_mode(&parent, 0o775)?;
        Err(io::Error::other("writer stopped").into())
    });
    assert!(matches!(
        error,
        Err(DirectoryPublishError::BeforePublication(_))
    ));
    assert!(!output.exists());
    assert_eq!(fs::read_dir(&parent)?.count(), 1);
    Ok(())
}

#[test]
fn foreign_directories_are_rejected() -> TestResult {
    const CHILD_ROOT: &str = "L2_TEST_FOREIGN_TRUST_ROOT";
    if let Some(root) = std::env::var_os(CHILD_ROOT) {
        // The new root belongs to the mapped UID 0, independent of the host root
        rustix::process::chroot(Path::new(&root))?;
        std::env::set_current_dir("/")?;
        let sticky = Path::new("/tmp");
        let intermediate = sticky.join("foreign");
        fs::create_dir(sticky)?;
        fs::create_dir(&intermediate)?;
        set_mode(sticky, 0o1777)?;
        set_mode(&intermediate, 0o755)?;
        rustix::fs::chown(&intermediate, Some(rustix::process::Uid::from_raw(1)), None)?;
        assert_eq!(intermediate.metadata()?.uid(), 1);

        let initial = publish::check_new_directory_destination(&intermediate.join("output"));
        let replacement = publish::prepare_directory_replacement(&intermediate);
        assert_eq!(
            initial.err().map(|error| error.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );
        assert_permission_denied(replacement)?;
        assert_eq!(fs::read_dir(&intermediate)?.count(), 0);
        return Ok(());
    }

    let namespace = ["--user", "--map-root-user", "--map-auto", "--"];
    let probe = Command::new("unshare")
        .args(namespace)
        .arg("true")
        .output()?;
    if !probe.status.success() {
        eprintln!(
            "mapped UIDs unavailable: {}",
            String::from_utf8_lossy(&probe.stderr)
        );
        return Ok(());
    }
    let root = tempfile::tempdir()?;
    let proc = root.path().join("proc");
    fs::create_dir(&proc)?;
    let output = Command::new("unshare")
        .args([
            "--user",
            "--map-root-user",
            "--map-auto",
            "--mount",
            "--pid",
            "--mount-proc",
            "--fork",
            "--",
        ])
        // Give the chroot a visible mountinfo entry for its root
        .args([
            "sh",
            "-ec",
            "mount --bind \"$1\" \"$1\"; mount --bind /proc \"$1/proc\"; shift; exec \"$@\"",
            "foreign-fixture",
        ])
        .arg(root.path())
        .arg(std::env::current_exe()?)
        .args(["--exact", "trust::foreign_directories_are_rejected"])
        .env(CHILD_ROOT, root.path())
        .output()?;
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[test]
fn sticky_and_private_ancestors_allow_publication() -> TestResult {
    let tmp = Path::new("/tmp");
    let root = tempfile::tempdir_in(tmp)?;
    let public = root.path().join("public");
    let shared = public.join("sticky");
    fs::create_dir_all(&shared)?;
    set_mode(root.path(), 0o700)?;
    set_mode(&public, 0o755)?;
    set_mode(&shared, 0o1777)?;
    let destination = shared.join("output");

    publish::check_new_directory_destination(&destination)?;
    publish::create_directory(&destination, |staging| {
        assert_eq!(staging.metadata()?.mode() & 0o777, 0o700);
        fs::write(staging.join("payload"), b"previous")?;
        Ok(())
    })?;
    let prepared = publish::prepare_directory_replacement(&destination)?;
    let ((), backup) = publish::replace_directory_with_precommit(
        &prepared,
        |staging| {
            assert_eq!(staging.metadata()?.mode() & 0o777, 0o700);
            fs::write(staging.join("payload"), b"refreshed")?;
            Ok(())
        },
        || Ok(()),
    )?;
    assert_eq!(fs::read(destination.join("payload"))?, b"refreshed");
    assert_eq!(fs::read(backup.join("payload"))?, b"previous");
    Ok(())
}
