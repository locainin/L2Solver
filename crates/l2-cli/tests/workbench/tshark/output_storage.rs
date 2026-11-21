use super::{OutputStorage, SandboxProcess};
use std::{
    error::Error,
    fs,
    io::{BufRead, BufReader, Write},
    process::{Child, ChildStdout, Command, Stdio},
    thread,
    time::Duration,
};

#[test]
fn missing_process() {
    assert!(SandboxProcess::pin(u32::MAX, 1).is_err());
}

#[test]
fn inode_exhaustion() -> Result<(), Box<dyn Error>> {
    let (_child, directory) = private_mount("size=1m,nr_inodes=2")?;
    let filesystem = rustix::fs::fstatfs(&directory)?;
    assert!(filesystem.f_bfree > 0);
    assert_eq!(filesystem.f_ffree, 0);
    assert!(OutputStorage { directory }.is_full()?);
    Ok(())
}

#[test]
fn unlimited_inodes() -> Result<(), Box<dyn Error>> {
    let (_child, directory) = private_mount("size=1m,nr_inodes=0")?;
    let filesystem = rustix::fs::fstatfs(&directory)?;
    assert_eq!(filesystem.f_files, 0);
    assert_eq!(filesystem.f_ffree, 0);
    assert!(!OutputStorage { directory }.is_full()?);
    Ok(())
}

fn private_mount(options: &str) -> Result<(MountProcess, fs::File), Box<dyn Error>> {
    // This mount exists only in the child namespace and cannot change the host mount
    let script = "mount --make-rprivate / && mount -t tmpfs -o \"$1\" tmpfs /dev/shm && mkdir /dev/shm/http && printf 'ready\\n' && IFS= read -r";
    let child = Command::new("/usr/bin/unshare")
        .args([
            "--user",
            "--map-root-user",
            "--mount",
            "/usr/bin/bash",
            "-c",
            script,
            "mount-test",
            options,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let mut child = MountProcess(child);
    let mut stdout = BufReader::new(child.0.stdout.take().ok_or("stdout missing")?);
    let mut ready = String::new();
    stdout.read_line(&mut ready)?;
    assert_eq!(ready, "ready\n");
    let directory = fs::File::open(format!("/proc/{}/root/dev/shm", child.0.id()))?;
    Ok((child, directory))
}

struct MountProcess(Child);

impl Drop for MountProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn rejects_non_tmpfs() -> Result<(), Box<dyn Error>> {
    let script =
        "printf 'L2_EXPORT_READY\\n'; IFS= read -r release; [[ $release == L2_EXPORT_GO ]]";
    let (mut child, _stdout, process) = start_sandbox(&["--proc", "/output"], script)?;
    assert!(process.output().is_err());
    writeln!(child.stdin.take().ok_or("stdin missing")?, "L2_EXPORT_GO")?;
    assert!(child.wait()?.success());
    Ok(())
}

#[test]
fn tmpfs_survives_namespace_exit() -> Result<(), Box<dyn Error>> {
    let script = r"
        printf 'L2_EXPORT_READY\n'
        IFS= read -r release || exit 125
        [[ $release == L2_EXPORT_GO ]] || exit 125
        exec </dev/null >/dev/null
        printf 'stable object' > /output/object
        /usr/bin/setsid /usr/bin/bash -c '
            printf ready > /output/child-ready
            sleep 1
            printf changed > /output/object
        ' </dev/null >/dev/null 2>&1 &
        while [[ ! -e /output/child-ready ]]; do sleep 0.01; done
        exit 0
    ";
    let (mut child, _stdout, process) =
        start_sandbox(&["--size", "1048576", "--tmpfs", "/output"], script)?;
    let storage = process.output()?;
    let root = storage.path()?;
    assert!(!storage.is_full()?);
    assert_eq!(fs::read_dir(&root)?.count(), 0);
    writeln!(child.stdin.take().ok_or("stdin missing")?, "L2_EXPORT_GO")?;
    let status = child.wait()?;
    assert!(status.success(), "sandbox failed: {status}");
    assert!(process.output().is_err());

    // The detached writer must die with namespace PID 1 before the snapshot is read
    thread::sleep(Duration::from_millis(1200));
    assert_eq!(fs::read(root.join("object"))?, b"stable object");
    let overflow = fs::write(root.join("full"), vec![1_u8; 1024 * 1024]);
    assert_eq!(
        overflow.err().and_then(|error| error.raw_os_error()),
        Some(libc::ENOSPC)
    );
    assert!(storage.is_full()?);
    Ok(())
}

fn start_sandbox(
    mount: &[&str],
    script: &str,
) -> Result<(Child, BufReader<ChildStdout>, SandboxProcess), Box<dyn Error>> {
    let mut command = Command::new("/usr/bin/bash");
    command
        .args([
            "--noprofile",
            "--norc",
            "-c",
            "exec 9>&1; exec \"$@\"",
            "output-storage-test",
            "/usr/bin/bwrap",
            "--unshare-user",
            "--unshare-pid",
            "--disable-userns",
            "--uid",
            "65534",
            "--gid",
            "65534",
            "--cap-drop",
            "ALL",
            "--die-with-parent",
            "--as-pid-1",
            "--ro-bind",
            "/usr",
            "/usr",
            "--ro-bind",
            "/bin",
            "/bin",
            "--ro-bind-try",
            "/lib",
            "/lib",
            "--ro-bind-try",
            "/lib64",
            "/lib64",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
        ])
        .args(mount)
        .args([
            "--json-status-fd",
            "9",
            "--",
            "/usr/bin/bash",
            "--noprofile",
            "--norc",
            "-c",
            script,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn()?;

    let mut stdout = BufReader::new(child.stdout.take().ok_or("stdout missing")?);
    let mut line = String::new();
    stdout.read_line(&mut line)?;
    let information: serde_json::Value = serde_json::from_str(&line)?;
    let pid = u32::try_from(
        information
            .get("child-pid")
            .ok_or("child PID missing")?
            .as_u64()
            .ok_or("child PID missing")?,
    )?;
    let namespace = information
        .get("mnt-namespace")
        .ok_or("mount namespace missing")?
        .as_u64()
        .ok_or("mount namespace missing")?;
    assert!(SandboxProcess::pin(pid, namespace + 1).is_err());
    let process = SandboxProcess::pin(pid, namespace)?;
    line.clear();
    stdout.read_line(&mut line)?;
    assert_eq!(line, "L2_EXPORT_READY\n");
    Ok((child, stdout, process))
}
