use super::{BRIDGE, Sandbox, check_status};
use crate::workbench::tshark::{
    ObjectExportBudget,
    process::{self, StreamingPolicy},
    resources::test_plan,
    secure_files::{VerifiedExecutable, Workspace},
};
use std::{
    error::Error,
    ffi::{OsStr, OsString},
    fs,
    io::{self, Write},
    net::TcpListener,
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::Path,
    process::Command,
    time::{Duration, Instant},
};

const CLEAN_STATUS: &str = "Uid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000000\n";
const PROBE_VARIABLE: &str = "L2_SANDBOX_TEST_PROBE";

#[test]
fn sandbox_descriptor_enumeration_failure() -> Result<(), Box<dyn Error>> {
    let (scrub, _) = BRIDGE
        .split_once("exec 3<\"$1\"")
        .ok_or("bridge setup missing")?;
    // Fill the descriptor table before Bash tries to enumerate /proc/self/fd
    let command = format!(
        "ulimit -n 10 || exit 125; exec 3</dev/null 4</dev/null 5</dev/null 6</dev/null 7</dev/null 8</dev/null 9</dev/null || exit 125; printf 'ready\\n'; {scrub} printf 'continued\\n'"
    );
    let result = Command::new("/usr/bin/bash")
        .args(["--noprofile", "--norc", "-c", &command])
        .output()?;
    assert!(
        !result.status.success(),
        "descriptor enumeration did not abort"
    );
    assert_eq!(
        result.stdout, b"ready\n",
        "bridge continued after enumeration failed"
    );
    Ok(())
}

#[test]
fn privilege_status_clean() -> Result<(), Box<dyn Error>> {
    check_status(CLEAN_STATUS)?;
    Ok(())
}

#[test]
fn privileged_caller() -> Result<(), Box<dyn Error>> {
    const PROBE: &str = "L2_PRIVILEGED_CALLER_PROBE";
    if std::env::var_os(PROBE).is_some() {
        assert_eq!(rustix::process::geteuid().as_raw(), 0);
        let error = super::check_privileges()
            .err()
            .ok_or("privileged caller was accepted")?;
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        return Ok(());
    }
    // Namespace root has no additional authority over the host
    let result = Command::new("unshare")
        .args(["--user", "--map-root-user", "--"])
        .arg(std::env::current_exe()?)
        .args([
            "--exact",
            "workbench::tshark::sandbox::tests::privileged_caller",
        ])
        .env(PROBE, "1")
        .output()?;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(())
}

#[test]
fn privilege_status_rejections() {
    for status in [
        CLEAN_STATUS.replace("Uid:\t1000\t1000\t1000\t1000", "Uid:\t0\t0\t0\t0"),
        CLEAN_STATUS.replace("Uid:\t1000\t1000\t1000\t1000", "Uid:\t1000\t1000\t0\t1000"),
        CLEAN_STATUS.replace("Uid:\t1000\t1000\t1000\t1000", "Uid:\t1000\t1000\t1000\t0"),
        CLEAN_STATUS.replace(
            "Gid:\t1000\t1000\t1000\t1000",
            "Gid:\t1000\t1001\t1000\t1000",
        ),
        CLEAN_STATUS.replace("CapInh:\t0000000000000000", "CapInh:\t0000000000000001"),
        CLEAN_STATUS.replace("CapPrm:\t0000000000000000", "CapPrm:\t0000000000000001"),
        CLEAN_STATUS.replace("CapEff:\t0000000000000000", "CapEff:\t0000000000000001"),
        CLEAN_STATUS.replace("CapAmb:\t0000000000000000", "CapAmb:\t0000000000000001"),
        CLEAN_STATUS.replace("CapAmb:\t0000000000000000\n", ""),
        CLEAN_STATUS.replace("CapAmb:\t0000000000000000", "CapAmb:\tbogus"),
        format!("{CLEAN_STATUS}Uid:\t0\t0\t0\t0\n"),
    ] {
        assert!(check_status(&status).is_err(), "accepted {status:?}");
    }
}

#[test]
fn sandbox_probe() -> Result<(), Box<dyn Error>> {
    if std::env::var_os(PROBE_VARIABLE).is_none() {
        return Ok(());
    }

    assert_eq!(fs::read_link("/proc/self/fd/1")?, Path::new("/dev/null"));
    assert_eq!(
        fs::symlink_metadata("/proc/self/fd/9")
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::NotFound)
    );
    let status = fs::read_to_string("/proc/self/status")?;
    for (field, expected) in [
        ("Uid", "65534\t65534\t65534\t65534"),
        ("Gid", "65534\t65534\t65534\t65534"),
        ("CapInh", "0000000000000000"),
        ("CapPrm", "0000000000000000"),
        ("CapEff", "0000000000000000"),
        ("CapBnd", "0000000000000000"),
        ("CapAmb", "0000000000000000"),
        ("NoNewPrivs", "1"),
    ] {
        let actual = status
            .lines()
            .find_map(|line| line.strip_prefix(field)?.strip_prefix(':').map(str::trim));
        assert_eq!(actual, Some(expected), "unexpected {field} in {status}");
    }
    assert_eq!(fs::read("/work/capture.bin")?, b"capture bytes");
    assert_eq!(fs::read("/work/tls-keylog.txt")?, b"keylog bytes");
    assert!(fs::write("/work/capture.bin", b"changed").is_err());
    assert!(fs::write("/work/tls-keylog.txt", b"changed").is_err());
    assert!(fs::write("/work/forbidden", b"changed").is_err());
    // The pre-sandbox workspace descriptor must not bypass the read-only mount
    assert!(fs::write("/proc/self/fd/4/capture.bin", b"changed").is_err());
    for path in ["/forbidden", "/tool/forbidden", "/dev/forbidden"] {
        assert!(fs::write(path, b"changed").is_err(), "writable: {path}");
    }
    fs::write("/tmp/writable", b"x")?;
    fs::write("/dev/shm/writable", b"x")?;
    fs::write("/output/writable", b"x")?;
    let host_file = std::env::var_os("L2_SANDBOX_TEST_HOST_FILE").ok_or("host file missing")?;
    assert!(fs::write(host_file, b"escape").is_err());
    let tcp_error = TcpListener::bind("127.0.0.1:0")
        .err()
        .ok_or("TCP socket was allowed")?;
    assert_eq!(tcp_error.raw_os_error(), Some(libc::EPERM));
    let pair_error = UnixStream::pair().err().ok_or("socket pair was allowed")?;
    assert_eq!(pair_error.raw_os_error(), Some(libc::EPERM));
    Ok(())
}

#[test]
fn sandbox_filesystem_network_credentials() -> Result<(), Box<dyn Error>> {
    let parent = tempfile::tempdir()?;
    let workspace = Workspace::new(Some(parent.path()))?;
    let mut capture = workspace.create_file(OsStr::new("capture.bin"))?;
    capture.write_all(b"capture bytes")?;
    let mut keylog = workspace.create_file(OsStr::new("tls-keylog.txt"))?;
    keylog.write_all(b"keylog bytes")?;
    let executable = VerifiedExecutable::open(&std::env::current_exe()?)?;
    let sandbox = Sandbox::new(
        &workspace,
        &executable,
        Some(&capture),
        Some(&keylog),
        &test_plan()?,
        Instant::now() + Duration::from_secs(10),
    )?;
    let name = format!(
        "{}::sandbox_probe",
        module_path!()
            .split_once("::")
            .ok_or("test module path missing")?
            .1
    );
    let arguments = [
        OsString::from("--exact"),
        OsString::from(name),
        OsString::from("--nocapture"),
    ];
    let host_file = parent.path().join("outside");
    let environment = [
        (OsString::from(PROBE_VARIABLE), OsString::from("1")),
        (
            OsString::from("L2_SANDBOX_TEST_HOST_FILE"),
            host_file.as_os_str().to_owned(),
        ),
    ];
    let mut launch = sandbox.command(&arguments, &environment, Some(&[]))?;
    let result = process::run_streaming_launch(&mut launch, streaming_policy(workspace.path()))?;
    assert!(
        result.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let output = launch
        .output_storage
        .as_ref()
        .ok_or("output mount missing")?
        .path()?;
    assert_eq!(fs::read(output.join("writable"))?, b"x");
    assert!(!workspace.path().join("results").exists());
    assert!(!host_file.exists());
    assert_eq!(
        fs::read(workspace.path().join("capture.bin"))?,
        b"capture bytes"
    );
    assert_eq!(
        fs::read(workspace.path().join("tls-keylog.txt"))?,
        b"keylog bytes"
    );
    Ok(())
}

#[test]
fn sandbox_argument_integrity() -> Result<(), Box<dyn Error>> {
    let parent = tempfile::tempdir()?;
    let workspace = Workspace::new(Some(parent.path()))?;
    let script = parent.path().join("fixture");
    fs::write(&script, "#!/bin/sh\nprintf '<%s>\\n' \"$@\"\n")?;
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700))?;
    let executable = VerifiedExecutable::open(&script)?;
    let sandbox = Sandbox::new(
        &workspace,
        &executable,
        None,
        None,
        &test_plan()?,
        Instant::now() + Duration::from_secs(10),
    )?;
    let arguments = [
        OsString::from("with spaces"),
        OsString::from("$(touch /tmp/never)"),
        OsString::from("; literal"),
    ];
    let mut launch = sandbox.command(&arguments, &[], None)?;
    let result = process::run_launch(&mut launch, Duration::from_secs(10), 4096, 4096, None)?;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        result.stdout,
        b"<with spaces>\n<$(touch /tmp/never)>\n<; literal>\n"
    );
    Ok(())
}

#[test]
fn sandbox_workspace_path_translation() -> Result<(), Box<dyn Error>> {
    let parent = tempfile::tempdir()?;
    let workspace = Workspace::new(Some(parent.path()))?;
    let script = parent.path().join("fixture");
    fs::write(
        &script,
        "#!/bin/sh\nprintf '<%s>\\n' \"$HOME\" \"$TMPDIR\" \"$@\"\n",
    )?;
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700))?;
    let executable = VerifiedExecutable::open(&script)?;
    let sandbox = Sandbox::new(
        &workspace,
        &executable,
        None,
        None,
        &test_plan()?,
        Instant::now() + Duration::from_secs(10),
    )?;
    let output_path = workspace.path().join("export-objects");
    let mut keylog = OsString::from("tls.keylog_file:");
    keylog.push(workspace.path().join("tls-keylog.txt"));
    let mut object = OsString::from("http,");
    object.push(output_path.join("http"));
    let mut similar_prefix = workspace.path().as_os_str().to_owned();
    similar_prefix.push("-other");
    let arguments = [
        workspace.path().join("capture.bin").into_os_string(),
        keylog,
        object,
        similar_prefix.clone(),
    ];
    let environment = [
        (
            OsString::from("HOME"),
            workspace.path().join("home").into_os_string(),
        ),
        (
            OsString::from("TMPDIR"),
            workspace.path().as_os_str().to_owned(),
        ),
    ];
    let output_launch = sandbox.command(&arguments, &environment, Some(&["http".to_owned()]))?;
    assert!(
        output_launch
            .arguments
            .iter()
            .any(|argument| argument == "http,/output/http")
    );
    let mut launch = sandbox.command(&arguments, &environment, None)?;
    let result = process::run_launch(&mut launch, Duration::from_secs(10), 4096, 4096, None)?;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let expected = format!(
        "</work/home>\n</tmp>\n</work/capture.bin>\n<tls.keylog_file:/work/tls-keylog.txt>\n<http,/work/export-objects/http>\n<{}>\n",
        similar_prefix.to_string_lossy()
    );
    assert_eq!(result.stdout, expected.as_bytes());
    Ok(())
}

#[test]
fn sandbox_snapshot_inode_identity() -> Result<(), Box<dyn Error>> {
    let parent = tempfile::tempdir()?;
    let workspace = Workspace::new(Some(parent.path()))?;
    let mut capture = workspace.create_file(OsStr::new("capture.bin"))?;
    capture.write_all(b"original capture")?;
    let script = parent.path().join("fixture");
    fs::write(&script, "#!/bin/sh\ncat /work/capture.bin\n")?;
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700))?;
    let executable = VerifiedExecutable::open(&script)?;
    let sandbox = Sandbox::new(
        &workspace,
        &executable,
        Some(&capture),
        None,
        &test_plan()?,
        Instant::now() + Duration::from_secs(10),
    )?;
    drop(capture);
    drop(executable);
    fs::rename(
        workspace.path().join("capture.bin"),
        workspace.path().join("original"),
    )?;
    fs::write(workspace.path().join("capture.bin"), b"replacement capture")?;
    fs::rename(&script, parent.path().join("original-fixture"))?;
    fs::write(&script, "#!/bin/sh\nprintf replacement\n")?;
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700))?;
    let mut launch = sandbox.command(&[], &[], None)?;
    let result = process::run_launch(&mut launch, Duration::from_secs(10), 4096, 4096, None)?;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(result.stdout, b"original capture");
    Ok(())
}

#[test]
fn sandbox_inherited_descriptor() -> Result<(), Box<dyn Error>> {
    const PROBE: &str = "L2_SANDBOX_INHERITED_FD_PROBE";
    if std::env::var_os(PROBE).is_some() {
        let parent = tempfile::tempdir()?;
        let workspace = Workspace::new(Some(parent.path()))?;
        let script = parent.path().join("fixture");
        fs::write(
            &script,
            "#!/bin/sh\nif [ -e /proc/self/fd/9 ]; then : > /proc/self/fd/9/escaped; fi\n",
        )?;
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700))?;
        let executable = VerifiedExecutable::open(&script)?;
        let sandbox = Sandbox::new(
            &workspace,
            &executable,
            None,
            None,
            &test_plan()?,
            Instant::now() + Duration::from_secs(10),
        )?;
        let mut launch = sandbox.command(&[], &[], None)?;
        let result = process::run_launch(&mut launch, Duration::from_secs(10), 4096, 4096, None)?;
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        return Ok(());
    }
    let host_directory = tempfile::tempdir()?;
    let test_name = format!(
        "{}::sandbox_inherited_descriptor",
        module_path!()
            .split_once("::")
            .ok_or("test module path missing")?
            .1
    );
    let result = Command::new("/bin/sh")
        .args(["-c", "exec 9<\"$1\"; shift; exec \"$@\"", "fd-test"])
        .arg(host_directory.path())
        .arg(std::env::current_exe()?)
        .args(["--exact", &test_name, "--nocapture"])
        .env(PROBE, "1")
        .output()?;
    assert!(
        result.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        !host_directory.path().join("escaped").exists(),
        "sandbox retained a host directory descriptor"
    );
    Ok(())
}

#[test]
fn sandbox_unused_descriptors() -> Result<(), Box<dyn Error>> {
    let parent = tempfile::tempdir()?;
    let workspace = Workspace::new(Some(parent.path()))?;
    let script = parent.path().join("fixture");
    fs::write(
        &script,
        "#!/bin/sh\nfor fd in 6 7 8; do if [ -d /proc/self/fd/$fd ]; then : > /proc/self/fd/$fd/escaped; fi; done\n",
    )?;
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700))?;
    let executable = VerifiedExecutable::open(&script)?;
    let sandbox = Sandbox::new(
        &workspace,
        &executable,
        None,
        None,
        &test_plan()?,
        Instant::now() + Duration::from_secs(10),
    )?;
    let mut launch = sandbox.command(&[], &[], None)?;
    let result = process::run_launch(&mut launch, Duration::from_secs(10), 4096, 4096, None)?;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        !workspace.path().join("escaped").exists(),
        "unused mount slot exposed the writable workspace"
    );
    Ok(())
}

#[test]
fn sandbox_detached_descendants() -> Result<(), Box<dyn Error>> {
    let parent = tempfile::tempdir()?;
    let workspace = Workspace::new(Some(parent.path()))?;
    let script = parent.path().join("fixture");
    fs::write(
        &script,
        "#!/bin/sh\nsetsid /bin/sh -c 'touch /output/ready; sleep 1; touch /output/escaped' </dev/null >/dev/null 2>&1 &\nwhile [ ! -e /output/ready ]; do sleep 0.01; done\n",
    )?;
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700))?;
    let executable = VerifiedExecutable::open(&script)?;
    let sandbox = Sandbox::new(
        &workspace,
        &executable,
        None,
        None,
        &test_plan()?,
        Instant::now() + Duration::from_secs(10),
    )?;
    let mut launch = sandbox.command(&[], &[], Some(&[]))?;
    let result = process::run_streaming_launch(&mut launch, streaming_policy(workspace.path()))?;
    let output_path = launch
        .output_storage
        .as_ref()
        .ok_or("output mount missing")?
        .path()?;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        output_path.join("ready").exists(),
        "detached child never started"
    );
    let deadline = Instant::now() + Duration::from_millis(1400);
    while Instant::now() < deadline {
        assert!(
            !output_path.join("escaped").exists(),
            "detached child survived namespace shutdown"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(())
}

fn streaming_policy(object_root: &std::path::Path) -> StreamingPolicy<'_> {
    StreamingPolicy {
        stderr_maximum: 64 * 1024,
        deadline: Instant::now() + Duration::from_secs(10),
        object_root,
        protocol_directory_count: 0,
        object_budget: ObjectExportBudget {
            temporary_bytes: 1,
            temporary_files: 1,
        },
        job: None,
    }
}

#[cfg(all(
    target_endian = "little",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn filter_action(program: &[u8], syscall: u32, flags: u32) -> Result<u32, Box<dyn Error>> {
    if !program.len().is_multiple_of(8) {
        return Err("incomplete BPF instruction".into());
    }
    #[cfg(target_arch = "x86_64")]
    let architecture = 0xc000_0000 | u32::from(libc::EM_X86_64);
    #[cfg(target_arch = "aarch64")]
    let architecture = 0xc000_0000 | u32::from(libc::EM_AARCH64);

    let mut accumulator = 0;
    let mut position = 0;
    loop {
        let instruction: [u8; 8] = program
            .as_chunks::<8>()
            .0
            .get(position)
            .copied()
            .ok_or("BPF program did not return")?;
        let [
            code_lo,
            code_hi,
            yes,
            no,
            value_0,
            value_1,
            value_2,
            value_3,
        ] = instruction;
        let code = u32::from(u16::from_ne_bytes([code_lo, code_hi]));
        let value = u32::from_ne_bytes([value_0, value_1, value_2, value_3]);
        position += 1;
        match code {
            code if code == libc::BPF_LD | libc::BPF_W | libc::BPF_ABS => {
                // Load the fields defined by Linux's seccomp_data layout
                accumulator = match usize::try_from(value)? {
                    offset if offset == std::mem::offset_of!(libc::seccomp_data, nr) => syscall,
                    offset if offset == std::mem::offset_of!(libc::seccomp_data, arch) => {
                        architecture
                    }
                    offset if offset == std::mem::offset_of!(libc::seccomp_data, args) => flags,
                    _ => return Err("unexpected seccomp data offset".into()),
                };
            }
            code if code == libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K => {
                position += usize::from(if accumulator == value { yes } else { no });
            }
            code if code == libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K => {
                position += usize::from(if accumulator >= value { yes } else { no });
            }
            code if code == libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K => {
                position += usize::from(if accumulator & value != 0 { yes } else { no });
            }
            code if code == libc::BPF_RET | libc::BPF_K => return Ok(value),
            _ => return Err("unexpected BPF instruction".into()),
        }
    }
}

#[cfg(all(
    target_endian = "little",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[test]
fn seccomp_clone_namespace_flags() -> Result<(), Box<dyn Error>> {
    let program = super::seccomp_filter()?;
    let clone = u32::try_from(libc::SYS_clone)?;
    let normal = u32::try_from(
        libc::CLONE_VM
            | libc::CLONE_FS
            | libc::CLONE_FILES
            | libc::CLONE_SIGHAND
            | libc::CLONE_THREAD,
    )?;
    let denied = libc::SECCOMP_RET_ERRNO | u32::try_from(libc::EPERM)?;

    assert_eq!(filter_action(&program, clone, 0)?, libc::SECCOMP_RET_ALLOW);
    assert_eq!(
        filter_action(&program, clone, normal)?,
        libc::SECCOMP_RET_ALLOW
    );
    for (name, flag) in [
        ("CLONE_NEWNS", libc::CLONE_NEWNS),
        ("CLONE_NEWCGROUP", libc::CLONE_NEWCGROUP),
        ("CLONE_NEWUTS", libc::CLONE_NEWUTS),
        ("CLONE_NEWIPC", libc::CLONE_NEWIPC),
        ("CLONE_NEWUSER", libc::CLONE_NEWUSER),
        ("CLONE_NEWPID", libc::CLONE_NEWPID),
        ("CLONE_NEWNET", libc::CLONE_NEWNET),
    ] {
        let flag = u32::try_from(flag)?;
        assert_eq!(filter_action(&program, clone, flag)?, denied, "{name}");
        assert_eq!(
            filter_action(&program, clone, normal | flag)?,
            denied,
            "{name}"
        );
    }
    // clone3 falls back to clone, and network syscalls stay blocked
    assert_eq!(
        filter_action(&program, u32::try_from(libc::SYS_clone3)?, 0)?,
        libc::SECCOMP_RET_ERRNO | u32::try_from(libc::ENOSYS)?
    );
    assert_eq!(
        filter_action(&program, u32::try_from(libc::SYS_socket)?, 0)?,
        denied
    );
    Ok(())
}
