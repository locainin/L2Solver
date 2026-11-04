//! Check that the live correlation fixture cannot capture without a private scope

use std::{
    error::Error,
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Output},
};

const CHILD_MODE: &str = "L2_TEST_ENDPOINT_NAMESPACE_CHILD";
const PARENT_FDS: &str = "L2_TEST_ENDPOINT_PARENT_FDS";
const PARENT_UID: &str = "L2_TEST_ENDPOINT_PARENT_UID";

pub fn run_in_private_namespace() -> Result<bool, Box<dyn Error>> {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/endpoint/namespace.py");
    if let Some(child) = std::env::var_os(CHILD_MODE) {
        // Inherited descriptors must prove the caller's actual namespace identities
        if child != "1"
            || std::env::var_os(PARENT_FDS).is_none()
            || std::env::var_os(PARENT_UID).is_none()
        {
            return Err("unproved private namespace: missing parent descriptors".into());
        }
        let output = Command::new("python3")
            .arg(&fixture)
            .arg("--verify")
            .output()
            .map_err(|error| format!("unproved private namespace: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "unproved private namespace: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        return Ok(true);
    }

    // The fixture owns and bounds the child before the parent reports success
    let output = Command::new("python3")
        .arg(fixture)
        .arg("--run")
        .arg(std::env::current_exe()?)
        .output()?;
    if !output.status.success()
        || !output
            .stdout
            .windows(b"capture_test_passed=true".len())
            .any(|window| window == b"capture_test_passed=true")
    {
        return Err(format!(
            "isolated capture fixture failed: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(false)
}

fn install_fake_capture(directory: &Path) -> Result<(), Box<dyn Error>> {
    let dumpcap = directory.join("dumpcap");
    // Record any attempt to start capture without touching a network interface
    fs::write(
        &dumpcap,
        "#!/bin/sh\n: > \"$L2_TEST_CAPTURE_MARKER\"\nexit 99\n",
    )?;
    fs::set_permissions(&dumpcap, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn assert_unproved_child_was_rejected(output: &Output, marker: &Path) {
    assert!(!output.status.success(), "an unproved child was accepted");
    assert!(
        !marker.exists(),
        "capture started before scope verification"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("unproved private namespace"),
        "unexpected child error: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn child_mode_rejects_an_unproved_namespace_before_starting_capture() -> Result<(), Box<dyn Error>>
{
    let directory = tempfile::tempdir()?;
    let marker = directory.path().join("capture-started");
    install_fake_capture(directory.path())?;
    let output = Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "strace_correlate_io_captured_packets",
            "--nocapture",
        ])
        .env(CHILD_MODE, "1")
        .env_remove(PARENT_FDS)
        .env_remove(PARENT_UID)
        .env("L2_TEST_CAPTURE_MARKER", &marker)
        .env("PATH", directory.path())
        .output()?;
    assert_unproved_child_was_rejected(&output, &marker);
    Ok(())
}

#[test]
fn child_mode_rejects_the_callers_namespace_before_starting_capture() -> Result<(), Box<dyn Error>>
{
    let directory = tempfile::tempdir()?;
    let marker = directory.path().join("capture-started");
    install_fake_capture(directory.path())?;
    let path = std::env::var_os("PATH").unwrap_or_default();
    let path = std::env::join_paths(
        std::iter::once(directory.path().to_path_buf()).chain(std::env::split_paths(&path)),
    )?;
    // Pass real descriptors for the current namespaces to test identity rejection
    let launcher = r"
import os, sys
fds = [os.open('/proc/self/ns/' + name, os.O_RDONLY) for name in ('user', 'mnt', 'net', 'pid')]
for fd in fds:
    os.set_inheritable(fd, True)
os.environ['L2_TEST_ENDPOINT_PARENT_FDS'] = ','.join(str(fd) for fd in fds)
os.environ['L2_TEST_ENDPOINT_PARENT_UID'] = str(os.getuid())
os.execv(sys.argv[1], [sys.argv[1], '--exact', 'strace_correlate_io_captured_packets', '--nocapture'])
";
    let output = Command::new("python3")
        .args(["-c", launcher])
        .arg(std::env::current_exe()?)
        .env(CHILD_MODE, "1")
        .env("L2_TEST_CAPTURE_MARKER", &marker)
        .env("PATH", path)
        .output()?;
    assert_unproved_child_was_rejected(&output, &marker);
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("user namespace did not change"),
        "current namespace was rejected for the wrong reason: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[test]
fn timeout_kills_the_owned_process_group() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/endpoint/namespace.py");
    let check = r"
import importlib.util, os, signal, subprocess, sys, time
from pathlib import Path
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('endpoint_namespace', sys.argv[1])
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
marker = Path(sys.argv[2])
launcher = '''import os, subprocess, sys, time
child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
temporary = sys.argv[1] + '.tmp'
with open(temporary, 'w') as marker:
    marker.write(str(child.pid))
os.replace(temporary, sys.argv[1])
time.sleep(60)
'''
process = subprocess.Popen([sys.executable, '-c', launcher, str(marker)],
                           start_new_session=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
def watchdog(_signal, _frame):
    raise RuntimeError('cleanup test timed out')
signal.signal(signal.SIGALRM, watchdog)
signal.alarm(8)
try:
    deadline = time.monotonic() + 4
    while not marker.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    if not marker.exists():
        raise RuntimeError('child process did not start')
    child = int(marker.read_text())
    try:
        fixture.ns.wait_for_owned_process(process, 0.1)
    except subprocess.TimeoutExpired:
        pass
    else:
        raise RuntimeError('hung fixture did not time out')
    if process.poll() is None:
        raise RuntimeError('fixture leader survived timeout')
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            state = Path(f'/proc/{child}/stat').read_text().split()[2]
        except (FileNotFoundError, ProcessLookupError):
            break
        if state == 'Z':
            break
        time.sleep(0.01)
    else:
        raise RuntimeError('fixture descendant survived timeout')
finally:
    signal.alarm(0)
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.communicate(timeout=2)
";
    let output = Command::new("python3")
        .args(["-c", check])
        .arg(fixture)
        .arg(directory.path().join("child-pid"))
        .output()?;
    assert!(
        output.status.success(),
        "timeout cleanup failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}
