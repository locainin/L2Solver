#![cfg(target_os = "linux")]

use std::{error::Error, path::Path, process::Command};

fn fixture() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/switching/fixtures/veth.py")
}

#[test]
#[ignore = "uses a proved private namespace and owned veth pair"]
fn owned_veth_delivers_switching_frames_without_a_client_send() -> Result<(), Box<dyn Error>> {
    let output = Command::new("python3").arg(fixture()).output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("switching_delivered=true no_client_send=true cleanup_confirmed=true")
    );
    Ok(())
}

#[test]
#[ignore = "uses a proved private namespace and owned veth pair"]
fn owned_veth_exercises_a_ready_receive_only_client() -> Result<(), Box<dyn Error>> {
    // The client is started only after the fixture proves its private namespace
    let client = r"
import os
import runpy
import socket
from pathlib import Path
fixtures = Path(os.environ['L2_TEST_SWITCHING_FIXTURES'])
expected = {bytes(frame) for frame in runpy.run_path(str(fixtures / 'veth.py'))['frames']()}
ready = Path(os.environ['L2_TEST_SWITCHING_READY'])
with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as link:
    link.bind((os.environ['L2_TEST_SWITCHING_INTERFACE'], 0))
    link.settimeout(2)
    ready.write_text('ready')
    while expected:
        expected.discard(link.recv(65535))
";
    let output = Command::new("python3")
        .arg(fixture())
        .args(["--", "python3", "-c", client])
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("switching_delivered=true no_client_send=true cleanup_confirmed=true")
    );
    Ok(())
}

#[test]
#[ignore = "uses a proved private namespace and owned veth pair"]
fn owned_veth_rejects_a_client_that_never_signals_readiness() -> Result<(), Box<dyn Error>> {
    let output = Command::new("python3")
        .arg(fixture())
        .args(["--", "python3", "-c", "pass"])
        .output()?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("ready"));
    Ok(())
}

#[test]
#[ignore = "uses a proved private namespace and owned veth pair"]
fn owned_veth_detects_transmission_by_the_observer() -> Result<(), Box<dyn Error>> {
    // The synthetic test transmission stays inside the proved private veth
    let client = r"
import os
import socket
import time
from pathlib import Path
ready = Path(os.environ['L2_TEST_SWITCHING_READY'])
wire = (Path(os.environ['L2_TEST_SWITCHING_FIXTURES']) / 'dtp.bin').read_bytes()
with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as link:
    link.bind((os.environ['L2_TEST_SWITCHING_INTERFACE'], 0))
    ready.write_text('ready')
    link.send(wire)
    time.sleep(0.5)
";
    let output = Command::new("python3")
        .arg(fixture())
        .args(["--", "python3", "-c", client])
        .output()?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unexpected client transmission"));
    Ok(())
}
