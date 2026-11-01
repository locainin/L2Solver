#![cfg(target_os = "linux")]

use std::{error::Error, path::Path, process::Command};

fn fixture() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/isl/fixtures/veth.py")
}

#[test]
#[ignore = "uses a proved private namespace and owned veth pair"]
fn owned_veth_delivers_isl_without_client_transmission() -> Result<(), Box<dyn Error>> {
    let output = Command::new("python3").arg(fixture()).output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("isl_delivered=true no_client_send=true cleanup_confirmed=true")
    );
    Ok(())
}

#[test]
#[ignore = "uses a proved private namespace and owned veth pair"]
fn owned_veth_delivers_positive_and_negative_frames_to_ready_client() -> Result<(), Box<dyn Error>>
{
    // The harness proves the namespace and pair before starting this client
    let client = r"
import os
import socket
from pathlib import Path
fixtures = Path(os.environ['L2_TEST_ISL_FIXTURE'])
ready = Path(os.environ['L2_TEST_ISL_SYNC_DIR']) / 'ready'
names = ('other-prefix.bin', 'unsupported-media.bin', 'malformed-llc.bin', 'unsupported-length.bin', 'valid.bin')
expected = {(fixtures / name).read_bytes() for name in names}
with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as link:
    link.bind((os.environ['L2_TEST_ISL_INTERFACE'], 0))
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
            .contains("isl_delivered=true no_client_send=true cleanup_confirmed=true")
    );
    Ok(())
}

#[test]
#[ignore = "uses a proved private namespace and owned veth pair"]
fn owned_veth_detects_an_unexpected_observer_transmission() -> Result<(), Box<dyn Error>> {
    // The negative transmission is confined to the verified private veth
    let client = r"
import os
import socket
import time
from pathlib import Path
ready = Path(os.environ['L2_TEST_ISL_SYNC_DIR']) / 'ready'
wire = (Path(os.environ['L2_TEST_ISL_FIXTURE']) / 'valid.bin').read_bytes()
with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as link:
    link.bind((os.environ['L2_TEST_ISL_INTERFACE'], 0))
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
