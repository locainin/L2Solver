#![cfg(target_os = "linux")]

use std::{error::Error, path::Path, process::Command};

#[test]
#[ignore = "uses a proved private network namespace and an owned veth pair"]
fn owned_veth_delivers_hsrp_without_a_client_send() -> Result<(), Box<dyn Error>> {
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/first_hop/hsrp/fixtures/veth.py");
    let output = Command::new("python3").arg(fixture).output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("messages_delivered=true no_client_send=true cleanup_confirmed=true")
    );
    Ok(())
}

#[test]
#[ignore = "uses a proved private network namespace and an owned veth pair"]
fn owned_veth_rejects_a_command_that_never_becomes_ready() -> Result<(), Box<dyn Error>> {
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/first_hop/hsrp/fixtures/veth.py");
    let output = Command::new("python3")
        .arg(fixture)
        .args(["--", "python3", "-c", "pass"])
        .output()?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("ready"));
    Ok(())
}

#[test]
#[ignore = "uses a proved private network namespace and an owned veth pair"]
fn owned_veth_delivers_frames_to_a_ready_receive_only_client() -> Result<(), Box<dyn Error>> {
    let client = r"
import os
import socket
from pathlib import Path
fixture = Path(os.environ['L2_TEST_HSRP_FIXTURE'])
ready = Path(os.environ['L2_TEST_HSRP_SYNC_DIR']) / 'ready'
expected = (fixture / 'advertisement.bin').read_bytes()
with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as link:
    link.bind((os.environ['L2_TEST_HSRP_INTERFACE'], 0))
    link.settimeout(3)
    ready.write_text('ready')
    for _ in range(32):
        if link.recv(65535) == expected:
            break
    else:
        raise RuntimeError('valid HSRP message was not received')
";
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/first_hop/hsrp/fixtures/veth.py");
    let output = Command::new("python3")
        .arg(fixture)
        .args(["--", "python3", "-c", client])
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("messages_delivered=true no_client_send=true cleanup_confirmed=true")
    );
    Ok(())
}

#[test]
#[ignore = "uses a proved private network namespace and an owned veth pair"]
fn owned_veth_detects_a_client_transmission() -> Result<(), Box<dyn Error>> {
    // The namespace harness proves ownership before the test attempts a send
    let client = r"
import os
import socket
import time
from pathlib import Path
fixture = Path(os.environ['L2_TEST_HSRP_FIXTURE'])
ready = Path(os.environ['L2_TEST_HSRP_SYNC_DIR']) / 'ready'
frame = (fixture / 'advertisement.bin').read_bytes()
with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as link:
    link.bind((os.environ['L2_TEST_HSRP_INTERFACE'], 0))
    ready.write_text('ready')
    link.send(frame)
    time.sleep(0.5)
";
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/first_hop/hsrp/fixtures/veth.py");
    let output = Command::new("python3")
        .arg(fixture)
        .args(["--", "python3", "-c", client])
        .output()?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unexpected client transmission"));
    Ok(())
}
