#![cfg(target_os = "linux")]

use std::{error::Error, path::Path, process::Command};

#[test]
#[ignore = "uses a proved private network namespace and an owned veth pair"]
fn owned_veth_delivers_vrrp_advertisement_without_a_client_send() -> Result<(), Box<dyn Error>> {
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/first_hop/vrrp/fixtures/veth.py");
    let output = Command::new("python3").arg(fixture).output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("advertisements_delivered=true no_client_send=true cleanup_confirmed=true")
    );
    Ok(())
}

#[test]
#[ignore = "uses a proved private network namespace and an owned veth pair"]
fn owned_veth_rejects_a_command_that_never_became_ready() -> Result<(), Box<dyn Error>> {
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/first_hop/vrrp/fixtures/veth.py");
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
fn owned_veth_exercises_a_ready_receive_only_command() -> Result<(), Box<dyn Error>> {
    // The harness verifies namespace ownership before starting the test client
    let client = r"
import os
import socket
from pathlib import Path
fixture = Path(os.environ['L2_TEST_VRRP_FIXTURE'])
ready = Path(os.environ['L2_TEST_VRRP_SYNC_DIR']) / 'ready'
expected = (fixture / 'valid.bin').read_bytes()
with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as link:
    link.bind((os.environ['L2_TEST_VRRP_INTERFACE'], 0))
    link.settimeout(3)
    ready.write_text('ready')
    for _ in range(32):
        if link.recv(65535) == expected:
            break
    else:
        raise RuntimeError('valid advertisement was not received')
";
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/first_hop/vrrp/fixtures/veth.py");
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
            .contains("advertisements_delivered=true no_client_send=true cleanup_confirmed=true")
    );
    Ok(())
}

#[test]
#[ignore = "uses a proved private network namespace and an owned veth pair"]
fn owned_veth_detects_a_command_transmitting_from_the_selected_interface()
-> Result<(), Box<dyn Error>> {
    // The attempted send is confined to the validated private veth
    let client = r"
import os
import socket
import time
from pathlib import Path
fixture = Path(os.environ['L2_TEST_VRRP_FIXTURE'])
ready = Path(os.environ['L2_TEST_VRRP_SYNC_DIR']) / 'ready'
frame = (fixture / 'valid.bin').read_bytes()
with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as link:
    link.bind((os.environ['L2_TEST_VRRP_INTERFACE'], 0))
    ready.write_text('ready')
    link.send(frame)
    time.sleep(0.5)
";
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/first_hop/vrrp/fixtures/veth.py");
    let output = Command::new("python3")
        .arg(fixture)
        .args(["--", "python3", "-c", client])
        .output()?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unexpected client transmission"));
    Ok(())
}

#[test]
#[ignore = "uses a proved private network namespace and an owned veth pair"]
fn owned_veth_does_not_echo_untrusted_client_output_on_failure() -> Result<(), Box<dyn Error>> {
    let client = r"
import os
import socket
import sys
from pathlib import Path
fixture = Path(os.environ['L2_TEST_VRRP_FIXTURE'])
ready = Path(os.environ['L2_TEST_VRRP_SYNC_DIR']) / 'ready'
expected = (fixture / 'valid.bin').read_bytes()
with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as link:
    link.bind((os.environ['L2_TEST_VRRP_INTERFACE'], 0))
    link.settimeout(3)
    ready.write_text('ready')
    for _ in range(32):
        if link.recv(65535) == expected:
            break
    else:
        raise RuntimeError('valid advertisement was not received')
sys.stderr.write('UNTRUSTED-CLIENT-CONTENT')
sys.exit(1)
";
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/first_hop/vrrp/fixtures/veth.py");
    let output = Command::new("python3")
        .arg(fixture)
        .args(["--", "python3", "-c", client])
        .output()?;
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("UNTRUSTED-CLIENT-CONTENT"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("UNTRUSTED-CLIENT-CONTENT"));
    Ok(())
}
