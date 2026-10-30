#![cfg(target_os = "linux")]

use std::{error::Error, path::Path, process::Command};

#[test]
#[ignore = "uses only a proved private namespace and owned veth pair"]
fn owned_veth_observes_one_start_and_one_independent_request() -> Result<(), Box<dyn Error>> {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/dot1x/fixtures/veth.py");
    let output = Command::new("python3").arg(fixture).output()?;
    assert!(
        output.status.success(),
        "EAPOL fixture failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("start_captured=true request_captured=true cleanup_confirmed=true")
    );
    Ok(())
}

#[test]
#[ignore = "uses only a proved private namespace and owned veth pair"]
fn owned_veth_does_not_claim_a_start_when_command_sends_nothing() -> Result<(), Box<dyn Error>> {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/dot1x/fixtures/veth.py");
    let output = Command::new("python3")
        .arg(fixture)
        .args(["--", "python3", "-c", "pass"])
        .output()?;
    assert!(
        !output.status.success(),
        "a silent command must fail the fixture"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("starts=0"));
    Ok(())
}

#[test]
#[ignore = "uses only a proved private namespace and owned veth pair"]
fn owned_veth_rejects_altered_or_repeated_starts() -> Result<(), Box<dyn Error>> {
    // The harness verifies namespace ownership before this isolated client runs
    let client = r"
import os
import socket
import sys
import time
from pathlib import Path
start = bytearray((Path(os.environ['L2_TEST_DOT1X_FIXTURE']) / 'start.bin').read_bytes())
if sys.argv[1] == 'altered':
    start[0] ^= 1
with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as link:
    link.bind((os.environ['L2_TEST_DOT1X_INTERFACE'], 0))
    for _ in range(2 if sys.argv[1] == 'repeated' else 1):
        if link.send(start) != len(start):
            raise RuntimeError('partial EAPOL Start')
    time.sleep(0.25)
";
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/dot1x/fixtures/veth.py");
    for (kind, expected) in [("altered", "starts=0"), ("repeated", "starts=2")] {
        let output = Command::new("python3")
            .arg(&fixture)
            .args(["--", "python3", "-c", client, kind])
            .output()?;
        assert!(
            !output.status.success(),
            "{kind} Start must fail the fixture"
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains(expected));
    }
    Ok(())
}

#[test]
#[ignore = "uses only a proved private namespace and owned veth pair"]
fn owned_veth_responder_answers_a_real_start_in_the_selected_namespace()
-> Result<(), Box<dyn Error>> {
    // The harness verifies namespace ownership before this isolated client runs
    let client = r"
import os
import socket
from pathlib import Path
from scapy.all import EAP, Ether
fixture = Path(os.environ['L2_TEST_DOT1X_FIXTURE'])
start = (fixture / 'start.bin').read_bytes()
with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as link:
    link.bind((os.environ['L2_TEST_DOT1X_INTERFACE'], 0))
    link.settimeout(2)
    if link.send(start) != len(start):
        raise RuntimeError('partial EAPOL Start')
    for _ in range(16):
        request = Ether(link.recv(65535))
        if request.haslayer(EAP) and request[EAP].code == 1:
            if request.dst != '02:00:00:00:00:01' or request[EAP].id != 41:
                raise RuntimeError('unexpected EAP Request')
            break
    else:
        raise RuntimeError('no EAP Request on the owned veth')
";
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/dot1x/fixtures/veth.py");
    let output = Command::new("python3")
        .arg(fixture)
        .args(["--", "python3", "-c", client])
        .output()?;
    assert!(
        output.status.success(),
        "EAPOL fixture failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("start_captured=true request_captured=true cleanup_confirmed=true")
    );
    Ok(())
}
