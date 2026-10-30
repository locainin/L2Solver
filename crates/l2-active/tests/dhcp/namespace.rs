#![cfg(target_os = "linux")]

use std::{error::Error, path::Path, process::Command};

#[test]
#[ignore = "uses only a verified private user, mount, and network namespace with a veth pair"]
fn owned_veth_carries_a_synthetic_dhcp_exchange_and_confirms_cleanup() -> Result<(), Box<dyn Error>>
{
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/dhcp/fixtures/veth.py");
    let output = Command::new("python3").arg(fixture).output()?;
    assert!(
        output.status.success(),
        "DHCP veth fixture failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("request_captured=true offer_captured=true cleanup_confirmed=true")
    );
    Ok(())
}

#[test]
#[ignore = "uses only a verified private user, mount, and network namespace with a veth pair"]
fn owned_veth_does_not_claim_a_discover_when_command_sends_nothing() -> Result<(), Box<dyn Error>> {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/dhcp/fixtures/veth.py");
    let output = Command::new("python3")
        .arg(fixture)
        .args(["--", "python3", "-c", "pass"])
        .output()?;
    assert!(
        !output.status.success(),
        "a silent command must fail the fixture"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("requests=0"));
    Ok(())
}

#[test]
#[ignore = "uses only a verified private user, mount, and network namespace with a veth pair"]
fn owned_veth_responder_copies_the_request_transaction() -> Result<(), Box<dyn Error>> {
    // This client is executed only after the fixture has verified the isolated namespace
    let client = r"
import os
import socket
from pathlib import Path
from scapy.all import BOOTP, Ether, IP, UDP, raw
request = Ether((Path(os.environ['L2_TEST_DHCP_FIXTURE']) / 'discover.bin').read_bytes())
request[BOOTP].xid = 0x87654321
del request[IP].chksum
del request[UDP].chksum
with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as link:
    link.bind((os.environ['L2_TEST_DHCP_INTERFACE'], 0))
    link.settimeout(2)
    encoded = raw(request)
    if link.send(encoded) != len(encoded):
        raise RuntimeError('partial test request')
    for _ in range(16):
        reply = Ether(link.recv(65535))
        if reply.haslayer(BOOTP) and reply[BOOTP].op == 2:
            if reply[BOOTP].xid != 0x87654321:
                raise RuntimeError('response transaction mismatch')
            break
    else:
        raise RuntimeError('test client did not receive the response')
";
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/dhcp/fixtures/veth.py");
    let output = Command::new("python3")
        .arg(fixture)
        .args(["--", "python3", "-c", client])
        .output()?;
    assert!(
        output.status.success(),
        "dynamic DHCP fixture failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("request_captured=true offer_captured=true cleanup_confirmed=true")
    );
    Ok(())
}
