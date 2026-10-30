use std::{error::Error, net::Ipv4Addr};

use super::fixture::{CLIENT_MAC, DISCOVER, SERVER, TRANSACTION, probe};

#[test]
fn discover_matches_independent_scapy_bytes_and_uses_explicit_client_identity()
-> Result<(), Box<dyn Error>> {
    let operation = probe(None, 8, 4_096)?;
    assert_eq!(operation.frame(), DISCOVER);
    assert_eq!(operation.source_mac().bytes(), CLIENT_MAC);
    assert_eq!(operation.transaction().get(), TRANSACTION);
    Ok(())
}

#[test]
fn malformed_or_duplicate_server_expectations_are_rejected_before_sending() {
    assert!(probe(Some(&[]), 8, 4_096).is_err());
    assert!(probe(Some(&[SERVER, SERVER]), 8, 4_096).is_err());
    let oversized: Vec<Ipv4Addr> = (1..=65).map(|last| Ipv4Addr::new(10, 0, 0, last)).collect();
    assert!(probe(Some(&oversized), 8, 4_096).is_err());
    for invalid in [
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::BROADCAST,
        Ipv4Addr::LOCALHOST,
        Ipv4Addr::new(224, 0, 0, 1),
    ] {
        assert!(probe(Some(&[invalid]), 8, 4_096).is_err());
    }
}

#[test]
fn invalid_allowlist_reports_an_actionable_error() -> Result<(), Box<dyn Error>> {
    let error = probe(Some(&[]), 8, 4_096)
        .err()
        .ok_or("empty allowlist should be rejected")?;
    assert_eq!(error.to_string(), "invalid DHCP server allowlist");
    Ok(())
}
