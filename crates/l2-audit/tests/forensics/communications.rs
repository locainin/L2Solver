use super::support::*;
use l2_discovery::NetworkAddress;

#[test]
fn ordinary_traffic_maps_header_pairs() -> TestResult {
    let packet = captured(traffic(SECOND_MAC, ADDRESS), 0)?;
    let report = assess([packet.clone(), packet])?;
    let communication = report
        .forensics
        .communications
        .first()
        .ok_or("missing communication")?;
    assert_eq!(communication.source, NetworkAddress::Ipv4([192, 0, 2, 3]));
    assert_eq!(communication.destination, NetworkAddress::Ipv4(ADDRESS));
    assert_eq!(communication.source_mac, "02:00:00:00:00:03");
    assert_eq!(communication.destination_mac, "02:00:00:00:00:02");
    assert_eq!(communication.ports, Some((12345, 443)));
    assert_eq!(communication.protocol, 17);
    assert_eq!(communication.frames, 2);
    assert_eq!(report.forensics.ip_frames_seen, 2);
    assert_eq!(report.forensics.ip_frames_parsed, 2);
    assert_evidence(&report, &[communication.packet]);
    assert!(report.findings.is_empty());
    Ok(())
}

#[test]
fn priority_bits_preserve_vlan_scope() -> TestResult {
    let traffic = traffic(SECOND_MAC, ADDRESS);
    let report = assess([
        captured(tagged(&traffic, 20)?, 0)?,
        captured(tagged(&traffic, 0xb014)?, 0)?,
        captured(tagged(&traffic, 20)?, 1)?,
    ])?;
    assert_eq!(report.forensics.communications.len(), 2);
    let first = report
        .forensics
        .communications
        .first()
        .ok_or("missing communication")?;
    assert_eq!(first.scope.vlan_ids, [(0x8100, 20)]);
    assert_eq!(first.frames, 2);
    Ok(())
}

#[test]
fn untagged_priority_native_membership_distinct() -> TestResult {
    let bytes = traffic(SECOND_MAC, ADDRESS);
    let report = assess([
        captured(bytes.clone(), 0)?,
        captured(tagged(&bytes, 0)?, 0)?,
        captured(tagged(&bytes, 1)?, 0)?,
    ])?;
    assert_eq!(report.forensics.communications.len(), 3);
    Ok(())
}

#[test]
fn invalid_capture_ip_remains_unparsed() -> TestResult {
    let mut invalid = traffic(SECOND_MAC, ADDRESS);
    *invalid.get_mut(14).ok_or("short fixture")? = 0x44;
    let mut truncated = traffic(SECOND_MAC, ADDRESS);
    truncated.pop();
    let report = assess([captured(invalid, 0)?, captured(truncated, 0)?])?;
    assert_eq!(
        report.forensics.communications,
        [] as [l2_audit::IpCommunication; 0]
    );
    assert_eq!(report.forensics.ip_frames_seen, 2);
    assert_eq!(report.forensics.ip_frames_parsed, 0);
    assert!(!report.collection_complete());
    Ok(())
}
