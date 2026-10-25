#[path = "../src/forensic_report.rs"]
mod forensic_report;

use l2_audit::{
    ArpObservation, DnsAddressUse, DnsResponseMatch, ForensicScope, IpCommunication, NetworkAddress,
};
use l2_cli::arguments::{Command, parse};
use std::{ffi::OsString, path::PathBuf, process::Command as ProcessCommand};

#[path = "../src/relationships_report.rs"]
mod relationships_report;

#[test]
fn parses_relationships() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = ["relationships", "capture.pcap"].map(OsString::from);

    let command = parse(&arguments)?;

    assert_eq!(
        command,
        Command::Relationships(PathBuf::from("capture.pcap"))
    );
    Ok(())
}

#[test]
fn command_reads_capture_without_case() -> Result<(), Box<dyn std::error::Error>> {
    let output = ProcessCommand::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["relationships", "../../tests/pcaps/lldp.pcap"])
        .output()?;

    assert!(output.status.success());
    let text = String::from_utf8(output.stdout)?;
    assert!(text.starts_with("Capture: ../../tests/pcaps/lldp.pcap\nCapture relationships\n"));
    assert!(text.contains("Forensic observations"));
    assert!(text.contains("does not establish ownership, delivery, cause, or intent"));
    assert!(!text.contains("graph"));
    assert!(!text.contains("node"));
    Ok(())
}

#[test]
fn help_lists_relationships() -> Result<(), Box<dyn std::error::Error>> {
    let output = ProcessCommand::new(env!("CARGO_BIN_EXE_l2solver"))
        .arg("--help")
        .output()?;

    assert!(output.status.success());
    let text = String::from_utf8(output.stdout)?;
    assert!(text.lines().any(|line| {
        line.trim_start().starts_with("relationships ")
            && line.contains("MAC/IP, ARP, DNS, and transport relationships")
    }));
    Ok(())
}

#[test]
fn renders_capture_facts() -> Result<(), Box<dyn std::error::Error>> {
    let mut report = l2_audit::Survey::new().finish(&l2_audit::Policy::default())?;
    let scope = ForensicScope {
        section: 0,
        interface: 1,
        vlan_ids: vec![(0x8100, 20)],
        vlan_aux: None,
    };
    report.forensics.communications.push(IpCommunication {
        scope: scope.clone(),
        source: NetworkAddress::Ipv4([192, 0, 2, 10]),
        destination: NetworkAddress::Ipv4([198, 51, 100, 20]),
        source_mac: String::from("02:00:00:00:00:01"),
        destination_mac: String::from("02:00:00:00:00:02"),
        protocol: 6,
        ports: Some((49152, 443)),
        fragmented: false,
        frames: 3,
        packet: 7,
    });
    report.forensics.arp_observations.push(ArpObservation {
        scope,
        source_mac: String::from("02:00:00:00:00:01"),
        operation: 1,
        sender_mac: String::from("02:00:00:00:00:01"),
        sender_address: NetworkAddress::Ipv4([192, 0, 2, 10]),
        target_mac: String::from("00:00:00:00:00:00"),
        target_address: NetworkAddress::Ipv4([192, 0, 2, 1]),
        frames: 1,
        packet: 2,
    });
    report.forensics.dns_matches.push(DnsResponseMatch {
        response_packet: 9,
        query_packet: Some(5),
        candidate_queries: 1,
    });
    report.forensics.dns_address_uses.push(DnsAddressUse {
        query_packet: 5,
        response_packet: 9,
        packet: 12,
        answer_record: 0,
        address: NetworkAddress::Ipv4([198, 51, 100, 20]),
        client_matches_requester: true,
    });

    let mut output = Vec::new();
    relationships_report::write(&report, &mut output)?;
    let text = String::from_utf8(output)?;

    assert!(text.contains("02:00:00:00:00:01"));
    assert!(text.contains("192.0.2.10"));
    assert!(text.contains("protocol=6 ports=49152->443"));
    assert!(text.contains("ARP operation=1"));
    assert!(text.contains("DNS response packet=9 matching outstanding queries=1 query_packet=5"));
    assert!(text.contains("DNS address 198.51.100.20 packets 5 -> 9 -> 12"));
    assert!(text.contains("does not establish ownership, delivery, cause, or intent"));
    assert!(!text.contains("graph"));
    assert!(!text.contains("node"));
    Ok(())
}
