use super::common::{LINUX_STP_PCAP, captured, source_with_suffix, tagged_ethernet_frame};
use l2_audit::{Policy, Survey};

#[test]
fn malformed_lldp_keeps_ethernet_inventory() -> Result<(), Box<dyn std::error::Error>> {
    let source = source_with_suffix(101);
    let bytes = tagged_ethernet_frame(
        [0x01, 0x80, 0xc2, 0, 0, 0x0e],
        source,
        0x8100,
        20,
        0x88cc,
        &[0],
    );
    let mut survey = Survey::new();
    survey.observe(&captured(bytes)?)?;
    let report = survey.finish(&Policy::default())?;
    let interface = report.interfaces.first().ok_or("interface")?;

    assert_eq!(report.quality.malformed, 1);
    assert_eq!(interface.macs, ["00:00:00:00:00:65"]);
    assert_eq!(
        interface.vlans.first().ok_or("VLAN observation")?.tags,
        [(0x8100, 20)]
    );
    assert_eq!(interface.untagged_packet, None);
    assert!(interface.neighbors.is_empty());
    assert_eq!(report.evidence.len(), 1);
    assert_eq!(report.evidence.first().ok_or("evidence")?.sequence, 1);
    Ok(())
}

#[test]
fn malformed_stp_keeps_ethernet_inventory() -> Result<(), Box<dyn std::error::Error>> {
    let mut reader = l2_pcap::CaptureReader::new(LINUX_STP_PCAP)?;
    let packet = reader.next_packet()?.ok_or("STP fixture")?;
    let mut bytes = packet.bytes().to_vec();
    bytes
        .get_mut(17..19)
        .ok_or("STP protocol identifier")?
        .copy_from_slice(&[0, 1]);

    let mut survey = Survey::new();
    survey.observe(&captured(bytes)?)?;
    let report = survey.finish(&Policy::default())?;
    let interface = report.interfaces.first().ok_or("interface")?;

    assert_eq!(report.quality.malformed, 1);
    assert_eq!(interface.macs, ["36:09:f1:ae:e3:29"]);
    assert_eq!(interface.untagged_packet, Some(1));
    assert_eq!(interface.stp_frames, 0);
    assert!(interface.stp.is_empty());
    assert_eq!(report.evidence.len(), 1);
    Ok(())
}

#[test]
fn unsupported_stp_keeps_ethernet_inventory() -> Result<(), Box<dyn std::error::Error>> {
    let mut reader = l2_pcap::CaptureReader::new(LINUX_STP_PCAP)?;
    let packet = reader.next_packet()?.ok_or("STP fixture")?;
    let mut bytes = packet.bytes().to_vec();
    *bytes.get_mut(19).ok_or("STP version")? = 3;

    let mut survey = Survey::new();
    survey.observe(&captured(bytes)?)?;
    let report = survey.finish(&Policy::default())?;
    let interface = report.interfaces.first().ok_or("interface")?;

    assert_eq!(report.quality.unsupported_stp, 1);
    assert_eq!(interface.macs, ["36:09:f1:ae:e3:29"]);
    assert_eq!(interface.untagged_packet, Some(1));
    assert_eq!(interface.stp_frames, 0);
    assert!(interface.stp.is_empty());
    assert_eq!(report.evidence.len(), 1);
    Ok(())
}

#[test]
fn malformed_ethernet_creates_no_inventory() -> Result<(), Box<dyn std::error::Error>> {
    let mut survey = Survey::new();
    survey.observe(&captured(vec![0; 13])?)?;
    let report = survey.finish(&Policy::default())?;
    let interface = report.interfaces.first().ok_or("interface")?;

    assert_eq!(report.quality.malformed, 1);
    assert!(interface.macs.is_empty());
    assert!(interface.vlans.is_empty());
    assert_eq!(interface.untagged_packet, None);
    assert!(report.evidence.is_empty());
    Ok(())
}

#[test]
fn ethernet_ii_signature_not_stp() -> Result<(), Box<dyn std::error::Error>> {
    let mut reader = l2_pcap::CaptureReader::new(LINUX_STP_PCAP)?;
    let packet = reader.next_packet()?.ok_or("STP fixture")?;
    let mut bytes = packet.bytes().to_vec();
    bytes
        .get_mut(12..14)
        .ok_or("Ethernet field")?
        .copy_from_slice(&[0x08, 0x00]);
    let mut survey = Survey::new();
    survey.observe(&captured(bytes)?)?;
    let report = survey.finish(&Policy::default())?;
    let interface = report.interfaces.first().ok_or("interface")?;
    assert_eq!(interface.stp_frames, 0);
    assert!(interface.stp.is_empty());
    assert_eq!(report.quality.unsupported_stp, 0);
    Ok(())
}
