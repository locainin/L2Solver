use super::common::{LLDP_PCAP, captured, ethernet_frame};
use l2_audit::{Policy, Survey, Verdict};

fn lldp_tlv(kind: u8, value: &[u8]) -> Vec<u8> {
    let Ok(length) = u16::try_from(value.len()) else {
        return Vec::new();
    };
    let header = (u16::from(kind) << 9) | length;
    let mut bytes = header.to_be_bytes().to_vec();
    bytes.extend_from_slice(value);
    bytes
}

pub fn lldp_frame(chassis_subtype: u8, chassis: [u8; 6], port: &[u8], name: &[u8]) -> Vec<u8> {
    lldp_frame_with_names(chassis_subtype, chassis, port, &[name])
}

fn lldp_frame_with_names(
    chassis_subtype: u8,
    chassis: [u8; 6],
    port: &[u8],
    names: &[&[u8]],
) -> Vec<u8> {
    let mut chassis_value = vec![chassis_subtype];
    chassis_value.extend_from_slice(&chassis);
    let mut port_value = vec![5];
    port_value.extend_from_slice(port);

    let mut payload = lldp_tlv(1, &chassis_value);
    payload.extend(lldp_tlv(2, &port_value));
    payload.extend(lldp_tlv(3, &120_u16.to_be_bytes()));
    for name in names {
        payload.extend(lldp_tlv(5, name));
    }
    payload.extend_from_slice(&[0, 0]);

    let mut bytes = ethernet_frame(
        [0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e],
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        0x88cc,
        &payload,
    );
    // Ethernet padding is retained by the wire parser but is outside LLDP
    // after the End TLV, so the test remains a realistic minimum frame
    bytes.resize(bytes.len().max(60), 0);
    bytes
}

#[test]
fn inventory_keeps_capture_provenance() -> Result<(), Box<dyn std::error::Error>> {
    let mut reader = l2_pcap::CaptureReader::new(LLDP_PCAP)?;
    let mut survey = Survey::new();
    survey.observe(&reader.next_packet()?.ok_or("no frame")?)?;
    let report = survey.finish(&Policy::default())?;
    assert_eq!(
        report
            .interfaces
            .first()
            .ok_or("interface")?
            .neighbors
            .first()
            .ok_or("neighbor")?
            .system_name,
        b"core\x1b\x07"
    );
    assert!(
        report.exposures.iter().any(
            |exposure| exposure.check_id == "LLDP-001" && !exposure.evidence_packets.is_empty()
        )
    );
    assert!(report.findings.iter().all(|f| f.verdict != Verdict::Pass));
    Ok(())
}

#[test]
fn deduplicates_and_updates_identity() -> Result<(), Box<dyn std::error::Error>> {
    let chassis_a = [0, 1, 2, 3, 4, 5];
    let chassis_b = [0, 1, 2, 3, 4, 6];
    let mut survey = Survey::new();
    for (chassis, port, name) in [
        (chassis_a, &b"port-a"[..], &b"one"[..]),
        (chassis_a, &b"port-a"[..], &b"one"[..]),
        (chassis_a, &b"port-a"[..], &b"two"[..]),
        (chassis_b, &b"port-a"[..], &b"two"[..]),
        (chassis_a, &b"port-b"[..], &b"two"[..]),
    ] {
        survey.observe(&captured(lldp_frame(4, chassis, port, name))?)?;
    }
    let report = survey.finish(&Policy::default())?;
    let interface = report.interfaces.first().ok_or("interface")?;
    assert_eq!(interface.neighbors.len(), 3);
    let updated = interface
        .neighbors
        .iter()
        .find(|neighbor| neighbor.chassis_id == [4, 0, 1, 2, 3, 4, 5]);
    let updated = updated.ok_or("updated neighbor")?;
    assert_eq!(updated.port_id, [5, b'p', b'o', b'r', b't', b'-', b'a']);
    assert_eq!(updated.system_name, b"two");
    assert_eq!(updated.packet, 3);
    assert!(
        interface.neighbors.iter().any(|neighbor| {
            neighbor.chassis_id == [4, 0, 1, 2, 3, 4, 6] && neighbor.packet == 4
        })
    );
    assert!(interface.neighbors.iter().any(|neighbor| {
        neighbor.chassis_id == [4, 0, 1, 2, 3, 4, 5]
            && neighbor.port_id == [5, b'p', b'o', b'r', b't', b'-', b'b']
            && neighbor.packet == 5
    }));
    assert_eq!(
        report
            .evidence
            .iter()
            .map(|evidence| evidence.sequence)
            .collect::<Vec<_>>(),
        [1, 3, 4, 5]
    );
    Ok(())
}

#[test]
fn duplicate_system_names_ambiguous_every() -> Result<(), Box<dyn std::error::Error>> {
    let chassis = [0, 1, 2, 3, 4, 5];
    for names in [[&b"one"[..], &b"two"[..]], [&b"two"[..], &b"one"[..]]] {
        let mut survey = Survey::new();
        survey.observe(&captured(lldp_frame_with_names(
            4, chassis, b"port-a", &names,
        ))?)?;
        let report = survey.finish(&Policy::default())?;
        let neighbor = report
            .interfaces
            .first()
            .and_then(|interface| interface.neighbors.first())
            .ok_or("missing neighbor")?;
        assert!(neighbor.system_name.is_empty());
    }
    Ok(())
}
