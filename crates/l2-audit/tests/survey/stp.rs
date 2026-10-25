use super::common::{LINUX_STP_PCAP, captured, ethernet_frame, frame};
use l2_audit::{Policy, Survey, Verdict};

fn stp_configuration_frame(root_bridge: [u8; 8]) -> Vec<u8> {
    let mut bpdu = vec![0, 0, 0, 0, 0x81];
    bpdu.extend_from_slice(&root_bridge);
    bpdu.extend_from_slice(&0_u32.to_be_bytes());
    bpdu.extend_from_slice(&[0x90, 0x02, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
    bpdu.extend_from_slice(&0x8001_u16.to_be_bytes());
    bpdu.extend_from_slice(&0x0100_u16.to_be_bytes());
    bpdu.extend_from_slice(&0x1400_u16.to_be_bytes());
    bpdu.extend_from_slice(&0x0200_u16.to_be_bytes());
    bpdu.extend_from_slice(&0x0f00_u16.to_be_bytes());

    let mut llc = vec![0x42, 0x42, 0x03];
    llc.extend_from_slice(&bpdu);
    let length = u16::try_from(llc.len()).unwrap_or_default();
    let mut bytes = ethernet_frame(
        [0x01, 0x80, 0xc2, 0x00, 0x00, 0x00],
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        length,
        &llc,
    );
    bytes.resize(bytes.len().max(60), 0);
    bytes
}

fn rstp_variant(stp: &[u8]) -> Vec<u8> {
    let mut bytes = stp.to_vec();
    let Some(version) = bytes.get_mut(19) else {
        return Vec::new();
    };
    *version = 2;
    let Some(kind) = bytes.get_mut(20) else {
        return Vec::new();
    };
    *kind = 2;
    // RSTP appends the version-one-length octet to the STP tree fields
    bytes.push(0);
    let Some(length) = bytes.get_mut(12..14) else {
        return Vec::new();
    };
    length.copy_from_slice(&[0, 0x27]);
    bytes
}

#[test]
fn later_expected_root_earlier_violation() -> Result<(), Box<dyn std::error::Error>> {
    let mut reader = l2_pcap::CaptureReader::new(LINUX_STP_PCAP)?;
    let original = reader.next_packet()?.ok_or("STP fixture")?;
    let mut unexpected = original.bytes().to_vec();
    // Root MAC starts after Ethernet, LLC, protocol, version, type, flags, and priority
    *unexpected.get_mut(24).ok_or("root MAC")? = 0xaa;
    let unexpected = frame(unexpected, u32::try_from(original.bytes().len())?)?;
    let mut survey = Survey::new();
    survey.observe(&unexpected)?;
    survey.observe(&original)?;
    let report = survey.finish(&Policy {
        expected_stp_root: Some("36:09:f1:ae:e3:29".into()),
        ..Policy::default()
    })?;
    assert!(report.findings.iter().any(|f| f.check_id == "STP-002"
        && f.verdict == Verdict::Fail
        && f.evidence_packets.contains(&1)));
    Ok(())
}

#[test]
fn history_keeps_priority_and_extension() -> Result<(), Box<dyn std::error::Error>> {
    let mut reader = l2_pcap::CaptureReader::new(LINUX_STP_PCAP)?;
    let original = reader.next_packet()?.ok_or("STP fixture")?;
    let mut different_priority = original.bytes().to_vec();
    different_priority
        .get_mut(22..24)
        .ok_or("root priority")?
        .copy_from_slice(&[0x90, 0x00]);
    let mut different_extension = original.bytes().to_vec();
    different_extension
        .get_mut(22..24)
        .ok_or("root extension")?
        .copy_from_slice(&[0x80, 0x01]);

    let mut survey = Survey::new();
    survey.observe(&captured(different_priority)?)?;
    survey.observe(&captured(different_extension)?)?;
    let report = survey.finish(&Policy::default())?;
    let interface = report.interfaces.first().ok_or("interface")?;
    assert_eq!(interface.stp.len(), 2);
    assert_eq!(
        interface.stp.first().ok_or("priority state")?.root.priority,
        0x9000
    );
    assert_eq!(
        interface
            .stp
            .first()
            .ok_or("priority state")?
            .root
            .system_id_extension,
        0
    );
    assert_eq!(
        interface.stp.get(1).ok_or("extension state")?.root.priority,
        0x8000
    );
    assert_eq!(
        interface
            .stp
            .get(1)
            .ok_or("extension state")?
            .root
            .system_id_extension,
        1
    );
    assert_eq!(
        interface
            .stp
            .first()
            .ok_or("priority state")?
            .root
            .mac
            .as_str(),
        "36:09:f1:ae:e3:29"
    );
    assert_eq!(
        interface
            .stp
            .get(1)
            .ok_or("extension state")?
            .root
            .mac
            .as_str(),
        "36:09:f1:ae:e3:29"
    );
    Ok(())
}

#[test]
fn history_tracks_repeats_and_versions() -> Result<(), Box<dyn std::error::Error>> {
    let mut reader = l2_pcap::CaptureReader::new(LINUX_STP_PCAP)?;
    let original = reader.next_packet()?.ok_or("STP fixture")?;
    let rstp = captured(rstp_variant(original.bytes()))?;
    let root_bridge: [u8; 8] = original
        .bytes()
        .get(22..30)
        .ok_or("root bridge")?
        .try_into()
        .map_err(|_| "root bridge width")?;

    let mut priority = rstp.bytes().to_vec();
    priority
        .get_mut(22..24)
        .ok_or("root priority")?
        .copy_from_slice(&[0x80, 0x01]);
    let mut different_root = rstp.bytes().to_vec();
    *different_root.get_mut(24).ok_or("root MAC")? = 0xaa;

    let mut survey = Survey::new();
    survey.observe(&rstp)?;
    survey.observe(&rstp)?;
    survey.observe(&captured(priority)?)?;
    survey.observe(&captured(rstp.bytes().to_vec())?)?;
    survey.observe(&captured(stp_configuration_frame(root_bridge))?)?;
    survey.observe(&captured(stp_configuration_frame(root_bridge))?)?;
    survey.observe(&captured(different_root)?)?;
    let report = survey.finish(&Policy::default())?;
    let interface = report.interfaces.first().ok_or("interface")?;
    assert_eq!(interface.stp_frames, 7);
    assert_eq!(interface.stp.len(), 5);
    assert_eq!(
        interface
            .stp
            .iter()
            .map(|observation| observation.frames)
            .collect::<Vec<_>>(),
        [2, 1, 1, 2, 1]
    );
    assert_eq!(
        interface.stp.first().ok_or("first STP state")?.version,
        "Rstp"
    );
    assert_eq!(
        interface
            .stp
            .get(1)
            .ok_or("second STP state")?
            .root
            .priority,
        0x8000
    );
    assert_eq!(
        interface
            .stp
            .get(1)
            .ok_or("second STP state")?
            .root
            .system_id_extension,
        1
    );
    assert_eq!(
        interface.stp.get(2).ok_or("third STP state")?.version,
        "Rstp"
    );
    assert_eq!(
        interface.stp.get(3).ok_or("fourth STP state")?.version,
        "Stp"
    );
    assert_eq!(
        report
            .evidence
            .iter()
            .map(|evidence| evidence.sequence)
            .collect::<Vec<_>>(),
        [1, 3, 4, 5, 7]
    );
    Ok(())
}
