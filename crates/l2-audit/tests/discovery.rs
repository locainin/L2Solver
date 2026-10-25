use l2_audit::{CoverageStatus, FingerprintStatus, Policy, Protocol, Survey};
use l2_capture::{CaptureMetadata, CapturedFrame, InterfaceId};

fn captured(payload: &[u8]) -> Result<CapturedFrame, Box<dyn std::error::Error>> {
    let mut bytes = Vec::with_capacity(14 + payload.len());
    bytes.extend_from_slice(&[0x01, 0x80, 0xc2, 0, 0, 3]);
    bytes.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    bytes.extend_from_slice(&0x888e_u16.to_be_bytes());
    bytes.extend_from_slice(payload);
    let original_len = u32::try_from(bytes.len())?;
    Ok(CapturedFrame::new(
        bytes,
        CaptureMetadata::unknown(
            InterfaceId {
                section: 0,
                index: 0,
            },
            original_len,
        ),
    )?)
}

fn tagged_eapol() -> Result<CapturedFrame, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&[0x01, 0x80, 0xc2, 0, 0, 3]);
    bytes.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    bytes.extend_from_slice(&0x88a8_u16.to_be_bytes());
    bytes.extend_from_slice(&0x0064_u16.to_be_bytes());
    bytes.extend_from_slice(&0x8100_u16.to_be_bytes());
    bytes.extend_from_slice(&0xa014_u16.to_be_bytes());
    bytes.extend_from_slice(&0x888e_u16.to_be_bytes());
    bytes.extend_from_slice(&[2, 0, 0, 0]);
    let original_len = u32::try_from(bytes.len())?;
    Ok(CapturedFrame::new(
        bytes,
        CaptureMetadata::unknown(
            InterfaceId {
                section: 0,
                index: 0,
            },
            original_len,
        ),
    )?)
}

#[test]
fn fingerprint_drives_inventory_and_planning() -> Result<(), Box<dyn std::error::Error>> {
    let mut survey = Survey::new();
    survey.observe(&captured(&[2, 0, 0, 0])?)?;
    let report = survey.finish(&Policy::default())?;
    let protocol = report
        .interfaces
        .first()
        .and_then(|interface| interface.protocols.first())
        .ok_or("missing EAPOL observation")?;

    assert_eq!(protocol.protocol, Protocol::Eapol);
    assert_eq!(protocol.status, FingerprintStatus::Observed);
    assert_eq!(protocol.frames, 1);
    assert_eq!(protocol.packet, 1);
    assert!(
        report
            .plan
            .recommendations
            .iter()
            .any(|row| row.check_id == "DOT1X-001")
    );
    assert!(
        report
            .coverage
            .iter()
            .any(|row| { row.check_id == "DOT1X-001" && row.status == CoverageStatus::NotTested })
    );
    Ok(())
}

#[test]
fn malformed_fingerprint_no_check() -> Result<(), Box<dyn std::error::Error>> {
    let mut survey = Survey::new();
    survey.observe(&captured(&[0, 0, 0, 0])?)?;
    let report = survey.finish(&Policy::default())?;
    let protocol = report
        .interfaces
        .first()
        .and_then(|interface| interface.protocols.first())
        .ok_or("missing malformed EAPOL observation")?;

    assert_eq!(protocol.status, FingerprintStatus::Malformed);
    assert_eq!(report.quality.invalid, 1);
    assert!(
        report.coverage.iter().any(|row| {
            row.check_id == "DOT1X-001" && row.status == CoverageStatus::NotApplicable
        })
    );
    Ok(())
}

#[test]
fn counts_protocol_status_without_duplicates() -> Result<(), Box<dyn std::error::Error>> {
    let mut survey = Survey::new();
    let packet = captured(&[2, 0, 0, 0])?;
    survey.observe(&packet)?;
    survey.observe(&packet)?;
    let report = survey.finish(&Policy::default())?;
    let interface = report.interfaces.first().ok_or("missing interface")?;

    assert_eq!(interface.protocols.len(), 1);
    assert_eq!(
        interface
            .protocols
            .first()
            .ok_or("missing protocol")?
            .frames,
        2
    );
    assert_eq!(report.evidence_refs.len(), 1);
    Ok(())
}

#[test]
fn protocol_identity_retains_vlan_context() -> Result<(), Box<dyn std::error::Error>> {
    let mut survey = Survey::new();
    survey.observe(&tagged_eapol()?)?;
    let report = survey.finish(&Policy::default())?;
    let identity = report
        .interfaces
        .first()
        .and_then(|interface| interface.identities.first())
        .ok_or("missing tagged EAPOL identity")?;

    assert_eq!(identity.protocol, Protocol::Eapol);
    assert_eq!(identity.source_mac, "02:00:00:00:00:01");
    assert_eq!(identity.vlan_tags, [(0x88a8, 100), (0x8100, 0xa014)]);
    assert_eq!(report.network_model.nodes.len(), 1);
    assert_eq!(
        report
            .network_model
            .nodes
            .first()
            .ok_or("missing network node")?
            .vlan_contexts,
        [vec![(0x88a8, 100), (0x8100, 0xa014)]]
    );
    Ok(())
}
