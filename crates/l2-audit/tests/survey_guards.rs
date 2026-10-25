use l2_audit::{FingerprintStatus, Policy, Protocol, ResourceLimit, Survey};
use l2_capture::{CaptureMetadata, CapturedFrame, InterfaceId};

const SOURCE: [u8; 6] = [0x02, 0, 0, 0, 0, 1];
const DESTINATION: [u8; 6] = [0x01, 0x80, 0xc2, 0, 0, 3];

fn ethernet(field: u16, payload: &[u8]) -> Result<CapturedFrame, Box<dyn std::error::Error>> {
    let mut bytes = Vec::with_capacity(14 + payload.len());
    bytes.extend_from_slice(&DESTINATION);
    bytes.extend_from_slice(&SOURCE);
    bytes.extend_from_slice(&field.to_be_bytes());
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

fn eapol(version: u8) -> Result<CapturedFrame, Box<dyn std::error::Error>> {
    ethernet(0x888e, &[version, 0, 0, 0])
}

fn truncated_eapol() -> Result<CapturedFrame, Box<dyn std::error::Error>> {
    ethernet(0x888e, &[1, 0, 0, 4])
}

fn arp(sender_octet: u8) -> Result<CapturedFrame, Box<dyn std::error::Error>> {
    let mut payload = vec![0, 1, 0x08, 0, 6, 4, 0, 1];
    payload.extend_from_slice(&SOURCE);
    payload.extend_from_slice(&[192, 0, 2, sender_octet]);
    payload.extend_from_slice(&[0; 6]);
    payload.extend_from_slice(&[192, 0, 2, 1]);
    ethernet(0x0806, &payload)
}

#[test]
fn keeps_second_protocol_observation() -> Result<(), Box<dyn std::error::Error>> {
    let mut survey = Survey::new();
    survey.observe(&eapol(1)?)?;
    survey.observe(&eapol(4)?)?;
    let report = survey.finish(&Policy::default())?;
    let interface = report.interfaces.first().ok_or("missing interface")?;

    assert_eq!(interface.protocols.len(), 2);
    assert!(interface.protocols.iter().any(|observation| {
        observation.protocol == Protocol::Eapol
            && observation.status == FingerprintStatus::Observed
            && observation.packet == 1
    }));
    assert!(interface.protocols.iter().any(|observation| {
        observation.protocol == Protocol::Eapol
            && observation.status == FingerprintStatus::Unsupported
            && observation.packet == 2
    }));
    assert_eq!(report.evidence_refs.len(), 2);
    assert_eq!(report.quality.unsupported_fingerprints, 1);
    Ok(())
}

#[test]
fn keeps_new_protocol_evidence() -> Result<(), Box<dyn std::error::Error>> {
    let mut survey = Survey::new();
    survey.observe(&arp(10)?)?;
    survey.observe(&arp(11)?)?;
    let report = survey.finish(&Policy::default())?;
    let interface = report.interfaces.first().ok_or("missing interface")?;

    assert_eq!(interface.identities.len(), 2);
    assert_eq!(
        interface.identities.first().map(|identity| identity.packet),
        Some(1)
    );
    assert_eq!(
        interface.identities.get(1).map(|identity| identity.packet),
        Some(2)
    );
    assert_eq!(report.evidence_refs.len(), 2);
    Ok(())
}

#[test]
fn fingerprints_update_quality_counters() -> Result<(), Box<dyn std::error::Error>> {
    let mut survey = Survey::new();
    survey.observe(&eapol(1)?)?;
    survey.observe(&truncated_eapol()?)?;
    survey.observe(&eapol(4)?)?;
    let report = survey.finish(&Policy::default())?;

    assert_eq!(report.quality.malformed, 1);
    assert_eq!(report.quality.unsupported_fingerprints, 1);
    assert!(!report.resource_limits.is_reached(ResourceLimit::MacFacts));
    Ok(())
}
