use l2_audit::{Policy, ResourceLimit, Survey, SurveyLimits};
use l2_capture::{CaptureMetadata, CapturedFrame, InterfaceId};
use l2_discovery::{IdentityRole, NetworkAddress, Protocol};

fn arp_frame(
    outer_source: [u8; 6],
    claimed_source: [u8; 6],
    address: [u8; 4],
) -> Result<CapturedFrame, Box<dyn std::error::Error>> {
    let mut bytes = vec![0xff; 6];
    bytes.extend_from_slice(&outer_source);
    bytes.extend_from_slice(&0x0806_u16.to_be_bytes());
    bytes.extend_from_slice(&[0, 1, 0x08, 0, 6, 4, 0, 2]);
    bytes.extend_from_slice(&claimed_source);
    bytes.extend_from_slice(&address);
    bytes.extend_from_slice(&[0; 6]);
    bytes.extend_from_slice(&[192, 0, 2, 1]);
    let metadata = CaptureMetadata::unknown(
        InterfaceId {
            section: 0,
            index: 0,
        },
        u32::try_from(bytes.len())?,
    );
    Ok(CapturedFrame::new(bytes, metadata)?)
}

#[test]
fn retains_bounded_identity_claims() -> Result<(), Box<dyn std::error::Error>> {
    let outer = [0x02, 0, 0, 0, 0, 1];
    let claimed = [0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];
    let packet = arp_frame(outer, claimed, [192, 0, 2, 7])?;
    let mut survey = Survey::new();
    survey.observe(&packet)?;
    survey.observe(&packet)?;

    let report = survey.finish(&Policy::default())?;
    let interface = report.interfaces.first().ok_or("missing interface")?;
    let identity = interface.identities.first().ok_or("missing identity")?;

    assert_eq!(identity.protocol, Protocol::Arp);
    assert_eq!(identity.role, IdentityRole::AddressClaim);
    assert_eq!(identity.source_mac, "02:00:00:00:00:01");
    assert_eq!(identity.claimed_mac.as_deref(), Some("00:aa:bb:cc:dd:ee"));
    assert_eq!(identity.address, Some(NetworkAddress::Ipv4([192, 0, 2, 7])));
    assert_eq!(identity.frames, 2);
    assert_eq!(identity.packet, 1);
    Ok(())
}

#[test]
fn zero_sender_never_arp_conflicts() -> Result<(), Box<dyn std::error::Error>> {
    let mut survey = Survey::new();
    for suffix in [1, 2] {
        let mac = [2, 0, 0, 0, 0, suffix];
        survey.observe(&arp_frame(mac, mac, [0; 4])?)?;
    }
    let report = survey.finish(&Policy::default())?;
    assert_eq!(
        report.network_model.address_conflicts,
        [] as [l2_audit::AddressConflict; 0]
    );
    assert!(
        !report
            .exposures
            .iter()
            .any(|exposure| exposure.check_id == "ARP-CONFLICT-001")
    );
    Ok(())
}

#[test]
fn identity_limit_marks_inventory_incomplete() -> Result<(), Box<dyn std::error::Error>> {
    let limits = SurveyLimits::default().with_protocol_identities(1)?;
    let mut survey = Survey::with_limits(limits);
    survey.observe(&arp_frame(
        [0x02, 0, 0, 0, 0, 1],
        [0x02, 0, 0, 0, 0, 1],
        [192, 0, 2, 1],
    )?)?;
    survey.observe(&arp_frame(
        [0x02, 0, 0, 0, 0, 2],
        [0x02, 0, 0, 0, 0, 2],
        [192, 0, 2, 2],
    )?)?;

    let report = survey.finish(&Policy::default())?;
    let interface = report.interfaces.first().ok_or("missing interface")?;
    assert_eq!(report.quality.frames, 2);
    assert_eq!(interface.identities.len(), 1);
    assert!(
        report
            .resource_limits
            .is_reached(ResourceLimit::ProtocolIdentities)
    );
    assert!(!report.collection_complete());
    Ok(())
}
