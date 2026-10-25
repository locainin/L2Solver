use l2_audit::{Policy, ResourceLimit, Survey, SurveyLimits};
use l2_capture::{CaptureMetadata, CapturedFrame, InterfaceId};

fn captured(bytes: Vec<u8>) -> Result<CapturedFrame, Box<dyn std::error::Error>> {
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

fn ethernet(source: [u8; 6], field: u16, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 6];
    bytes.extend_from_slice(&source);
    bytes.extend_from_slice(&field.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn tagged(source: [u8; 6], vlan: u16) -> Vec<u8> {
    let mut bytes = vec![0; 6];
    bytes.extend_from_slice(&source);
    bytes.extend_from_slice(&0x8100_u16.to_be_bytes());
    bytes.extend_from_slice(&vlan.to_be_bytes());
    bytes.extend_from_slice(&0x0800_u16.to_be_bytes());
    bytes
}

fn tlv(kind: u8, value: &[u8]) -> Vec<u8> {
    let length = u16::try_from(value.len()).unwrap_or_default();
    let mut bytes = ((u16::from(kind) << 9) | length).to_be_bytes().to_vec();
    bytes.extend_from_slice(value);
    bytes
}

fn lldp(chassis: u8, name: &[u8]) -> Vec<u8> {
    let mut payload = tlv(1, &[4, 0, 1, 2, 3, 4, chassis]);
    payload.extend(tlv(2, &[5, b'p', chassis]));
    payload.extend(tlv(3, &120_u16.to_be_bytes()));
    payload.extend(tlv(5, name));
    payload.extend_from_slice(&[0, 0]);
    let mut frame = ethernet([2, 0, 0, 0, 0, 1], 0x88cc, &payload);
    frame.resize(60, 0);
    frame
}

fn stp(root_suffix: u8) -> Vec<u8> {
    let mut bpdu = vec![0, 0, 0, 0, 0x81, 0x80, 0, 0, 1, 2, 3, 4, root_suffix];
    bpdu.extend_from_slice(&0_u32.to_be_bytes());
    bpdu.extend_from_slice(&[0x90, 0x02, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
    bpdu.extend_from_slice(&0x8001_u16.to_be_bytes());
    bpdu.extend_from_slice(&0x0100_u16.to_be_bytes());
    bpdu.extend_from_slice(&0x1400_u16.to_be_bytes());
    bpdu.extend_from_slice(&0x0200_u16.to_be_bytes());
    bpdu.extend_from_slice(&0x0f00_u16.to_be_bytes());
    let mut llc = vec![0x42, 0x42, 0x03];
    llc.extend(bpdu);
    let length = u16::try_from(llc.len()).unwrap_or_default();
    let mut frame = ethernet([2, 0, 0, 0, 0, 1], length, &llc);
    frame.resize(60, 0);
    frame
}

#[test]
fn inventory_limits_report_omitted_facts() -> Result<(), Box<dyn std::error::Error>> {
    let limits = SurveyLimits::default()
        .with_mac_facts(2)?
        .with_vlan_contexts(1)?
        .with_neighbors(1)?;
    let mut survey = Survey::with_limits(limits);
    for suffix in 1..=3 {
        survey.observe(&captured(ethernet([2, 0, 0, 0, 0, suffix], 0x0800, &[]))?)?;
    }
    survey.observe(&captured(tagged([2, 0, 0, 0, 0, 1], 10))?)?;
    survey.observe(&captured(tagged([2, 0, 0, 0, 0, 1], 20))?)?;
    survey.observe(&captured(lldp(1, b"first"))?)?;
    survey.observe(&captured(lldp(2, b"second"))?)?;

    let report = survey.finish(&Policy::default())?;
    let interface = report.interfaces.first().ok_or("interface")?;
    assert_eq!(report.quality.frames, 7);
    assert_eq!(interface.macs.len(), 2);
    assert_eq!(interface.vlans.len(), 1);
    assert_eq!(interface.neighbors.len(), 1);
    for limit in [
        ResourceLimit::MacFacts,
        ResourceLimit::VlanContexts,
        ResourceLimit::Neighbors,
    ] {
        assert!(report.resource_limits.is_reached(limit));
    }
    assert!(!report.collection_complete());
    Ok(())
}

#[test]
fn full_neighbor_table_identity_updates() -> Result<(), Box<dyn std::error::Error>> {
    let limits = SurveyLimits::default().with_neighbors(1)?;
    let mut survey = Survey::with_limits(limits);
    survey.observe(&captured(lldp(1, b"old"))?)?;
    survey.observe(&captured(lldp(1, b"new"))?)?;
    survey.observe(&captured(lldp(2, b"omitted"))?)?;

    let report = survey.finish(&Policy::default())?;
    let neighbors = &report.interfaces.first().ok_or("interface")?.neighbors;
    assert_eq!(neighbors.len(), 1);
    assert_eq!(neighbors.first().ok_or("neighbor")?.system_name, b"new");
    assert_eq!(neighbors.first().ok_or("neighbor")?.packet, 2);
    assert!(report.resource_limits.is_reached(ResourceLimit::Neighbors));
    Ok(())
}

#[test]
fn bounds_stp_without_losing_counts() -> Result<(), Box<dyn std::error::Error>> {
    let limits = SurveyLimits::default().with_stp_transitions(1)?;
    let mut survey = Survey::with_limits(limits);
    survey.observe(&captured(stp(1))?)?;
    survey.observe(&captured(stp(2))?)?;

    let report = survey.finish(&Policy::default())?;
    let interface = report.interfaces.first().ok_or("interface")?;
    assert_eq!(interface.stp_frames, 2);
    assert_eq!(interface.stp.len(), 1);
    assert!(
        report
            .resource_limits
            .is_reached(ResourceLimit::StpTransitions)
    );
    Ok(())
}

#[test]
fn validates_mac_fact_boundaries() {
    assert!(SurveyLimits::default().with_mac_facts(65_536).is_ok());
    assert!(SurveyLimits::default().with_mac_facts(65_537).is_err());
    assert!(SurveyLimits::default().with_mac_facts(0).is_err());
}

#[test]
fn validates_vlan_context_boundaries() {
    assert!(SurveyLimits::default().with_vlan_contexts(4_096).is_ok());
    assert!(SurveyLimits::default().with_vlan_contexts(4_097).is_err());
    assert!(SurveyLimits::default().with_vlan_contexts(0).is_err());
}

#[test]
fn validates_neighbor_boundaries() {
    assert!(SurveyLimits::default().with_neighbors(4_096).is_ok());
    assert!(SurveyLimits::default().with_neighbors(4_097).is_err());
    assert!(SurveyLimits::default().with_neighbors(0).is_err());
}

#[test]
fn validates_protocol_identity_boundaries() {
    assert!(
        SurveyLimits::default()
            .with_protocol_identities(65_536)
            .is_ok()
    );
    assert!(
        SurveyLimits::default()
            .with_protocol_identities(65_537)
            .is_err()
    );
    assert!(SurveyLimits::default().with_protocol_identities(0).is_err());
}

#[test]
fn validates_stp_transition_boundaries() {
    assert!(SurveyLimits::default().with_stp_transitions(10_000).is_ok());
    assert!(
        SurveyLimits::default()
            .with_stp_transitions(10_001)
            .is_err()
    );
    assert!(SurveyLimits::default().with_stp_transitions(0).is_err());
}

#[test]
fn validates_evidence_reference_boundaries() {
    assert!(
        SurveyLimits::default()
            .with_evidence_references(262_144)
            .is_ok()
    );
    assert!(
        SurveyLimits::default()
            .with_evidence_references(262_145)
            .is_err()
    );
    assert!(SurveyLimits::default().with_evidence_references(0).is_err());
}

#[test]
fn validates_embedded_packet_boundaries() {
    assert!(SurveyLimits::default().with_embedded_packets(4_096).is_ok());
    assert!(
        SurveyLimits::default()
            .with_embedded_packets(4_097)
            .is_err()
    );
    assert!(SurveyLimits::default().with_embedded_packets(0).is_err());
}

#[test]
fn validates_embedded_byte_boundaries() {
    assert!(
        SurveyLimits::default()
            .with_embedded_bytes(67_108_864)
            .is_ok()
    );
    assert!(
        SurveyLimits::default()
            .with_embedded_bytes(67_108_865)
            .is_err()
    );
    assert!(SurveyLimits::default().with_embedded_bytes(0).is_err());
}

#[test]
fn embedded_byte_limit_checks_boundary() -> Result<(), Box<dyn std::error::Error>> {
    let limits = SurveyLimits::default().with_embedded_bytes(14)?;
    let mut survey = Survey::with_limits(limits);
    survey.observe(&captured(ethernet([2, 0, 0, 0, 0, 1], 0x0800, &[]))?)?;
    survey.observe(&captured(ethernet([2, 0, 0, 0, 0, 2], 0x0800, &[]))?)?;

    let report = survey.finish(&Policy::default())?;
    assert_eq!(report.evidence.len(), 1);
    assert!(
        report
            .resource_limits
            .is_reached(ResourceLimit::EmbeddedBytes)
    );
    Ok(())
}

#[test]
fn survey_sorts_inventory_before_export() -> Result<(), Box<dyn std::error::Error>> {
    let mut survey = Survey::new();
    survey.observe(&captured(ethernet([2, 0, 0, 0, 0, 2], 0x0800, &[]))?)?;
    survey.observe(&captured(ethernet([2, 0, 0, 0, 0, 1], 0x0800, &[]))?)?;
    let report = survey.finish(&Policy::default())?;
    let interface = report.interfaces.first().ok_or("missing interface")?;
    assert_eq!(
        interface.macs,
        vec![
            String::from("02:00:00:00:00:01"),
            String::from("02:00:00:00:00:02"),
        ]
    );
    Ok(())
}
