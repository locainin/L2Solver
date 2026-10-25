use super::common::{ethernet_frame, frame};
use l2_audit::{Policy, ResourceLimit, Survey};
use l2_capture::{CaptureMetadata, CapturedFrame, InterfaceId, LinuxInterfaceIdentity};

#[test]
fn evidence_limit_preserves_inventory() -> Result<(), Box<dyn std::error::Error>> {
    let mut survey = Survey::new();
    for source in 0_u16..256 {
        let mut bytes = vec![0; 12];
        bytes
            .get_mut(10..12)
            .ok_or("MAC range")?
            .copy_from_slice(&source.to_be_bytes());
        // A private EtherType keeps this evidence-budget fixture independent of IP parsing
        bytes.extend_from_slice(&[0x88, 0xb5]);
        survey.observe(&frame(bytes, 14)?)?;
    }
    let mut bytes = vec![0; 12];
    bytes
        .get_mut(10..12)
        .ok_or("MAC range")?
        .copy_from_slice(&256_u16.to_be_bytes());
    bytes.extend_from_slice(&[0x88, 0xb5]);
    let packet = frame(bytes, 14)?;
    survey.observe(&packet)?;
    let report = survey.finish(&Policy::default())?;

    assert_eq!(
        report.interfaces.first().ok_or("interface")?.macs.len(),
        257
    );
    assert_eq!(report.evidence_refs.len(), 257);
    assert_eq!(report.evidence.len(), 256);
    assert!(
        report
            .resource_limits
            .is_reached(ResourceLimit::EmbeddedPackets)
    );
    assert!(
        !report
            .resource_limits
            .is_reached(ResourceLimit::EvidenceReferences)
    );
    assert!(report.collection_complete());
    Ok(())
}

#[test]
fn evidence_reference_linux_interface_provenance() -> Result<(), Box<dyn std::error::Error>> {
    let identity = LinuxInterfaceIdentity::new(11, 12, 13, 14, 15)?;
    let bytes = ethernet_frame([0xff; 6], [0x02, 0, 0, 0, 0, 1], 0x0800, &[0; 20]);
    let original_len = u32::try_from(bytes.len())?;
    let metadata = CaptureMetadata::unknown(
        InterfaceId {
            section: 0,
            index: 0,
        },
        original_len,
    )
    .with_linux_interface(identity);
    let packet = CapturedFrame::new(bytes, metadata)?;
    let mut survey = Survey::new();

    survey.observe(&packet)?;
    let report = survey.finish(&Policy::default())?;
    let evidence = report.evidence_refs.first().ok_or("missing evidence")?;
    let source = evidence
        .linux_interface
        .as_ref()
        .ok_or("missing Linux source identity")?;

    assert_eq!(source.namespace_device, 11);
    assert_eq!(source.namespace_inode, 12);
    assert_eq!(source.interface_device, 13);
    assert_eq!(source.interface_inode, 14);
    assert_eq!(source.ifindex, 15);
    Ok(())
}
