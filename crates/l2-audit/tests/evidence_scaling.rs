use l2_audit::{EvidenceLocator, Policy, ResourceLimit, Survey, SurveyLimits};
use l2_capture::{CaptureMetadata, CapturedFrame, InterfaceId};

fn ethernet_frame(source_suffix: u16) -> Result<CapturedFrame, Box<dyn std::error::Error>> {
    let [high, low] = source_suffix.to_be_bytes();
    let mut bytes = vec![0; 10];
    bytes.extend_from_slice(&[high, low]);
    bytes.extend_from_slice(&0x0800_u16.to_be_bytes());
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
fn keeps_collecting_after_evidence_saturation() -> Result<(), Box<dyn std::error::Error>> {
    let limits = SurveyLimits::default().with_evidence_references(2)?;
    let mut survey = Survey::with_limits(limits);
    for suffix in 1..=3 {
        survey.observe(&ethernet_frame(suffix)?)?;
    }

    let report = survey.finish(&Policy::default())?;
    assert_eq!(
        report
            .interfaces
            .first()
            .ok_or("missing interface")?
            .macs
            .len(),
        3
    );
    assert_eq!(report.evidence_refs.len(), 2);
    assert!(
        report
            .resource_limits
            .is_reached(ResourceLimit::EvidenceReferences)
    );
    assert!(!report.collection_complete());
    Ok(())
}

#[test]
fn evidence_reference_preserves_capture_location() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = include_bytes!("../../../tests/pcaps/lldp.pcap");
    let mut reader = l2_pcap::CaptureReader::new(bytes.as_slice())?;
    let packet = reader.next_packet()?.ok_or("missing packet")?;
    let mut survey = Survey::new();
    survey.observe(&packet)?;
    let report = survey.finish(&Policy::default())?;
    let reference = report.evidence_refs.first().ok_or("missing reference")?;

    assert_eq!(
        reference.locator,
        EvidenceLocator::ClassicPcap {
            record_offset: 24,
            data_offset: 40,
        }
    );
    Ok(())
}

#[test]
fn keeps_inventory_after_embedded_limit() -> Result<(), Box<dyn std::error::Error>> {
    let mut survey = Survey::new();
    for suffix in 0..300 {
        survey.observe(&ethernet_frame(suffix)?)?;
    }

    let report = survey.finish(&Policy::default())?;
    let interface = report.interfaces.first().ok_or("missing interface")?;
    assert_eq!(interface.macs.len(), 300);
    assert_eq!(report.evidence_refs.len(), 300);
    assert_eq!(report.evidence.len(), 256);

    let first = report.evidence_refs.first().ok_or("missing reference")?;
    assert_eq!(first.sequence, 1);
    assert_eq!(first.captured_len, 14);
    assert_eq!(
        first.sha256,
        "76d386fb5a6b4fde582c81dc9860611ce02cf18afb4566c14dac1c7566b0dae5"
    );

    let last = report
        .evidence_refs
        .last()
        .ok_or("missing last reference")?;
    assert_eq!(last.sequence, 300);
    assert!(
        report
            .evidence
            .iter()
            .all(|embedded| embedded.sequence != last.sequence)
    );
    Ok(())
}

#[test]
fn default_embedded_byte_budget() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = vec![0; 12];
    bytes.extend_from_slice(&0x0800_u16.to_be_bytes());
    bytes.resize(3_000, 0);
    let original_len = u32::try_from(bytes.len())?;
    let packet = CapturedFrame::new(
        bytes,
        CaptureMetadata::unknown(
            InterfaceId {
                section: 0,
                index: 0,
            },
            original_len,
        ),
    )?;
    let mut survey = Survey::new();
    survey.observe(&packet)?;
    let report = survey.finish(&Policy::default())?;
    assert_eq!(report.evidence.len(), 1);
    assert!(
        !report
            .resource_limits
            .is_reached(ResourceLimit::EmbeddedBytes)
    );
    Ok(())
}
