use super::common::{LINUX_STP_PCAP, captured, ethernet_frame, frame, source_with_suffix};
use super::lldp::lldp_frame;
use l2_audit::{CoverageStatus, Policy, Survey, Verdict};
use l2_capture::{CaptureMetadata, CapturedFrame, InterfaceId};

#[test]
fn empty_survey_reports_untested_coverage() -> Result<(), Box<dyn std::error::Error>> {
    let report = Survey::new().finish(&Policy::default())?;
    assert!(!report.collection_complete());
    assert!(report.findings.iter().all(|f| f.verdict != Verdict::Pass));
    for id in ["SEG-001", "DOT1X-001"] {
        assert!(
            report
                .coverage
                .iter()
                .any(|entry| entry.check_id == id && entry.status != CoverageStatus::Tested)
        );
    }
    Ok(())
}

#[test]
fn truncated_advertisements_stay_unconfirmed() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = vec![0; 12];
    bytes.extend_from_slice(&[0x81, 0, 0, 20, 0x08, 0]);
    let mut survey = Survey::new();
    survey.observe(&frame(bytes, 60)?)?;
    let report = survey.finish(&Policy {
        allowed_vlans: Some(vec![]),
        ..Policy::default()
    })?;
    assert_eq!(report.quality.truncated, 1);
    assert!(report.findings.iter().all(|f| f.verdict != Verdict::Fail));
    assert!(
        report
            .interfaces
            .first()
            .ok_or("missing interface")?
            .vlans
            .is_empty()
    );
    Ok(())
}

#[test]
fn limits_and_loss_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let mut survey = Survey::new();
    for index in 0..64 {
        let packet = CapturedFrame::new(
            vec![],
            CaptureMetadata::unknown(InterfaceId { section: 0, index }, 0),
        )?;
        survey.observe(&packet)?;
    }
    let packet = CapturedFrame::new(
        vec![],
        CaptureMetadata::unknown(
            InterfaceId {
                section: 0,
                index: 64,
            },
            0,
        ),
    )?;
    assert!(survey.observe(&packet).is_err());
    assert!(survey.finish(&Policy::default()).is_err());
    let mut survey = Survey::new();
    survey.record_quality(14, true)?;
    let report = survey.finish(&Policy::default())?;
    assert_eq!(report.quality.dropped, 14);
    assert!(report.quality.incomplete);
    assert!(!report.quality.clean());
    assert!(report.coverage.iter().all(|entry| {
        entry.status != CoverageStatus::Tested
            || entry.reason.contains("capture quality is incomplete")
    }));
    let mut survey = Survey::new();
    survey.record_quality(u64::MAX, false)?;
    assert!(survey.record_quality(1, false).is_err());
    assert!(survey.finish(&Policy::default()).is_err());
    Ok(())
}

#[test]
fn reports_unsupported_stp() -> Result<(), Box<dyn std::error::Error>> {
    let mut reader = l2_pcap::CaptureReader::new(LINUX_STP_PCAP)?;
    let packet = reader.next_packet()?.ok_or("STP fixture")?;
    let mut bytes = packet.bytes().to_vec();
    *bytes.get_mut(19).ok_or("version")? = 3;
    let mut survey = Survey::new();
    survey.observe(&frame(bytes, u32::try_from(packet.bytes().len())?)?)?;
    let mut reader = l2_pcap::CaptureReader::new(LINUX_STP_PCAP)?;
    let second = reader.next_packet()?.ok_or("STP fixture")?;
    let mut second_bytes = second.bytes().to_vec();
    *second_bytes.get_mut(19).ok_or("version")? = 3;
    survey.observe(&captured(second_bytes)?)?;
    let report = survey.finish(&Policy::default())?;
    assert_eq!(report.quality.unsupported_stp, 2);
    assert!(!report.quality.clean());
    assert_eq!(report.evidence.len(), 1);
    Ok(())
}

#[test]
fn counts_invalid_and_malformed_frames() -> Result<(), Box<dyn std::error::Error>> {
    let mut survey = Survey::new();
    survey.observe(&captured(lldp_frame(
        0,
        [0, 1, 2, 3, 4, 5],
        b"port",
        b"bad",
    ))?)?;
    survey.observe(&captured(vec![0; 13])?)?;
    survey.observe(&captured(ethernet_frame(
        [0; 6],
        source_with_suffix(8),
        0x88cc,
        &[0],
    ))?)?;
    let mut reader = l2_pcap::CaptureReader::new(LINUX_STP_PCAP)?;
    let stp = reader.next_packet()?.ok_or("STP fixture")?;
    let mut malformed_stp = stp.bytes().to_vec();
    malformed_stp
        .get_mut(17..19)
        .ok_or("STP protocol identifier")?
        .copy_from_slice(&[0, 1]);
    survey.observe(&captured(malformed_stp)?)?;
    let report = survey.finish(&Policy::default())?;
    assert_eq!(report.quality.invalid, 1);
    assert_eq!(report.quality.malformed, 3);
    assert_eq!(report.quality.frames, 4);
    assert_eq!(report.interfaces.first().ok_or("interface")?.frames, 4);
    assert!(
        report
            .interfaces
            .first()
            .ok_or("interface")?
            .neighbors
            .is_empty()
    );
    let interface = report.interfaces.first().ok_or("interface")?;
    assert_eq!(interface.macs.len(), 3);
    assert_eq!(interface.untagged_packet, Some(1));
    assert_eq!(report.evidence.len(), 3);
    Ok(())
}

#[test]
fn large_frame_bounded_survey() -> Result<(), Box<dyn std::error::Error>> {
    const FRAME_COUNT: u64 = 1_000_001;

    let limits = l2_audit::SurveyLimits::default()
        .with_evidence_references(1)?
        .with_embedded_packets(1)?;
    let mut survey = Survey::with_limits(limits);
    let first = super::common::captured(super::common::ethernet_frame(
        [0xff; 6],
        super::common::source_with_suffix(1),
        0x88b5,
        &[],
    ))?;
    let repeated = super::common::captured(super::common::ethernet_frame(
        [0xff; 6],
        super::common::source_with_suffix(2),
        0x88b5,
        &[],
    ))?;

    survey.observe(&first)?;
    survey.observe(&repeated)?;
    for _ in 2..FRAME_COUNT {
        survey.observe(&repeated)?;
    }
    let report = survey.finish(&l2_audit::Policy::default())?;
    let interface = report.interfaces.first().ok_or("missing interface")?;

    assert_eq!(report.quality.frames, FRAME_COUNT);
    assert_eq!(interface.frames, FRAME_COUNT);
    assert_eq!(interface.macs.len(), 2);
    assert_eq!(report.evidence_refs.len(), 1);
    assert_eq!(report.evidence.len(), 1);
    assert!(
        report
            .resource_limits
            .is_reached(l2_audit::ResourceLimit::EvidenceReferences)
    );
    assert!(
        report
            .resource_limits
            .is_reached(l2_audit::ResourceLimit::EmbeddedPackets)
    );
    assert!(!report.collection_complete());
    Ok(())
}
