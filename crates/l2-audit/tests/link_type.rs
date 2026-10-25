use l2_capture::{CaptureMetadata, CapturedFrame, Direction, FcsStatus, InterfaceId, LinkType};

#[test]
fn non_ethernet_frames_are_unsupported() -> Result<(), Box<dyn std::error::Error>> {
    let metadata = CaptureMetadata::new(
        InterfaceId {
            section: 0,
            index: 0,
        },
        14,
        None,
        None,
        Direction::Unknown,
        None,
        FcsStatus::Unknown,
    )
    .with_link_type(LinkType::Ieee80211);
    let frame = CapturedFrame::new(vec![0xff; 14], metadata)?;
    let mut survey = l2_audit::Survey::new();
    survey.observe(&frame)?;
    let report = survey.finish(&l2_audit::Policy::default())?;

    assert_eq!(report.quality.frames, 1);
    assert_eq!(report.quality.unsupported_link_types, 1);
    assert_eq!(report.quality.malformed, 0);
    assert!(report.interfaces.first().is_some_and(|interface| {
        interface.frames == 1 && interface.macs.is_empty() && interface.protocols.is_empty()
    }));
    assert!(!report.quality.clean());
    Ok(())
}

#[test]
fn retains_truncation_unsupported_link_type() -> Result<(), Box<dyn std::error::Error>> {
    let metadata = CaptureMetadata::new(
        InterfaceId {
            section: 0,
            index: 0,
        },
        15,
        None,
        None,
        Direction::Unknown,
        None,
        FcsStatus::Unknown,
    )
    .with_link_type(LinkType::Ieee80211Radiotap);
    let frame = CapturedFrame::new(vec![0xff; 14], metadata)?;
    let mut survey = l2_audit::Survey::new();
    survey.observe(&frame)?;
    let report = survey.finish(&l2_audit::Policy::default())?;

    assert_eq!(report.quality.unsupported_link_types, 1);
    assert_eq!(report.quality.truncated, 1);
    Ok(())
}
