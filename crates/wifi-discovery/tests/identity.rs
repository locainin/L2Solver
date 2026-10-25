use wifi_discovery::{ObservationContext, ObservationStatus, Survey, SurveyLimits, WirelessInput};

fn from_ds_data(receiver: [u8; 6]) -> Vec<u8> {
    let mut frame = Vec::from(0x0208_u16.to_le_bytes());
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&receiver);
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]);
    frame.extend_from_slice(&[0, 0]);
    frame
}

fn beacon(bssid: [u8; 6]) -> Vec<u8> {
    let mut frame = Vec::from(0x0080_u16.to_le_bytes());
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&[0xff; 6]);
    frame.extend_from_slice(&bssid);
    frame.extend_from_slice(&bssid);
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&0_u64.to_le_bytes());
    frame.extend_from_slice(&100_u16.to_le_bytes());
    frame.extend_from_slice(&0_u16.to_le_bytes());
    frame
}

#[test]
fn group_destination_not_station() -> Result<(), Box<dyn std::error::Error>> {
    let mut survey = Survey::new(SurveyLimits::default())?;
    let frame = from_ds_data([0xff; 6]);

    assert_eq!(
        survey.observe(
            WirelessInput::Ieee80211(&frame),
            ObservationContext::new(1, 10),
        ),
        ObservationStatus::Observed
    );
    assert_eq!(survey.stations().len(), 0);
    Ok(())
}

#[test]
fn group_bssid_not_access_point() -> Result<(), Box<dyn std::error::Error>> {
    let mut survey = Survey::new(SurveyLimits::default())?;
    let frame = beacon([0xff; 6]);

    assert_eq!(
        survey.observe(
            WirelessInput::Ieee80211(&frame),
            ObservationContext::new(1, 10),
        ),
        ObservationStatus::NonCanonical
    );
    assert_eq!(survey.access_points().len(), 0);
    assert_eq!(survey.diagnostics().len(), 1);
    Ok(())
}
