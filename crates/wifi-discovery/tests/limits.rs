use wifi_discovery::{ObservationContext, ObservationStatus, Survey, SurveyLimits, WirelessInput};

fn malformed_security_beacon() -> Vec<u8> {
    let bssid = [0x02, 0, 0, 0, 0, 1];
    let mut frame = Vec::from(0x0080_u16.to_le_bytes());
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&[0xff; 6]);
    frame.extend_from_slice(&bssid);
    frame.extend_from_slice(&bssid);
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&0_u64.to_le_bytes());
    frame.extend_from_slice(&100_u16.to_le_bytes());
    frame.extend_from_slice(&0x0010_u16.to_le_bytes());
    frame.extend_from_slice(&[48, 2, 1, 0]);
    frame
}

#[test]
fn exhausted_diagnostic_budget_is_reported() -> Result<(), Box<dyn std::error::Error>> {
    let mut survey = Survey::new(SurveyLimits::new(1, 1, 1, 1)?)?;
    let frame = malformed_security_beacon();

    assert_eq!(
        survey.observe(
            WirelessInput::Ieee80211(&frame),
            ObservationContext::new(1, 10),
        ),
        ObservationStatus::Malformed
    );
    assert_eq!(
        survey.observe(
            WirelessInput::Ieee80211(&frame),
            ObservationContext::new(2, 20),
        ),
        ObservationStatus::ResourceLimited
    );
    assert!(survey.inventory_incomplete());
    assert_eq!(survey.diagnostics().len(), 1);
    Ok(())
}
