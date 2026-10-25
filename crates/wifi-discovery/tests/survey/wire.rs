use wifi_discovery::{ObservationStatus, SecurityMode, Survey, SurveyLimits, WirelessInput};

use super::common::{AP, STATION, assert_status};
use super::frames::{association, beacon_frame, radiotap_at};

#[test]
fn zero_length_psdu_is_valid() -> Result<(), Box<dyn std::error::Error>> {
    // The radiotap length and zero-length PSDU are deliberately raw bytes
    let mut bytes = vec![0, 0, 9, 0];
    bytes.extend_from_slice(&(1_u32 << 26).to_le_bytes());
    bytes.push(1);
    let mut survey = Survey::new(SurveyLimits::default())?;

    assert_status(
        &mut survey,
        WirelessInput::Radiotap(&bytes),
        70,
        ObservationStatus::Observed,
    );
    assert!(survey.diagnostics().is_empty());
    Ok(())
}

#[test]
fn zero_length_psdu_payload_noncanonical() -> Result<(), Box<dyn std::error::Error>> {
    // A payload after a zero-length PSDU is a non-canonical capture
    let mut bytes = vec![0, 0, 9, 0];
    bytes.extend_from_slice(&(1_u32 << 26).to_le_bytes());
    bytes.extend_from_slice(&[1, 0x08, 0x00]);
    let mut survey = Survey::new(SurveyLimits::default())?;

    assert_status(
        &mut survey,
        WirelessInput::Radiotap(&bytes),
        71,
        ObservationStatus::NonCanonical,
    );
    assert_eq!(survey.diagnostics().len(), 1);
    Ok(())
}

#[test]
fn malformed_management_keeps_identity() -> Result<(), Box<dyn std::error::Error>> {
    // The malformed element follows a complete management header and BSSID
    let frame = beacon_frame(AP, b"", 0, None, &[0, 5, b'a']);
    let mut survey = Survey::new(SurveyLimits::default())?;

    assert_status(
        &mut survey,
        WirelessInput::Ieee80211(&frame),
        100,
        ObservationStatus::Malformed,
    );
    let access_point = survey
        .access_points()
        .next()
        .ok_or("missing access point")?;
    assert_eq!(access_point.bssid().octets(), AP);
    assert_eq!(access_point.security(), SecurityMode::Unknown);
    Ok(())
}

#[test]
fn management_correlates_station_and_bssid() -> Result<(), Box<dyn std::error::Error>> {
    let frame = association();
    let mut survey = Survey::new(SurveyLimits::default())?;

    assert_status(
        &mut survey,
        WirelessInput::Ieee80211(&frame),
        60,
        ObservationStatus::Observed,
    );
    let station = survey.stations().next().ok_or("missing station")?;
    assert_eq!(station.address().octets(), STATION);
    assert_eq!(
        station
            .associated_bssid()
            .map(wifi_core::MacAddress::octets),
        Some(AP)
    );
    Ok(())
}

#[test]
fn protected_management_keeps_transmitter() -> Result<(), Box<dyn std::error::Error>> {
    let mut frame = association();
    *frame.get_mut(1).ok_or("missing frame-control flags")? |= 0x40;
    let mut survey = Survey::new(SurveyLimits::default())?;

    assert_status(
        &mut survey,
        WirelessInput::Ieee80211(&frame),
        101,
        ObservationStatus::Protected,
    );
    let station = survey.stations().next().ok_or("missing station")?;
    assert_eq!(station.address().octets(), STATION);
    Ok(())
}

#[test]
fn invalid_ds_keeps_radiotap_channel() -> Result<(), Box<dyn std::error::Error>> {
    let frame = beacon_frame(AP, b"Corp", 0, None, &[3, 2, 6, 99]);
    let input = radiotap_at(&frame, 2_437);
    let mut survey = Survey::new(SurveyLimits::default())?;

    assert_status(
        &mut survey,
        WirelessInput::Radiotap(&input),
        102,
        ObservationStatus::NonCanonical,
    );
    let access_point = survey
        .access_points()
        .next()
        .ok_or("missing access point")?;
    assert_eq!(access_point.channel(), Some(6));
    assert_eq!(survey.diagnostics().len(), 1);
    Ok(())
}

#[test]
fn duplicate_ssid_elements_rejected_independent() -> Result<(), Box<dyn std::error::Error>> {
    let hidden_then_named = beacon_frame(
        [2, 0, 0, 0, 0, 20],
        b"",
        0,
        None,
        &[0, 4, b'C', b'o', b'r', b'p'],
    );
    let named_then_hidden = beacon_frame([2, 0, 0, 0, 0, 21], b"Corp", 0, None, &[0, 0]);
    let mut survey = Survey::new(SurveyLimits::default())?;

    assert_status(
        &mut survey,
        WirelessInput::Ieee80211(&hidden_then_named),
        104,
        ObservationStatus::NonCanonical,
    );
    assert_status(
        &mut survey,
        WirelessInput::Ieee80211(&named_then_hidden),
        105,
        ObservationStatus::NonCanonical,
    );
    assert!(
        survey
            .access_points()
            .all(|access_point| access_point.ssid().is_none())
    );
    Ok(())
}

#[test]
fn duplicate_ds_parameters_rejected_independent() -> Result<(), Box<dyn std::error::Error>> {
    let six_then_eleven = beacon_frame([2, 0, 0, 0, 0, 22], b"First", 0, Some(6), &[3, 1, 11]);
    let eleven_then_six = beacon_frame([2, 0, 0, 0, 0, 23], b"Second", 0, Some(11), &[3, 1, 6]);
    let mut survey = Survey::new(SurveyLimits::default())?;

    assert_status(
        &mut survey,
        WirelessInput::Ieee80211(&six_then_eleven),
        106,
        ObservationStatus::NonCanonical,
    );
    assert_status(
        &mut survey,
        WirelessInput::Ieee80211(&eleven_then_six),
        107,
        ObservationStatus::NonCanonical,
    );
    assert!(
        survey
            .access_points()
            .all(|access_point| access_point.channel().is_none())
    );
    Ok(())
}

#[test]
fn unsupported_radiotap_is_incomplete() -> Result<(), Box<dyn std::error::Error>> {
    let frame = beacon_frame(AP, b"Corp", 0, None, &[]);
    // Presence bit 16 advertises a field the bounded decoder does not support
    let presence = (1_u32 << 3) | (1_u32 << 16);
    let mut input = vec![0, 0, 12, 0];
    input.extend_from_slice(&presence.to_le_bytes());
    input.extend_from_slice(&2_437_u16.to_le_bytes());
    input.extend_from_slice(&0x00a0_u16.to_le_bytes());
    input.extend_from_slice(&frame);
    let mut survey = Survey::new(SurveyLimits::default())?;

    assert_status(
        &mut survey,
        WirelessInput::Radiotap(&input),
        103,
        ObservationStatus::NonCanonical,
    );
    assert_eq!(survey.access_points().len(), 1);
    assert_eq!(survey.diagnostics().len(), 1);
    Ok(())
}
