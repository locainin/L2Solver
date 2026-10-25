#[path = "survey/common.rs"]
mod common;
#[path = "regressions/fixtures.rs"]
mod fixtures;

use wifi_discovery::{ObservationStatus, Survey, SurveyLimits, WirelessInput};

use common::{AP, STATION, assert_status, context};
use fixtures::{beacon, beacon_frame, radiotap_at, radiotap_with_flags};

fn management_frame(
    subtype: u16,
    receiver: [u8; 6],
    transmitter: [u8; 6],
    bssid: [u8; 6],
    body: &[u8],
) -> Vec<u8> {
    let mut frame = Vec::from((subtype << 4).to_le_bytes());
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&receiver);
    frame.extend_from_slice(&transmitter);
    frame.extend_from_slice(&bssid);
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(body);
    frame
}

#[test]
fn truncated_fcs_keeps_wire_body() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = radiotap_with_flags(&beacon(), 0x10);
    // The original record carried four FCS octets that snaplen omitted
    input.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    let retained_length = input.len().checked_sub(4).ok_or("frame is too short")?;
    input.truncate(retained_length);
    let mut survey = Survey::new(SurveyLimits::default())?;

    let status = survey.observe(
        WirelessInput::Radiotap(&input),
        context(200).with_capture_truncated(true),
    );
    assert_eq!(status, ObservationStatus::Incomplete);

    let access_point = survey
        .access_points()
        .next()
        .ok_or("missing access point")?;
    assert_eq!(access_point.bssid().octets(), AP);
    assert_eq!(access_point.ssid(), Some(b"Corp".as_slice()));
    assert_eq!(access_point.channel(), Some(6));
    assert_eq!(access_point.frequency_mhz(), Some(2_437));
    assert_eq!(survey.diagnostics().len(), 1);
    Ok(())
}

mod management_address_roles {
    use super::*;

    #[test]
    fn association_response_tracks_client_bssid() -> Result<(), Box<dyn std::error::Error>> {
        let frame = management_frame(1, STATION, AP, AP, &[0x10, 0, 0, 0, 1, 0]);
        let mut survey = Survey::new(SurveyLimits::default())?;

        assert_status(
            &mut survey,
            WirelessInput::Ieee80211(&frame),
            201,
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
        assert!(!station.association_changed());
        assert_eq!(survey.stations().len(), 1);
        Ok(())
    }

    #[test]
    fn ap_deauthentication_tracks_client() -> Result<(), Box<dyn std::error::Error>> {
        let frame = management_frame(12, STATION, AP, AP, &[3, 0]);
        let mut survey = Survey::new(SurveyLimits::default())?;

        assert_status(
            &mut survey,
            WirelessInput::Ieee80211(&frame),
            202,
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
        assert_eq!(survey.stations().len(), 1);
        Ok(())
    }

    #[test]
    fn client_authentication_tracks_ap() -> Result<(), Box<dyn std::error::Error>> {
        let frame = management_frame(11, AP, STATION, AP, &[0, 0, 1, 0, 0, 0]);
        let mut survey = Survey::new(SurveyLimits::default())?;

        assert_status(
            &mut survey,
            WirelessInput::Ieee80211(&frame),
            204,
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
        assert!(!station.association_changed());
        assert_eq!(survey.stations().len(), 1);
        Ok(())
    }
}

#[test]
fn channel_mismatch_noncanonical_both_sources() -> Result<(), Box<dyn std::error::Error>> {
    let frame = beacon_frame(AP, b"Corp", 0, None, &[3, 1, 1]);
    let input = radiotap_at(&frame, 5_180);
    let mut survey = Survey::new(SurveyLimits::default())?;

    assert_status(
        &mut survey,
        WirelessInput::Radiotap(&input),
        203,
        ObservationStatus::NonCanonical,
    );

    let access_point = survey
        .access_points()
        .next()
        .ok_or("missing access point")?;
    assert_eq!(access_point.channel(), Some(1));
    assert_eq!(access_point.frequency_mhz(), Some(5_180));
    let diagnostic = survey.diagnostics().first().ok_or("missing diagnostic")?;
    assert!(diagnostic.message().contains("advertised channel 1"));
    assert!(diagnostic.message().contains("radiotap channel 36"));
    Ok(())
}
