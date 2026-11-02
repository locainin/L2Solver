use wifi_discovery::{ObservationContext, ObservationStatus, Survey, SurveyLimits, WirelessInput};

use super::common::{AP, STATION, assert_status, context};
use super::frames::{beacon, beacon_frame, beacon_with_ssid, radiotap, radiotap_with_flags};

#[test]
fn beacon_builds_security_inventory() -> Result<(), Box<dyn std::error::Error>> {
    let mut survey = Survey::new(SurveyLimits::default())?;

    assert_status(
        &mut survey,
        WirelessInput::Radiotap(&radiotap(&beacon())),
        1,
        ObservationStatus::Observed,
    );
    let access_point = survey
        .access_points()
        .next()
        .ok_or("missing access point")?;
    assert_eq!(access_point.bssid().octets(), AP);
    assert_eq!(access_point.ssid(), Some(b"Corp".as_slice()));
    assert_eq!(access_point.channel(), Some(6));
    assert_eq!(access_point.frequency_mhz(), Some(2_437));
    assert_eq!(access_point.signal_dbm(), Some(-40));
    assert_eq!(
        access_point.security(),
        wifi_discovery::SecurityMode::Wpa2Wpa3PersonalTransition
    );
    assert!(!access_point.tkip());
    assert!(access_point.pmf_capable());
    assert!(access_point.wps());
    assert!(access_point.pmf_required());
    assert_eq!(access_point.first_sequence(), 1);
    assert_eq!(access_point.last_sequence(), 1);
    assert_eq!(access_point.frames(), 1);
    Ok(())
}

#[test]
fn older_observation_cannot_point_state() -> Result<(), Box<dyn std::error::Error>> {
    let newer = beacon_frame(AP, b"Current", 0, Some(6), &[]);
    let older = beacon_frame(AP, b"Stale", 0, Some(11), &[]);
    let mut survey = Survey::new(SurveyLimits::default())?;

    assert_eq!(
        survey.observe(WirelessInput::Ieee80211(&newer), context(100)),
        ObservationStatus::Observed
    );
    assert_eq!(
        survey.observe(WirelessInput::Ieee80211(&older), context(1)),
        ObservationStatus::NonCanonical
    );

    let access_point = survey
        .access_points()
        .next()
        .ok_or("missing access point")?;
    assert_eq!(access_point.ssid(), Some(b"Current".as_slice()));
    assert_eq!(access_point.channel(), Some(6));
    assert_eq!(access_point.first_sequence(), 100);
    assert_eq!(access_point.last_sequence(), 100);
    assert_eq!(access_point.frames(), 1);
    assert_eq!(survey.diagnostics().len(), 1);
    Ok(())
}

#[test]
fn regressing_monotonic_cannot_point_state() -> Result<(), Box<dyn std::error::Error>> {
    let current = beacon_frame(AP, b"Current", 0, Some(6), &[]);
    let regressed = beacon_frame(AP, b"Regressed", 0, Some(11), &[]);
    let mut survey = Survey::new(SurveyLimits::default())?;

    assert_eq!(
        survey.observe(
            WirelessInput::Ieee80211(&current),
            ObservationContext::new(1, 100),
        ),
        ObservationStatus::Observed
    );
    assert_eq!(
        survey.observe(
            WirelessInput::Ieee80211(&regressed),
            ObservationContext::new(2, 99),
        ),
        ObservationStatus::NonCanonical
    );

    let access_point = survey
        .access_points()
        .next()
        .ok_or("missing access point")?;
    assert_eq!(access_point.ssid(), Some(b"Current".as_slice()));
    assert_eq!(access_point.channel(), Some(6));
    assert_eq!(access_point.last_sequence(), 1);
    assert_eq!(access_point.frames(), 1);
    Ok(())
}

#[test]
fn timed_capture_sequence_zero_accepted() -> Result<(), Box<dyn std::error::Error>> {
    let frame = beacon_frame(AP, b"First", 0, Some(6), &[]);
    let mut survey = Survey::new(SurveyLimits::default())?;

    assert_eq!(
        survey.observe(
            WirelessInput::Ieee80211(&frame),
            ObservationContext::new(0, 100),
        ),
        ObservationStatus::Observed
    );
    assert_eq!(survey.access_points().count(), 1);
    assert_eq!(survey.diagnostics(), []);
    Ok(())
}

#[test]
fn duplicate_timed_not_mistaken_regression() -> Result<(), Box<dyn std::error::Error>> {
    let frame = beacon_frame(AP, b"Duplicate", 0, Some(6), &[]);
    let mut survey = Survey::new(SurveyLimits::default())?;
    let context = ObservationContext::new(0, 100);

    assert_eq!(
        survey.observe(WirelessInput::Ieee80211(&frame), context),
        ObservationStatus::Observed
    );
    assert_eq!(
        survey.observe(WirelessInput::Ieee80211(&frame), context),
        ObservationStatus::Observed
    );
    assert_eq!(survey.diagnostics().len(), 0);
    Ok(())
}

#[test]
fn later_timestamp_lower_source_sequence() -> Result<(), Box<dyn std::error::Error>> {
    let first = beacon_frame(AP, b"First", 0, Some(6), &[]);
    let later = beacon_frame(AP, b"Later", 0, Some(11), &[]);
    let mut survey = Survey::new(SurveyLimits::default())?;

    assert_eq!(
        survey.observe(
            WirelessInput::Ieee80211(&first),
            ObservationContext::new(100, 100),
        ),
        ObservationStatus::Observed
    );
    assert_eq!(
        survey.observe(
            WirelessInput::Ieee80211(&later),
            ObservationContext::new(1, 101),
        ),
        ObservationStatus::Observed
    );
    let access_point = survey
        .access_points()
        .next()
        .ok_or("missing access point")?;
    assert_eq!(access_point.channel(), Some(11));
    assert_eq!(access_point.last_sequence(), 1);
    Ok(())
}

#[test]
fn data_correlates_station_and_bssid() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = Vec::from(0x0108_u16.to_le_bytes());
    bytes.extend_from_slice(&[0, 0]);
    bytes.extend_from_slice(&AP);
    bytes.extend_from_slice(&STATION);
    bytes.extend_from_slice(&[0x10; 6]);
    bytes.extend_from_slice(&[0, 0, 1, 2]);
    let mut survey = Survey::new(SurveyLimits::default())?;

    assert_status(
        &mut survey,
        WirelessInput::Ieee80211(&bytes),
        3,
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
    assert_eq!(station.first_sequence(), 3);
    assert_eq!(station.last_sequence(), 3);
    assert_eq!(station.frames(), 1);

    assert_status(
        &mut survey,
        WirelessInput::Ieee80211(&bytes),
        4,
        ObservationStatus::Observed,
    );
    let station = survey.stations().next().ok_or("missing station")?;
    assert_eq!(station.last_sequence(), 4);
    assert_eq!(station.frames(), 2);
    Ok(())
}

#[test]
fn station_move_latest_bssid_drift() -> Result<(), Box<dyn std::error::Error>> {
    let mut first = Vec::from(0x0108_u16.to_le_bytes());
    first.extend_from_slice(&[0, 0]);
    first.extend_from_slice(&AP);
    first.extend_from_slice(&STATION);
    first.extend_from_slice(&[0x10; 6]);
    first.extend_from_slice(&[0, 0, 1, 2]);

    let moved_bssid = [0x02, 0, 0, 0, 0, 9];
    let mut moved = first.clone();
    moved
        .get_mut(4..10)
        .ok_or("missing first receiver")?
        .copy_from_slice(&moved_bssid);

    let mut survey = Survey::new(SurveyLimits::default())?;
    assert_status(
        &mut survey,
        WirelessInput::Ieee80211(&first),
        12,
        ObservationStatus::Observed,
    );
    assert_status(
        &mut survey,
        WirelessInput::Ieee80211(&moved),
        13,
        ObservationStatus::Observed,
    );

    let station = survey.stations().next().ok_or("missing station")?;
    assert_eq!(
        station
            .associated_bssid()
            .map(wifi_core::MacAddress::octets),
        Some(moved_bssid)
    );
    assert!(station.association_changed());
    assert_eq!(station.first_sequence(), 12);
    assert_eq!(station.last_sequence(), 13);
    assert_eq!(station.frames(), 2);

    // An observation without a BSSID must not erase the latest known association
    let mut probe = Vec::from(0x0040_u16.to_le_bytes());
    probe.extend_from_slice(&[0, 0]);
    probe.extend_from_slice(&[0xff; 6]);
    probe.extend_from_slice(&STATION);
    probe.extend_from_slice(&[0xff; 6]);
    probe.extend_from_slice(&[0, 0]);
    assert_status(
        &mut survey,
        WirelessInput::Ieee80211(&probe),
        14,
        ObservationStatus::Observed,
    );
    let station = survey.stations().next().ok_or("missing station")?;
    assert_eq!(
        station
            .associated_bssid()
            .map(wifi_core::MacAddress::octets),
        Some(moved_bssid)
    );
    assert!(station.association_changed());
    Ok(())
}

#[test]
fn malformed_radiotap_is_bounded() -> Result<(), Box<dyn std::error::Error>> {
    let mut survey = Survey::new(SurveyLimits::default())?;

    assert_status(
        &mut survey,
        WirelessInput::Radiotap(&[0, 0, 50, 0]),
        7,
        ObservationStatus::Malformed,
    );
    assert_eq!(survey.diagnostics().len(), 1);
    assert_eq!(
        survey
            .diagnostics()
            .first()
            .map(wifi_discovery::Diagnostic::sequence),
        Some(7)
    );
    assert_eq!(
        survey
            .diagnostics()
            .first()
            .map(wifi_discovery::Diagnostic::message),
        Some("truncated radiotap declared header: need 50 bytes, have 4")
    );
    Ok(())
}

#[test]
fn bad_fcs_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let mut survey = Survey::new(SurveyLimits::default())?;
    let bytes = radiotap_with_flags(&beacon(), 0x40);

    assert_status(
        &mut survey,
        WirelessInput::Radiotap(&bytes),
        8,
        ObservationStatus::Malformed,
    );
    assert_eq!(survey.access_points().len(), 0);
    assert_eq!(survey.diagnostics().len(), 1);
    Ok(())
}

#[test]
fn fcs_not_parsed_ie() -> Result<(), Box<dyn std::error::Error>> {
    let mut frame = beacon();
    frame.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    let bytes = radiotap_with_flags(&frame, 0x10);
    let mut survey = Survey::new(SurveyLimits::default())?;

    assert_status(
        &mut survey,
        WirelessInput::Radiotap(&bytes),
        9,
        ObservationStatus::Observed,
    );
    assert_eq!(survey.access_points().len(), 1);
    assert_eq!(survey.diagnostics(), []);
    Ok(())
}

#[test]
fn oversized_ssid_keeps_inventory() -> Result<(), Box<dyn std::error::Error>> {
    let frame = beacon_with_ssid(&[b'A'; 33]);
    let mut survey = Survey::new(SurveyLimits::default())?;

    assert_status(
        &mut survey,
        WirelessInput::Ieee80211(&frame),
        10,
        ObservationStatus::NonCanonical,
    );
    let access_point = survey
        .access_points()
        .next()
        .ok_or("missing access point")?;
    assert_eq!(access_point.bssid().octets(), AP);
    assert_eq!(access_point.ssid(), None);
    assert_eq!(survey.diagnostics().len(), 1);
    Ok(())
}

#[test]
fn no_ds_uses_third_address() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = Vec::from(0x0008_u16.to_le_bytes());
    bytes.extend_from_slice(&[0, 0]);
    bytes.extend_from_slice(&[0xff; 6]);
    bytes.extend_from_slice(&STATION);
    bytes.extend_from_slice(&AP);
    bytes.extend_from_slice(&[0, 0]);
    let mut survey = Survey::new(SurveyLimits::default())?;

    assert_status(
        &mut survey,
        WirelessInput::Ieee80211(&bytes),
        11,
        ObservationStatus::Observed,
    );
    let station = survey.stations().next().ok_or("missing station")?;
    assert_eq!(
        station
            .associated_bssid()
            .map(wifi_core::MacAddress::octets),
        Some(AP)
    );
    Ok(())
}

#[test]
fn inventory_limit_is_bounded() -> Result<(), Box<dyn std::error::Error>> {
    let limits = SurveyLimits::new(1, 4, 4, 4)?;
    let mut survey = Survey::new(limits)?;
    let first = beacon();
    survey.observe(WirelessInput::Ieee80211(&first), context(1));
    let mut second = beacon();
    second
        .get_mut(16..22)
        .ok_or("missing second BSSID")?
        .copy_from_slice(&[0x02, 0, 0, 0, 0, 9]);

    assert_status(
        &mut survey,
        WirelessInput::Ieee80211(&second),
        2,
        ObservationStatus::ResourceLimited,
    );
    assert_eq!(survey.access_points().len(), 1);
    assert!(survey.inventory_incomplete());
    Ok(())
}

#[test]
fn conflicting_ap_identity_remains_visible() -> Result<(), Box<dyn std::error::Error>> {
    let first = beacon_frame(AP, b"Corp", 0, Some(6), &[]);
    let changed = beacon_frame(AP, b"Guest", 0, Some(11), &[]);
    let mut survey = Survey::new(SurveyLimits::default())?;

    assert_status(
        &mut survey,
        WirelessInput::Ieee80211(&first),
        1,
        ObservationStatus::Observed,
    );
    assert_status(
        &mut survey,
        WirelessInput::Ieee80211(&changed),
        2,
        ObservationStatus::Observed,
    );

    let access_point = survey
        .access_points()
        .next()
        .ok_or("missing access point")?;
    assert_eq!(access_point.ssid(), Some(b"Corp".as_slice()));
    assert_eq!(access_point.ssid_conflict(), Some(b"Guest".as_slice()));
    assert!(access_point.ssid_inconsistent());
    assert_eq!(access_point.channel(), Some(11));
    assert!(access_point.channel_changed());
    Ok(())
}
