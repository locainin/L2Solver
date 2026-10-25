use wifi_discovery::{ObservationStatus, SecurityMode, Survey, SurveyLimits, WirelessInput};

use super::common::{AP, assert_status, context};
use super::frames::{
    beacon_frame, beacon_with_ssid, rsn_group_tkip, rsn_psk, rsn_sae_only, rsn_transition, wpa,
};

fn rsn_profile(
    capabilities: u16,
    group_cipher: u8,
    pairwise_ciphers: &[u8],
    akms: &[u8],
    pmkid: Option<u8>,
) -> Vec<u8> {
    let body_length = 2
        + 4
        + 2
        + pairwise_ciphers.len() * 4
        + 2
        + akms.len() * 4
        + 2
        + pmkid.map_or(0, |_| 2 + 16);
    let mut body = Vec::with_capacity(body_length);
    body.extend_from_slice(&1_u16.to_le_bytes());
    body.extend_from_slice(&[0x00, 0x0f, 0xac, group_cipher]);
    body.extend_from_slice(
        &u16::try_from(pairwise_ciphers.len())
            .unwrap_or_default()
            .to_le_bytes(),
    );
    for cipher in pairwise_ciphers {
        body.extend_from_slice(&[0x00, 0x0f, 0xac, *cipher]);
    }
    body.extend_from_slice(&u16::try_from(akms.len()).unwrap_or_default().to_le_bytes());
    for akm in akms {
        body.extend_from_slice(&[0x00, 0x0f, 0xac, *akm]);
    }
    body.extend_from_slice(&capabilities.to_le_bytes());
    if let Some(value) = pmkid {
        body.extend_from_slice(&1_u16.to_le_bytes());
        body.extend_from_slice(&[value; 16]);
    }
    let mut element = vec![48, u8::try_from(body.len()).unwrap_or_default()];
    element.extend_from_slice(&body);
    element
}

#[test]
fn beacon_updates_inventory() -> Result<(), Box<dyn std::error::Error>> {
    let mut first_elements = vec![221, 4, 0x00, 0x50, 0xf2, 4];
    first_elements.extend_from_slice(&rsn_transition());
    let first = beacon_frame(AP, b"Corp", 0x0010, Some(6), &first_elements);
    let second_elements = rsn_psk(0, false);
    let second = beacon_frame(AP, b"New", 0x0010, Some(11), &second_elements);
    let mut survey = Survey::new(SurveyLimits::default())?;

    assert_status(
        &mut survey,
        WirelessInput::Ieee80211(&first),
        4,
        ObservationStatus::Observed,
    );
    assert_status(
        &mut survey,
        WirelessInput::Ieee80211(&second),
        5,
        ObservationStatus::NonCanonical,
    );

    let access_point = survey
        .access_points()
        .next()
        .ok_or("missing access point")?;
    assert_eq!(access_point.ssid(), Some(b"Corp".as_slice()));
    assert_eq!(access_point.ssid_conflict(), Some(b"New".as_slice()));
    assert!(access_point.ssid_inconsistent());
    assert_eq!(access_point.channel(), Some(11));
    assert!(access_point.channel_changed());
    assert_eq!(
        access_point.security(),
        SecurityMode::Wpa2Wpa3PersonalTransition
    );
    assert!(access_point.wps());
    assert!(!access_point.pmf_capable());
    assert!(!access_point.security_complete());
    assert!(access_point.security_inconsistent());
    assert_eq!(access_point.first_sequence(), 4);
    assert_eq!(access_point.last_sequence(), 5);
    assert_eq!(access_point.frames(), 2);
    Ok(())
}

#[test]
fn security_modes_are_classified() -> Result<(), Box<dyn std::error::Error>> {
    let mut survey = Survey::new(SurveyLimits::default())?;
    let wps_elements = vec![221, 4, 0x00, 0x50, 0xf2, 4];
    let open = beacon_frame([2, 0, 0, 0, 0, 3], b"Open", 0, Some(1), &wps_elements);
    let wep = beacon_frame([2, 0, 0, 0, 0, 4], b"Wep", 0x0010, Some(1), &[]);
    let legacy_elements = wpa();
    let legacy = beacon_frame(
        [2, 0, 0, 0, 0, 5],
        b"Legacy",
        0x0010,
        Some(1),
        &legacy_elements,
    );
    let mut mixed_elements = wpa();
    mixed_elements.extend_from_slice(&rsn_transition());
    let mixed = beacon_frame(
        [2, 0, 0, 0, 0, 6],
        b"Mixed",
        0x0010,
        Some(1),
        &mixed_elements,
    );
    let psk_elements = rsn_psk(0, false);
    let psk = beacon_frame([2, 0, 0, 0, 0, 7], b"Psk", 0x0010, Some(1), &psk_elements);
    let capable_elements = rsn_psk(0x0080, false);
    let capable = beacon_frame(
        [2, 0, 0, 0, 0, 8],
        b"Capable",
        0x0010,
        Some(1),
        &capable_elements,
    );
    let sae_elements = rsn_sae_only(0x00c0);
    let sae = beacon_frame([2, 0, 0, 0, 0, 9], b"Sae", 0x0010, Some(1), &sae_elements);
    for (sequence, frame) in [
        (1, open),
        (2, wep),
        (3, legacy),
        (4, mixed),
        (5, psk),
        (6, capable),
        (7, sae),
    ] {
        assert_status(
            &mut survey,
            WirelessInput::Ieee80211(&frame),
            40 + sequence,
            ObservationStatus::Observed,
        );
    }

    let points: Vec<_> = survey.access_points().collect();
    let [open, wep, legacy, mixed, psk, capable, sae] = points
        .as_slice()
        .try_into()
        .map_err(|_| "unexpected access-point count")?;
    assert_eq!(open.security(), SecurityMode::Open);
    assert!(open.wps());
    assert!(!open.pmf_capable());
    assert!(!open.pmf_required());
    assert_eq!(wep.security(), SecurityMode::Wep);
    assert_eq!(legacy.security(), SecurityMode::WpaLegacy);
    assert_eq!(mixed.security(), SecurityMode::WpaMixedLegacy);
    assert_eq!(psk.security(), SecurityMode::Wpa2Personal);
    assert!(!psk.wps());
    assert!(capable.pmf_capable());
    assert!(!capable.pmf_required());
    assert_eq!(sae.security(), SecurityMode::Wpa3Personal);
    assert!(!legacy.tkip());
    assert!(!mixed.tkip());
    Ok(())
}

#[test]
fn tkip_is_retained() -> Result<(), Box<dyn std::error::Error>> {
    let elements = rsn_group_tkip();
    let frame = beacon_frame(AP, b"Corp", 0x0010, Some(6), &elements);
    let mut survey = Survey::new(SurveyLimits::default())?;
    survey.observe(WirelessInput::Ieee80211(&frame), context(50));
    let access_point = survey
        .access_points()
        .next()
        .ok_or("missing access point")?;
    assert!(access_point.tkip());
    Ok(())
}

#[test]
fn complete_same_security_changes_drift() -> Result<(), Box<dyn std::error::Error>> {
    let first = beacon_frame(
        AP,
        b"Corp",
        0x0010,
        Some(6),
        &rsn_profile(0, 4, &[4], &[2], None),
    );
    let second = beacon_frame(
        AP,
        b"Corp",
        0x0010,
        Some(6),
        &rsn_profile(0x0080, 4, &[4], &[2], None),
    );
    let mut survey = Survey::new(SurveyLimits::default())?;

    assert_status(
        &mut survey,
        WirelessInput::Ieee80211(&first),
        60,
        ObservationStatus::Observed,
    );
    assert_status(
        &mut survey,
        WirelessInput::Ieee80211(&second),
        61,
        ObservationStatus::NonCanonical,
    );

    let access_point = survey
        .access_points()
        .next()
        .ok_or("missing access point")?;
    assert_eq!(access_point.security(), SecurityMode::Wpa2Personal);
    assert!(access_point.security_inconsistent());
    assert!(!access_point.security_complete());
    assert_eq!(survey.diagnostics().len(), 1);
    Ok(())
}

#[test]
fn complete_security_visible_incomplete_evidence() -> Result<(), Box<dyn std::error::Error>> {
    let first = beacon_frame(
        AP,
        b"Corp",
        0x0010,
        Some(6),
        &rsn_profile(0, 4, &[4], &[2], None),
    );
    let malformed = beacon_frame(AP, b"Corp", 0x0010, Some(6), &[48, 2, 1, 0]);
    let changed = beacon_frame(
        AP,
        b"Corp",
        0x0010,
        Some(6),
        &rsn_profile(0x0080, 4, &[4], &[2], None),
    );
    let mut survey = Survey::new(SurveyLimits::default())?;

    assert_status(
        &mut survey,
        WirelessInput::Ieee80211(&first),
        64,
        ObservationStatus::Observed,
    );
    assert_status(
        &mut survey,
        WirelessInput::Ieee80211(&malformed),
        65,
        ObservationStatus::Malformed,
    );
    assert_status(
        &mut survey,
        WirelessInput::Ieee80211(&changed),
        66,
        ObservationStatus::NonCanonical,
    );

    let access_point = survey
        .access_points()
        .next()
        .ok_or("missing access point")?;
    assert!(access_point.security_inconsistent());
    assert!(!access_point.security_complete());
    assert_eq!(survey.diagnostics().len(), 2);
    Ok(())
}

#[test]
fn complete_security_incomplete_evidence_retained() -> Result<(), Box<dyn std::error::Error>> {
    let malformed = beacon_frame(AP, b"Corp", 0x0010, Some(6), &[48, 2, 1, 0]);
    let first = beacon_frame(
        AP,
        b"Corp",
        0x0010,
        Some(6),
        &rsn_profile(0, 4, &[4], &[2], None),
    );
    let changed = beacon_frame(
        AP,
        b"Corp",
        0x0010,
        Some(6),
        &rsn_profile(0x0080, 4, &[4], &[2], None),
    );
    let mut survey = Survey::new(SurveyLimits::default())?;

    assert_status(
        &mut survey,
        WirelessInput::Ieee80211(&malformed),
        67,
        ObservationStatus::Malformed,
    );
    assert_status(
        &mut survey,
        WirelessInput::Ieee80211(&first),
        68,
        ObservationStatus::Observed,
    );
    assert_status(
        &mut survey,
        WirelessInput::Ieee80211(&changed),
        69,
        ObservationStatus::NonCanonical,
    );

    let access_point = survey
        .access_points()
        .next()
        .ok_or("missing access point")?;
    assert!(access_point.security_inconsistent());
    assert!(!access_point.security_complete());
    assert_eq!(survey.diagnostics().len(), 2);
    Ok(())
}

#[test]
fn reordered_suites_not_security_fingerprint() -> Result<(), Box<dyn std::error::Error>> {
    let first = beacon_frame(
        AP,
        b"Corp",
        0x00c0,
        Some(6),
        &rsn_profile(0x00c0, 4, &[4, 8], &[2, 8], Some(0x11)),
    );
    let second = beacon_frame(
        AP,
        b"Corp",
        0x00c0,
        Some(6),
        &rsn_profile(0x00c0, 4, &[8, 4], &[8, 2], Some(0xee)),
    );
    let mut survey = Survey::new(SurveyLimits::default())?;

    assert_status(
        &mut survey,
        WirelessInput::Ieee80211(&first),
        62,
        ObservationStatus::Observed,
    );
    assert_status(
        &mut survey,
        WirelessInput::Ieee80211(&second),
        63,
        ObservationStatus::Observed,
    );

    let access_point = survey
        .access_points()
        .next()
        .ok_or("missing access point")?;
    assert_eq!(
        access_point.security(),
        SecurityMode::Wpa2Wpa3PersonalTransition
    );
    assert!(!access_point.security_inconsistent());
    assert!(access_point.security_complete());
    assert_eq!(survey.diagnostics().len(), 0);
    Ok(())
}

#[test]
fn security_element_mode_deduplication() -> Result<(), Box<dyn std::error::Error>> {
    let psk = rsn_psk(0, false);
    let sae = rsn_sae_only(0x00c0);
    let mut psk_then_sae = psk.clone();
    psk_then_sae.extend_from_slice(&sae);
    let mut sae_then_psk = sae;
    sae_then_psk.extend_from_slice(&psk);
    let first = beacon_frame(
        [2, 0, 0, 0, 0, 10],
        b"First",
        0x0010,
        Some(6),
        &psk_then_sae,
    );
    let second = beacon_frame(
        [2, 0, 0, 0, 0, 11],
        b"Second",
        0x0010,
        Some(6),
        &sae_then_psk,
    );
    let mut survey = Survey::new(SurveyLimits::default())?;

    assert_status(
        &mut survey,
        WirelessInput::Ieee80211(&first),
        64,
        ObservationStatus::Observed,
    );
    assert_status(
        &mut survey,
        WirelessInput::Ieee80211(&second),
        65,
        ObservationStatus::Observed,
    );
    let modes: Vec<_> = survey
        .access_points()
        .map(wifi_discovery::AccessPoint::security)
        .collect();
    assert_eq!(
        modes,
        vec![
            SecurityMode::Wpa2Wpa3PersonalTransition,
            SecurityMode::Wpa2Wpa3PersonalTransition,
        ]
    );
    Ok(())
}

#[test]
fn too_many_security_profiles_incomplete() -> Result<(), Box<dyn std::error::Error>> {
    let profile = rsn_profile(0, 4, &[4], &[2], None);
    let mut elements = Vec::new();
    for _ in 0..=16 {
        elements.extend_from_slice(&profile);
    }
    let frame = beacon_frame(AP, b"Corp", 0x0010, Some(6), &elements);
    let mut survey = Survey::new(SurveyLimits::default())?;

    assert_status(
        &mut survey,
        WirelessInput::Ieee80211(&frame),
        70,
        ObservationStatus::Malformed,
    );
    let access_point = survey
        .access_points()
        .next()
        .ok_or("missing access point")?;
    assert_eq!(access_point.security(), SecurityMode::Wpa2Personal);
    assert!(!access_point.security_complete());
    assert_eq!(survey.diagnostics().len(), 1);
    Ok(())
}

#[test]
fn maximum_ssid_length_is_accepted() -> Result<(), Box<dyn std::error::Error>> {
    let frame = beacon_with_ssid(&[b'A'; 32]);
    let mut survey = Survey::new(SurveyLimits::default())?;

    assert_status(
        &mut survey,
        WirelessInput::Ieee80211(&frame),
        51,
        ObservationStatus::Observed,
    );
    let access_point = survey
        .access_points()
        .next()
        .ok_or("missing access point")?;
    assert_eq!(access_point.ssid(), Some(&[b'A'; 32][..]));
    Ok(())
}

#[test]
fn truncated_capture_keeps_security_unknown() -> Result<(), Box<dyn std::error::Error>> {
    let frame = beacon_frame(AP, b"Corp", 0x0010, Some(6), &[]);
    let mut survey = Survey::new(SurveyLimits::default())?;

    let status = survey.observe(
        WirelessInput::Ieee80211(&frame),
        context(80).with_capture_truncated(true),
    );

    assert_eq!(status, ObservationStatus::Incomplete);
    let access_point = survey
        .access_points()
        .next()
        .ok_or("missing access point")?;
    assert_eq!(access_point.security(), SecurityMode::Unknown);
    assert!(!access_point.security_complete());
    assert_eq!(survey.diagnostics().len(), 1);
    Ok(())
}

#[test]
fn malformed_rsn_is_unknown() -> Result<(), Box<dyn std::error::Error>> {
    let frame = beacon_frame(AP, b"Corp", 0x0010, Some(6), &[48, 2, 1, 0]);
    let mut survey = Survey::new(SurveyLimits::default())?;

    assert_status(
        &mut survey,
        WirelessInput::Ieee80211(&frame),
        81,
        ObservationStatus::Malformed,
    );
    let access_point = survey
        .access_points()
        .next()
        .ok_or("missing access point")?;
    assert_eq!(access_point.security(), SecurityMode::Unknown);
    assert!(!access_point.security_complete());
    Ok(())
}

#[test]
fn malformed_security_keeps_valid_evidence() -> Result<(), Box<dyn std::error::Error>> {
    let valid_elements = rsn_sae_only(0x00c0);
    let valid = beacon_frame(AP, b"Corp", 0x0010, Some(6), &valid_elements);
    let malformed = beacon_frame(AP, b"Corp", 0x0010, Some(6), &[48, 2, 1, 0]);

    for frames in [
        [valid.as_slice(), malformed.as_slice()],
        [malformed.as_slice(), valid.as_slice()],
    ] {
        let mut survey = Survey::new(SurveyLimits::default())?;
        for (index, frame) in frames.into_iter().enumerate() {
            survey.observe(
                WirelessInput::Ieee80211(frame),
                context(u64::try_from(index)? + 90),
            );
        }
        let access_point = survey
            .access_points()
            .next()
            .ok_or("missing access point")?;
        assert_eq!(access_point.security(), SecurityMode::Wpa3Personal);
        assert!(!access_point.security_complete());
    }
    Ok(())
}
