use wifi_audit::{
    AuditError, PmfRequirement, Verdict, WirelessNetworkPolicy, WirelessPolicy, assess,
};
use wifi_core::MacAddress;
use wifi_discovery::{ObservationContext, SecurityMode, Survey, SurveyLimits, WirelessInput};

use super::frames::{EXPECTED_AP, beacon, beacon_with, rsn_sae_with, rsn_transition, wpa};
use super::policies::policy_with_pmf;

#[test]
fn errors_render() {
    assert_eq!(
        AuditError::InvalidPolicy("bad").to_string(),
        "invalid wireless policy: bad"
    );
    assert_eq!(
        AuditError::PolicyLimit {
            field: "networks",
            count: 257,
            maximum: 256,
        }
        .to_string(),
        "wireless policy networks count 257 exceeds limit 256"
    );
    assert_eq!(
        AuditError::AssessmentLimit {
            field: "radio coverage",
            count: 257,
            maximum: 256,
        }
        .to_string(),
        "wireless assessment radio coverage count 257 exceeds limit 256"
    );
}

#[test]
fn modes_are_reported() -> Result<(), Box<dyn std::error::Error>> {
    let mut survey = Survey::new(SurveyLimits::default())?;
    let wep = beacon_with([2, 0, 0, 0, 0, 2], b"Wep", 0x0010, &[]);
    let legacy = beacon_with([2, 0, 0, 0, 0, 3], b"Legacy", 0x0010, &wpa());
    let mut mixed_elements = wpa();
    mixed_elements.extend_from_slice(&rsn_sae_with(0));
    let mixed = beacon_with([2, 0, 0, 0, 0, 4], b"Mixed", 0x0010, &mixed_elements);
    let transition = beacon_with([2, 0, 0, 0, 0, 5], b"Transition", 0x0010, &rsn_transition());
    for (sequence, frame) in [(20, wep), (21, legacy), (22, mixed), (23, transition)] {
        survey.observe(
            WirelessInput::Ieee80211(&frame),
            ObservationContext::new(sequence, 1_000),
        );
    }

    let assessment = assess(&survey, &WirelessPolicy::default(), &[])?;
    for id in [
        "WIFI-ENC-WEP",
        "WIFI-ENC-WPA",
        "WIFI-ENC-MIXED",
        "WIFI-ENC-TRANSITION",
    ] {
        assert!(assessment.exposure(id).is_some(), "missing {id}");
    }
    assert!(assessment.exposure("WIFI-PMF-001").is_none());
    Ok(())
}

#[test]
fn pmf_policy_is_checked() -> Result<(), Box<dyn std::error::Error>> {
    let mut survey = Survey::new(SurveyLimits::default())?;
    let frame = beacon_with(EXPECTED_AP, b"Corp", 0x0010, &rsn_sae_with(0));
    survey.observe(
        WirelessInput::Ieee80211(&frame),
        ObservationContext::new(30, 1_000),
    );

    let assessment = assess(&survey, &policy_with_pmf(PmfRequirement::Capable)?, &[])?;
    let finding = assessment
        .finding("WIFI-PMF-POLICY-001")
        .ok_or("missing PMF policy finding")?;
    assert_eq!(finding.verdict(), Verdict::Fail);
    assert_eq!(finding.observed(), "PMF not advertised");
    assert!(assessment.exposure("WIFI-PMF-001").is_some());

    let capable = beacon(EXPECTED_AP, true, false);
    let mut capable_survey = Survey::new(SurveyLimits::default())?;
    capable_survey.observe(
        WirelessInput::Ieee80211(&capable),
        ObservationContext::new(31, 1_000),
    );
    let capable_assessment = assess(
        &capable_survey,
        &policy_with_pmf(PmfRequirement::Capable)?,
        &[],
    )?;
    assert!(capable_assessment.finding("WIFI-PMF-POLICY-001").is_none());
    Ok(())
}

#[test]
fn incompatible_pmf_policy_stays_conservative() -> Result<(), Box<dyn std::error::Error>> {
    let cases = vec![
        (
            [2, 0, 0, 0, 0, 2],
            b"Wep".as_slice(),
            Vec::new(),
            SecurityMode::Wep,
        ),
        (
            [2, 0, 0, 0, 0, 3],
            b"Legacy".as_slice(),
            wpa(),
            SecurityMode::WpaLegacy,
        ),
    ];

    for (sequence, (bssid, ssid, elements, mode)) in cases.into_iter().enumerate() {
        let network = WirelessNetworkPolicy::new(ssid.to_vec())?
            .with_allowed_bssids(vec![MacAddress::new(bssid)])?
            .with_security_modes(vec![mode])?
            .with_pmf(PmfRequirement::Required);
        let policy = WirelessPolicy::new(vec![network])?;
        let mut survey = Survey::new(SurveyLimits::default())?;
        let frame = beacon_with(bssid, ssid, 0x0010, &elements);
        survey.observe(
            WirelessInput::Ieee80211(&frame),
            ObservationContext::new(u64::try_from(sequence)?, 1_000),
        );

        let assessment = assess(&survey, &policy, &[])?;
        let finding = assessment
            .finding("WIFI-PMF-POLICY-001")
            .ok_or("missing incompatible PMF finding")?;
        assert_eq!(finding.verdict(), Verdict::Potential);
        assert!(finding.observed().contains("not applicable"));
        assert!(assessment.exposure("WIFI-PMF-001").is_none());
    }
    Ok(())
}

#[test]
fn channel_policy_is_checked() -> Result<(), Box<dyn std::error::Error>> {
    let network = WirelessNetworkPolicy::new(b"Corp".to_vec())?
        .with_allowed_bssids(vec![MacAddress::new(EXPECTED_AP)])?
        .with_security_modes(vec![SecurityMode::Wpa3Personal])?
        .with_pmf(PmfRequirement::Required)
        .with_allowed_channels(vec![1])?;
    let policy = WirelessPolicy::new(vec![network])?;
    let mut survey = Survey::new(SurveyLimits::default())?;
    let frame = beacon(EXPECTED_AP, true, false);
    survey.observe(
        WirelessInput::Ieee80211(&frame),
        ObservationContext::new(32, 1_000),
    );

    let assessment = assess(&survey, &policy, &[])?;
    assert!(assessment.finding("WIFI-CHANNEL-POLICY-001").is_some());
    Ok(())
}

#[test]
fn wps_policy_is_checked() -> Result<(), Box<dyn std::error::Error>> {
    let network = WirelessNetworkPolicy::new(b"Corp".to_vec())?.with_wps_allowed(true);
    let policy = WirelessPolicy::new(vec![network])?;
    let mut survey = Survey::new(SurveyLimits::default())?;
    let frame = beacon(EXPECTED_AP, false, true);
    survey.observe(
        WirelessInput::Ieee80211(&frame),
        ObservationContext::new(33, 1_000),
    );

    let assessment = assess(&survey, &policy, &[])?;
    assert!(assessment.finding("WIFI-WPS-POLICY-001").is_none());
    Ok(())
}

#[test]
fn policy_limits_are_bounded() -> Result<(), Box<dyn std::error::Error>> {
    let base = WirelessNetworkPolicy::new(b"Corp".to_vec())?;

    let mut bssids = Vec::new();
    for index in 0..=256_u16 {
        bssids.push(MacAddress::new([
            2,
            0,
            0,
            0,
            u8::try_from(index / 256)?,
            u8::try_from(index % 256)?,
        ]));
    }
    let within_limit = bssids.get(..256).ok_or("missing BSSID prefix")?;
    assert!(
        base.clone()
            .with_allowed_bssids(within_limit.to_vec())
            .is_ok()
    );
    assert!(matches!(
        base.clone().with_allowed_bssids(bssids),
        Err(AuditError::PolicyLimit {
            field: "BSSIDs",
            count: 257,
            maximum: 256
        })
    ));

    assert!(
        base.clone()
            .with_security_modes(vec![SecurityMode::Wpa3Personal; 16])
            .is_ok()
    );
    assert!(matches!(
        base.clone()
            .with_security_modes(vec![SecurityMode::Wpa3Personal; 17]),
        Err(AuditError::PolicyLimit {
            field: "security modes",
            count: 17,
            maximum: 16
        })
    ));

    let channels: Vec<u16> = (1..=256).collect();
    assert!(base.clone().with_allowed_channels(channels.clone()).is_ok());
    let mut too_many_channels = channels;
    too_many_channels.push(257);
    assert!(matches!(
        base.with_allowed_channels(too_many_channels),
        Err(AuditError::PolicyLimit {
            field: "channels",
            count: 257,
            maximum: 256
        })
    ));

    let mut networks = Vec::new();
    for index in 0..=256_u16 {
        networks.push(WirelessNetworkPolicy::new(vec![
            u8::try_from(index / 256)?,
            u8::try_from(index % 256)?,
        ])?);
    }
    let within_limit = networks.get(..256).ok_or("missing network prefix")?;
    assert!(WirelessPolicy::new(within_limit.to_vec()).is_ok());
    assert!(matches!(
        WirelessPolicy::new(networks),
        Err(AuditError::PolicyLimit {
            field: "networks",
            count: 257,
            maximum: 256
        })
    ));
    Ok(())
}
