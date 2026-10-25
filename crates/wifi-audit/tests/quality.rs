use wifi_audit::{
    CoverageStatus, PmfRequirement, Verdict, WirelessNetworkPolicy, WirelessPolicy, assess,
};
use wifi_discovery::{
    ObservationContext, ObservationStatus, SecurityMode, Survey, SurveyLimits, WirelessInput,
};

const AP: [u8; 6] = [0x02, 0, 0, 0, 0, 1];

fn rsn_sae() -> Vec<u8> {
    let mut element = vec![48, 20];
    element.extend_from_slice(&1_u16.to_le_bytes());
    element.extend_from_slice(&[0x00, 0x0f, 0xac, 4]);
    element.extend_from_slice(&1_u16.to_le_bytes());
    element.extend_from_slice(&[0x00, 0x0f, 0xac, 4]);
    element.extend_from_slice(&1_u16.to_le_bytes());
    element.extend_from_slice(&[0x00, 0x0f, 0xac, 8]);
    element.extend_from_slice(&0x00c0_u16.to_le_bytes());
    element
}

fn rsn_unknown_akm() -> Vec<u8> {
    // An unknown selector is valid evidence but cannot be classified by policy
    let mut element = vec![48, 20];
    element.extend_from_slice(&1_u16.to_le_bytes());
    element.extend_from_slice(&[0x00, 0x0f, 0xac, 4]);
    element.extend_from_slice(&1_u16.to_le_bytes());
    element.extend_from_slice(&[0x00, 0x0f, 0xac, 4]);
    element.extend_from_slice(&1_u16.to_le_bytes());
    element.extend_from_slice(&[0x00, 0x0f, 0xac, 99]);
    element.extend_from_slice(&0_u16.to_le_bytes());
    element
}

fn beacon(
    ssid: Option<&[u8]>,
    channel: Option<u8>,
    capability: u16,
    elements: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // The fixed header keeps each test focused on advertisement quality
    let mut frame = Vec::from(0x0080_u16.to_le_bytes());
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&[0xff; 6]);
    frame.extend_from_slice(&AP);
    frame.extend_from_slice(&AP);
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&0_u64.to_le_bytes());
    frame.extend_from_slice(&100_u16.to_le_bytes());
    frame.extend_from_slice(&capability.to_le_bytes());
    if let Some(value) = ssid {
        frame.extend_from_slice(&[0, u8::try_from(value.len())?]);
        frame.extend_from_slice(value);
    }
    if let Some(value) = channel {
        frame.extend_from_slice(&[3, 1, value]);
    }
    frame.extend_from_slice(elements);
    Ok(frame)
}

fn policy() -> Result<WirelessPolicy, Box<dyn std::error::Error>> {
    let network = WirelessNetworkPolicy::new(b"Corp".to_vec())?
        .with_security_modes(vec![SecurityMode::Wpa3Personal])?
        .with_pmf(PmfRequirement::Required)
        .with_allowed_channels(vec![36])?;
    Ok(WirelessPolicy::new(vec![network])?.with_unlisted_ssids_forbidden(true))
}

fn verdict(assessment: &wifi_audit::Assessment, id: &str) -> Option<Verdict> {
    assessment.finding(id).map(wifi_audit::Finding::verdict)
}

fn passive_status(
    assessment: &wifi_audit::Assessment,
) -> Result<CoverageStatus, Box<dyn std::error::Error>> {
    Ok(assessment
        .coverage("WIFI-PASSIVE-SURVEY")
        .ok_or("missing passive coverage")?
        .status())
}

fn radiotap_at(frame: &[u8], frequency: u16) -> Vec<u8> {
    let mut bytes = vec![0_u8, 0, 13, 0, 0x28, 0, 0, 0];
    bytes.extend_from_slice(&frequency.to_le_bytes());
    bytes.extend_from_slice(&0x00a0_u16.to_le_bytes());
    bytes.extend_from_slice(&(-40_i8).to_ne_bytes());
    bytes.extend_from_slice(frame);
    bytes
}

mod incomplete_security {
    use super::*;

    #[test]
    fn unknown_protected_mismatch_potential_incomplete() -> Result<(), Box<dyn std::error::Error>> {
        let mut survey = Survey::new(SurveyLimits::default())?;
        let frame = beacon(Some(b"Corp"), Some(36), 0x0010, &rsn_unknown_akm())?;
        assert_eq!(
            survey.observe(
                WirelessInput::Ieee80211(&frame),
                ObservationContext::new(1, 10),
            ),
            ObservationStatus::Observed
        );

        let access_point = survey
            .access_points()
            .next()
            .ok_or("missing access point")?;
        assert_eq!(access_point.security(), SecurityMode::UnknownProtected);
        assert!(!access_point.security_complete());

        let network = WirelessNetworkPolicy::new(b"Corp".to_vec())?
            .with_security_modes(vec![SecurityMode::Wpa3Personal])?
            .with_allowed_channels(vec![1])?;
        let assessment = assess(&survey, &WirelessPolicy::new(vec![network])?, &[])?;
        assert_eq!(
            verdict(&assessment, "WIFI-SEC-POLICY-001"),
            Some(Verdict::Potential)
        );
        assert_eq!(
            verdict(&assessment, "WIFI-CHANNEL-POLICY-001"),
            Some(Verdict::Fail)
        );
        assert_eq!(
            assessment
                .coverage("WIFI-PASSIVE-SURVEY")
                .ok_or("missing passive coverage")?
                .status(),
            CoverageStatus::Incomplete
        );
        Ok(())
    }

    #[test]
    fn malformed_rsn_not_open_wep() -> Result<(), Box<dyn std::error::Error>> {
        let mut survey = Survey::new(SurveyLimits::default())?;
        let frame = beacon(Some(b"Corp"), Some(36), 0x0010, &[48, 2, 1, 0])?;

        assert_eq!(
            survey.observe(
                WirelessInput::Ieee80211(&frame),
                ObservationContext::new(1, 10),
            ),
            ObservationStatus::Malformed
        );

        let assessment = assess(&survey, &policy()?, &[])?;
        assert!(assessment.exposure("WIFI-ENC-OPEN").is_none());
        assert!(assessment.exposure("WIFI-ENC-WEP").is_none());
        assert_eq!(
            verdict(&assessment, "WIFI-SEC-UNKNOWN-001"),
            Some(Verdict::Potential)
        );
        assert_eq!(
            assessment
                .coverage("WIFI-PASSIVE-SURVEY")
                .ok_or("missing passive coverage")?
                .status(),
            CoverageStatus::Incomplete
        );
        Ok(())
    }

    #[test]
    fn known_mismatch_is_only_potential() -> Result<(), Box<dyn std::error::Error>> {
        let mut survey = Survey::new(SurveyLimits::default())?;
        let complete = beacon(Some(b"Corp"), Some(36), 0x0010, &rsn_sae())?;
        let malformed = beacon(Some(b"Corp"), Some(36), 0x0010, &[48, 2, 1, 0])?;
        survey.observe(
            WirelessInput::Ieee80211(&complete),
            ObservationContext::new(1, 10),
        );
        survey.observe(
            WirelessInput::Ieee80211(&malformed),
            ObservationContext::new(2, 20),
        );
        let network = WirelessNetworkPolicy::new(b"Corp".to_vec())?
            .with_security_modes(vec![SecurityMode::Wpa2Enterprise])?;
        let assessment = assess(&survey, &WirelessPolicy::new(vec![network])?, &[])?;

        assert_eq!(
            verdict(&assessment, "WIFI-SEC-POLICY-001"),
            Some(Verdict::Potential)
        );
        Ok(())
    }

    #[test]
    fn truncation_degrades_coverage() -> Result<(), Box<dyn std::error::Error>> {
        let mut survey = Survey::new(SurveyLimits::default())?;
        let frame = beacon(Some(b"Corp"), Some(36), 0, &[])?;
        let status = survey.observe(
            WirelessInput::Ieee80211(&frame),
            ObservationContext::new(1, 10).with_capture_truncated(true),
        );

        assert_eq!(status, ObservationStatus::Incomplete);
        let assessment = assess(&survey, &WirelessPolicy::default(), &[])?;
        assert_eq!(
            assessment
                .coverage("WIFI-PASSIVE-SURVEY")
                .ok_or("missing passive coverage")?
                .status(),
            CoverageStatus::Incomplete
        );
        Ok(())
    }
}

mod missing_identity {
    use super::*;

    #[test]
    fn hidden_ssid_is_reported() -> Result<(), Box<dyn std::error::Error>> {
        let mut survey = Survey::new(SurveyLimits::default())?;
        let frame = beacon(None, Some(36), 0x0010, &rsn_sae())?;
        survey.observe(
            WirelessInput::Ieee80211(&frame),
            ObservationContext::new(1, 10),
        );

        let assessment = assess(&survey, &policy()?, &[])?;
        assert_eq!(
            verdict(&assessment, "WIFI-SSID-HIDDEN-001"),
            Some(Verdict::Potential)
        );
        assert_eq!(passive_status(&assessment)?, CoverageStatus::Incomplete);
        Ok(())
    }

    #[test]
    fn unknown_channel_is_reported() -> Result<(), Box<dyn std::error::Error>> {
        let mut survey = Survey::new(SurveyLimits::default())?;
        let frame = beacon(Some(b"Corp"), None, 0x0010, &rsn_sae())?;
        survey.observe(
            WirelessInput::Ieee80211(&frame),
            ObservationContext::new(1, 10),
        );

        let assessment = assess(&survey, &policy()?, &[])?;
        assert_eq!(
            verdict(&assessment, "WIFI-CHANNEL-UNKNOWN-001"),
            Some(Verdict::Potential)
        );
        assert_eq!(passive_status(&assessment)?, CoverageStatus::Incomplete);
        Ok(())
    }
}

mod channel_identity {
    use super::*;

    #[test]
    fn drift_every_observed_channel_policy() -> Result<(), Box<dyn std::error::Error>> {
        let mut survey = Survey::new(SurveyLimits::default())?;
        let disallowed = beacon(Some(b"Corp"), Some(11), 0x0010, &rsn_sae())?;
        let allowed = beacon(Some(b"Corp"), Some(36), 0x0010, &rsn_sae())?;
        survey.observe(
            WirelessInput::Ieee80211(&disallowed),
            ObservationContext::new(1, 10),
        );
        survey.observe(
            WirelessInput::Ieee80211(&allowed),
            ObservationContext::new(2, 20),
        );

        let access_point = survey
            .access_points()
            .next()
            .ok_or("missing access point")?;
        assert_eq!(access_point.observed_channels(), [11, 36]);
        let assessment = assess(&survey, &policy()?, &[])?;
        assert_eq!(
            verdict(&assessment, "WIFI-CHANNEL-POLICY-001"),
            Some(Verdict::Fail)
        );
        assert_eq!(passive_status(&assessment)?, CoverageStatus::Incomplete);
        Ok(())
    }

    #[test]
    fn contradictory_channel_cannot_definite_failure() -> Result<(), Box<dyn std::error::Error>> {
        let mut survey = Survey::new(SurveyLimits::default())?;
        let advertised = beacon(Some(b"Corp"), Some(11), 0x0010, &rsn_sae())?;
        let conflicting = radiotap_at(&advertised, 5_180);
        survey.observe(
            WirelessInput::Radiotap(&conflicting),
            ObservationContext::new(1, 10),
        );

        let access_point = survey
            .access_points()
            .next()
            .ok_or("missing access point")?;
        assert!(access_point.channel_inconsistent());
        let assessment = assess(&survey, &policy()?, &[])?;
        assert_eq!(
            verdict(&assessment, "WIFI-CHANNEL-POLICY-001"),
            Some(Verdict::Potential)
        );
        assert_eq!(passive_status(&assessment)?, CoverageStatus::Incomplete);
        Ok(())
    }
}
