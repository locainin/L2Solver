use wifi_audit::{CoverageStatus, RiskClass, WirelessPolicy, assess};
use wifi_discovery::{ObservationContext, ObservationStatus, Survey, SurveyLimits, WirelessInput};

use super::frames::{EXPECTED_AP, beacon};
use super::policies::policy;

#[test]
fn compliant_ap_has_no_findings() -> Result<(), Box<dyn std::error::Error>> {
    let mut survey = Survey::new(SurveyLimits::default())?;
    let frame = beacon(EXPECTED_AP, true, false);
    survey.observe(
        WirelessInput::Ieee80211(&frame),
        ObservationContext::new(4, 1_000),
    );

    let assessment = assess(&survey, &policy()?, &[])?;

    assert!(assessment.findings().is_empty());
    assert!(assessment.exposures().is_empty());
    Ok(())
}

#[test]
fn missing_schedule_is_unclaimed() -> Result<(), Box<dyn std::error::Error>> {
    let survey = Survey::new(SurveyLimits::default())?;

    let assessment = assess(&survey, &WirelessPolicy::default(), &[])?;

    let passive = assessment
        .coverage("WIFI-PASSIVE-SURVEY")
        .ok_or("missing passive coverage")?;
    assert_eq!(
        passive.reason(),
        "no access-point advertisement was decoded"
    );

    let coverage = assessment
        .coverage("WIFI-CHANNEL-COVERAGE")
        .ok_or("missing channel coverage")?;
    assert_eq!(coverage.status(), CoverageStatus::NotTested);
    assert!(coverage.reason().contains("schedule"));
    Ok(())
}

#[test]
fn active_catalog_requires_transmit() -> Result<(), Box<dyn std::error::Error>> {
    let first = wifi_audit::active_catalog()
        .first()
        .ok_or("empty active catalog")?;
    assert_eq!(first.id(), "WIFI-ASSOC-001");
    assert_eq!(first.risk(), RiskClass::Stateful);
    assert!(first.requires_transmit());
    assert_eq!(first.required_agents(), 1);
    assert_eq!(first.packet_budget(), 24);
    assert_eq!(first.duration_ms(), 15_000);

    let second = wifi_audit::active_catalog()
        .get(1)
        .ok_or("missing second active check")?;
    assert_eq!(second.required_agents(), 2);

    for check in wifi_audit::active_catalog() {
        assert!(check.requires_transmit() || check.required_agents() > 0);
        assert!(check.packet_budget() > 0);
        assert!(check.duration_ms() > 0);
    }
    Ok(())
}

#[test]
fn radio_coverage_is_bounded() -> Result<(), Box<dyn std::error::Error>> {
    let mut survey = Survey::new(SurveyLimits::new(1, 1, 1, 300)?)?;
    let mut coverage = Vec::new();
    for radio in 0_u16..=256 {
        survey.record_radio_schedule(radio, 1)?;
        coverage.push(survey.channel_coverage(radio)?);
    }

    let within_limit = coverage.get(..256).ok_or("missing coverage prefix")?;
    assert!(assess(&survey, &WirelessPolicy::default(), within_limit).is_ok());
    assert!(matches!(
        assess(&survey, &WirelessPolicy::default(), &coverage),
        Err(wifi_audit::AuditError::AssessmentLimit {
            field: "radio coverage",
            count: 257,
            maximum: 256
        })
    ));
    Ok(())
}

#[test]
fn zero_duration_radio_not_tested() -> Result<(), Box<dyn std::error::Error>> {
    let mut survey = Survey::new(SurveyLimits::default())?;
    survey.record_radio_schedule(0, 0)?;
    survey.record_channel_dwell(0, 2_412, 0)?;

    let channel = survey.channel_coverage(0)?;
    let assessment = assess(&survey, &WirelessPolicy::default(), &[channel])?;

    let coverage = assessment
        .coverage("WIFI-CHANNEL-COVERAGE")
        .ok_or("missing channel coverage")?;
    assert_eq!(coverage.status(), CoverageStatus::NotTested);
    assert!(coverage.reason().contains("zero"));
    Ok(())
}

#[test]
fn scheduled_radio_without_not_tested() -> Result<(), Box<dyn std::error::Error>> {
    let mut survey = Survey::new(SurveyLimits::default())?;
    survey.record_radio_schedule(0, 1_000)?;

    let channel = survey.channel_coverage(0)?;
    let assessment = assess(&survey, &WirelessPolicy::default(), &[channel])?;

    assert_eq!(
        assessment
            .coverage("WIFI-CHANNEL-COVERAGE")
            .ok_or("missing channel coverage")?
            .status(),
        CoverageStatus::NotTested
    );
    Ok(())
}

#[test]
fn positive_radio_dwell_is_tested() -> Result<(), Box<dyn std::error::Error>> {
    let mut survey = Survey::new(SurveyLimits::default())?;
    survey.record_radio_schedule(0, 1_000)?;
    survey.record_channel_dwell(0, 2_412, 1_000)?;

    let channel = survey.channel_coverage(0)?;
    let assessment = assess(&survey, &WirelessPolicy::default(), &[channel])?;

    assert_eq!(
        assessment
            .coverage("WIFI-CHANNEL-COVERAGE")
            .ok_or("missing channel coverage")?
            .status(),
        CoverageStatus::Tested
    );
    Ok(())
}

#[test]
fn protected_advertisement_is_incomplete() -> Result<(), Box<dyn std::error::Error>> {
    let mut survey = Survey::new(SurveyLimits::default())?;
    let mut frame = beacon(EXPECTED_AP, true, false);
    let frame_flags = frame.get_mut(1).ok_or("missing frame-control flags")?;
    *frame_flags |= 0x40;

    assert_eq!(
        survey.observe(
            WirelessInput::Ieee80211(&frame),
            ObservationContext::new(5, 1_000),
        ),
        ObservationStatus::Protected
    );
    assert!(survey.diagnostics().is_empty());

    let assessment = assess(&survey, &WirelessPolicy::default(), &[])?;
    let coverage = assessment
        .coverage("WIFI-PASSIVE-SURVEY")
        .ok_or("missing passive coverage")?;
    assert_eq!(coverage.status(), CoverageStatus::Incomplete);
    assert!(coverage.reason().contains("incomplete"));
    Ok(())
}
