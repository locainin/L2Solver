use wifi_audit::{Severity, Verdict};
use wifi_core::MacAddress;

use super::common::{assert_verdict, assess_frame};
use super::frames::{EXPECTED_AP, ROGUE_AP, beacon, beacon_named, beacon_on_channel, rsn_sae};

#[test]
fn open_network_exposes_evidence() -> Result<(), Box<dyn std::error::Error>> {
    let frame = beacon(ROGUE_AP, false, true);
    let assessment = assess_frame(&frame, 9)?;

    let open = assessment
        .exposure("WIFI-ENC-OPEN")
        .ok_or("missing open exposure")?;
    assert_eq!(open.title(), "Open wireless network observed");
    assert_eq!(open.severity(), Severity::High);
    assert_eq!(open.bssid(), MacAddress::new(ROGUE_AP));
    assert_eq!(open.evidence_sequences(), &[9]);
    assert!(assessment.exposure("WIFI-PMF-001").is_none());
    assert!(assessment.exposure("WIFI-WPS-001").is_some());
    assert!(assessment.exposures().len() >= 2);
    assert!(assessment.exposure("missing").is_none());
    Ok(())
}

#[test]
fn rogue_bssid_exposes_evidence() -> Result<(), Box<dyn std::error::Error>> {
    let frame = beacon(ROGUE_AP, false, true);
    let assessment = assess_frame(&frame, 9)?;
    let rogue = assessment
        .finding("WIFI-ROGUE-001")
        .ok_or("missing rogue finding")?;
    assert_eq!(rogue.title(), "SSID observed from an unapproved BSSID");
    assert_eq!(rogue.expected(), "an approved BSSID");
    assert_eq!(rogue.observed(), "BSSID 02:00:00:00:00:09");
    assert_eq!(rogue.bssid(), MacAddress::new(ROGUE_AP));
    assert_eq!(rogue.severity(), Severity::Critical);
    assert_verdict(&assessment, "WIFI-ROGUE-001", Verdict::Potential);
    assert_eq!(rogue.evidence_sequences(), &[9]);
    assert!(assessment.finding("WIFI-SEC-POLICY-001").is_some());
    assert!(assessment.finding("WIFI-PMF-POLICY-001").is_some());
    assert!(assessment.finding("WIFI-WPS-POLICY-001").is_some());
    assert_ne!(assessment.findings(), []);
    assert_ne!(assessment.coverage_entries(), []);
    assert!(assessment.finding("missing").is_none());
    Ok(())
}

#[test]
fn unlisted_ssid_is_reported() -> Result<(), Box<dyn std::error::Error>> {
    let other = beacon_named(ROGUE_AP, b"Other", false, false);
    let assessment = assess_frame(&other, 10)?;
    let finding = assessment
        .finding("WIFI-SSID-POLICY-001")
        .ok_or("missing unlisted SSID finding")?;
    assert_eq!(finding.observed(), "SSID Other");
    Ok(())
}

#[test]
fn advertisement_drift_remains_exposed() -> Result<(), Box<dyn std::error::Error>> {
    let first = beacon_on_channel(EXPECTED_AP, b"Corp", 0x0010, 36, &rsn_sae());
    let changed = beacon_on_channel(EXPECTED_AP, b"Guest", 0, 11, &[]);
    let mut survey = wifi_discovery::Survey::new(wifi_discovery::SurveyLimits::default())?;
    survey.observe(
        wifi_discovery::WirelessInput::Ieee80211(&first),
        wifi_discovery::ObservationContext::new(1, 1_000),
    );
    survey.observe(
        wifi_discovery::WirelessInput::Ieee80211(&changed),
        wifi_discovery::ObservationContext::new(2, 2_000),
    );

    let assessment = wifi_audit::assess(&survey, &wifi_audit::WirelessPolicy::default(), &[])?;

    assert!(assessment.exposure("WIFI-IDENTITY-DRIFT").is_some());
    assert!(assessment.exposure("WIFI-CHANNEL-DRIFT").is_some());
    assert!(assessment.exposure("WIFI-SECURITY-DRIFT").is_some());
    assert_eq!(
        assessment
            .coverage("WIFI-PASSIVE-SURVEY")
            .ok_or("missing passive coverage")?
            .status(),
        wifi_audit::CoverageStatus::Incomplete
    );
    Ok(())
}
