use super::support::*;
use l2_audit::{Policy, ResourceLimit, Survey, SurveyLimits};
use l2_capture::FcsStatus;

#[test]
fn shared_limit_usable_incomplete() -> TestResult {
    let limits = SurveyLimits::default().with_forensic_records(1)?;
    let mut survey = Survey::with_limits(limits);
    survey.observe(&captured(traffic(SECOND_MAC, ADDRESS), 0)?)?;
    survey.observe(&captured(traffic(FIRST_MAC, ADDRESS), 0)?)?;
    let report = survey.finish(&Policy::default())?;
    assert_eq!(report.forensics.communications.len(), 1);
    assert_eq!(report.quality.frames, 2);
    assert!(
        report
            .resource_limits
            .is_reached(ResourceLimit::ForensicRecords)
    );
    assert!(!report.collection_complete());
    Ok(())
}

#[test]
fn record_kinds_shared_retention_budget() -> TestResult {
    let mut survey = Survey::with_limits(SurveyLimits::default().with_forensic_records(5)?);
    survey.observe(&captured(arp(FIRST_MAC, FIRST_MAC, ADDRESS), 0)?)?;
    survey.observe(&captured(arp(SECOND_MAC, SECOND_MAC, ADDRESS), 0)?)?;
    let mut bytes = traffic(SECOND_MAC, ADDRESS);
    bytes.extend_from_slice(&[0, 0x55, 0xaa, 0]);
    survey.observe(&captured_with_fcs(bytes, 0, FcsStatus::Absent)?)?;
    survey.observe(&captured(traffic(FIRST_MAC, [192, 0, 2, 99]), 0)?)?;

    let report = survey.finish(&Policy::default())?;
    let facts = &report.forensics;
    assert_eq!(
        (
            facts.communications.len(),
            facts.arp_observations.len(),
            facts.arp_changes.len(),
            facts.trailing_data.len()
        ),
        (1, 2, 1, 1)
    );
    assert!(
        report
            .resource_limits
            .is_reached(ResourceLimit::ForensicRecords)
    );
    assert_evidence(&report, &[1, 2, 3]);
    assert!(!report.collection_complete());
    Ok(())
}

#[test]
fn saturation_stops_chains_missing_events() -> TestResult {
    let limits = SurveyLimits::default().with_forensic_records(3)?;
    let mut survey = Survey::with_limits(limits);
    for bytes in [
        arp(FIRST_MAC, FIRST_MAC, ADDRESS),
        arp(SECOND_MAC, SECOND_MAC, ADDRESS),
        arp(CLIENT_MAC, CLIENT_MAC, ADDRESS),
        traffic(SECOND_MAC, ADDRESS),
    ] {
        survey.observe(&captured(bytes, 0)?)?;
    }
    let report = survey.finish(&Policy::default())?;
    let change = report
        .forensics
        .arp_changes
        .first()
        .ok_or("missing retained change")?;
    assert_eq!(change.followup_packet, None);
    assert!(
        report
            .resource_limits
            .is_reached(ResourceLimit::ForensicRecords)
    );
    assert_evidence(&report, &[1, 2]);
    Ok(())
}

#[test]
fn evidence_saturation_new_facts_chains() -> TestResult {
    let limits = SurveyLimits::default().with_evidence_references(2)?;
    let mut survey = Survey::with_limits(limits);
    for bytes in [
        arp(FIRST_MAC, FIRST_MAC, ADDRESS),
        arp(SECOND_MAC, SECOND_MAC, ADDRESS),
        traffic(SECOND_MAC, ADDRESS),
    ] {
        survey.observe(&captured(bytes, 0)?)?;
    }
    let report = survey.finish(&Policy::default())?;
    let change = report
        .forensics
        .arp_changes
        .first()
        .ok_or("missing change")?;
    // A packet without a retained reference cannot become the proof for a later event
    assert_eq!(change.followup_packet, None);
    assert_eq!(
        report.forensics.communications,
        [] as [l2_audit::IpCommunication; 0]
    );
    assert_eq!(report.forensics.ip_frames_parsed, 1);
    assert_eq!(report.evidence_refs.len(), 2);
    assert!(
        report
            .resource_limits
            .is_reached(ResourceLimit::EvidenceReferences)
    );
    assert!(!report.collection_complete());
    Ok(())
}

#[test]
fn forensic_limit_bounded_positive_value() {
    assert!(SurveyLimits::default().with_forensic_records(0).is_err());
    assert!(
        SurveyLimits::default()
            .with_forensic_records(65_536)
            .is_ok()
    );
    assert!(
        SurveyLimits::default()
            .with_forensic_records(65_537)
            .is_err()
    );
}
