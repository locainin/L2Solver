use super::support::*;
use l2_audit::{Policy, ResourceLimit, Survey, SurveyLimits};

const fn retained_record_count(report: &l2_audit::Report) -> usize {
    report.forensics.communications.len()
        + report.forensics.arp_observations.len()
        + report.forensics.arp_changes.len()
        + report.forensics.trailing_data.len()
        + report.forensics.dns_observations.len()
        + report.forensics.dns_matches.len()
        + report.forensics.dns_address_uses.len()
}

#[test]
fn dns_message_tracking_actual_omission() -> TestResult {
    assert!(SurveyLimits::default().with_dns_messages(0).is_err());
    assert!(SurveyLimits::default().with_dns_messages(4096).is_ok());
    assert!(SurveyLimits::default().with_dns_messages(4097).is_err());
    let question = standard_question()?;
    let mut survey = Survey::with_limits(SurveyLimits::default().with_dns_messages(1)?);
    survey.observe(&captured(query(70, std::slice::from_ref(&question))?, 0)?)?;
    survey.observe(&captured(
        response(
            70,
            std::slice::from_ref(&question),
            &[address_record(pointer_to_question(), ANSWER)],
            0x8180,
            &[],
            &[],
        )?,
        0,
    )?)?;
    survey.observe(&captured(client_use(CLIENT, ANSWER)?, 0)?)?;
    let report = survey.finish(&Policy::default())?;
    assert_eq!(report.forensics.dns_candidates_seen, 2);
    assert_eq!(report.forensics.dns_messages_parsed, 2);
    assert_eq!(report.forensics.dns_observations.len(), 1);
    assert!(report.forensics.dns_matches.is_empty());
    assert!(report.forensics.dns_address_uses.is_empty());
    assert!(
        report
            .resource_limits
            .is_reached(ResourceLimit::DnsMessages)
    );
    assert!(!report.collection_complete());
    Ok(())
}
#[test]
fn dns_facts_share_forensic_budget() -> TestResult {
    let question = standard_question()?;
    let limits = SurveyLimits::default().with_forensic_records(1)?;
    let mut survey = Survey::with_limits(limits);
    survey.observe(&captured(query(71, std::slice::from_ref(&question))?, 0)?)?;
    survey.observe(&captured(
        response(71, std::slice::from_ref(&question), &[], 0x8180, &[], &[])?,
        0,
    )?)?;
    let report = survey.finish(&Policy::default())?;
    assert_eq!(report.forensics.dns_observations.len(), 1);
    assert!(report.forensics.dns_matches.is_empty());
    assert!(retained_record_count(&report) <= 1);
    assert!(
        report
            .resource_limits
            .is_reached(ResourceLimit::ForensicRecords)
    );
    assert!(!report.collection_complete());
    Ok(())
}

#[test]
fn dns_observations_share_forensic_budget() -> TestResult {
    let question = standard_question()?;
    let limits = SurveyLimits::default().with_forensic_records(7)?;
    let mut survey = Survey::with_limits(limits);
    survey.observe(&captured(query(73, std::slice::from_ref(&question))?, 0)?)?;
    survey.observe(&captured(
        response(
            73,
            std::slice::from_ref(&question),
            &[address_record(pointer_to_question(), ANSWER)],
            0x8180,
            &[],
            &[],
        )?,
        0,
    )?)?;
    survey.observe(&captured(client_use(CLIENT, ANSWER)?, 0)?)?;
    survey.observe(&captured(client_use(OTHER_CLIENT, ANSWER)?, 0)?)?;

    let report = survey.finish(&Policy::default())?;
    assert_eq!(
        (
            report.forensics.communications.len(),
            report.forensics.dns_observations.len(),
            report.forensics.dns_matches.len(),
            report.forensics.dns_address_uses.len(),
        ),
        (3, 2, 1, 1)
    );
    assert_eq!(retained_record_count(&report), 7);
    assert!(
        report
            .resource_limits
            .is_reached(ResourceLimit::ForensicRecords)
    );
    Ok(())
}

#[test]
fn missing_evidence_referencing_unretained_packets() -> TestResult {
    let question = standard_question()?;
    let limits = SurveyLimits::default().with_evidence_references(2)?;
    let mut survey = Survey::with_limits(limits);
    survey.observe(&captured(query(72, std::slice::from_ref(&question))?, 0)?)?;
    survey.observe(&captured(
        response(
            72,
            std::slice::from_ref(&question),
            &[address_record(pointer_to_question(), ANSWER)],
            0x8180,
            &[],
            &[],
        )?,
        0,
    )?)?;
    survey.observe(&captured(client_use(CLIENT, ANSWER)?, 0)?)?;
    let report = survey.finish(&Policy::default())?;
    assert_eq!(report.evidence_refs.len(), 2);
    assert_eq!(report.forensics.dns_matches.len(), 1);
    assert!(report.forensics.dns_address_uses.is_empty());
    assert!(
        report
            .resource_limits
            .is_reached(ResourceLimit::EvidenceReferences)
    );
    assert!(!report.collection_complete());
    Ok(())
}
