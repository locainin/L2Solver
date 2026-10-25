use l2_audit::{AssessmentProfile, CoverageStatus, Policy, Survey};

#[test]
fn full_profile_unseen_active_applicable() -> Result<(), Box<dyn std::error::Error>> {
    let report = Survey::new().finish_with_profile(&Policy::default(), AssessmentProfile::Full)?;
    let dtp = report
        .plan
        .entry("DTP-001")
        .ok_or("missing DTP planner entry")?;

    assert!(dtp.applicable);
    assert_eq!(dtp.coverage, CoverageStatus::NotTested);
    assert!(dtp.recommendation);
    assert_eq!(report.assessment_profile, AssessmentProfile::Full);
    Ok(())
}

#[test]
fn default_profile_requires_discovery_hint() -> Result<(), Box<dyn std::error::Error>> {
    let report = Survey::new().finish(&Policy::default())?;
    let dtp = report
        .plan
        .entry("DTP-001")
        .ok_or("missing DTP planner entry")?;

    assert!(!dtp.applicable);
    assert_eq!(dtp.coverage, CoverageStatus::NotApplicable);
    assert!(!dtp.recommendation);
    Ok(())
}
