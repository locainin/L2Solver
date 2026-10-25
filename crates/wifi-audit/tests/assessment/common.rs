use wifi_audit::{Assessment, Finding, Verdict, assess};
use wifi_discovery::{ObservationContext, Survey, SurveyLimits, WirelessInput};

use super::policies::policy;

// Assess one raw 802.11 frame with the standard required-PMF policy
pub fn assess_frame(frame: &[u8], sequence: u64) -> Result<Assessment, Box<dyn std::error::Error>> {
    let mut survey = Survey::new(SurveyLimits::default())?;
    survey.observe(
        WirelessInput::Ieee80211(frame),
        ObservationContext::new(sequence, 1_000),
    );
    Ok(assess(&survey, &policy()?, &[])?)
}

// Keep verdict assertions at the call site when a finding is absent or unexpected
#[track_caller]
pub fn assert_verdict(assessment: &Assessment, id: &str, expected: Verdict) {
    assert_eq!(assessment.finding(id).map(Finding::verdict), Some(expected));
}
