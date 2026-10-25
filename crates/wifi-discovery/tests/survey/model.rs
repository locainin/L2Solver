use wifi_discovery::{
    ObservationContext, PmfStatus, SecurityEvidence, SecurityMode, Survey, SurveyError,
    SurveyLimits,
};

#[test]
fn context_retains_clock() {
    let value = ObservationContext::new(7, 99);
    assert_eq!(value.sequence(), 7);
    assert_eq!(value.monotonic_ns(), Some(99));

    let timeless = ObservationContext::without_time(8);
    assert_eq!(timeless.sequence(), 8);
    assert_eq!(timeless.monotonic_ns(), None);
}

#[test]
fn errors_render() {
    assert_eq!(
        SurveyError::InvalidLimit {
            field: "stations",
            value: 0,
            maximum: 65_536,
        }
        .to_string(),
        "wireless survey stations limit 0 is outside 1..=65536"
    );
    assert_eq!(
        SurveyError::UnknownRadio(3).to_string(),
        "wireless radio 3 has no schedule"
    );
    assert_eq!(
        SurveyError::ChannelLimit { maximum: 4 }.to_string(),
        "wireless channel records exceed limit 4"
    );
    assert_eq!(
        SurveyError::ArithmeticOverflow.to_string(),
        "wireless survey arithmetic overflow"
    );
    assert_eq!(
        SurveyError::DwellExceedsSchedule {
            radio: 3,
            observed_ns: 101,
            scheduled_ns: 100,
        }
        .to_string(),
        "radio 3 dwell 101 ns exceeds schedule 100 ns"
    );
}

#[test]
fn limits_accept_bounds() -> Result<(), Box<dyn std::error::Error>> {
    assert!(SurveyLimits::new(0, 1, 1, 1).is_err());
    assert!(SurveyLimits::new(4_097, 1, 1, 1).is_err());
    assert!(SurveyLimits::new(1, 0, 1, 1).is_err());
    assert!(SurveyLimits::new(1, 65_537, 1, 1).is_err());
    assert!(SurveyLimits::new(1, 1, 0, 1).is_err());
    assert!(SurveyLimits::new(1, 1, 4_097, 1).is_err());
    assert!(SurveyLimits::new(1, 1, 1, 0).is_err());
    assert!(SurveyLimits::new(1, 1, 1, 1_025).is_err());

    let limits = SurveyLimits::new(4_096, 65_536, 4_096, 1_024)?;
    let survey = Survey::new(limits)?;
    assert!(!survey.inventory_incomplete());
    Ok(())
}

#[test]
fn evidence_merges_conservatively() {
    let left = SecurityEvidence::new(SecurityMode::Open, false, false, PmfStatus::Capable);
    let right = SecurityEvidence::new(SecurityMode::Wpa2Personal, true, true, PmfStatus::Required);
    let merged = left.merged(right);
    assert!(!left.tkip());
    assert!(!left.wps());
    assert_eq!(merged.mode(), SecurityMode::Open);
    assert!(merged.tkip());
    assert!(merged.wps());
    assert_eq!(merged.pmf(), PmfStatus::Capable);
    assert!(!merged.complete());
    assert!(merged.inconsistent());

    let retained = right.merged(left);
    assert_eq!(retained.mode(), SecurityMode::Open);
    assert!(retained.tkip());
    assert!(retained.wps());
    assert_eq!(retained.pmf(), PmfStatus::Capable);
    assert!(!retained.complete());
    assert!(retained.inconsistent());
}
