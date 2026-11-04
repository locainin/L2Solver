use wifi_discovery::{Survey, SurveyError, SurveyLimits, WirelessInput};

use super::common::{AP, context};
use super::frames::{beacon_frame, radiotap_at, rsn_psk};

#[test]
fn dwell_tracks_observed_time() -> Result<(), Box<dyn std::error::Error>> {
    let mut survey = Survey::new(SurveyLimits::default())?;
    survey.record_radio_schedule(2, 1_000)?;
    survey.record_channel_dwell(2, 2_412, 400)?;
    survey.record_channel_dwell(2, 2_437, 100)?;

    let coverage = survey.channel_coverage(2)?;

    assert_eq!(coverage.total_scheduled_ns(), 1_000);
    assert_eq!(coverage.observed_ns(), 500);
    assert_eq!(coverage.coverage_basis_points(), 5_000);
    assert_eq!(coverage.radio(), 2);
    assert_eq!(coverage.channels().len(), 2);
    let [first, second] = coverage.channels() else {
        return Err("unexpected channel count".into());
    };
    assert_eq!(first.frequency_mhz(), 2_412);
    assert_eq!(first.dwell_ns(), 400);
    assert_eq!(second.frequency_mhz(), 2_437);
    assert_eq!(second.dwell_ns(), 100);
    Ok(())
}

#[test]
fn dwell_respects_schedule() -> Result<(), Box<dyn std::error::Error>> {
    let mut survey = Survey::new(SurveyLimits::default())?;
    survey.record_radio_schedule(1, 100)?;

    assert_eq!(
        survey.record_channel_dwell(1, 2_412, 101),
        Err(SurveyError::DwellExceedsSchedule {
            radio: 1,
            observed_ns: 101,
            scheduled_ns: 100
        })
    );
    Ok(())
}

#[test]
fn zero_frequency_without_changing_coverage() -> Result<(), Box<dyn std::error::Error>> {
    let mut survey = Survey::new(SurveyLimits::default())?;
    survey.record_radio_schedule(1, 100)?;

    assert_eq!(
        survey.record_channel_dwell(1, 0, 100),
        Err(SurveyError::InvalidFrequency { frequency_mhz: 0 })
    );
    let coverage = survey.channel_coverage(1)?;
    assert_eq!(coverage.observed_ns(), 0);
    assert_eq!(coverage.channels(), []);
    Ok(())
}

#[test]
fn schedule_rejects_unknown_and_overflow() -> Result<(), Box<dyn std::error::Error>> {
    let limits = SurveyLimits::new(4, 4, 4, 1)?;
    let mut survey = Survey::new(limits)?;
    assert_eq!(
        survey.record_channel_dwell(1, 2_412, 1),
        Err(SurveyError::UnknownRadio(1))
    );
    survey.record_radio_schedule(1, 100)?;
    survey.record_channel_dwell(1, 2_412, 100)?;
    assert_eq!(survey.record_radio_schedule(1, 100), Ok(()));
    assert_eq!(
        survey.record_radio_schedule(1, 99),
        Err(SurveyError::DwellExceedsSchedule {
            radio: 1,
            observed_ns: 100,
            scheduled_ns: 99,
        })
    );
    assert_eq!(
        survey.record_channel_dwell(1, 2_437, 0),
        Err(SurveyError::ChannelLimit { maximum: 1 })
    );
    assert!(!survey.inventory_incomplete());
    Ok(())
}

#[test]
fn unordered_radio_schedules_remain_atomic() -> Result<(), Box<dyn std::error::Error>> {
    let limits = SurveyLimits::new(4, 4, 4, 3)?;
    let mut survey = Survey::new(limits)?;
    survey.record_radio_schedule(9, 100)?;
    survey.record_radio_schedule(2, 50)?;
    survey.record_radio_schedule(5, 30)?;

    // Existing radios can still be updated when the schedule budget is full
    survey.record_radio_schedule(2, 40)?;
    survey.record_channel_dwell(9, 2_437, 20)?;

    assert_eq!(
        survey.record_radio_schedule(9, 19),
        Err(SurveyError::DwellExceedsSchedule {
            radio: 9,
            observed_ns: 20,
            scheduled_ns: 19,
        })
    );
    assert_eq!(
        survey.record_radio_schedule(4, 10),
        Err(SurveyError::ChannelLimit { maximum: 3 })
    );

    let radio_9 = survey.channel_coverage(9)?;
    assert_eq!(radio_9.total_scheduled_ns(), 100);
    assert_eq!(radio_9.observed_ns(), 20);
    assert_eq!(radio_9.channels().len(), 1);

    let radio_2 = survey.channel_coverage(2)?;
    assert_eq!(radio_2.total_scheduled_ns(), 40);
    assert_eq!(radio_2.observed_ns(), 0);
    assert_eq!(radio_2.channels(), []);

    let radio_5 = survey.channel_coverage(5)?;
    assert_eq!(radio_5.total_scheduled_ns(), 30);
    assert_eq!(radio_5.observed_ns(), 0);
    assert_eq!(radio_5.channels(), []);
    Ok(())
}

#[test]
fn channel_numbers_follow_frequency() -> Result<(), Box<dyn std::error::Error>> {
    let cases = [
        (2_417, Some(2)),
        (2_484, Some(14)),
        (5_180, Some(36)),
        (5_960, Some(2)),
        (9_999, None),
    ];
    for (frequency, expected) in cases {
        let elements = rsn_psk(0, false);
        let frame = beacon_frame(AP, b"Corp", 0x0010, None, &elements);
        let mut survey = Survey::new(SurveyLimits::default())?;
        survey.observe(
            WirelessInput::Radiotap(&radiotap_at(&frame, frequency)),
            context(u64::from(frequency)),
        );
        let access_point = survey
            .access_points()
            .next()
            .ok_or("missing access point")?;
        assert_eq!(access_point.channel(), expected);
    }
    Ok(())
}
