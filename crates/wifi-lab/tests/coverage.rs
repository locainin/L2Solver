use std::error::Error;

use wifi_discovery::{ObservationStatus, Survey, SurveyError, SurveyLimits};
use wifi_lab::{CaptureInput, ChannelDwell, CoverageInput, VirtualAir, VirtualRadio};

#[test]
fn coverage_reports_dwell_and_discovery() -> Result<(), Box<dyn Error>> {
    let mut air = VirtualAir::new();
    let mut radio = VirtualRadio::new(11);
    radio.tune(0, 400, 2_412)?;
    radio.tune(400, 500, 2_437)?;
    air.add_radio(radio)?;
    air.add_record(wifi_lab::RawCapture::new(
        25,
        2_412,
        CaptureInput::ieee80211([0x08, 0, 0, 0]),
    ))?;

    let report = air.run()?;
    let coverage = report.coverage_inputs();
    assert_eq!(coverage.len(), 1);
    let input = coverage.first().ok_or("missing coverage")?;
    assert_eq!(input.radio_id(), 11);
    assert_eq!(input.total_scheduled_ns(), 500);
    assert_eq!(input.dwell_ns(), 500);
    assert_eq!(input.channels().len(), 2);
    let first_channel = input.channels().first().ok_or("missing first channel")?;
    let second_channel = input.channels().get(1).ok_or("missing second channel")?;
    assert_eq!(first_channel.frequency_mhz(), 2_412);
    assert_eq!(first_channel.dwell_ns(), 400);
    assert_eq!(second_channel.frequency_mhz(), 2_437);
    assert_eq!(second_channel.dwell_ns(), 100);
    assert_eq!(input.coverage_basis_points(), 10_000);

    let mut survey = Survey::new(SurveyLimits::default())?;
    report.apply_coverage_to(&mut survey)?;
    let applied = survey.channel_coverage(11)?;
    assert_eq!(applied.total_scheduled_ns(), 500);
    assert_eq!(applied.observed_ns(), 500);
    assert_eq!(applied.channels().len(), 2);
    Ok(())
}

#[test]
fn captured_inputs_reach_discovery_directly() -> Result<(), Box<dyn Error>> {
    let mut air = VirtualAir::new();
    let mut radio = VirtualRadio::new(5);
    radio.tune(0, 10, 2_412)?;
    air.add_radio(radio)?;
    air.add_capture(2, 2_412, CaptureInput::ieee80211([0x08, 0, 0, 0]))?;

    let report = air.run()?;
    let frame = report
        .observations()
        .first()
        .ok_or("missing bridged capture")?;
    let mut survey = Survey::new(SurveyLimits::default())?;
    assert_eq!(
        survey.observe(frame.wireless_input(), frame.context()),
        ObservationStatus::Malformed
    );
    Ok(())
}

#[test]
fn empty_radio_explicit_zero_coverage() -> Result<(), Box<dyn Error>> {
    let mut air = VirtualAir::new();
    air.add_radio(VirtualRadio::new(1))?;
    let report = air.run()?;
    let input = report
        .coverage_inputs()
        .first()
        .ok_or("missing empty-radio coverage")?;
    assert_eq!(input.total_scheduled_ns(), 0);
    assert_eq!(input.dwell_ns(), 0);
    assert_eq!(input.coverage_basis_points(), 0);
    Ok(())
}

#[test]
fn schedule_horizon_excludes_untuned_time() -> Result<(), Box<dyn Error>> {
    let mut radio = wifi_lab::VirtualRadio::new(8);
    radio.tune(100, 300, 2_412)?;
    assert_eq!(radio.set_scheduled_ns(200), Ok(()));
    assert_eq!(radio.scheduled_ns(), 200);
    assert_eq!(
        radio.set_scheduled_ns(199),
        Err(wifi_lab::LabError::DwellExceedsSchedule {
            radio: 8,
            dwell_ns: 200,
            scheduled_ns: 199,
        })
    );
    radio.set_scheduled_ns(400)?;

    let input = radio.coverage_input()?;
    assert_eq!(input.total_scheduled_ns(), 400);
    assert_eq!(input.dwell_ns(), 200);
    assert_eq!(input.coverage_basis_points(), 5_000);
    Ok(())
}

#[test]
fn failed_coverage_leaves_survey_unchanged() -> Result<(), Box<dyn Error>> {
    let input = CoverageInput::new(
        7,
        200,
        vec![ChannelDwell::new(2_412, 100), ChannelDwell::new(2_437, 100)],
    )?;
    let mut survey = Survey::new(SurveyLimits::new(8, 8, 8, 1)?)?;

    assert_eq!(
        input.apply_to(&mut survey),
        Err(SurveyError::ChannelLimit { maximum: 1 })
    );
    assert_eq!(
        survey.channel_coverage(7),
        Err(SurveyError::UnknownRadio(7))
    );
    Ok(())
}

#[test]
fn failed_multi_leaves_survey_unchanged() -> Result<(), Box<dyn Error>> {
    let mut air = VirtualAir::new();
    let mut first = VirtualRadio::new(7);
    first.tune(0, 100, 2_412)?;
    air.add_radio(first)?;
    let mut second = VirtualRadio::new(8);
    second.tune(0, 100, 2_437)?;
    air.add_radio(second)?;
    let report = air.run()?;
    let mut survey = Survey::new(SurveyLimits::new(8, 8, 8, 1)?)?;

    assert_eq!(
        report.apply_coverage_to(&mut survey),
        Err(SurveyError::ChannelLimit { maximum: 1 })
    );
    assert_eq!(
        survey.channel_coverage(7),
        Err(SurveyError::UnknownRadio(7))
    );
    assert_eq!(
        survey.channel_coverage(8),
        Err(SurveyError::UnknownRadio(8))
    );
    Ok(())
}
