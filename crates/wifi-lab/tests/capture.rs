use std::error::Error;

use wifi_lab::{
    CaptureInput, CaptureReport, LinkType, LossReason, RawCapture, VirtualAir, VirtualRadio,
};

fn ieee(bytes: &[u8]) -> CaptureInput {
    CaptureInput::ieee80211(bytes)
}

fn tuned_window_report() -> Result<CaptureReport, Box<dyn Error>> {
    let mut air = VirtualAir::new();
    let mut radio = VirtualRadio::new(1);
    radio.tune(100, 200, 2_412)?;
    air.add_radio(radio)?;
    assert_eq!(air.radios().len(), 1);
    assert!(air.radio(1).is_some());
    assert!(air.radio(9).is_none());
    air.add_record(RawCapture::new(99, 2_412, ieee(&[1, 2, 3])))?;
    air.add_record(RawCapture::new(100, 2_412, ieee(&[4, 5])))?;
    air.add_record(RawCapture::new(199, 2_412, ieee(&[6])))?;
    air.add_record(RawCapture::new(200, 2_412, ieee(&[7])))?;
    air.add_record(RawCapture::new(150, 2_437, ieee(&[8])))?;
    Ok(air.run()?)
}

#[test]
fn accounts_tuned_window() -> Result<(), Box<dyn Error>> {
    let report = tuned_window_report()?;
    assert_eq!(report.observations().len(), 2);
    assert_eq!(report.losses().len(), 3);
    assert_eq!(report.accounting().offered_records(), 5);
    assert_eq!(report.accounting().captured_records(), 2);
    assert_eq!(report.accounting().lost_records(), 3);
    assert_eq!(report.accounting().observation_count(), 2);
    assert_eq!(report.accounting().observed_bytes(), 3);
    Ok(())
}

#[test]
fn captures_tuned_window_frames() -> Result<(), Box<dyn Error>> {
    let report = tuned_window_report()?;
    let first = report
        .observations()
        .first()
        .ok_or("missing first capture")?;
    let second = report
        .observations()
        .get(1)
        .ok_or("missing second capture")?;
    assert_eq!(first.timestamp_ns(), 100);
    assert_eq!(second.timestamp_ns(), 199);
    assert_eq!(first.radio_id(), 1);
    assert_eq!(first.sequence(), 1);
    assert_eq!(first.frequency_mhz(), 2_412);
    assert_eq!(first.observation_context().sequence(), 1);
    assert_eq!(first.context().monotonic_ns(), Some(100));
    assert_eq!(first.input().link_type(), LinkType::Ieee80211);
    assert_eq!(first.input().bytes(), &[4, 5]);
    assert_eq!(second.input().bytes(), &[6]);
    Ok(())
}

#[test]
fn reports_tuned_window_losses() -> Result<(), Box<dyn Error>> {
    let report = tuned_window_report()?;
    let outside = report
        .losses()
        .iter()
        .find(|loss| loss.reason() == LossReason::OutsideDwell)
        .ok_or("missing outside-dwell loss")?;
    assert_eq!(outside.sequence(), 0);
    assert_eq!(outside.timestamp_ns(), 99);
    assert_eq!(outside.frequency_mhz(), 2_412);
    let wrong_frequency = report
        .losses()
        .iter()
        .find(|loss| loss.reason() == LossReason::FrequencyNotTuned)
        .ok_or("missing frequency loss")?;
    assert_eq!(wrong_frequency.sequence(), 4);
    assert_eq!(wrong_frequency.timestamp_ns(), 150);
    assert_eq!(wrong_frequency.frequency_mhz(), 2_437);
    Ok(())
}

#[test]
fn equal_timestamps_source_sequence_radio() -> Result<(), Box<dyn Error>> {
    let mut air = VirtualAir::new();
    let mut high = VirtualRadio::new(20);
    high.tune(0, 10, 2_412)?;
    let mut low = VirtualRadio::new(2);
    low.tune(0, 10, 2_412)?;
    air.add_radio(high)?;
    air.add_radio(low)?;
    air.add_record(RawCapture::new(5, 2_412, ieee(&[1])))?;
    air.add_record(RawCapture::new(5, 2_412, ieee(&[2])))?;

    let report = air.run()?;
    let observations = report.observations();
    assert_eq!(observations.len(), 4);
    let first = observations.first().ok_or("missing first capture")?;
    let second = observations.get(1).ok_or("missing second capture")?;
    let third = observations.get(2).ok_or("missing third capture")?;
    let fourth = observations.get(3).ok_or("missing fourth capture")?;
    assert_eq!((first.radio_id(), first.sequence()), (2, 0));
    assert_eq!((second.radio_id(), second.sequence()), (20, 0));
    assert_eq!((third.radio_id(), third.sequence()), (2, 1));
    assert_eq!((fourth.radio_id(), fourth.sequence()), (20, 1));
    Ok(())
}

#[test]
fn empty_input_preserved_downstream_parser() -> Result<(), Box<dyn Error>> {
    assert_eq!(CaptureInput::ieee80211([1, 2]).into_bytes(), vec![1, 2]);
    assert_eq!(CaptureInput::radiotap([3]).into_bytes(), vec![3]);

    let mut air = VirtualAir::new();
    let mut radio = VirtualRadio::new(1);
    radio.tune(0, 1, 2_412)?;
    air.add_radio(radio)?;
    air.add_record(RawCapture::new(0, 2_412, CaptureInput::radiotap([])))?;

    let report = air.run()?;
    let observation = report
        .observations()
        .first()
        .ok_or("missing malformed capture")?;
    assert_eq!(
        observation.input().link_type(),
        wifi_lab::LinkType::Radiotap
    );
    assert_eq!(observation.input().bytes(), []);
    Ok(())
}

#[test]
fn unregistered_air_reports_loss() -> Result<(), Box<dyn Error>> {
    let mut air = VirtualAir::new();
    air.add_record(RawCapture::new(
        5,
        2_412,
        CaptureInput::ieee80211([0x08, 0, 0, 0]),
    ))?;

    let report = air.run()?;
    assert_eq!(report.observations(), []);
    let loss = report.losses().first().ok_or("missing no-radio loss")?;
    assert_eq!(loss.reason(), LossReason::NoRadio);
    assert_eq!(report.accounting().captured_records(), 0);
    assert_eq!(report.accounting().lost_records(), 1);
    Ok(())
}
