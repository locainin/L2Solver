use std::error::Error;

use wifi_lab::{CaptureInput, VirtualAir, VirtualRadio};

#[test]
fn same_frequency_per_radio_evidence() -> Result<(), Box<dyn Error>> {
    let mut air = VirtualAir::new();
    let mut first = VirtualRadio::new(1);
    first.tune(0, 100, 2_412)?;
    let mut second = VirtualRadio::new(2);
    second.tune(50, 150, 2_412)?;
    air.add_radio(first)?;
    air.add_radio(second)?;
    air.add_record(wifi_lab::RawCapture::new(
        75,
        2_412,
        CaptureInput::ieee80211([0xaa, 0xbb]),
    ))?;

    let report = air.run()?;
    assert_eq!(report.observations().len(), 2);
    assert_eq!(report.accounting().captured_records(), 1);
    assert_eq!(report.accounting().observation_count(), 2);
    assert!(report.losses().is_empty());
    let radios = report.radio_accounting();
    assert_eq!(radios.len(), 2);
    let first_stats = radios.first().ok_or("missing first radio")?;
    let second_stats = radios.get(1).ok_or("missing second radio")?;
    assert_eq!(first_stats.radio_id(), 1);
    assert_eq!(first_stats.scheduled_ns(), 100);
    assert_eq!(first_stats.tuned_ns(), 100);
    assert_eq!(first_stats.captured_records(), 1);
    assert_eq!(first_stats.missed_records(), 0);
    assert_eq!(first_stats.observation_count(), 1);
    assert_eq!(second_stats.radio_id(), 2);
    assert_eq!(second_stats.scheduled_ns(), 100);
    assert_eq!(second_stats.tuned_ns(), 100);
    assert_eq!(second_stats.captured_records(), 1);
    assert_eq!(second_stats.missed_records(), 0);
    assert_eq!(second_stats.observation_count(), 1);
    Ok(())
}

#[test]
fn missed_record_is_accounted_globally() -> Result<(), Box<dyn Error>> {
    let mut air = VirtualAir::new();
    let mut matching = VirtualRadio::new(4);
    matching.tune(0, 10, 2_437)?;
    let mut idle = VirtualRadio::new(9);
    idle.tune(0, 10, 2_412)?;
    air.add_radio(matching)?;
    air.add_radio(idle)?;
    air.add_record(wifi_lab::RawCapture::new(
        5,
        2_437,
        CaptureInput::radiotap([0, 0, 0, 0]),
    ))?;

    let report = air.run()?;
    assert_eq!(report.accounting().captured_records(), 1);
    assert_eq!(report.accounting().lost_records(), 0);
    let radio_stats = report.radio_accounting();
    let idle_stats = radio_stats
        .iter()
        .find(|item| item.radio_id() == 9)
        .ok_or("missing idle radio")?;
    assert_eq!(idle_stats.captured_records(), 0);
    assert_eq!(idle_stats.missed_records(), 1);
    assert_eq!(idle_stats.observation_count(), 0);
    Ok(())
}
