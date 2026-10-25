use std::error::Error;

pub use wifi_lab::LabError;
use wifi_lab::{CaptureInput, LabLimits, RawCapture, VirtualAir, VirtualRadio};

pub mod limits_model {
    include!("../src/limits.rs");

    #[test]
    fn invalid_lab_limits() {
        let limits = LabLimits {
            radios: 0,
            windows: 1,
            records: 1,
            frame_bytes: 1,
            channels: 1,
            input_bytes: 1,
            observations: 1,
            observed_bytes: 1,
        };
        assert!(limits.validate().is_err());
    }
}

#[test]
fn radio_records_bounded_before_mutation() -> Result<(), Box<dyn Error>> {
    let limits = LabLimits::new(1, 2, 2, 32, 2)?;
    let mut air = VirtualAir::with_limits(limits)?;
    air.add_radio(VirtualRadio::new(1))?;
    assert_eq!(
        air.add_radio(VirtualRadio::new(2)),
        Err(LabError::RadioLimit { maximum: 1 })
    );
    air.add_record(RawCapture::new(0, 2_412, CaptureInput::ieee80211([1])))?;
    air.add_record(RawCapture::new(1, 2_437, CaptureInput::radiotap([2])))?;
    assert_eq!(
        air.add_record(RawCapture::new(2, 2_462, CaptureInput::ieee80211([3]),)),
        Err(LabError::RecordLimit { maximum: 2 })
    );
    assert_eq!(air.records().len(), 2);
    Ok(())
}

#[test]
fn radio_window_budget_checked_add() -> Result<(), Box<dyn Error>> {
    let limits = LabLimits::new(2, 1, 4, 32, 1)?;
    let mut air = VirtualAir::with_limits(limits)?;
    let mut radio = VirtualRadio::new(4);
    radio.tune(0, 1, 2_412)?;
    radio.tune(1, 2, 2_437)?;
    assert_eq!(
        air.add_radio(radio),
        Err(LabError::WindowLimit { maximum: 1 })
    );
    assert!(air.radios().is_empty());
    Ok(())
}

#[test]
fn frame_byte_budget_oversized() -> Result<(), Box<dyn Error>> {
    let limits = LabLimits::new(1, 1, 1, 2, 1)?;
    let mut air = VirtualAir::with_limits(limits)?;
    assert_eq!(
        air.add_record(RawCapture::new(
            0,
            2_412,
            CaptureInput::ieee80211([1, 2, 3]),
        )),
        Err(LabError::FrameTooLarge {
            maximum: 2,
            actual: 3
        })
    );
    assert_eq!(
        air.add_record(RawCapture::new(1, 2_412, CaptureInput::ieee80211([1, 2]),)),
        Ok(0)
    );
    assert_eq!(air.records().len(), 1);
    Ok(())
}

#[test]
fn invalid_runtime_limits_are_rejected() {
    assert_eq!(
        LabLimits::new(0, 1, 1, 1, 1),
        Err(LabError::InvalidLimit {
            field: "radios",
            value: 0,
            maximum: wifi_lab::MAX_RADIOS,
        })
    );
    assert!(
        LabLimits::new(
            wifi_lab::MAX_RADIOS,
            wifi_lab::MAX_WINDOWS,
            wifi_lab::MAX_RECORDS,
            wifi_lab::MAX_FRAME_BYTES,
            wifi_lab::MAX_CHANNELS,
        )
        .is_ok()
    );
}

#[test]
fn total_input_bytes_bounded_storage() -> Result<(), Box<dyn Error>> {
    let limits = LabLimits::new(1, 1, 2, 4, 1)?.with_storage_limits(3, 2, 8)?;
    let mut air = VirtualAir::with_limits(limits)?;
    air.add_capture(0, 2_412, CaptureInput::ieee80211([1, 2]))?;

    assert_eq!(
        air.add_capture(1, 2_412, CaptureInput::ieee80211([3, 4])),
        Err(LabError::InputByteLimit {
            maximum: 3,
            attempted: 4,
        })
    );
    assert_eq!(air.records().len(), 1);
    air.add_capture(2, 2_412, CaptureInput::ieee80211([3]))?;
    assert_eq!(air.records().len(), 2);
    Ok(())
}

#[test]
fn observation_count_bounded_delivery() -> Result<(), Box<dyn Error>> {
    let limits = LabLimits::new(2, 2, 1, 4, 1)?.with_storage_limits(4, 1, 8)?;
    let mut air = VirtualAir::with_limits(limits)?;
    for radio_id in [1, 2] {
        let mut radio = VirtualRadio::new(radio_id);
        radio.tune(0, 2, 2_412)?;
        air.add_radio(radio)?;
    }
    air.add_capture(1, 2_412, CaptureInput::ieee80211([1, 2]))?;

    assert_eq!(
        air.run(),
        Err(LabError::ObservationLimit {
            maximum: 1,
            attempted: 2,
        })
    );

    let exact_limits = LabLimits::new(1, 1, 1, 4, 1)?.with_storage_limits(4, 1, 8)?;
    let mut exact = VirtualAir::with_limits(exact_limits)?;
    let mut radio = VirtualRadio::new(1);
    radio.tune(0, 2, 2_412)?;
    exact.add_radio(radio)?;
    exact.add_capture(1, 2_412, CaptureInput::ieee80211([1, 2]))?;
    assert!(exact.run().is_ok());
    Ok(())
}

#[test]
fn delivered_bytes_bounded_cloning() -> Result<(), Box<dyn Error>> {
    let limits = LabLimits::new(2, 2, 1, 4, 1)?.with_storage_limits(4, 2, 3)?;
    let mut air = VirtualAir::with_limits(limits)?;
    for radio_id in [1, 2] {
        let mut radio = VirtualRadio::new(radio_id);
        radio.tune(0, 2, 2_412)?;
        air.add_radio(radio)?;
    }
    air.add_capture(1, 2_412, CaptureInput::ieee80211([1, 2]))?;

    assert_eq!(
        air.run(),
        Err(LabError::ObservedByteLimit {
            maximum: 3,
            attempted: 4,
        })
    );

    let exact_limits = LabLimits::new(1, 1, 1, 4, 1)?.with_storage_limits(4, 1, 2)?;
    let mut exact = VirtualAir::with_limits(exact_limits)?;
    let mut radio = VirtualRadio::new(1);
    radio.tune(0, 2, 2_412)?;
    exact.add_radio(radio)?;
    exact.add_capture(1, 2_412, CaptureInput::ieee80211([1, 2]))?;
    assert!(exact.run().is_ok());
    Ok(())
}

#[test]
fn storage_limits_zero_absolute_overflow() -> Result<(), Box<dyn Error>> {
    let limits = LabLimits::new(1, 1, 1, 1, 1)?;
    assert_eq!(
        limits.with_storage_limits(0, 1, 1),
        Err(LabError::InvalidLimit {
            field: "input bytes",
            value: 0,
            maximum: wifi_lab::MAX_INPUT_BYTES,
        })
    );
    assert_eq!(
        limits.with_storage_limits(1, wifi_lab::MAX_OBSERVATIONS + 1, 1),
        Err(LabError::InvalidLimit {
            field: "observations",
            value: wifi_lab::MAX_OBSERVATIONS + 1,
            maximum: wifi_lab::MAX_OBSERVATIONS,
        })
    );
    Ok(())
}
