use std::error::Error;

use wifi_lab::{DwellWindow, LabError, VirtualRadio};

#[test]
fn windows_sorted_adjacent_windows_valid() -> Result<(), Box<dyn Error>> {
    let mut radio = VirtualRadio::new(7);
    radio.add_window(DwellWindow::new(100, 200, 2_437)?)?;
    radio.add_window(DwellWindow::new(0, 100, 2_412)?)?;

    assert_eq!(radio.windows().len(), 2);
    let first = radio.windows().first().ok_or("missing first window")?;
    let second = radio.windows().get(1).ok_or("missing second window")?;
    assert_eq!(first.start_ns(), 0);
    assert_eq!(first.end_ns(), 100);
    assert_eq!(first.frequency_mhz(), 2_412);
    assert_eq!(first.duration_ns(), 100);
    assert!(first.contains(0));
    assert!(first.contains(99));
    assert!(!first.contains(100));
    assert_eq!(second.start_ns(), 100);
    assert_eq!(second.end_ns(), 200);
    assert_eq!(second.duration_ns(), 100);
    assert_eq!(radio.dwell_ns(), 200);
    assert_eq!(radio.scheduled_ns(), 200);
    Ok(())
}

#[test]
fn malformed_windows_not_mutate_radio() -> Result<(), Box<dyn Error>> {
    let mut radio = VirtualRadio::new(3);
    radio.add_window(DwellWindow::new(10, 20, 2_412)?)?;

    assert_eq!(
        DwellWindow::new(20, 10, 2_412),
        Err(LabError::WindowReversed {
            start_ns: 20,
            end_ns: 10,
        })
    );
    assert_eq!(
        DwellWindow::new(10, 10, 2_412),
        Err(LabError::ZeroLengthWindow { at_ns: 10 })
    );
    assert_eq!(
        DwellWindow::new(0, 10, 0),
        Err(LabError::InvalidFrequency { frequency_mhz: 0 })
    );
    assert_eq!(
        radio.add_window(DwellWindow::new(15, 25, 2_437)?),
        Err(LabError::WindowOverlap {
            radio: 3,
            existing_start_ns: 10,
            existing_end_ns: 20,
            requested_start_ns: 15,
            requested_end_ns: 25,
        })
    );
    assert_eq!(radio.windows().len(), 1);
    Ok(())
}

#[test]
fn duration_constructor_checks_time_overflow() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        DwellWindow::for_duration(u64::MAX - 2, 3, 2_412),
        Err(LabError::TimeOverflow)
    );
    let mut radio = VirtualRadio::new(8);
    radio.tune_for(10, 5, 2_412)?;
    assert_eq!(radio.windows().len(), 1);
    assert_eq!(
        radio
            .windows()
            .first()
            .ok_or("missing dwell window")?
            .end_ns(),
        15
    );
    Ok(())
}

#[test]
fn window_limit() -> Result<(), Box<dyn Error>> {
    let mut windows = Vec::with_capacity(wifi_lab::MAX_WINDOWS);
    for index in 0..wifi_lab::MAX_WINDOWS {
        let start = u64::try_from(index)?.saturating_mul(2);
        windows.push(DwellWindow::new(start, start + 1, 2_412)?);
    }
    let mut radio = VirtualRadio::from_windows(9, windows)?;
    assert_eq!(
        radio.add_window(DwellWindow::new(
            u64::try_from(wifi_lab::MAX_WINDOWS)?.saturating_mul(2),
            u64::try_from(wifi_lab::MAX_WINDOWS)?.saturating_mul(2) + 1,
            2_412,
        )?),
        Err(LabError::WindowLimit {
            maximum: wifi_lab::MAX_WINDOWS,
        })
    );
    Ok(())
}

#[test]
fn schedule_window_errors() {
    assert_eq!(
        LabError::InvalidFrequency { frequency_mhz: 0 }.to_string(),
        "wireless frequency 0 MHz is invalid"
    );
    assert_eq!(
        LabError::WindowReversed {
            start_ns: 20,
            end_ns: 10,
        }
        .to_string(),
        "wireless dwell window ends at 10 ns before it starts at 20 ns"
    );
    assert_eq!(
        LabError::WindowOverlap {
            radio: 3,
            existing_start_ns: 10,
            existing_end_ns: 20,
            requested_start_ns: 15,
            requested_end_ns: 25,
        }
        .to_string(),
        "radio 3 dwell 15..25 ns overlaps 10..20 ns"
    );
    assert_eq!(
        LabError::DwellExceedsSchedule {
            radio: 4,
            dwell_ns: 101,
            scheduled_ns: 100,
        }
        .to_string(),
        "radio 4 dwell 101 ns exceeds schedule 100 ns"
    );
    assert_eq!(
        LabError::ArithmeticOverflow.to_string(),
        "wireless lab arithmetic overflow"
    );
}
