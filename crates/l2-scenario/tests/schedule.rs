use l2_onpath::Budget;
use l2_scenario::{AdmissionError, Cleanup, Control, MAX_STIMULI, Schedule, Stimulus, StopReason};

#[test]
fn virtual_time_and_sequence_determine_dispatch_order() -> Result<(), Box<dyn std::error::Error>> {
    // Input order must not change the causal order of equal-time events
    let schedule = Schedule::new(
        &[
            Stimulus::new(3, 5, 80),
            Stimulus::new(2, 1, 70),
            Stimulus::new(1, 1, 60),
        ],
        Budget::new(3, 210, 5)?,
    )?;
    let mut runner = schedule.start();
    let mut observed = Vec::new();
    for _ in 0..3 {
        let Some(event) = runner.next(Control::Continue) else {
            return Err("dispatch ended before all scheduled events were returned".into());
        };
        observed.push((event.sequence(), event.at_millis(), event.frame_bytes()));
    }
    // A bounded check also catches a runner that repeats an event indefinitely
    assert!(runner.next(Control::Continue).is_none());
    assert_eq!(observed, vec![(1, 1, 60), (2, 1, 70), (3, 5, 80)]);
    let report = runner.report(Cleanup::Confirmed)?;
    assert_eq!(report.stop_reason(), StopReason::Exhausted);
    assert_eq!(
        (report.packets(), report.bytes(), report.elapsed_millis()),
        (3, 210, 5)
    );
    assert_eq!(report.cleanup(), Cleanup::Confirmed);
    Ok(())
}

#[test]
fn admission_rejects_each_resource_limit_before_any_dispatch()
-> Result<(), Box<dyn std::error::Error>> {
    let stimuli = [Stimulus::new(1, 1, 60), Stimulus::new(2, 2, 60)];
    assert_eq!(
        Schedule::new(&stimuli, Budget::new(1, 120, 2)?).err(),
        Some(AdmissionError::PacketLimit)
    );
    assert_eq!(
        Schedule::new(&stimuli, Budget::new(2, 119, 2)?).err(),
        Some(AdmissionError::ByteLimit)
    );
    assert_eq!(
        Schedule::new(&stimuli, Budget::new(2, 120, 1)?).err(),
        Some(AdmissionError::DurationLimit)
    );
    // A large frame is rejected even when the addition itself does not overflow
    assert_eq!(
        Schedule::new(&[Stimulus::new(1, 0, u64::MAX)], Budget::new(1, 120, 2)?).err(),
        Some(AdmissionError::ByteLimit)
    );
    // An oversized frame after prior usage must not wrap the cumulative byte count
    assert_eq!(
        Schedule::new(
            &[Stimulus::new(1, 0, 1), Stimulus::new(2, 0, u64::MAX)],
            Budget::new(2, 120, 2)?
        )
        .err(),
        Some(AdmissionError::ByteLimit)
    );
    Ok(())
}

#[test]
fn admission_accepts_schedule_ceiling_and_rejects_one_extra_stimulus()
-> Result<(), Box<dyn std::error::Error>> {
    let limit = u64::try_from(MAX_STIMULI)?;
    let budget = Budget::new(limit, limit, 1)?;
    let mut stimuli: Vec<_> = (1..=limit)
        .map(|sequence| Stimulus::new(sequence, 0, 1))
        .collect();

    // The ceiling is inclusive; the extra event gets a dedicated limit error
    assert!(Schedule::new(&stimuli, budget).is_ok());
    stimuli.push(Stimulus::new(limit + 1, 0, 1));
    assert_eq!(
        Schedule::new(&stimuli, budget).err(),
        Some(AdmissionError::ScheduleLimit)
    );
    Ok(())
}

#[test]
fn admission_rejects_ambiguous_or_empty_work() -> Result<(), Box<dyn std::error::Error>> {
    let budget = Budget::new(4, 500, 10)?;
    assert_eq!(
        Schedule::new(&[], budget).err(),
        Some(AdmissionError::Empty)
    );
    assert_eq!(
        Schedule::new(&[Stimulus::new(0, 1, 60)], budget).err(),
        Some(AdmissionError::InvalidStimulus)
    );
    assert_eq!(
        Schedule::new(&[Stimulus::new(1, 1, 0)], budget).err(),
        Some(AdmissionError::InvalidStimulus)
    );
    assert_eq!(
        Schedule::new(&[Stimulus::new(1, 1, 60), Stimulus::new(1, 2, 60)], budget).err(),
        Some(AdmissionError::DuplicateSequence)
    );
    Ok(())
}

#[test]
fn cancellation_stops_further_dispatch_and_keeps_cleanup_unconfirmed()
-> Result<(), Box<dyn std::error::Error>> {
    let mut runner = Schedule::new(
        &[Stimulus::new(1, 3, 60), Stimulus::new(2, 9, 80)],
        Budget::new(2, 140, 10)?,
    )?
    .start();
    assert!(
        runner.report(Cleanup::Confirmed).is_err(),
        "running work cannot be finalized"
    );
    assert!(runner.next(Control::Continue).is_some());
    assert!(runner.next(Control::Cancel).is_none());
    assert!(
        runner.next(Control::Continue).is_none(),
        "cancellation is permanent"
    );
    let report = runner.report(Cleanup::Unconfirmed)?;
    assert_eq!(report.stop_reason(), StopReason::Cancelled);
    assert_eq!(
        (report.packets(), report.bytes(), report.elapsed_millis()),
        (1, 60, 3)
    );
    assert_eq!(report.cleanup(), Cleanup::Unconfirmed);
    Ok(())
}

#[test]
fn cancellation_before_first_dispatch_has_zero_usage() -> Result<(), Box<dyn std::error::Error>> {
    let mut runner = Schedule::new(&[Stimulus::new(1, 9, 60)], Budget::new(1, 60, 10)?)?.start();
    assert!(runner.next(Control::Cancel).is_none());
    let report = runner.report(Cleanup::Confirmed)?;
    assert_eq!(
        (report.packets(), report.bytes(), report.elapsed_millis()),
        (0, 0, 0)
    );
    assert_eq!(report.stop_reason(), StopReason::Cancelled);
    Ok(())
}

#[test]
fn completion_cannot_be_rewritten_by_later_cancellation() -> Result<(), Box<dyn std::error::Error>>
{
    let mut runner = Schedule::new(&[Stimulus::new(1, 0, 60)], Budget::new(1, 60, 1)?)?.start();
    assert!(runner.next(Control::Continue).is_some());
    assert!(runner.next(Control::Cancel).is_none());
    assert_eq!(
        runner.report(Cleanup::Confirmed)?.stop_reason(),
        StopReason::Exhausted
    );
    Ok(())
}

#[test]
fn many_equal_time_events_dispatch_in_sequence_order() -> Result<(), Box<dyn std::error::Error>> {
    let stimuli: Vec<_> = (1..=128)
        .map(|sequence| Stimulus::new(sequence, sequence % 7, 1))
        .collect();
    let mut runner = Schedule::new(&stimuli, Budget::new(128, 128, 6)?)?.start();

    // Interleaved time groups exercise the sequence tie-break across the whole schedule
    for time in 0..7 {
        for sequence in (1..=128).filter(|sequence| sequence % 7 == time) {
            let Some(event) = runner.next(Control::Continue) else {
                return Err("dispatch ended before all scheduled events were returned".into());
            };
            assert_eq!((event.at_millis(), event.sequence()), (time, sequence));
        }
    }
    assert!(runner.next(Control::Continue).is_none());
    Ok(())
}
