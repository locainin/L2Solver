//! Modeled causal claims passed to the canonical segmentation evaluator

use l2_segmentation::{
    ClockDomainId, ClockStamp, ControllerEvent, ObservationWindowReceipt, ObservationWindowTiming,
    PlannedCanaryFrame, Probe, TxCommitment, TxReceipt, TxTiming,
};

use crate::{LabError, ObservationMode};

pub struct Claims {
    pub commitment: TxCommitment,
    pub transmit: TxReceipt,
    pub window: Option<ObservationWindowReceipt>,
    pub observed_at: ClockStamp,
}

pub fn claims(
    probe: Probe,
    frame: &PlannedCanaryFrame,
    at_millis: u64,
    observer: ObservationMode,
) -> Result<Claims, LabError> {
    let canary = frame.canary();
    let run = canary.run_id().into_bytes();
    let sequence = probe.sequence();
    let domain = ClockDomainId::new([0x56; 16])?;
    // The immutable plan caps sequences at 4096, and the schedule uses each sequence as its time
    let stamp = ClockStamp::new(domain, at_millis + 1)?;
    let commitment = TxCommitment::from_planned_frame(frame, probe.source_interface());
    let transmit = TxReceipt::new(
        run,
        sequence,
        probe.source_interface(),
        frame.frame_hash(),
        TxTiming::new(stamp, controller_event(run, sequence, 2)?),
    )?;
    let window = observation_window(probe, run, stamp, observer)?;
    Ok(Claims {
        commitment,
        transmit,
        window,
        observed_at: stamp,
    })
}

fn observation_window(
    probe: Probe,
    run: [u8; l2_canary::ID_LEN],
    stamp: ClockStamp,
    observer: ObservationMode,
) -> Result<Option<ObservationWindowReceipt>, LabError> {
    if observer == ObservationMode::Unavailable {
        return Ok(None);
    }
    let sequence = probe.sequence();
    // Causal events order all operations within the same virtual clock tick
    let timing = ObservationWindowTiming::new(
        stamp,
        stamp,
        controller_event(run, sequence, 1)?,
        controller_event(run, sequence, 3)?,
        controller_event(run, sequence, 4)?,
    )?;
    let loss = u64::from(observer == ObservationMode::Dropped);
    Ok(Some(ObservationWindowReceipt::new(
        run,
        sequence,
        probe.destination_agent_id(),
        probe.destination_interface(),
        timing,
        loss,
        true,
    )?))
}

fn controller_event(
    run: [u8; l2_canary::ID_LEN],
    sequence: u64,
    offset: u64,
) -> Result<ControllerEvent, LabError> {
    // Planned sequences are at most 4096 and offsets are the fixed roles 1 through 4
    Ok(ControllerEvent::new(run, sequence, sequence * 4 + offset)?)
}
