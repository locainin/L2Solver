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
    let base = sequence.checked_mul(4).ok_or(LabError::Invariant)?;
    let ordinal = |offset| base.checked_add(offset).ok_or(LabError::Invariant);
    let event =
        |offset| ControllerEvent::new(run, sequence, ordinal(offset)?).map_err(LabError::from);
    let domain = ClockDomainId::new([0x56; 16])?;
    // All operations at one scheduler tick use causal events for their order
    let stamp = ClockStamp::new(domain, at_millis.checked_add(1).ok_or(LabError::Invariant)?)?;
    let commitment = TxCommitment::from_planned_frame(frame, probe.source_interface());
    let transmit = TxReceipt::new(
        run,
        sequence,
        probe.source_interface(),
        frame.frame_hash(),
        TxTiming::new(stamp, event(2)?),
    )?;
    let window = if matches!(observer, ObservationMode::Unavailable) {
        None
    } else {
        let timing = ObservationWindowTiming::new(stamp, stamp, event(1)?, event(3)?, event(4)?)?;
        let loss = u64::from(matches!(observer, ObservationMode::Dropped));
        Some(ObservationWindowReceipt::new(
            run,
            sequence,
            probe.destination_agent_id(),
            probe.destination_interface(),
            timing,
            loss,
            true,
        )?)
    };
    Ok(Claims {
        commitment,
        transmit,
        window,
        observed_at: stamp,
    })
}
