use std::error::Error;

use l2_canary::RunIdError;
use l2_segmentation::PlanInput;

#[test]
fn ordinary_input_generates_run_id() -> Result<(), Box<dyn Error>> {
    let input = PlanInput::new()?;

    assert_ne!(input.run_id(), &[0; 16]);
    Ok(())
}

#[test]
fn replay_input_preserves_recorded_id() -> Result<(), Box<dyn Error>> {
    let input = PlanInput::for_replay([0x77; 16])?;

    assert_eq!(input.run_id(), &[0x77; 16]);
    Ok(())
}

#[test]
fn replay_input_rejects_zero_id() {
    assert_eq!(
        PlanInput::for_replay([0; 16]),
        Err(RunIdError::ReservedZero)
    );
}
