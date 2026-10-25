use std::error::Error;

use l2_canary::{ID_LEN, RunId, RunIdError};

#[test]
fn generated_id_not_reserved_sentinel() -> Result<(), Box<dyn Error>> {
    let run_id = RunId::generate()?;

    assert_ne!(run_id.as_bytes(), &[0; ID_LEN]);
    Ok(())
}

#[test]
fn recorded_id_round_trips_exactly() -> Result<(), Box<dyn Error>> {
    let bytes = [0x5a; ID_LEN];
    let run_id = RunId::from_recorded(bytes)?;

    assert_eq!(run_id.as_bytes(), &bytes);
    assert_eq!(run_id.into_bytes(), bytes);
    Ok(())
}

#[test]
fn recorded_zero_id_is_rejected() {
    assert_eq!(
        RunId::from_recorded([0; ID_LEN]),
        Err(RunIdError::ReservedZero)
    );
}
