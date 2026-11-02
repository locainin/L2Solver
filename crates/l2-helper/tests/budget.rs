use std::time::Duration;

use l2_helper::{
    BudgetError, MAX_SESSION_BYTES, MAX_SESSION_DURATION, MAX_SESSION_FRAMES, SessionBudget,
    SessionLimits,
};

#[test]
fn session_limits_checked_capture_starts() {
    assert!(SessionLimits::new(1, 1, Duration::from_secs(1)).is_ok());
    assert_eq!(
        SessionLimits::new(0, 1, Duration::from_secs(1)),
        Err(BudgetError::ZeroFrameLimit)
    );
    assert_eq!(
        SessionLimits::new(1, 0, Duration::from_secs(1)),
        Err(BudgetError::ZeroByteLimit)
    );
    assert_eq!(
        SessionLimits::new(1, 1, Duration::ZERO),
        Err(BudgetError::DurationTooShort)
    );
}

#[test]
fn session_limits_accept_ceilings_and_reject_each_excess() -> Result<(), BudgetError> {
    let limits = SessionLimits::new(MAX_SESSION_FRAMES, MAX_SESSION_BYTES, MAX_SESSION_DURATION)?;
    assert_eq!(limits.max_frames(), MAX_SESSION_FRAMES);
    assert_eq!(limits.max_bytes(), MAX_SESSION_BYTES);
    assert_eq!(limits.duration(), MAX_SESSION_DURATION);

    assert_eq!(
        SessionLimits::new(MAX_SESSION_FRAMES + 1, 1, Duration::from_secs(1)),
        Err(BudgetError::FrameLimit)
    );
    assert_eq!(
        SessionLimits::new(1, MAX_SESSION_BYTES + 1, Duration::from_secs(1)),
        Err(BudgetError::ByteLimit)
    );
    assert_eq!(
        SessionLimits::new(1, 1, MAX_SESSION_DURATION + Duration::from_nanos(1)),
        Err(BudgetError::DurationTooLong)
    );
    assert_eq!(
        SessionLimits::new(1, 1, Duration::from_secs(1) - Duration::from_nanos(1)),
        Err(BudgetError::DurationTooShort)
    );
    Ok(())
}

#[test]
fn session_budget_accounts_without_overflow() -> Result<(), Box<dyn std::error::Error>> {
    let limits = SessionLimits::new(2, 4, Duration::from_secs(1))?;
    let mut budget = SessionBudget::start(limits);
    budget.reserve(3)?;
    budget.commit(3)?;
    assert_eq!(budget.frames(), 1);
    assert_eq!(budget.bytes(), 3);
    assert_eq!(budget.reserve(2), Err(BudgetError::FrameWouldExceedBytes));
    assert_eq!(budget.reserve(1), Ok(()));
    budget.commit(1)?;
    assert_eq!(budget.reserve(1), Err(BudgetError::FrameWouldExceedCount));
    Ok(())
}
