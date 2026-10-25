use std::time::{Duration, Instant};

use super::{BudgetError, SessionBudget, SessionLimits};

#[test]
fn future_budget_start_rejected_accounting() -> Result<(), Box<dyn std::error::Error>> {
    let limits = SessionLimits::new(1, 1, Duration::from_secs(1))?;
    let result = SessionBudget::start_at(limits, Instant::now() + Duration::from_mins(1));

    assert!(matches!(result, Err(BudgetError::FutureStart)));
    Ok(())
}
