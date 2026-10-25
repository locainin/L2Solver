use std::error::Error;

use l2_onpath::{BudgetError, BudgetTimebase, ClockDomainId};

#[test]
fn budget_timebase_nonzero_tick_resolution() -> Result<(), Box<dyn Error>> {
    let domain = ClockDomainId::new([0x41; 16])?;

    assert_eq!(
        BudgetTimebase::new(domain, 0),
        Err(BudgetError::ZeroTicksPerMillisecond)
    );
    let timebase = BudgetTimebase::new(domain, 1)?;
    assert_eq!(timebase.domain(), domain);
    assert_eq!(timebase.ticks_per_millisecond(), 1);
    Ok(())
}
