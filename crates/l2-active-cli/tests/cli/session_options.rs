use std::{error::Error as StdError, io};

use super::finish;
use crate::Error;

#[test]
fn unconfirmed_close_keeps_an_already_collected_report() -> Result<(), Box<dyn StdError>> {
    let (report, close) = finish(Ok(42), Err(io::Error::other("close missing")))?;
    assert_eq!(report, 42);
    assert_eq!(
        close.as_ref().map(ToString::to_string).as_deref(),
        Some("close missing")
    );
    Ok(())
}

#[test]
fn preparation_and_cleanup_failures_are_both_retained() -> Result<(), Box<dyn StdError>> {
    let result = finish::<()>(
        Err(l2_active::RunError::Allocation),
        Err(io::Error::other("close missing")),
    );
    let Err(Error::Cleanup { preparation, close }) = result else {
        return Err("expected combined failure".into());
    };
    assert_eq!(preparation, l2_active::RunError::Allocation);
    assert_eq!(close.to_string(), "close missing");
    Ok(())
}

#[test]
fn confirmed_close_keeps_the_preparation_failure() {
    let result = finish::<()>(Err(l2_active::RunError::DeadlineOverflow), Ok(()));
    assert!(matches!(
        result,
        Err(Error::Run(l2_active::RunError::DeadlineOverflow))
    ));
}
