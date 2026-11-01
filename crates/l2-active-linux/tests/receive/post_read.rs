use std::{
    error::Error,
    io,
    time::{Duration, Instant},
};

use l2_active::ReceiveEvent;

#[test]
fn completed_validation_before_backend_deadline_allows_the_frame() -> Result<(), Box<dyn Error>> {
    assert!(super::post_read_result(Ok(()), Instant::now() + Duration::from_secs(1))?.is_none());
    Ok(())
}

#[test]
fn expired_backend_deadline_after_consumption_is_a_backend_timeout() -> Result<(), Box<dyn Error>> {
    for validation in [Ok(()), Err(io::Error::from(io::ErrorKind::TimedOut))] {
        assert!(matches!(
            super::post_read_result(validation, Instant::now())?,
            Some(ReceiveEvent::BackendTimedOut)
        ));
    }
    Ok(())
}

#[test]
fn earlier_lookup_timeout_and_cancellation_remain_errors() -> Result<(), Box<dyn Error>> {
    for kind in [io::ErrorKind::TimedOut, io::ErrorKind::Interrupted] {
        let error = super::post_read_result(
            Err(io::Error::from(kind)),
            Instant::now() + Duration::from_secs(1),
        )
        .err()
        .ok_or("expected validation error")?;
        assert_eq!(error.kind(), kind);
    }
    Ok(())
}

#[test]
fn observed_vlan_scope_change_takes_priority_over_an_expired_deadline() -> Result<(), Box<dyn Error>>
{
    let changed = io::Error::new(io::ErrorKind::InvalidData, crate::VlanScopeChanged);
    let error = super::post_read_result(Err(changed), Instant::now())
        .err()
        .ok_or("expected VLAN scope failure")?;
    assert!(matches!(
        error.get_ref(),
        Some(source) if source.is::<crate::VlanScopeChanged>()
    ));
    Ok(())
}
