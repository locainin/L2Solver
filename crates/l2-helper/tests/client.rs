use std::time::{Duration, Instant};

use l2_helper::{FrontendClient, HelperError, MAX_FRONTEND_REPLY_WAIT, SessionId};

#[path = "support/delayed.rs"]
mod delayed;
mod support;

#[path = "client/cancellation.rs"]
mod cancellation;
#[path = "client/integrity.rs"]
mod integrity;
#[path = "client/lifecycle.rs"]
mod lifecycle;
#[path = "support/wire.rs"]
mod wire;

#[test]
fn frontend_reply_wait_bounded_configurable() -> Result<(), Box<dyn std::error::Error>> {
    let Some((transport, helper)) = support::pair()? else {
        return Ok(());
    };
    let session = SessionId::new([31; 16])?;
    let client = FrontendClient::with_reply_timeout(transport, session, Duration::from_millis(10))?;
    let started = Instant::now();
    assert!(matches!(client.hello(), Err(HelperError::ReplyTimeout)));
    assert!(started.elapsed() < Duration::from_secs(1));
    drop(helper);
    Ok(())
}

#[test]
fn reply_timeout_respects_helper_ceiling() -> Result<(), Box<dyn std::error::Error>> {
    let Some((transport, _helper)) = support::pair()? else {
        return Ok(());
    };
    let session = SessionId::new([32; 16])?;
    assert!(matches!(
        FrontendClient::with_reply_timeout(
            transport,
            session,
            MAX_FRONTEND_REPLY_WAIT + Duration::from_nanos(1),
        ),
        Err(HelperError::InvalidRequest(_))
    ));
    let Some((transport, _helper)) = support::pair()? else {
        return Ok(());
    };
    assert!(matches!(
        FrontendClient::with_reply_timeout(transport, session, Duration::ZERO),
        Err(HelperError::InvalidRequest(_))
    ));
    Ok(())
}

mod timeout_poisoning {
    use super::*;

    #[test]
    fn rejects_late_reply_stream_reuse() -> Result<(), Box<dyn std::error::Error>> {
        let Some((frontend, helper_data, helper_control)) = delayed::pair()? else {
            return Ok(());
        };
        let session = SessionId::new([33; 16])?;
        let helper = delayed::spawn(helper_data, helper_control, session);

        let client =
            FrontendClient::with_reply_timeout(frontend, session, Duration::from_millis(10))?;
        let later_client = client.try_clone()?;
        let started = Instant::now();
        assert!(matches!(client.hello(), Err(HelperError::ReplyTimeout)));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(helper.cancellation.recv_timeout(Duration::from_secs(1))?);
        helper.late_reply.recv_timeout(Duration::from_secs(1))?;

        // The stale reply exists, so a non-poisoned client would consume it here
        let binding = l2_helper::InterfaceBindingRequest::new(10, 20, 33, 1)?;
        assert!(matches!(
            later_client.open_receive(binding),
            Err(HelperError::SessionPoisoned)
        ));
        assert!(!helper.workload.recv_timeout(Duration::from_secs(1))?);
        helper
            .worker
            .join()
            .map_err(|_| "helper thread panicked")?
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        Ok(())
    }
}
