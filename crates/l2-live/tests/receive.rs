use l2_io::LinkIo;
use l2_live::{LiveLink, StopReason};
use std::time::Duration;

#[test]
fn unknown_interface_rejection() {
    let result = LiveLink::open_with_limits(
        "l2solver-interface-that-does-not-exist",
        1,
        Duration::from_secs(1),
    );
    assert!(
        result.is_err(),
        "an unknown capture interface must be rejected"
    );
    if let Err(error) = result {
        assert!(error.to_string().contains("unknown capture interface"));
    }
}

#[test]
fn expired_deadline_queued_host_traffic() -> Result<(), Box<dyn std::error::Error>> {
    let mut link = match LiveLink::open_with_limits("lo", 1, Duration::from_secs(1)) {
        Ok(link) => link,
        Err(error) if error.to_string().contains("CAP_NET_RAW") => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    assert_eq!(link.stop_reason(), None);
    // Let the budget expire before reading so unrelated loopback traffic is irrelevant
    std::thread::sleep(Duration::from_secs(1));
    assert!(link.recv()?.is_none());
    assert_eq!(link.stop_reason(), Some(StopReason::Deadline));
    Ok(())
}
