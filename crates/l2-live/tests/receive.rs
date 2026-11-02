use l2_live::LiveLink;
use std::time::Duration;

#[cfg(target_os = "linux")]
use l2_io::LinkIo;
#[cfg(target_os = "linux")]
use l2_live::StopReason;
#[cfg(target_os = "linux")]
use std::{net::UdpSocket, time::Instant};

#[cfg(target_os = "linux")]
#[path = "receive/isolation.rs"]
mod isolation;

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
#[cfg(target_os = "linux")]
fn expired_deadline_stops_after_loopback_traffic() -> Result<(), Box<dyn std::error::Error>> {
    if !isolation::run_in_private_namespace()? {
        return Ok(());
    }

    let receiver = UdpSocket::bind(("127.0.0.1", 0))?;
    receiver.set_read_timeout(Some(Duration::from_secs(1)))?;
    let sender = UdpSocket::bind(("127.0.0.1", 0))?;
    let mut witness = LiveLink::open_with_limits("lo", 1, Duration::from_secs(3))?;
    let duration = Duration::from_secs(2);
    // Opening may take time, so bracket its deadline for both assertions
    let before_open = Instant::now();
    let mut link = LiveLink::open_with_limits("lo", 1, duration)?;
    let opened = Instant::now();
    let initial = link.statistics()?;
    assert_eq!(link.stop_reason(), None);

    // The second capture observes the generated datagram before the budget expires
    let payload = b"l2solver private loopback deadline test";
    assert_eq!(
        sender.send_to(payload, receiver.local_addr()?)?,
        payload.len()
    );
    let mut buffer = [0; 128];
    let (length, _) = receiver.recv_from(&mut buffer)?;
    assert_eq!(buffer.get(..length), Some(payload.as_slice()));
    let observed = witness
        .recv()?
        .ok_or("witness capture reached its deadline")?;
    assert!(
        observed
            .bytes()
            .windows(payload.len())
            .any(|part| part == payload),
        "witness capture did not contain the generated datagram"
    );
    let after_traffic = link.statistics()?;
    assert!(
        after_traffic.received() > initial.received(),
        "target capture reported no packets"
    );
    assert_eq!(
        after_traffic.capture_dropped(),
        initial.capture_dropped(),
        "target capture reported dropped traffic"
    );
    assert!(
        before_open.elapsed() < duration,
        "traffic arrived after the target deadline"
    );

    // Leave the target capture unread until its deadline has passed
    std::thread::sleep(duration.saturating_sub(opened.elapsed()) + Duration::from_millis(10));
    assert!(link.recv()?.is_none());
    assert_eq!(link.stop_reason(), Some(StopReason::Deadline));
    Ok(())
}
