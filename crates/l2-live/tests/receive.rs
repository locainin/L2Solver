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

#[cfg(target_os = "linux")]
fn assert_unproved_child_is_rejected(mode: &str) -> Result<(), Box<dyn std::error::Error>> {
    let output = std::process::Command::new("python3")
        .arg(isolation::namespace_fixture())
        .arg(format!("--probe-{mode}"))
        .arg(std::env::current_exe()?)
        .output()?;
    assert!(
        output.status.success()
            && String::from_utf8_lossy(&output.stdout)
                .lines()
                .any(|line| line == "namespace_rejected=true"),
        "child with {mode} namespace proof was not rejected: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn missing_parent_descriptors_gate() -> Result<(), Box<dyn std::error::Error>> {
    assert_unproved_child_is_rejected("missing")
}

#[cfg(target_os = "linux")]
#[test]
fn current_namespace_descriptors_gate() -> Result<(), Box<dyn std::error::Error>> {
    assert_unproved_child_is_rejected("same")
}

#[cfg(target_os = "linux")]
#[test]
fn current_pid_namespace_gate() -> Result<(), Box<dyn std::error::Error>> {
    assert_unproved_child_is_rejected("pid")
}

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

#[cfg(target_os = "linux")]
#[test]
fn interface_rename_revalidation() -> Result<(), Box<dyn std::error::Error>> {
    fn ip(arguments: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
        let output = std::process::Command::new("ip").args(arguments).output()?;
        if !output.status.success() {
            return Err(format!(
                "ip {arguments:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    if !isolation::run_in_private_namespace()? {
        return Ok(());
    }

    let mut link = LiveLink::open_with_limits("lo", 1, Duration::from_secs(10))?;
    let original = link.interface_identity()?;
    assert_eq!(original.ifindex(), 1);

    // The proved private namespace owns this loopback name
    ip(&["link", "set", "dev", "lo", "down"])?;
    ip(&["link", "set", "dev", "lo", "name", "l2renamed"])?;
    assert!(
        link.interface_identity().is_err(),
        "identity accepted a stale interface name"
    );
    assert!(
        link.statistics().is_err(),
        "statistics accepted a stale interface name"
    );
    assert!(
        link.recv().is_err(),
        "receive accepted a stale interface name"
    );
    Ok(())
}
