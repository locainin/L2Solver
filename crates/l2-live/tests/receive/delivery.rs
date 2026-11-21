use std::{cell::Cell, error::Error, net::UdpSocket, time::Duration};

use l2_io::LinkIo;

use super::{LiveLink, StopReason};

#[path = "isolation.rs"]
mod isolation;

thread_local! {
    static DELIVERY_DELAY: Cell<Option<Duration>> = const { Cell::new(None) };
}

pub(super) fn before_delivery() {
    DELIVERY_DELAY.with(|delay| {
        if let Some(duration) = delay.take() {
            // Hold the copied frame until after the capture deadline
            std::thread::sleep(duration);
        }
    });
}

#[test]
fn expired_frame_exclusion() -> Result<(), Box<dyn Error>> {
    if !isolation::run_in_private_namespace()? {
        return Ok(());
    }

    let receiver = UdpSocket::bind(("127.0.0.1", 0))?;
    let sender = UdpSocket::bind(("127.0.0.1", 0))?;
    let mut link = LiveLink::open_with_limits("lo", 1, Duration::from_secs(1))?;
    let payload = b"private live capture deadline";
    assert_eq!(
        sender.send_to(payload, receiver.local_addr()?)?,
        payload.len()
    );
    DELIVERY_DELAY.set(Some(Duration::from_millis(1200)));
    let result = link.recv()?;
    assert_eq!(
        DELIVERY_DELAY.get(),
        None,
        "no frame reached the delivery point"
    );
    assert!(result.is_none(), "a frame was returned after the deadline");
    assert_eq!(link.stop_reason(), Some(StopReason::Deadline));
    Ok(())
}
