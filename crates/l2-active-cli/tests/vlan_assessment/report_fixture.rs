use std::{error::Error, sync::atomic::AtomicBool};

use l2_active::{ArpReport, PreSendUsage, ReceiveEvent};

use super::arp_fixture;

pub(super) fn report(
    senders: &[[u8; 6]],
    drained: Option<PreSendUsage>,
) -> Result<ArpReport, Box<dyn Error>> {
    let identity = arp_fixture::identity()?;
    let mut events = Vec::new();
    for sender in senders {
        let bytes = arp_fixture::reply(*sender, arp_fixture::TARGET_IP, arp_fixture::LOCAL_IP);
        events.push(ReceiveEvent::Frame(arp_fixture::captured(
            bytes,
            Some(identity),
            60,
        )?));
    }
    events.push(ReceiveEvent::TimedOut);
    let mut link = arp_fixture::Link::new(events, Some(0))?;
    link.pre_send = drained;
    Ok(
        arp_fixture::probe(Some(arp_fixture::REMOTE_MAC), 10, 1_000)?
            .run(&mut link, &AtomicBool::new(false))?,
    )
}
