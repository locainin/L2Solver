use std::{error::Error, sync::atomic::AtomicBool};

use l2_active::discovery::{DiscoveryDisposition, DiscoveryMonitor, DiscoveryProtocol};

use crate::{fixture, support::Link};

// Serialized independently with Scapy Ethernet and LLDP layers
const SCAPY_LLDP: &[u8] = include_bytes!("../fixtures/lldp-advertisement.bin");
const END_OF_LLDP: usize = 51;

#[test]
fn independent_lldp_frame_retains_scapy_identity_and_ttl() -> Result<(), Box<dyn Error>> {
    let mut link = Link::new(vec![fixture::event(SCAPY_LLDP.to_vec())?], Some(0))?;
    let report =
        DiscoveryMonitor::new(fixture::limits(8, 4096)?).run(&mut link, &AtomicBool::new(false))?;
    let observed = report
        .observations()
        .first()
        .ok_or("missing independent LLDP frame")?;
    let identity = observed.identity().ok_or("missing LLDP identity")?;
    assert_eq!(observed.frame().bytes(), SCAPY_LLDP);
    assert_eq!(observed.protocol(), DiscoveryProtocol::Lldp);
    assert_eq!(observed.disposition(), DiscoveryDisposition::Advertisement);
    assert_eq!(observed.hold_seconds(), Some(120));
    assert_eq!(identity.device(), b"\x07independent-switch");
    assert_eq!(identity.port(), b"\x05Gi1/0/1");
    Ok(())
}

#[test]
fn shortened_lldp_rejects_missing_tlvs_but_allows_missing_ethernet_padding()
-> Result<(), Box<dyn Error>> {
    let mut events = Vec::new();
    for end in 0..SCAPY_LLDP.len() {
        let prefix = SCAPY_LLDP.get(..end).ok_or("invalid prefix")?;
        events.push(fixture::event(prefix.to_vec())?);
    }
    let mut link = Link::new(events, Some(0))?;
    let report = DiscoveryMonitor::new(fixture::limits(100, 8192)?)
        .run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(
        report.summary().received_packets(),
        u32::try_from(SCAPY_LLDP.len())?
    );
    for observed in report.observations() {
        if observed.frame().bytes().len() < END_OF_LLDP {
            assert_ne!(observed.disposition(), DiscoveryDisposition::Advertisement);
            assert_eq!(observed.identity(), None);
        } else {
            assert_eq!(observed.disposition(), DiscoveryDisposition::Advertisement);
            assert_eq!(observed.hold_seconds(), Some(120));
        }
    }
    assert!(
        report
            .observations()
            .iter()
            .any(|item| item.frame().bytes().len() == END_OF_LLDP)
    );
    Ok(())
}

#[test]
fn every_shortened_scapy_cdp_frame_cannot_create_a_valid_advertisement()
-> Result<(), Box<dyn Error>> {
    let mut events = Vec::new();
    for end in 0..fixture::CDP.len() {
        let prefix = fixture::CDP.get(..end).ok_or("invalid prefix")?;
        events.push(fixture::event(prefix.to_vec())?);
    }
    let mut link = Link::new(events, Some(0))?;
    let report = DiscoveryMonitor::new(fixture::limits(100, 8192)?)
        .run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(
        report.summary().received_packets(),
        u32::try_from(fixture::CDP.len())?
    );
    assert!(report.observations().iter().all(|item| {
        !matches!(
            item.disposition(),
            DiscoveryDisposition::Advertisement | DiscoveryDisposition::Withdrawal
        )
    }));
    Ok(())
}
