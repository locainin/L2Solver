use std::{error::Error, sync::atomic::AtomicBool};

use l2_active::stp::{StpEvidence, StpMonitor};
use l2_codecs::{BridgeId, StpBpduType};

use crate::{fixture, support::Link};

// Serialized independently with Scapy Dot3, LLC, and STP
const SCAPY_CONFIGURATION: &[u8] = include_bytes!("../fixtures/stp-configuration.bin");

#[test]
fn independent_scapy_configuration_is_decoded_as_the_expected_root() -> Result<(), Box<dyn Error>> {
    let mut link = Link::new(vec![fixture::event(SCAPY_CONFIGURATION.to_vec())?], Some(0))?;
    let report =
        StpMonitor::new(fixture::limits(8, 4096)?).run(&mut link, &AtomicBool::new(false))?;
    let observation = report
        .observations()
        .first()
        .ok_or("missing independent frame")?;
    let decoded = observation.decoded().ok_or("STP decode failed")?;
    assert_eq!(observation.frame().bytes(), SCAPY_CONFIGURATION);
    assert_eq!(decoded.bpdu_type, StpBpduType::Configuration);
    assert_eq!(
        decoded.root,
        Some(BridgeId::from_wire(0x8001, fixture::ROOT))
    );
    assert_eq!(decoded.cost, Some(16));
    assert_eq!(decoded.timers.map(|timers| timers.hello_time), Some(512));
    Ok(())
}

#[test]
fn every_shortened_independent_frame_is_never_reported_as_a_decoded_bpdu()
-> Result<(), Box<dyn Error>> {
    let mut packets = Vec::new();
    for end in 0..SCAPY_CONFIGURATION.len() {
        let prefix = SCAPY_CONFIGURATION.get(..end).ok_or("invalid prefix")?;
        packets.push(fixture::event(prefix.to_vec())?);
    }
    let mut link = Link::new(packets, Some(0))?;
    let report =
        StpMonitor::new(fixture::limits(100, 8192)?).run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(
        report.summary().received_packets(),
        u32::try_from(SCAPY_CONFIGURATION.len())?
    );
    assert!(
        report
            .observations()
            .iter()
            .all(|item| item.evidence() != StpEvidence::Decoded)
    );
    assert!(!report.has_sender_root_changes());
    Ok(())
}
