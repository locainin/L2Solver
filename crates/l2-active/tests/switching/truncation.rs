use std::{error::Error, sync::atomic::AtomicBool};

use l2_active::switching::{
    dtp::{DtpEvidence, DtpMonitor},
    vtp::{VtpEvidence, VtpMonitor},
};

use crate::{fixture, support::Link};

fn payload_end(frame: &[u8]) -> Result<usize, Box<dyn Error>> {
    let length = <[u8; 2]>::try_from(frame.get(12..14).ok_or("missing length field")?)?;
    Ok(14 + usize::from(u16::from_be_bytes(length)))
}

#[test]
fn all_shortened_dtp_frames_reject_truncated_payload_and_allow_shorter_padding()
-> Result<(), Box<dyn Error>> {
    let end = payload_end(fixture::DTP)?;
    let prefixes = (0..fixture::DTP.len())
        .map(|length| fixture::DTP.get(..length).ok_or("bad prefix"))
        .collect::<Result<Vec<_>, _>>()?;
    let mut recognized = 0;
    for batch in prefixes.chunks(50) {
        let events = batch
            .iter()
            .map(|bytes| fixture::event(bytes))
            .collect::<Result<Vec<_>, _>>()?;
        let mut link = Link::new(events, Some(0))?;
        let report =
            DtpMonitor::new(fixture::limits(64, 8192)?).run(&mut link, &AtomicBool::new(false))?;
        for observation in report.observations() {
            recognized += 1;
            if observation.frame().captured_len() < end {
                assert!(matches!(observation.evidence(), DtpEvidence::Malformed(_)));
            } else {
                assert!(matches!(
                    observation.evidence(),
                    DtpEvidence::Advertisement(_)
                ));
            }
        }
    }
    assert!(recognized > 0);
    Ok(())
}

#[test]
fn all_shortened_vtp_frames_reject_truncated_payload_and_allow_shorter_padding()
-> Result<(), Box<dyn Error>> {
    let end = payload_end(fixture::SUMMARY)?;
    let prefixes = (0..fixture::SUMMARY.len())
        .map(|length| fixture::SUMMARY.get(..length).ok_or("bad prefix"))
        .collect::<Result<Vec<_>, _>>()?;
    let mut recognized = 0;
    for batch in prefixes.chunks(50) {
        let events = batch
            .iter()
            .map(|bytes| fixture::event(bytes))
            .collect::<Result<Vec<_>, _>>()?;
        let mut link = Link::new(events, Some(0))?;
        let report =
            VtpMonitor::new(fixture::limits(64, 8192)?).run(&mut link, &AtomicBool::new(false))?;
        for observation in report.observations() {
            recognized += 1;
            if observation.frame().captured_len() < end {
                assert!(matches!(observation.evidence(), VtpEvidence::Malformed(_)));
            } else {
                assert!(matches!(observation.evidence(), VtpEvidence::Message(_)));
            }
        }
    }
    assert!(recognized > 0);
    Ok(())
}
