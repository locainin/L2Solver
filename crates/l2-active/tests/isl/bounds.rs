use std::{error::Error, sync::atomic::AtomicBool};

use l2_active::{
    StopReason,
    isl::{IslEvidence, IslMonitor, IslObservation},
};

use crate::{fixture, support::Link};

#[test]
fn isl_rejects_all_shortened_headers_and_declared_payloads() -> Result<(), Box<dyn Error>> {
    let prefixes = (0..fixture::VALID.len())
        .map(|length| fixture::VALID.get(..length).ok_or("bad prefix"))
        .collect::<Result<Vec<_>, _>>()?;
    let mut recognized = 0;
    for batch in prefixes.chunks(50) {
        let events = batch
            .iter()
            .map(|bytes| fixture::event(bytes))
            .collect::<Result<Vec<_>, _>>()?;
        let mut link = Link::new(events, Some(0))?;
        let report =
            IslMonitor::new(fixture::limits(60, 8192)?).run(&mut link, &AtomicBool::new(false))?;
        for observation in report.observations() {
            recognized += 1;
            assert!(matches!(observation.evidence(), IslEvidence::Malformed(_)));
        }
    }
    assert_eq!(recognized, fixture::VALID.len() - 5);
    Ok(())
}

#[test]
fn isl_accepts_an_inner_frame_at_its_limit_and_rejects_one_byte_over() -> Result<(), Box<dyn Error>>
{
    fn frame(inner_bytes: usize) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut frame = fixture::VALID
            .get(..fixture::VALID.len() - 4)
            .ok_or("missing FCS")?
            .to_vec();
        frame.resize(26 + inner_bytes - 4, 0x5a);
        frame.extend_from_slice(&[0; 4]);
        let length = u16::try_from(inner_bytes + 12)?.to_be_bytes();
        frame
            .get_mut(12..14)
            .ok_or("missing length")?
            .copy_from_slice(&length);
        Ok(frame)
    }
    let boundary = frame(24_575)?;
    let over = frame(24_576)?;
    let mut link = Link::new(
        vec![fixture::event(&boundary)?, fixture::event(&over)?],
        Some(0),
    )?;
    let report =
        IslMonitor::new(fixture::limits(8, 100_000)?).run(&mut link, &AtomicBool::new(false))?;
    let first = report.observations().first().ok_or("missing boundary")?;
    let IslEvidence::Frame(header) = first.evidence() else {
        return Err("boundary rejected".into());
    };
    assert_eq!(header.inner_frame_length(), 24_575);
    assert!(matches!(
        report.observations().get(1).map(IslObservation::evidence),
        Some(IslEvidence::LimitExceeded)
    ));
    Ok(())
}

#[test]
fn isl_non_ethernet_media_are_explicitly_unsupported_for_every_user_value()
-> Result<(), Box<dyn Error>> {
    for media in 1..=3 {
        let mut events = Vec::new();
        for prefix in [1, 3] {
            for user in 0..16 {
                let frame = fixture::change(
                    &fixture::change(fixture::VALID, 0, prefix)?,
                    5,
                    (media << 4) | user,
                )?;
                events.push(fixture::event(&frame)?);
            }
        }
        let mut link = Link::new(events, Some(0))?;
        let report =
            IslMonitor::new(fixture::limits(40, 8192)?).run(&mut link, &AtomicBool::new(false))?;
        assert_eq!(report.observations().len(), 32);
        assert!(report.observations().iter().all(|item| matches!(item.evidence(), IslEvidence::UnsupportedMedia(value) if *value == media)));
    }
    Ok(())
}

#[test]
fn isl_accepts_extra_outer_bytes_without_claiming_they_are_an_fcs() -> Result<(), Box<dyn Error>> {
    let mut appended = fixture::VALID.to_vec();
    appended.extend_from_slice(b"EXTRA-PRIVATE-OUTER");
    let mut link = Link::new(
        vec![fixture::event(fixture::VALID)?, fixture::event(&appended)?],
        Some(0),
    )?;
    let report =
        IslMonitor::new(fixture::limits(8, 4096)?).run(&mut link, &AtomicBool::new(false))?;
    let first = report.observations().first().ok_or("missing frame")?;
    let second = report
        .observations()
        .get(1)
        .ok_or("missing frame with trailing bytes")?;
    assert_eq!(first.evidence(), second.evidence());
    assert_eq!(second.frame().bytes(), appended);
    assert!(!format!("{report:?}").contains("EXTRA-PRIVATE-OUTER"));
    Ok(())
}

#[test]
fn isl_observation_limit_stops_before_retaining_unbounded_frames() -> Result<(), Box<dyn Error>> {
    let events = (0..65)
        .map(|_| fixture::event(fixture::VALID))
        .collect::<Result<Vec<_>, _>>()?;
    let mut link = Link::new(events, Some(0))?;
    let report =
        IslMonitor::new(fixture::limits(70, 20_000)?).run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.summary().stop_reason(), StopReason::ObservationLimit);
    assert_eq!(report.observations().len(), 64);
    assert_eq!(report.summary().received_packets(), 64);
    Ok(())
}

#[test]
fn isl_preserves_reserved_and_high_vlan_bits_as_advertised() -> Result<(), Box<dyn Error>> {
    let mut wire = fixture::change(fixture::VALID, 5, 0x0f)?;
    wire.get_mut(20..22)
        .ok_or("missing VLAN and BPDU")?
        .copy_from_slice(&u16::MAX.to_be_bytes());
    wire.get_mut(24..26)
        .ok_or("missing reserved field")?
        .copy_from_slice(&0x1234_u16.to_be_bytes());
    let mut link = Link::new(vec![fixture::event(&wire)?], Some(0))?;
    let report =
        IslMonitor::new(fixture::limits(8, 4096)?).run(&mut link, &AtomicBool::new(false))?;
    let IslEvidence::Frame(header) = report
        .observations()
        .first()
        .ok_or("missing candidate")?
        .evidence()
    else {
        return Err("missing header".into());
    };
    assert_eq!(header.user(), 15);
    assert_eq!(header.priority(), 3);
    assert_eq!(header.vlan_id(), 0x7fff);
    assert!(header.bpdu());
    assert_eq!(header.reserved(), 0x1234);
    Ok(())
}

#[test]
fn isl_fcs_metadata_alone_does_not_change_crc_or_header_claims() -> Result<(), Box<dyn Error>> {
    use l2_active::ReceiveEvent;
    use l2_capture::{CaptureMetadata, CapturedFrame, Direction, FcsStatus, InterfaceId};

    let mut events = Vec::new();
    for fcs in [
        FcsStatus::Unknown,
        FcsStatus::Absent,
        FcsStatus::present(4)?,
    ] {
        let metadata = CaptureMetadata::new(
            InterfaceId {
                section: 0,
                index: 5,
            },
            u32::try_from(fixture::VALID.len())?,
            None,
            None,
            Direction::Inbound,
            None,
            fcs,
        )
        .with_linux_interface(crate::support::identity()?);
        events.push(ReceiveEvent::Frame(CapturedFrame::new(
            fixture::VALID.to_vec(),
            metadata,
        )?));
    }
    let mut link = Link::new(events, Some(0))?;
    let report =
        IslMonitor::new(fixture::limits(8, 4096)?).run(&mut link, &AtomicBool::new(false))?;
    let first = report.observations().first().ok_or("missing unknown FCS")?;
    assert!(matches!(first.evidence(), IslEvidence::Frame(_)));
    for observation in report.observations() {
        assert_eq!(observation.evidence(), first.evidence());
    }
    assert_eq!(first.frame().metadata().fcs(), FcsStatus::Unknown);
    Ok(())
}
