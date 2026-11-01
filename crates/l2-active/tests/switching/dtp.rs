use std::{error::Error, sync::atomic::AtomicBool};

use l2_active::switching::dtp::{
    DtpAdministrativeStatus, DtpEvidence, DtpMonitor, DtpObservation, DtpOperatingStatus,
    DtpTrunkEncapsulation,
};

use crate::{fixture, support::Link};

#[test]
fn scapy_dtp_claims_preserve_exact_values_without_sending() -> Result<(), Box<dyn Error>> {
    let mut link = Link::new(vec![fixture::event(fixture::DTP)?], Some(0))?;
    let report =
        DtpMonitor::new(fixture::limits(8, 4096)?).run(&mut link, &AtomicBool::new(false))?;
    let observation = report.observations().first().ok_or("missing DTP frame")?;
    let DtpEvidence::Advertisement(advert) = observation.evidence() else {
        return Err("DTP claim not decoded".into());
    };
    assert_eq!(advert.source_mac(), [2, 0, 0, 0, 0, 2]);
    assert_eq!(advert.domain(), Some(b"PRIVATE-DOMAIN\0".as_slice()));
    assert_eq!(advert.sender_id(), Some([2, 0, 0, 0, 0, 2]));
    let status = advert.status().ok_or("missing status")?;
    assert_eq!(status.raw(), 0x83);
    assert_eq!(status.operating(), DtpOperatingStatus::Trunk);
    assert_eq!(status.administrative(), DtpAdministrativeStatus::Desirable);
    let trunk_type = advert.trunk_type().ok_or("missing trunk type")?;
    assert_eq!(trunk_type.raw(), 0xa5);
    assert_eq!(trunk_type.operating(), DtpTrunkEncapsulation::Dot1q);
    assert_eq!(trunk_type.administrative(), DtpTrunkEncapsulation::Dot1q);
    assert_eq!(observation.frame().bytes(), fixture::DTP);
    assert!(!report.summary().send_attempted());
    assert!(link.sent.is_empty());
    let debug = format!("{report:?}");
    assert!(!debug.contains("PRIVATE-DOMAIN"));
    assert!(!debug.contains("PADDING-SECRET"));
    assert!(!debug.contains("80, 82, 73, 86, 65, 84, 69"));
    Ok(())
}

#[test]
fn dtp_rejects_short_duplicate_and_overlong_known_tlvs() -> Result<(), Box<dyn Error>> {
    let cases: &[&[u8]] = &[
        &[1, 0, 2, 0, 4],
        &[1, 0, 2, 0, 6, 0x83],
        &[1, 0, 2, 0, 5, 0x83, 0, 2, 0, 5, 3],
        &[1, 0, 4, 0, 5, 1],
        &[1, 0, 1, 0, 3],
    ];
    let events = cases
        .iter()
        .map(|payload| fixture::frame(0x2004, payload).and_then(|wire| fixture::event(&wire)))
        .collect::<Result<Vec<_>, _>>()?;
    let mut link = Link::new(events, Some(0))?;
    let report =
        DtpMonitor::new(fixture::limits(8, 4096)?).run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.observations().len(), cases.len());
    assert!(
        report
            .observations()
            .iter()
            .all(|item| matches!(item.evidence(), DtpEvidence::Malformed(_)))
    );
    Ok(())
}

#[test]
fn dtp_domain_boundaries_and_duplicate_domain_or_trunk_fields_are_checked()
-> Result<(), Box<dyn Error>> {
    fn domain(length: usize) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut payload = vec![1, 0, 1];
        payload.extend_from_slice(&u16::try_from(length + 4)?.to_be_bytes());
        payload.resize(payload.len() + length, b'A');
        fixture::frame(0x2004, &payload)
    }
    let duplicate_domain = fixture::frame(0x2004, &[1, 0, 1, 0, 5, b'A', 0, 1, 0, 5, b'B'])?;
    let duplicate_trunk = fixture::frame(0x2004, &[1, 0, 3, 0, 5, 1, 0, 3, 0, 5, 2])?;
    let frames = [
        domain(1)?,
        domain(33)?,
        domain(0)?,
        domain(34)?,
        duplicate_domain,
        duplicate_trunk,
    ];
    let events = frames
        .iter()
        .map(|frame| fixture::event(frame))
        .collect::<Result<Vec<_>, _>>()?;
    let mut link = Link::new(events, Some(0))?;
    let report =
        DtpMonitor::new(fixture::limits(8, 4096)?).run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.observations().len(), frames.len());
    for (index, expected_length) in [(0, 1), (1, 33)] {
        let Some(DtpEvidence::Advertisement(claim)) = report
            .observations()
            .get(index)
            .map(DtpObservation::evidence)
        else {
            return Err("valid DTP domain was rejected".into());
        };
        assert_eq!(claim.domain().map(<[u8]>::len), Some(expected_length));
    }
    assert!(report.observations().iter().skip(2).all(|item| matches!(
        item.evidence(),
        DtpEvidence::Malformed(l2_active::switching::dtp::DtpMalformed::Protocol)
    )));
    Ok(())
}

#[test]
fn dtp_unsupported_versions_and_tlv_limits_are_not_valid_claims() -> Result<(), Box<dyn Error>> {
    let unsupported = fixture::frame(0x2004, &[2, 0, 2, 0, 5, 3])?;
    let mut payload = vec![1];
    for _ in 0..65 {
        payload.extend_from_slice(&[0x12, 0x34, 0, 5, 7]);
    }
    let excessive = fixture::frame(0x2004, &payload)?;
    let mut link = Link::new(
        vec![fixture::event(&unsupported)?, fixture::event(&excessive)?],
        Some(0),
    )?;
    let report =
        DtpMonitor::new(fixture::limits(8, 4096)?).run(&mut link, &AtomicBool::new(false))?;
    assert!(matches!(
        report.observations().first().map(DtpObservation::evidence),
        Some(DtpEvidence::UnsupportedVersion(2))
    ));
    assert!(matches!(
        report.observations().get(1).map(DtpObservation::evidence),
        Some(DtpEvidence::LimitExceeded)
    ));
    Ok(())
}

#[test]
fn dtp_recognizes_broken_length_and_invalid_sender_without_decoding_them()
-> Result<(), Box<dyn Error>> {
    use l2_active::switching::dtp::DtpMalformed;
    let bad_length = fixture::change(fixture::DTP, 13, 0xff)?;
    let bad_sender = fixture::change(fixture::DTP, 6, 1)?;
    let mut link = Link::new(
        vec![fixture::event(&bad_length)?, fixture::event(&bad_sender)?],
        Some(0),
    )?;
    let report =
        DtpMonitor::new(fixture::limits(8, 4096)?).run(&mut link, &AtomicBool::new(false))?;
    assert!(matches!(
        report.observations().first().map(DtpObservation::evidence),
        Some(DtpEvidence::Malformed(DtpMalformed::Ethernet))
    ));
    assert!(matches!(
        report.observations().get(1).map(DtpObservation::evidence),
        Some(DtpEvidence::Malformed(DtpMalformed::SourceMac))
    ));
    Ok(())
}

#[test]
fn dtp_does_not_treat_ethernet_padding_as_a_tlv() -> Result<(), Box<dyn Error>> {
    let mut padded = fixture::frame(0x2004, &[1, 0, 2, 0, 5, 0x83])?;
    padded.extend_from_slice(b"not-a-dtp-tlv");
    let mut link = Link::new(vec![fixture::event(&padded)?], Some(0))?;
    let report =
        DtpMonitor::new(fixture::limits(8, 4096)?).run(&mut link, &AtomicBool::new(false))?;
    assert!(matches!(
        report.observations().first().map(DtpObservation::evidence),
        Some(DtpEvidence::Advertisement(_))
    ));
    Ok(())
}
