use std::{error::Error, sync::atomic::AtomicBool, time::Instant};

use l2_active::{
    ReceiveEvent, StopReason,
    dot1x::{Dot1xDestination, Dot1xStatus, MalformedReason},
};

use super::fixture::{AUTHENTICATOR, CLIENT, GROUP, REQUEST, START, capture, probe};
use crate::support::{Link, captured, identity};

#[test]
fn scoped_requests_preserve_source_identifier_type_and_exact_evidence() -> Result<(), Box<dyn Error>>
{
    let mut link = Link::new(vec![ReceiveEvent::Frame(capture(REQUEST)?)], Some(0))?;
    let report = probe(1, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), Dot1xStatus::Observed);
    let request = report.observations().first().ok_or("missing request")?;
    assert_eq!(request.source_mac().bytes(), AUTHENTICATOR);
    assert_eq!(request.destination(), Dot1xDestination::SelectedInterface);
    assert_eq!(request.version(), 2);
    assert_eq!(request.identifier(), 41);
    assert_eq!(request.request_type(), 1);
    assert_eq!(request.frame().bytes(), REQUEST);
    assert_eq!(report.summary().sent_packets(), 1);
    assert_eq!(report.summary().sent_bytes(), 60);
    assert_eq!(link.sent.first().ok_or("missing Start")?, START);
    Ok(())
}

#[test]
fn pae_group_requests_and_retransmissions_remain_separate_observations()
-> Result<(), Box<dyn Error>> {
    let mut link = Link::new(
        vec![
            ReceiveEvent::Frame(capture(GROUP)?),
            ReceiveEvent::Frame(capture(GROUP)?),
        ],
        Some(0),
    )?;
    let report = probe(2, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), Dot1xStatus::Observed);
    assert_eq!(report.observations().len(), 2);
    for request in report.observations() {
        assert_eq!(request.destination(), Dot1xDestination::PaeGroup);
        assert_eq!(request.version(), 1);
        assert_eq!(request.identifier(), 0);
        assert_eq!(request.request_type(), 2);
    }
    Ok(())
}

#[test]
fn different_claimed_senders_and_capture_loss_are_preserved_without_a_guard_verdict()
-> Result<(), Box<dyn Error>> {
    let mut second = REQUEST.to_vec();
    *second.get_mut(11).ok_or("missing source")? = 3;
    let mut link = Link::new(
        vec![
            ReceiveEvent::Frame(capture(REQUEST)?),
            ReceiveEvent::Frame(capture(&second)?),
        ],
        Some(2),
    )?;
    let report = probe(2, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), Dot1xStatus::Observed);
    let [first, other] = report.observations() else {
        return Err("expected both source claims".into());
    };
    assert_eq!(first.source_mac().bytes(), AUTHENTICATOR);
    assert_eq!(other.source_mac().bytes(), [2, 0, 0, 0, 0, 3]);
    assert_eq!(report.summary().capture_loss(), Some(2));
    Ok(())
}

#[test]
fn malformed_recognizable_requests_keep_failure_evidence_separate_from_noise()
-> Result<(), Box<dyn Error>> {
    let mut bad_eapol_length = REQUEST.to_vec();
    bad_eapol_length
        .get_mut(16..18)
        .ok_or("missing EAPOL length")?
        .copy_from_slice(&100_u16.to_be_bytes());
    let mut bad_eap_length = REQUEST.to_vec();
    bad_eap_length
        .get_mut(20..22)
        .ok_or("missing EAP length")?
        .copy_from_slice(&8_u16.to_be_bytes());
    let mut bad_type = REQUEST.to_vec();
    *bad_type.get_mut(22).ok_or("missing EAP type")? = 3;
    let mut noise = REQUEST.to_vec();
    *noise.get_mut(5).ok_or("missing destination")? = 9;
    let malformed = [&bad_eapol_length, &bad_eap_length, &bad_type];
    let events = malformed
        .into_iter()
        .chain([&noise])
        .map(|frame| Ok(ReceiveEvent::Frame(capture(frame)?)))
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let mut link = Link::new(events, Some(0))?;
    let report = probe(4, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), Dot1xStatus::Inconclusive);
    assert_eq!(report.unrelated_packets(), 1);
    let [first, second, third] = report.malformed() else {
        return Err("expected three malformed frames".into());
    };
    assert_eq!(first.reason(), MalformedReason::EapolHeader);
    assert_eq!(second.reason(), MalformedReason::EapHeader);
    assert_eq!(third.reason(), MalformedReason::RequestType);
    assert_eq!(first.frame().bytes(), bad_eapol_length);
    assert_eq!(report.summary().stop_reason(), StopReason::PacketLimit);
    Ok(())
}

#[test]
fn short_headers_invalid_sources_versions_and_request_types_are_rejected()
-> Result<(), Box<dyn Error>> {
    let mut frames = Vec::new();
    for end in 14..23 {
        frames.push(REQUEST.get(..end).ok_or("invalid prefix")?.to_vec());
    }
    let mut bad_source = REQUEST.to_vec();
    bad_source.get_mut(6..12).ok_or("missing source")?.fill(0);
    frames.push(bad_source);
    for (index, value) in [(14, 0), (22, 0), (22, 3), (22, 254)] {
        let mut frame = REQUEST.to_vec();
        *frame.get_mut(index).ok_or("fixture offset")? = value;
        frames.push(frame);
    }
    let count = u32::try_from(frames.len())?;
    let events = frames
        .iter()
        .map(|frame| Ok(ReceiveEvent::Frame(capture(frame)?)))
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let mut link = Link::new(events, Some(0))?;
    let report = probe(count, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), Dot1xStatus::Inconclusive);
    assert_eq!(report.malformed().len(), usize::try_from(count)?);
    assert_eq!(report.summary().received_packets(), count);
    Ok(())
}

#[test]
fn request_lengths_below_the_complete_eap_header_are_malformed() -> Result<(), Box<dyn Error>> {
    let mut shorter_than_header = REQUEST.to_vec();
    shorter_than_header
        .get_mut(20..22)
        .ok_or("missing EAP length")?
        .copy_from_slice(&3_u16.to_be_bytes());
    let mut missing_type = REQUEST.to_vec();
    missing_type
        .get_mut(20..22)
        .ok_or("missing EAP length")?
        .copy_from_slice(&4_u16.to_be_bytes());
    let frames = [shorter_than_header, missing_type];
    let events = frames
        .iter()
        .map(|frame| Ok(ReceiveEvent::Frame(capture(frame)?)))
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let mut link = Link::new(events, Some(0))?;
    let report = probe(2, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), Dot1xStatus::Inconclusive);
    assert_eq!(report.malformed().len(), 2);
    assert!(
        report
            .malformed()
            .iter()
            .all(|item| item.reason() == MalformedReason::EapHeader)
    );
    Ok(())
}

#[test]
fn expanded_requests_require_a_vendor_header_and_cannot_be_expanded_nak()
-> Result<(), Box<dyn Error>> {
    let mut valid = REQUEST.to_vec();
    valid
        .get_mut(16..18)
        .ok_or("missing EAPOL length")?
        .copy_from_slice(&12_u16.to_be_bytes());
    valid
        .get_mut(20..22)
        .ok_or("missing EAP length")?
        .copy_from_slice(&12_u16.to_be_bytes());
    *valid.get_mut(22).ok_or("missing type")? = 254;
    valid
        .get_mut(23..30)
        .ok_or("missing vendor header")?
        .copy_from_slice(&[0, 0, 0, 0, 0, 0, 7]);
    let mut expanded_nak = valid.clone();
    *expanded_nak.get_mut(29).ok_or("missing vendor type")? = 3;
    let events = [valid, expanded_nak]
        .iter()
        .map(|frame| Ok(ReceiveEvent::Frame(capture(frame)?)))
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let mut link = Link::new(events, Some(0))?;
    let report = probe(2, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.observations().len(), 1);
    assert_eq!(
        report
            .observations()
            .first()
            .ok_or("missing expanded request")?
            .request_type(),
        254
    );
    assert_eq!(report.malformed().len(), 1);
    assert_eq!(
        report
            .malformed()
            .first()
            .ok_or("missing expanded Nak")?
            .reason(),
        MalformedReason::RequestType
    );
    Ok(())
}

#[test]
fn notification_request_requires_nonempty_utf8_message_without_nul() -> Result<(), Box<dyn Error>> {
    let mut empty = REQUEST.to_vec();
    *empty.get_mut(22).ok_or("missing type")? = 2;
    let mut nul = empty.clone();
    nul.get_mut(16..18)
        .ok_or("missing EAPOL length")?
        .copy_from_slice(&6_u16.to_be_bytes());
    nul.get_mut(20..22)
        .ok_or("missing EAP length")?
        .copy_from_slice(&6_u16.to_be_bytes());
    let mut invalid_utf8 = nul.clone();
    *invalid_utf8.get_mut(23).ok_or("missing message")? = 0xff;
    let frames = [empty, nul, invalid_utf8];
    let events = frames
        .iter()
        .map(|frame| Ok(ReceiveEvent::Frame(capture(frame)?)))
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let mut link = Link::new(events, Some(0))?;
    let report = probe(3, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), Dot1xStatus::Inconclusive);
    assert_eq!(report.malformed().len(), 3);
    assert!(
        report
            .malformed()
            .iter()
            .all(|item| item.reason() == MalformedReason::RequestType)
    );
    Ok(())
}

#[test]
fn eapol_and_eap_length_bounds_allow_trailing_link_padding() -> Result<(), Box<dyn Error>> {
    let mut padding = REQUEST.to_vec();
    padding
        .get_mut(16..18)
        .ok_or("missing EAPOL length")?
        .copy_from_slice(&8_u16.to_be_bytes());
    padding
        .get_mut(23..26)
        .ok_or("missing padding")?
        .copy_from_slice(&[1, 2, 3]);
    let mut link = Link::new(vec![ReceiveEvent::Frame(capture(&padding)?)], Some(0))?;
    let report = probe(1, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), Dot1xStatus::Observed);
    assert_eq!(report.observations().len(), 1);
    Ok(())
}

#[test]
fn only_scoped_request_packets_are_observations() -> Result<(), Box<dyn Error>> {
    let mut wrong_destination = REQUEST.to_vec();
    *wrong_destination.get_mut(5).ok_or("missing destination")? = 9;
    let mut self_origin = REQUEST.to_vec();
    self_origin
        .get_mut(6..12)
        .ok_or("missing source")?
        .copy_from_slice(&CLIENT);
    let mut response = REQUEST.to_vec();
    *response.get_mut(18).ok_or("missing code")? = 2;
    let mut start = REQUEST.to_vec();
    *start.get_mut(15).ok_or("missing EAPOL type")? = 1;
    start
        .get_mut(16..18)
        .ok_or("missing EAPOL length")?
        .copy_from_slice(&0_u16.to_be_bytes());
    let mut unsupported_version = REQUEST.to_vec();
    *unsupported_version.get_mut(14).ok_or("missing version")? = 4;
    let mut vlan = REQUEST.to_vec();
    vlan.splice(12..14, [0x81, 0, 0, 1, 0x88, 0x8e]);
    let frames = [
        wrong_destination,
        self_origin,
        response,
        start,
        unsupported_version,
        vlan,
    ];
    let events = frames
        .iter()
        .map(|frame| Ok(ReceiveEvent::Frame(capture(frame)?)))
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let mut link = Link::new(events, Some(0))?;
    let report = probe(6, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), Dot1xStatus::Inconclusive);
    assert_eq!(report.unrelated_packets(), 6);
    assert!(report.malformed().is_empty());
    Ok(())
}

#[test]
fn malformed_non_request_eapol_envelopes_are_retained_as_failure_evidence()
-> Result<(), Box<dyn Error>> {
    let mut overlong_start = START.to_vec();
    overlong_start
        .get_mut(0..6)
        .ok_or("missing destination")?
        .copy_from_slice(&CLIENT);
    overlong_start
        .get_mut(6..12)
        .ok_or("missing source")?
        .copy_from_slice(&AUTHENTICATOR);
    *overlong_start.get_mut(17).ok_or("missing length")? = 1;
    let mut truncated_key = overlong_start.clone();
    *truncated_key.get_mut(15).ok_or("missing type")? = 3;
    *truncated_key.get_mut(17).ok_or("missing length")? = 100;
    let events = [overlong_start, truncated_key]
        .iter()
        .map(|frame| Ok(ReceiveEvent::Frame(capture(frame)?)))
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let mut link = Link::new(events, Some(0))?;
    let report = probe(2, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), Dot1xStatus::Inconclusive);
    assert_eq!(report.unrelated_packets(), 0);
    assert_eq!(report.malformed().len(), 2);
    assert!(
        report
            .malformed()
            .iter()
            .all(|frame| frame.reason() == MalformedReason::EapolHeader)
    );
    Ok(())
}

#[test]
fn capture_provenance_and_truncation_are_required() -> Result<(), Box<dyn Error>> {
    let truncated = captured(
        REQUEST.to_vec(),
        Some(identity()?),
        u32::try_from(REQUEST.len() + 1)?,
    )?;
    let unknown = captured(REQUEST.to_vec(), None, u32::try_from(REQUEST.len())?)?;
    let mut link = Link::new(
        vec![ReceiveEvent::Frame(truncated), ReceiveEvent::Frame(unknown)],
        Some(0),
    )?;
    let report = probe(2, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), Dot1xStatus::Inconclusive);
    assert_eq!(report.summary().truncated_packets(), 1);
    assert_eq!(report.summary().unscoped_packets(), 1);
    assert!(report.malformed().is_empty());
    Ok(())
}

#[test]
fn unrelated_traffic_consumes_the_receive_byte_budget() -> Result<(), Box<dyn Error>> {
    let mut noise = REQUEST.to_vec();
    *noise.get_mut(5).ok_or("missing destination")? = 9;
    let mut link = Link::new(vec![ReceiveEvent::Frame(capture(&noise)?)], Some(0))?;
    let report = probe(8, u64::try_from(noise.len())?)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), Dot1xStatus::Inconclusive);
    assert_eq!(report.unrelated_packets(), 1);
    assert_eq!(
        report.summary().received_bytes(),
        u64::try_from(noise.len())?
    );
    assert_eq!(report.summary().stop_reason(), StopReason::ByteLimit);
    Ok(())
}

#[test]
fn silent_loss_and_pre_send_cancellation_never_claim_a_request() -> Result<(), Box<dyn Error>> {
    for loss in [None, Some(0), Some(3)] {
        let mut link = Link::new(vec![], loss)?;
        let report = probe(8, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
        assert_eq!(report.status(), Dot1xStatus::Inconclusive);
        assert_eq!(report.summary().capture_loss(), loss);
    }
    let mut link = Link::new(vec![], Some(0))?;
    let report = probe(8, 4_096)?.run(&mut link, &AtomicBool::new(true))?;
    assert_eq!(report.summary().stop_reason(), StopReason::Cancelled);
    assert_eq!(report.summary().sent_packets(), 0);
    assert!(link.sent.is_empty());
    Ok(())
}

#[test]
fn expired_shared_deadline_prevents_the_start() -> Result<(), Box<dyn Error>> {
    let mut link = Link::new(vec![], Some(0))?;
    let report = probe(8, 4_096)?.run_until(&mut link, &AtomicBool::new(false), Instant::now())?;
    assert_eq!(report.status(), Dot1xStatus::Inconclusive);
    assert_eq!(report.summary().stop_reason(), StopReason::Deadline);
    assert!(link.sent.is_empty());
    Ok(())
}

#[test]
fn shared_evidence_cap_bounds_repeated_requests_and_malformed_frames() -> Result<(), Box<dyn Error>>
{
    let mut invalid = REQUEST.to_vec();
    *invalid.get_mut(22).ok_or("missing EAP type")? = 0;
    let events = (0..80)
        .map(|index| {
            let frame = if index % 2 == 0 { REQUEST } else { &invalid };
            Ok(ReceiveEvent::Frame(capture(frame)?))
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let mut link = Link::new(events, Some(0))?;
    let report = probe(80, 8_192)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.observations().len(), 32);
    assert_eq!(report.malformed().len(), 32);
    assert_eq!(report.summary().received_packets(), 64);
    assert_eq!(report.summary().stop_reason(), StopReason::ObservationLimit);
    Ok(())
}
