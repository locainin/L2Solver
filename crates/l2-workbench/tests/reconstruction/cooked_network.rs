use super::support::{cooked, fragment, tcp};
use l2_capture::{CaptureMetadata, CapturedFrame, InterfaceId};
use l2_workbench::reconstruction::Reconstructor;
use std::error::Error;

fn ipv6_fragment(flags: u16, body: &[u8]) -> Result<CapturedFrame, Box<dyn Error>> {
    let mut frame = vec![2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 0x86, 0xdd];
    frame.extend_from_slice(&[0x60, 0, 0, 0]);
    frame.extend_from_slice(&u16::try_from(8 + body.len())?.to_be_bytes());
    frame.extend_from_slice(&[44, 64]);
    frame.extend_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    frame.extend_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    frame.extend_from_slice(&[17, 0]);
    frame.extend_from_slice(&flags.to_be_bytes());
    frame.extend_from_slice(&42_u32.to_be_bytes());
    frame.extend_from_slice(body);
    let metadata = CaptureMetadata::unknown(
        InterfaceId {
            section: 0,
            index: 0,
        },
        u32::try_from(frame.len())?,
    );
    Ok(CapturedFrame::new(frame, metadata)?)
}

#[test]
fn cooked_tcp_preserves_offsets_and_capture_local_scopes() -> Result<(), Box<dyn Error>> {
    let mut engine = Reconstructor::new();
    let first = InterfaceId {
        section: 2,
        index: 7,
    };
    let other = InterfaceId {
        section: 2,
        index: 8,
    };
    for (number, version, scope, ifindex, bytes) in [
        (1, 113, first, 0, b"sll1".as_slice()),
        (2, 276, first, 37, b"sll2".as_slice()),
        (3, 276, first, 38, b"other".as_slice()),
        (4, 276, other, 37, b"interface".as_slice()),
    ] {
        let packet = cooked(
            tcp(false, 101, 0x18, bytes)?.bytes(),
            version,
            scope,
            ifindex,
        )?;
        engine.observe(number, &packet)?;
    }
    let report = engine.finish()?;
    assert_eq!(report.unsupported_frames, 0);
    assert_eq!(report.sessions.len(), 4);
    for (version, scope, ifindex, expected) in [
        (113, first, None, b"sll1".as_slice()),
        (276, first, Some(37), b"sll2".as_slice()),
        (276, first, Some(38), b"other".as_slice()),
        (276, other, Some(37), b"interface".as_slice()),
    ] {
        let session = report
            .sessions
            .iter()
            .find(|session| {
                session.scope.section == scope.section
                    && session.scope.interface == scope.index
                    && session.scope.cooked_ifindex == ifindex
            })
            .ok_or("missing scoped cooked session")?;
        assert_eq!(session.scope.vlan_ids.len(), 0);
        assert_eq!(session.scope.vlan_aux, None);
        let stream = session
            .directions
            .iter()
            .find(|stream| !stream.origins.is_empty())
            .ok_or("missing TCP stream")?;
        assert_eq!(stream.runs().first().map(|run| run.bytes), Some(expected));
        assert_eq!(
            stream
                .origins
                .first()
                .ok_or("missing TCP origin")?
                .frame_offset,
            if version == 113 { 56 } else { 60 }
        );
    }
    Ok(())
}

#[test]
fn cooked_ipv6_fragments_reassemble_with_header_relative_ranges() -> Result<(), Box<dyn Error>> {
    for (version, header) in [(113, 16), (276, 20)] {
        let interface = InterfaceId {
            section: 0,
            index: 0,
        };
        let first = cooked(
            ipv6_fragment(1, &[0x9c, 0x40, 0x23, 0x45, 0, 14, 0, 0])?.bytes(),
            version,
            interface,
            7,
        )?;
        let second = cooked(ipv6_fragment(8, b"abcdef")?.bytes(), version, interface, 7)?;
        let mut engine = Reconstructor::new();
        engine.observe(1, &first)?;
        engine.observe(2, &second)?;
        let report = engine.finish()?;
        let message = report.udp.first().ok_or("missing IPv6 UDP")?;
        assert_eq!(message.bytes, b"abcdef");
        let origin = message.origins.first().ok_or("missing IPv6 origin")?;
        assert_eq!(origin.packet, 2);
        assert_eq!(origin.frame_offset, header + 48);
        assert_eq!(
            second
                .bytes()
                .get(origin.frame_offset..origin.frame_offset + origin.length),
            Some(message.bytes.as_slice())
        );
    }
    Ok(())
}

#[test]
fn cooked_fragments_reassemble_udp_with_literal_source_offsets() -> Result<(), Box<dyn Error>> {
    for (version, header) in [(113, 16), (276, 20)] {
        let mut engine = Reconstructor::new();
        let interface = InterfaceId {
            section: 1,
            index: 3,
        };
        let first = cooked(
            fragment(0x2000, &[0x9c, 0x40, 0x23, 0x45, 0, 14, 0, 0])?.bytes(),
            version,
            interface,
            42,
        )?;
        let second = cooked(fragment(1, b"abcdef")?.bytes(), version, interface, 42)?;
        engine.observe(1, &first)?;
        engine.observe(2, &second)?;
        let report = engine.finish()?;
        assert_eq!(report.unsupported_frames, 0);
        let message = report.udp.first().ok_or("missing UDP message")?;
        assert_eq!(message.bytes, b"abcdef");
        assert!(message.fragment_candidate.is_some());
        assert_eq!(message.origins.len(), 1);
        let origin = message.origins.first().ok_or("missing IPv4 origin")?;
        assert_eq!(origin.packet, 2);
        assert_eq!(origin.frame_offset, header + 20);
        assert_eq!(
            second
                .bytes()
                .get(origin.frame_offset..origin.frame_offset + origin.length),
            Some(message.bytes.as_slice())
        );
        let datagram = report.datagrams.first().ok_or("missing datagram")?;
        assert_eq!(
            datagram
                .origins
                .iter()
                .map(|origin| origin.frame_offset)
                .collect::<Vec<_>>(),
            [header + 20, header + 20]
        );
    }
    Ok(())
}
