use super::support::capture;
use l2_capture::{CaptureMetadata, CapturedFrame, InterfaceId};
use l2_workbench::store::{Options, Relationship, Store};
use std::{error::Error, io::Cursor, net::IpAddr};

const REQUESTER: [u8; 4] = [192, 0, 2, 128];
const DNS_SERVER: [u8; 4] = [192, 0, 2, 53];
const LOWER_ANSWER: [u8; 4] = [192, 0, 2, 10];
const HIGHER_ANSWER: [u8; 4] = [192, 0, 2, 200];

#[test]
fn relationships_both_endpoint_requester_fanout() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut packets = vec![
        dns_packet(
            false,
            REQUESTER,
            DNS_SERVER,
            &[LOWER_ANSWER, HIGHER_ANSWER],
            None,
        )?,
        dns_packet(
            true,
            REQUESTER,
            DNS_SERVER,
            &[LOWER_ANSWER, HIGHER_ANSWER],
            None,
        )?,
    ];
    // Keep one requester across many unrelated endpoints to exercise fanout without timing checks
    for offset in 0..128_u8 {
        packets.push(tcp_packet(
            REQUESTER,
            [198, 51, 100, offset.saturating_add(1)],
            50_000,
            443,
            None,
        )?);
    }
    packets.push(tcp_packet(REQUESTER, LOWER_ANSWER, 50_000, 443, None)?);
    packets.push(tcp_packet(REQUESTER, HIGHER_ANSWER, 50_000, 443, None)?);
    let mut store = Store::create(temporary.path(), Options::default())?;
    let source = store.ingest("endpoint-orders", Cursor::new(capture(&packets)?))?;

    let all = relationships(&store, None)?;
    let first = all.first().ok_or("first answer relationship missing")?;
    let second = all.get(1).ok_or("second answer relationship missing")?;
    assert_eq!(all.len(), 2);
    assert_eq!(first.answer_address, IpAddr::from(LOWER_ANSWER));
    assert_eq!(second.answer_address, IpAddr::from(HIGHER_ANSWER));
    assert_eq!(first.destination_packet, 131);
    assert_eq!(second.destination_packet, 132);
    assert_eq!(first.source_id, source.source_id);
    assert_eq!(second.source_id, source.source_id);

    let limited = relationships(&store, Some(1))?;
    assert_eq!(limited.len(), 1);
    assert_eq!(
        limited.first().map(|entry| entry.answer_address),
        Some(first.answer_address)
    );
    assert!(relationships(&store, Some(0))?.is_empty());
    Ok(())
}

#[test]
fn relationships_never_cross_source_scope() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    let dns = [
        dns_packet(false, REQUESTER, DNS_SERVER, &[HIGHER_ANSWER], None)?,
        dns_packet(true, REQUESTER, DNS_SERVER, &[HIGHER_ANSWER], None)?,
    ];
    let flow = tcp_packet(REQUESTER, HIGHER_ANSWER, 50_000, 443, None)?;
    let flow_bytes = capture(std::slice::from_ref(&flow))?;
    store.ingest("dns-only", Cursor::new(capture(&dns)?))?;
    store.ingest("flow-only", Cursor::new(flow_bytes))?;
    assert!(relationships(&store, None)?.is_empty());

    let scoped_dns = [
        dns_packet(false, REQUESTER, DNS_SERVER, &[HIGHER_ANSWER], Some(7))?,
        dns_packet(true, REQUESTER, DNS_SERVER, &[HIGHER_ANSWER], Some(7))?,
        tcp_packet(REQUESTER, HIGHER_ANSWER, 50_000, 443, Some(8))?,
    ];
    // Matching addresses cannot bridge different VLAN scopes inside one source
    store.ingest("different-scopes", Cursor::new(capture(&scoped_dns)?))?;
    assert!(relationships(&store, None)?.is_empty());
    Ok(())
}

#[test]
fn same_address_earliest_directional_packet() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let packets = [
        dns_packet(false, REQUESTER, DNS_SERVER, &[REQUESTER], None)?,
        dns_packet(true, REQUESTER, DNS_SERVER, &[REQUESTER], None)?,
        tcp_packet(REQUESTER, REQUESTER, 50_000, 443, None)?,
        tcp_packet(REQUESTER, REQUESTER, 443, 50_000, None)?,
    ];
    // Both endpoint clauses match, so the merged relationship must keep one earliest witness
    let mut store = Store::create(temporary.path(), Options::default())?;
    store.ingest("same-address", Cursor::new(capture(&packets)?))?;

    let found = relationships(&store, None)?;
    let relationship = found.first().ok_or("same-address relationship missing")?;
    assert_eq!(found.len(), 1);
    assert_eq!(relationship.answer_address, IpAddr::from(REQUESTER));
    assert_eq!(relationship.destination_packet, 3);
    Ok(())
}

#[test]
fn relationship_requires_requester_answer_direction() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let packets = [
        tcp_packet(REQUESTER, HIGHER_ANSWER, 50_000, 443, None)?,
        dns_packet(false, REQUESTER, DNS_SERVER, &[HIGHER_ANSWER], None)?,
        dns_packet(true, REQUESTER, DNS_SERVER, &[HIGHER_ANSWER], None)?,
        tcp_packet(HIGHER_ANSWER, REQUESTER, 443, 50_000, None)?,
    ];
    let mut store = Store::create(temporary.path(), Options::default())?;
    store.ingest("reverse-only-after-answer", Cursor::new(capture(&packets)?))?;

    assert!(relationships(&store, None)?.is_empty());
    Ok(())
}

#[test]
fn opposite_direction_packet_match() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let packets = [
        tcp_packet(REQUESTER, HIGHER_ANSWER, 50_000, 443, None)?,
        dns_packet(false, REQUESTER, DNS_SERVER, &[HIGHER_ANSWER], None)?,
        dns_packet(true, REQUESTER, DNS_SERVER, &[HIGHER_ANSWER], None)?,
        tcp_packet(HIGHER_ANSWER, REQUESTER, 443, 50_000, None)?,
        tcp_packet(REQUESTER, HIGHER_ANSWER, 50_000, 443, None)?,
    ];
    let mut store = Store::create(temporary.path(), Options::default())?;
    store.ingest("matching-after-opposite", Cursor::new(capture(&packets)?))?;

    let found = relationships(&store, None)?;
    let relationship = found
        .first()
        .ok_or("matching direction relationship missing")?;
    assert_eq!(found.len(), 1);
    assert_eq!(relationship.destination_packet, 5);
    Ok(())
}

fn relationships(store: &Store, maximum: Option<u64>) -> Result<Vec<Relationship>, Box<dyn Error>> {
    let mut results = Vec::new();
    store.visit_relationships(maximum, |relationship| {
        results.push(relationship);
        Ok(())
    })?;
    Ok(results)
}

fn dns_packet(
    response: bool,
    requester: [u8; 4],
    server: [u8; 4],
    answers: &[[u8; 4]],
    vlan: Option<u16>,
) -> Result<CapturedFrame, Box<dyn Error>> {
    // Queries and responses share an identifier and question, while answers appear only in responses
    let mut message = vec![0, 7];
    message.extend_from_slice(&(if response { 0x8180_u16 } else { 0x0100_u16 }).to_be_bytes());
    message.extend_from_slice(&[0, 1]);
    message
        .extend_from_slice(&u16::try_from(if response { answers.len() } else { 0 })?.to_be_bytes());
    message.extend_from_slice(&[0, 0, 0, 0]);
    message.extend_from_slice(b"\x01x\x07invalid\0\0\x01\0\x01");
    if response {
        for address in answers {
            message.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4]);
            message.extend_from_slice(address);
        }
    }
    let (source, destination, source_port, destination_port) = if response {
        (server, requester, 53_u16, 44_000_u16)
    } else {
        (requester, server, 44_000, 53)
    };
    let mut datagram = Vec::new();
    datagram.extend_from_slice(&source_port.to_be_bytes());
    datagram.extend_from_slice(&destination_port.to_be_bytes());
    datagram.extend_from_slice(&u16::try_from(8 + message.len())?.to_be_bytes());
    datagram.extend_from_slice(&[0, 0]);
    datagram.extend_from_slice(&message);
    ipv4_packet(source, destination, 17, &datagram, vlan)
}

fn tcp_packet(
    source: [u8; 4],
    destination: [u8; 4],
    source_port: u16,
    destination_port: u16,
    vlan: Option<u16>,
) -> Result<CapturedFrame, Box<dyn Error>> {
    let mut segment = Vec::new();
    segment.extend_from_slice(&source_port.to_be_bytes());
    segment.extend_from_slice(&destination_port.to_be_bytes());
    segment.extend_from_slice(&[0; 8]);
    segment.extend_from_slice(&[0x50, 0x18, 0, 0, 0, 0, 0, 0]);
    ipv4_packet(source, destination, 6, &segment, vlan)
}

fn ipv4_packet(
    source: [u8; 4],
    destination: [u8; 4],
    protocol: u8,
    payload: &[u8],
    vlan: Option<u16>,
) -> Result<CapturedFrame, Box<dyn Error>> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&[2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1]);
    // VLAN bytes sit between the Ethernet addresses and the IPv4 type field
    if let Some(vid) = vlan {
        bytes.extend_from_slice(&0x8100_u16.to_be_bytes());
        bytes.extend_from_slice(&vid.to_be_bytes());
    }
    bytes.extend_from_slice(&0x0800_u16.to_be_bytes());
    bytes.push(0x45);
    bytes.push(0);
    bytes.extend_from_slice(&u16::try_from(20 + payload.len())?.to_be_bytes());
    bytes.extend_from_slice(&[0, 1, 0, 0, 64, protocol, 0, 0]);
    bytes.extend_from_slice(&source);
    bytes.extend_from_slice(&destination);
    bytes.extend_from_slice(payload);
    let metadata = CaptureMetadata::unknown(
        InterfaceId {
            section: 0,
            index: 0,
        },
        u32::try_from(bytes.len())?,
    );
    Ok(CapturedFrame::new(bytes, metadata)?)
}
