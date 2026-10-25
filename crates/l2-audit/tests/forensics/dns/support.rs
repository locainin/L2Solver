use super::super::support::ethernet;
pub(super) use super::super::support::{CLIENT_MAC, FIRST_MAC, SECOND_MAC};
pub(super) use super::super::support::{TestResult, assert_evidence, assess, captured, tagged};
use l2_capture::{CaptureMetadata, CapturedFrame, Direction, FcsStatus, InterfaceId};

pub(super) const CLIENT: [u8; 4] = [192, 0, 2, 10];
pub(super) const OTHER_CLIENT: [u8; 4] = [192, 0, 2, 11];
pub(super) const RESOLVER: [u8; 4] = [192, 0, 2, 53];
pub(super) const ANSWER: [u8; 4] = [198, 51, 100, 7];
pub(super) const CLIENT_PORT: u16 = 53000;
pub(super) const DNS_PORT: u16 = 53;
type FixtureResult<T> = Result<T, Box<dyn std::error::Error>>;

pub(super) fn at<T>(values: &[T], index: usize) -> Result<&T, &'static str> {
    values.get(index).ok_or("expected test item is missing")
}

fn u8_length(length: usize) -> FixtureResult<u8> {
    Ok(u8::try_from(length)?)
}

fn u16_length(length: usize) -> FixtureResult<u16> {
    Ok(u16::try_from(length)?)
}

fn write_field<const LENGTH: usize>(
    buffer: &mut [u8],
    start: usize,
    value: &[u8; LENGTH],
) -> FixtureResult<()> {
    let end = start
        .checked_add(LENGTH)
        .ok_or("fixture field range overflow")?;
    let field = buffer
        .get_mut(start..end)
        .ok_or("fixture field is outside the buffer")?;
    field.copy_from_slice(value);
    Ok(())
}

#[derive(Clone)]
pub(super) struct Question {
    name: Vec<u8>,
    qtype: u16,
    qclass: u16,
}

pub(super) struct Record {
    owner: Vec<u8>,
    rr_type: u16,
    class: u16,
    ttl: u32,
    data: Vec<u8>,
}

pub(super) fn encoded_name(name: &str) -> FixtureResult<Vec<u8>> {
    // Keep the original label bytes so case-preservation is testable
    let mut wire = Vec::new();
    for label in name.split('.') {
        let length = u8_length(label.len())?;
        assert!(!label.is_empty() && length <= 63);
        wire.push(length);
        wire.extend_from_slice(label.as_bytes());
    }
    wire.push(0);
    Ok(wire)
}

pub(super) fn question(name: &str, qtype: u16, qclass: u16) -> FixtureResult<Question> {
    Ok(Question {
        name: encoded_name(name)?,
        qtype,
        qclass,
    })
}

pub(super) const fn record(owner: Vec<u8>, rr_type: u16, class: u16, data: Vec<u8>) -> Record {
    Record {
        owner,
        rr_type,
        class,
        ttl: 60,
        data,
    }
}

pub(super) fn address_record(owner: Vec<u8>, address: [u8; 4]) -> Record {
    record(owner, 1, 1, address.to_vec())
}

pub(super) fn aaaa_record(owner: Vec<u8>, address: [u8; 16]) -> Record {
    record(owner, 28, 1, address.to_vec())
}

pub(super) fn cname_record(owner: Vec<u8>, target: &str) -> FixtureResult<Record> {
    Ok(record(owner, 5, 1, encoded_name(target)?))
}

pub(super) fn pointer_to_question() -> Vec<u8> {
    // The first question name begins at message offset twelve
    vec![0xc0, 0x0c]
}

pub(super) fn opt_record(extended_response_code: u8) -> Record {
    // The high response-code byte is stored in the OPT TTL prefix
    Record {
        owner: vec![0],
        rr_type: 41,
        class: 1232,
        ttl: u32::from(extended_response_code) << 24,
        data: Vec::new(),
    }
}

pub(super) fn dns_message(
    id: u16,
    flags: u16,
    questions: &[Question],
    answers: &[Record],
    authorities: &[Record],
    additionals: &[Record],
) -> FixtureResult<Vec<u8>> {
    let section_counts = [
        questions.len(),
        answers.len(),
        authorities.len(),
        additionals.len(),
    ];
    let mut message = Vec::new();
    message.extend_from_slice(&id.to_be_bytes());
    message.extend_from_slice(&flags.to_be_bytes());
    for count in section_counts {
        message.extend_from_slice(&u16_length(count)?.to_be_bytes());
    }
    for question in questions {
        message.extend_from_slice(&question.name);
        message.extend_from_slice(&question.qtype.to_be_bytes());
        message.extend_from_slice(&question.qclass.to_be_bytes());
    }
    // DNS records are serialized in answer, authority, then additional order
    for record in answers.iter().chain(authorities).chain(additionals) {
        message.extend_from_slice(&record.owner);
        message.extend_from_slice(&record.rr_type.to_be_bytes());
        message.extend_from_slice(&record.class.to_be_bytes());
        message.extend_from_slice(&record.ttl.to_be_bytes());
        message.extend_from_slice(&u16_length(record.data.len())?.to_be_bytes());
        message.extend_from_slice(&record.data);
    }
    Ok(message)
}

pub(super) fn ipv4_udp_frame(
    source: [u8; 4],
    destination: [u8; 4],
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> FixtureResult<Vec<u8>> {
    ipv4_udp_frame_with_macs(
        source,
        destination,
        source_port,
        destination_port,
        payload,
        CLIENT_MAC,
        SECOND_MAC,
    )
}

pub(super) fn ipv4_udp_frame_with_macs(
    source: [u8; 4],
    destination: [u8; 4],
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
    source_mac: [u8; 6],
    destination_mac: [u8; 6],
) -> FixtureResult<Vec<u8>> {
    let udp_len = 8 + payload.len();
    let ip_len = 20 + udp_len;
    let mut udp = Vec::with_capacity(udp_len);
    udp.extend_from_slice(&source_port.to_be_bytes());
    udp.extend_from_slice(&destination_port.to_be_bytes());
    udp.extend_from_slice(&u16_length(udp_len)?.to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(payload);

    let mut ip = vec![0x45, 0, 0, 0, 0, 1, 0, 0, 64, 17, 0, 0];
    write_field(&mut ip, 2, &u16_length(ip_len)?.to_be_bytes())?;
    ip.extend_from_slice(&source);
    ip.extend_from_slice(&destination);
    ip.extend_from_slice(&udp);
    Ok(ethernet(source_mac, destination_mac, 0x0800, &ip))
}

pub(super) fn ipv4_tcp_frame(payload: &[u8]) -> FixtureResult<Vec<u8>> {
    // A single TCP segment is only a boundary check, not a reassembled DNS message
    let tcp_len = 20 + payload.len();
    let ip_len = 20 + tcp_len;
    let mut tcp = Vec::with_capacity(tcp_len);
    tcp.extend_from_slice(&0x01bb_u16.to_be_bytes());
    tcp.extend_from_slice(&DNS_PORT.to_be_bytes());
    tcp.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x18]);
    tcp.extend_from_slice(&[0x10, 0, 0, 0, 0, 0]);
    tcp.extend_from_slice(payload);
    let mut ip = vec![0x45, 0, 0, 0, 0, 1, 0, 0, 64, 6, 0, 0];
    write_field(&mut ip, 2, &u16_length(ip_len)?.to_be_bytes())?;
    ip.extend_from_slice(&CLIENT);
    ip.extend_from_slice(&RESOLVER);
    ip.extend_from_slice(&tcp);
    Ok(ethernet(CLIENT_MAC, SECOND_MAC, 0x0800, &ip))
}

pub(super) fn ipv6_udp_frame(
    source: [u8; 16],
    destination: [u8; 16],
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> FixtureResult<Vec<u8>> {
    let udp_len = 8 + payload.len();
    let mut udp = Vec::with_capacity(udp_len);
    udp.extend_from_slice(&source_port.to_be_bytes());
    udp.extend_from_slice(&destination_port.to_be_bytes());
    udp.extend_from_slice(&u16_length(udp_len)?.to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(payload);

    let mut ip = vec![0x60, 0, 0, 0, 0, 0, 17, 64];
    write_field(&mut ip, 4, &u16_length(udp_len)?.to_be_bytes())?;
    ip.extend_from_slice(&source);
    ip.extend_from_slice(&destination);
    ip.extend_from_slice(&udp);
    Ok(ethernet(CLIENT_MAC, SECOND_MAC, 0x86dd, &ip))
}

pub(super) fn captured_in(
    bytes: Vec<u8>,
    section: u32,
    interface: u32,
) -> FixtureResult<CapturedFrame> {
    let length = u32::try_from(bytes.len())?;
    Ok(CapturedFrame::new(
        bytes,
        CaptureMetadata::new(
            InterfaceId {
                section,
                index: interface,
            },
            length,
            None,
            None,
            Direction::Unknown,
            None,
            FcsStatus::Unknown,
        ),
    )?)
}

pub(super) fn client_use(source: [u8; 4], destination: [u8; 4]) -> FixtureResult<Vec<u8>> {
    ipv4_udp_frame(source, destination, 40000, 443, &[])
}

pub(super) fn standard_question() -> FixtureResult<Question> {
    question("Host.Example", 1, 1)
}

pub(super) fn query(id: u16, questions: &[Question]) -> FixtureResult<Vec<u8>> {
    let message = dns_message(id, 0x0100, questions, &[], &[], &[])?;
    ipv4_udp_frame(CLIENT, RESOLVER, CLIENT_PORT, DNS_PORT, &message)
}

pub(super) fn response(
    id: u16,
    questions: &[Question],
    answers: &[Record],
    flags: u16,
    authorities: &[Record],
    additionals: &[Record],
) -> FixtureResult<Vec<u8>> {
    let message = dns_message(id, flags, questions, answers, authorities, additionals)?;
    ipv4_udp_frame(RESOLVER, CLIENT, DNS_PORT, CLIENT_PORT, &message)
}
