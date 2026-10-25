use super::{bytes_at, dump, ethernet, full_record, ipv4, range, tcp, udp};
use serde_json::json;
use std::error::Error;

fn response() -> Vec<u8> {
    // A case-preserved question and compressed A owner use one complete DNS message
    let mut bytes = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
    bytes.extend_from_slice(b"\x04FaCt\x07example\x00\x00\x01\x00\x01");
    bytes.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 9]);
    bytes
}

#[test]
fn dns_reference_vlan_ip_options() -> Result<(), Box<dyn Error>> {
    let message = response();
    let mut segment = udp(42000, 53, &message, None)?;
    // Bytes beyond the UDP declaration must never become DNS record bytes
    segment.extend_from_slice(&[0xfa, 0xfb]);
    let packet = ipv4(17, &segment, &[1, 1, 1, 1], 0)?;
    let frame = ethernet(0x0800, &packet, true);
    let (status, records) = dump(&[full_record(frame.clone())?])?;
    assert!(status.success());
    let record = records.first().ok_or("missing record")?;
    assert_eq!(
        record.pointer("/ip/transport/dns/status"),
        Some(&json!("decoded"))
    );
    assert_eq!(
        record.pointer("/ip/transport/dns/message/id"),
        Some(&json!(0x1234))
    );
    let (message_offset, message_length) = range(record, "/ip/transport/payload")?;
    assert_eq!(message_length, message.len());
    let (rdata_offset, rdata_length) = range(record, "/ip/transport/dns/message/records/0/rdata")?;
    let raw = bytes_at(record, "/raw_bytes")?;
    assert_eq!(raw, frame);
    assert_eq!(
        raw.get(message_offset..message_offset + message_length),
        Some(message.as_slice())
    );
    assert_eq!(
        raw.get(message_offset + rdata_offset..message_offset + rdata_offset + rdata_length),
        Some([192, 0, 2, 9].as_slice())
    );
    Ok(())
}

#[test]
fn unresolved_dns_range_raw_evidence() -> Result<(), Box<dyn Error>> {
    let malformed = [0x12, 0x34, 0x81, 0x80, 0];
    let segment = udp(53, 42000, &malformed, None)?;
    let packet = ipv4(17, &segment, &[], 0)?;
    let frame = ethernet(0x0800, &packet, false);
    let (status, records) = dump(&[full_record(frame.clone())?])?;
    assert!(status.success());
    let record = records.first().ok_or("missing record")?;
    assert_eq!(
        record.pointer("/ip/transport/dns/status"),
        Some(&json!("unresolved"))
    );
    assert!(
        record
            .pointer("/ip/transport/dns/error")
            .is_some_and(serde_json::Value::is_object)
    );
    assert!(record.pointer("/ip/transport/dns/message").is_none());
    assert_eq!(bytes_at(record, "/raw_bytes")?, frame);
    assert_eq!(range(record, "/ip/transport/payload")?.1, malformed.len());
    Ok(())
}

#[test]
fn dns_selection_not_ports_messages() -> Result<(), Box<dyn Error>> {
    let message = response();
    let tcp_segment = tcp(42000, 53, 1, 0, 0x18, &[], &message)?;
    let other_udp = udp(42000, 42001, &message, None)?;
    let frames = [
        ethernet(0x0800, &ipv4(6, &tcp_segment, &[], 0)?, false),
        ethernet(0x0800, &ipv4(17, &other_udp, &[], 0)?, false),
    ]
    .into_iter()
    .map(full_record)
    .collect::<Result<Vec<_>, _>>()?;
    let (status, records) = dump(&frames)?;
    assert!(status.success());
    for record in &records {
        assert_eq!(
            record.pointer("/ip/transport/dns"),
            Some(&serde_json::Value::Null)
        );
    }
    Ok(())
}
