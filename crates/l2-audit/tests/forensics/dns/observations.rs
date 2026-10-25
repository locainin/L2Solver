use super::support::*;
use l2_audit::NetworkAddress;
use l2_discovery::dns::{DnsDecoding, DnsSection, DnsValue};

#[test]
fn dns_observations_offsets_decoded_ranges() -> TestResult {
    let question = standard_question()?;
    let query_frame = query(7, std::slice::from_ref(&question))?;
    let response_frame = response(
        7,
        std::slice::from_ref(&question),
        &[address_record(pointer_to_question(), ANSWER)],
        0x8180,
        &[],
        &[],
    )?;
    let query_length =
        dns_message(7, 0x0100, std::slice::from_ref(&question), &[], &[], &[])?.len();
    let response_length = dns_message(
        7,
        0x8180,
        &[question],
        &[address_record(pointer_to_question(), ANSWER)],
        &[],
        &[],
    )?
    .len();
    let report = assess([captured(query_frame, 0)?, captured(response_frame, 0)?])?;
    let facts = &report.forensics;
    assert_eq!(facts.dns_observations.len(), 2);
    for observation in &facts.dns_observations {
        assert_eq!(observation.payload_offset, 42);
        let evidence = report
            .evidence_refs
            .iter()
            .find(|reference| reference.sequence == observation.packet)
            .ok_or("missing DNS packet evidence")?;
        let payload_end = observation
            .payload_offset
            .checked_add(observation.payload_length)
            .ok_or("DNS payload range overflow")?;
        assert!(payload_end <= evidence.captured_len);
        assert!(matches!(&observation.decoding, DnsDecoding::Decoded { .. }));
    }
    let query_observation = at(&facts.dns_observations, 0)?;
    let response_observation = at(&facts.dns_observations, 1)?;
    assert_eq!(query_observation.payload_length, query_length);
    assert_eq!(response_observation.payload_length, response_length);
    let DnsDecoding::Decoded { message } = &query_observation.decoding else {
        return Err("query did not decode".into());
    };
    let question = at(&message.questions, 0)?;
    assert_eq!(question.name.wire(), encoded_name("Host.Example")?);
    assert_eq!(question.name.canonical(), encoded_name("host.example")?);
    let DnsDecoding::Decoded { message } = &response_observation.decoding else {
        return Err("response did not decode".into());
    };
    assert_eq!(message.records.len(), 1);
    let record = at(&message.records, 0)?;
    assert_eq!(record.section, DnsSection::Answer);
    assert_eq!(record.rdata.length, 4);
    let rdata_end = record
        .rdata
        .offset
        .checked_add(record.rdata.length)
        .ok_or("DNS RDATA range overflow")?;
    assert!(rdata_end <= response_length);
    assert_eq!(
        record.value,
        DnsValue::Address(NetworkAddress::Ipv4(ANSWER))
    );
    Ok(())
}
#[test]
fn malformed_dns_unresolved_never_correlated() -> TestResult {
    let question = standard_question()?;
    let mut malformed = dns_message(50, 0x0100, std::slice::from_ref(&question), &[], &[], &[])?;
    // A self-pointer must fail parsing instead of becoming a pending query
    *malformed.get_mut(12).ok_or("short DNS fixture")? = 0xc0;
    *malformed.get_mut(13).ok_or("short DNS fixture")? = 0x0c;
    let valid_response = response(
        50,
        std::slice::from_ref(&question),
        &[address_record(pointer_to_question(), ANSWER)],
        0x8180,
        &[],
        &[],
    )?;
    let report = assess([
        captured(
            ipv4_udp_frame(CLIENT, RESOLVER, CLIENT_PORT, DNS_PORT, &malformed)?,
            0,
        )?,
        captured(valid_response, 0)?,
    ])?;
    assert_eq!(report.forensics.dns_candidates_seen, 2);
    assert_eq!(report.forensics.dns_messages_parsed, 1);
    assert_eq!(report.forensics.dns_observations.len(), 2);
    assert!(matches!(
        &at(&report.forensics.dns_observations, 0)?.decoding,
        DnsDecoding::Unresolved { .. }
    ));
    assert!(matches!(
        &at(&report.forensics.dns_observations, 1)?.decoding,
        DnsDecoding::Decoded { .. }
    ));
    assert_eq!(at(&report.forensics.dns_matches, 0)?.query_packet, None);
    assert!(report.forensics.dns_address_uses.is_empty());
    assert!(!report.collection_complete());
    Ok(())
}
#[test]
fn unfragmented_udp_packets_dns_candidates() -> TestResult {
    let question = standard_question()?;
    let message = dns_message(60, 0x0100, std::slice::from_ref(&question), &[], &[], &[])?;
    let mut fragmented = ipv4_udp_frame(CLIENT, RESOLVER, CLIENT_PORT, DNS_PORT, &message)?;
    fragmented
        .get_mut(20..22)
        .ok_or("short IPv4 fixture")?
        .copy_from_slice(&0x2000_u16.to_be_bytes());
    let mut invalid_udp = ipv4_udp_frame(CLIENT, RESOLVER, CLIENT_PORT, DNS_PORT, &message)?;
    invalid_udp
        .get_mut(38..40)
        .ok_or("short UDP fixture")?
        .copy_from_slice(&u16::MAX.to_be_bytes());
    let mdns = ipv4_udp_frame(CLIENT, [224, 0, 0, 251], CLIENT_PORT, 5353, &message)?;
    let tcp = ipv4_tcp_frame(&message)?;
    let report = assess([
        captured(fragmented, 0)?,
        captured(invalid_udp, 0)?,
        captured(mdns, 0)?,
        captured(tcp, 0)?,
    ])?;
    assert_eq!(report.forensics.dns_candidates_seen, 0);
    assert!(report.forensics.dns_observations.is_empty());
    Ok(())
}
#[test]
fn dns_payload_ip_trailing_bytes() -> TestResult {
    let question = standard_question()?;
    let message = dns_message(62, 0x0100, std::slice::from_ref(&question), &[], &[], &[])?;
    let mut frame = ipv4_udp_frame(CLIENT, RESOLVER, CLIENT_PORT, DNS_PORT, &message)?;
    frame.extend_from_slice(&[0xa5, 0x5a, 0x01, 0xfe]);
    let ip_total_length = u16::try_from(frame.len() - 14)?;
    frame
        .get_mut(16..18)
        .ok_or("short IPv4 fixture")?
        .copy_from_slice(&ip_total_length.to_be_bytes());
    let report = assess([captured(frame, 0)?])?;
    assert_eq!(report.forensics.dns_observations.len(), 1);
    let observation = at(&report.forensics.dns_observations, 0)?;
    assert_eq!(observation.payload_offset, 42);
    assert_eq!(observation.payload_length, message.len());
    assert!(matches!(&observation.decoding, DnsDecoding::Decoded { .. }));
    Ok(())
}
