use super::support::*;
use l2_audit::NetworkAddress;
use l2_discovery::dns::{DnsDecoding, DnsSection, DnsValue};

#[test]
fn matched_answer_use_client_class() -> TestResult {
    let question = standard_question()?;
    let query_frame = query(0x1234, std::slice::from_ref(&question))?;
    let answer = address_record(pointer_to_question(), ANSWER);
    let response_message = dns_message(
        0x1234,
        0x8180,
        std::slice::from_ref(&question),
        &[answer],
        &[],
        &[],
    )?;
    let response_frame = ipv4_udp_frame_with_macs(
        RESOLVER,
        CLIENT,
        DNS_PORT,
        CLIENT_PORT,
        &response_message,
        FIRST_MAC,
        [2, 0, 0, 0, 0, 9],
    )?;
    // The response has unrelated Ethernet addresses but the reversed IP/UDP tuple
    let report = assess([
        captured(query_frame, 0)?,
        captured(response_frame, 0)?,
        captured(client_use(CLIENT, ANSWER)?, 0)?,
        captured(client_use(CLIENT, ANSWER)?, 0)?,
        captured(client_use(OTHER_CLIENT, ANSWER)?, 0)?,
        captured(client_use(OTHER_CLIENT, ANSWER)?, 0)?,
    ])?;
    let facts = &report.forensics;
    assert_eq!(facts.dns_observations.len(), 2);
    assert_eq!(facts.dns_candidates_seen, 2);
    assert_eq!(facts.dns_messages_parsed, 2);
    assert_eq!(facts.dns_matches.len(), 1);
    let matched = at(&facts.dns_matches, 0)?;
    assert_eq!(matched.response_packet, 2);
    assert_eq!(matched.query_packet, Some(1));
    assert_eq!(matched.candidate_queries, 1);
    assert_eq!(facts.dns_address_uses.len(), 2);
    let first_use = at(&facts.dns_address_uses, 0)?;
    assert_eq!(first_use.query_packet, 1);
    assert_eq!(first_use.response_packet, 2);
    assert_eq!(first_use.packet, 3);
    assert_eq!(first_use.answer_record, 0);
    assert_eq!(first_use.address, NetworkAddress::Ipv4(ANSWER));
    assert!(first_use.client_matches_requester);
    let second_use = at(&facts.dns_address_uses, 1)?;
    assert_eq!(second_use.packet, 5);
    assert!(!second_use.client_matches_requester);
    assert_evidence(&report, &[1, 2, 3, 5]);
    Ok(())
}
#[test]
fn cname_chains_final_answer_owner() -> TestResult {
    let question = standard_question()?;
    let answers = [
        cname_record(pointer_to_question(), "alias.example")?,
        cname_record(encoded_name("alias.example")?, "address.example")?,
        address_record(encoded_name("address.example")?, ANSWER),
    ];
    let report = assess([
        captured(query(14, std::slice::from_ref(&question))?, 0)?,
        captured(
            response(
                14,
                std::slice::from_ref(&question),
                &answers,
                0x8180,
                &[],
                &[],
            )?,
            0,
        )?,
        captured(client_use(CLIENT, ANSWER)?, 0)?,
    ])?;
    assert_eq!(report.forensics.dns_address_uses.len(), 1);
    let address_use = at(&report.forensics.dns_address_uses, 0)?;
    assert_eq!(address_use.answer_record, 2);
    assert_eq!(address_use.address, NetworkAddress::Ipv4(ANSWER));
    assert!(address_use.client_matches_requester);
    Ok(())
}

#[test]
fn duplicate_address_later_use_fact() -> TestResult {
    let question = standard_question()?;
    let answer = address_record(pointer_to_question(), ANSWER);
    let report = assess([
        captured(query(15, std::slice::from_ref(&question))?, 0)?,
        captured(
            response(
                15,
                std::slice::from_ref(&question),
                &[answer, address_record(pointer_to_question(), ANSWER)],
                0x8180,
                &[],
                &[],
            )?,
            0,
        )?,
        captured(client_use(CLIENT, ANSWER)?, 0)?,
    ])?;

    assert_eq!(report.forensics.dns_address_uses.len(), 1);
    assert_eq!(at(&report.forensics.dns_address_uses, 0)?.answer_record, 0);
    Ok(())
}

#[test]
fn other_client_not_first_use() -> TestResult {
    let question = standard_question()?;
    let report = assess([
        captured(query(16, std::slice::from_ref(&question))?, 0)?,
        captured(
            response(
                16,
                std::slice::from_ref(&question),
                &[address_record(pointer_to_question(), ANSWER)],
                0x8180,
                &[],
                &[],
            )?,
            0,
        )?,
        captured(client_use(OTHER_CLIENT, ANSWER)?, 0)?,
        captured(client_use(OTHER_CLIENT, ANSWER)?, 0)?,
        captured(client_use(CLIENT, ANSWER)?, 0)?,
        captured(client_use(CLIENT, ANSWER)?, 0)?,
    ])?;

    assert_eq!(report.forensics.dns_address_uses.len(), 2);
    let first_use = at(&report.forensics.dns_address_uses, 0)?;
    assert_eq!(first_use.packet, 3);
    assert!(!first_use.client_matches_requester);
    let requester_use = at(&report.forensics.dns_address_uses, 1)?;
    assert_eq!(requester_use.packet, 5);
    assert!(requester_use.client_matches_requester);
    assert_evidence(&report, &[1, 2, 3, 5]);
    Ok(())
}

#[test]
fn response_destination_not_answer_use() -> TestResult {
    let question = standard_question()?;
    let response_dns = dns_message(
        17,
        0x8180,
        std::slice::from_ref(&question),
        &[address_record(pointer_to_question(), CLIENT)],
        &[],
        &[],
    )?;
    let response_frame = ipv4_udp_frame_with_macs(
        RESOLVER,
        CLIENT,
        DNS_PORT,
        CLIENT_PORT,
        &response_dns,
        FIRST_MAC,
        [2, 0, 0, 0, 0, 9],
    )?;
    let report = assess([
        captured(query(17, std::slice::from_ref(&question))?, 0)?,
        captured(response_frame, 0)?,
        captured(client_use(OTHER_CLIENT, CLIENT)?, 0)?,
    ])?;

    assert_eq!(report.forensics.dns_address_uses.len(), 1);
    let address_use = at(&report.forensics.dns_address_uses, 0)?;
    assert_eq!(address_use.response_packet, 2);
    assert_eq!(address_use.packet, 3);
    assert!(!address_use.client_matches_requester);
    Ok(())
}

#[test]
fn ambiguous_cname_suppresses_address_use() -> TestResult {
    let question = standard_question()?;
    let cases = [
        vec![
            cname_record(pointer_to_question(), "first.example")?,
            cname_record(pointer_to_question(), "second.example")?,
            address_record(encoded_name("first.example")?, ANSWER),
        ],
        vec![
            cname_record(pointer_to_question(), "alias.example")?,
            cname_record(encoded_name("alias.example")?, "Host.Example")?,
            address_record(encoded_name("alias.example")?, ANSWER),
        ],
        vec![
            cname_record(pointer_to_question(), "alias.example")?,
            address_record(pointer_to_question(), ANSWER),
            address_record(encoded_name("alias.example")?, ANSWER),
        ],
        vec![
            record(pointer_to_question(), 2, 1, encoded_name("alias.example")?),
            address_record(encoded_name("alias.example")?, ANSWER),
        ],
        vec![
            cname_record(pointer_to_question(), "alias.example")?,
            aaaa_record(
                pointer_to_question(),
                [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8],
            ),
            address_record(encoded_name("alias.example")?, ANSWER),
        ],
    ];
    for (index, answers) in cases.into_iter().enumerate() {
        let id = 20 + u16::try_from(index)?;
        let report = assess([
            captured(query(id, std::slice::from_ref(&question))?, 0)?,
            captured(
                response(
                    id,
                    std::slice::from_ref(&question),
                    &answers,
                    0x8180,
                    &[],
                    &[],
                )?,
                0,
            )?,
            captured(client_use(CLIENT, ANSWER)?, 0)?,
        ])?;
        assert!(report.forensics.dns_address_uses.is_empty(), "case {index}");
    }
    Ok(())
}
#[test]
fn authority_additional_not_answer_evidence() -> TestResult {
    let question = standard_question()?;
    let report = assess([
        captured(query(25, std::slice::from_ref(&question))?, 0)?,
        captured(
            response(
                25,
                std::slice::from_ref(&question),
                &[],
                0x8180,
                &[record(
                    pointer_to_question(),
                    2,
                    1,
                    encoded_name("ns.example")?,
                )],
                &[address_record(pointer_to_question(), ANSWER)],
            )?,
            0,
        )?,
        captured(client_use(CLIENT, ANSWER)?, 0)?,
    ])?;
    assert_eq!(at(&report.forensics.dns_matches, 0)?.query_packet, Some(1));
    assert!(report.forensics.dns_address_uses.is_empty());
    let response_observation = at(&report.forensics.dns_observations, 1)?;
    let DnsDecoding::Decoded { message } = &response_observation.decoding else {
        return Err("response did not decode".into());
    };
    assert_eq!(message.records.len(), 2);
    let authority_record = at(&message.records, 0)?;
    let additional_record = at(&message.records, 1)?;
    assert_eq!(authority_record.section, DnsSection::Authority);
    assert!(matches!(&authority_record.value, DnsValue::Name(_)));
    assert_eq!(additional_record.section, DnsSection::Additional);
    assert_eq!(
        additional_record.value,
        DnsValue::Address(NetworkAddress::Ipv4(ANSWER))
    );
    for record in &message.records {
        let end = record
            .rdata
            .offset
            .checked_add(record.rdata.length)
            .ok_or("DNS RDATA range overflow")?;
        assert!(end <= response_observation.payload_length);
    }
    Ok(())
}
#[test]
fn address_linkage_matching_answer_owner() -> TestResult {
    let address_v6 = [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8];
    let first = standard_question()?;
    let second = question("Other.Example", 1, 1)?;
    let cases = [
        (
            vec![first.clone()],
            vec![address_record(encoded_name("Different.Example")?, ANSWER)],
        ),
        (
            vec![first.clone()],
            vec![aaaa_record(pointer_to_question(), address_v6)],
        ),
        (
            vec![question("Host.Example", 1, 3)?],
            vec![address_record(pointer_to_question(), ANSWER)],
        ),
        (
            vec![first, second],
            vec![
                address_record(pointer_to_question(), ANSWER),
                address_record(encoded_name("Other.Example")?, [198, 51, 100, 8]),
            ],
        ),
    ];
    for (index, (questions, answers)) in cases.into_iter().enumerate() {
        let id = 26 + u16::try_from(index)?;
        let report = assess([
            captured(query(id, &questions)?, 0)?,
            captured(response(id, &questions, &answers, 0x8180, &[], &[])?, 0)?,
            captured(client_use(CLIENT, ANSWER)?, 0)?,
        ])?;
        assert_eq!(at(&report.forensics.dns_matches, 0)?.query_packet, Some(1));
        assert!(report.forensics.dns_address_uses.is_empty());
    }
    Ok(())
}
#[test]
fn unusable_responses_suppress_address_use() -> TestResult {
    let question = standard_question()?;
    let cases = [
        ("truncated", 0x8380, Vec::new()),
        ("rcode", 0x8183, Vec::new()),
        ("extended", 0x8180, vec![opt_record(1)]),
    ];
    for (index, (label, flags, additionals)) in cases.into_iter().enumerate() {
        let id = 30 + u16::try_from(index)?;
        let report = assess([
            captured(query(id, std::slice::from_ref(&question))?, 0)?,
            captured(
                response(
                    id,
                    std::slice::from_ref(&question),
                    &[address_record(pointer_to_question(), ANSWER)],
                    flags,
                    &[],
                    &additionals,
                )?,
                0,
            )?,
            captured(client_use(CLIENT, ANSWER)?, 0)?,
        ])?;
        assert_eq!(
            at(&report.forensics.dns_matches, 0)?.query_packet,
            Some(1),
            "{label}"
        );
        assert!(report.forensics.dns_address_uses.is_empty(), "{label}");
        let response_observation = at(&report.forensics.dns_observations, 1)?;
        let DnsDecoding::Decoded { message } = &response_observation.decoding else {
            return Err(format!("{label} response did not decode").into());
        };
        if label == "extended" {
            assert_eq!(message.response_code(), 16);
        }
    }
    Ok(())
}
#[test]
fn ipv6_address_destination_use() -> TestResult {
    let client = [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let resolver = [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 53];
    let answer = [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7];
    let question = question("Host.Example", 28, 1)?;
    let request_dns = dns_message(61, 0x0100, std::slice::from_ref(&question), &[], &[], &[])?;
    let response_dns = dns_message(
        61,
        0x8180,
        std::slice::from_ref(&question),
        &[aaaa_record(pointer_to_question(), answer)],
        &[],
        &[],
    )?;
    let report = assess([
        captured(
            ipv6_udp_frame(client, resolver, CLIENT_PORT, DNS_PORT, &request_dns)?,
            0,
        )?,
        captured(
            ipv6_udp_frame(resolver, client, DNS_PORT, CLIENT_PORT, &response_dns)?,
            0,
        )?,
        captured(ipv6_udp_frame(client, answer, 40000, 443, &[])?, 0)?,
    ])?;
    assert_eq!(report.forensics.dns_address_uses.len(), 1);
    let address_use = at(&report.forensics.dns_address_uses, 0)?;
    assert_eq!(address_use.address, NetworkAddress::Ipv6(answer));
    assert!(address_use.client_matches_requester);
    Ok(())
}
