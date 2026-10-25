use super::support::*;

#[test]
fn query_names_insensitively_questions_ordered() -> TestResult {
    let requested = [
        question("Host.Example", 1, 1)?,
        question("Mail.Example", 28, 1)?,
    ];
    let case_changed = [
        question("host.example", 1, 1)?,
        question("MAIL.example", 28, 1)?,
    ];
    let reversed = [at(&case_changed, 1)?.clone(), at(&case_changed, 0)?.clone()];
    let report = assess([
        captured(query(9, &requested)?, 0)?,
        captured(response(9, &case_changed, &[], 0x8180, &[], &[])?, 0)?,
        captured(query(10, &requested)?, 0)?,
        captured(response(10, &reversed, &[], 0x8180, &[], &[])?, 0)?,
    ])?;
    let matches = &report.forensics.dns_matches;
    assert_eq!(matches.len(), 2);
    let first_match = at(matches, 0)?;
    let second_match = at(matches, 1)?;
    assert_eq!(
        (first_match.query_packet, first_match.candidate_queries),
        (Some(1), 1)
    );
    assert_eq!(
        (second_match.query_packet, second_match.candidate_queries),
        (None, 0)
    );
    Ok(())
}

#[test]
fn compression_question_fields_never_correlates() -> TestResult {
    let malformed_query = assess([
        captured(
            ipv4_udp_frame(
                CLIENT,
                RESOLVER,
                CLIENT_PORT,
                DNS_PORT,
                &qtype_pointer_message(51, 0x0100, true),
            )?,
            0,
        )?,
        captured(
            ipv4_udp_frame(
                RESOLVER,
                CLIENT,
                DNS_PORT,
                CLIENT_PORT,
                &qtype_pointer_message(51, 0x8180, false),
            )?,
            0,
        )?,
    ])?;

    assert_eq!(malformed_query.forensics.dns_messages_parsed, 1);
    let unmatched = at(&malformed_query.forensics.dns_matches, 0)?;
    assert_eq!(
        (unmatched.query_packet, unmatched.candidate_queries),
        (None, 0)
    );
    assert!(malformed_query.forensics.dns_address_uses.is_empty());
    assert!(matches!(
        &at(&malformed_query.forensics.dns_observations, 0)?.decoding,
        l2_discovery::dns::DnsDecoding::Unresolved { .. }
    ));

    let malformed_response = assess([
        captured(
            ipv4_udp_frame(
                CLIENT,
                RESOLVER,
                CLIENT_PORT,
                DNS_PORT,
                &qtype_pointer_message(52, 0x0100, false),
            )?,
            0,
        )?,
        captured(
            ipv4_udp_frame(
                RESOLVER,
                CLIENT,
                DNS_PORT,
                CLIENT_PORT,
                &qtype_pointer_message(52, 0x8180, true),
            )?,
            0,
        )?,
    ])?;
    assert_eq!(malformed_response.forensics.dns_messages_parsed, 1);
    assert!(malformed_response.forensics.dns_matches.is_empty());
    assert!(malformed_response.forensics.dns_address_uses.is_empty());
    assert!(matches!(
        &at(&malformed_response.forensics.dns_observations, 1)?.decoding,
        l2_discovery::dns::DnsDecoding::Unresolved { .. }
    ));
    Ok(())
}

fn qtype_pointer_message(id: u16, flags: u16, compressed_second: bool) -> Vec<u8> {
    let mut message = Vec::with_capacity(12 + 7 * 2);
    message.extend_from_slice(&id.to_be_bytes());
    message.extend_from_slice(&flags.to_be_bytes());
    message.extend_from_slice(&2_u16.to_be_bytes());
    message.extend_from_slice(&0_u16.to_be_bytes());
    message.extend_from_slice(&0_u16.to_be_bytes());
    message.extend_from_slice(&0_u16.to_be_bytes());
    // The first question's QTYPE bytes accidentally resemble a length-prefixed name
    message.extend_from_slice(&[1, 0, 0, 1, 0, 0, 1]);
    if compressed_second {
        message.extend_from_slice(&[0xc0, 0x0f]);
    } else {
        message.extend_from_slice(&[1, 0, 0]);
    }
    message.extend_from_slice(&256_u16.to_be_bytes());
    message.extend_from_slice(&1_u16.to_be_bytes());
    message
}

#[test]
fn response_matching_tuple_id_question() -> TestResult {
    let base = standard_question()?;
    for case in [
        Mismatch::new(
            "id",
            CLIENT,
            RESOLVER,
            DNS_PORT,
            CLIENT_PORT,
            8,
            base.clone(),
        ),
        Mismatch::new(
            "source",
            [192, 0, 2, 54],
            CLIENT,
            DNS_PORT,
            CLIENT_PORT,
            7,
            base.clone(),
        ),
        Mismatch::new(
            "destination",
            RESOLVER,
            [192, 0, 2, 12],
            DNS_PORT,
            CLIENT_PORT,
            7,
            base.clone(),
        ),
        Mismatch::new("client port", CLIENT, RESOLVER, DNS_PORT, 53001, 7, base),
        Mismatch::new(
            "name",
            CLIENT,
            RESOLVER,
            DNS_PORT,
            CLIENT_PORT,
            7,
            question("other.example", 1, 1)?,
        ),
        Mismatch::new(
            "type",
            CLIENT,
            RESOLVER,
            DNS_PORT,
            CLIENT_PORT,
            7,
            question("Host.Example", 28, 1)?,
        ),
        Mismatch::new(
            "class",
            CLIENT,
            RESOLVER,
            DNS_PORT,
            CLIENT_PORT,
            7,
            question("Host.Example", 1, 3)?,
        ),
    ] {
        assert_unmatched_response(&case)?;
    }

    Ok(())
}

#[test]
fn response_different_port_retained_unmatched() -> TestResult {
    let question = standard_question()?;
    let request_message = dns_message(7, 0x0100, std::slice::from_ref(&question), &[], &[], &[])?;
    let response_message = dns_message(
        7,
        0x8180,
        std::slice::from_ref(&question),
        &[address_record(pointer_to_question(), ANSWER)],
        &[],
        &[],
    )?;
    let request = ipv4_udp_frame(CLIENT, RESOLVER, DNS_PORT, DNS_PORT, &request_message)?;
    let response = ipv4_udp_frame(RESOLVER, CLIENT, DNS_PORT + 1, DNS_PORT, &response_message)?;
    let report = assess([captured(request, 0)?, captured(response, 0)?])?;

    assert_eq!(report.forensics.dns_candidates_seen, 2);
    assert_eq!(report.forensics.dns_matches.len(), 1);
    let matched = at(&report.forensics.dns_matches, 0)?;
    assert_eq!(matched.query_packet, None);
    assert_eq!(matched.candidate_queries, 0);
    assert!(report.forensics.dns_address_uses.is_empty());
    Ok(())
}

struct Mismatch {
    label: &'static str,
    source: [u8; 4],
    destination: [u8; 4],
    source_port: u16,
    destination_port: u16,
    id: u16,
    question: super::support::Question,
}

impl Mismatch {
    const fn new(
        label: &'static str,
        source: [u8; 4],
        destination: [u8; 4],
        source_port: u16,
        destination_port: u16,
        id: u16,
        question: super::support::Question,
    ) -> Self {
        Self {
            label,
            source,
            destination,
            source_port,
            destination_port,
            id,
            question,
        }
    }
}

fn assert_unmatched_response(case: &Mismatch) -> TestResult {
    let question = standard_question()?;
    let request = query(7, std::slice::from_ref(&question))?;
    let reply_message = dns_message(
        case.id,
        0x8180,
        std::slice::from_ref(&case.question),
        &[address_record(pointer_to_question(), ANSWER)],
        &[],
        &[],
    )?;
    let reply = ipv4_udp_frame(
        case.source,
        case.destination,
        case.source_port,
        case.destination_port,
        &reply_message,
    )?;
    let report = assess([captured(request, 0)?, captured(reply, 0)?])?;
    let matched = report
        .forensics
        .dns_matches
        .first()
        .ok_or("missing response observation")?;
    assert_eq!(
        matched.query_packet, None,
        "unexpected {} match",
        case.label
    );
    assert_eq!(
        matched.candidate_queries, 0,
        "unexpected {} candidate",
        case.label
    );
    assert!(report.forensics.dns_address_uses.is_empty());
    Ok(())
}
#[test]
fn dns_matching_scoped_interface_vlan() -> TestResult {
    let question = standard_question()?;
    let request = query(12, std::slice::from_ref(&question))?;
    let reply = response(12, std::slice::from_ref(&question), &[], 0x8180, &[], &[])?;
    let interface_report = assess([
        captured_in(request.clone(), 0, 1)?,
        captured_in(reply.clone(), 0, 2)?,
    ])?;
    let section_report = assess([
        captured_in(request.clone(), 1, 0)?,
        captured_in(reply.clone(), 0, 0)?,
    ])?;
    let vlan_report = assess([
        captured(tagged(&request, 10)?, 0)?,
        captured(tagged(&reply, 20)?, 0)?,
    ])?;
    for report in [&interface_report, &section_report, &vlan_report] {
        assert_eq!(report.forensics.dns_matches.len(), 1);
        let matched = at(&report.forensics.dns_matches, 0)?;
        assert_eq!(matched.query_packet, None);
        assert_eq!(matched.candidate_queries, 0);
    }
    Ok(())
}
#[test]
fn duplicate_pending_ambiguous_unique_consumed() -> TestResult {
    let question = standard_question()?;
    let request = query(13, std::slice::from_ref(&question))?;
    let reply = response(13, std::slice::from_ref(&question), &[], 0x8180, &[], &[])?;
    let ambiguous = assess([
        captured(request.clone(), 0)?,
        captured(request.clone(), 0)?,
        captured(reply.clone(), 0)?,
        captured(reply.clone(), 0)?,
    ])?;
    assert_eq!(ambiguous.forensics.dns_matches.len(), 2);
    assert!(
        ambiguous
            .forensics
            .dns_matches
            .iter()
            .all(|entry| { entry.query_packet.is_none() && entry.candidate_queries == 2 })
    );

    let unique = assess([
        captured(request, 0)?,
        captured(reply.clone(), 0)?,
        captured(reply, 0)?,
    ])?;
    assert_eq!(unique.forensics.dns_matches.len(), 2);
    let first_match = at(&unique.forensics.dns_matches, 0)?;
    let second_match = at(&unique.forensics.dns_matches, 1)?;
    assert_eq!(first_match.query_packet, Some(1));
    assert_eq!(first_match.candidate_queries, 1);
    assert_eq!(second_match.query_packet, None);
    assert_eq!(second_match.candidate_queries, 0);
    Ok(())
}
#[test]
fn address_use_later_same_scope() -> TestResult {
    let question = standard_question()?;
    let reply = response(
        29,
        std::slice::from_ref(&question),
        &[address_record(pointer_to_question(), ANSWER)],
        0x8180,
        &[],
        &[],
    )?;
    let report = assess([
        captured(query(29, std::slice::from_ref(&question))?, 0)?,
        captured(client_use(CLIENT, ANSWER)?, 0)?,
        captured(reply, 0)?,
        captured_in(client_use(CLIENT, ANSWER)?, 0, 1)?,
        captured(client_use(CLIENT, ANSWER)?, 0)?,
    ])?;
    assert_eq!(report.forensics.dns_address_uses.len(), 1);
    let address_use = at(&report.forensics.dns_address_uses, 0)?;
    assert_eq!(address_use.response_packet, 3);
    assert_eq!(address_use.packet, 5);
    Ok(())
}
#[test]
fn nonstandard_or_questionless_responses_unmatched() -> TestResult {
    let question = standard_question()?;
    let query_frame = query(40, std::slice::from_ref(&question))?;
    let nonstandard = response(40, std::slice::from_ref(&question), &[], 0x8980, &[], &[])?;
    let query_shaped = response(40, std::slice::from_ref(&question), &[], 0x0180, &[], &[])?;
    let empty = response(41, &[], &[], 0x8180, &[], &[])?;
    let report = assess([
        captured(query_frame, 0)?,
        captured(nonstandard, 0)?,
        captured(query_shaped, 0)?,
        captured(empty, 0)?,
    ])?;
    assert_eq!(report.forensics.dns_matches.len(), 0);
    Ok(())
}
