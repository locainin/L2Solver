use super::ftp_association_support::{
    endpoint, event, event_from_endpoints, event_in_episode, scope, session,
};
use l2_discovery::NetworkAddress;
use l2_workbench::application::{
    ByteRange, ParseContext, ParseStatus,
    ftp::FtpDataMode,
    ftp::association::{
        FtpAssociationStatus, FtpDataDirection, FtpEndpointAddressSource,
        FtpSessionAssociationStatus, FtpTransferAction, MAX_ASSOCIATED_SESSIONS,
        MAX_CONTROL_EVENTS, MAX_ENDPOINT_CANDIDATES, MAX_SESSION_CANDIDATES,
        associate_data_sessions,
    },
};

const COMPLETE: ParseContext = ParseContext {
    start_known: true,
    end_observed: true,
};
const UNKNOWN_START: ParseContext = ParseContext {
    start_known: false,
    end_observed: true,
};

#[test]
fn active_endpoint_later_exact_candidates() -> Result<(), &'static str> {
    let capture_scope = scope(17);
    let client = endpoint([192, 0, 2, 10], 40_000);
    let server = endpoint([192, 0, 2, 20], 21);
    let advertisement = event(
        b"PORT 192,0,2,10,7,138\r\n",
        10,
        client.clone(),
        server.clone(),
        capture_scope.clone(),
        COMPLETE,
    )?;
    let transfer = event(
        b"RETR /archive.bin\r\n",
        20,
        client,
        server,
        capture_scope.clone(),
        COMPLETE,
    )?;
    let first = session(
        capture_scope.clone(),
        21,
        endpoint([192, 0, 2, 20], 50_001),
        endpoint([192, 0, 2, 10], 1_930),
        false,
    );
    let second = session(
        capture_scope.clone(),
        22,
        endpoint([192, 0, 2, 20], 50_002),
        endpoint([192, 0, 2, 10], 1_930),
        false,
    );
    let wrong_port = session(
        capture_scope,
        23,
        endpoint([192, 0, 2, 20], 50_003),
        endpoint([192, 0, 2, 10], 1_931),
        false,
    );

    let report = associate_data_sessions(&[advertisement, transfer], &[first, second, wrong_port]);
    let assessment = report
        .transfers
        .first()
        .ok_or("missing transfer assessment")?;
    let endpoint_candidate = assessment
        .endpoint_candidates
        .first()
        .ok_or("missing advertised endpoint")?;

    assert_eq!(report.transfers.len(), 1);
    assert_eq!(assessment.action, FtpTransferAction::Retrieve);
    assert_eq!(assessment.status, FtpAssociationStatus::Candidates);
    assert_eq!(endpoint_candidate.mode, FtpDataMode::Active);
    assert_eq!(endpoint_candidate.endpoint_packet, 10);
    assert_eq!(
        endpoint_candidate.address_source,
        FtpEndpointAddressSource::Advertised
    );
    assert_eq!(endpoint_candidate.sessions.len(), 2);
    assert_eq!(
        endpoint_candidate
            .sessions
            .iter()
            .map(|candidate| candidate.session_index)
            .collect::<Vec<_>>(),
        [0, 1]
    );
    assert!(endpoint_candidate.sessions.iter().all(|candidate| {
        candidate.direction == FtpDataDirection::ActiveControlPeerToEndpoint
            && !candidate.generation_ambiguous
            && !candidate.opened_before_transfer
            && candidate.initiator_matches_expected == Some(true)
            && !candidate.direction_ambiguous
            && candidate.association_status == FtpSessionAssociationStatus::Unique
    }));
    Ok(())
}

#[test]
fn later_unmatched_not_earlier_session() -> Result<(), &'static str> {
    let capture_scope = scope(17);
    let client = endpoint([192, 0, 2, 10], 40_000);
    let server = endpoint([192, 0, 2, 20], 21);
    let matching_advertisement = event(
        b"PORT 192,0,2,10,7,138\r\n",
        10,
        client.clone(),
        server.clone(),
        capture_scope.clone(),
        COMPLETE,
    )?;
    let unmatched_advertisement = event(
        b"PORT 192,0,2,10,7,139\r\n",
        11,
        client.clone(),
        server.clone(),
        capture_scope.clone(),
        COMPLETE,
    )?;
    let transfer = event(
        b"RETR /archive.bin\r\n",
        20,
        client,
        server,
        capture_scope.clone(),
        COMPLETE,
    )?;
    let data_session = session(
        capture_scope,
        21,
        endpoint([192, 0, 2, 20], 50_001),
        endpoint([192, 0, 2, 10], 1_930),
        false,
    );

    let report = associate_data_sessions(
        &[matching_advertisement, unmatched_advertisement, transfer],
        &[data_session],
    );
    let assessment = report
        .transfers
        .first()
        .ok_or("missing transfer assessment")?;

    assert_eq!(assessment.status, FtpAssociationStatus::Candidates);
    assert_eq!(assessment.endpoint_candidates.len(), 2);
    assert_eq!(
        assessment
            .endpoint_candidates
            .first()
            .map(|candidate| candidate.sessions.len()),
        Some(1)
    );
    assert!(
        assessment
            .endpoint_candidates
            .get(1)
            .is_some_and(|candidate| candidate.sessions.is_empty())
    );
    Ok(())
}

#[test]
fn epsv_uses_labels_address_source() -> Result<(), &'static str> {
    let capture_scope = scope(0);
    let client = endpoint([198, 51, 100, 9], 42_000);
    let server = endpoint([203, 0, 113, 8], 21);
    let advertisement = event(
        b"229 Entering Extended Passive Mode (|||6446|)\r\n",
        30,
        server.clone(),
        client.clone(),
        capture_scope.clone(),
        COMPLETE,
    )?;
    let transfer = event(
        b"STOR /incoming.bin\r\n",
        31,
        client,
        server,
        capture_scope.clone(),
        COMPLETE,
    )?;
    let data_session = session(
        capture_scope,
        32,
        endpoint([198, 51, 100, 9], 42_001),
        endpoint([203, 0, 113, 8], 6_446),
        false,
    );

    let report = associate_data_sessions(&[advertisement, transfer], &[data_session]);
    let assessment = report
        .transfers
        .first()
        .ok_or("missing transfer assessment")?;
    let candidate = assessment
        .endpoint_candidates
        .first()
        .ok_or("missing EPSV endpoint")?;

    assert_eq!(assessment.action, FtpTransferAction::Store);
    assert_eq!(assessment.status, FtpAssociationStatus::Candidates);
    assert_eq!(candidate.endpoint.address, None);
    assert_eq!(
        candidate.effective_address,
        NetworkAddress::Ipv4([203, 0, 113, 8])
    );
    assert_eq!(
        candidate.address_source,
        FtpEndpointAddressSource::ControlPeer
    );
    assert_eq!(candidate.sessions.len(), 1);
    assert_eq!(
        candidate.sessions.first().map(|value| value.direction),
        Some(FtpDataDirection::PassiveControlPeerToEndpoint)
    );
    Ok(())
}

#[test]
fn exact_scope_without_nat_rewriting() -> Result<(), &'static str> {
    let capture_scope = scope(21);
    let client = endpoint([198, 51, 100, 9], 42_000);
    let server = endpoint([203, 0, 113, 8], 21);
    let advertisement = event(
        b"227 Entering Passive Mode (10,0,0,8,25,76)\r\n",
        40,
        server.clone(),
        client.clone(),
        capture_scope.clone(),
        COMPLETE,
    )?;
    let transfer = event(
        b"RETR /archive.bin\r\n",
        42,
        client,
        server,
        capture_scope.clone(),
        COMPLETE,
    )?;
    let wrong_scope = session(
        scope(22),
        43,
        endpoint([198, 51, 100, 9], 42_001),
        endpoint([10, 0, 0, 8], 6_476),
        false,
    );
    let before_advertisement = session(
        capture_scope.clone(),
        39,
        endpoint([198, 51, 100, 9], 42_002),
        endpoint([10, 0, 0, 8], 6_476),
        false,
    );
    let translated = session(
        capture_scope,
        44,
        endpoint([198, 51, 100, 9], 42_003),
        endpoint([203, 0, 113, 8], 6_476),
        false,
    );

    let report = associate_data_sessions(
        &[advertisement, transfer],
        &[wrong_scope, before_advertisement, translated],
    );
    let assessment = report
        .transfers
        .first()
        .ok_or("missing transfer assessment")?;
    let candidate = assessment
        .endpoint_candidates
        .first()
        .ok_or("missing PASV endpoint")?;

    assert_eq!(assessment.status, FtpAssociationStatus::NoExactSession);
    assert!(candidate.sessions.is_empty());
    assert!(
        report
            .limitations
            .iter()
            .any(|limitation| limitation.contains("NAT"))
    );
    Ok(())
}

#[test]
fn passive_session_advertisement_transfer_retained() -> Result<(), &'static str> {
    let capture_scope = scope(0);
    let client = endpoint([198, 51, 100, 9], 42_000);
    let server = endpoint([203, 0, 113, 8], 21);
    let advertisement = event(
        b"229 Entering Extended Passive Mode (|||6446|)\r\n",
        70,
        server.clone(),
        client.clone(),
        capture_scope.clone(),
        COMPLETE,
    )?;
    let data_session = session(
        capture_scope.clone(),
        71,
        endpoint([198, 51, 100, 9], 42_001),
        endpoint([203, 0, 113, 8], 6_446),
        false,
    );
    let transfer = event(
        b"RETR /archive.bin\r\n",
        72,
        client,
        server,
        capture_scope,
        COMPLETE,
    )?;

    let report = associate_data_sessions(&[advertisement, transfer], &[data_session]);
    let candidate = report
        .transfers
        .first()
        .and_then(|assessment| assessment.endpoint_candidates.first())
        .ok_or("missing PASV endpoint candidate")?;

    assert_eq!(candidate.sessions.len(), 1);
    assert!(
        candidate
            .sessions
            .first()
            .is_some_and(|session| session.opened_before_transfer)
    );
    Ok(())
}

#[test]
fn closed_passive_not_later_store() -> Result<(), &'static str> {
    let capture_scope = scope(0);
    let client = endpoint([198, 51, 100, 9], 42_000);
    let server = endpoint([203, 0, 113, 8], 21);
    let server_reply = |bytes: &[u8], packet| {
        event_from_endpoints(bytes, packet, &server, &client, &capture_scope, COMPLETE)
    };
    let client_command = |bytes: &[u8], packet| {
        event_from_endpoints(bytes, packet, &client, &server, &capture_scope, COMPLETE)
    };
    let first_advertisement =
        server_reply(b"227 Entering Passive Mode (203,0,113,8,234,96)\r\n", 10)?;
    let first_transfer = client_command(b"STOR first.bin\r\n", 20)?;
    let second_advertisement =
        server_reply(b"227 Entering Passive Mode (203,0,113,8,234,97)\r\n", 30)?;
    let second_transfer = client_command(b"STOR second.bin\r\n", 40)?;
    let mut closed_session = session(
        capture_scope.clone(),
        21,
        endpoint([198, 51, 100, 9], 42_001),
        endpoint([203, 0, 113, 8], 60_000),
        false,
    );
    let closed_direction = closed_session
        .directions
        .get_mut(0)
        .ok_or("missing passive data direction")?;
    closed_direction.end_observed = true;
    closed_direction.packets.push(25);
    let next_session = session(
        capture_scope,
        41,
        endpoint([198, 51, 100, 9], 42_002),
        endpoint([203, 0, 113, 8], 60_001),
        false,
    );

    let report = associate_data_sessions(
        &[
            first_advertisement,
            first_transfer,
            second_advertisement,
            second_transfer,
        ],
        &[closed_session, next_session],
    );
    let second = report
        .transfers
        .get(1)
        .ok_or("missing second transfer assessment")?;
    let stale_endpoint = second
        .endpoint_candidates
        .first()
        .ok_or("missing first endpoint candidate")?;
    let new_endpoint = second
        .endpoint_candidates
        .get(1)
        .ok_or("missing second endpoint candidate")?;

    assert_eq!(report.transfers.len(), 2);
    assert_eq!(stale_endpoint.endpoint.port, 60_000);
    assert!(stale_endpoint.sessions.is_empty());
    assert_eq!(new_endpoint.endpoint.port, 60_001);
    assert_eq!(new_endpoint.sessions.len(), 1);
    assert_eq!(
        new_endpoint
            .sessions
            .first()
            .map(|candidate| candidate.session_index),
        Some(1)
    );
    Ok(())
}

#[test]
fn unclosed_passive_multiple_stores_ambiguous() -> Result<(), &'static str> {
    let capture_scope = scope(0);
    let client = endpoint([198, 51, 100, 9], 42_000);
    let server = endpoint([203, 0, 113, 8], 21);
    let advertisement = event(
        b"227 Entering Passive Mode (203,0,113,8,234,96)\r\n",
        10,
        server.clone(),
        client.clone(),
        capture_scope.clone(),
        COMPLETE,
    )?;
    let first_transfer = event(
        b"STOR first.bin\r\n",
        20,
        client.clone(),
        server.clone(),
        capture_scope.clone(),
        COMPLETE,
    )?;
    let second_transfer = event(
        b"STOR second.bin\r\n",
        30,
        client,
        server,
        capture_scope.clone(),
        COMPLETE,
    )?;
    let data_session = session(
        capture_scope,
        21,
        endpoint([198, 51, 100, 9], 42_001),
        endpoint([203, 0, 113, 8], 60_000),
        false,
    );

    let report = associate_data_sessions(
        &[advertisement, first_transfer, second_transfer],
        &[data_session],
    );
    let first_candidate = report
        .transfers
        .first()
        .and_then(|transfer| transfer.endpoint_candidates.first())
        .and_then(|endpoint| endpoint.sessions.first())
        .ok_or("missing first transfer session candidate")?;
    let second_candidate = report
        .transfers
        .get(1)
        .and_then(|transfer| transfer.endpoint_candidates.first())
        .and_then(|endpoint| endpoint.sessions.first())
        .ok_or("missing second transfer session candidate")?;

    assert_eq!(
        first_candidate.session_index,
        second_candidate.session_index
    );
    assert_eq!(
        first_candidate.association_status,
        FtpSessionAssociationStatus::ReusedAcrossTransfers
    );
    assert_eq!(
        second_candidate.association_status,
        FtpSessionAssociationStatus::ReusedAcrossTransfers
    );
    assert!(report.limitations.iter().any(|limitation| {
        limitation.contains("An unended data session matching multiple FTP transfers is ambiguous")
    }));
    Ok(())
}

#[test]
fn either_input_transfer_association_unresolved() -> Result<(), &'static str> {
    let capture_scope = scope(0);
    let client = endpoint([198, 51, 100, 9], 42_000);
    let server = endpoint([203, 0, 113, 8], 21);
    let transfer = event(
        b"RETR /archive.bin\r\n",
        20,
        client,
        server,
        capture_scope.clone(),
        COMPLETE,
    )?;
    let events = vec![transfer.clone(); MAX_CONTROL_EVENTS + 1];
    let sessions = std::iter::repeat_with(|| {
        session(
            capture_scope.clone(),
            21,
            endpoint([192, 0, 2, 1], 40_000),
            endpoint([192, 0, 2, 2], 40_001),
            false,
        )
    })
    .take(MAX_ASSOCIATED_SESSIONS + 1)
    .collect::<Vec<_>>();
    let one_transfer = [transfer];

    for (events, sessions, expected_events, expected_sessions) in [
        (&events[..], &[][..], 1, 0),
        (&one_transfer[..], &sessions[..], 0, 1),
    ] {
        let report = associate_data_sessions(events, sessions);
        let assessment = report
            .transfers
            .first()
            .ok_or("missing transfer assessment")?;
        assert_eq!(report.omitted_events, expected_events);
        assert_eq!(report.omitted_sessions, expected_sessions);
        assert_eq!(assessment.status, FtpAssociationStatus::UnresolvedLimit);
        assert!(assessment.truncated);
        assert!(!report.complete);
    }
    Ok(())
}

#[test]
fn completed_payload_ftp_mode_action() -> Result<(), &'static str> {
    for (mode, action, advertisement, transfer, payload_direction) in [
        (
            FtpDataMode::Active,
            FtpTransferAction::Retrieve,
            &b"PORT 198,51,100,9,234,96\r\n"[..],
            &b"RETR file.bin\r\n"[..],
            1,
        ),
        (
            FtpDataMode::Active,
            FtpTransferAction::Store,
            &b"PORT 198,51,100,9,234,96\r\n"[..],
            &b"STOR file.bin\r\n"[..],
            0,
        ),
        (
            FtpDataMode::Passive,
            FtpTransferAction::Retrieve,
            &b"227 Entering Passive Mode (203,0,113,8,234,96)\r\n"[..],
            &b"RETR file.bin\r\n"[..],
            1,
        ),
        (
            FtpDataMode::Passive,
            FtpTransferAction::Store,
            &b"227 Entering Passive Mode (203,0,113,8,234,96)\r\n"[..],
            &b"STOR file.bin\r\n"[..],
            0,
        ),
    ] {
        assert_payload_direction_closed(mode, action, advertisement, transfer, payload_direction)?;
    }
    Ok(())
}

fn assert_payload_direction_closed(
    mode: FtpDataMode,
    action: FtpTransferAction,
    advertisement_bytes: &[u8],
    transfer_bytes: &[u8],
    payload_direction: usize,
) -> Result<(), &'static str> {
    let capture_scope = scope(0);
    let client = endpoint([198, 51, 100, 9], 42_000);
    let server = endpoint([203, 0, 113, 8], 21);
    let (advertisement_source, advertisement_destination, data_source, data_destination) =
        match mode {
            FtpDataMode::Active => (
                client.clone(),
                server.clone(),
                server.clone(),
                endpoint([198, 51, 100, 9], 60_000),
            ),
            FtpDataMode::Passive => (
                server.clone(),
                client.clone(),
                client.clone(),
                endpoint([203, 0, 113, 8], 60_000),
            ),
        };
    let advertisement = event(
        advertisement_bytes,
        10,
        advertisement_source,
        advertisement_destination,
        capture_scope.clone(),
        COMPLETE,
    )?;
    let transfer = event(
        transfer_bytes,
        30,
        client,
        server,
        capture_scope.clone(),
        COMPLETE,
    )?;
    let mut data_session = session(capture_scope, 21, data_source, data_destination, false);
    let ended_stream = data_session
        .directions
        .get_mut(payload_direction)
        .ok_or("missing expected payload direction")?;
    ended_stream.end_observed = true;
    ended_stream.packets.push(25);

    let report = associate_data_sessions(&[advertisement, transfer], &[data_session]);
    let assessment = report
        .transfers
        .first()
        .ok_or("missing transfer assessment")?;
    let endpoint = assessment
        .endpoint_candidates
        .first()
        .ok_or("missing endpoint candidate")?;
    assert_eq!(assessment.action, action);
    assert_eq!(
        assessment.status,
        FtpAssociationStatus::NoExactSession,
        "{mode:?} {action:?}"
    );
    assert!(endpoint.sessions.is_empty());
    Ok(())
}

#[test]
fn endpoint_facts_episode_not_reused() -> Result<(), &'static str> {
    let capture_scope = scope(0);
    let client = endpoint([192, 0, 2, 10], 40_000);
    let server = endpoint([192, 0, 2, 20], 21);
    let advertisement = event_in_episode(
        b"PORT 192,0,2,10,7,138\r\n",
        80,
        1,
        client.clone(),
        server.clone(),
        capture_scope.clone(),
        COMPLETE,
    )?;
    let transfer = event_in_episode(
        b"RETR /archive.bin\r\n",
        81,
        2,
        client,
        server,
        capture_scope.clone(),
        COMPLETE,
    )?;
    let data_session = session(
        capture_scope,
        82,
        endpoint([192, 0, 2, 20], 50_001),
        endpoint([192, 0, 2, 10], 1_930),
        false,
    );

    let report = associate_data_sessions(&[advertisement, transfer], &[data_session]);
    let assessment = report
        .transfers
        .first()
        .ok_or("missing transfer assessment")?;

    assert_eq!(assessment.status, FtpAssociationStatus::NoPriorEndpointFact);
    assert!(assessment.endpoint_candidates.is_empty());
    Ok(())
}

#[test]
fn endpoint_facts_tuple_not_reused() -> Result<(), &'static str> {
    let capture_scope = scope(0);
    let client = endpoint([192, 0, 2, 10], 40_000);
    let other_client = endpoint([192, 0, 2, 10], 40_001);
    let server = endpoint([192, 0, 2, 20], 21);
    let active = event(
        b"PORT 192,0,2,10,7,138\r\n",
        80,
        other_client.clone(),
        server.clone(),
        capture_scope.clone(),
        COMPLETE,
    )?;
    let passive = event(
        b"227 Entering Passive Mode (192,0,2,20,7,138)\r\n",
        80,
        server.clone(),
        other_client,
        capture_scope.clone(),
        COMPLETE,
    )?;
    let transfer = event(
        b"RETR /archive.bin\r\n",
        81,
        client,
        server,
        capture_scope,
        COMPLETE,
    )?;

    for advertisement in [active, passive] {
        let report = associate_data_sessions(&[advertisement, transfer.clone()], &[]);
        let assessment = report
            .transfers
            .first()
            .ok_or("missing transfer assessment")?;
        assert_eq!(assessment.status, FtpAssociationStatus::NoPriorEndpointFact);
        assert!(assessment.endpoint_candidates.is_empty());
    }
    Ok(())
}

#[test]
fn same_packet_transfer_ranges_ordered() -> Result<(), &'static str> {
    let before = same_packet_active_events(
        ByteRange {
            offset: 10,
            length: 20,
        },
        ByteRange {
            offset: 30,
            length: 16,
        },
    )?;
    let after = same_packet_active_events(
        ByteRange {
            offset: 30,
            length: 20,
        },
        ByteRange {
            offset: 10,
            length: 16,
        },
    )?;

    let before_report = associate_data_sessions(&before, &[]);
    let after_report = associate_data_sessions(&after, &[]);
    let before_assessment = before_report
        .transfers
        .first()
        .ok_or("missing ordered transfer")?;
    let after_assessment = after_report
        .transfers
        .first()
        .ok_or("missing reversed transfer")?;

    assert_eq!(
        before_assessment.status,
        FtpAssociationStatus::NoExactSession
    );
    assert_eq!(before_assessment.endpoint_candidates.len(), 1);
    assert_eq!(
        after_assessment.status,
        FtpAssociationStatus::NoPriorEndpointFact
    );
    assert!(after_assessment.endpoint_candidates.is_empty());
    Ok(())
}

fn same_packet_active_events(
    advertisement_range: ByteRange,
    transfer_range: ByteRange,
) -> Result<Vec<l2_workbench::application::ftp::association::FtpControlEvent>, &'static str> {
    let client = endpoint([192, 0, 2, 10], 40_000);
    let server = endpoint([192, 0, 2, 20], 21);
    let capture_scope = scope(0);
    let mut advertisement = event(
        b"PORT 192,0,2,10,7,138\r\n",
        90,
        client.clone(),
        server.clone(),
        capture_scope.clone(),
        COMPLETE,
    )?;
    let mut transfer = event(
        b"RETR /archive.bin\r\n",
        90,
        client,
        server,
        capture_scope,
        COMPLETE,
    )?;
    advertisement.range = advertisement_range;
    transfer.range = transfer_range;
    Ok(vec![advertisement, transfer])
}

#[test]
fn endpoint_transfer_ambiguity_reported_independently() -> Result<(), &'static str> {
    let client = endpoint([192, 0, 2, 10], 40_000);
    let server = endpoint([192, 0, 2, 20], 21);
    let capture_scope = scope(0);
    let mut ambiguous_advertisement = event(
        b"PORT 192,0,2,10,7,138\r\n",
        91,
        client.clone(),
        server.clone(),
        capture_scope.clone(),
        COMPLETE,
    )?;
    ambiguous_advertisement.status = ParseStatus::Ambiguous;
    let complete_transfer = event(
        b"RETR /first.bin\r\n",
        92,
        client.clone(),
        server.clone(),
        capture_scope.clone(),
        COMPLETE,
    )?;
    let complete_advertisement = event(
        b"PORT 192,0,2,10,7,138\r\n",
        93,
        client.clone(),
        server.clone(),
        capture_scope.clone(),
        COMPLETE,
    )?;
    let mut ambiguous_transfer = event(
        b"RETR /second.bin\r\n",
        94,
        client,
        server,
        capture_scope,
        COMPLETE,
    )?;
    ambiguous_transfer.status = ParseStatus::Ambiguous;

    for events in [
        vec![ambiguous_advertisement, complete_transfer],
        vec![complete_advertisement, ambiguous_transfer],
    ] {
        let report = associate_data_sessions(&events, &[]);
        let assessment = report
            .transfers
            .first()
            .ok_or("missing transfer assessment")?;
        assert!(assessment.boundary_ambiguous);
    }
    Ok(())
}

#[test]
fn omission_flags_no_transfer_assessed() -> Result<(), &'static str> {
    let capture_scope = scope(0);
    let client = endpoint([192, 0, 2, 10], 40_000);
    let server = endpoint([192, 0, 2, 20], 21);
    let control_event_count = u32::try_from(MAX_CONTROL_EVENTS)
        .map_err(|_| "control event limit does not fit a packet number")?;
    let endpoint_events = (0..=control_event_count)
        .map(|packet| {
            event(
                b"PORT 192,0,2,10,7,138\r\n",
                packet + 1,
                client.clone(),
                server.clone(),
                capture_scope.clone(),
                COMPLETE,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let session_count = u32::try_from(MAX_ASSOCIATED_SESSIONS)
        .map_err(|_| "session limit does not fit a packet number")?;
    let session_inputs = (0..=session_count)
        .map(|packet| {
            session(
                capture_scope.clone(),
                packet + 1,
                endpoint([192, 0, 2, 20], 50_001),
                endpoint([192, 0, 2, 10], 1_930),
                false,
            )
        })
        .collect::<Vec<_>>();

    let complete = associate_data_sessions(&[], &[]);
    let omitted_events = associate_data_sessions(&endpoint_events, &[]);
    let omitted_sessions = associate_data_sessions(&[], &session_inputs);

    assert!(complete.complete);
    assert!(!omitted_events.complete);
    assert_eq!(omitted_events.omitted_events, 1);
    assert!(!omitted_sessions.complete);
    assert_eq!(omitted_sessions.omitted_sessions, 1);
    Ok(())
}

#[test]
fn session_candidate_budget_global_dropped() -> Result<(), &'static str> {
    let capture_scope = scope(0);
    let client = endpoint([198, 51, 100, 9], 42_000);
    let server = endpoint([203, 0, 113, 8], 21);
    let mut events = vec![event(
        b"227 Entering Passive Mode (203,0,113,8,234,96)\r\n",
        10,
        server.clone(),
        client.clone(),
        capture_scope.clone(),
        COMPLETE,
    )?];
    for index in 0..5_u32 {
        events.push(event(
            b"STOR file.bin\r\n",
            20 + index * 10,
            client.clone(),
            server.clone(),
            capture_scope.clone(),
            COMPLETE,
        )?);
    }
    let session_count = u32::try_from(MAX_ASSOCIATED_SESSIONS)
        .map_err(|_| "session limit does not fit a packet number")?;
    let sessions = (0..session_count)
        .map(|_| {
            session(
                capture_scope.clone(),
                21,
                endpoint([198, 51, 100, 9], 42_001),
                endpoint([203, 0, 113, 8], 60_000),
                false,
            )
        })
        .collect::<Vec<_>>();

    let report = associate_data_sessions(&events, &sessions);
    let retained = report
        .transfers
        .iter()
        .filter_map(|transfer| transfer.endpoint_candidates.first())
        .map(|endpoint| endpoint.sessions.len())
        .sum::<usize>();
    let last = report.transfers.last().ok_or("missing final transfer")?;
    let last_endpoint = last
        .endpoint_candidates
        .first()
        .ok_or("missing final endpoint candidate")?;

    assert_eq!(retained, MAX_SESSION_CANDIDATES);
    assert_eq!(report.omitted_session_candidates, MAX_ASSOCIATED_SESSIONS);
    assert!(!report.complete);
    assert!(last.truncated);
    assert!(last_endpoint.sessions.is_empty());
    assert!(last_endpoint.truncated);
    Ok(())
}

#[test]
fn endpoint_candidate_global_tracks_omissions() -> Result<(), &'static str> {
    let capture_scope = scope(0);
    let client = endpoint([192, 0, 2, 10], 40_000);
    let server = endpoint([192, 0, 2, 20], 21);
    let event_limit = u32::try_from(MAX_CONTROL_EVENTS)
        .map_err(|_| "control event limit does not fit a packet number")?;
    let mut events = Vec::with_capacity(MAX_CONTROL_EVENTS);
    for packet in 1..=3 {
        events.push(event(
            b"PORT 192,0,2,10,7,138\r\n",
            packet,
            client.clone(),
            server.clone(),
            capture_scope.clone(),
            COMPLETE,
        )?);
    }
    for packet in 4..=event_limit {
        events.push(event(
            b"RETR file.bin\r\n",
            packet,
            client.clone(),
            server.clone(),
            capture_scope.clone(),
            COMPLETE,
        )?);
    }

    let report = associate_data_sessions(&events, &[]);
    let retained = report
        .transfers
        .iter()
        .map(|transfer| transfer.endpoint_candidates.len())
        .sum::<usize>();
    let expected_matches = (MAX_CONTROL_EVENTS - 3) * 3;
    let last = report.transfers.last().ok_or("missing final transfer")?;

    assert_eq!(retained, MAX_ENDPOINT_CANDIDATES);
    assert_eq!(
        report.omitted_endpoint_candidates,
        expected_matches - MAX_ENDPOINT_CANDIDATES
    );
    assert_eq!(report.transfers.len(), MAX_CONTROL_EVENTS - 3);
    assert_eq!(last.status, FtpAssociationStatus::UnresolvedLimit);
    assert!(last.truncated);
    assert!(!report.complete);
    Ok(())
}

#[test]
fn missing_observed_tuple_direction_ambiguous() -> Result<(), &'static str> {
    let capture_scope = scope(0);
    let client = endpoint([198, 51, 100, 9], 42_000);
    let server = endpoint([203, 0, 113, 8], 21);
    let advertisement = event(
        b"229 Entering Extended Passive Mode (|||6446|)\r\n",
        90,
        server.clone(),
        client.clone(),
        capture_scope.clone(),
        COMPLETE,
    )?;
    let transfer = event(
        b"RETR /archive.bin\r\n",
        92,
        client,
        server,
        capture_scope.clone(),
        COMPLETE,
    )?;
    let mut data_session = session(
        capture_scope,
        91,
        endpoint([198, 51, 100, 9], 42_001),
        endpoint([203, 0, 113, 8], 6_446),
        false,
    );
    data_session.initiator = None;

    let report = associate_data_sessions(&[advertisement, transfer], &[data_session]);
    let candidate = report
        .transfers
        .first()
        .and_then(|assessment| assessment.endpoint_candidates.first())
        .and_then(|endpoint| endpoint.sessions.first())
        .ok_or("missing observed tuple candidate")?;

    assert_eq!(candidate.initiator_matches_expected, None);
    assert!(candidate.direction_ambiguous);
    Ok(())
}

#[test]
fn empty_stream_not_endpoint_candidate() -> Result<(), &'static str> {
    let capture_scope = scope(0);
    let client = endpoint([198, 51, 100, 9], 42_000);
    let server = endpoint([203, 0, 113, 8], 21);
    let advertisement = event(
        b"229 Entering Extended Passive Mode (|||6446|)\r\n",
        100,
        server.clone(),
        client.clone(),
        capture_scope.clone(),
        COMPLETE,
    )?;
    let transfer = event(
        b"RETR /archive.bin\r\n",
        101,
        client,
        server,
        capture_scope.clone(),
        COMPLETE,
    )?;
    let mut data_session = session(
        capture_scope,
        102,
        endpoint([198, 51, 100, 9], 42_001),
        endpoint([203, 0, 113, 8], 6_446),
        false,
    );
    if let Some(stream) = data_session.directions.first_mut() {
        stream.packets.clear();
    }

    let report = associate_data_sessions(&[advertisement, transfer], &[data_session]);
    let assessment = report
        .transfers
        .first()
        .ok_or("missing transfer assessment")?;
    let candidate = assessment
        .endpoint_candidates
        .first()
        .ok_or("missing endpoint fact")?;

    assert_eq!(assessment.status, FtpAssociationStatus::NoExactSession);
    assert!(candidate.sessions.is_empty());
    Ok(())
}

#[test]
fn ambiguous_control_session_generation_visible() -> Result<(), &'static str> {
    let capture_scope = scope(0);
    let client = endpoint([192, 0, 2, 10], 40_000);
    let server = endpoint([192, 0, 2, 20], 21);
    let advertisement = event(
        b"PORT 192,0,2,10,7,138\r\n",
        50,
        client.clone(),
        server.clone(),
        capture_scope.clone(),
        UNKNOWN_START,
    )?;
    let transfer = event(
        b"RETR /archive.bin\r\n",
        51,
        client,
        server,
        capture_scope.clone(),
        UNKNOWN_START,
    )?;
    let data_session = session(
        capture_scope,
        52,
        endpoint([192, 0, 2, 20], 50_001),
        endpoint([192, 0, 2, 10], 1_930),
        true,
    );

    let report = associate_data_sessions(&[advertisement, transfer], &[data_session]);
    let assessment = report
        .transfers
        .first()
        .ok_or("missing transfer assessment")?;
    let candidate = assessment
        .endpoint_candidates
        .first()
        .ok_or("missing endpoint candidate")?;

    assert_eq!(assessment.status, FtpAssociationStatus::Candidates);
    assert!(assessment.boundary_ambiguous);
    assert_eq!(candidate.sessions.len(), 1);
    assert!(
        candidate
            .sessions
            .first()
            .is_some_and(|session| session.generation_ambiguous)
    );
    Ok(())
}

#[test]
fn transfer_without_associated_port_guessing() -> Result<(), &'static str> {
    let client = endpoint([192, 0, 2, 10], 40_000);
    let server = endpoint([192, 0, 2, 20], 21);
    let transfer = event(
        b"RETR /archive.bin\r\n",
        60,
        client,
        server,
        scope(0),
        COMPLETE,
    )?;

    let report = associate_data_sessions(&[transfer], &[]);
    let assessment = report
        .transfers
        .first()
        .ok_or("missing transfer assessment")?;
    assert_eq!(assessment.status, FtpAssociationStatus::NoPriorEndpointFact);
    assert!(assessment.endpoint_candidates.is_empty());
    Ok(())
}

#[test]
fn future_endpoint_not_earlier_transfer() -> Result<(), &'static str> {
    let client = endpoint([192, 0, 2, 10], 40_000);
    let server = endpoint([192, 0, 2, 20], 21);
    let mut transfer = event(
        b"RETR /archive.bin\r\n",
        60,
        client.clone(),
        server.clone(),
        scope(0),
        COMPLETE,
    )?;
    let mut advertisement = event(
        b"PORT 192,0,2,10,7,138\r\n",
        61,
        client,
        server,
        scope(0),
        COMPLETE,
    )?;

    // Later TCP bytes can arrive before a gap-filling segment
    transfer.range = ByteRange::new(100, 20);
    advertisement.range = ByteRange::new(0, 25);

    let report = associate_data_sessions(&[transfer, advertisement], &[]);
    let assessment = report.transfers.first().ok_or("missing earlier transfer")?;

    assert_eq!(assessment.status, FtpAssociationStatus::NoPriorEndpointFact);
    assert!(assessment.endpoint_candidates.is_empty());
    Ok(())
}
