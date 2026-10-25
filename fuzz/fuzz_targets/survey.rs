#![no_main]
use l2_audit::{DnsObservation, Policy, Report, Survey, SurveyLimits, Verdict};
use l2_capture::{CaptureMetadata, CapturedFrame, InterfaceId};
use l2_discovery::dns::{DnsDecoding, DnsMessage, DnsSection, DnsValue};
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;

fn observation(report: &Report, packet: u64) -> Option<&DnsObservation> {
    report
        .forensics
        .dns_observations
        .iter()
        .find(|entry| entry.packet == packet)
}

const fn decoded(observation: &DnsObservation) -> Option<&DnsMessage> {
    match &observation.decoding {
        DnsDecoding::Decoded { message } => Some(message),
        DnsDecoding::Unresolved { .. } => None,
    }
}

fn same_questions(left: &DnsMessage, right: &DnsMessage) -> bool {
    left.questions.len() == right.questions.len()
        && left
            .questions
            .iter()
            .zip(&right.questions)
            .all(|(left, right)| {
                left.name.canonical() == right.name.canonical()
                    && left.qtype == right.qtype
                    && left.qclass == right.qclass
            })
}

fn observation_invariants(report: &Report, evidence: &BTreeMap<u64, usize>) {
    let facts = &report.forensics;
    assert!(facts.dns_observations.iter().all(|entry| {
        evidence.get(&entry.packet).is_some_and(|captured_len| {
            entry
                .payload_offset
                .checked_add(entry.payload_length)
                .is_some_and(|end| end <= *captured_len)
        }) && match &entry.decoding {
            DnsDecoding::Unresolved { .. } => true,
            DnsDecoding::Decoded { message } => {
                message
                    .questions
                    .iter()
                    .all(|question| question.name.wire().len() <= 255)
                    && message.records.iter().all(|record| {
                        record
                            .rdata
                            .offset
                            .checked_add(record.rdata.length)
                            .is_some_and(|end| end <= entry.payload_length)
                    })
            }
        }
    }));
}

fn response_match_is_valid(
    report: &Report,
    evidence: &BTreeMap<u64, usize>,
    matched: &l2_audit::DnsResponseMatch,
) -> bool {
    if !evidence.contains_key(&matched.response_packet)
        || (matched.query_packet.is_some() != (matched.candidate_queries == 1))
    {
        return false;
    }
    let Some(response) = observation(report, matched.response_packet) else {
        return false;
    };
    let Some(response_message) = decoded(response) else {
        return false;
    };
    if !response_message.is_response()
        || response_message.opcode() != 0
        || response_message.questions.is_empty()
    {
        return false;
    }
    let Some(query_packet) = matched.query_packet else {
        return true;
    };
    if !evidence.contains_key(&query_packet) || query_packet >= matched.response_packet {
        return false;
    }
    observation(report, query_packet).is_some_and(|query| {
        decoded(query).is_some_and(|query_message| {
            !query_message.is_response()
                && query.scope == response.scope
                && query.source == response.destination
                && query.destination == response.source
                && query.ports == (response.ports.1, response.ports.0)
                && query_message.id == response_message.id
                && query_message.opcode() == response_message.opcode()
                && same_questions(query_message, response_message)
        })
    })
}

fn response_match_invariants(report: &Report, evidence: &BTreeMap<u64, usize>) {
    assert!(
        report
            .forensics
            .dns_matches
            .iter()
            .all(|matched| response_match_is_valid(report, evidence, matched))
    );
}

fn address_use_is_valid(
    report: &Report,
    evidence: &BTreeMap<u64, usize>,
    address_use: &l2_audit::DnsAddressUse,
) -> bool {
    if !evidence.contains_key(&address_use.query_packet)
        || !evidence.contains_key(&address_use.response_packet)
        || !evidence.contains_key(&address_use.packet)
        || address_use.query_packet >= address_use.response_packet
        || address_use.response_packet >= address_use.packet
        || !report.forensics.dns_matches.iter().any(|matched| {
            matched.response_packet == address_use.response_packet
                && matched.query_packet == Some(address_use.query_packet)
                && matched.candidate_queries == 1
        })
    {
        return false;
    }
    let query_is_request = observation(report, address_use.query_packet)
        .and_then(decoded)
        .is_some_and(|message| !message.is_response());
    if !query_is_request {
        return false;
    }
    observation(report, address_use.response_packet).is_some_and(|response| {
        decoded(response).is_some_and(|message| {
            message
                .records
                .get(address_use.answer_record)
                .is_some_and(|record| {
                    record.section == DnsSection::Answer
                        && record.value == DnsValue::Address(address_use.address)
                        && record
                            .rdata
                            .offset
                            .checked_add(record.rdata.length)
                            .is_some_and(|end| end <= response.payload_length)
                })
        })
    })
}

fn address_use_invariants(report: &Report, evidence: &BTreeMap<u64, usize>) {
    assert!(
        report
            .forensics
            .dns_address_uses
            .iter()
            .all(|address_use| address_use_is_valid(report, evidence, address_use))
    );
}

// Exercise complete packets and bounded packet sequences through the same survey
fuzz_target!(|data: &[u8]| {
    // A small quota exercises omission and correlation boundaries in short inputs
    let Ok(limits) = SurveyLimits::default().with_forensic_records(8) else {
        return;
    };
    let Ok(limits) = limits.with_dns_messages(8) else {
        return;
    };
    let mut survey = Survey::with_limits(limits);
    for bytes in std::iter::once(data).chain(data.chunks(128).take(256)) {
        let Ok(length) = u32::try_from(bytes.len()) else {
            return;
        };
        let Ok(frame) = CapturedFrame::new(
            bytes.to_vec(),
            CaptureMetadata::unknown(
                InterfaceId {
                    section: 0,
                    index: 0,
                },
                length,
            ),
        ) else {
            continue;
        };
        if survey.observe(&frame).is_err() {
            break;
        }
    }
    if let Ok(report) = survey.finish(&Policy::default()) {
        let evidence = report
            .evidence_refs
            .iter()
            .map(|packet| (packet.sequence, packet.captured_len))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(evidence.len(), report.evidence_refs.len());
        let facts = &report.forensics;
        assert!(facts.ip_frames_parsed <= facts.ip_frames_seen);
        assert!(
            facts.communications.len()
                + facts.arp_observations.len()
                + facts.arp_changes.len()
                + facts.trailing_data.len()
                + facts.dns_observations.len()
                + facts.dns_matches.len()
                + facts.dns_address_uses.len()
                <= 8
        );
        for packet in facts
            .communications
            .iter()
            .map(|row| row.packet)
            .chain(facts.arp_observations.iter().map(|row| row.packet))
            .chain(facts.trailing_data.iter().map(|row| row.packet))
        {
            assert!(evidence.contains_key(&packet));
        }
        for change in &facts.arp_changes {
            // Event order is capture record order, independent of source timestamps
            assert!(change.previous_packet < change.packet);
            assert!(evidence.contains_key(&change.previous_packet));
            assert!(evidence.contains_key(&change.packet));
            if let Some(packet) = change.followup_packet {
                assert!(change.packet < packet);
                assert!(evidence.contains_key(&packet));
            }
        }
        assert!(facts.dns_messages_parsed <= facts.dns_candidates_seen);
        observation_invariants(&report, &evidence);
        response_match_invariants(&report, &evidence);
        address_use_invariants(&report, &evidence);
        for finding in report.findings {
            assert_ne!(finding.verdict, Verdict::Pass);
            for sequence in finding.evidence_packets {
                assert!(evidence.contains_key(&sequence));
            }
        }
    }
});
