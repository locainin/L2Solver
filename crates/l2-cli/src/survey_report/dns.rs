//! Explain DNS wire facts and keep address co-occurrence separate from causality

use l2_audit::{DnsObservation, ForensicReport};
use l2_discovery::dns::{DnsDecoding, DnsValue};
use std::io::{self, Write};

pub(super) fn details(
    facts: &ForensicReport,
    verbosity: u8,
    output: &mut impl Write,
) -> io::Result<()> {
    for association in &facts.dns_matches {
        write!(
            output,
            "  DNS response packet={} matching outstanding queries={}",
            association.response_packet, association.candidate_queries
        )?;
        if let Some(query) = association.query_packet {
            writeln!(output, " query_packet={query}")?;
        } else {
            writeln!(output, " (no unique association)")?;
        }
    }
    for usage in &facts.dns_address_uses {
        writeln!(
            output,
            "  DNS address {} packets {} -> {} -> {}; answer_record={} requester_is_later_source={} (destination co-occurrence, causality unresolved)",
            usage.address,
            usage.query_packet,
            usage.response_packet,
            usage.packet,
            usage.answer_record,
            usage.client_matches_requester
        )?;
    }
    if verbosity > 1 {
        for observation in &facts.dns_observations {
            observation_detail(observation, output)?;
        }
    }
    Ok(())
}

fn observation_detail(observation: &DnsObservation, output: &mut impl Write) -> io::Result<()> {
    writeln!(
        output,
        "  DNS candidate packet={} source={}:{} vlan_ids={:?} vlan_aux={:?} {}:{} -> {}:{} offset={} length={}",
        observation.packet,
        observation.scope.section,
        observation.scope.interface,
        observation.scope.vlan_ids,
        observation.scope.vlan_aux,
        observation.source,
        observation.ports.0,
        observation.destination,
        observation.ports.1,
        observation.payload_offset,
        observation.payload_length
    )?;
    let message = match &observation.decoding {
        DnsDecoding::Decoded { message } => message,
        DnsDecoding::Unresolved { error } => {
            return writeln!(output, "    unresolved: {error}");
        }
    };
    writeln!(
        output,
        "    id={} flags={:#06x} opcode={} rcode={}",
        message.id,
        message.flags,
        message.opcode(),
        message.response_code()
    )?;
    for question in &message.questions {
        // DNS name display escapes control bytes and literal dots within labels
        writeln!(
            output,
            "    question={} type={} class={}",
            question.name, question.qtype, question.qclass
        )?;
    }
    for record in &message.records {
        write!(
            output,
            "    {:?} owner={} type={} class={} ttl={} rdata_offset={} length={}",
            record.section,
            record.name,
            record.rr_type,
            record.class,
            record.ttl,
            observation.payload_offset + record.rdata.offset,
            record.rdata.length
        )?;
        match &record.value {
            DnsValue::Address(address) => writeln!(output, " address={address}")?,
            DnsValue::Name(name) => writeln!(output, " name={name}")?,
            DnsValue::Opaque => writeln!(output, " value=opaque")?,
        }
    }
    Ok(())
}
