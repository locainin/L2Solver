//! The receive loop preserves capture metadata independently from protocol validity

use crate::{render, report};
use l2_io::LinkIo;
use std::{error::Error, io::Write};

#[derive(Default)]
pub struct Summary {
    frames: u64,
    pub malformed: u64,
    pub invalid: u64,
    pub unsupported: u64,
    pub truncated: u64,
    pub collection: l2_pcap::CollectionSummary,
}

pub fn inspect<L: LinkIo>(
    link: &mut L,
    output: &mut impl Write,
) -> Result<Summary, Box<dyn Error>> {
    let mut summary = Summary::default();
    while let Some(packet) = link.recv()? {
        // Truncation describes capture evidence independently from protocol validity
        summary.frames += 1;
        summary.truncated += u64::from(packet.is_truncated());
        let metadata = packet.metadata();
        write!(
            output,
            "frame={} interface={}:{} captured={} original={} ",
            summary.frames,
            metadata.interface().section,
            metadata.interface().index,
            packet.captured_len(),
            metadata.original_len()
        )?;
        // The checked link type selects the only safe protocol assessment path
        let assessment = report::assess_with_link_type(metadata.link_type(), packet.bytes());
        match assessment.status {
            report::Status::Malformed => summary.malformed += 1,
            report::Status::Invalid => summary.invalid += 1,
            report::Status::Unsupported if assessment.diagnostic.is_some() => {
                summary.unsupported += 1;
            }
            _ => {}
        }
        if let Some(ethernet) = assessment.ethernet {
            render::mac(output, ethernet.source)?;
            write!(output, " -> ")?;
            render::mac(output, ethernet.destination)?;
            writeln!(
                output,
                " {:?} tags={:?}",
                ethernet.field, ethernet.vlan_tags
            )?;
        }
        if let Some(ip) = assessment.ip {
            writeln!(
                output,
                "  IP {} -> {} protocol={} ports={:?} fragmented={} declared={}",
                ip.source,
                ip.destination,
                ip.protocol,
                ip.ports(),
                ip.fragmented,
                ip.declared_len
            )?;
        }
        if let Some(lldp) = assessment.lldp {
            writeln!(output, "  LLDP {:?} (mandatory fields)", lldp.validity)?;
            for tlv in lldp.tlvs {
                write!(output, "  tlv={} offset={} value=", tlv.kind, tlv.offset)?;
                render::bytes(output, tlv.value)?;
                writeln!(output)?;
            }
        }
        if let Some(stp) = assessment.stp {
            writeln!(
                output,
                "  STP {:?} {:?} root={:?} cost={:?}",
                stp.version, stp.bpdu_type, stp.root, stp.cost
            )?;
        }
        if let Some(diagnostic) = assessment.diagnostic {
            writeln!(output, "{diagnostic}")?;
        }
    }
    writeln!(
        output,
        "frames={} malformed={} invalid={} unsupported={} truncated={}",
        summary.frames, summary.malformed, summary.invalid, summary.unsupported, summary.truncated
    )?;
    summary.collection = link.collection_summary();
    crate::source_collection::text(summary.collection, output)?;
    Ok(summary)
}
