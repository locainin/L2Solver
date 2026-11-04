//! A single protocol assessment is shared by text and NDJSON output

use l2_capture::LinkType;
use l2_codecs::{LldpFrame, StpError, StpFrame, Validity};
use l2_core::FrameField;
use l2_discovery::{
    IpPacket, ip_packet_from_payload,
    link::{NetworkEnvelope, decode_network_frame},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Parsed,
    Malformed,
    Invalid,
    Unsupported,
}

pub struct Assessment<'input> {
    pub network: Option<NetworkEnvelope<'input>>,
    pub lldp: Option<LldpFrame<'input>>,
    pub stp: Option<StpFrame<'input>>,
    pub ip: Option<IpPacket<'input>>,
    pub status: Status,
    pub diagnostic: Option<String>,
}

/// Assess bytes only when the capture boundary identifies an Ethernet frame
pub fn assess(bytes: &[u8]) -> Assessment<'_> {
    let ethernet = match l2_core::decode(bytes) {
        Ok(frame) => frame,
        Err(error) => {
            return Assessment {
                network: None,
                lldp: None,
                stp: None,
                ip: None,
                status: Status::Malformed,
                diagnostic: Some(format!("malformed Ethernet: {error}")),
            };
        }
    };
    assess_network(NetworkEnvelope::Ethernet(ethernet))
}

fn assess_network(network: NetworkEnvelope<'_>) -> Assessment<'_> {
    let field = network.field();
    let payload = network.payload();
    let mut result = Assessment {
        network: None,
        lldp: None,
        stp: None,
        ip: None,
        status: Status::Unsupported,
        diagnostic: None,
    };
    if matches!(field, Some(FrameField::EtherType(0x0800 | 0x86dd))) {
        result.ip = ip_packet_from_payload(network.protocol(), payload);
        if result.ip.is_some() {
            result.status = Status::Parsed;
        } else {
            // Unsupported extension layouts and incomplete envelopes remain unresolved
            result.diagnostic = Some(String::from(
                "IP envelope incomplete, malformed, or unsupported",
            ));
        }
    }
    if field == Some(FrameField::EtherType(0x88cc)) {
        match l2_codecs::decode_lldp(payload) {
            Ok(lldp) => {
                result.status = if lldp.validity == Validity::Valid {
                    Status::Parsed
                } else {
                    Status::Invalid
                };
                result.lldp = Some(lldp);
            }
            Err(error) => {
                result.status = Status::Malformed;
                result.diagnostic = Some(format!("malformed LLDP: {error}"));
            }
        }
    }
    // LLC identifies bridge BPDUs without guessing from arbitrary payload bytes
    if matches!(field, Some(FrameField::Length(_))) && payload.starts_with(&[0x42, 0x42, 0x03]) {
        match l2_codecs::decode_stp(payload) {
            Ok(stp) => {
                result.status = Status::Parsed;
                result.stp = Some(stp);
            }
            Err(error) => {
                result.status = match error {
                    StpError::UnsupportedVersion { .. }
                    | StpError::UnsupportedType { .. }
                    | StpError::UnsupportedExtension { .. } => Status::Unsupported,
                    _ => Status::Malformed,
                };
                result.diagnostic = Some(format!("STP: {error}"));
            }
        }
    }
    if field.is_none() {
        // The cooked protocol field cannot always be treated as an EtherType
        result.diagnostic = Some(format!(
            "unsupported Linux cooked protocol or hardware type (protocol 0x{:04x})",
            network.protocol()
        ));
    }
    result.network = Some(network);
    result
}

/// Route a captured frame through the decoder selected by its checked link type
pub fn assess_with_link_type(link_type: LinkType, bytes: &[u8]) -> Assessment<'_> {
    match link_type {
        LinkType::Ethernet => assess(bytes),
        LinkType::LinuxSll | LinkType::LinuxSll2 => decode_network_frame(link_type, bytes)
            .map_or_else(
                || Assessment {
                    network: None,
                    lldp: None,
                    stp: None,
                    ip: None,
                    status: Status::Malformed,
                    diagnostic: Some(format!("malformed {} header", link_type.name())),
                },
                assess_network,
            ),
        _ => Assessment {
            network: None,
            lldp: None,
            stp: None,
            ip: None,
            status: Status::Unsupported,
            diagnostic: Some(format!(
                "unsupported link type {} ({})",
                link_type.name(),
                link_type.raw()
            )),
        },
    }
}
