use l2_audit::ForensicScope;
use l2_discovery::NetworkAddress;
use l2_workbench::{
    application::{
        ParseContext,
        ftp::{FtpControlEvent, decode_ftp},
    },
    reconstruction::{Endpoint, HandshakeAssessment, Stream, TcpSession},
};

pub fn scope(vlan: u16) -> ForensicScope {
    ForensicScope {
        section: 0,
        interface: 1,
        vlan_ids: if vlan == 0 {
            Vec::new()
        } else {
            vec![(0x8100, vlan)]
        },
        vlan_aux: None,
    }
}

pub const fn endpoint(address: [u8; 4], port: u16) -> Endpoint {
    Endpoint {
        address: NetworkAddress::Ipv4(address),
        port,
    }
}

pub fn event(
    bytes: &[u8],
    packet: u32,
    source: Endpoint,
    destination: Endpoint,
    scope: ForensicScope,
    context: ParseContext,
) -> Result<FtpControlEvent, &'static str> {
    event_in_episode(bytes, packet, 1, source, destination, scope, context)
}

pub fn event_from_endpoints(
    bytes: &[u8],
    packet: u32,
    source: &Endpoint,
    destination: &Endpoint,
    scope: &ForensicScope,
    context: ParseContext,
) -> Result<FtpControlEvent, &'static str> {
    event(
        bytes,
        packet,
        source.clone(),
        destination.clone(),
        scope.clone(),
        context,
    )
}

pub fn event_in_episode(
    bytes: &[u8],
    packet: u32,
    control_episode: u32,
    source: Endpoint,
    destination: Endpoint,
    scope: ForensicScope,
    context: ParseContext,
) -> Result<FtpControlEvent, &'static str> {
    let report = decode_ftp(bytes, context);
    let item = report.findings.first().ok_or("missing FTP control item")?;
    FtpControlEvent::from_item(scope, packet, 0, control_episode, source, destination, item)
        .ok_or("FTP line did not produce an association event")
}

pub fn session(
    scope: ForensicScope,
    first_packet: u32,
    source: Endpoint,
    destination: Endpoint,
    generation_ambiguous: bool,
) -> TcpSession {
    let forward = source <= destination;
    let initiator = Some(source.clone());
    let [left, right] = if forward {
        [source, destination]
    } else {
        [destination, source]
    };
    let (forward_packets, reverse_packets) = if forward {
        (vec![first_packet], Vec::new())
    } else {
        (Vec::new(), vec![first_packet])
    };
    let canonical_endpoints = [left.clone(), right.clone()];
    let directions = [
        stream(left.clone(), right.clone(), forward_packets),
        stream(right, left, reverse_packets),
    ];
    TcpSession {
        handshake: HandshakeAssessment::default(),
        scope,
        endpoints: canonical_endpoints,
        first_packet,
        generation_ambiguous,
        initiator,
        reset_packets: Vec::new(),
        directions,
    }
}

const fn stream(source: Endpoint, destination: Endpoint, packets: Vec<u32>) -> Stream {
    Stream {
        fragment_candidates: Vec::new(),
        source,
        destination,
        start_sequence: 0,
        start_known: true,
        end_observed: false,
        sequence_ambiguous: false,
        outside_segments: 0,
        coverage: None,
        origins: Vec::new(),
        packets,
    }
}
