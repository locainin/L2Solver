use l2_workbench::{
    evidence::{Case, SourceRange},
    sha256,
};
use serde_json::json;
use std::error::Error;

#[derive(Clone)]
pub struct PacketSpec {
    pub bytes: Vec<u8>,
    pub interface: u32,
    pub vlan_ids: Vec<u16>,
    pub ticks: Option<u64>,
    pub timestamp_source: &'static str,
    pub timestamp_source_offset: Option<u64>,
}

impl PacketSpec {
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            interface: 0,
            vlan_ids: Vec::new(),
            ticks: None,
            timestamp_source: "CaptureFile",
            timestamp_source_offset: None,
        }
    }

    pub fn with_scope(mut self, interface: u32, vlan_ids: Vec<u16>) -> Self {
        self.interface = interface;
        tag_frame(&mut self.bytes, &vlan_ids);
        self.vlan_ids = vlan_ids;
        self
    }

    pub const fn with_ticks(mut self, ticks: u64) -> Self {
        self.ticks = Some(ticks);
        self
    }
}

fn tag_frame(frame: &mut Vec<u8>, vlan_ids: &[u16]) {
    if vlan_ids.is_empty() {
        return;
    }
    let Some(ether_type) = frame.get(12..14) else {
        return;
    };
    let mut encapsulation = Vec::with_capacity(vlan_ids.len() * 4 + 2);
    for vlan_id in vlan_ids {
        encapsulation.extend_from_slice(&[0x81, 0x00]);
        encapsulation.extend_from_slice(&vlan_id.to_be_bytes());
    }
    encapsulation.extend_from_slice(ether_type);
    frame.splice(12..14, encapsulation);
}

pub fn case_with_packets(specs: Vec<PacketSpec>) -> Result<Case, Box<dyn Error>> {
    let source_bytes = specs
        .iter()
        .flat_map(|spec| spec.bytes.iter().copied())
        .collect::<Vec<_>>();
    let mut case = Case::new();
    let source = case.add_source(
        "generic-capture.pcap",
        "capture",
        u64::try_from(source_bytes.len())?,
        &sha256(&source_bytes),
        None,
    )?;
    let mut source_offset = 0_u64;
    for (index, spec) in specs.into_iter().enumerate() {
        let packet = u64::try_from(index + 1)?;
        let blob = case.add_blob(&spec.bytes)?;
        let timestamp = spec.ticks.map(|ticks| {
            json!({
                "ticks": ticks,
                "radix": 10,
                "exponent": 7,
                "offset_seconds": 0,
                "source": spec.timestamp_source,
            })
        });
        let timestamp_source_ranges = spec
            .timestamp_source_offset
            .map(|offset| {
                vec![SourceRange {
                    source: source.clone(),
                    packet: Some(packet),
                    offset,
                    length: 8,
                }]
            })
            .unwrap_or_default();
        let id = case.add_node(
            "packet",
            Some(&blob),
            vec![SourceRange {
                source: source.clone(),
                packet: Some(packet),
                offset: source_offset,
                length: u64::try_from(spec.bytes.len())?,
            }],
            json!({
                "record": packet,
                "link_type": 1,
                "captured_length": spec.bytes.len(),
                "scope": {
                    "section": 0,
                    "interface": spec.interface,
                    "vlan_ids": spec.vlan_ids.iter().map(|vid| [33024, *vid]).collect::<Vec<_>>(),
                    "vlan_aux": null,
                },
                "timestamp": timestamp,
                "timestamp_source_ranges": timestamp_source_ranges,
            }),
        )?;
        assert_eq!(id, packet);
        source_offset = source_offset
            .checked_add(u64::try_from(spec.bytes.len())?)
            .ok_or("source byte offset overflow")?;
    }
    Ok(case)
}

pub fn tcp_frame(
    source: [u8; 4],
    destination: [u8; 4],
    source_port: u16,
    destination_port: u16,
    flags: u8,
) -> Vec<u8> {
    let mut frame = ethernet_ipv4(6, source, destination, 40);
    frame.extend_from_slice(&source_port.to_be_bytes());
    frame.extend_from_slice(&destination_port.to_be_bytes());
    frame.extend_from_slice(&1_u32.to_be_bytes());
    frame.extend_from_slice(&0_u32.to_be_bytes());
    frame.extend_from_slice(&[0x50, flags, 0, 0, 0, 0, 0, 0]);
    frame
}

pub fn udp_frame(
    source: [u8; 4],
    destination: [u8; 4],
    source_port: u16,
    destination_port: u16,
) -> Vec<u8> {
    let mut frame = ethernet_ipv4(17, source, destination, 28);
    frame.extend_from_slice(&source_port.to_be_bytes());
    frame.extend_from_slice(&destination_port.to_be_bytes());
    frame.extend_from_slice(&8_u16.to_be_bytes());
    frame.extend_from_slice(&0_u16.to_be_bytes());
    frame
}

fn ethernet_ipv4(protocol: u8, source: [u8; 4], destination: [u8; 4], ip_length: u16) -> Vec<u8> {
    let mut frame = vec![2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 8, 0];
    frame.extend_from_slice(&[0x45, 0]);
    frame.extend_from_slice(&ip_length.to_be_bytes());
    frame.extend_from_slice(&42_u16.to_be_bytes());
    frame.extend_from_slice(&0_u16.to_be_bytes());
    frame.extend_from_slice(&[64, protocol, 0, 0]);
    frame.extend_from_slice(&source);
    frame.extend_from_slice(&destination);
    frame
}
