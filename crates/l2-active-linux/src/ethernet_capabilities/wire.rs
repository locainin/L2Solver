//! The generic-netlink controller and the two read-only ethtool requests

use std::{fmt::Debug, io, sync::atomic::AtomicBool, time::Instant};

use netlink_packet_core::{
    DefaultNla, Emitable, NLA_F_NESTED, NLM_F_REQUEST, NetlinkBuffer, NetlinkMessage,
    NetlinkPayload, NetlinkSerializable,
};
use netlink_packet_generic::{
    GenlFamily, GenlHeader, GenlMessage,
    constants::GENL_ID_CTRL,
    ctrl::{GenlCtrl, GenlCtrlCmd, nlas::GenlCtrlAttrs},
};

use super::transport;

const FEATURES_GET: u8 = 11;
const FEATURES_REPLY: u8 = 11;
const TSINFO_GET: u8 = 25;
const TSINFO_REPLY: u8 = 26;

pub fn family(deadline: Instant, cancelled: &AtomicBool) -> io::Result<u16> {
    let bytes = transport::exchange(deadline, cancelled, |sequence, port| {
        let request = GenlCtrl {
            cmd: GenlCtrlCmd::GetFamily,
            nlas: vec![GenlCtrlAttrs::FamilyName("ethtool".into())],
        };
        encode(GenlMessage::from_payload(request), sequence, port)
    })?;
    let buffer = NetlinkBuffer::new_checked(&bytes).map_err(invalid)?;
    if buffer.message_type() != GENL_ID_CTRL {
        return Err(invalid("unexpected controller family"));
    }
    let message = NetlinkMessage::<GenlMessage<GenlCtrl>>::deserialize(&bytes).map_err(invalid)?;
    let NetlinkPayload::InnerMessage(message) = message.payload else {
        return Err(invalid("unexpected controller reply"));
    };
    if message.payload.cmd != GenlCtrlCmd::NewFamily {
        return Err(invalid("unexpected controller command"));
    }
    let mut family_id = None;
    let mut family_name = None;
    for attribute in message.payload.nlas {
        match attribute {
            GenlCtrlAttrs::FamilyId(id) if family_id.replace(id).is_some() => {
                return Err(invalid("duplicate family id"));
            }
            GenlCtrlAttrs::FamilyName(name) => {
                if family_name.replace(name).is_some() {
                    return Err(invalid("duplicate family name"));
                }
            }
            _ => {}
        }
    }
    if family_name.as_deref() != Some("ethtool") {
        return Err(invalid("unexpected family name"));
    }
    family_id
        .filter(|id| *id >= GENL_ID_CTRL)
        .ok_or_else(|| invalid("missing family id"))
}

pub fn features(
    family: u16,
    index: u32,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> io::Result<Vec<u8>> {
    query(
        family,
        FEATURES_GET,
        FEATURES_REPLY,
        index,
        deadline,
        cancelled,
    )
}

pub fn timestamps(
    family: u16,
    index: u32,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> io::Result<Vec<u8>> {
    query(family, TSINFO_GET, TSINFO_REPLY, index, deadline, cancelled)
}

fn query(
    family: u16,
    command: u8,
    expected: u8,
    index: u32,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> io::Result<Vec<u8>> {
    let bytes = transport::exchange(deadline, cancelled, |sequence, port| {
        let index = DefaultNla::new(1, index.to_ne_bytes().to_vec());
        let mut nested = vec![0; index.buffer_len()];
        index.emit(&mut nested);
        let request = Request {
            command,
            attrs: vec![DefaultNla::new(1 | NLA_F_NESTED, nested)],
        };
        let mut message = GenlMessage::from_payload(request);
        message.set_resolved_family_id(family);
        encode(message, sequence, port)
    })?;
    let buffer = NetlinkBuffer::new_checked(&bytes).map_err(invalid)?;
    if buffer.message_type() != family {
        return Err(invalid("unexpected ethtool family"));
    }
    let payload = buffer.payload();
    let header = GenlHeader::parse(payload).map_err(invalid)?;
    if header.cmd != expected || header.version != 1 {
        return Err(invalid("unexpected ethtool reply command or version"));
    }
    let attributes = payload
        .get(4..)
        .ok_or_else(|| invalid("short ethtool reply"))?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(attributes.len())
        .map_err(io::Error::other)?;
    output.extend_from_slice(attributes);
    Ok(output)
}

fn encode<T: NetlinkSerializable + Debug>(
    payload: T,
    sequence: u32,
    port: u32,
) -> io::Result<Vec<u8>>
where
    NetlinkPayload<T>: From<T>,
{
    let mut message = NetlinkMessage::from(payload);
    message.header.flags = NLM_F_REQUEST;
    message.header.sequence_number = sequence;
    message.header.port_number = port;
    message.finalize();
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(message.buffer_len())
        .map_err(io::Error::other)?;
    bytes.resize(message.buffer_len(), 0);
    message.serialize(&mut bytes);
    Ok(bytes)
}

#[derive(Debug)]
struct Request {
    command: u8,
    attrs: Vec<DefaultNla>,
}

impl GenlFamily for Request {
    fn family_name() -> &'static str {
        "ethtool"
    }
    fn command(&self) -> u8 {
        self.command
    }
    fn version(&self) -> u8 {
        1
    }
}

impl Emitable for Request {
    fn buffer_len(&self) -> usize {
        self.attrs.as_slice().buffer_len()
    }
    fn emit(&self, bytes: &mut [u8]) {
        self.attrs.as_slice().emit(bytes);
    }
}

fn invalid(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}
