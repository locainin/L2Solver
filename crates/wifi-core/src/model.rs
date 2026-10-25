use serde::{Deserialize, Serialize};

/// Six-byte address carried by an IEEE 802.11 MAC header
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct MacAddress([u8; 6]);

impl MacAddress {
    /// Preserve all six address octets without normalization
    #[must_use]
    pub const fn new(octets: [u8; 6]) -> Self {
        Self(octets)
    }

    /// Return the address exactly as it appeared on the wire
    #[must_use]
    pub const fn octets(self) -> [u8; 6] {
        self.0
    }

    /// Return whether the address selects a group receiver
    #[must_use]
    pub const fn is_group(self) -> bool {
        let [first, _, _, _, _, _] = self.0;
        first & 1 != 0
    }

    /// Return whether the address can identify one transmitting station
    #[must_use]
    pub const fn is_usable_unicast(self) -> bool {
        !self.is_group() && !matches!(self.0, [0, 0, 0, 0, 0, 0])
    }
}

/// Top-level frame type from the two-bit frame-control field
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum FrameType {
    Management,
    Control,
    Data,
    Extension,
}

/// Management subtype values used by passive assessment
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum ManagementSubtype {
    AssociationRequest,
    AssociationResponse,
    ReassociationRequest,
    ReassociationResponse,
    ProbeRequest,
    ProbeResponse,
    Beacon,
    Authentication,
    Disassociation,
    Deauthentication,
    Action,
    Other(u8),
}

impl ManagementSubtype {
    pub(crate) const fn from_wire(value: u8) -> Self {
        match value {
            0 => Self::AssociationRequest,
            1 => Self::AssociationResponse,
            2 => Self::ReassociationRequest,
            3 => Self::ReassociationResponse,
            4 => Self::ProbeRequest,
            5 => Self::ProbeResponse,
            8 => Self::Beacon,
            10 => Self::Disassociation,
            11 => Self::Authentication,
            12 => Self::Deauthentication,
            13 => Self::Action,
            other => Self::Other(other),
        }
    }
}

/// Control subtype values with assessment relevance
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum ControlSubtype {
    BlockAckRequest,
    BlockAck,
    PsPoll,
    Rts,
    Cts,
    Ack,
    CfEnd,
    CfEndCfAck,
    Other(u8),
}

impl ControlSubtype {
    pub(crate) const fn from_wire(value: u8) -> Self {
        match value {
            8 => Self::BlockAckRequest,
            9 => Self::BlockAck,
            10 => Self::PsPoll,
            11 => Self::Rts,
            12 => Self::Cts,
            13 => Self::Ack,
            14 => Self::CfEnd,
            15 => Self::CfEndCfAck,
            other => Self::Other(other),
        }
    }
}

/// Raw four-bit data subtype
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct DataSubtype(u8);

impl DataSubtype {
    /// Construct from a value already extracted from the four-bit wire field
    #[must_use]
    pub const fn from_wire_nibble(value: u8) -> Self {
        Self(value & 0x0f)
    }

    /// Return the raw subtype nibble
    #[must_use]
    pub const fn value(self) -> u8 {
        self.0
    }

    /// `QoS` data subtypes carry a two-byte `QoS` control field
    #[must_use]
    pub const fn has_qos(self) -> bool {
        self.0 & 0x08 != 0
    }
}

/// Typed interpretation of the frame type and subtype bits
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum FrameKind {
    Management(ManagementSubtype),
    Control(ControlSubtype),
    Data(DataSubtype),
    Extension(u8),
}

/// Frame-control fields retained independently from address interpretation
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct FrameControl {
    raw: u16,
    kind: FrameKind,
}

impl FrameControl {
    pub(crate) const fn new(raw: u16, kind: FrameKind) -> Self {
        Self { raw, kind }
    }

    #[must_use]
    pub const fn raw(self) -> u16 {
        self.raw
    }

    #[must_use]
    pub const fn kind(self) -> FrameKind {
        self.kind
    }

    #[must_use]
    pub const fn frame_type(self) -> FrameType {
        match self.kind {
            FrameKind::Management(_) => FrameType::Management,
            FrameKind::Control(_) => FrameType::Control,
            FrameKind::Data(_) => FrameType::Data,
            FrameKind::Extension(_) => FrameType::Extension,
        }
    }

    #[must_use]
    pub const fn to_ds(self) -> bool {
        self.raw & 0x0100 != 0
    }

    #[must_use]
    pub const fn from_ds(self) -> bool {
        self.raw & 0x0200 != 0
    }

    #[must_use]
    pub const fn retry(self) -> bool {
        self.raw & 0x0800 != 0
    }

    #[must_use]
    pub const fn protected(self) -> bool {
        self.raw & 0x4000 != 0
    }

    #[must_use]
    pub const fn order(self) -> bool {
        self.raw & 0x8000 != 0
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HeaderFields {
    pub receiver: Option<MacAddress>,
    pub transmitter: Option<MacAddress>,
    pub address3: Option<MacAddress>,
    pub address4: Option<MacAddress>,
    pub sequence_control: Option<u16>,
    pub qos_control: Option<u16>,
    pub ht_control: Option<u32>,
}

/// One borrowed IEEE 802.11 MAC frame
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WifiFrame<'a> {
    bytes: &'a [u8],
    body: &'a [u8],
    control: FrameControl,
    fields: HeaderFields,
}

impl<'a> WifiFrame<'a> {
    pub(crate) const fn new(
        bytes: &'a [u8],
        body: &'a [u8],
        control: FrameControl,
        fields: HeaderFields,
    ) -> Self {
        Self {
            bytes,
            body,
            control,
            fields,
        }
    }

    #[must_use]
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    #[must_use]
    pub const fn body(&self) -> &'a [u8] {
        self.body
    }

    #[must_use]
    pub const fn control(&self) -> FrameControl {
        self.control
    }

    #[must_use]
    pub const fn kind(&self) -> FrameKind {
        self.control.kind()
    }

    #[must_use]
    pub const fn receiver(&self) -> Option<MacAddress> {
        self.fields.receiver
    }

    #[must_use]
    pub const fn transmitter(&self) -> Option<MacAddress> {
        self.fields.transmitter
    }

    #[must_use]
    pub const fn address3(&self) -> Option<MacAddress> {
        self.fields.address3
    }

    #[must_use]
    pub const fn address4(&self) -> Option<MacAddress> {
        self.fields.address4
    }

    #[must_use]
    pub const fn sequence_control(&self) -> Option<u16> {
        self.fields.sequence_control
    }

    #[must_use]
    pub const fn qos_control(&self) -> Option<u16> {
        self.fields.qos_control
    }

    #[must_use]
    pub const fn ht_control(&self) -> Option<u32> {
        self.fields.ht_control
    }
}
