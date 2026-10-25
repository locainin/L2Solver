//! Borrowed STP and RSTP observation types

/// The spanning-tree protocol versions implemented by the passive decoder
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StpVersion {
    /// IEEE 802.1D configuration and topology-change BPDUs
    Stp,
    /// IEEE 802.1w rapid spanning-tree BPDUs
    Rstp,
}

/// The supported BPDU layouts
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StpBpduType {
    /// Configuration BPDU carrying tree and timer fields
    Configuration,
    /// Topology Change Notification BPDU
    TopologyChange,
    /// Rapid spanning-tree BPDU carrying the configuration fields
    Rapid,
}

/// The STP LLC header when the caller supplied one
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StpLlcHeader {
    /// Destination service access point
    pub dsap: u8,
    /// Source service access point
    pub ssap: u8,
    /// Unnumbered information control value
    pub control: u8,
}

/// A decoded eight-byte bridge identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BridgeId {
    /// The priority bits in their wire position
    pub priority: u16,
    /// The twelve-bit system identifier extension
    pub system_id_extension: u16,
    /// The bridge MAC address
    pub mac: [u8; 6],
}

impl BridgeId {
    /// Split a wire bridge identifier into its typed fields
    #[must_use]
    pub const fn from_wire(priority_and_extension: u16, mac: [u8; 6]) -> Self {
        Self {
            priority: priority_and_extension & 0xf000,
            system_id_extension: priority_and_extension & 0x0fff,
            mac,
        }
    }

    /// Reconstruct the two-byte priority and system-extension field
    #[must_use]
    pub const fn wire_priority_and_extension(self) -> u16 {
        // OR preserves the established behavior even when public fields are
        // manually constructed with overlapping bits
        self.priority | self.system_id_extension
    }
}

/// A decoded two-byte port identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortId {
    /// The complete identifier as it appeared on the wire
    pub raw: u16,
}

impl PortId {
    /// Split a wire port identifier into priority and number fields
    #[must_use]
    pub const fn from_wire(raw: u16) -> Self {
        Self { raw }
    }

    /// Return the four-bit port-priority field in its wire position
    #[must_use]
    pub const fn priority(self) -> u8 {
        let [high, _low] = self.raw.to_be_bytes();
        high >> 4
    }

    /// Return the twelve-bit port number
    #[must_use]
    pub const fn number(self) -> u16 {
        self.raw & 0x0fff
    }
}

/// The RSTP flag octet with raw bits retained
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StpFlags {
    /// The original flag octet
    pub raw: u8,
}

impl StpFlags {
    /// Decode all defined flag bits while retaining unknown combinations
    #[must_use]
    pub const fn from_wire(raw: u8) -> Self {
        Self { raw }
    }

    /// Return the port role encoded in bits three and four
    #[must_use]
    pub const fn port_role(self) -> PortRole {
        PortRole::from_wire((self.raw >> 2) & 0x03)
    }

    /// Return whether the topology-change bit is set
    #[must_use]
    pub const fn topology_change(self) -> bool {
        self.raw & 0x01 != 0
    }

    /// Return whether the proposal bit is set
    #[must_use]
    pub const fn proposal(self) -> bool {
        self.raw & 0x02 != 0
    }

    /// Return whether the learning bit is set
    #[must_use]
    pub const fn learning(self) -> bool {
        self.raw & 0x10 != 0
    }

    /// Return whether the forwarding bit is set
    #[must_use]
    pub const fn forwarding(self) -> bool {
        self.raw & 0x20 != 0
    }

    /// Return whether the agreement bit is set
    #[must_use]
    pub const fn agreement(self) -> bool {
        self.raw & 0x40 != 0
    }

    /// Return whether the topology-change acknowledgement bit is set
    #[must_use]
    pub const fn topology_change_ack(self) -> bool {
        self.raw & 0x80 != 0
    }
}

/// RSTP port role values from the two-bit role field
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortRole {
    /// The role value is reserved or not assigned in a TCN/configuration BPDU
    Unknown,
    /// Alternate or backup port
    AlternateBackup,
    /// Root port
    Root,
    /// Designated port
    Designated,
}

impl PortRole {
    const fn from_wire(value: u8) -> Self {
        match value {
            1 => Self::AlternateBackup,
            2 => Self::Root,
            3 => Self::Designated,
            _ => Self::Unknown,
        }
    }
}

/// The four timer values carried in configuration and RSTP BPDUs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StpTimers {
    /// Message age in one-256th-second wire units
    pub message_age: u16,
    /// Maximum age in one-256th-second wire units
    pub max_age: u16,
    /// Hello interval in one-256th-second wire units
    pub hello_time: u16,
    /// Forward delay in one-256th-second wire units
    pub forward_delay: u16,
}

/// A passive STP/RSTP BPDU observation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StpFrame<'input> {
    /// BPDU bytes from the protocol identifier through the supported layout
    pub raw: &'input [u8],
    /// Complete supplied bytes, including optional LLC and trailing bytes
    pub wire: &'input [u8],
    /// Optional validated 802.2 LLC header
    pub llc: Option<StpLlcHeader>,
    /// IEEE protocol identifier, retained as a wire value
    pub protocol_identifier: u16,
    /// Typed STP/RSTP protocol version
    pub version: StpVersion,
    /// Numeric version identifier from the BPDU
    pub version_id: u8,
    /// Typed BPDU layout
    pub bpdu_type: StpBpduType,
    /// Numeric BPDU type from the wire
    pub type_id: u8,
    /// Decoded flag bits
    pub flags: StpFlags,
    /// Root bridge identifier for configuration and RSTP BPDUs
    pub root: Option<BridgeId>,
    /// Root path cost for configuration and RSTP BPDUs
    pub cost: Option<u32>,
    /// Sending bridge identifier for configuration and RSTP BPDUs
    pub bridge: Option<BridgeId>,
    /// Sending port identifier for configuration and RSTP BPDUs
    pub port: Option<PortId>,
    /// Timers for configuration and RSTP BPDUs
    pub timers: Option<StpTimers>,
    /// RSTP version-one length field, when present
    pub version_1_length: Option<u8>,
    /// Bytes after the recognized BPDU layout
    pub padding: &'input [u8],
}
