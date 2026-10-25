use crate::vlan::VlanTag;

// A decoded frame borrows payload bytes so parsing does not copy unbounded input
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EthernetFrame<'a> {
    /// Destination MAC address in wire order
    pub destination: [u8; 6],
    /// Source MAC address in wire order
    pub source: [u8; 6],
    /// Supported VLAN tags in their original nesting order
    pub vlan_tags: Vec<VlanTag>,
    /// Protocol data, or the declared IEEE 802.3 data section
    pub payload: &'a [u8],
    /// Bytes after a declared IEEE 802.3 payload length
    pub padding: &'a [u8],
    /// The first non-VLAN type or length field
    pub field: FrameField,
}

// Values at or above 1536 identify an EtherType, while values at or below 1500 identify length
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameField {
    /// An Ethernet II protocol identifier, including unknown values
    EtherType(u16),
    /// An IEEE 802.3 data length
    Length(u16),
}
