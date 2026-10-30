//! Borrowed CDP results and caller-selected parser limits

/// Maximum CDP bytes in an IEEE 802.3 payload after the eight-byte LLC/SNAP header
pub const MAX_CDP_BYTES: usize = 1_492;

/// Limits applied before retaining CDP identity values
///
/// The Ethernet payload ceiling bounds work even when a caller selects larger
/// values. Zero limits intentionally reject any nonempty identity-bearing PDU
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CdpLimits {
    pub(crate) max_tlvs: usize,
    pub(crate) max_identity_bytes: usize,
}

impl CdpLimits {
    /// Select the maximum TLV count and size of each identity value
    #[must_use]
    pub const fn new(max_tlvs: usize, max_identity_bytes: usize) -> Self {
        Self {
            max_tlvs,
            max_identity_bytes,
        }
    }
}

/// One identity value and its byte offset within the CDP packet
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CdpField<'a> {
    /// Raw value bytes, which are not assumed to be UTF-8
    pub value: &'a [u8],
    /// Byte offset to the first value byte, not the TLV header
    pub offset: usize,
}

/// Checksum-valid CDP fields borrowed from the supplied packet
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CdpFrame<'a> {
    /// CDP version 1 or 2
    pub version: u8,
    /// Advertised hold time; zero requests immediate withdrawal
    pub hold_seconds: u8,
    /// Unique nonempty device-ID value
    pub device: CdpField<'a>,
    /// Unique nonempty port-ID value
    pub port: CdpField<'a>,
    /// Total number of parsed TLVs, including unknown types
    pub tlv_count: usize,
}
