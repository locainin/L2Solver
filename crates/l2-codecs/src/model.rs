//! Borrowed LLDP output types and parser budgets

/// Maximum number of bytes accepted for one LLDP data unit
pub const MAX_FRAME_LEN: usize = 0xffff;

/// Maximum number of non-End TLVs retained in one LLDP data unit
pub const MAX_TLVS: usize = 128;

/// Semantic status of a structurally decoded LLDP data unit
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Validity {
    /// The mandatory TLV sequence and mandatory field constraints are valid
    Valid,
    /// The bytes decode, but one or more mandatory semantic rules are invalid
    Invalid,
}

/// One decoded LLDP TLV borrowed from the input byte slice
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tlv<'input> {
    /// Seven-bit LLDP TLV type
    pub kind: u8,
    /// TLV information field without its two-byte header
    pub value: &'input [u8],
    /// Byte offset of the TLV header within the input slice
    pub offset: usize,
}

/// A structurally valid LLDP data unit and its semantic status
#[derive(Debug, PartialEq, Eq)]
pub struct LldpFrame<'input> {
    /// All non-End TLVs in their wire order, including unknown and duplicate types
    pub tlvs: Vec<Tlv<'input>>,
    /// Bytes after the End TLV, retained without interpreting them as TLVs
    pub padding: &'input [u8],
    /// Result of mandatory LLDP semantic validation
    pub validity: Validity,
}
