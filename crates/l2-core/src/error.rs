use core::fmt;

// Parsing context keeps truncation reports useful without exposing offsets as strings
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeContext {
    /// The fixed destination, source, and field header
    EthernetHeader,
    /// A four-byte 802.1Q or 802.1ad tag
    VlanTag,
    /// The two-byte `EtherType` or IEEE 802.3 length field
    TypeLengthField,
}

// Every failure is bounded data from the caller, never an unchecked parser condition
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    /// The supplied capture is larger than the parser budget
    FrameTooLong { length: usize, max: usize },
    /// A required wire section is shorter than its fixed size
    Truncated {
        context: DecodeContext,
        needed: usize,
        available: usize,
    },
    /// The field value is reserved between length and `EtherType` ranges
    ReservedField { value: u16 },
    /// An IEEE 802.3 length advertises bytes absent from the capture
    PayloadTruncated { declared: usize, available: usize },
    /// The bounded VLAN parser found another supported tag after its limit
    TooManyVlanTags { max: usize },
}

impl fmt::Display for DecodeContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::EthernetHeader => "Ethernet header",
            Self::VlanTag => "VLAN tag",
            Self::TypeLengthField => "type/length field",
        };
        formatter.write_str(name)
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameTooLong { length, max } => {
                write!(formatter, "frame length {length} exceeds maximum {max}")
            }
            Self::Truncated {
                context,
                needed,
                available,
            } => write!(
                formatter,
                "truncated {context}: need {needed} bytes, have {available}"
            ),
            Self::ReservedField { value } => {
                write!(formatter, "reserved EtherType/length value 0x{value:04x}")
            }
            Self::PayloadTruncated {
                declared,
                available,
            } => write!(
                formatter,
                "802.3 payload declares {declared} bytes, only {available} available"
            ),
            Self::TooManyVlanTags { max } => {
                write!(formatter, "frame contains more than {max} VLAN tags")
            }
        }
    }
}

impl std::error::Error for DecodeError {}

// Encoding errors are checked before the destination buffer is touched
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncodeError {
    /// The reconstructed frame is larger than the bounded frame policy
    FrameTooLong { length: usize, max: usize },
    /// The caller did not provide enough output space
    BufferTooShort { needed: usize, available: usize },
    /// The frame contains more supported VLAN tags than the bounded model allows
    TooManyVlanTags { max: usize },
    /// A VLAN tag uses a TPID this encoder does not model
    UnsupportedVlanTpid { index: usize, tpid: u16 },
    /// A terminal `EtherType` is a VLAN TPID and therefore requires a tag body
    VlanTpidAsFinalType { value: u16 },
    /// A type/length field falls in the reserved IEEE range
    ReservedField { value: u16 },
    /// An IEEE 802.3 length does not match the payload bytes supplied
    LengthMismatch { declared: u16, payload: usize },
    /// A checked output-length calculation could not be represented
    LengthOverflow,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameTooLong { length, max } => {
                write!(
                    formatter,
                    "encoded frame length {length} exceeds maximum {max}"
                )
            }
            Self::BufferTooShort { needed, available } => write!(
                formatter,
                "output buffer is too short: need {needed} bytes, have {available}"
            ),
            Self::TooManyVlanTags { max } => {
                write!(formatter, "frame contains more than {max} VLAN tags")
            }
            Self::UnsupportedVlanTpid { index, tpid } => write!(
                formatter,
                "VLAN tag {index} uses unsupported TPID 0x{tpid:04x}"
            ),
            Self::VlanTpidAsFinalType { value } => write!(
                formatter,
                "terminal EtherType 0x{value:04x} is a VLAN TPID and requires a tag"
            ),
            Self::ReservedField { value } => {
                write!(formatter, "reserved EtherType/length value 0x{value:04x}")
            }
            Self::LengthMismatch { declared, payload } => write!(
                formatter,
                "802.3 length field declares {declared} bytes, payload has {payload}"
            ),
            Self::LengthOverflow => formatter.write_str("encoded frame length overflowed"),
        }
    }
}

impl std::error::Error for EncodeError {}
