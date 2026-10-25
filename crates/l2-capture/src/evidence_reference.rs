//! Canonical source and packet identities for captured evidence

use core::{fmt, num::NonZeroU64, str::FromStr};

const SOURCE_PREFIX: &str = "sha256:";
const SOURCE_HEX_LENGTH: usize = 64;

/// Invalid capture evidence source or packet reference
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceReferenceError {
    /// A source ID is not exactly `sha256:` followed by 64 lowercase hex digits
    InvalidSourceId,
    /// Packet numbers are one based within each source
    ZeroPacketNumber,
}

impl fmt::Display for EvidenceReferenceError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSourceId => {
                output.write_str("evidence source ID must be canonical sha256 hex")
            }
            Self::ZeroPacketNumber => output.write_str("evidence packet number must be nonzero"),
        }
    }
}

impl std::error::Error for EvidenceReferenceError {}

/// SHA-256 identity of one exact source containing evidence
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EvidenceSourceId([u8; 32]);

impl EvidenceSourceId {
    /// Construct a source identity from its 32 digest bytes
    #[must_use]
    pub const fn from_bytes(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    /// Return the source digest bytes
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for EvidenceSourceId {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str(SOURCE_PREFIX)?;
        for byte in self.0 {
            write!(output, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for EvidenceSourceId {
    type Err = EvidenceReferenceError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let Some(encoded_digest) = value.strip_prefix(SOURCE_PREFIX) else {
            return Err(EvidenceReferenceError::InvalidSourceId);
        };
        if encoded_digest.len() != SOURCE_HEX_LENGTH {
            return Err(EvidenceReferenceError::InvalidSourceId);
        }

        let mut digest = [0; 32];
        for (index, pair) in encoded_digest.as_bytes().chunks_exact(2).enumerate() {
            let mut digits = pair.iter().copied();
            let Some(high) = digits.next().and_then(hex_nibble) else {
                return Err(EvidenceReferenceError::InvalidSourceId);
            };
            let Some(low) = digits.next().and_then(hex_nibble) else {
                return Err(EvidenceReferenceError::InvalidSourceId);
            };
            let Some(byte) = digest.get_mut(index) else {
                return Err(EvidenceReferenceError::InvalidSourceId);
            };
            *byte = (high << 4) | low;
        }
        Ok(Self(digest))
    }
}

const fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

/// One packet number scoped to its exact source file or capture stream
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PacketReference {
    source: EvidenceSourceId,
    packet_number: NonZeroU64,
}

impl PacketReference {
    /// Construct a source-scoped packet reference
    ///
    /// # Errors
    /// Returns [`EvidenceReferenceError::ZeroPacketNumber`] for the reserved zero value
    pub const fn new(
        source: EvidenceSourceId,
        packet_number: u64,
    ) -> Result<Self, EvidenceReferenceError> {
        let Some(packet_number) = NonZeroU64::new(packet_number) else {
            return Err(EvidenceReferenceError::ZeroPacketNumber);
        };
        Ok(Self {
            source,
            packet_number,
        })
    }

    /// Return the exact source containing this packet
    #[must_use]
    pub const fn source(self) -> EvidenceSourceId {
        self.source
    }

    /// Return the one-based packet number within its source
    #[must_use]
    pub const fn packet_number(self) -> u64 {
        self.packet_number.get()
    }
}
