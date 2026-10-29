//! Deterministic virtual receiver records and their exact evidence source

use l2_canary::AgentId;
use l2_segmentation::EvidenceSourceId;
use sha2::{Digest, Sha256};

use crate::LabError;
use crate::frame::FRAME_LEN;

// The marker makes these bytes distinguishable from a physical capture format
const CAPTURE_MARKER: &[u8] = b"l2solver-virtual-capture-v1\0";
const RECORD_LEN: usize = 8 + l2_canary::ID_LEN + 8 + FRAME_LEN;

/// A complete frame observed by one synthetic receiver
#[derive(Debug, Eq, PartialEq)]
pub struct CapturedFrame {
    pub(crate) sequence: u64,
    pub(crate) receiver: AgentId,
    pub(crate) frame: [u8; FRAME_LEN],
}

impl CapturedFrame {
    /// Return the planned canary sequence associated with this delivery
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Return the synthetic destination that received this frame
    #[must_use]
    pub const fn receiver(&self) -> AgentId {
        self.receiver
    }

    /// Borrow the complete untagged Ethernet frame delivered to the port
    #[must_use]
    pub const fn frame(&self) -> &[u8] {
        &self.frame
    }
}

/// An ordered virtual capture and the digest of its exact serialized content
///
/// The byte stream is a model artifact, not a PCAP or physical capture. It
/// contains a fixed marker followed by records: big-endian sequence, 16-byte
/// receiver identity, big-endian frame length, and the exact frame bytes
/// Packet references are one-based positions in this record sequence
#[derive(Debug, Eq, PartialEq)]
pub struct VirtualCapture {
    records: Vec<CapturedFrame>,
    source: EvidenceSourceId,
}

impl VirtualCapture {
    pub(crate) fn new(records: Vec<CapturedFrame>) -> Result<Self, LabError> {
        let bytes = serialize(&records)?;
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        Ok(Self {
            records,
            source: EvidenceSourceId::from_bytes(digest),
        })
    }

    /// Return receiver deliveries in virtual execution order
    #[must_use]
    pub fn records(&self) -> &[CapturedFrame] {
        &self.records
    }

    /// Return the SHA-256 identity of the exact synthetic capture stream
    #[must_use]
    pub const fn source(&self) -> EvidenceSourceId {
        self.source
    }

    /// Serialize the complete deterministic virtual capture stream
    ///
    /// # Errors
    /// Returns an allocation error if bounded output storage is unavailable
    pub fn bytes(&self) -> Result<Vec<u8>, LabError> {
        serialize(&self.records)
    }
}

fn serialize(records: &[CapturedFrame]) -> Result<Vec<u8>, LabError> {
    let size = records
        .len()
        .checked_mul(RECORD_LEN)
        .and_then(|size| size.checked_add(CAPTURE_MARKER.len()))
        .ok_or(LabError::Invariant)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|_| LabError::Allocation)?;
    bytes.extend_from_slice(CAPTURE_MARKER);
    for record in records {
        bytes.extend_from_slice(&record.sequence.to_be_bytes());
        bytes.extend_from_slice(record.receiver.as_bytes());
        bytes.extend_from_slice(&(FRAME_LEN as u64).to_be_bytes());
        bytes.extend_from_slice(&record.frame);
    }
    Ok(bytes)
}
