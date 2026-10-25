//! Exact authenticated canary frames prepared before transmission

use l2_canary::{Canary, SessionKey};
use l2_core::FrameField;
use sha2::{Digest, Sha256};

use crate::{PlannedFrameError, Probe};

/// One authenticated canary bound to the complete Ethernet bytes to transmit
///
/// Construction validates structure only. It does not prove that an interface,
/// helper, or physical agent transmitted the retained bytes
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannedCanaryFrame {
    canary: Canary,
    bytes: Vec<u8>,
    frame_hash: [u8; 32],
    frame_length: u64,
}

impl PlannedCanaryFrame {
    /// Bind a planned probe to its authenticated payload and complete frame
    ///
    /// # Errors
    /// Returns an error when the probe, key scope, Ethernet frame, `EtherType`,
    /// or payload does not form one continuous canary frame
    pub fn from_probe(
        probe: Probe,
        key: &SessionKey,
        frame: &[u8],
    ) -> Result<Self, PlannedFrameError> {
        let canary = probe.canary().map_err(PlannedFrameError::Canary)?;
        Self::from_canary(canary, key, frame)
    }

    /// Bind checked canary fields to their authenticated payload and frame
    ///
    /// # Errors
    /// Returns an error when the key or complete Ethernet frame does not match
    pub fn from_canary(
        canary: Canary,
        key: &SessionKey,
        frame: &[u8],
    ) -> Result<Self, PlannedFrameError> {
        // Encode first so the key scope and exact authenticated bytes are fixed
        let expected_payload = l2_canary::encode(&canary, key).map_err(PlannedFrameError::Key)?;
        let decoded = l2_core::decode(frame).map_err(PlannedFrameError::Frame)?;

        // A length field or another protocol cannot carry a planned canary
        if decoded.field != FrameField::EtherType(l2_canary::ETHER_TYPE) {
            return Err(PlannedFrameError::WrongEtherType);
        }
        if decoded.payload != expected_payload {
            return Err(PlannedFrameError::CanaryPayloadMismatch);
        }

        // Hash the exact complete bytes retained for the eventual send call
        let frame_hash: [u8; 32] = Sha256::digest(frame).into();
        let frame_length =
            u64::try_from(frame.len()).map_err(|_| PlannedFrameError::FrameLengthOverflow)?;
        Ok(Self {
            canary,
            bytes: frame.to_vec(),
            frame_hash,
            frame_length,
        })
    }

    /// Return the exact checked canary carried by the frame
    #[must_use]
    pub const fn canary(&self) -> Canary {
        self.canary
    }

    /// Borrow the complete Ethernet bytes that must be transmitted unchanged
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Return the digest derived from the retained complete frame
    #[must_use]
    pub const fn frame_hash(&self) -> [u8; 32] {
        self.frame_hash
    }

    /// Return the exact byte count retained by this planned frame
    #[must_use]
    pub const fn frame_length(&self) -> u64 {
        self.frame_length
    }
}
