//! Source-backed, caller-modeled neighbor state observations
//!
//! A source identity binds the exact encoded bytes, not their physical origin

mod codec;
mod error;

use std::{net::IpAddr, num::NonZeroU64};

use sha2::{Digest, Sha256};

use crate::{AgentId, ClockStamp, EvidenceSourceId, InterfaceBindingRequest, MacAddress, RunId};

pub use error::StateSourceError;

/// One caller's claim about a neighbor entry at a modeled observer
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateRecordClaim {
    /// Assessment run named by the source
    pub run_id: RunId,
    /// Agent reporting the state
    pub observer: AgentId,
    /// Exact interface used for the observation
    pub interface: InterfaceBindingRequest,
    /// Agent whose address is being observed
    pub subject: AgentId,
    /// Address of the observed subject
    pub address: IpAddr,
    /// Observed MAC or explicit absence of an entry
    pub binding: Option<MacAddress>,
    /// Source-local observation time
    pub observed_at: ClockStamp,
}

/// Completeness and loss claims applying to the whole state source
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateSourceQuality {
    /// Whether the source claims its collection completed
    pub complete: bool,
    /// Number of records the source claims were lost
    pub dropped_records: u64,
}

/// One-based identity of a state record in a specific source
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StateRecordReference {
    source: EvidenceSourceId,
    record_number: NonZeroU64,
}

impl StateRecordReference {
    /// Name a record within a particular state source
    ///
    /// # Errors
    /// Returns [`StateSourceError::ZeroRecord`] for the reserved zero index
    pub const fn new(
        source: EvidenceSourceId,
        record_number: u64,
    ) -> Result<Self, StateSourceError> {
        let Some(record_number) = NonZeroU64::new(record_number) else {
            return Err(StateSourceError::ZeroRecord);
        };
        Ok(Self {
            source,
            record_number,
        })
    }

    /// Return the digest of the exact source containing this record
    #[must_use]
    pub const fn source(self) -> EvidenceSourceId {
        self.source
    }

    /// Return the one-based record number
    #[must_use]
    pub const fn record_number(self) -> u64 {
        self.record_number.get()
    }
}

/// A decoded claim tied to the exact bytes of a validated source
///
/// Verification checks the source format and reference, not who supplied it
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedStateRecord {
    reference: StateRecordReference,
    record: StateRecordClaim,
    quality: StateSourceQuality,
}

impl VerifiedStateRecord {
    /// Return the exact source and record number
    #[must_use]
    pub const fn reference(self) -> StateRecordReference {
        self.reference
    }

    /// Return the source's modeled state claim
    #[must_use]
    pub const fn record(self) -> StateRecordClaim {
        self.record
    }

    /// Return the source's completeness and loss claims
    #[must_use]
    pub const fn quality(self) -> StateSourceQuality {
        self.quality
    }
}

/// Immutable canonical source bytes and their SHA-256 identity
#[derive(Debug)]
pub struct StateSource {
    bytes: Vec<u8>,
    source: EvidenceSourceId,
}

impl StateSource {
    /// Encode bounded modeled claims and identify the exact resulting bytes
    ///
    /// # Errors
    /// Rejects too many records, invalid subject addresses, or allocation failure
    pub fn from_records(
        quality: StateSourceQuality,
        records: &[StateRecordClaim],
    ) -> Result<Self, StateSourceError> {
        let bytes = codec::encode(quality, records)?;
        Ok(Self::from_validated_bytes(bytes))
    }

    /// Validate and retain one complete canonical state-source stream
    ///
    /// # Errors
    /// Rejects invalid, truncated, noncanonical, oversized, or unallocatable input
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, StateSourceError> {
        codec::validate(bytes)?;
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| StateSourceError::Allocation)?;
        owned.extend_from_slice(bytes);
        Ok(Self::from_validated_bytes(owned))
    }

    fn from_validated_bytes(bytes: Vec<u8>) -> Self {
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        Self {
            bytes,
            source: EvidenceSourceId::from_bytes(digest),
        }
    }

    /// Return the digest of the retained canonical bytes
    #[must_use]
    pub const fn source(&self) -> EvidenceSourceId {
        self.source
    }

    /// Borrow the complete canonical source stream
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Return the number of records stored in this source
    #[must_use]
    pub const fn len(&self) -> usize {
        // Both constructors retain only a complete header and whole records
        (self.bytes.len() - codec::HEADER_LEN) / codec::RECORD_LEN
    }

    /// Return whether the source contains no state records
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Resolve a source-scoped record into a private-field verified claim
    ///
    /// # Errors
    /// Rejects a source mismatch, out-of-range index, or invalid record encoding
    pub fn resolve(
        &self,
        reference: StateRecordReference,
    ) -> Result<VerifiedStateRecord, StateSourceError> {
        if reference.source != self.source {
            return Err(StateSourceError::SourceMismatch);
        }
        let index = usize::try_from(reference.record_number.get() - 1)
            .map_err(|_| StateSourceError::RecordOutOfBounds)?;
        if index >= self.len() {
            return Err(StateSourceError::RecordOutOfBounds);
        }
        // Parse the indexed record from the immutable source bytes
        let (record, quality) = codec::decode_record(&self.bytes, index)?;
        Ok(VerifiedStateRecord {
            reference,
            record,
            quality,
        })
    }
}
