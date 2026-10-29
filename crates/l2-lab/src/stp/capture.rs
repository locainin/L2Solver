//! Bounded, source-tagged virtual BPDU ingress records

use l2_segmentation::{EvidenceSourceId, PacketReference};
use sha2::{Digest, Sha256};

use super::{Error, Port};

// This marker distinguishes the synthetic stream from a physical capture
const MARKER: &[u8] = b"l2solver-virtual-stp-v1\0";
const MAX_RECORDS: usize = 2;

/// One complete synthetic Ethernet frame observed at a modeled ingress port
#[derive(Debug, Eq, PartialEq)]
pub struct CapturedFrame {
    sequence: u64,
    port: Port,
    frame: Vec<u8>,
    reference: PacketReference,
}

impl CapturedFrame {
    /// Return the virtual schedule sequence
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    /// Return the modeled port where the frame was observed
    #[must_use]
    pub const fn port(&self) -> Port {
        self.port
    }
    /// Borrow the exact complete Ethernet bytes delivered to the model
    #[must_use]
    pub fn frame(&self) -> &[u8] {
        &self.frame
    }
    /// Return the source-scoped one-based packet reference
    #[must_use]
    pub const fn reference(&self) -> PacketReference {
        self.reference
    }
}

/// An exact synthetic capture stream and its receiver-independent ingress records
#[derive(Debug, Eq, PartialEq)]
pub struct Capture {
    source: EvidenceSourceId,
    records: Vec<CapturedFrame>,
}

impl Capture {
    /// Return the digest of the exact synthetic capture stream
    #[must_use]
    pub const fn source(&self) -> EvidenceSourceId {
        self.source
    }
    /// Return observed frames in deterministic dispatch order
    #[must_use]
    pub fn records(&self) -> &[CapturedFrame] {
        &self.records
    }
    /// Serialize the modeled capture, which is not a PCAP or physical capture
    ///
    /// # Errors
    /// Returns an allocation error when bounded output storage is unavailable
    pub fn bytes(&self) -> Result<Vec<u8>, Error> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(encoded_capacity())
            .map_err(|_| Error::Allocation)?;
        encode(
            self.records
                .iter()
                .map(|record| (record.sequence, record.port, record.frame.as_slice())),
            &mut bytes,
        );
        Ok(bytes)
    }
}

struct RawFrame {
    sequence: u64,
    port: Port,
    frame: Vec<u8>,
}

pub struct CaptureBuilder {
    pending_control: Option<Vec<u8>>,
    pending_attack: Option<Vec<u8>>,
    raw: Vec<RawFrame>,
    records: Vec<CapturedFrame>,
    bytes: Vec<u8>,
}

impl CaptureBuilder {
    pub fn new(control: &[u8], attack: &[u8], observed: bool) -> Result<Self, Error> {
        // Reserve all modeled capture storage before any bridge state can change
        let mut raw = Vec::new();
        raw.try_reserve_exact(MAX_RECORDS)
            .map_err(|_| Error::Allocation)?;
        let mut records = Vec::new();
        records
            .try_reserve_exact(MAX_RECORDS)
            .map_err(|_| Error::Allocation)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(encoded_capacity())
            .map_err(|_| Error::Allocation)?;
        let (pending_control, pending_attack) = if observed {
            (Some(copy_frame(control)?), Some(copy_frame(attack)?))
        } else {
            (None, None)
        };
        Ok(Self {
            pending_control,
            pending_attack,
            raw,
            records,
            bytes,
        })
    }

    pub fn record(&mut self, sequence: u64, port: Port) {
        let frame = match port {
            Port::Trusted => self.pending_control.take(),
            Port::Edge => self.pending_attack.take(),
        };
        if let Some(frame) = frame {
            self.raw.push(RawFrame {
                sequence,
                port,
                frame,
            });
        }
    }

    pub fn finish(mut self) -> Result<Capture, Error> {
        encode(
            self.raw
                .iter()
                .map(|record| (record.sequence, record.port, record.frame.as_slice())),
            &mut self.bytes,
        );
        let digest: [u8; 32] = Sha256::digest(&self.bytes).into();
        let source = EvidenceSourceId::from_bytes(digest);
        for (index, record) in self.raw.into_iter().enumerate() {
            let number = u64::try_from(index + 1).map_err(|_| Error::Invariant)?;
            let reference = PacketReference::new(source, number).map_err(|_| Error::Invariant)?;
            self.records.push(CapturedFrame {
                sequence: record.sequence,
                port: record.port,
                frame: record.frame,
                reference,
            });
        }
        Ok(Capture {
            source,
            records: self.records,
        })
    }
}

fn copy_frame(input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(input.len())
        .map_err(|_| Error::Allocation)?;
    bytes.extend_from_slice(input);
    Ok(bytes)
}

const fn encoded_capacity() -> usize {
    MARKER.len() + MAX_RECORDS * (8 + 1 + 8 + super::admission::MAX_FRAME_BYTES)
}

fn encode<'a>(records: impl Iterator<Item = (u64, Port, &'a [u8])>, bytes: &mut Vec<u8>) {
    bytes.extend_from_slice(MARKER);
    for (sequence, port, frame) in records {
        bytes.extend_from_slice(&sequence.to_be_bytes());
        bytes.push(match port {
            Port::Trusted => 1,
            Port::Edge => 2,
        });
        bytes.extend_from_slice(&(frame.len() as u64).to_be_bytes());
        bytes.extend_from_slice(frame);
    }
}
