//! Logical owned allocation sizes for artifact provenance

use std::mem::size_of;

use super::{AnalysisOmission, ArtifactOrigin};
use crate::{
    derivation::{OperandRef, Operation},
    recovery::regions::RegionCueOrigin,
};

impl ArtifactOrigin {
    /// Return heap capacity owned by this origin, or `None` on overflow
    ///
    /// Allocator overhead and process RSS are outside this logical charge
    #[must_use]
    pub fn owned_heap_bytes(&self) -> Option<usize> {
        match self {
            Self::Source | Self::SourceRange { .. } | Self::EmbeddedObject { .. } => Some(0),
            Self::ArchiveMember {
                raw_name_sha256,
                raw_name_hex_preview,
                ..
            } => raw_name_sha256
                .capacity()
                .checked_add(raw_name_hex_preview.capacity()),
            Self::Transformation {
                operation,
                cue_origins,
                ..
            } => cue_origins
                .capacity()
                .checked_mul(size_of::<RegionCueOrigin>())?
                .checked_add(operation_bytes(operation)?),
        }
    }
}

impl AnalysisOmission {
    /// Return heap capacity owned by this omission's nested payload, or `None` on overflow
    #[must_use]
    pub fn owned_heap_bytes(&self) -> Option<usize> {
        match self {
            Self::SourceRangeValidationLimit { reason, .. }
            | Self::ValidationLimit { reason, .. } => Some(reason.capacity()),
            Self::SourceStreamTransform { operation, reason } => reason
                .capacity()
                .checked_add(operation.as_ref().map_or(Some(0), operation_bytes)?),
            Self::TransformFailed {
                operation, message, ..
            } => message.capacity().checked_add(operation_bytes(operation)?),
            Self::DerivedStreamRangeCoverage { output_sha256, .. } => {
                Some(output_sha256.capacity())
            }
            _ => Some(0),
        }
    }
}

fn operation_bytes(operation: &Operation) -> Option<usize> {
    match operation {
        Operation::XorRepeat { key, .. } => Some(key.capacity()),
        Operation::Sha256CounterXor { seed, .. } => Some(operand_bytes(seed)),
        Operation::AesGcmDecrypt {
            key,
            nonce,
            associated_data,
            ..
        } => operand_bytes(key)
            .checked_add(operand_bytes(nonce))?
            .checked_add(operand_bytes(associated_data)),
        Operation::ScryptDerive { salt, .. } => Some(operand_bytes(salt)),
        Operation::Select { indices }
        | Operation::SelectBits { indices, .. }
        | Operation::Permute { indices } => indices.capacity().checked_mul(size_of::<usize>()),
        // These operation variants carry only inline values
        Operation::HexDecode { .. }
        | Operation::HexEncode { .. }
        | Operation::Base64Decode { .. }
        | Operation::Base64Encode { .. }
        | Operation::ByteAdd { .. }
        | Operation::RotateBits { .. }
        | Operation::Slice { .. }
        | Operation::SelectBitRange { .. }
        | Operation::Reverse { .. }
        | Operation::GzipDecompress { .. }
        | Operation::ZlibDecompress { .. } => Some(0),
    }
}

const fn operand_bytes(operand: &OperandRef) -> usize {
    match operand {
        OperandRef::Literal(bytes) => bytes.capacity(),
        OperandRef::NodeRange { .. } | OperandRef::SelectedInputRange { .. } => 0,
    }
}
